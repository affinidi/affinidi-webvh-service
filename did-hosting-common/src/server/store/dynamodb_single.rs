//! Single-table DynamoDB storage backend.
//!
//! Consolidates the 12 keyspace-per-table layout used by
//! [`super::dynamodb`] into a **single externally-provisioned** DynamoDB
//! table with a composite key. The table must exist before the service
//! starts — this backend performs **no `DescribeTable`/`CreateTable`**
//! calls and therefore requires no table-management IAM permissions at
//! runtime.
//!
//! # Schema
//!
//! ```text
//! pk  : String (HASH)   — keyspace name          e.g. "dids", "sessions"
//! sk  : String (RANGE)  — the record key          e.g. "did:tenant/alice"
//! val : Binary          — JSON or raw value bytes (unchanged from multi-table)
//! ```
//!
//! # Why a sort key
//!
//! The multi-table backend's `prefix_iter_raw` runs a full-table
//! `Scan` because `pk` is the only attribute. A composite `(pk, sk)`
//! turns every prefix listing into a partition-scoped
//! `Query(pk = :ks AND begins_with(sk, :prefix))` — server-side,
//! bounded to one partition, no client-side filtering.
//!
//! # UTF-8 keys
//!
//! Every keyspace key in the workspace is constructed with
//! `format!("prefix:{}", …)` and is therefore valid UTF-8. This
//! backend enforces that invariant at the boundary: any non-UTF-8
//! key returns [`AppError::Store`] rather than silently corrupting
//! via `from_utf8_lossy`.
//!
//! # Batch limits
//!
//! `TransactWriteItems` is chunked at 100 items per request, matching
//! the multi-table backend's semantics — cross-chunk atomicity is
//! **not** guaranteed. All existing callers stay well under 100.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, ReturnValue, TransactWriteItem};
use tracing::{info, warn};

use crate::server::config::StoreConfig;
use crate::server::error::AppError;

use super::{BatchLimits, BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

const PK_ATTR: &str = "pk";
const SK_ATTR: &str = "sk";
const VAL_ATTR: &str = "val";
const CNT_ATTR: &str = "cnt";

// ---------------------------------------------------------------------------
// SingleTableDynamoDbBackend
// ---------------------------------------------------------------------------

/// Externally-managed single-table DynamoDB backend.
///
/// The table name is supplied by the operator via config or env var;
/// the backend never issues `CreateTable`.
pub struct SingleTableDynamoDbBackend {
    client: Client,
    table_name: String,
    namespace: Option<String>,
    consistent_reads: bool,
}

/// Longest accepted key namespace.
const MAX_NAMESPACE_LEN: usize = 32;

/// Separates a namespace from the keyspace in the partition key. Keyspace names
/// may not contain it (see [`SingleTableDynamoDbBackend::keyspace`]), so
/// `"witness#acl"` can only ever mean keyspace `acl` in namespace `witness`.
const NAMESPACE_SEP: char = '#';

/// Check a key namespace against a strict allowlist: ASCII letters, digits,
/// `_`, `-` and `.`, 1 to [`MAX_NAMESPACE_LEN`] characters. The namespace is an
/// isolation boundary and part of every partition key, so nothing else is let
/// through (in particular not [`NAMESPACE_SEP`], whitespace or non-ASCII).
fn validate_namespace(ns: &str) -> Result<(), String> {
    if ns.is_empty() || ns.len() > MAX_NAMESPACE_LEN {
        return Err(format!("must be 1 to {MAX_NAMESPACE_LEN} characters"));
    }
    if !ns
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("may contain only ASCII letters, digits, '_', '-' and '.'".into());
    }
    Ok(())
}

/// Reserved keyspace and key the startup probe reads; never written.
const PROBE_KEYSPACE: &str = "_probe";
const PROBE_KEY: &str = "_probe";

/// Classify a failed probe. `Err` is a definitive configuration error that must
/// stop startup; `Ok` means the probe was inconclusive and startup continues.
fn probe_outcome(code: Option<&str>, message: Option<&str>, table: &str) -> Result<(), AppError> {
    match code {
        Some("ResourceNotFoundException") => Err(AppError::Config(format!(
            "DynamoDB table `{table}` was not found. store-dynamodb-single needs an \
             existing table with partition key `{PK_ATTR}` (String) and sort key \
             `{SK_ATTR}` (String); it never creates one"
        ))),
        Some("ValidationException") => Err(AppError::Config(format!(
            "DynamoDB table `{table}` does not match the expected key schema \
             (partition key `{PK_ATTR}` String, sort key `{SK_ATTR}` String), or its \
             name is invalid: {}",
            message.unwrap_or("no detail")
        ))),
        _ => Ok(()),
    }
}

/// The `pk` attribute for a keyspace: the bare keyspace name, or
/// `"{namespace}#{keyspace}"` when a namespace is set.
fn pk_for(namespace: Option<&str>, keyspace: &str) -> String {
    match namespace {
        Some(ns) => format!("{ns}{NAMESPACE_SEP}{keyspace}"),
        None => keyspace.to_string(),
    }
}

/// Validated, normalised settings for the backend, derived from a
/// [`StoreConfig`] in one place so every rule is checked before any AWS call.
struct Settings {
    table_name: String,
    namespace: Option<String>,
    consistent_reads: bool,
}

impl Settings {
    fn from_config(config: &StoreConfig) -> Result<Self, AppError> {
        let table_name = config.dynamodb_table_name.clone().ok_or_else(|| {
            AppError::Config(
                "store-dynamodb-single requires `store.dynamodb_table_name` \
                 (env: <PREFIX>_STORE_DYNAMODB_TABLE_NAME)"
                    .into(),
            )
        })?;
        if table_name.trim().is_empty() {
            return Err(AppError::Config(
                "`store.dynamodb_table_name` is blank \
                 (env: <PREFIX>_STORE_DYNAMODB_TABLE_NAME)"
                    .into(),
            ));
        }
        let namespace = config.dynamodb_key_namespace.clone();
        if let Some(ns) = &namespace {
            validate_namespace(ns).map_err(|reason| {
                AppError::Config(format!(
                    "`store.dynamodb_key_namespace` {reason} \
                     (env: <PREFIX>_STORE_DYNAMODB_KEY_NAMESPACE)"
                ))
            })?;
        }
        Ok(Self {
            table_name,
            namespace,
            // Unset means strongly consistent: the store backs sessions, refresh
            // tokens and lockout counters, which must read their own writes.
            consistent_reads: config.dynamodb_consistent_reads.unwrap_or(true),
        })
    }
}

impl SingleTableDynamoDbBackend {
    pub async fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        let settings = Settings::from_config(config)?;

        let mut aws_config_loader = aws_config::from_env();
        if let Some(ref region) = config.dynamodb_region {
            aws_config_loader = aws_config_loader.region(aws_config::Region::new(region.clone()));
        }
        let aws_config = aws_config_loader.load().await;
        let client = Client::new(&aws_config);

        info!(
            table = %settings.table_name,
            namespace = settings.namespace.as_deref().unwrap_or("(none)"),
            consistent_reads = settings.consistent_reads,
            "opening single-table dynamodb store"
        );

        let backend = Self::new(client, settings);
        backend.probe().await?;
        Ok(Box::new(backend))
    }

    /// Fail at startup, with a message that says what to fix, when the table is
    /// missing or has the wrong key schema, instead of on the first request deep
    /// in the service.
    ///
    /// A strongly consistent `GetItem` on a reserved key, then a one-row `Query`
    /// on the same partition: the only permissions the backend already needs (no
    /// `DescribeTable`). Only a *definitive* answer stops startup; throttling, a
    /// timeout, or an access error is logged and startup continues, so a
    /// transient blip never keeps a working service from starting.
    ///
    /// The `GetItem` alone is not enough: it names `pk` and `sk` without saying
    /// which is the partition key, so a table keyed the other way round (`sk`
    /// HASH, `pk` RANGE) answers it and starts fine, then fails every prefix
    /// `Query`. The `Query` conditions on `pk` for equality and `sk` with
    /// `begins_with`, which DynamoDB only accepts when the roles are right.
    async fn probe(&self) -> Result<(), AppError> {
        let pk = pk_for(self.namespace.as_deref(), PROBE_KEYSPACE);
        let got = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(PK_ATTR, AttributeValue::S(pk.clone()))
            .key(SK_ATTR, AttributeValue::S(PROBE_KEY.to_string()))
            .projection_expression(PK_ATTR)
            .consistent_read(true)
            .send()
            .await;
        if let Err(e) = &got {
            self.probe_failed(e)?;
        }

        let queried = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("#pk = :ks AND begins_with(#sk, :pfx)")
            .expression_attribute_names("#pk", PK_ATTR)
            .expression_attribute_names("#sk", SK_ATTR)
            .expression_attribute_values(":ks", AttributeValue::S(pk))
            .expression_attribute_values(":pfx", AttributeValue::S(PROBE_KEY.to_string()))
            .projection_expression("#pk")
            .consistent_read(true)
            .limit(1)
            .send()
            .await;
        if let Err(e) = &queried {
            self.probe_failed(e)?;
        }
        Ok(())
    }

    /// What a failed probe call means for startup: a definitive configuration
    /// error stops it, anything else is logged and let through.
    fn probe_failed<E: ProvideErrorMetadata + std::fmt::Display>(
        &self,
        e: &E,
    ) -> Result<(), AppError> {
        let outcome = probe_outcome(e.code(), e.message(), &self.table_name);
        if outcome.is_ok() {
            warn!(
                table = %self.table_name,
                error = %e,
                "could not confirm the DynamoDB table at startup; continuing"
            );
        }
        outcome
    }

    fn new(client: Client, settings: Settings) -> Self {
        Self {
            client,
            table_name: settings.table_name,
            namespace: settings.namespace,
            consistent_reads: settings.consistent_reads,
        }
    }
}

impl StorageBackend for SingleTableDynamoDbBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        // A '#' in a keyspace name would let it alias another namespace's
        // partition ("witness#acl" is keyspace `acl` in namespace `witness`).
        if name.contains(NAMESPACE_SEP) {
            return Err(AppError::Config(format!(
                "dynamodb-single: keyspace name must not contain '{NAMESPACE_SEP}'"
            )));
        }
        Ok((
            name.to_string(),
            Arc::new(SingleTableKeyspace {
                client: self.client.clone(),
                table_name: self.table_name.clone(),
                pk: pk_for(self.namespace.as_deref(), name),
                consistent_reads: self.consistent_reads,
            }),
        ))
    }

    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(SingleTableBatch {
            client: self.client.clone(),
            table_name: self.table_name.clone(),
            namespace: self.namespace.clone(),
            ops: Vec::new(),
            invalid: None,
        })
    }

    fn batch_limits(&self) -> Option<BatchLimits> {
        Some(BATCH_LIMITS)
    }

    fn commits_atomically(&self) -> bool {
        // `TransactWriteItems`: all of the batch or none of it.
        true
    }

    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>> {
        // DynamoDB is fully managed; no-op.
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// SingleTableKeyspace
// ---------------------------------------------------------------------------

struct SingleTableKeyspace {
    client: Client,
    table_name: String,
    /// The `pk` attribute of every row in this keyspace (namespace included).
    pk: String,
    consistent_reads: bool,
}

/// Convert a raw key (bytes) into a `String` for the `sk` attribute.
///
/// Rejects non-UTF-8 rather than lossily replacing invalid bytes —
/// silently corrupting a lookup key is worse than surfacing an error.
fn key_as_string(key: &[u8]) -> Result<String, AppError> {
    std::str::from_utf8(key)
        .map(str::to_owned)
        .map_err(|e| AppError::Store(format!("dynamodb-single: key is not valid UTF-8: {e}")))
}

impl KeyspaceOps for SingleTableKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let sk = key_as_string(&key)?;
            self.client
                .put_item()
                .table_name(&self.table_name)
                .item(PK_ATTR, AttributeValue::S(self.pk.clone()))
                .item(SK_ATTR, AttributeValue::S(sk))
                .item(VAL_ATTR, AttributeValue::B(Blob::new(value)))
                .send()
                .await
                .map_err(|e| AppError::Store(format!("dynamodb-single put: {e}")))?;
            Ok(())
        })
    }

    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            let sk = key_as_string(&key)?;
            let result = self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key(PK_ATTR, AttributeValue::S(self.pk.clone()))
                .key(SK_ATTR, AttributeValue::S(sk))
                .consistent_read(self.consistent_reads)
                .send()
                .await
                .map_err(|e| AppError::Store(format!("dynamodb-single get: {e}")))?;

            Ok(result.item.and_then(extract_val_bytes))
        })
    }

    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let sk = key_as_string(&key)?;
            self.client
                .delete_item()
                .table_name(&self.table_name)
                .key(PK_ATTR, AttributeValue::S(self.pk.clone()))
                .key(SK_ATTR, AttributeValue::S(sk))
                .send()
                .await
                .map_err(|e| AppError::Store(format!("dynamodb-single delete: {e}")))?;
            Ok(())
        })
    }

    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            let sk = key_as_string(&key)?;
            let result = self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key(PK_ATTR, AttributeValue::S(self.pk.clone()))
                .key(SK_ATTR, AttributeValue::S(sk))
                .projection_expression(PK_ATTR)
                .consistent_read(self.consistent_reads)
                .send()
                .await
                .map_err(|e| AppError::Store(format!("dynamodb-single get: {e}")))?;
            Ok(result.item.is_some())
        })
    }

    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            let sk = key_as_string(&key)?;
            // DeleteItem with ReturnValues=ALL_OLD atomically removes the
            // item and returns the previous attributes — same semantics as
            // the multi-table backend. DynamoDB serialises DeleteItem per
            // full primary key (pk + sk), so exactly one concurrent caller
            // sees a non-empty response.
            let response = self
                .client
                .delete_item()
                .table_name(&self.table_name)
                .key(PK_ATTR, AttributeValue::S(self.pk.clone()))
                .key(SK_ATTR, AttributeValue::S(sk))
                .return_values(ReturnValue::AllOld)
                .send()
                .await
                .map_err(|e| {
                    AppError::Store(format!("dynamodb-single delete (atomic take): {e}"))
                })?;
            Ok(response.attributes.and_then(extract_val_bytes))
        })
    }

    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        Box::pin(async move {
            let sk = key_as_string(&key)?;
            // `ADD` on a Number attribute is DynamoDB's native atomic
            // counter: the read-modify-write happens server-side under the
            // item's lock, so replicas racing this call each get a distinct,
            // correctly-ordered result. The counter lives in its own `cnt`
            // attribute on the (pk, sk) item — same shape as the multi-table
            // backend — and `UpdatedNew` returns the post-increment value in
            // the same round trip.
            let response = self
                .client
                .update_item()
                .table_name(&self.table_name)
                .key(PK_ATTR, AttributeValue::S(self.pk.clone()))
                .key(SK_ATTR, AttributeValue::S(sk))
                .update_expression("ADD #cnt :one")
                .expression_attribute_names("#cnt", CNT_ATTR)
                .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
                .return_values(ReturnValue::UpdatedNew)
                .send()
                .await
                .map_err(|e| AppError::Store(format!("dynamodb-single update (incr): {e}")))?;
            response
                .attributes
                .as_ref()
                .and_then(|attrs| attrs.get(CNT_ATTR))
                .and_then(|attr| match attr {
                    AttributeValue::N(s) => s.parse::<u64>().ok(),
                    _ => None,
                })
                .ok_or_else(|| {
                    AppError::Store("dynamodb-single incr: no numeric counter in response".into())
                })
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            // Server-side partition-scoped Query. This is the key win over
            // the multi-table backend, which must Scan the whole table for
            // every prefix listing.
            //
            // Non-UTF-8 prefixes cannot be expressed against a String sort
            // key. All keyspace prefixes in the workspace are ASCII string
            // literals (`did:`, `owner:`, `content:`, `ts:` …), so this is
            // never a problem in practice — but a caller who passes bytes
            // outside UTF-8 gets a clear error rather than a silent
            // empty result.
            let prefix_str = if prefix.is_empty() {
                None
            } else {
                Some(key_as_string(&prefix)?)
            };

            let mut results = Vec::new();
            let mut last_key: Option<HashMap<String, AttributeValue>> = None;

            loop {
                let mut req = self
                    .client
                    .query()
                    .table_name(&self.table_name)
                    .consistent_read(self.consistent_reads)
                    .expression_attribute_values(":ks", AttributeValue::S(self.pk.clone()));

                if let Some(ref p) = prefix_str {
                    req = req
                        .key_condition_expression("#pk = :ks AND begins_with(#sk, :pfx)")
                        .expression_attribute_names("#pk", PK_ATTR)
                        .expression_attribute_names("#sk", SK_ATTR)
                        .expression_attribute_values(":pfx", AttributeValue::S(p.clone()));
                } else {
                    req = req
                        .key_condition_expression("#pk = :ks")
                        .expression_attribute_names("#pk", PK_ATTR);
                }

                if let Some(ref lk) = last_key {
                    req = req.set_exclusive_start_key(Some(lk.clone()));
                }

                let resp = req
                    .send()
                    .await
                    .map_err(|e| AppError::Store(format!("dynamodb-single query: {e}")))?;

                if let Some(items) = resp.items {
                    extract_pairs(items, &mut results);
                }

                last_key = resp.last_evaluated_key;
                if last_key.is_none() {
                    break;
                }
            }

            Ok(results)
        })
    }
}

/// Extract the `val` attribute as raw bytes from a single item.
fn extract_val_bytes(item: HashMap<String, AttributeValue>) -> Option<Vec<u8>> {
    item.get(VAL_ATTR).and_then(|attr| {
        if let AttributeValue::B(blob) = attr {
            Some(blob.as_ref().to_vec())
        } else {
            None
        }
    })
}

/// Reduce a page of query items to `(sk_bytes, val_bytes)` pairs.
///
/// The returned key is `sk` (the record key), *not* the composite
/// `pk+sk` — callers of `prefix_iter_raw` expect the original per-
/// keyspace key back, exactly as the multi-table backend returns it.
fn extract_pairs(items: Vec<HashMap<String, AttributeValue>>, out: &mut Vec<RawKvPair>) {
    for item in items {
        let sk = match item.get(SK_ATTR) {
            Some(AttributeValue::S(s)) => s.as_bytes().to_vec(),
            _ => continue,
        };
        let val = match item.get(VAL_ATTR) {
            Some(AttributeValue::B(blob)) => blob.as_ref().to_vec(),
            _ => continue,
        };
        out.push((sk, val));
    }
}

// ---------------------------------------------------------------------------
// SingleTableBatch
// ---------------------------------------------------------------------------

/// `TransactWriteItems` accepts at most this many actions per call.
const MAX_TRANSACT_ITEMS: usize = 100;
/// ... and at most this many bytes across the whole call.
const MAX_TRANSACT_BYTES: usize = 4 * 1024 * 1024;

/// DynamoDB also counts each item's attribute names (`pk`, `sk`, `val`) and the
/// namespace prefix of the partition key against the transaction size. The
/// limit reported to callers counts only keyspace name, key and value bytes (so
/// a caller can compute it exactly) and reserves this worst-case overhead for
/// every operation.
const ATTR_NAME_OVERHEAD: usize =
    PK_ATTR.len() + SK_ATTR.len() + VAL_ATTR.len() + MAX_NAMESPACE_LEN + NAMESPACE_SEP.len_utf8();

/// What one [`WriteBatch`](super::WriteBatch) can hold on this backend: a batch
/// is one atomic transaction or it is refused.
pub(super) const BATCH_LIMITS: BatchLimits = BatchLimits {
    max_ops: MAX_TRANSACT_ITEMS,
    max_bytes: MAX_TRANSACT_BYTES - MAX_TRANSACT_ITEMS * ATTR_NAME_OVERHEAD,
};

enum SingleTableBatchOp {
    Insert {
        pk: String,
        /// Length of the bare keyspace name, for [`BatchLimits::max_bytes`].
        name_len: usize,
        sk: String,
        value: Vec<u8>,
    },
    Remove {
        pk: String,
        name_len: usize,
        sk: String,
    },
}

impl SingleTableBatchOp {
    /// The item this operation targets.
    fn target(&self) -> (&str, &str) {
        match self {
            Self::Insert { pk, sk, .. } | Self::Remove { pk, sk, .. } => (pk, sk),
        }
    }

    /// Bytes this operation counts against [`BatchLimits::max_bytes`]: the
    /// keyspace name, the key and, for an insert, the value.
    fn size(&self) -> usize {
        match self {
            Self::Insert {
                name_len,
                sk,
                value,
                ..
            } => name_len
                .saturating_add(sk.len())
                .saturating_add(value.len()),
            Self::Remove { name_len, sk, .. } => name_len.saturating_add(sk.len()),
        }
    }
}

struct SingleTableBatch {
    client: Client,
    table_name: String,
    namespace: Option<String>,
    ops: Vec<SingleTableBatchOp>,
    /// Set when an operation named something that cannot be stored (a key that
    /// is not UTF-8, a keyspace name containing '#'). The batch is then
    /// refused at `commit()` before anything is written: nothing is altered to
    /// fit.
    invalid: Option<&'static str>,
}

/// Refuse, before any write, a batch that cannot be one atomic transaction.
fn check_batch(ops: &[SingleTableBatchOp]) -> Result<(), AppError> {
    if ops.len() > MAX_TRANSACT_ITEMS {
        return Err(AppError::Validation(format!(
            "write batch of {} operations exceeds the {MAX_TRANSACT_ITEMS}-operation limit of one atomic write",
            ops.len()
        )));
    }
    let mut seen = HashSet::with_capacity(ops.len());
    let mut bytes = 0usize;
    for op in ops {
        if !seen.insert(op.target()) {
            return Err(AppError::Validation(
                "write batch touches the same key more than once".into(),
            ));
        }
        bytes = bytes.saturating_add(op.size());
    }
    if bytes > BATCH_LIMITS.max_bytes {
        return Err(AppError::Validation(format!(
            "write batch of {bytes} bytes exceeds the {}-byte limit of one atomic write",
            BATCH_LIMITS.max_bytes
        )));
    }
    Ok(())
}

const INVALID_KEY: &str = "write batch contains a key that is not valid UTF-8";
const INVALID_KEYSPACE: &str = "write batch names a keyspace that is not allowed";

impl SingleTableBatch {
    /// The partition key for `keyspace`, or `None` for a name that must not be
    /// used (it would alias another namespace's partition).
    fn pk(&self, keyspace: &str) -> Option<String> {
        (!keyspace.contains(NAMESPACE_SEP)).then(|| pk_for(self.namespace.as_deref(), keyspace))
    }
}

impl BatchOps for SingleTableBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        // The batch API cannot return an error per operation, so an unusable
        // key or keyspace is recorded and the whole batch is refused at commit().
        match (self.pk(keyspace), key_as_string(&key)) {
            (Some(pk), Ok(sk)) => self.ops.push(SingleTableBatchOp::Insert {
                pk,
                name_len: keyspace.len(),
                sk,
                value,
            }),
            (None, _) => self.invalid = Some(INVALID_KEYSPACE),
            (_, Err(_)) => self.invalid = Some(INVALID_KEY),
        }
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        match (self.pk(keyspace), key_as_string(&key)) {
            (Some(pk), Ok(sk)) => self.ops.push(SingleTableBatchOp::Remove {
                pk,
                name_len: keyspace.len(),
                sk,
            }),
            (None, _) => self.invalid = Some(INVALID_KEYSPACE),
            (_, Err(_)) => self.invalid = Some(INVALID_KEY),
        }
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let Self {
                client,
                table_name,
                ops,
                invalid,
                ..
            } = *self;

            if let Some(reason) = invalid {
                return Err(AppError::Validation(reason.into()));
            }
            check_batch(&ops)?;
            if ops.is_empty() {
                return Ok(());
            }

            let mut items = Vec::with_capacity(ops.len());
            for op in ops {
                match op {
                    SingleTableBatchOp::Insert { pk, sk, value, .. } => {
                        let put = Put::builder()
                            .table_name(&table_name)
                            .item(PK_ATTR, AttributeValue::S(pk))
                            .item(SK_ATTR, AttributeValue::S(sk))
                            .item(VAL_ATTR, AttributeValue::B(Blob::new(value)))
                            .build()
                            .map_err(|e| {
                                AppError::Store(format!("dynamodb-single put build: {e}"))
                            })?;
                        items.push(TransactWriteItem::builder().put(put).build());
                    }
                    SingleTableBatchOp::Remove { pk, sk, .. } => {
                        let del = Delete::builder()
                            .table_name(&table_name)
                            .key(PK_ATTR, AttributeValue::S(pk))
                            .key(SK_ATTR, AttributeValue::S(sk))
                            .build()
                            .map_err(|e| {
                                AppError::Store(format!("dynamodb-single delete build: {e}"))
                            })?;
                        items.push(TransactWriteItem::builder().delete(del).build());
                    }
                }
            }

            // One call, one transaction: all of it applies or none of it does.
            client
                .transact_write_items()
                .set_transact_items(Some(items))
                .send()
                .await
                .map_err(|e| AppError::Store(format!("dynamodb-single transact: {e}")))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(pk: &str, sk: &str, val: &[u8]) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (PK_ATTR.to_string(), AttributeValue::S(pk.to_string())),
            (SK_ATTR.to_string(), AttributeValue::S(sk.to_string())),
            (
                VAL_ATTR.to_string(),
                AttributeValue::B(Blob::new(val.to_vec())),
            ),
        ])
    }

    #[test]
    fn extract_pairs_returns_sk_and_val() {
        let items = vec![
            item("dids", "did:alice", b"a"),
            item("dids", "did:bob", b"b"),
        ];
        let mut out = Vec::new();
        extract_pairs(items, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, b"did:alice");
        assert_eq!(out[0].1, b"a");
        assert_eq!(out[1].0, b"did:bob");
        assert_eq!(out[1].1, b"b");
    }

    #[test]
    fn extract_pairs_skips_items_missing_attrs() {
        // Missing sk (invalid — shouldn't happen with our schema, but
        // extract_pairs must not panic).
        let missing_sk = HashMap::from([
            (PK_ATTR.to_string(), AttributeValue::S("dids".to_string())),
            (
                VAL_ATTR.to_string(),
                AttributeValue::B(Blob::new(b"v".to_vec())),
            ),
        ]);
        // sk of wrong type (Binary instead of String).
        let wrong_sk_type = HashMap::from([
            (PK_ATTR.to_string(), AttributeValue::S("dids".to_string())),
            (
                SK_ATTR.to_string(),
                AttributeValue::B(Blob::new(b"did:x".to_vec())),
            ),
            (
                VAL_ATTR.to_string(),
                AttributeValue::B(Blob::new(b"v".to_vec())),
            ),
        ]);
        let items = vec![missing_sk, wrong_sk_type, item("dids", "did:z", b"v")];
        let mut out = Vec::new();
        extract_pairs(items, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, b"did:z");
    }

    #[test]
    fn extract_val_bytes_returns_binary() {
        let mut item = HashMap::new();
        item.insert(
            VAL_ATTR.to_string(),
            AttributeValue::B(Blob::new(b"hello".to_vec())),
        );
        assert_eq!(extract_val_bytes(item), Some(b"hello".to_vec()));
    }

    #[test]
    fn extract_val_bytes_rejects_non_binary() {
        let mut item = HashMap::new();
        item.insert(
            VAL_ATTR.to_string(),
            AttributeValue::S("not-binary".to_string()),
        );
        assert_eq!(extract_val_bytes(item), None);
    }

    #[test]
    fn key_as_string_accepts_utf8() {
        assert_eq!(key_as_string(b"did:alice").unwrap(), "did:alice");
        assert_eq!(key_as_string(b"").unwrap(), "");
        // Unicode is fine.
        assert_eq!(key_as_string("μ".as_bytes()).unwrap(), "μ");
    }

    #[test]
    fn key_as_string_rejects_non_utf8() {
        // 0xFF is never a valid UTF-8 start byte.
        let err = key_as_string(&[0xff, 0x00]).unwrap_err();
        match err {
            AppError::Store(msg) => assert!(msg.contains("not valid UTF-8")),
            other => panic!("expected AppError::Store, got {other:?}"),
        }
    }

    #[test]
    fn extract_pairs_preserves_order() {
        // Verify that order is preserved when extracting multiple items.
        let items = vec![
            item("ks", "z_item", b"z"),
            item("ks", "a_item", b"a"),
            item("ks", "m_item", b"m"),
        ];
        let mut out = Vec::new();
        extract_pairs(items, &mut out);
        assert_eq!(out.len(), 3);
        // Order comes from the input vector.
        assert_eq!(out[0].0, b"z_item");
        assert_eq!(out[1].0, b"a_item");
        assert_eq!(out[2].0, b"m_item");
    }

    #[test]
    fn extract_pairs_handles_empty_values() {
        // Values can be empty bytes.
        let items = vec![item("ks", "empty", b"")];
        let mut out = Vec::new();
        extract_pairs(items, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, b"empty");
        assert_eq!(out[0].1, b"");
    }

    #[test]
    fn extract_pairs_all_missing_returns_empty() {
        // All items missing required attributes.
        let items = vec![
            HashMap::from([(PK_ATTR.to_string(), AttributeValue::S("ks".to_string()))]),
            HashMap::from([(SK_ATTR.to_string(), AttributeValue::S("k".to_string()))]),
        ];
        let mut out = Vec::new();
        extract_pairs(items, &mut out);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn extract_val_bytes_with_empty_blob() {
        // Empty blob should still return Some.
        let mut item = HashMap::new();
        item.insert(
            VAL_ATTR.to_string(),
            AttributeValue::B(Blob::new(Vec::new())),
        );
        assert_eq!(extract_val_bytes(item), Some(Vec::new()));
    }

    #[test]
    fn extract_val_bytes_missing_val_attr() {
        // Item without VAL_ATTR returns None.
        let item = HashMap::from([(PK_ATTR.to_string(), AttributeValue::S("test".to_string()))]);
        assert_eq!(extract_val_bytes(item), None);
    }

    #[test]
    fn key_as_string_with_special_chars() {
        // UTF-8 strings with special characters should work.
        assert_eq!(
            key_as_string("special:chars:!@#$%".as_bytes()).unwrap(),
            "special:chars:!@#$%"
        );
        assert_eq!(
            key_as_string("path/to/resource".as_bytes()).unwrap(),
            "path/to/resource"
        );
    }

    fn insert(sk: &str, value_len: usize) -> SingleTableBatchOp {
        SingleTableBatchOp::Insert {
            pk: "ks".into(),
            name_len: 2,
            sk: sk.into(),
            value: vec![0; value_len],
        }
    }

    fn remove(sk: &str) -> SingleTableBatchOp {
        SingleTableBatchOp::Remove {
            pk: "ks".into(),
            name_len: 2,
            sk: sk.into(),
        }
    }

    fn is_validation(r: Result<(), AppError>) -> bool {
        matches!(r, Err(AppError::Validation(_)))
    }

    #[test]
    fn the_reported_byte_limit_reserves_attribute_name_overhead() {
        // 4 MiB minus, per operation (x 100): the attribute names ("pk", "sk",
        // "val" = 7 bytes) and the longest namespace plus its separator (33).
        assert_eq!(BATCH_LIMITS.max_ops, 100);
        assert_eq!(BATCH_LIMITS.max_bytes, 4 * 1024 * 1024 - 100 * (7 + 33));
    }

    #[test]
    fn check_batch_accepts_the_limit_and_refuses_one_more() {
        let at_limit: Vec<_> = (0..100).map(|i| insert(&format!("k{i:03}"), 1)).collect();
        assert!(check_batch(&at_limit).is_ok());
        let over: Vec<_> = (0..101).map(|i| insert(&format!("k{i:03}"), 1)).collect();
        assert!(is_validation(check_batch(&over)));
    }

    #[test]
    fn check_batch_counts_keyspace_key_and_value_bytes_against_the_byte_limit() {
        // One insert of keyspace "ks" (2) + key "k" (1) + value N is N + 3 bytes.
        let exact = BATCH_LIMITS.max_bytes - 3;
        assert!(check_batch(&[insert("k", exact)]).is_ok());
        assert!(is_validation(check_batch(&[insert("k", exact + 1)])));
    }

    #[test]
    fn check_batch_counts_removes_by_key_only() {
        // A remove carries no value: keyspace "ks" (2) + key (3 bytes) = 5.
        assert_eq!(remove("abc").size(), 5);
        assert!(check_batch(&[remove("abc"), remove("abd")]).is_ok());
    }

    #[test]
    fn check_batch_refuses_the_same_key_twice_but_not_the_same_key_in_two_keyspaces() {
        assert!(is_validation(check_batch(&[insert("k", 1), remove("k")])));
        let other = SingleTableBatchOp::Insert {
            pk: "other".into(),
            name_len: 5,
            sk: "k".into(),
            value: vec![],
        };
        assert!(check_batch(&[insert("k", 1), other]).is_ok());
    }

    // -----------------------------------------------------------------------
    // Request capture: assert what is sent on the wire, with no network.
    //
    // dynamodb-local cannot tell us whether a read was strongly consistent, so
    // the SDK's own interceptor hook records each serialised request and then
    // aborts before transmission.
    // -----------------------------------------------------------------------

    use aws_sdk_dynamodb::config::interceptors::BeforeTransmitInterceptorContextRef;
    use aws_sdk_dynamodb::config::{
        BehaviorVersion, ConfigBag, Credentials, Intercept, Region, RuntimeComponents,
    };
    use aws_sdk_dynamodb::error::BoxError;
    use std::sync::Mutex;

    /// One captured request: the DynamoDB operation and its JSON body.
    type Sent = (String, serde_json::Value);

    #[derive(Debug, Clone, Default)]
    struct Capture(Arc<Mutex<Vec<Sent>>>);

    impl Intercept for Capture {
        fn name(&self) -> &'static str {
            "capture"
        }

        fn read_before_transmit(
            &self,
            context: &BeforeTransmitInterceptorContextRef<'_>,
            _runtime_components: &RuntimeComponents,
            _cfg: &mut ConfigBag,
        ) -> Result<(), BoxError> {
            let request = context.request();
            let operation = request
                .headers()
                .get("x-amz-target")
                .and_then(|t| t.rsplit('.').next())
                .unwrap_or_default()
                .to_string();
            let body = request
                .body()
                .bytes()
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or(serde_json::Value::Null);
            self.0.lock().expect("capture lock").push((operation, body));
            // Abort before the network: the call returns an error we ignore.
            Err("captured".into())
        }
    }

    fn capturing_backend(consistent_reads: Option<bool>) -> (SingleTableDynamoDbBackend, Capture) {
        let capture = Capture::default();
        let conf = aws_sdk_dynamodb::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("k", "s", None, None, "test"))
            .interceptor(capture.clone())
            .build();
        let settings = Settings::from_config(&StoreConfig {
            dynamodb_table_name: Some("t".into()),
            dynamodb_consistent_reads: consistent_reads,
            ..StoreConfig::default()
        })
        .expect("settings");
        (
            SingleTableDynamoDbBackend::new(Client::from_conf(conf), settings),
            capture,
        )
    }

    /// Run every keyspace operation once and return what was sent, by operation.
    async fn exercise(backend: &SingleTableDynamoDbBackend, capture: &Capture) -> Vec<Sent> {
        let (_, ks) = backend.keyspace("meta").expect("keyspace");
        let _ = ks.get_raw(b"k".to_vec()).await;
        let _ = ks.contains_key(b"k".to_vec()).await;
        let _ = ks.prefix_iter_raw(b"p".to_vec()).await;
        let _ = ks.prefix_iter_raw(Vec::new()).await;
        let _ = ks.insert_raw(b"k".to_vec(), b"v".to_vec()).await;
        let _ = ks.remove(b"k".to_vec()).await;
        let _ = ks.take_raw_atomic(b"k".to_vec()).await;
        let _ = ks.incr_raw(b"k".to_vec()).await;
        capture.0.lock().expect("capture lock").clone()
    }

    fn consistent(body: &serde_json::Value) -> Option<bool> {
        body.get("ConsistentRead")
            .and_then(serde_json::Value::as_bool)
    }

    #[tokio::test]
    async fn reads_are_strongly_consistent_by_default() {
        let (backend, capture) = capturing_backend(None);
        let sent = exercise(&backend, &capture).await;

        let reads: Vec<_> = sent
            .iter()
            .filter(|(op, _)| op == "GetItem" || op == "Query")
            .collect();
        assert_eq!(
            reads.len(),
            4,
            "two GetItem (get, contains) and two Query (prefix, all): {sent:?}"
        );
        for (op, body) in reads {
            assert_eq!(
                consistent(body),
                Some(true),
                "{op} must be strongly consistent: {body}"
            );
        }
    }

    #[tokio::test]
    async fn reads_can_opt_out_of_strong_consistency() {
        let (backend, capture) = capturing_backend(Some(false));
        let sent = exercise(&backend, &capture).await;

        for (op, body) in sent
            .iter()
            .filter(|(op, _)| op == "GetItem" || op == "Query")
        {
            assert_ne!(consistent(body), Some(true), "{op} opted out: {body}");
        }
    }

    #[tokio::test]
    async fn writes_never_carry_a_consistency_flag() {
        let (backend, capture) = capturing_backend(None);
        let sent = exercise(&backend, &capture).await;

        for (op, body) in sent
            .iter()
            .filter(|(op, _)| matches!(op.as_str(), "PutItem" | "DeleteItem" | "UpdateItem"))
        {
            assert!(body.get("ConsistentRead").is_none(), "{op}: {body}");
        }
    }

    #[test]
    fn settings_default_to_strongly_consistent_reads() {
        let cfg = |reads| StoreConfig {
            dynamodb_table_name: Some("t".into()),
            dynamodb_consistent_reads: reads,
            ..StoreConfig::default()
        };
        assert!(Settings::from_config(&cfg(None)).unwrap().consistent_reads);
        assert!(
            Settings::from_config(&cfg(Some(true)))
                .unwrap()
                .consistent_reads
        );
        assert!(
            !Settings::from_config(&cfg(Some(false)))
                .unwrap()
                .consistent_reads
        );
    }

    #[test]
    fn the_partition_key_is_the_bare_keyspace_unless_a_namespace_is_set() {
        assert_eq!(pk_for(None, "dids"), "dids");
        assert_eq!(pk_for(Some("witness"), "dids"), "witness#dids");
    }

    #[test]
    fn namespaces_use_a_strict_allowlist() {
        for ok in ["witness", "a", "A1", "a-b_c.d", &"x".repeat(32)] {
            assert!(validate_namespace(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "a#b",
            "a b",
            "a/b",
            "caf\u{e9}",
            "a\nb",
            &"x".repeat(33),
        ] {
            assert!(validate_namespace(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn settings_validate_the_namespace_and_name_the_field() {
        let cfg = |ns: Option<&str>| StoreConfig {
            dynamodb_table_name: Some("t".into()),
            dynamodb_key_namespace: ns.map(str::to_string),
            ..StoreConfig::default()
        };
        assert_eq!(Settings::from_config(&cfg(None)).unwrap().namespace, None);
        assert_eq!(
            Settings::from_config(&cfg(Some("witness")))
                .unwrap()
                .namespace
                .as_deref(),
            Some("witness")
        );
        let err = Settings::from_config(&cfg(Some("a#b")))
            .err()
            .expect("refused");
        assert!(
            matches!(&err, AppError::Config(m) if m.contains("dynamodb_key_namespace")),
            "{err:?}"
        );
    }

    #[test]
    fn a_keyspace_name_with_a_hash_is_refused() {
        let (backend, _) = capturing_backend(None);
        assert!(backend.keyspace("dids").is_ok());
        assert!(backend.keyspace("witness#dids").is_err());
    }

    // -----------------------------------------------------------------------
    // Startup probe and table-name validation
    // -----------------------------------------------------------------------

    fn is_config_error_containing(r: Result<(), AppError>, needle: &str) -> bool {
        matches!(&r, Err(AppError::Config(m)) if m.contains(needle))
    }

    #[test]
    fn a_missing_table_is_a_definitive_configuration_error() {
        let r = probe_outcome(
            Some("ResourceNotFoundException"),
            Some("Requested resource not found"),
            "my-table",
        );
        assert!(is_config_error_containing(r, "my-table"));
        let r = probe_outcome(Some("ResourceNotFoundException"), None, "my-table");
        assert!(is_config_error_containing(r, "not found"));
    }

    #[test]
    fn a_wrong_key_schema_is_a_definitive_configuration_error() {
        let r = probe_outcome(
            Some("ValidationException"),
            Some("The provided key element does not match the schema"),
            "my-table",
        );
        assert!(
            is_config_error_containing(r, "key schema"),
            "names the expected schema"
        );
    }

    #[test]
    fn anything_else_is_inconclusive_and_never_blocks_startup() {
        for code in [
            Some("AccessDeniedException"),
            Some("ThrottlingException"),
            Some("ProvisionedThroughputExceededException"),
            Some("InternalServerError"),
            None, // a dispatch failure or timeout carries no service code
        ] {
            assert!(probe_outcome(code, None, "t").is_ok(), "{code:?}");
        }
    }

    #[tokio::test]
    async fn the_probe_is_a_consistent_get_item_then_a_one_row_query_on_a_reserved_key() {
        let (backend, capture) = capturing_backend(None);
        // The captured requests are aborted before the network: inconclusive, so Ok.
        backend
            .probe()
            .await
            .expect("an inconclusive probe must not fail startup");

        let sent = capture.0.lock().expect("capture lock").clone();
        assert_eq!(sent.len(), 2, "exactly two requests: {sent:?}");
        let (op, body) = &sent[0];
        assert_eq!(
            op, "GetItem",
            "the only permission the backend already needs"
        );
        assert_eq!(body["Key"]["pk"]["S"], "_probe");
        assert_eq!(consistent(body), Some(true));

        // The query tells the partition key from the sort key: equality on `pk`,
        // `begins_with` on `sk`, as every prefix listing does.
        let (op, body) = &sent[1];
        assert_eq!(op, "Query");
        assert_eq!(
            body["KeyConditionExpression"],
            "#pk = :ks AND begins_with(#sk, :pfx)"
        );
        assert_eq!(body["ExpressionAttributeNames"]["#pk"], "pk");
        assert_eq!(body["ExpressionAttributeNames"]["#sk"], "sk");
        assert_eq!(body["ExpressionAttributeValues"][":ks"]["S"], "_probe");
        assert_eq!(body["ExpressionAttributeValues"][":pfx"]["S"], "_probe");
        assert_eq!(body["Limit"], 1, "one row is enough to prove the schema");
        assert_eq!(consistent(body), Some(true));
    }

    #[tokio::test]
    async fn the_probe_follows_the_namespace() {
        let capture = Capture::default();
        let conf = aws_sdk_dynamodb::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("k", "s", None, None, "test"))
            .interceptor(capture.clone())
            .build();
        let settings = Settings::from_config(&StoreConfig {
            dynamodb_table_name: Some("t".into()),
            dynamodb_key_namespace: Some("witness".into()),
            ..StoreConfig::default()
        })
        .expect("settings");
        let backend = SingleTableDynamoDbBackend::new(Client::from_conf(conf), settings);
        backend.probe().await.expect("probe");
        let sent = capture.0.lock().expect("capture lock").clone();
        assert_eq!(sent[0].1["Key"]["pk"]["S"], "witness#_probe");
        assert_eq!(
            sent[1].1["ExpressionAttributeValues"][":ks"]["S"],
            "witness#_probe"
        );
    }

    #[test]
    fn a_blank_table_name_is_refused() {
        for blank in ["", " ", "\t\n"] {
            let r = Settings::from_config(&StoreConfig {
                dynamodb_table_name: Some(blank.into()),
                ..StoreConfig::default()
            });
            assert!(
                matches!(&r, Err(AppError::Config(m)) if m.contains("dynamodb_table_name")),
                "{blank:?}"
            );
        }
        assert!(
            Settings::from_config(&StoreConfig {
                dynamodb_table_name: Some("webvh".into()),
                ..StoreConfig::default()
            })
            .is_ok()
        );
    }
}

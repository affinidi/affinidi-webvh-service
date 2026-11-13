use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeValue, Delete, KeySchemaElement, KeyType, ProvisionedThroughput, Put, ReturnValue,
    ScalarAttributeType, TransactWriteItem,
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::server::config::StoreConfig;
use crate::server::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, PrefixPage, RawKvPair, StorageBackend};

const PK_ATTR: &str = "pk";
const VAL_ATTR: &str = "val";
/// Numeric attribute `incr_raw` adds to atomically — kept apart from
/// `VAL_ATTR` so an increment never collides with a JSON blob some other
/// caller stores at the same partition key.
const CNT_ATTR: &str = "cnt";

/// DynamoDB's error codes for a request refused because the table or the
/// account is over its throughput, after the SDK's own retries.
const THROTTLING_CODES: &[&str] = &[
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
];

/// The same, as a reason a cancelled transaction gives for one of its items.
const THROTTLED_CANCELLATION_CODES: &[&str] = &["ThrottlingError", "ProvisionedThroughputExceeded"];

/// A failed request as an [`AppError`]: throttling is
/// [`AppError::RateLimited`], so it reaches the client as "retry later"
/// rather than as a fault; anything else stays [`AppError::Store`].
fn request_error<E, R>(op: &str, e: SdkError<E, R>) -> AppError
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    if e.code()
        .is_some_and(|code| THROTTLING_CODES.contains(&code))
    {
        warn!(op, error = %DisplayErrorContext(&e), "dynamodb throttled");
        return AppError::store_throttled();
    }
    AppError::Store(format!("dynamodb {op}: {e}"))
}

/// [`request_error`] for `TransactWriteItems`, whose throttling can also
/// arrive as a cancelled transaction naming throttling as an item's reason.
fn transact_error<R: std::fmt::Debug>(e: SdkError<TransactWriteItemsError, R>) -> AppError {
    if let Some(TransactWriteItemsError::TransactionCanceledException(cancelled)) =
        e.as_service_error()
        && cancelled.cancellation_reasons().iter().any(|reason| {
            reason
                .code()
                .is_some_and(|code| THROTTLED_CANCELLATION_CODES.contains(&code))
        })
    {
        warn!(error = %DisplayErrorContext(&e), "dynamodb transaction throttled");
        return AppError::store_throttled();
    }
    request_error("transact", e)
}

/// DynamoDB's item size limit, 400 KB: attribute names and values together.
const MAX_ITEM_BYTES: usize = 400 * 1024;

/// Refuse a `pk`/`val` item DynamoDB would reject as too large.
fn check_item_size(key: &[u8], value: &[u8]) -> Result<(), AppError> {
    let size = PK_ATTR.len() + key.len() + VAL_ATTR.len() + value.len();
    super::check_item_size("DynamoDB", size, MAX_ITEM_BYTES)
}

// ---------------------------------------------------------------------------
// DynamoDbBackend
// ---------------------------------------------------------------------------

pub struct DynamoDbBackend {
    client: Client,
    table_prefix: String,
    verified_tables: Arc<RwLock<HashSet<String>>>,
}

impl DynamoDbBackend {
    pub async fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        let table_prefix = config
            .dynamodb_table_prefix
            .clone()
            .unwrap_or_else(|| "webvh".to_string());

        let mut aws_config_loader = aws_config::from_env();
        if let Some(ref region) = config.dynamodb_region {
            aws_config_loader = aws_config_loader.region(aws_config::Region::new(region.clone()));
        }
        let aws_config = aws_config_loader.load().await;
        let client = Client::new(&aws_config);

        info!(table_prefix, "opening dynamodb store");

        Ok(Box::new(Self {
            client,
            table_prefix,
            verified_tables: Arc::new(RwLock::new(HashSet::new())),
        }))
    }

    fn table_name(&self, keyspace: &str) -> String {
        format!("{}_{}", self.table_prefix, keyspace)
    }

    fn open_keyspace(
        &self,
        name: &str,
        consistent_read: bool,
        consistent_scan: bool,
    ) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        Ok((
            name.to_string(),
            Arc::new(DynamoDbKeyspace {
                client: self.client.clone(),
                table: self.table_name(name),
                verified: self.verified_tables.clone(),
                consistent_read,
                consistent_scan,
            }),
        ))
    }
}

impl StorageBackend for DynamoDbBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        self.open_keyspace(name, false, false)
    }

    fn keyspace_consistent(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        self.open_keyspace(name, true, false)
    }

    fn keyspace_consistent_with_scans(
        &self,
        name: &str,
    ) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        self.open_keyspace(name, true, true)
    }

    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(DynamoDbBatch {
            client: self.client.clone(),
            table_prefix: self.table_prefix.clone(),
            ops: Vec::new(),
        })
    }

    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>> {
        // DynamoDB is fully managed; no-op.
        Box::pin(async { Ok(()) })
    }
}

/// Ensure a DynamoDB table exists, creating it if necessary.
/// Results are cached in `verified` so subsequent calls for the same table are no-ops.
async fn ensure_table(
    client: &Client,
    table: &str,
    verified: &RwLock<HashSet<String>>,
) -> Result<(), AppError> {
    // Fast path: already verified
    if verified.read().await.contains(table) {
        return Ok(());
    }

    match client.describe_table().table_name(table).send().await {
        Ok(_) => {}
        Err(_) => {
            client
                .create_table()
                .table_name(table)
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name(PK_ATTR)
                        .key_type(KeyType::Hash)
                        .build()
                        .map_err(|e| AppError::Store(format!("dynamodb schema: {e}")))?,
                )
                .attribute_definitions(
                    aws_sdk_dynamodb::types::AttributeDefinition::builder()
                        .attribute_name(PK_ATTR)
                        .attribute_type(ScalarAttributeType::B)
                        .build()
                        .map_err(|e| AppError::Store(format!("dynamodb attr def: {e}")))?,
                )
                .provisioned_throughput(
                    ProvisionedThroughput::builder()
                        .read_capacity_units(5)
                        .write_capacity_units(5)
                        .build()
                        .map_err(|e| AppError::Store(format!("dynamodb throughput: {e}")))?,
                )
                .send()
                .await
                .map_err(|e| AppError::Store(format!("dynamodb create table: {e}")))?;
        }
    }

    verified.write().await.insert(table.to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// DynamoDbKeyspace
// ---------------------------------------------------------------------------

struct DynamoDbKeyspace {
    client: Client,
    table: String,
    verified: Arc<RwLock<HashSet<String>>>,
    /// Send `GetItem` with `ConsistentRead`, so a read sees every write
    /// that committed before it. Off by default: an eventually consistent
    /// read costs half the read units and is fine where a stale answer
    /// decides nothing.
    consistent_read: bool,
    /// Send `Scan` with `ConsistentRead` too. Separate from
    /// `consistent_read` because a scan reads the whole table: doubling
    /// that is only worth it on a small keyspace.
    consistent_scan: bool,
}

impl KeyspaceOps for DynamoDbKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            check_item_size(&key, &value)?;
            ensure_table(&self.client, &self.table, &self.verified).await?;
            self.client
                .put_item()
                .table_name(&self.table)
                .item(PK_ATTR, AttributeValue::B(Blob::new(key)))
                .item(VAL_ATTR, AttributeValue::B(Blob::new(value)))
                .send()
                .await
                .map_err(|e| request_error("put", e))?;
            Ok(())
        })
    }

    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            ensure_table(&self.client, &self.table, &self.verified).await?;
            let result = self
                .client
                .get_item()
                .table_name(&self.table)
                .key(PK_ATTR, AttributeValue::B(Blob::new(key)))
                .consistent_read(self.consistent_read)
                .send()
                .await
                .map_err(|e| request_error("get", e))?;

            Ok(result.item.and_then(|item| {
                item.get(VAL_ATTR).and_then(|attr| {
                    if let AttributeValue::B(blob) = attr {
                        Some(blob.as_ref().to_vec())
                    } else {
                        None
                    }
                })
            }))
        })
    }

    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            ensure_table(&self.client, &self.table, &self.verified).await?;
            self.client
                .delete_item()
                .table_name(&self.table)
                .key(PK_ATTR, AttributeValue::B(Blob::new(key)))
                .send()
                .await
                .map_err(|e| request_error("delete", e))?;
            Ok(())
        })
    }

    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            ensure_table(&self.client, &self.table, &self.verified).await?;
            let result = self
                .client
                .get_item()
                .table_name(&self.table)
                .key(PK_ATTR, AttributeValue::B(Blob::new(key)))
                .projection_expression(PK_ATTR)
                .consistent_read(self.consistent_read)
                .send()
                .await
                .map_err(|e| request_error("get", e))?;
            Ok(result.item.is_some())
        })
    }

    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            ensure_table(&self.client, &self.table, &self.verified).await?;
            // DeleteItem with ReturnValues=ALL_OLD atomically removes the
            // item and returns the previous attributes — exactly the
            // get-and-remove primitive we need. DynamoDB serialises the
            // operation per partition key, so two concurrent callers see
            // exactly one non-empty response.
            let response = self
                .client
                .delete_item()
                .table_name(&self.table)
                .key(PK_ATTR, AttributeValue::B(Blob::new(key)))
                .return_values(ReturnValue::AllOld)
                .send()
                .await
                .map_err(|e| request_error("delete (atomic take)", e))?;
            Ok(response.attributes.and_then(|attrs| {
                attrs.get(VAL_ATTR).and_then(|attr| {
                    if let AttributeValue::B(blob) = attr {
                        Some(blob.as_ref().to_vec())
                    } else {
                        None
                    }
                })
            }))
        })
    }

    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        Box::pin(async move {
            ensure_table(&self.client, &self.table, &self.verified).await?;
            // `ADD` on a Number attribute is DynamoDB's native atomic
            // counter: the read-modify-write happens server-side under the
            // partition key's lock, so two replicas racing this call each
            // get a distinct, correctly-ordered result — never the same
            // next value twice. `UpdatedNew` returns the post-increment
            // value in the same round trip.
            let response = self
                .client
                .update_item()
                .table_name(&self.table)
                .key(PK_ATTR, AttributeValue::B(Blob::new(key)))
                .update_expression("ADD #cnt :one")
                .expression_attribute_names("#cnt", CNT_ATTR)
                .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
                .return_values(ReturnValue::UpdatedNew)
                .send()
                .await
                .map_err(|e| request_error("update (incr)", e))?;
            let n = response
                .attributes
                .as_ref()
                .and_then(|attrs| attrs.get(CNT_ATTR))
                .and_then(|attr| match attr {
                    AttributeValue::N(s) => s.parse::<u64>().ok(),
                    _ => None,
                })
                .ok_or_else(|| {
                    AppError::Store("dynamodb incr: no numeric counter in response".into())
                })?;
            Ok(n)
        })
    }

    fn compare_and_swap_raw(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            check_item_size(&key, &new)?;
            ensure_table(&self.client, &self.table, &self.verified).await?;
            // A conditional `PutItem`: DynamoDB evaluates the condition and
            // writes under the partition key's lock, so of any number of
            // replicas swapping from the same value, one wins and the rest
            // fail the condition.
            let request = self
                .client
                .put_item()
                .table_name(&self.table)
                .item(PK_ATTR, AttributeValue::B(Blob::new(key)))
                .item(VAL_ATTR, AttributeValue::B(Blob::new(new)));
            let request = match expected {
                Some(expected) => request
                    .condition_expression("#val = :expected")
                    .expression_attribute_names("#val", VAL_ATTR)
                    .expression_attribute_values(
                        ":expected",
                        AttributeValue::B(Blob::new(expected)),
                    ),
                None => request
                    .condition_expression("attribute_not_exists(#pk)")
                    .expression_attribute_names("#pk", PK_ATTR),
            };
            match request.send().await {
                Ok(_) => Ok(true),
                Err(e)
                    if e.as_service_error()
                        .is_some_and(PutItemError::is_conditional_check_failed_exception) =>
                {
                    Ok(false)
                }
                Err(e) => Err(request_error("put (compare-and-swap)", e)),
            }
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            ensure_table(&self.client, &self.table, &self.verified).await?;

            // Single full-table Scan, filtered client-side. The table has no
            // sort key (`pk` is the only attribute and it's the HASH key), so
            // a Query-by-prefix isn't possible; and a Scan `begins_with`
            // filter on a Binary `pk` is both unreliable across
            // implementations (notably motoserver) and doesn't reduce read
            // capacity. `filter_items_by_prefix` applies byte-prefix
            // semantics in Rust — an empty prefix matches everything.
            let mut results = Vec::new();
            let mut last_key: Option<HashMap<String, AttributeValue>> = None;
            loop {
                let mut req = self
                    .client
                    .scan()
                    .table_name(&self.table)
                    .consistent_read(self.consistent_scan);
                if let Some(ref key) = last_key {
                    req = req.set_exclusive_start_key(Some(key.clone()));
                }
                let resp = req.send().await.map_err(|e| request_error("scan", e))?;

                if let Some(items) = resp.items {
                    filter_items_by_prefix(items, &prefix, &mut results);
                }

                last_key = resp.last_evaluated_key;
                if last_key.is_none() {
                    break;
                }
            }

            Ok(results)
        })
    }

    /// One `Scan` request: `limit` items evaluated from where the last page
    /// stopped, filtered to `prefix` as [`Self::prefix_iter_raw`] filters.
    /// The table has only a hash key, so pages come in hash order
    /// (`ordered: false`) and may be empty while more follow. The cursor is
    /// the `pk` of the last item evaluated (`LastEvaluatedKey`), which
    /// stays a valid start even once that item is deleted, so a caller can
    /// delete behind it.
    fn prefix_page_raw(
        &self,
        prefix: Vec<u8>,
        cursor: Option<Vec<u8>>,
        limit: usize,
    ) -> BoxFuture<'_, Result<Option<PrefixPage>, AppError>> {
        Box::pin(async move {
            ensure_table(&self.client, &self.table, &self.verified).await?;
            let mut req = self
                .client
                .scan()
                .table_name(&self.table)
                .consistent_read(self.consistent_scan)
                .limit(i32::try_from(limit.max(1)).unwrap_or(i32::MAX));
            if let Some(pk) = cursor {
                req = req.exclusive_start_key(PK_ATTR, AttributeValue::B(Blob::new(pk)));
            }
            let resp = req.send().await.map_err(|e| request_error("scan", e))?;
            let mut page = PrefixPage::default();
            if let Some(items) = resp.items {
                filter_items_by_prefix(items, &prefix, &mut page.rows);
            }
            page.next = resp
                .last_evaluated_key
                .and_then(|key| match key.get(PK_ATTR) {
                    Some(AttributeValue::B(pk)) => Some(pk.as_ref().to_vec()),
                    _ => None,
                });
            Ok(Some(page))
        })
    }
}

/// Reduce one page of scanned items to the `(pk, val)` byte pairs whose key
/// begins with `prefix`, appending them to `out`.
///
/// Byte-prefix semantics (`pk.starts_with(prefix)`) are applied here in Rust
/// rather than delegated to a DynamoDB `Scan` filter expression: `begins_with`
/// on a Binary attribute is unreliable across DynamoDB implementations
/// (notably the motoserver emulator returns nothing), and a `Scan` filter
/// doesn't reduce consumed read capacity anyway. An empty `prefix` matches
/// every item. Items missing a Binary `pk`/`val` are skipped.
fn filter_items_by_prefix(
    items: Vec<HashMap<String, AttributeValue>>,
    prefix: &[u8],
    out: &mut Vec<RawKvPair>,
) {
    for item in items {
        if let (Some(AttributeValue::B(pk)), Some(AttributeValue::B(val))) =
            (item.get(PK_ATTR), item.get(VAL_ATTR))
        {
            let pk_bytes = pk.as_ref();
            if pk_bytes.starts_with(prefix) {
                out.push((pk_bytes.to_vec(), val.as_ref().to_vec()));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DynamoDbBatch
// ---------------------------------------------------------------------------

enum DynamoDbBatchOp {
    Insert {
        table: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Remove {
        table: String,
        key: Vec<u8>,
    },
}

struct DynamoDbBatch {
    client: Client,
    table_prefix: String,
    ops: Vec<DynamoDbBatchOp>,
}

impl BatchOps for DynamoDbBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        let table = format!("{}_{}", self.table_prefix, keyspace);
        self.ops.push(DynamoDbBatchOp::Insert { table, key, value });
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        let table = format!("{}_{}", self.table_prefix, keyspace);
        self.ops.push(DynamoDbBatchOp::Remove { table, key });
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let ops = prepare_ops(self.ops)?;
            if ops.is_empty() {
                return Ok(());
            }
            // One transaction, so the batch lands whole or not at all. A batch
            // over the bound is refused here, before anything is sent, rather
            // than split into transactions that could land part-way.
            let bytes: usize = ops.iter().map(DynamoDbBatchOp::size).sum();
            if ops.len() > MAX_TRANSACT_ACTIONS || bytes > MAX_TRANSACT_BYTES {
                warn!(
                    writes = ops.len(),
                    bytes, "batch refused: over one DynamoDB transaction"
                );
                // `AppError::quota_kind` keys on the word "size".
                return Err(AppError::QuotaExceeded(format!(
                    "a change of {} writes ({bytes} bytes) is over the store's \
                     size limit for one atomic write: {MAX_TRANSACT_ACTIONS} \
                     writes and {MAX_TRANSACT_BYTES} bytes",
                    ops.len()
                )));
            }
            send_transaction(&self.client, &ops).await
        })
    }

    fn commit_in_parts(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let ops = prepare_ops(self.ops)?;
            for part in split_transactions(&ops) {
                send_transaction(&self.client, part).await?;
            }
            Ok(())
        })
    }
}

/// `TransactWriteItems` takes at most 100 actions.
const MAX_TRANSACT_ACTIONS: usize = 100;

/// `TransactWriteItems` takes at most 4 MB of items in all. Counted as
/// 4,000,000 bytes, not 4 MiB, so the bound errs on the side of refusing.
const MAX_TRANSACT_BYTES: usize = 4_000_000;

impl DynamoDbBatchOp {
    fn target(&self) -> (&str, &[u8]) {
        match self {
            Self::Insert { table, key, .. } | Self::Remove { table, key } => (table, key),
        }
    }

    /// The size DynamoDB counts against a transaction: a put's whole item, a
    /// delete's key.
    fn size(&self) -> usize {
        match self {
            Self::Insert { key, value, .. } => {
                PK_ATTR.len() + key.len() + VAL_ATTR.len() + value.len()
            }
            Self::Remove { key, .. } => PK_ATTR.len() + key.len(),
        }
    }
}

/// Check every item fits, then keep only the last operation on each item.
///
/// The size check runs over every operation before anything is sent, so a
/// refused item writes nothing. DynamoDB refuses a transaction that names an
/// item twice; applied in order, the batch leaves each item as its last
/// operation says, so that is the one kept.
fn prepare_ops(ops: Vec<DynamoDbBatchOp>) -> Result<Vec<DynamoDbBatchOp>, AppError> {
    for op in &ops {
        if let DynamoDbBatchOp::Insert { key, value, .. } = op {
            check_item_size(key, value)?;
        }
    }
    let mut last = HashMap::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        let (table, key) = op.target();
        last.insert((table.to_owned(), key.to_vec()), i);
    }
    Ok(ops
        .into_iter()
        .enumerate()
        .filter(|(i, op)| {
            let (table, key) = op.target();
            last.get(&(table.to_owned(), key.to_vec())) == Some(i)
        })
        .map(|(_, op)| op)
        .collect())
}

/// Split operations into runs that each fit one transaction. Every item
/// already fits on its own ([`check_item_size`]), so no run is empty.
fn split_transactions(ops: &[DynamoDbBatchOp]) -> Vec<&[DynamoDbBatchOp]> {
    let mut parts = Vec::new();
    let (mut start, mut bytes) = (0, 0);
    for (i, op) in ops.iter().enumerate() {
        let size = op.size();
        if i > start && (i - start == MAX_TRANSACT_ACTIONS || bytes + size > MAX_TRANSACT_BYTES) {
            parts.push(&ops[start..i]);
            (start, bytes) = (i, 0);
        }
        bytes += size;
    }
    if start < ops.len() {
        parts.push(&ops[start..]);
    }
    parts
}

/// Send `ops` as one `TransactWriteItems`.
async fn send_transaction(client: &Client, ops: &[DynamoDbBatchOp]) -> Result<(), AppError> {
    let mut items = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            DynamoDbBatchOp::Insert { table, key, value } => {
                let put = Put::builder()
                    .table_name(table)
                    .item(PK_ATTR, AttributeValue::B(Blob::new(key.clone())))
                    .item(VAL_ATTR, AttributeValue::B(Blob::new(value.clone())))
                    .build()
                    .map_err(|e| AppError::Store(format!("dynamodb put build: {e}")))?;
                items.push(TransactWriteItem::builder().put(put).build());
            }
            DynamoDbBatchOp::Remove { table, key } => {
                let del = Delete::builder()
                    .table_name(table)
                    .key(PK_ATTR, AttributeValue::B(Blob::new(key.clone())))
                    .build()
                    .map_err(|e| AppError::Store(format!("dynamodb delete build: {e}")))?;
                items.push(TransactWriteItem::builder().delete(del).build());
            }
        }
    }
    client
        .transact_write_items()
        .set_transact_items(Some(items))
        .send()
        .await
        .map_err(transact_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use aws_sdk_dynamodb::config::interceptors::BeforeTransmitInterceptorContextRef;
    use aws_sdk_dynamodb::config::{
        BehaviorVersion, ConfigBag, Credentials, Intercept, Region, RuntimeComponents,
    };
    use aws_sdk_dynamodb::error::ErrorMetadata;
    use aws_sdk_dynamodb::operation::get_item::GetItemError;
    use aws_sdk_dynamodb::types::CancellationReason;
    use aws_sdk_dynamodb::types::error::TransactionCanceledException;

    use super::*;

    fn get_failure(code: &str) -> SdkError<GetItemError, ()> {
        SdkError::service_error(
            GetItemError::generic(ErrorMetadata::builder().code(code).build()),
            (),
        )
    }

    #[test]
    fn throttling_is_rate_limited_and_other_failures_stay_store_errors() {
        for code in THROTTLING_CODES {
            let e = request_error("get", get_failure(code));
            assert!(e.is_store_throttled(), "{code}: {e:?}");
        }
        assert!(matches!(
            request_error("get", get_failure("ResourceNotFoundException")),
            AppError::Store(_)
        ));
    }

    #[test]
    fn a_transaction_cancelled_for_throttling_is_rate_limited() {
        let cancelled = |code: &str| {
            SdkError::<_, ()>::service_error(
                TransactWriteItemsError::TransactionCanceledException(
                    TransactionCanceledException::builder()
                        .cancellation_reasons(CancellationReason::builder().code("None").build())
                        .cancellation_reasons(CancellationReason::builder().code(code).build())
                        .build(),
                ),
                (),
            )
        };
        for code in THROTTLED_CANCELLATION_CODES {
            assert!(
                transact_error(cancelled(code)).is_store_throttled(),
                "{code}"
            );
        }
        assert!(matches!(
            transact_error(cancelled("ConditionalCheckFailed")),
            AppError::Store(_)
        ));
    }

    /// Records each request body and stops it before it leaves the process.
    #[derive(Debug, Default, Clone)]
    struct CaptureBodies(Arc<Mutex<Vec<String>>>);

    impl Intercept for CaptureBodies {
        fn name(&self) -> &'static str {
            "CaptureBodies"
        }

        fn read_before_transmit(
            &self,
            context: &BeforeTransmitInterceptorContextRef<'_>,
            _runtime_components: &RuntimeComponents,
            _cfg: &mut ConfigBag,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let body = context.request().body().bytes().unwrap_or_default();
            self.0
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(body).into_owned());
            Err("request captured".into())
        }
    }

    fn offline_backend(capture: &CaptureBodies) -> DynamoDbBackend {
        let config = aws_sdk_dynamodb::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .endpoint_url("http://127.0.0.1:1")
            .interceptor(capture.clone())
            .build();
        DynamoDbBackend {
            client: Client::from_conf(config),
            table_prefix: "webvh".into(),
            // Marked as present so `ensure_table` sends nothing.
            verified_tables: Arc::new(RwLock::new(HashSet::from(["webvh_dids".to_string()]))),
        }
    }

    async fn read_requests(ops: Arc<dyn KeyspaceOps>, capture: &CaptureBodies) -> Vec<String> {
        assert!(ops.get_raw(b"did:a".to_vec()).await.is_err());
        assert!(ops.contains_key(b"did:a".to_vec()).await.is_err());
        std::mem::take(&mut *capture.0.lock().unwrap())
    }

    #[tokio::test]
    async fn consistent_keyspace_reads_strongly_consistent() {
        let capture = CaptureBodies::default();
        let backend = offline_backend(&capture);

        let (_, ops) = backend.keyspace_consistent("dids").unwrap();
        let bodies = read_requests(ops, &capture).await;
        assert_eq!(bodies.len(), 2, "get_raw and contains_key: {bodies:?}");
        for body in &bodies {
            assert!(body.contains(r#""ConsistentRead":true"#), "{body}");
        }

        let (_, ops) = backend.keyspace("dids").unwrap();
        let bodies = read_requests(ops, &capture).await;
        assert_eq!(bodies.len(), 2, "get_raw and contains_key: {bodies:?}");
        for body in &bodies {
            assert!(!body.contains(r#""ConsistentRead":true"#), "{body}");
        }
    }

    #[tokio::test]
    async fn only_a_with_scans_keyspace_scans_strongly_consistent() {
        let capture = CaptureBodies::default();
        let backend = offline_backend(&capture);
        let scan = async |ops: Arc<dyn KeyspaceOps>| {
            assert!(ops.prefix_iter_raw(b"did:".to_vec()).await.is_err());
            let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
            assert_eq!(bodies.len(), 1, "one scan: {bodies:?}");
            bodies[0].contains(r#""ConsistentRead":true"#)
        };

        assert!(scan(backend.keyspace_consistent_with_scans("dids").unwrap().1).await);
        assert!(!scan(backend.keyspace_consistent("dids").unwrap().1).await);
        assert!(!scan(backend.keyspace("dids").unwrap().1).await);
    }

    /// A page is one `Scan` request of `limit` items, resumed from the
    /// cursor as its `ExclusiveStartKey`, never a whole-table read.
    #[tokio::test]
    async fn a_prefix_page_is_one_scan_request_from_the_cursor() {
        let capture = CaptureBodies::default();
        let backend = offline_backend(&capture);
        let (_, ops) = backend.keyspace("dids").unwrap();

        assert!(
            ops.prefix_page_raw(b"ts:".to_vec(), None, 50)
                .await
                .is_err()
        );
        assert!(
            ops.prefix_page_raw(b"ts:".to_vec(), Some(b"ts:a:300".to_vec()), 50)
                .await
                .is_err()
        );
        let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
        assert_eq!(bodies.len(), 2, "one scan a page: {bodies:?}");
        for body in &bodies {
            assert!(body.contains(r#""Limit":50"#), "{body}");
        }
        assert!(!bodies[0].contains("ExclusiveStartKey"), "{}", bodies[0]);
        // base64("ts:a:300")
        assert!(
            bodies[1].contains(r#""ExclusiveStartKey":{"pk":{"B":"dHM6YTozMDA="}}"#),
            "{}",
            bodies[1]
        );
    }

    fn batch_of(backend: &DynamoDbBackend, ops: &[(&[u8], Option<usize>)]) -> Box<dyn BatchOps> {
        let mut batch = backend.batch();
        for (key, value_len) in ops {
            match value_len {
                Some(len) => batch.insert_raw("dids", key.to_vec(), vec![b'x'; *len]),
                None => batch.remove("dids", key.to_vec()),
            }
        }
        batch
    }

    fn keys(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("did:{i}").into_bytes()).collect()
    }

    /// A batch is one transaction: up to 100 writes is sent as one request,
    /// more is refused as a size quota with nothing sent, rather than split
    /// into transactions that could land part-way.
    #[tokio::test]
    async fn an_atomic_batch_over_100_writes_is_refused_before_sending() {
        let capture = CaptureBodies::default();
        let backend = offline_backend(&capture);

        let keys = keys(101);
        let ops: Vec<_> = keys.iter().map(|k| (k.as_slice(), Some(10))).collect();

        // At the bound: sent (the offline client then fails the send).
        assert!(batch_of(&backend, &ops[..100]).commit().await.is_err());
        let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
        assert_eq!(bodies.len(), 1, "{bodies:?}");
        assert_eq!(bodies[0].matches(r#"{"Put":"#).count(), 100);

        let err = batch_of(&backend, &ops).commit().await.unwrap_err();
        assert!(matches!(err, AppError::QuotaExceeded(_)), "{err:?}");
        assert_eq!(err.quota_kind(), crate::server::error::QuotaKind::Size);
        assert!(capture.0.lock().unwrap().is_empty(), "nothing is sent");
    }

    /// Eleven items that each fit are over 4 MB together: refused, nothing sent.
    #[tokio::test]
    async fn an_atomic_batch_over_4_mb_is_refused_before_sending() {
        let capture = CaptureBodies::default();
        let backend = offline_backend(&capture);

        let keys = keys(11);
        let ops: Vec<_> = keys
            .iter()
            .map(|k| (k.as_slice(), Some(390 * 1024)))
            .collect();
        let err = batch_of(&backend, &ops).commit().await.unwrap_err();
        assert!(matches!(err, AppError::QuotaExceeded(_)), "{err:?}");
        assert!(capture.0.lock().unwrap().is_empty(), "nothing is sent");
    }

    /// DynamoDB refuses a transaction naming an item twice, so a batch keeps
    /// only each item's last operation: the one that decides its final state.
    #[tokio::test]
    async fn a_batch_writing_one_item_twice_sends_its_last_operation() {
        let capture = CaptureBodies::default();
        let backend = offline_backend(&capture);

        let ops: &[(&[u8], Option<usize>)] = &[
            (b"did:a", Some(1)),
            (b"did:b", None),
            (b"did:a", None),
            (b"did:b", Some(2)),
            (b"did:c", None),
        ];
        assert!(batch_of(&backend, ops).commit().await.is_err());
        let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
        assert_eq!(bodies.len(), 1, "{bodies:?}");
        // did:a deleted, did:b put, did:c deleted.
        assert_eq!(bodies[0].matches(r#"{"Put":"#).count(), 1, "{}", bodies[0]);
        assert_eq!(
            bodies[0].matches(r#"{"Delete":"#).count(),
            2,
            "{}",
            bodies[0]
        );
    }

    /// `commit_in_parts` splits on both bounds, keeping every operation once
    /// and in order.
    #[test]
    fn parts_stay_within_100_writes_and_4_mb() {
        let op = |key: Vec<u8>, len| DynamoDbBatchOp::Insert {
            table: "webvh_dids".into(),
            key,
            value: vec![b'x'; len],
        };

        let small: Vec<_> = keys(250).into_iter().map(|k| op(k, 10)).collect();
        let parts = split_transactions(&small);
        let lens: Vec<_> = parts.iter().map(|p| p.len()).collect();
        assert_eq!(lens, [100, 100, 50]);

        let large: Vec<_> = keys(30).into_iter().map(|k| op(k, 300 * 1024)).collect();
        let parts = split_transactions(&large);
        assert!(parts.len() > 1);
        for part in &parts {
            let bytes: usize = part.iter().map(DynamoDbBatchOp::size).sum();
            assert!(bytes <= MAX_TRANSACT_BYTES, "{bytes}");
            assert!(part.len() <= MAX_TRANSACT_ACTIONS);
        }
        let rejoined: Vec<_> = parts.iter().flat_map(|p| p.iter()).collect();
        assert_eq!(rejoined.len(), large.len());
        assert!(
            rejoined
                .iter()
                .zip(&large)
                .all(|(a, b)| a.target() == b.target())
        );
    }

    fn bin_item(pk: &[u8], val: &[u8]) -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                PK_ATTR.to_string(),
                AttributeValue::B(Blob::new(pk.to_vec())),
            ),
            (
                VAL_ATTR.to_string(),
                AttributeValue::B(Blob::new(val.to_vec())),
            ),
        ])
    }

    /// An item at DynamoDB's 400 KB limit is written; one byte over is
    /// refused as a size quota, before anything is sent.
    #[test]
    fn item_over_400_kb_is_refused_as_a_size_quota() {
        let key = b"content:alice:log";
        let overhead = PK_ATTR.len() + key.len() + VAL_ATTR.len();
        let fits = vec![b'x'; MAX_ITEM_BYTES - overhead];
        check_item_size(key, &fits).unwrap();

        let over = vec![b'x'; MAX_ITEM_BYTES - overhead + 1];
        let err = check_item_size(key, &over).unwrap_err();
        let AppError::QuotaExceeded(message) = &err else {
            panic!("expected a size quota, got {err:?}");
        };
        assert!(
            message.contains("per-item limit of 409600 bytes"),
            "{message}"
        );
        assert!(
            !message.contains("DynamoDB"),
            "the backend is not told to the caller"
        );
    }

    #[test]
    fn keeps_only_matching_prefix() {
        let items = vec![
            bin_item(b"did:alice", b"a"),
            bin_item(b"did:bob", b"b"),
            bin_item(b"owner:alice", b"o"),
        ];
        let mut out = Vec::new();
        filter_items_by_prefix(items, b"did:", &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|(k, _)| k == b"did:alice"));
        assert!(out.iter().any(|(k, _)| k == b"did:bob"));
        assert!(out.iter().all(|(k, _)| k.starts_with(b"did:")));
    }

    #[test]
    fn matches_non_utf8_binary_prefix() {
        // Regression for the original bug: prefix matching is byte-oriented,
        // not UTF-8. A prefix that isn't valid UTF-8 must still match — this
        // is the case a DynamoDB `begins_with` filter on a Binary key got
        // wrong under motoserver.
        let items = vec![
            bin_item(&[0xff, 0x00, 0x01], b"v1"),
            bin_item(&[0xff, 0x00, 0x02], b"v2"),
            bin_item(&[0x00, 0xff, 0x01], b"nope"),
        ];
        let mut out = Vec::new();
        filter_items_by_prefix(items, &[0xff, 0x00], &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|(k, _)| k.starts_with(&[0xff, 0x00])));
    }

    #[test]
    fn empty_prefix_matches_everything() {
        let items = vec![bin_item(b"a", b"1"), bin_item(b"\x00\x01", b"2")];
        let mut out = Vec::new();
        filter_items_by_prefix(items, b"", &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn skips_items_missing_binary_attrs() {
        // Missing val, and a String-typed pk — neither should be returned.
        let missing_val = HashMap::from([(
            PK_ATTR.to_string(),
            AttributeValue::B(Blob::new(b"did:x".to_vec())),
        )]);
        let string_pk = HashMap::from([
            (PK_ATTR.to_string(), AttributeValue::S("did:y".to_string())),
            (
                VAL_ATTR.to_string(),
                AttributeValue::B(Blob::new(b"v".to_vec())),
            ),
        ]);
        let items = vec![missing_val, string_pk, bin_item(b"did:z", b"v")];
        let mut out = Vec::new();
        filter_items_by_prefix(items, b"did:", &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, b"did:z");
    }
}

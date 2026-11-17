//! The AWS DynamoDB store backend.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::operation::create_table::CreateTableError;
use aws_sdk_dynamodb::operation::delete_item::DeleteItemError;
use aws_sdk_dynamodb::operation::describe_table::DescribeTableError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, Delete, KeySchemaElement, KeyType, ProvisionedThroughput, Put,
    ReturnValue, ScalarAttributeType, Select, TableStatus, TransactWriteItem,
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
    tables: Arc<Tables>,
}

/// How a table this backend creates is billed (`store.dynamodb_billing_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Billing {
    /// On demand: no capacity to size, and a full-table scan is not throttled
    /// at a handful of units.
    PayPerRequest,
    Provisioned {
        read: i64,
        write: i64,
    },
}

impl Billing {
    /// `pay_per_request` (the default) or `provisioned:<read>:<write>`.
    fn parse(mode: Option<&str>) -> Result<Self, AppError> {
        let Some(mode) = mode.map(str::trim).filter(|m| !m.is_empty()) else {
            return Ok(Self::PayPerRequest);
        };
        if mode.eq_ignore_ascii_case("pay_per_request") || mode.eq_ignore_ascii_case("on_demand") {
            return Ok(Self::PayPerRequest);
        }
        let invalid = || {
            AppError::Config(format!(
                "invalid store.dynamodb_billing_mode {mode:?}: expected \
                 \"pay_per_request\" or \"provisioned:<read units>:<write units>\""
            ))
        };
        let mut parts = mode.split(':');
        if !parts
            .next()
            .is_some_and(|p| p.eq_ignore_ascii_case("provisioned"))
        {
            return Err(invalid());
        }
        let units = |p: Option<&str>| -> Result<i64, AppError> {
            p.and_then(|p| p.trim().parse::<i64>().ok())
                .filter(|n| *n > 0)
                .ok_or_else(invalid)
        };
        let (read, write) = (units(parts.next())?, units(parts.next())?);
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(Self::Provisioned { read, write })
    }
}

/// The tables this backend has seen ready, and how it makes a missing one.
/// Shared by every keyspace handle and batch.
struct Tables {
    client: Client,
    billing: Billing,
    auto_create: bool,
    ready: RwLock<HashSet<String>>,
}

/// How long [`Tables::ensure`] waits for a table to become `ACTIVE`.
const TABLE_ACTIVE_TIMEOUT: Duration = Duration::from_secs(120);

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
        let billing = Billing::parse(config.dynamodb_billing_mode.as_deref())?;
        let auto_create = config.dynamodb_auto_create.unwrap_or(true);

        info!(
            table_prefix,
            ?billing,
            auto_create,
            "opening dynamodb store"
        );

        Ok(Box::new(Self {
            tables: Arc::new(Tables {
                client: client.clone(),
                billing,
                auto_create,
                ready: RwLock::new(HashSet::new()),
            }),
            client,
            table_prefix,
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
                tables: self.tables.clone(),
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
            tables: self.tables.clone(),
            ops: Vec::new(),
        })
    }

    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>> {
        // DynamoDB is fully managed; no-op.
        Box::pin(async { Ok(()) })
    }

    fn max_item_bytes(&self) -> Option<usize> {
        Some(MAX_ITEM_BYTES)
    }
}

impl Tables {
    /// Make sure `table` exists and is usable, once per table per process.
    ///
    /// Only a table DynamoDB reports missing (`ResourceNotFoundException`)
    /// is created, and only with `auto_create`; any other `DescribeTable`
    /// failure (throttling, `AccessDenied`, the network) is returned as it
    /// is. A table someone else is creating meanwhile
    /// (`ResourceInUseException`) counts as created. Either way it is used
    /// only once it is `ACTIVE`: until then DynamoDB refuses its reads and
    /// writes as `ResourceNotFoundException`.
    async fn ensure(&self, table: &str) -> Result<(), AppError> {
        if self.ready.read().await.contains(table) {
            return Ok(());
        }
        match self.client.describe_table().table_name(table).send().await {
            Ok(out) => {
                let status = out.table().and_then(|t| t.table_status());
                if !is_usable(status) {
                    self.wait_until_active(table).await?;
                }
            }
            Err(e)
                if e.as_service_error()
                    .is_some_and(DescribeTableError::is_resource_not_found_exception) =>
            {
                if !self.auto_create {
                    return Err(AppError::Config(format!(
                        "dynamodb table {table} does not exist, and \
                         store.dynamodb_auto_create is false"
                    )));
                }
                self.create(table).await?;
                self.wait_until_active(table).await?;
            }
            Err(e) => return Err(request_error("describe table", e)),
        }
        self.ready.write().await.insert(table.to_string());
        Ok(())
    }

    async fn create(&self, table: &str) -> Result<(), AppError> {
        let mut request = self
            .client
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
            );
        request = match self.billing {
            Billing::PayPerRequest => request.billing_mode(BillingMode::PayPerRequest),
            Billing::Provisioned { read, write } => request
                .billing_mode(BillingMode::Provisioned)
                .provisioned_throughput(
                    ProvisionedThroughput::builder()
                        .read_capacity_units(read)
                        .write_capacity_units(write)
                        .build()
                        .map_err(|e| AppError::Store(format!("dynamodb throughput: {e}")))?,
                ),
        };
        match request.send().await {
            Ok(_) => {
                info!(table, billing = ?self.billing, "dynamodb table created");
                Ok(())
            }
            // Another process (or task) is creating it: wait for it instead.
            Err(e)
                if e.as_service_error()
                    .is_some_and(CreateTableError::is_resource_in_use_exception) =>
            {
                Ok(())
            }
            Err(e) => Err(request_error("create table", e)),
        }
    }

    /// Poll `DescribeTable` until `table` is usable, up to
    /// [`TABLE_ACTIVE_TIMEOUT`]. A table just created may briefly describe
    /// as missing; that is waited out too.
    async fn wait_until_active(&self, table: &str) -> Result<(), AppError> {
        let deadline = tokio::time::Instant::now() + TABLE_ACTIVE_TIMEOUT;
        let mut delay = Duration::from_millis(100);
        loop {
            match self.client.describe_table().table_name(table).send().await {
                Ok(out) if is_usable(out.table().and_then(|t| t.table_status())) => return Ok(()),
                Ok(_) => {}
                Err(e)
                    if e.as_service_error()
                        .is_some_and(DescribeTableError::is_resource_not_found_exception) => {}
                Err(e) => return Err(request_error("describe table", e)),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AppError::Store(format!(
                    "dynamodb table {table} did not become ACTIVE within {}s",
                    TABLE_ACTIVE_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(2));
        }
    }
}

/// Whether a table in `status` takes reads and writes: `ACTIVE`, or
/// `UPDATING` (a capacity or index change, which keeps serving).
fn is_usable(status: Option<&TableStatus>) -> bool {
    matches!(status, Some(TableStatus::Active | TableStatus::Updating))
}

// ---------------------------------------------------------------------------
// DynamoDbKeyspace
// ---------------------------------------------------------------------------

struct DynamoDbKeyspace {
    client: Client,
    table: String,
    tables: Arc<Tables>,
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
            self.tables.ensure(&self.table).await?;
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
            self.tables.ensure(&self.table).await?;
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
            self.tables.ensure(&self.table).await?;
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
            self.tables.ensure(&self.table).await?;
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
            self.tables.ensure(&self.table).await?;
            // A DeleteItem conditional on the item existing, returning the
            // old attributes: of any number of callers deleting the same
            // item, the condition lets exactly one delete through, and only
            // that one gets the value. An unconditional delete with ALL_OLD
            // is not enough: concurrent deletes of one item can each be
            // handed the old attributes (DynamoDB Local does, under the
            // conformance suite's race).
            let response = match self
                .client
                .delete_item()
                .table_name(&self.table)
                .key(PK_ATTR, AttributeValue::B(Blob::new(key)))
                .condition_expression("attribute_exists(#pk)")
                .expression_attribute_names("#pk", PK_ATTR)
                .return_values(ReturnValue::AllOld)
                .send()
                .await
            {
                Ok(response) => response,
                Err(e)
                    if e.as_service_error()
                        .is_some_and(DeleteItemError::is_conditional_check_failed_exception) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(request_error("delete (atomic take)", e)),
            };
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
            self.tables.ensure(&self.table).await?;
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
            self.tables.ensure(&self.table).await?;
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
            self.tables.ensure(&self.table).await?;

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
            self.tables.ensure(&self.table).await?;
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

    /// A `Scan` projected to the key: the same read units as a full scan,
    /// but no values sent back.
    fn prefix_keys_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, AppError>> {
        Box::pin(async move {
            self.tables.ensure(&self.table).await?;
            let mut keys = Vec::new();
            let mut last_key: Option<HashMap<String, AttributeValue>> = None;
            loop {
                let resp = self
                    .client
                    .scan()
                    .table_name(&self.table)
                    .consistent_read(self.consistent_scan)
                    .projection_expression("#pk")
                    .expression_attribute_names("#pk", PK_ATTR)
                    .set_exclusive_start_key(last_key.take())
                    .send()
                    .await
                    .map_err(|e| request_error("scan", e))?;
                for item in resp.items.unwrap_or_default() {
                    if let Some(AttributeValue::B(pk)) = item.get(PK_ATTR)
                        && pk.as_ref().starts_with(&prefix)
                    {
                        keys.push(pk.as_ref().to_vec());
                    }
                }
                last_key = resp.last_evaluated_key;
                if last_key.is_none() {
                    return Ok(keys);
                }
            }
        })
    }

    /// The whole table counts server-side (`Select: COUNT`); a prefix counts
    /// [`Self::prefix_keys_raw`], since the prefix test is made here.
    fn prefix_count(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<usize, AppError>> {
        Box::pin(async move {
            if !prefix.is_empty() {
                return Ok(self.prefix_keys_raw(prefix).await?.len());
            }
            self.tables.ensure(&self.table).await?;
            let mut count = 0usize;
            let mut last_key: Option<HashMap<String, AttributeValue>> = None;
            loop {
                let resp = self
                    .client
                    .scan()
                    .table_name(&self.table)
                    .consistent_read(self.consistent_scan)
                    .select(Select::Count)
                    .set_exclusive_start_key(last_key.take())
                    .send()
                    .await
                    .map_err(|e| request_error("scan", e))?;
                count += usize::try_from(resp.count).unwrap_or_default();
                last_key = resp.last_evaluated_key;
                if last_key.is_none() {
                    return Ok(count);
                }
            }
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
    tables: Arc<Tables>,
    ops: Vec<DynamoDbBatchOp>,
}

/// Make sure every table `ops` writes exists, as a single-key write would:
/// a keyspace whose first write is a batch is otherwise missing on a fresh
/// deployment.
async fn ensure_tables(tables: &Tables, ops: &[DynamoDbBatchOp]) -> Result<(), AppError> {
    let names: BTreeSet<&str> = ops.iter().map(|op| op.target().0).collect();
    for name in names {
        tables.ensure(name).await?;
    }
    Ok(())
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
                return Err(AppError::quota(
                    crate::server::error::QuotaKind::Size,
                    format!(
                        "a change of {} writes ({bytes} bytes) is over the store's \
                     size limit for one atomic write: {MAX_TRANSACT_ACTIONS} \
                     writes and {MAX_TRANSACT_BYTES} bytes",
                        ops.len()
                    ),
                ));
            }
            ensure_tables(&self.tables, &ops).await?;
            send_transaction(&self.client, &ops).await
        })
    }

    fn commit_in_parts(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let ops = prepare_ops(self.ops)?;
            ensure_tables(&self.tables, &ops).await?;
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
#[path = "dynamodb_tests.rs"]
mod tests;

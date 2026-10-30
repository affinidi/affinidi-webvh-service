use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
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

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

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
}

impl StorageBackend for DynamoDbBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        Ok((
            name.to_string(),
            Arc::new(DynamoDbKeyspace {
                client: self.client.clone(),
                table: self.table_name(name),
                verified: self.verified_tables.clone(),
            }),
        ))
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
}

impl KeyspaceOps for DynamoDbKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
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
                let mut req = self.client.scan().table_name(&self.table);
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
            // DynamoDB TransactWriteItems supports up to 100 items per request.
            for chunk in self.ops.chunks(100) {
                let mut items = Vec::with_capacity(chunk.len());
                for op in chunk {
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
                                .map_err(|e| {
                                    AppError::Store(format!("dynamodb delete build: {e}"))
                                })?;
                            items.push(TransactWriteItem::builder().delete(del).build());
                        }
                    }
                }

                self.client
                    .transact_write_items()
                    .set_transact_items(Some(items))
                    .send()
                    .await
                    .map_err(transact_error)?;
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
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

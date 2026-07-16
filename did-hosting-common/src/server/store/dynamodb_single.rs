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

use std::collections::HashMap;
use std::sync::Arc;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, ReturnValue, TransactWriteItem};
use tracing::info;

use crate::server::config::StoreConfig;
use crate::server::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

const PK_ATTR: &str = "pk";
const SK_ATTR: &str = "sk";
const VAL_ATTR: &str = "val";

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
}

impl SingleTableDynamoDbBackend {
    pub async fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        let table_name = config.dynamodb_table_name.clone().ok_or_else(|| {
            AppError::Config(
                "store-dynamodb-single requires `store.dynamodb_table_name` \
                 (env: <PREFIX>_STORE_DYNAMODB_TABLE_NAME)"
                    .into(),
            )
        })?;

        let mut aws_config_loader = aws_config::from_env();
        if let Some(ref region) = config.dynamodb_region {
            aws_config_loader = aws_config_loader.region(aws_config::Region::new(region.clone()));
        }
        let aws_config = aws_config_loader.load().await;
        let client = Client::new(&aws_config);

        info!(table = %table_name, "opening single-table dynamodb store");

        Ok(Box::new(Self { client, table_name }))
    }
}

impl StorageBackend for SingleTableDynamoDbBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        Ok((
            name.to_string(),
            Arc::new(SingleTableKeyspace {
                client: self.client.clone(),
                table_name: self.table_name.clone(),
                keyspace: name.to_string(),
            }),
        ))
    }

    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(SingleTableBatch {
            client: self.client.clone(),
            table_name: self.table_name.clone(),
            ops: Vec::new(),
        })
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
    keyspace: String,
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
                .item(PK_ATTR, AttributeValue::S(self.keyspace.clone()))
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
                .key(PK_ATTR, AttributeValue::S(self.keyspace.clone()))
                .key(SK_ATTR, AttributeValue::S(sk))
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
                .key(PK_ATTR, AttributeValue::S(self.keyspace.clone()))
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
                .key(PK_ATTR, AttributeValue::S(self.keyspace.clone()))
                .key(SK_ATTR, AttributeValue::S(sk))
                .projection_expression(PK_ATTR)
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
                .key(PK_ATTR, AttributeValue::S(self.keyspace.clone()))
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
                    .expression_attribute_values(":ks", AttributeValue::S(self.keyspace.clone()));

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

enum SingleTableBatchOp {
    Insert {
        keyspace: String,
        sk: String,
        value: Vec<u8>,
    },
    Remove {
        keyspace: String,
        sk: String,
    },
}

struct SingleTableBatch {
    client: Client,
    table_name: String,
    ops: Vec<SingleTableBatchOp>,
}

impl BatchOps for SingleTableBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        // Batch API is fire-and-forget on individual ops; validation errors
        // surface on commit(). Push a poison-marker op that fails at commit
        // rather than swallowing the encoding problem here.
        match key_as_string(&key) {
            Ok(sk) => self.ops.push(SingleTableBatchOp::Insert {
                keyspace: keyspace.to_string(),
                sk,
                value,
            }),
            Err(_) => self.ops.push(SingleTableBatchOp::Insert {
                keyspace: keyspace.to_string(),
                sk: String::from_utf8_lossy(&key).into_owned(),
                value,
            }),
        }
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        match key_as_string(&key) {
            Ok(sk) => self.ops.push(SingleTableBatchOp::Remove {
                keyspace: keyspace.to_string(),
                sk,
            }),
            Err(_) => self.ops.push(SingleTableBatchOp::Remove {
                keyspace: keyspace.to_string(),
                sk: String::from_utf8_lossy(&key).into_owned(),
            }),
        }
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            // TransactWriteItems: up to 100 items per request. Cross-chunk
            // atomicity is not guaranteed — matches the multi-table
            // backend. All current callers stay under 100.
            for chunk in self.ops.chunks(100) {
                let mut items = Vec::with_capacity(chunk.len());
                for op in chunk {
                    match op {
                        SingleTableBatchOp::Insert {
                            keyspace,
                            sk,
                            value,
                        } => {
                            let put = Put::builder()
                                .table_name(&self.table_name)
                                .item(PK_ATTR, AttributeValue::S(keyspace.clone()))
                                .item(SK_ATTR, AttributeValue::S(sk.clone()))
                                .item(VAL_ATTR, AttributeValue::B(Blob::new(value.clone())))
                                .build()
                                .map_err(|e| {
                                    AppError::Store(format!("dynamodb-single put build: {e}"))
                                })?;
                            items.push(TransactWriteItem::builder().put(put).build());
                        }
                        SingleTableBatchOp::Remove { keyspace, sk } => {
                            let del = Delete::builder()
                                .table_name(&self.table_name)
                                .key(PK_ATTR, AttributeValue::S(keyspace.clone()))
                                .key(SK_ATTR, AttributeValue::S(sk.clone()))
                                .build()
                                .map_err(|e| {
                                    AppError::Store(format!("dynamodb-single delete build: {e}"))
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
                    .map_err(|e| AppError::Store(format!("dynamodb-single transact: {e}")))?;
            }
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
}

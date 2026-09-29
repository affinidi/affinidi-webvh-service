use std::sync::Arc;

use azure_data_cosmos::FeedScope;
use azure_data_cosmos::options::{ItemWriteOptions, Precondition, Region};
use azure_data_cosmos::{AccountEndpoint, AccountReference, CosmosClient, RoutingStrategy};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::server::config::StoreConfig;
use crate::server::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

/// The partition key value used for all items (single-partition design).
const PARTITION_VALUE: &str = "kv";

/// How many times a conditional (ETag) write is retried under contention
/// before `take_raw_atomic`/`incr_raw` give up with an error. Each retry
/// means another writer won, so this is only reached under a sustained
/// race on one key.
const CONDITIONAL_WRITE_ATTEMPTS: usize = 16;

/// Document model stored in Cosmos DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KvDoc {
    /// Document ID: base64url-encoded raw key.
    id: String,
    /// Partition key field.
    pk: String,
    /// Base64url-encoded raw value bytes.
    data: String,
}

// ---------------------------------------------------------------------------
// CosmosDbBackend
// ---------------------------------------------------------------------------

pub struct CosmosDbBackend {
    client: CosmosClient,
    database: String,
}

/// Parse a Cosmos DB connection string into (endpoint, key).
///
/// Format: `AccountEndpoint=https://xxx.documents.azure.com:443/;AccountKey=xxx`
fn parse_connection_string(conn_str: &str) -> Result<(String, String), AppError> {
    let mut endpoint = None;
    let mut key = None;

    for part in conn_str.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("AccountEndpoint=") {
            endpoint = Some(val.to_string());
        } else if let Some(val) = part.strip_prefix("AccountKey=") {
            key = Some(val.to_string());
        }
    }

    match (endpoint, key) {
        (Some(e), Some(k)) => Ok((e, k)),
        _ => Err(AppError::Config(
            "invalid cosmosdb connection string: expected AccountEndpoint=...;AccountKey=..."
                .into(),
        )),
    }
}

impl CosmosDbBackend {
    pub async fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        let database = config
            .cosmosdb_database
            .clone()
            .unwrap_or_else(|| "webvh".to_string());

        let connection_string = config
            .cosmosdb_connection_string
            .as_deref()
            .ok_or_else(|| {
                AppError::Config("store.cosmosdb_connection_string is required".into())
            })?;

        info!(database, "opening cosmosdb store");

        let (endpoint_str, account_key) = parse_connection_string(connection_string)?;

        let endpoint: AccountEndpoint = endpoint_str
            .parse()
            .map_err(|e| AppError::Store(format!("cosmosdb endpoint parse: {e}")))?;

        let account = AccountReference::with_authentication_key(
            endpoint,
            azure_core::credentials::Secret::new(account_key),
        );

        // Cosmos DB 0.32 requires explicit routing. Accept any Azure region
        // name (display or normalized form); default to EAST_US when unset.
        let region = config
            .cosmosdb_region
            .as_deref()
            .map(|name| Region::new(name.to_string()))
            .unwrap_or(Region::EAST_US);

        let client = CosmosClient::builder()
            .build(account, RoutingStrategy::ProximityTo(region))
            .await
            .map_err(|e| AppError::Store(format!("cosmosdb build client: {e}")))?;

        Ok(Box::new(Self { client, database }))
    }
}

impl StorageBackend for CosmosDbBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        Ok((
            name.to_string(),
            Arc::new(CosmosDbKeyspace {
                client: self.client.clone(),
                database: self.database.clone(),
                container_name: name.to_string(),
            }),
        ))
    }

    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(CosmosDbBatch {
            client: self.client.clone(),
            database: self.database.clone(),
            ops: Vec::new(),
        })
    }

    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>> {
        // Cosmos DB is fully managed; no-op.
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// CosmosDbKeyspace
// ---------------------------------------------------------------------------

struct CosmosDbKeyspace {
    client: CosmosClient,
    database: String,
    container_name: String,
}

fn encode_doc_id(key: &[u8]) -> String {
    BASE64.encode(key)
}

impl CosmosDbKeyspace {
    async fn container(&self) -> Result<azure_data_cosmos::clients::ContainerClient, AppError> {
        self.client
            .database_client(&self.database)
            .container_client(&self.container_name, None)
            .await
            .map_err(|e| AppError::Store(format!("cosmosdb container client: {e}")))
    }
}

impl KeyspaceOps for CosmosDbKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let container = self.container().await?;
            let doc_id = encode_doc_id(&key);
            let doc = KvDoc {
                id: doc_id.clone(),
                pk: PARTITION_VALUE.to_string(),
                data: BASE64.encode(&value),
            };
            container
                .upsert_item(PARTITION_VALUE, &doc_id, doc, None)
                .await
                .map_err(|e| AppError::Store(format!("cosmosdb upsert: {e}")))?;
            Ok(())
        })
    }

    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            let container = self.container().await?;
            let doc_id = encode_doc_id(&key);
            match container.read_item(PARTITION_VALUE, &doc_id, None).await {
                Ok(resp) => {
                    let doc: KvDoc = resp
                        .into_model()
                        .map_err(|e| AppError::Store(format!("cosmosdb read body: {e}")))?;
                    let bytes = BASE64
                        .decode(&doc.data)
                        .map_err(|e| AppError::Store(format!("cosmosdb decode: {e}")))?;
                    Ok(Some(bytes))
                }
                Err(e) if is_not_found(&e) => Ok(None),
                Err(e) => Err(AppError::Store(format!("cosmosdb read: {e}"))),
            }
        })
    }

    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let container = self.container().await?;
            let doc_id = encode_doc_id(&key);
            match container.delete_item(PARTITION_VALUE, &doc_id, None).await {
                Ok(_) => Ok(()),
                Err(e) if is_not_found(&e) => Ok(()),
                Err(e) => Err(AppError::Store(format!("cosmosdb delete: {e}"))),
            }
        })
    }

    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            let container = self.container().await?;
            let doc_id = encode_doc_id(&key);
            match container.read_item(PARTITION_VALUE, &doc_id, None).await {
                Ok(_) => Ok(true),
                Err(e) if is_not_found(&e) => Ok(false),
                Err(e) => Err(AppError::Store(format!("cosmosdb read: {e}"))),
            }
        })
    }

    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        // Read the item and its ETag, then delete it `If-Match` that ETag.
        // Cosmos DB deletes a given version of an item exactly once, so of
        // any number of callers — on any replica — racing on the same key,
        // one delete succeeds and returns the value; the rest see 404 (it's
        // gone) or 412 (it changed; re-read) and never return it.
        Box::pin(async move {
            let container = self.container().await?;
            let doc_id = encode_doc_id(&key);
            for _ in 0..CONDITIONAL_WRITE_ATTEMPTS {
                let resp = match container.read_item(PARTITION_VALUE, &doc_id, None).await {
                    Ok(resp) => resp,
                    Err(e) if is_not_found(&e) => return Ok(None),
                    Err(e) => return Err(AppError::Store(format!("cosmosdb read: {e}"))),
                };
                let etag = resp
                    .headers()
                    .etag()
                    .cloned()
                    .ok_or_else(|| AppError::Store("cosmosdb read: no etag".into()))?;
                let doc: KvDoc = resp
                    .into_model()
                    .map_err(|e| AppError::Store(format!("cosmosdb read body: {e}")))?;
                let options =
                    ItemWriteOptions::default().with_precondition(Precondition::if_match(etag));
                match container
                    .delete_item(PARTITION_VALUE, &doc_id, Some(options))
                    .await
                {
                    Ok(_) => {
                        let bytes = BASE64
                            .decode(&doc.data)
                            .map_err(|e| AppError::Store(format!("cosmosdb decode: {e}")))?;
                        return Ok(Some(bytes));
                    }
                    Err(e) if is_not_found(&e) => return Ok(None),
                    Err(e) if e.status().is_precondition_failed() => continue,
                    Err(e) => return Err(AppError::Store(format!("cosmosdb delete: {e}"))),
                }
            }
            Err(AppError::Store("cosmosdb take: too much contention".into()))
        })
    }

    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        // Optimistic concurrency: create the counter (a create 409s if the
        // item already exists), or replace it `If-Match` the ETag just read. A racing writer on another replica
        // makes the write fail (409/412) and this re-reads, so no increment
        // is ever lost.
        Box::pin(async move {
            let container = self.container().await?;
            let doc_id = encode_doc_id(&key);
            let counter_doc = |n: u64| KvDoc {
                id: doc_id.clone(),
                pk: PARTITION_VALUE.to_string(),
                data: BASE64.encode(encode_counter(n)),
            };
            for _ in 0..CONDITIONAL_WRITE_ATTEMPTS {
                match container.read_item(PARTITION_VALUE, &doc_id, None).await {
                    Err(e) if is_not_found(&e) => {
                        match container
                            .create_item(PARTITION_VALUE, &doc_id, counter_doc(1), None)
                            .await
                        {
                            Ok(_) => return Ok(1),
                            Err(e) if e.status().is_conflict() => continue,
                            Err(e) => return Err(AppError::Store(format!("cosmosdb create: {e}"))),
                        }
                    }
                    Err(e) => return Err(AppError::Store(format!("cosmosdb read: {e}"))),
                    Ok(resp) => {
                        let etag = resp
                            .headers()
                            .etag()
                            .cloned()
                            .ok_or_else(|| AppError::Store("cosmosdb read: no etag".into()))?;
                        let doc: KvDoc = resp
                            .into_model()
                            .map_err(|e| AppError::Store(format!("cosmosdb read body: {e}")))?;
                        let next = BASE64
                            .decode(&doc.data)
                            .map(|bytes| decode_counter(&bytes))
                            .unwrap_or(0)
                            .saturating_add(1);
                        let options = ItemWriteOptions::default()
                            .with_precondition(Precondition::if_match(etag));
                        match container
                            .replace_item(
                                PARTITION_VALUE,
                                &doc_id,
                                counter_doc(next),
                                Some(options),
                            )
                            .await
                        {
                            Ok(_) => return Ok(next),
                            Err(e) if e.status().is_precondition_failed() || is_not_found(&e) => {
                                continue;
                            }
                            Err(e) => {
                                return Err(AppError::Store(format!("cosmosdb replace: {e}")));
                            }
                        }
                    }
                }
            }
            Err(AppError::Store("cosmosdb incr: too much contention".into()))
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            let container = self.container().await?;

            let query = if prefix.is_empty() {
                azure_data_cosmos::Query::from("SELECT * FROM c WHERE c.pk = @pk")
                    .with_parameter("@pk", PARTITION_VALUE)
                    .map_err(|e| AppError::Store(format!("cosmosdb query param: {e}")))?
            } else {
                let prefix_encoded = encode_doc_id(&prefix);
                azure_data_cosmos::Query::from(
                    "SELECT * FROM c WHERE c.pk = @pk AND STARTSWITH(c.id, @prefix)",
                )
                .with_parameter("@pk", PARTITION_VALUE)
                .map_err(|e| AppError::Store(format!("cosmosdb query param: {e}")))?
                .with_parameter("@prefix", &prefix_encoded)
                .map_err(|e| AppError::Store(format!("cosmosdb query param: {e}")))?
            };

            let mut results = Vec::new();
            let mut pager = container
                .query_items::<KvDoc>(query, FeedScope::partition(PARTITION_VALUE), None)
                .await
                .map_err(|e| AppError::Store(format!("cosmosdb query: {e}")))?;

            while let Some(item_result) = pager.next().await {
                let doc: KvDoc = item_result
                    .map_err(|e| AppError::Store(format!("cosmosdb query item: {e}")))?;
                let key_bytes = BASE64
                    .decode(&doc.id)
                    .map_err(|e| AppError::Store(format!("cosmosdb decode key: {e}")))?;
                // Verify prefix match on raw bytes
                if key_bytes.starts_with(&prefix) {
                    let val_bytes = BASE64
                        .decode(&doc.data)
                        .map_err(|e| AppError::Store(format!("cosmosdb decode val: {e}")))?;
                    results.push((key_bytes, val_bytes));
                }
            }

            Ok(results)
        })
    }
}

/// A counter as its decimal ASCII representation. Malformed values decode to
/// 0 (defensive: a counter key should never hold anything else).
fn decode_counter(bytes: &[u8]) -> u64 {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn encode_counter(n: u64) -> Vec<u8> {
    n.to_string().into_bytes()
}

/// Check if a Cosmos DB error is a 404 Not Found.
///
/// 0.34 surfaces typed status on `CosmosError` (`status().is_not_found()`
/// checks HTTP 404 with no contradicting sub-status), replacing the prior
/// stringly-typed match on `azure_core::Error`.
fn is_not_found(err: &azure_data_cosmos::CosmosError) -> bool {
    err.status().is_not_found()
}

// ---------------------------------------------------------------------------
// CosmosDbBatch
// ---------------------------------------------------------------------------

enum CosmosDbBatchOp {
    Insert {
        container: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Remove {
        container: String,
        key: Vec<u8>,
    },
}

struct CosmosDbBatch {
    client: CosmosClient,
    database: String,
    ops: Vec<CosmosDbBatchOp>,
}

impl BatchOps for CosmosDbBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push(CosmosDbBatchOp::Insert {
            container: keyspace.to_string(),
            key,
            value,
        });
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        self.ops.push(CosmosDbBatchOp::Remove {
            container: keyspace.to_string(),
            key,
        });
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            for op in &self.ops {
                let container_name = match op {
                    CosmosDbBatchOp::Insert { container, .. } => container,
                    CosmosDbBatchOp::Remove { container, .. } => container,
                };
                let container_client = self
                    .client
                    .database_client(&self.database)
                    .container_client(container_name, None)
                    .await
                    .map_err(|e| {
                        AppError::Store(format!("cosmosdb batch container client: {e}"))
                    })?;

                match op {
                    CosmosDbBatchOp::Insert { key, value, .. } => {
                        let doc_id = encode_doc_id(key);
                        let doc = KvDoc {
                            id: doc_id.clone(),
                            pk: PARTITION_VALUE.to_string(),
                            data: BASE64.encode(value),
                        };
                        container_client
                            .upsert_item(PARTITION_VALUE, &doc_id, doc, None)
                            .await
                            .map_err(|e| AppError::Store(format!("cosmosdb batch upsert: {e}")))?;
                    }
                    CosmosDbBatchOp::Remove { key, .. } => {
                        let doc_id = encode_doc_id(key);
                        match container_client
                            .delete_item(PARTITION_VALUE, &doc_id, None)
                            .await
                        {
                            Ok(_) => {}
                            Err(e) if is_not_found(&e) => {}
                            Err(e) => {
                                return Err(AppError::Store(format!("cosmosdb batch delete: {e}")));
                            }
                        }
                    }
                }
            }

            Ok(())
        })
    }
}

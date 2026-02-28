use std::sync::Arc;

use azure_data_cosmos::{
    CosmosAccountEndpoint, CosmosAccountReference, CosmosClient,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use base64::Engine;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::StoreConfig;
use crate::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

/// The partition key value used for all items (single-partition design).
const PARTITION_VALUE: &str = "kv";

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

        let endpoint: CosmosAccountEndpoint = endpoint_str
            .parse()
            .map_err(|e| AppError::Store(format!("cosmosdb endpoint parse: {e}")))?;

        let account = CosmosAccountReference::with_master_key(
            endpoint,
            azure_core::credentials::Secret::new(account_key),
        );

        let client = CosmosClient::builder()
            .build(account)
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
    async fn container(
        &self,
    ) -> azure_data_cosmos::clients::ContainerClient {
        self.client
            .database_client(&self.database)
            .container_client(&self.container_name)
            .await
    }
}

impl KeyspaceOps for CosmosDbKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let container = self.container().await;
            let doc = KvDoc {
                id: encode_doc_id(&key),
                pk: PARTITION_VALUE.to_string(),
                data: BASE64.encode(&value),
            };
            container
                .upsert_item(PARTITION_VALUE, doc, None)
                .await
                .map_err(|e| AppError::Store(format!("cosmosdb upsert: {e}")))?;
            Ok(())
        })
    }

    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            let container = self.container().await;
            let doc_id = encode_doc_id(&key);
            match container
                .read_item::<KvDoc>(PARTITION_VALUE, &doc_id, None)
                .await
            {
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
            let container = self.container().await;
            let doc_id = encode_doc_id(&key);
            match container
                .delete_item(PARTITION_VALUE, &doc_id, None)
                .await
            {
                Ok(_) => Ok(()),
                Err(e) if is_not_found(&e) => Ok(()),
                Err(e) => Err(AppError::Store(format!("cosmosdb delete: {e}"))),
            }
        })
    }

    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            let container = self.container().await;
            let doc_id = encode_doc_id(&key);
            match container
                .read_item::<KvDoc>(PARTITION_VALUE, &doc_id, None)
                .await
            {
                Ok(_) => Ok(true),
                Err(e) if is_not_found(&e) => Ok(false),
                Err(e) => Err(AppError::Store(format!("cosmosdb read: {e}"))),
            }
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            let container = self.container().await;

            let query = if prefix.is_empty() {
                azure_data_cosmos::Query::from(
                    "SELECT * FROM c WHERE c.pk = @pk",
                )
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
                .query_items::<KvDoc>(query, PARTITION_VALUE, None)
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

/// Check if an Azure error is a 404 Not Found.
fn is_not_found(err: &azure_core::Error) -> bool {
    err.to_string().contains("404") || err.to_string().contains("NotFound")
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
                    .container_client(container_name)
                    .await;

                match op {
                    CosmosDbBatchOp::Insert { key, value, .. } => {
                        let doc = KvDoc {
                            id: encode_doc_id(key),
                            pk: PARTITION_VALUE.to_string(),
                            data: BASE64.encode(value),
                        };
                        container_client
                            .upsert_item(PARTITION_VALUE, doc, None)
                            .await
                            .map_err(|e| {
                                AppError::Store(format!("cosmosdb batch upsert: {e}"))
                            })?;
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
                                return Err(AppError::Store(format!(
                                    "cosmosdb batch delete: {e}"
                                )));
                            }
                        }
                    }
                }
            }

            Ok(())
        })
    }
}

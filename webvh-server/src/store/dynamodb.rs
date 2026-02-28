use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeValue, Delete, KeySchemaElement, KeyType, Put, ProvisionedThroughput,
    ScalarAttributeType, TransactWriteItem,
};
use aws_sdk_dynamodb::Client;
use tokio::sync::RwLock;
use tracing::info;

use crate::config::StoreConfig;
use crate::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

const PK_ATTR: &str = "pk";
const VAL_ATTR: &str = "val";

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
            aws_config_loader =
                aws_config_loader.region(aws_config::Region::new(region.clone()));
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
                .map_err(|e| AppError::Store(format!("dynamodb put: {e}")))?;
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
                .map_err(|e| AppError::Store(format!("dynamodb get: {e}")))?;

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
                .map_err(|e| AppError::Store(format!("dynamodb delete: {e}")))?;
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
                .map_err(|e| AppError::Store(format!("dynamodb get: {e}")))?;
            Ok(result.item.is_some())
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            ensure_table(&self.client, &self.table, &self.verified).await?;

            let mut results = Vec::new();

            if prefix.is_empty() {
                // Full table scan
                let mut last_key: Option<HashMap<String, AttributeValue>> = None;
                loop {
                    let mut req = self.client.scan().table_name(&self.table);
                    if let Some(ref key) = last_key {
                        req = req.set_exclusive_start_key(Some(key.clone()));
                    }
                    let resp = req
                        .send()
                        .await
                        .map_err(|e| AppError::Store(format!("dynamodb scan: {e}")))?;

                    if let Some(items) = resp.items {
                        for item in items {
                            if let (Some(AttributeValue::B(pk)), Some(AttributeValue::B(val))) =
                                (item.get(PK_ATTR), item.get(VAL_ATTR))
                            {
                                results.push((pk.as_ref().to_vec(), val.as_ref().to_vec()));
                            }
                        }
                    }

                    last_key = resp.last_evaluated_key;
                    if last_key.is_none() {
                        break;
                    }
                }
            } else {
                // Scan with begins_with filter
                let mut last_key: Option<HashMap<String, AttributeValue>> = None;
                loop {
                    let mut req = self
                        .client
                        .scan()
                        .table_name(&self.table)
                        .filter_expression("begins_with(#pk, :prefix)")
                        .expression_attribute_names("#pk", PK_ATTR)
                        .expression_attribute_values(
                            ":prefix",
                            AttributeValue::B(Blob::new(prefix.clone())),
                        );
                    if let Some(ref key) = last_key {
                        req = req.set_exclusive_start_key(Some(key.clone()));
                    }
                    let resp = req
                        .send()
                        .await
                        .map_err(|e| AppError::Store(format!("dynamodb scan: {e}")))?;

                    if let Some(items) = resp.items {
                        for item in items {
                            if let (Some(AttributeValue::B(pk)), Some(AttributeValue::B(val))) =
                                (item.get(PK_ATTR), item.get(VAL_ATTR))
                            {
                                results.push((pk.as_ref().to_vec(), val.as_ref().to_vec()));
                            }
                        }
                    }

                    last_key = resp.last_evaluated_key;
                    if last_key.is_none() {
                        break;
                    }
                }
            }

            Ok(results)
        })
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
                                .map_err(|e| {
                                    AppError::Store(format!("dynamodb put build: {e}"))
                                })?;
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
                    .map_err(|e| AppError::Store(format!("dynamodb transact: {e}")))?;
            }

            Ok(())
        })
    }
}

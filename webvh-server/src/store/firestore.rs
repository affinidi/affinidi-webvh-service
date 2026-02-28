use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use base64::Engine;
use firestore::*;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::StoreConfig;
use crate::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

/// Document model stored in Firestore.
#[derive(Debug, Serialize, Deserialize)]
struct KvDoc {
    /// Base64url-encoded raw key bytes (also the document ID).
    key: String,
    /// Base64url-encoded raw value bytes.
    data: String,
}

// ---------------------------------------------------------------------------
// FirestoreBackend
// ---------------------------------------------------------------------------

pub struct FirestoreBackend {
    db: FirestoreDb,
}

impl FirestoreBackend {
    pub async fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        let project = config
            .firestore_project
            .as_deref()
            .ok_or_else(|| AppError::Config("store.firestore_project is required".into()))?;

        info!(project, "opening firestore store");

        let mut options = FirestoreDbOptions::new(project.to_string());
        if let Some(ref database) = config.firestore_database {
            options = options.with_database_id(database.clone());
        }

        let db = FirestoreDb::with_options(options)
            .await
            .map_err(|e| AppError::Store(format!("firestore connect: {e}")))?;

        Ok(Box::new(Self { db }))
    }
}

impl StorageBackend for FirestoreBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        Ok((
            name.to_string(),
            Arc::new(FirestoreKeyspace {
                db: self.db.clone(),
                collection: name.to_string(),
            }),
        ))
    }

    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(FirestoreBatch {
            db: self.db.clone(),
            ops: Vec::new(),
        })
    }

    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>> {
        // Firestore is fully managed; no-op.
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// FirestoreKeyspace
// ---------------------------------------------------------------------------

struct FirestoreKeyspace {
    db: FirestoreDb,
    collection: String,
}

/// Encode raw key bytes to a Firestore-safe document ID (base64url, no pad).
fn encode_doc_id(key: &[u8]) -> String {
    BASE64.encode(key)
}

impl KeyspaceOps for FirestoreKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let doc_id = encode_doc_id(&key);
            let doc = KvDoc {
                key: doc_id.clone(),
                data: BASE64.encode(&value),
            };
            // update_obj acts as an upsert in Firestore
            let _: KvDoc = self
                .db
                .update_obj(&self.collection, &doc_id, &doc, None, None, None)
                .await
                .map_err(|e| AppError::Store(format!("firestore upsert: {e}")))?;
            Ok(())
        })
    }

    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            let doc_id = encode_doc_id(&key);
            let result: Option<KvDoc> = self
                .db
                .get_obj_if_exists(&self.collection, &doc_id, None)
                .await
                .map_err(|e| AppError::Store(format!("firestore get: {e}")))?;

            match result {
                Some(doc) => {
                    let bytes = BASE64
                        .decode(&doc.data)
                        .map_err(|e| AppError::Store(format!("firestore decode: {e}")))?;
                    Ok(Some(bytes))
                }
                None => Ok(None),
            }
        })
    }

    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let doc_id = encode_doc_id(&key);
            self.db
                .delete_by_id(&self.collection, &doc_id, None)
                .await
                .map_err(|e| AppError::Store(format!("firestore delete: {e}")))?;
            Ok(())
        })
    }

    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            let doc_id = encode_doc_id(&key);
            let result: Option<KvDoc> = self
                .db
                .get_obj_if_exists(&self.collection, &doc_id, None)
                .await
                .map_err(|e| AppError::Store(format!("firestore get: {e}")))?;
            Ok(result.is_some())
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            let params = FirestoreListDocParams::new(self.collection.clone())
                .with_page_size(10_000);

            let mut stream = self
                .db
                .stream_list_obj::<KvDoc>(params)
                .await
                .map_err(|e| AppError::Store(format!("firestore list: {e}")))?;

            let mut results = Vec::new();
            while let Some(doc) = stream.next().await {
                let key_bytes = BASE64
                    .decode(&doc.key)
                    .map_err(|e| AppError::Store(format!("firestore decode key: {e}")))?;

                if prefix.is_empty() || key_bytes.starts_with(&prefix) {
                    let val_bytes = BASE64
                        .decode(&doc.data)
                        .map_err(|e| AppError::Store(format!("firestore decode val: {e}")))?;
                    results.push((key_bytes, val_bytes));
                }
            }

            Ok(results)
        })
    }
}

// ---------------------------------------------------------------------------
// FirestoreBatch
// ---------------------------------------------------------------------------

enum FirestoreBatchOp {
    Insert {
        collection: String,
        doc_id: String,
        doc: KvDoc,
    },
    Remove {
        collection: String,
        doc_id: String,
    },
}

struct FirestoreBatch {
    db: FirestoreDb,
    ops: Vec<FirestoreBatchOp>,
}

impl BatchOps for FirestoreBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        let doc_id = encode_doc_id(&key);
        self.ops.push(FirestoreBatchOp::Insert {
            collection: keyspace.to_string(),
            doc_id: doc_id.clone(),
            doc: KvDoc {
                key: doc_id,
                data: BASE64.encode(&value),
            },
        });
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        self.ops.push(FirestoreBatchOp::Remove {
            collection: keyspace.to_string(),
            doc_id: encode_doc_id(&key),
        });
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            // Firestore batched writes support up to 500 operations per request.
            for chunk in self.ops.chunks(500) {
                let mut batch = self.db.begin_transaction().await.map_err(|e| {
                    AppError::Store(format!("firestore begin transaction: {e}"))
                })?;

                for op in chunk {
                    match op {
                        FirestoreBatchOp::Insert {
                            collection,
                            doc_id,
                            doc,
                        } => {
                            self.db
                                .fluent()
                                .update()
                                .in_col(collection)
                                .document_id(doc_id)
                                .object(doc)
                                .add_to_transaction(&mut batch)
                                .map_err(|e| {
                                    AppError::Store(format!("firestore batch insert: {e}"))
                                })?;
                        }
                        FirestoreBatchOp::Remove {
                            collection,
                            doc_id,
                        } => {
                            self.db
                                .fluent()
                                .delete()
                                .from(collection)
                                .document_id(doc_id)
                                .add_to_transaction(&mut batch)
                                .map_err(|e| {
                                    AppError::Store(format!("firestore batch remove: {e}"))
                                })?;
                        }
                    }
                }

                batch.commit().await.map_err(|e| {
                    AppError::Store(format!("firestore commit transaction: {e}"))
                })?;
            }
            Ok(())
        })
    }
}

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
// firestore 0.53 made the `db::support` traits private, so the extension
// methods they carried (`update_obj`, `get_obj_if_exists`, `delete_by_id`,
// `stream_list_obj`) are no longer callable on `FirestoreDb`. Everything below
// goes through the fluent builders instead — the same API `FirestoreBatch`
// already used.
use firestore::*;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::server::config::StoreConfig;
use crate::server::error::AppError;

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

impl KeyspaceOps for FirestoreKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let doc_id = encode_doc_id(&key);
            let doc = KvDoc {
                key: doc_id.clone(),
                data: BASE64.encode(&value),
            };
            // `update` acts as an upsert in Firestore
            let _: KvDoc = self
                .db
                .fluent()
                .update()
                .in_col(&self.collection)
                .document_id(&doc_id)
                .object(&doc)
                .execute()
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
                .fluent()
                .select()
                .by_id_in(&self.collection)
                .obj()
                .one(&doc_id)
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
                .fluent()
                .delete()
                .from(&self.collection)
                .document_id(&doc_id)
                .execute()
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
                .fluent()
                .select()
                .by_id_in(&self.collection)
                .obj()
                .one(&doc_id)
                .await
                .map_err(|e| AppError::Store(format!("firestore get: {e}")))?;
            Ok(result.is_some())
        })
    }

    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        // A Firestore read-write transaction: the read takes a lock on the
        // document and the commit fails (and is retried by
        // `run_transaction`) if another transaction wrote it meanwhile, so
        // exactly one caller — on any replica — gets the value back.
        Box::pin(async move {
            let doc_id = encode_doc_id(&key);
            let collection = self.collection.clone();
            let taken = self
                .db
                .run_transaction(move |db, tx| {
                    let doc_id = doc_id.clone();
                    let collection = collection.clone();
                    Box::pin(async move {
                        let current: Option<KvDoc> = db
                            .fluent()
                            .select()
                            .by_id_in(&collection)
                            .obj()
                            .one(&doc_id)
                            .await?;
                        if current.is_some() {
                            db.fluent()
                                .delete()
                                .from(&collection)
                                .document_id(&doc_id)
                                .add_to_transaction(tx)?;
                        }
                        Ok(current.map(|d| d.data))
                    })
                })
                .await
                .map_err(|e| AppError::Store(format!("firestore take: {e}")))?;
            taken
                .map(|data| {
                    BASE64
                        .decode(&data)
                        .map_err(|e| AppError::Store(format!("firestore decode: {e}")))
                })
                .transpose()
        })
    }

    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        // Read-increment-write inside a Firestore read-write transaction, so
        // two replicas racing on the same counter serialise in the store:
        // the loser's commit aborts and `run_transaction` re-runs it against
        // the winner's value. No increment is lost, across replicas.
        Box::pin(async move {
            let doc_id = encode_doc_id(&key);
            let collection = self.collection.clone();
            self.db
                .run_transaction(move |db, tx| {
                    let doc_id = doc_id.clone();
                    let collection = collection.clone();
                    Box::pin(async move {
                        let current: Option<KvDoc> = db
                            .fluent()
                            .select()
                            .by_id_in(&collection)
                            .obj()
                            .one(&doc_id)
                            .await?;
                        let next = current
                            .and_then(|d| BASE64.decode(&d.data).ok())
                            .map(|bytes| decode_counter(&bytes))
                            .unwrap_or(0)
                            .saturating_add(1);
                        let doc = KvDoc {
                            key: doc_id.clone(),
                            data: BASE64.encode(encode_counter(next)),
                        };
                        db.fluent()
                            .update()
                            .in_col(&collection)
                            .document_id(&doc_id)
                            .object(&doc)
                            .add_to_transaction(tx)?;
                        Ok(next)
                    })
                })
                .await
                .map_err(|e| AppError::Store(format!("firestore incr: {e}")))
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            let mut stream = self
                .db
                .fluent()
                .list()
                .from(&self.collection)
                .page_size(10_000)
                .obj::<KvDoc>()
                .stream_all()
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
                let mut batch =
                    self.db.begin_transaction().await.map_err(|e| {
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
                        FirestoreBatchOp::Remove { collection, doc_id } => {
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

                batch
                    .commit()
                    .await
                    .map_err(|e| AppError::Store(format!("firestore commit transaction: {e}")))?;
            }
            Ok(())
        })
    }
}

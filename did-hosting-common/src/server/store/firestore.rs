//! The Google Cloud Firestore store backend.

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

use super::{BatchOps, BoxFuture, KeyspaceOps, PrefixPage, RawKvPair, StorageBackend};

/// Document model stored in Firestore.
#[derive(Debug, Serialize, Deserialize)]
struct KvDoc {
    /// Base64url-encoded raw key bytes (also the document ID).
    key: String,
    /// Base64url-encoded raw value bytes.
    data: String,
}

/// Firestore's document size limit, 1 MiB.
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Refuse a document Firestore would reject as too large, sized by its
/// documented rules: the name (each collection and document ID, plus one
/// byte each, plus 16), each field's name and string value (plus one byte
/// each), and 32 for the document. The value is stored base64url-encoded, so
/// it counts about a third more than its raw length.
fn check_document_size(collection: &str, doc: &KvDoc) -> Result<(), AppError> {
    super::check_item_size(
        "Firestore",
        document_size(collection, doc),
        MAX_DOCUMENT_BYTES,
    )
}

fn document_size(collection: &str, doc: &KvDoc) -> usize {
    let name = collection.len() + 1 + doc.key.len() + 1 + 16;
    let fields = "key".len() + 1 + doc.key.len() + 1 + "data".len() + 1 + doc.data.len() + 1;
    name + fields + 32
}

/// The most writes one commit (a batch, sent as one transaction) carries.
/// Firestore's documented bound; kept even where it is no longer enforced,
/// since only an unusually large change comes near it.
const MAX_COMMIT_WRITES: usize = 500;

/// The most bytes of documents one commit carries. A commit is one request,
/// and a request is at most 10 MiB; each write is counted as its document's
/// size plus [`COMMIT_WRITE_OVERHEAD`] for its full resource name and
/// encoding, against 10,000,000 bytes, so the bound errs on the side of
/// refusing.
const MAX_COMMIT_BYTES: usize = 10_000_000;

/// Per-write allowance for what a commit request carries besides the
/// document: its full resource name (`projects/…/databases/…/documents/…`)
/// and the write's own framing.
const COMMIT_WRITE_OVERHEAD: usize = 512;

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

    fn max_item_bytes(&self) -> Option<usize> {
        Some(max_value_bytes())
    }
}

/// The largest value a document holds under the shortest key: anything
/// larger is refused under every key. The value is stored base64-encoded,
/// 4 characters for 3 bytes.
fn max_value_bytes() -> usize {
    let empty = KvDoc {
        key: String::new(),
        data: String::new(),
    };
    (MAX_DOCUMENT_BYTES - document_size("", &empty)) * 3 / 4
}

/// The `key` field range every document whose key starts with `prefix`
/// falls in: `[start, start + "~")`.
///
/// Only whole 3-byte groups of the prefix encode the same in every key that
/// starts with it (see `encoded_query_prefix` in the Cosmos DB backend), so
/// `start` encodes those and the rest is checked on the decoded key. `~`
/// sorts after every base64url character, so the range holds exactly the
/// encodings that start with `start`.
fn key_range(prefix: &[u8]) -> (String, String) {
    let start = BASE64.encode(&prefix[..prefix.len() / 3 * 3]);
    let end = format!("{start}~");
    (start, end)
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
            check_document_size(&self.collection, &doc)?;
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

    fn compare_and_swap_raw(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> BoxFuture<'_, Result<bool, AppError>> {
        // Read-compare-write inside a Firestore read-write transaction: a
        // replica that wrote the document meanwhile aborts this commit, and
        // `run_transaction` re-runs the comparison against its value.
        Box::pin(async move {
            let doc_id = encode_doc_id(&key);
            let doc = KvDoc {
                key: doc_id.clone(),
                data: BASE64.encode(&new),
            };
            check_document_size(&self.collection, &doc)?;
            let collection = self.collection.clone();
            let expected = expected.map(|v| BASE64.encode(v));
            self.db
                .run_transaction(move |db, tx| {
                    let doc_id = doc_id.clone();
                    let collection = collection.clone();
                    let expected = expected.clone();
                    let doc = KvDoc {
                        key: doc.key.clone(),
                        data: doc.data.clone(),
                    };
                    Box::pin(async move {
                        let current: Option<KvDoc> = db
                            .fluent()
                            .select()
                            .by_id_in(&collection)
                            .obj()
                            .one(&doc_id)
                            .await?;
                        if current.map(|d| d.data) != expected {
                            return Ok(false);
                        }
                        db.fluent()
                            .update()
                            .in_col(&collection)
                            .document_id(&doc_id)
                            .object(&doc)
                            .add_to_transaction(tx)?;
                        Ok(true)
                    })
                })
                .await
                .map_err(|e| AppError::Store(format!("firestore compare-and-swap: {e}")))
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

    /// One query page over the `key` field, in its order, resumed after the
    /// cursor (the encoded key of the last document the previous page
    /// evaluated). Encoded order is not key order, so pages are not
    /// `ordered`; a document matching the encoded range but not the byte
    /// prefix takes a place in a page, so a page may come back short or
    /// empty while more follow.
    fn prefix_page_raw(
        &self,
        prefix: Vec<u8>,
        cursor: Option<Vec<u8>>,
        limit: usize,
    ) -> BoxFuture<'_, Result<Option<PrefixPage>, AppError>> {
        Box::pin(async move {
            let limit = limit.clamp(1, 10_000);
            let (start, end) = key_range(&prefix);
            let after = cursor
                .map(|c| {
                    String::from_utf8(c)
                        .map_err(|_| AppError::Store("firestore page: malformed cursor".into()))
                })
                .transpose()?;
            let docs: Vec<KvDoc> = self
                .db
                .fluent()
                .select()
                .from(self.collection.as_str())
                .filter(|q| {
                    q.for_all([
                        match &after {
                            Some(after) => q.field("key").greater_than(after.clone()),
                            None => q.field("key").greater_than_or_equal(start.clone()),
                        },
                        q.field("key").less_than(end.clone()),
                    ])
                })
                .order(|o| o.fields([o.field("key").asc()]))
                .limit(u32::try_from(limit).unwrap_or(u32::MAX))
                .obj::<KvDoc>()
                .query()
                .await
                .map_err(|e| AppError::Store(format!("firestore query: {e}")))?;
            let next = (docs.len() == limit)
                .then(|| docs.last().map(|d| d.key.clone().into_bytes()))
                .flatten();
            let mut rows = Vec::new();
            for doc in docs {
                let key = BASE64
                    .decode(&doc.key)
                    .map_err(|e| AppError::Store(format!("firestore decode key: {e}")))?;
                if key.starts_with(&prefix) {
                    let value = BASE64
                        .decode(&doc.data)
                        .map_err(|e| AppError::Store(format!("firestore decode val: {e}")))?;
                    rows.push((key, value));
                }
            }
            Ok(Some(PrefixPage {
                rows,
                next,
                ordered: false,
            }))
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
            check_documents(&self.ops)?;
            check_one_commit(&self.ops)?;
            if self.ops.is_empty() {
                return Ok(());
            }
            send_commit(&self.db, &self.ops).await
        })
    }

    fn commit_in_parts(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            check_documents(&self.ops)?;
            for part in split_commits(&self.ops) {
                send_commit(&self.db, part).await?;
            }
            Ok(())
        })
    }
}

impl FirestoreBatchOp {
    /// What this write counts against a commit's [`MAX_COMMIT_BYTES`].
    fn size(&self) -> usize {
        COMMIT_WRITE_OVERHEAD
            + match self {
                Self::Insert {
                    collection, doc, ..
                } => document_size(collection, doc),
                Self::Remove { collection, doc_id } => collection.len() + doc_id.len(),
            }
    }
}

/// Check every document fits, before anything is sent, so a refused document
/// writes nothing.
fn check_documents(ops: &[FirestoreBatchOp]) -> Result<(), AppError> {
    for op in ops {
        if let FirestoreBatchOp::Insert {
            collection, doc, ..
        } = op
        {
            check_document_size(collection, doc)?;
        }
    }
    Ok(())
}

/// Refuse a batch over one commit's bound. A batch is one commit, so it lands
/// whole or not at all; one over the bound is refused before anything is
/// sent, rather than split into commits that could land part-way.
fn check_one_commit(ops: &[FirestoreBatchOp]) -> Result<(), AppError> {
    let bytes: usize = ops.iter().map(FirestoreBatchOp::size).sum();
    if ops.len() > MAX_COMMIT_WRITES || bytes > MAX_COMMIT_BYTES {
        tracing::warn!(
            writes = ops.len(),
            bytes,
            "batch refused: over one Firestore commit"
        );
        return Err(AppError::quota(
            crate::server::error::QuotaKind::Size,
            format!(
                "a change of {} writes ({bytes} bytes) is over the store's size \
             limit for one atomic write: {MAX_COMMIT_WRITES} writes and \
             {MAX_COMMIT_BYTES} bytes",
                ops.len()
            ),
        ));
    }
    Ok(())
}

/// Split writes into runs that each fit one commit, keeping their order (a
/// commit applies its writes in order, and a later write to a document wins).
/// Every document already fits on its own, so no run is empty.
fn split_commits(ops: &[FirestoreBatchOp]) -> Vec<&[FirestoreBatchOp]> {
    let mut parts = Vec::new();
    let (mut start, mut bytes) = (0, 0);
    for (i, op) in ops.iter().enumerate() {
        let size = op.size();
        if i > start && (i - start == MAX_COMMIT_WRITES || bytes + size > MAX_COMMIT_BYTES) {
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

/// Send `ops` as one transaction commit.
async fn send_commit(db: &FirestoreDb, ops: &[FirestoreBatchOp]) -> Result<(), AppError> {
    let mut batch = db
        .begin_transaction()
        .await
        .map_err(|e| AppError::Store(format!("firestore begin transaction: {e}")))?;

    for op in ops {
        match op {
            FirestoreBatchOp::Insert {
                collection,
                doc_id,
                doc,
            } => {
                db.fluent()
                    .update()
                    .in_col(collection)
                    .document_id(doc_id)
                    .object(doc)
                    .add_to_transaction(&mut batch)
                    .map_err(|e| AppError::Store(format!("firestore batch insert: {e}")))?;
            }
            FirestoreBatchOp::Remove { collection, doc_id } => {
                db.fluent()
                    .delete()
                    .from(collection)
                    .document_id(doc_id)
                    .add_to_transaction(&mut batch)
                    .map_err(|e| AppError::Store(format!("firestore batch remove: {e}")))?;
            }
        }
    }

    batch
        .commit()
        .await
        .map_err(|e| AppError::Store(format!("firestore commit transaction: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(value_len: usize) -> KvDoc {
        let key = encode_doc_id(b"content:alice:log");
        KvDoc {
            data: BASE64.encode(vec![b'x'; value_len]),
            key,
        }
    }

    /// The base64 encoding counts against Firestore's 1 MiB: a 700 KB log
    /// fits, an 800 KB one does not, and it is refused as a size quota.
    #[test]
    fn document_over_1_mib_after_encoding_is_refused_as_a_size_quota() {
        check_document_size("dids", &doc(700 * 1024)).unwrap();
        let err = check_document_size("dids", &doc(800 * 1024)).unwrap_err();
        let AppError::QuotaExceeded { message, .. } = &err else {
            panic!("expected a size quota, got {err:?}");
        };
        assert!(
            message.contains("per-item limit of 1048576 bytes"),
            "{message}"
        );
        assert!(
            !message.contains("Firestore"),
            "the backend is not told to the caller"
        );
    }

    fn insert(i: usize, value_len: usize) -> FirestoreBatchOp {
        let doc_id = encode_doc_id(format!("did:{i}").as_bytes());
        FirestoreBatchOp::Insert {
            collection: "dids".into(),
            doc_id: doc_id.clone(),
            doc: KvDoc {
                key: doc_id,
                data: BASE64.encode(vec![b'x'; value_len]),
            },
        }
    }

    /// A batch is one commit: up to 500 writes is accepted, more is refused
    /// as a size quota rather than split into commits that could land
    /// part-way.
    /// The `key` range holds every encoded key with the byte prefix, at
    /// every prefix length, and nothing that sorts outside it.
    #[test]
    fn the_key_range_holds_every_key_with_the_prefix() {
        let keys: Vec<Vec<u8>> = (0u8..=255)
            .flat_map(|b| {
                (1..=10).map(move |len| {
                    let mut k = vec![b'k'; len];
                    k[0] = b;
                    k[len - 1] = b.wrapping_mul(7);
                    k
                })
            })
            .collect();
        for key in &keys {
            for len in 1..=key.len().min(9) {
                let (start, end) = key_range(&key[..len]);
                let encoded = BASE64.encode(key);
                assert!(
                    start <= encoded && encoded < end,
                    "{key:?} at {len}: {encoded} outside [{start}, {end})"
                );
            }
        }
    }

    /// The figure `max_item_bytes` reports fits a document, one byte more
    /// of value does not.
    #[test]
    fn the_reported_item_limit_fits_one_document() {
        let max = max_value_bytes();
        let key = b"did:example";
        let fits = |value_len: usize| {
            let doc = KvDoc {
                key: encode_doc_id(key),
                data: BASE64.encode(vec![b'x'; value_len]),
            };
            check_document_size("dids", &doc).is_ok()
        };
        assert!(fits(max - 64));
        assert!(!fits(max + 1));
    }

    #[test]
    fn an_atomic_batch_over_500_writes_is_refused() {
        let ops: Vec<_> = (0..501).map(|i| insert(i, 10)).collect();
        check_one_commit(&ops[..500]).unwrap();
        let err = check_one_commit(&ops).unwrap_err();
        assert!(matches!(err, AppError::QuotaExceeded { .. }), "{err:?}");
        assert_eq!(err.quota_kind(), crate::server::error::QuotaKind::Size);
    }

    /// Fourteen 700 KB logs each fit a document, but base64-encoded they are
    /// over one 10 MiB commit together: refused.
    #[test]
    fn an_atomic_batch_over_10_mib_is_refused() {
        let ops: Vec<_> = (0..14).map(|i| insert(i, 700 * 1024)).collect();
        check_documents(&ops).unwrap();
        let err = check_one_commit(&ops).unwrap_err();
        assert!(matches!(err, AppError::QuotaExceeded { .. }), "{err:?}");
    }

    /// `commit_in_parts` splits on both bounds, keeping every write once and
    /// in order.
    #[test]
    fn parts_stay_within_500_writes_and_10_mib() {
        let small: Vec<_> = (0..1200).map(|i| insert(i, 10)).collect();
        let lens: Vec<_> = split_commits(&small).iter().map(|p| p.len()).collect();
        assert_eq!(lens, [500, 500, 200]);

        let large: Vec<_> = (0..40).map(|i| insert(i, 700 * 1024)).collect();
        let parts = split_commits(&large);
        assert!(parts.len() > 1);
        for part in &parts {
            check_one_commit(part).unwrap();
        }
        let ids = |ops: &mut dyn Iterator<Item = &FirestoreBatchOp>| -> Vec<String> {
            ops.map(|op| match op {
                FirestoreBatchOp::Insert { doc_id, .. }
                | FirestoreBatchOp::Remove { doc_id, .. } => doc_id.clone(),
            })
            .collect()
        };
        assert_eq!(
            ids(&mut parts.iter().flat_map(|p| p.iter())),
            ids(&mut large.iter())
        );
    }
}

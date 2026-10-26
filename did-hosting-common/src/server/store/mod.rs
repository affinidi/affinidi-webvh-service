#[cfg(feature = "store-cosmosdb")]
mod cosmosdb;
#[cfg(feature = "store-dynamodb")]
mod dynamodb;
#[cfg(feature = "store-dynamodb-single")]
mod dynamodb_single;
#[cfg(feature = "store-firestore")]
mod firestore;
#[cfg(feature = "store-fjall")]
mod fjall;
pub mod keyspaces;
#[cfg(feature = "store-redis")]
mod redis;
#[cfg(test)]
pub(crate) mod test_support;

pub use keyspaces::{
    KS_ACL, KS_ASSIGNMENTS, KS_DIDS, KS_DOMAINS, KS_IDENTITY, KS_META, KS_OUTBOUND_QUEUE,
    KS_PASSKEY_STEP_UP, KS_PENDING_PURGES, KS_REGISTRY, KS_SCID_FLOORS, KS_SESSIONS, KS_STATS,
    KS_TIMESERIES, KS_TSP_RELATIONSHIPS, KS_WITNESSES,
};

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::config::{FjallTuning, StoreConfig};
use super::error::AppError;

// ---------------------------------------------------------------------------
// Key prefix constants — used across keyspaces to namespace stored data.
//
// session:<id>         — auth session record
// refresh:<token>      — reverse index: refresh token → session_id
// did:<mnemonic>       — DID record (DidRecord)
// content:<m>:log      — raw JSONL did-log content
// content:<m>:witness  — raw witness JSON content
// owner:<did>:<m>      — reverse index: owner DID → mnemonic
// watcher_sync:<m>     — per-DID watcher sync status
// passkey:<handle>     — WebAuthn credential record
// acl:<did>            — ACL entry
// stats:<mnemonic>     — per-DID resolve/update counters
// ts:<mnemonic>:<epoch> — time-series bucket
// ---------------------------------------------------------------------------
pub mod key_prefix {
    pub const SESSION: &str = "session:";
    pub const REFRESH: &str = "refresh:";
    pub const DID: &str = "did:";
    pub const CONTENT: &str = "content:";
    pub const OWNER: &str = "owner:";
    pub const WATCHER_SYNC: &str = "watcher_sync:";
    pub const PASSKEY: &str = "passkey:";
    pub const ACL: &str = "acl:";
    pub const STATS: &str = "stats:";
    pub const TIMESERIES: &str = "ts:";
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A key-value pair of raw bytes from a prefix scan.
pub type RawKvPair = (Vec<u8>, Vec<u8>);

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Per-keyspace CRUD + prefix scan over raw bytes.
pub trait KeyspaceOps: Send + Sync {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>>;
    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>>;
    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>>;
    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>>;
    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>>;

    /// Atomically read a key's value and remove it in one operation.
    ///
    /// Returns `Some(value)` if the key existed and was removed; `None` if
    /// the key was already absent. The semantics are the same as Redis
    /// `GETDEL` — exactly one concurrent caller observes `Some` for any
    /// given key, and all others observe `None`.
    ///
    /// **Required for refresh-token rotation.** A leaked refresh token must
    /// not be usable from two replicas simultaneously; this primitive is
    /// the cross-replica claim the rotation handlers depend on.
    ///
    /// Backends are expected to use a native atomic primitive
    /// (Redis `GETDEL`, DynamoDB `DeleteItem` + `ReturnValues=ALL_OLD`,
    /// a Cosmos DB `If-Match` delete, a Firestore transaction).
    /// Single-replica backends (fjall) wrap the non-atomic `get + remove`
    /// in a process-local mutex.
    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>>;

    /// Atomically increment a counter stored under `key` and return its new
    /// value. A key that does not exist yet starts at 0, so the first call
    /// returns 1.
    ///
    /// **Required for cross-replica lockout counters** — the passkey
    /// enrolment invite's wrong-claim-code count is the first user. A plain
    /// `get` + increment + `insert` races across replicas: two of them can
    /// both read the same count, both compute the same next value, and both
    /// write it back, silently losing an attempt — the exact bug that would
    /// let an attacker exceed the intended lockout threshold by spreading
    /// guesses across replicas.
    ///
    /// Every shared backend makes this atomic in the store itself: Redis
    /// `INCR`, DynamoDB `UpdateItem` with an `ADD` expression, Cosmos DB an
    /// ETag-conditional create/replace, Firestore a read-write transaction.
    /// Only fjall — single-process by construction — uses a process-local
    /// mutex.
    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>>;
}

/// Atomic multi-key write batch identified by keyspace name.
pub trait BatchOps: Send {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>);
    fn remove(&mut self, keyspace: &str, key: Vec<u8>);
    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>>;
}

/// What one atomic [`WriteBatch`] can hold on a backend.
///
/// A backend whose atomic write has a ceiling reports it here and refuses a
/// larger batch at `commit()` (before writing anything) rather than splitting
/// it, because a split batch is not atomic. A caller that writes in bulk and
/// does not need cross-chunk atomicity (a restore, say) chunks to this limit
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchLimits {
    /// Most operations (inserts plus removes) in one batch.
    pub max_ops: usize,
    /// Most bytes in one batch, counted as the sum over its operations of
    /// the keyspace name, key and value lengths (a remove counts no value).
    pub max_bytes: usize,
}

/// Split a bulk write into consecutive chunks that each fit one atomic batch.
///
/// `sizes[i]` is operation `i`'s byte count by the [`BatchLimits::max_bytes`]
/// rule. A chunk holds at most `cap_ops` operations and, when the backend
/// reports `limits`, at most `limits.max_ops` operations and `limits.max_bytes`
/// bytes. An entry that alone exceeds the byte limit still gets a chunk of its
/// own, so the backend refuses it visibly instead of it being dropped or
/// merged. Chunks are contiguous, in order, and cover every entry exactly once.
///
/// Only for callers that do not need atomicity across the whole write: each
/// chunk is its own atomic batch.
pub fn chunk_ranges(
    limits: Option<BatchLimits>,
    cap_ops: usize,
    sizes: &[usize],
) -> Vec<std::ops::Range<usize>> {
    let max_ops = limits.map_or(cap_ops, |l| l.max_ops.min(cap_ops)).max(1);
    let max_bytes = limits.map_or(usize::MAX, |l| l.max_bytes);

    let mut chunks = Vec::new();
    let mut start = 0;
    let mut bytes = 0usize;
    for (i, &size) in sizes.iter().enumerate() {
        let ops = i - start;
        if ops > 0 && (ops >= max_ops || bytes.saturating_add(size) > max_bytes) {
            chunks.push(start..i);
            start = i;
            bytes = 0;
        }
        bytes = bytes.saturating_add(size);
    }
    if start < sizes.len() {
        chunks.push(start..sizes.len());
    }
    chunks
}

/// Factory: create keyspaces, create batches, persist/flush.
pub trait StorageBackend: Send + Sync {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError>;
    fn batch(&self) -> Box<dyn BatchOps>;
    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>>;

    /// The ceiling of one atomic batch, or `None` when the backend imposes
    /// none (the default).
    fn batch_limits(&self) -> Option<BatchLimits> {
        None
    }
}

// ---------------------------------------------------------------------------
// Public wrapper types (same API surface as before)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Store {
    inner: Arc<dyn StorageBackend>,
}

#[derive(Clone)]
pub struct KeyspaceHandle {
    pub name: String,
    inner: Arc<dyn KeyspaceOps>,
    /// The backend this keyspace belongs to, so helpers handed only a
    /// keyspace can still make a multi-row change atomic ([`Self::batch`]).
    backend: Arc<dyn StorageBackend>,
}

/// An atomic write batch that collects operations and commits them in a single call.
pub struct WriteBatch {
    inner: Box<dyn BatchOps>,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

impl Store {
    /// Open a local store, with fjall's own memory tuning (block cache /
    /// write buffer / journal size — see [`FjallTuning`])
    /// left at its defaults. Every pre-existing call site uses this.
    pub async fn open(config: &StoreConfig) -> Result<Self, AppError> {
        Self::open_with(config, &FjallTuning::default()).await
    }

    /// [`Self::open`], applying `tuning`'s fjall memory settings. Only the
    /// real startup paths (did-hosting-control, did-hosting-server,
    /// webvh-witness, webvh-watcher, and did-hosting-daemon) build a
    /// non-default [`FjallTuning`] (their loaded
    /// config file, then an env var override) and call this directly —
    /// everywhere else keeps calling [`Self::open`], which is this with
    /// `FjallTuning::default()` (every field unset), so nothing that
    /// already opened a store needed to change. Backends other than
    /// `store-fjall` (redis, dynamodb, firestore, cosmosdb) ignore
    /// `tuning` entirely — these settings are fjall-specific.
    pub async fn open_with(config: &StoreConfig, tuning: &FjallTuning) -> Result<Self, AppError> {
        let backend = create_backend(config, tuning).await?;
        Ok(Self {
            inner: Arc::from(backend),
        })
    }

    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let (ks_name, ops) = self.inner.keyspace(name)?;
        Ok(KeyspaceHandle {
            name: ks_name,
            inner: ops,
            backend: self.inner.clone(),
        })
    }

    /// Create a new atomic write batch.
    pub fn batch(&self) -> WriteBatch {
        WriteBatch {
            inner: self.inner.batch(),
        }
    }

    /// The ceiling of one atomic batch on this backend, or `None` when it has
    /// none. See [`BatchLimits`].
    pub fn batch_limits(&self) -> Option<BatchLimits> {
        self.inner.batch_limits()
    }

    pub async fn persist(&self) -> Result<(), AppError> {
        self.inner.persist().await
    }
}

// ---------------------------------------------------------------------------
// WriteBatch
// ---------------------------------------------------------------------------

impl WriteBatch {
    /// Add a serializable insert to the batch.
    pub fn insert<V: Serialize>(
        &mut self,
        ks: &KeyspaceHandle,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let bytes = serde_json::to_vec(value)?;
        self.inner.insert_raw(&ks.name, key.into(), bytes);
        Ok(())
    }

    /// Add a raw-bytes insert to the batch.
    pub fn insert_raw(
        &mut self,
        ks: &KeyspaceHandle,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) {
        self.inner.insert_raw(&ks.name, key.into(), value.into());
    }

    /// Add a remove to the batch.
    pub fn remove(&mut self, ks: &KeyspaceHandle, key: impl Into<Vec<u8>>) {
        self.inner.remove(&ks.name, key.into());
    }

    /// Commit all batched operations atomically.
    pub async fn commit(self) -> Result<(), AppError> {
        self.inner.commit().await
    }
}

// ---------------------------------------------------------------------------
// KeyspaceHandle
// ---------------------------------------------------------------------------

impl KeyspaceHandle {
    /// A new atomic write batch on the store this keyspace belongs to —
    /// [`Store::batch`] for code that holds only a keyspace handle. The
    /// batch may span keyspaces like any other.
    pub fn batch(&self) -> WriteBatch {
        WriteBatch {
            inner: self.backend.batch(),
        }
    }

    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let bytes = serde_json::to_vec(value)?;
        self.inner.insert_raw(key.into(), bytes).await
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        match self.inner.get_raw(key.into()).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Atomically get-and-remove a key, returning the deserialized value.
    ///
    /// Backed by `KeyspaceOps::take_raw_atomic` — exactly one concurrent
    /// caller observes `Some` for a given key. Suitable for refresh-token
    /// rotation, single-use enrolment tokens, and any other "consume
    /// exactly once" pattern across multiple webvh replicas.
    pub async fn take<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        match self.inner.take_raw_atomic(key.into()).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Atomically get-and-remove a key's raw bytes.
    ///
    /// See [`Self::take`] for the deserialised version. Use this when the
    /// stored value is not JSON (e.g. a raw session_id under a refresh-
    /// token index).
    pub async fn take_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        self.inner.take_raw_atomic(key.into()).await
    }

    /// Atomically increment a counter and return its new value.
    ///
    /// Backed by `KeyspaceOps::incr_raw` — safe across replicas that share a
    /// store, so a caller relying on the returned count for a lockout
    /// decision gets the same guarantee `take` gives a single-use token.
    pub async fn incr_raw(&self, key: impl Into<Vec<u8>>) -> Result<u64, AppError> {
        self.inner.incr_raw(key.into()).await
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        self.inner.remove(key.into()).await
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        self.inner.insert_raw(key.into(), value.into()).await
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        self.inner.get_raw(key.into()).await
    }

    pub async fn contains_key(&self, key: impl Into<Vec<u8>>) -> Result<bool, AppError> {
        self.inner.contains_key(key.into()).await
    }

    /// Iterate all key-value pairs in the keyspace.
    pub async fn iter_all(&self) -> Result<Vec<RawKvPair>, AppError> {
        self.prefix_iter_raw(b"").await
    }

    /// Iterate all key-value pairs whose key starts with `prefix`.
    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        self.inner.prefix_iter_raw(prefix.into()).await
    }

    /// Returns the approximate number of items in the keyspace.
    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        Ok(self.prefix_iter_raw(b"").await?.len())
    }

    /// Verify integrity of all entries in this keyspace.
    ///
    /// Scans all key-value pairs and attempts to parse each value as JSON.
    /// Returns the number of corrupted (unparseable) entries found.
    /// Corrupted entries are logged as warnings.
    pub async fn verify_integrity(&self) -> Result<u64, AppError> {
        let all = self.prefix_iter_raw(b"").await?;
        let mut corrupted = 0u64;
        for (key, value) in &all {
            let key_str = String::from_utf8_lossy(key);
            // Skip entries that store raw bytes, not JSON
            if key_str.starts_with("content:")
                || key_str.starts_with("owner:")
                || key_str.starts_with("refresh:")
                || key_str.starts_with("ts:")
            {
                continue;
            }
            if serde_json::from_slice::<serde_json::Value>(value).is_err() {
                tracing::warn!(key = %key_str, "integrity check: corrupted entry (invalid JSON)");
                corrupted += 1;
            }
        }
        Ok(corrupted)
    }
}

// ---------------------------------------------------------------------------
// Backend factory
// ---------------------------------------------------------------------------

#[allow(unused_variables)]
async fn create_backend(
    config: &StoreConfig,
    tuning: &FjallTuning,
) -> Result<Box<dyn StorageBackend>, AppError> {
    #[cfg(feature = "store-fjall")]
    {
        return fjall::FjallBackend::open_with(config, tuning);
    }

    #[cfg(feature = "store-redis")]
    {
        return redis::RedisBackend::open(config).await;
    }

    #[cfg(feature = "store-dynamodb")]
    {
        return dynamodb::DynamoDbBackend::open(config).await;
    }

    #[cfg(feature = "store-dynamodb-single")]
    {
        return dynamodb_single::SingleTableDynamoDbBackend::open(config).await;
    }

    #[cfg(feature = "store-firestore")]
    {
        return firestore::FirestoreBackend::open(config).await;
    }

    #[cfg(feature = "store-cosmosdb")]
    {
        return cosmosdb::CosmosDbBackend::open(config).await;
    }

    // build.rs enforces exactly one feature, so this is unreachable
    #[allow(unreachable_code)]
    Err(AppError::Config(
        "no storage backend compiled — enable a store-* feature".into(),
    ))
}

#[cfg(test)]
mod chunk_tests {
    use super::{BatchLimits, chunk_ranges};

    const LIMITS: BatchLimits = BatchLimits {
        max_ops: 3,
        max_bytes: 100,
    };

    #[test]
    fn no_limits_chunks_only_by_the_callers_cap() {
        let sizes = [10; 7];
        assert_eq!(chunk_ranges(None, 3, &sizes), vec![0..3, 3..6, 6..7]);
    }

    #[test]
    fn empty_input_plans_no_chunks() {
        assert!(chunk_ranges(Some(LIMITS), 1000, &[]).is_empty());
    }

    #[test]
    fn the_smaller_of_the_cap_and_the_limit_wins_on_op_count() {
        let sizes = [1; 7];
        assert_eq!(
            chunk_ranges(Some(LIMITS), 1000, &sizes),
            vec![0..3, 3..6, 6..7]
        );
        assert_eq!(
            chunk_ranges(Some(LIMITS), 2, &sizes),
            vec![0..2, 2..4, 4..6, 6..7]
        );
    }

    #[test]
    fn a_chunk_closes_before_it_would_exceed_the_byte_limit() {
        // 60 + 60 > 100 closes the first chunk; 60 + 30 = 90 fits but another
        // 30 would make 120, so the second closes; the last two (60) fit.
        assert_eq!(
            chunk_ranges(Some(LIMITS), 1000, &[60, 60, 30, 30, 30]),
            vec![0..1, 1..3, 3..5]
        );
    }

    #[test]
    fn a_chunk_may_fill_the_byte_limit_exactly() {
        assert_eq!(
            chunk_ranges(Some(LIMITS), 1000, &[50, 50, 50]),
            vec![0..2, 2..3]
        );
    }

    #[test]
    fn an_oversized_single_entry_gets_its_own_chunk_for_the_backend_to_refuse() {
        // Never silently dropped or merged: the backend reports the refusal.
        assert_eq!(
            chunk_ranges(Some(LIMITS), 1000, &[500, 10]),
            vec![0..1, 1..2]
        );
    }

    #[test]
    fn every_entry_lands_in_exactly_one_chunk_in_order() {
        let sizes: Vec<usize> = (0..257).map(|i| (i * 7) % 41 + 1).collect();
        let chunks = chunk_ranges(Some(LIMITS), 1000, &sizes);
        let mut next = 0;
        for range in &chunks {
            assert_eq!(range.start, next, "chunks are contiguous");
            assert!(range.end > range.start && range.len() <= LIMITS.max_ops);
            assert!(
                sizes[range.clone()].iter().sum::<usize>() <= LIMITS.max_bytes || range.len() == 1
            );
            next = range.end;
        }
        assert_eq!(next, sizes.len(), "nothing dropped");
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod bounded_memory;
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

use std::cell::Cell;
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

/// Refuse a write whose stored item, `size` bytes as `backend` counts it,
/// is over that backend's per-item `limit`.
///
/// Backends with a per-item limit (DynamoDB, Firestore) check every item
/// before they send anything, so a refused batch writes nothing. The error is
/// [`AppError::QuotaExceeded`], whose message reaches the caller: a Trust Task
/// answers `taskFailed` with it (HTTPS `422`), and an edge or watcher refuses
/// the sync as `taskFailed` rather than retrying it. Left to the backend, the
/// same write failed as a store error (`500`) that no retry could fix. The
/// backend is logged here, not told to the caller.
#[cfg(any(feature = "store-dynamodb", feature = "store-firestore"))]
fn check_item_size(backend: &str, size: usize, limit: usize) -> Result<(), AppError> {
    if size > limit {
        tracing::warn!(
            backend,
            size,
            limit,
            "write refused: item over the store's per-item limit"
        );
        // `AppError::quota_kind` keys on the word "size".
        return Err(AppError::QuotaExceeded(format!(
            "item size {size} bytes is over the store's per-item limit of {limit} bytes"
        )));
    }
    Ok(())
}

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
    /// Apply every operation or none. A backend whose transactions are
    /// bounded (DynamoDB: 100 writes, 4 MB) refuses a batch over its bound
    /// before writing anything, rather than splitting it.
    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>>;
    /// Apply every operation, in as many store transactions as the backend
    /// needs: a failure part-way leaves the earlier parts written. Only for
    /// bulk loads that are safe to re-run, such as a backup restore. The
    /// default is [`Self::commit`], for backends with no such bound.
    fn commit_in_parts(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        self.commit()
    }
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

/// Writes besides one name-index row per agent name that the largest write
/// caused by publishing a DID makes: an edge's `apply_single_update` stores the
/// record, the log, the owner row, the witness row and two high-water marks. The
/// control plane's own publish batches are never bigger than that (record, log,
/// owner row and, on a takeover, two removals).
pub const PUBLISH_FIXED_WRITES: usize = 6;

impl BatchLimits {
    /// The most agent names a DID's document may claim for every write its
    /// publication causes to fit one atomic batch, or any number on a backend
    /// with no batch limit (see [`Store::max_agent_names`]).
    ///
    /// A publication writes an index row for each name it claims and removes the
    /// rows of the names it drops. Both sets are at most the cap, so the batch
    /// holds at most `2 * cap + PUBLISH_FIXED_WRITES` operations. Refusing a
    /// document over the cap up front keeps every accepted publication
    /// committable, here and on every edge it is synced to, without splitting a
    /// batch that must stay atomic.
    pub fn max_agent_names(&self) -> usize {
        self.max_ops.saturating_sub(PUBLISH_FIXED_WRITES) / 2
    }
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

    /// [`Self::keyspace`], with every `get_raw` and `contains_key` seeing
    /// all writes that committed before it. DynamoDB overrides this; fjall,
    /// Redis (against a primary) and Firestore already read their latest
    /// write. Cosmos DB does only if the account's consistency level gives
    /// it: nothing here asks for more.
    fn keyspace_consistent(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        self.keyspace(name)
    }

    /// [`Self::keyspace_consistent`], with `prefix_iter_raw` consistent
    /// too. DynamoDB overrides this; the other backends' scans already
    /// read their latest write, with the same Cosmos DB caveat.
    fn keyspace_consistent_with_scans(
        &self,
        name: &str,
    ) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        self.keyspace_consistent(name)
    }

    fn batch(&self) -> Box<dyn BatchOps>;
    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>>;

    /// The ceiling of one atomic batch, or `None` when the backend imposes
    /// none (the default).
    fn batch_limits(&self) -> Option<BatchLimits> {
        None
    }

    /// Whether a failed `commit()` of a batch wrote none of it.
    ///
    /// A caller that drains work before it commits and wants to retry it after a
    /// failure may only do so when this is `true`: on a backend that can commit
    /// part of a batch and then fail, retrying the whole batch writes the
    /// committed part twice. `false` is the default, so a backend must opt in,
    /// and only does so when its commit is one all-or-nothing operation (a
    /// journalled batch, `MULTI`/`EXEC`, a transaction), not a sequence of writes
    /// or of smaller batches.
    fn commits_atomically(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Write tracking
// ---------------------------------------------------------------------------

tokio::task_local! {
    /// Set once the task running under [`track_writes`] attempts a store write.
    static WROTE: Cell<bool>;
}

/// Run `f` and report whether it attempted a store write, through any
/// keyspace or batch. A write that failed counts too: a backend may have
/// applied it, or part of a batch, before reporting the failure. Writes made
/// by tasks `f` spawns are not seen. Box a large `f` (a dispatch) before
/// passing it: built on the stack and nested in the scope's future, it can
/// overflow a thread's stack.
pub async fn track_writes<F: Future>(f: F) -> (F::Output, bool) {
    WROTE
        .scope(
            Cell::new(false),
            Box::pin(async {
                let out = f.await;
                (out, WROTE.with(Cell::get))
            }),
        )
        .await
}

fn note_write() {
    let _ = WROTE.try_with(|wrote| wrote.set(true));
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

    /// A store over a caller-supplied backend, so a test can exercise code that
    /// takes a [`Store`] against a backend with a batch ceiling, or one that
    /// fails a commit, without a real database.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_backend(backend: Arc<dyn StorageBackend>) -> Self {
        Self { inner: backend }
    }

    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let (ks_name, ops) = self.inner.keyspace(name)?;
        Ok(KeyspaceHandle {
            name: ks_name,
            inner: ops,
            backend: self.inner.clone(),
        })
    }

    /// [`Self::keyspace`] for code whose reads decide a write: a key read
    /// through this handle reflects every write committed before the read
    /// (on Cosmos DB, only as far as the account's consistency level
    /// allows; see [`StorageBackend::keyspace_consistent`]). Prefix scans
    /// are not covered; see [`Self::keyspace_consistent_with_scans`]. Costs
    /// more on DynamoDB (twice the read units), so read-heavy paths keep
    /// [`Self::keyspace`]: an edge reads DID records through it on every
    /// resolve.
    pub fn keyspace_consistent(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let (ks_name, ops) = self.inner.keyspace_consistent(name)?;
        Ok(KeyspaceHandle {
            name: ks_name,
            inner: ops,
            backend: self.inner.clone(),
        })
    }

    /// [`Self::keyspace_consistent`], with prefix scans consistent too. A
    /// consistent scan costs twice the read units of the whole keyspace on
    /// DynamoDB, so this is for small keyspaces whose scan decides
    /// something, such as the domains resolution checks.
    pub fn keyspace_consistent_with_scans(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let (ks_name, ops) = self.inner.keyspace_consistent_with_scans(name)?;
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

    /// The most agent names one DID may claim on this backend, or `None` when its
    /// batches have no ceiling. See [`BatchLimits::max_agent_names`].
    pub fn max_agent_names(&self) -> Option<usize> {
        self.batch_limits().map(|l| l.max_agent_names())
    }

    /// Whether a failed batch commit on this backend wrote none of it. See
    /// [`StorageBackend::commits_atomically`].
    pub fn commits_atomically(&self) -> bool {
        self.inner.commits_atomically()
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

    /// Commit all batched operations atomically. On DynamoDB a batch over
    /// one transaction's bound (100 writes, 4 MB) is refused as
    /// [`AppError::QuotaExceeded`] and writes nothing.
    pub async fn commit(self) -> Result<(), AppError> {
        note_write();
        self.inner.commit().await
    }

    /// Commit all batched operations, **not** atomically: a backend with a
    /// transaction bound splits the batch, and a failure part-way leaves the
    /// earlier parts written. Only for bulk loads that are safe to re-run
    /// (a backup restore); anything that must change together uses
    /// [`Self::commit`].
    pub async fn commit_in_parts(self) -> Result<(), AppError> {
        note_write();
        self.inner.commit_in_parts().await
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
        note_write();
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
        note_write();
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
        note_write();
        self.inner.take_raw_atomic(key.into()).await
    }

    /// Atomically increment a counter and return its new value.
    ///
    /// Backed by `KeyspaceOps::incr_raw` — safe across replicas that share a
    /// store, so a caller relying on the returned count for a lockout
    /// decision gets the same guarantee `take` gives a single-use token.
    pub async fn incr_raw(&self, key: impl Into<Vec<u8>>) -> Result<u64, AppError> {
        note_write();
        self.inner.incr_raw(key.into()).await
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        note_write();
        self.inner.remove(key.into()).await
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        note_write();
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
            // Skip entries that store raw bytes, not JSON: logs (`content:`,
            // the edge's `hw:` high-water JSONL) and reverse indexes whose
            // value is a bare mnemonic (`owner:`, the agent-name `name:`).
            if key_str.starts_with("content:")
                || key_str.starts_with("owner:")
                || key_str.starts_with("name:")
                || key_str.starts_with("hw:")
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

// ---------------------------------------------------------------------------
// Test support: a keyspace whose writes start failing
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
impl KeyspaceHandle {
    /// Wrap this keyspace so that once `allowed` writes have succeeded,
    /// every further write fails with a store error, as a throttled store
    /// would. Reads are untouched. Raise `allowed` to let writes through
    /// again.
    pub fn failing_writes_after(&self, allowed: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        self.wrap_failing(allowed, false, injected_write_failure)
    }

    /// Like [`Self::failing_writes_after`], but a failing write is refused as
    /// a throttled store would ([`AppError::store_throttled`]).
    pub fn throttled_writes_after(&self, allowed: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        self.wrap_failing(allowed, false, AppError::store_throttled)
    }

    /// Like [`Self::failing_writes_after`], but a failing write is applied
    /// before it reports failure, as when a store times out after the write
    /// landed.
    pub fn failing_acks_after(&self, allowed: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        self.wrap_failing(allowed, true, injected_write_failure)
    }

    /// Wrap this keyspace so every read fails as a throttled store would
    /// ([`AppError::store_throttled`]). Writes are untouched.
    pub fn throttled_reads(&self) -> Self {
        self.failing_reads_after(0, AppError::store_throttled)
    }

    /// Wrap this keyspace so that once `allowed` reads have succeeded, every
    /// further read fails with `error()`. Writes are untouched.
    pub fn failing_reads_after(&self, allowed: usize, error: fn() -> AppError) -> Self {
        Self {
            name: self.name.clone(),
            inner: Arc::new(FailingReads {
                inner: self.inner.clone(),
                allowed: std::sync::atomic::AtomicUsize::new(allowed),
                error,
            }),
            backend: self.backend.clone(),
        }
    }

    fn wrap_failing(
        &self,
        allowed: Arc<std::sync::atomic::AtomicUsize>,
        apply: bool,
        error: fn() -> AppError,
    ) -> Self {
        Self {
            name: self.name.clone(),
            inner: Arc::new(FailingWrites {
                inner: self.inner.clone(),
                allowed,
                apply,
                error,
            }),
            backend: self.backend.clone(),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
struct FailingWrites {
    inner: Arc<dyn KeyspaceOps>,
    allowed: Arc<std::sync::atomic::AtomicUsize>,
    /// Apply a failing write before reporting the failure.
    apply: bool,
    error: fn() -> AppError,
}

#[cfg(any(test, feature = "test-support"))]
fn injected_write_failure() -> AppError {
    AppError::Store("injected write failure".into())
}

#[cfg(any(test, feature = "test-support"))]
impl FailingWrites {
    fn take_write(&self) -> Result<(), AppError> {
        use std::sync::atomic::Ordering;
        self.allowed
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .map(|_| ())
            .map_err(|_| (self.error)())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl KeyspaceOps for FailingWrites {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            match self.take_write() {
                Ok(()) => self.inner.insert_raw(key, value).await,
                Err(e) => {
                    if self.apply {
                        self.inner.insert_raw(key, value).await?;
                    }
                    Err(e)
                }
            }
        })
    }
    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        self.inner.get_raw(key)
    }
    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            self.take_write()?;
            self.inner.remove(key).await
        })
    }
    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        self.inner.contains_key(key)
    }
    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        self.inner.prefix_iter_raw(prefix)
    }
    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            self.take_write()?;
            self.inner.take_raw_atomic(key).await
        })
    }
    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        Box::pin(async move {
            self.take_write()?;
            self.inner.incr_raw(key).await
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
struct FailingReads {
    inner: Arc<dyn KeyspaceOps>,
    allowed: std::sync::atomic::AtomicUsize,
    error: fn() -> AppError,
}

#[cfg(any(test, feature = "test-support"))]
impl FailingReads {
    fn take_read(&self) -> Result<(), AppError> {
        use std::sync::atomic::Ordering;
        self.allowed
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .map(|_| ())
            .map_err(|_| (self.error)())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl KeyspaceOps for FailingReads {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        self.inner.insert_raw(key, value)
    }
    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            self.take_read()?;
            self.inner.get_raw(key).await
        })
    }
    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        self.inner.remove(key)
    }
    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            self.take_read()?;
            self.inner.contains_key(key).await
        })
    }
    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            self.take_read()?;
            self.inner.prefix_iter_raw(prefix).await
        })
    }
    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        self.inner.take_raw_atomic(key)
    }
    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        self.inner.incr_raw(key)
    }
}

#[cfg(test)]
mod chunk_tests {
    use super::{BatchLimits, chunk_ranges};

    const LIMITS: BatchLimits = BatchLimits {
        max_ops: 3,
        max_bytes: 100,
    };

    #[test]
    fn the_agent_name_cap_leaves_room_for_the_names_dropped_and_the_fixed_writes() {
        let l = |max_ops| BatchLimits {
            max_ops,
            max_bytes: usize::MAX,
        };
        // 100 operations: 47 inserts + 47 removals + 6 fixed = 100.
        assert_eq!(l(100).max_agent_names(), 47);
        assert_eq!(2 * 47 + super::PUBLISH_FIXED_WRITES, 100);
        assert_eq!(l(101).max_agent_names(), 47, "rounds down");
        assert_eq!(l(6).max_agent_names(), 0);
        assert_eq!(l(2).max_agent_names(), 0, "never underflows");
    }

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

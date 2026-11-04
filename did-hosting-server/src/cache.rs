//! Simple in-memory caches with TTL-based eviction.
//!
//! [`ContentCache`] holds DID content (`did.jsonl`, the witness file, a
//! did:web `did.json`) to reduce store lookups on the hot DID resolution
//! path; [`GateCache`] holds what resolution checks before serving it. An
//! expired entry is ignored on read and dropped by `evict_expired`, which a
//! background task calls every minute. Uses `Arc<Vec<u8>>` to avoid cloning
//! large documents on cache hits.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use did_hosting_common::server::domain::ResolutionDomains;
use did_hosting_common::server::store::{KS_DIDS, KS_DOMAINS, KeyspaceHandle, Store};

use crate::did_ops::{DidRecord, content_log_key, content_witness_key, did_key};
use crate::error::AppError;

/// How long a resolution cache entry lives: the most a change made without
/// telling the cache (another process writing the store) stays hidden.
pub const RESOLUTION_CACHE_TTL: Duration = Duration::from_secs(300);

struct CacheEntry {
    data: Arc<Vec<u8>>,
    inserted_at: Instant,
}

/// Thread-safe content cache with TTL-based eviction.
///
/// Uses `RwLock<HashMap>` — reads only acquire a read lock (no contention
/// between concurrent resolves). Writes acquire a write lock (infrequent:
/// only on cache miss or invalidation).
///
/// Data is stored behind `Arc` so cache hits return a cheap reference-counted
/// pointer instead of cloning the entire document.
pub struct ContentCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// Bumped by every invalidation. A miss takes it before reading the
    /// store and [`Self::insert`] stores only if it has not moved, so a
    /// read that raced a publish cannot put back the bytes from before it.
    generation: AtomicU64,
    ttl: Duration,
}

impl ContentCache {
    /// Create a new cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            generation: AtomicU64::new(0),
            ttl,
        }
    }

    /// The key a did:web `did.json` (extracted from the log) is cached
    /// under. Every key for a DID is dropped by [`Self::invalidate_did`].
    pub fn did_web_document_key(mnemonic: &str) -> String {
        format!("content:{mnemonic}:did.json")
    }

    /// Get cached content if it exists and hasn't expired.
    /// Returns an `Arc<Vec<u8>>` — cheap clone (reference count bump only).
    pub fn get(&self, key: &str) -> Option<Arc<Vec<u8>>> {
        let entries = self.entries.read().ok()?;
        let entry = entries.get(key)?;
        if entry.inserted_at.elapsed() < self.ttl {
            Some(entry.data.clone()) // Arc clone = atomic ref count increment
        } else {
            None // Expired — caller should fetch from store and re-insert
        }
    }

    /// The current generation: take it before reading the store on a miss,
    /// and pass it to [`Self::insert`].
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Insert or update a cache entry read from the store, unless something
    /// was invalidated since `generation` was taken.
    pub fn insert(&self, generation: u64, key: String, data: Vec<u8>) {
        if let Ok(mut entries) = self.entries.write()
            && self.generation() == generation
        {
            entries.insert(
                key,
                CacheEntry {
                    data: Arc::new(data),
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    /// Drop everything cached for `mnemonic` (its log, witness file and
    /// did:web document): call after any commit that changes them.
    pub fn invalidate_did(&self, mnemonic: &str) {
        // Bump while holding the lock, so no insert lands between the two.
        if let Ok(mut entries) = self.entries.write() {
            self.generation.fetch_add(1, Ordering::SeqCst);
            entries.remove(&content_log_key(mnemonic));
            entries.remove(&content_witness_key(mnemonic));
            entries.remove(&Self::did_web_document_key(mnemonic));
        }
    }

    /// Drop every entry — after a change that removes content in bulk (a
    /// domain purge), where naming each key would mean re-reading what is gone.
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            self.generation.fetch_add(1, Ordering::SeqCst);
            entries.clear();
        }
    }

    /// Remove all expired entries (call periodically from cleanup thread).
    pub fn evict_expired(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.retain(|_, entry| entry.inserted_at.elapsed() < self.ttl);
        }
    }
}

/// What resolution checks before serving bytes, cached: each DID's record
/// (disabled, deleted, its identifier) and the `domains` keyspace. With
/// these and the content cache warm, a resolve reads nothing from the store.
///
/// Only correct where every change to a record's gate state or to a domain
/// clears it in this process. A daemon running its own control plane, alone
/// on its store, is that case: the control plane writes in-process and calls
/// [`Self::forget_did`] and [`Self::forget_domains`] after each commit. A
/// standalone edge, or a daemon with its control plane off, leaves it off:
/// a writer elsewhere would never clear this one, and a disabled DID would
/// keep resolving here until the TTL.
///
/// A miss reads strongly consistent, the domains scan included (see
/// [`Store::keyspace_consistent_with_scans`]): an eventually consistent
/// read right after a disable could return the state from before it, and
/// this cache would then keep it for the TTL.
/// The TTL bounds staleness from writers that cannot call back (an admin
/// command run against the store from another process).
pub struct GateCache {
    dids_ks: KeyspaceHandle,
    domains_ks: KeyspaceHandle,
    records: RwLock<HashMap<String, GateEntry<Arc<DidRecord>>>>,
    domains: RwLock<Option<GateEntry<Arc<ResolutionDomains>>>>,
    /// Bumped by every record forget. A miss takes it before reading the
    /// store and caches what it read only if it has not moved, so a read
    /// that raced a write cannot put back what the write just cleared.
    record_generation: AtomicU64,
    /// The same, for the domains: kept apart so DID writes do not keep the
    /// domains (one consistent scan per load) from being cached.
    domain_generation: AtomicU64,
    ttl: Duration,
}

struct GateEntry<T> {
    value: T,
    inserted_at: Instant,
}

impl<T: Clone> GateEntry<T> {
    fn fresh(&self, ttl: Duration) -> Option<T> {
        (self.inserted_at.elapsed() < ttl).then(|| self.value.clone())
    }
}

impl GateCache {
    /// An empty cache over `store`, whose entries live for `ttl`.
    pub fn new(store: &Store, ttl: Duration) -> Result<Self, AppError> {
        Ok(Self {
            dids_ks: store.keyspace_consistent(KS_DIDS)?,
            // Domains load by scan; the keyspace holds a handful of rows.
            domains_ks: store.keyspace_consistent_with_scans(KS_DOMAINS)?,
            records: RwLock::new(HashMap::new()),
            domains: RwLock::new(None),
            record_generation: AtomicU64::new(0),
            domain_generation: AtomicU64::new(0),
            ttl,
        })
    }

    /// The strongly consistent DID keyspace this cache reads through. A
    /// resolver keeping a gate cache reads content misses through it too,
    /// so a miss right after a publish cannot cache the log from before it.
    pub fn dids_ks(&self) -> &KeyspaceHandle {
        &self.dids_ks
    }

    /// `mnemonic`'s record, from the cache or else the store. Only records
    /// that exist are cached: a miss for any path a client makes up must
    /// not grow the map.
    pub async fn record(&self, mnemonic: &str) -> Result<Option<Arc<DidRecord>>, AppError> {
        let cached = self
            .records
            .read()
            .ok()
            .and_then(|records| records.get(mnemonic)?.fresh(self.ttl));
        if let Some(record) = cached {
            return Ok(Some(record));
        }
        let generation = self.record_generation.load(Ordering::SeqCst);
        let Some(record) = self.dids_ks.get::<DidRecord>(did_key(mnemonic)).await? else {
            return Ok(None);
        };
        let record = Arc::new(record);
        if let Ok(mut records) = self.records.write()
            && self.record_generation.load(Ordering::SeqCst) == generation
        {
            records.insert(
                mnemonic.to_string(),
                GateEntry {
                    value: record.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }
        Ok(Some(record))
    }

    /// The domains, from the cache or else the store.
    pub async fn domains(&self) -> Result<Arc<ResolutionDomains>, AppError> {
        let cached = self
            .domains
            .read()
            .ok()
            .and_then(|domains| domains.as_ref()?.fresh(self.ttl));
        if let Some(domains) = cached {
            return Ok(domains);
        }
        let generation = self.domain_generation.load(Ordering::SeqCst);
        let domains = Arc::new(ResolutionDomains::load_from(&self.domains_ks).await?);
        if let Ok(mut slot) = self.domains.write()
            && self.domain_generation.load(Ordering::SeqCst) == generation
        {
            *slot = Some(GateEntry {
                value: domains.clone(),
                inserted_at: Instant::now(),
            });
        }
        Ok(domains)
    }

    /// Drop `mnemonic`'s record: call after any commit that changes it.
    pub fn forget_did(&self, mnemonic: &str) {
        // Bump while holding the lock, so no insert lands between the two.
        if let Ok(mut records) = self.records.write() {
            self.record_generation.fetch_add(1, Ordering::SeqCst);
            records.remove(mnemonic);
        }
    }

    /// Drop the domains: call after any commit that changes a domain.
    pub fn forget_domains(&self) {
        if let Ok(mut domains) = self.domains.write() {
            self.domain_generation.fetch_add(1, Ordering::SeqCst);
            *domains = None;
        }
    }

    /// Drop everything: after a change too broad to name (a domain purge
    /// deleting its DIDs).
    pub fn clear(&self) {
        if let Ok(mut records) = self.records.write() {
            self.record_generation.fetch_add(1, Ordering::SeqCst);
            records.clear();
        }
        self.forget_domains();
    }

    /// Remove expired entries (call periodically from a cleanup task).
    pub fn evict_expired(&self) {
        if let Ok(mut records) = self.records.write() {
            records.retain(|_, entry| entry.inserted_at.elapsed() < self.ttl);
        }
        if let Ok(mut domains) = self.domains.write()
            && domains
                .as_ref()
                .is_some_and(|entry| entry.inserted_at.elapsed() >= self.ttl)
        {
            *domains = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_that_raced_an_invalidation_is_not_cached() {
        let cache = ContentCache::new(Duration::from_secs(60));
        let key = content_log_key("alice");

        // A miss takes the generation, then a publish invalidates the DID
        // before the miss's store read comes back.
        let generation = cache.generation();
        cache.invalidate_did("alice");
        cache.insert(generation, key.clone(), b"from before the publish".to_vec());
        assert!(cache.get(&key).is_none());

        cache.insert(cache.generation(), key.clone(), b"current".to_vec());
        assert_eq!(cache.get(&key).unwrap().as_slice(), b"current");
    }

    #[test]
    fn invalidating_a_did_drops_all_its_entries_and_only_its() {
        let cache = ContentCache::new(Duration::from_secs(60));
        let keys = [
            content_log_key("alice"),
            content_witness_key("alice"),
            ContentCache::did_web_document_key("alice"),
        ];
        for key in keys.iter().chain([&content_log_key("bob")]) {
            cache.insert(cache.generation(), key.clone(), b"x".to_vec());
        }
        cache.invalidate_did("alice");
        assert!(keys.iter().all(|key| cache.get(key).is_none()));
        assert!(cache.get(&content_log_key("bob")).is_some());
    }
}

//! Simple in-memory caches with TTL-based eviction.
//!
//! [`ContentCache`] holds DID content (`did.jsonl`, the witness file, a
//! did:web `did.json`) to reduce store lookups on the hot DID resolution
//! path; [`GateCache`] holds what resolution checks before serving it. An
//! expired entry is ignored on read and dropped by `evict_expired`, which a
//! background task calls every minute. Content is held as [`Bytes`] with its
//! strong ETag computed once at insert, so a hit costs a reference-count bump
//! and a conditional request is answered without hashing anything.
//!
//! Every write an edge makes that changes what resolution would serve goes
//! through [`ResolutionCaches`], the one place that clears both caches.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use did_hosting_common::server::domain::ResolutionDomains;
use did_hosting_common::server::store::{KS_DIDS, KS_DOMAINS, KeyspaceHandle, Store};
use sha2::{Digest, Sha256};

use crate::did_ops::{DidRecord, content_log_key, content_witness_key, did_key};
use crate::error::AppError;

/// How long a resolution cache entry lives: the most a change made without
/// telling the cache (another process writing the store) stays hidden.
pub const RESOLUTION_CACHE_TTL: Duration = Duration::from_secs(300);

/// The bytes a [`ContentCache`] holds by default (`limits.content_cache_bytes`).
pub const DEFAULT_CONTENT_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// How many derived `did:webs` documents [`ContentCache`] keeps.
const WEBS_DOCUMENT_MEMO_ENTRIES: usize = 4096;

/// The strong entity tag of `bytes`: the quoted hex SHA-256 of exactly the
/// bytes served (RFC 9110 §8.8.3).
pub fn strong_etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Sha256::digest(bytes)))
}

/// Whether an `If-None-Match` header value matches `etag`, by the weak
/// comparison RFC 9110 §13.1.2 prescribes for it: `*`, or any listed tag
/// whose opaque part equals ours, `W/` prefix or not.
pub fn if_none_match_hits(header: &str, etag: &str) -> bool {
    let ours = etag.trim_start_matches("W/");
    header.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || (!candidate.is_empty() && candidate.trim_start_matches("W/") == ours)
    })
}

/// Content ready to serve: the bytes and their strong ETag.
#[derive(Clone, Debug)]
pub struct CachedContent {
    pub bytes: Bytes,
    pub etag: Arc<str>,
}

impl CachedContent {
    /// `bytes` with its ETag computed.
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        let etag = strong_etag(&bytes).into();
        Self { bytes, etag }
    }
}

struct CacheEntry {
    content: CachedContent,
    inserted_at: Instant,
}

/// The entries and the bytes they hold, under one lock.
#[derive(Default)]
struct Entries {
    map: HashMap<String, CacheEntry>,
    bytes: usize,
}

impl Entries {
    fn remove(&mut self, key: &str) {
        if let Some(old) = self.map.remove(key) {
            self.bytes -= old.content.bytes.len();
        }
    }

    /// Drop expired entries, then the oldest, until `incoming` more bytes fit
    /// in `max` with a tenth to spare (so a full cache does not evict on
    /// every insert).
    fn make_room(&mut self, incoming: usize, max: usize, ttl: Duration) {
        if self.bytes + incoming <= max {
            return;
        }
        let expired: Vec<String> = self
            .map
            .iter()
            .filter(|(_, e)| e.inserted_at.elapsed() >= ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
        let target = max - max / 10;
        if self.bytes + incoming <= target {
            return;
        }
        let mut by_age: Vec<(Instant, String)> = self
            .map
            .iter()
            .map(|(k, e)| (e.inserted_at, k.clone()))
            .collect();
        by_age.sort();
        for (_, key) in by_age {
            if self.bytes + incoming <= target {
                break;
            }
            self.remove(&key);
        }
    }
}

/// Thread-safe content cache with TTL-based eviction and a bound on the
/// bytes it holds.
///
/// Uses `RwLock<HashMap>` — reads only acquire a read lock (no contention
/// between concurrent resolves). Writes acquire a write lock (infrequent:
/// only on cache miss or invalidation). Content is [`Bytes`], so a hit
/// returns a reference-counted view instead of a copy of the document.
pub struct ContentCache {
    entries: RwLock<Entries>,
    /// Bumped by every invalidation. A miss takes it before reading the
    /// store and [`Self::insert`] stores only if it has not moved, so a
    /// read that raced a publish cannot put back the bytes from before it.
    generation: AtomicU64,
    ttl: Duration,
    max_bytes: usize,
    /// Derived `did:webs` documents, keyed by the DID and the SHA-256 of the
    /// key event log they were derived from. Never stale: a changed log is a
    /// different key, so an entry can only ever be the document its exact
    /// log implies (see `routes::resolve_webs`). In memory only.
    webs_documents: RwLock<HashMap<(String, [u8; 32]), CachedContent>>,
}

impl ContentCache {
    /// Create a new cache with the given TTL and the default size bound.
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_CONTENT_CACHE_BYTES)
    }

    /// A cache holding at most `max_bytes` of content.
    pub fn with_capacity(ttl: Duration, max_bytes: usize) -> Self {
        Self {
            entries: RwLock::new(Entries::default()),
            generation: AtomicU64::new(0),
            ttl,
            max_bytes,
            webs_documents: RwLock::new(HashMap::new()),
        }
    }

    /// The key a did:web `did.json` (extracted from the log) is cached
    /// under. Every key for a DID is dropped by [`Self::invalidate_did`].
    pub fn did_web_document_key(mnemonic: &str) -> String {
        format!("content:{mnemonic}:did.json")
    }

    /// Get cached content if it exists and hasn't expired. Cheap: a
    /// reference-count bump on the bytes and the tag.
    pub fn get(&self, key: &str) -> Option<CachedContent> {
        let entries = self.entries.read().ok()?;
        let entry = entries.map.get(key)?;
        (entry.inserted_at.elapsed() < self.ttl).then(|| entry.content.clone())
    }

    /// The current generation: take it before reading the store on a miss,
    /// and pass it to [`Self::insert`].
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// The bytes the cache holds now.
    pub fn held_bytes(&self) -> usize {
        self.entries.read().map(|e| e.bytes).unwrap_or(0)
    }

    /// Insert or update a cache entry read from the store, unless something
    /// was invalidated since `generation` was taken, or it is larger than the
    /// whole cache. Returns the content with its tag either way, for the
    /// caller to serve.
    pub fn insert(&self, generation: u64, key: String, data: impl Into<Bytes>) -> CachedContent {
        let content = CachedContent::new(data);
        let size = content.bytes.len();
        if size <= self.max_bytes
            && let Ok(mut entries) = self.entries.write()
            && self.generation() == generation
        {
            entries.remove(&key);
            entries.make_room(size, self.max_bytes, self.ttl);
            entries.bytes += size;
            entries.map.insert(
                key,
                CacheEntry {
                    content: content.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }
        content
    }

    /// The derived `did:webs` document for `did_id` from the key event log
    /// `keri_cesr`, memoised on the log's exact bytes; `derive` runs only on
    /// a miss.
    pub fn webs_document<E>(
        &self,
        did_id: &str,
        keri_cesr: &[u8],
        derive: impl FnOnce() -> Result<Vec<u8>, E>,
    ) -> Result<CachedContent, E> {
        if let Some(hit) = self.memoised_webs_document(did_id, keri_cesr) {
            return Ok(hit);
        }
        Ok(self.memoise_webs_document(did_id, keri_cesr, derive()?))
    }

    /// The memoised document derived for `did_id` from exactly `keri_cesr`.
    pub fn memoised_webs_document(&self, did_id: &str, keri_cesr: &[u8]) -> Option<CachedContent> {
        let key = (
            did_id.to_string(),
            <[u8; 32]>::from(Sha256::digest(keri_cesr)),
        );
        self.webs_documents.read().ok()?.get(&key).cloned()
    }

    /// Memoise `document`, derived for `did_id` from exactly `keri_cesr`.
    pub fn memoise_webs_document(
        &self,
        did_id: &str,
        keri_cesr: &[u8],
        document: Vec<u8>,
    ) -> CachedContent {
        let key = (
            did_id.to_string(),
            <[u8; 32]>::from(Sha256::digest(keri_cesr)),
        );
        let content = CachedContent::new(document);
        if let Ok(mut memo) = self.webs_documents.write() {
            if memo.len() >= WEBS_DOCUMENT_MEMO_ENTRIES {
                // Content-keyed, so any entry may go: drop half, arbitrarily.
                let drop: Vec<_> = memo
                    .keys()
                    .take(WEBS_DOCUMENT_MEMO_ENTRIES / 2)
                    .cloned()
                    .collect();
                for k in drop {
                    memo.remove(&k);
                }
            }
            memo.insert(key, content.clone());
        }
        content
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
            *entries = Entries::default();
        }
    }

    /// Remove all expired entries (call periodically from cleanup thread).
    pub fn evict_expired(&self) {
        if let Ok(mut entries) = self.entries.write() {
            let expired: Vec<String> = entries
                .map
                .iter()
                .filter(|(_, e)| e.inserted_at.elapsed() >= self.ttl)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                entries.remove(&key);
            }
        }
    }
}

/// The caches resolution reads through, cleared together: every edge write
/// that changes a DID's record or content, or a domain, calls one of these
/// after its commit. The gate cache is optional (a process that cannot see
/// every change keeps none).
#[derive(Clone)]
pub struct ResolutionCaches {
    pub content: Arc<ContentCache>,
    pub gate: Option<Arc<GateCache>>,
}

impl ResolutionCaches {
    /// After a commit that changed `mnemonic`'s record or content.
    pub fn forget_did(&self, mnemonic: &str) {
        self.content.invalidate_did(mnemonic);
        if let Some(gate) = &self.gate {
            gate.forget_did(mnemonic);
        }
    }

    /// After a commit that changed a domain or its assignment.
    pub fn forget_domains(&self) {
        if let Some(gate) = &self.gate {
            gate.forget_domains();
        }
    }

    /// After a change too broad to name (a domain purge deleting its DIDs).
    pub fn clear(&self) {
        self.content.clear();
        if let Some(gate) = &self.gate {
            gate.clear();
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
/// standalone edge is the same case: every change it serves arrives as a
/// Trust Task it applies in-process (sync update and delete, domain
/// directives, reconcile repairs, cleanup and purge sweeps), each of which
/// clears it through [`ResolutionCaches`]. A daemon with its control plane
/// off leaves it off: a writer elsewhere would never clear this one, and a
/// disabled DID would keep resolving here until the TTL.
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
        assert_eq!(&cache.get(&key).unwrap().bytes[..], b"current");
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

    #[test]
    fn the_cache_holds_no_more_than_its_bound() {
        let cache = ContentCache::with_capacity(Duration::from_secs(60), 1000);
        for i in 0..50 {
            cache.insert(cache.generation(), format!("k{i}"), vec![0u8; 100]);
            assert!(
                cache.held_bytes() <= 1000,
                "{} bytes held",
                cache.held_bytes()
            );
        }
        // The newest survive; the oldest went.
        assert!(cache.get("k49").is_some());
        assert!(cache.get("k0").is_none());
        // Replacing a key does not count it twice.
        cache.insert(cache.generation(), "k49".into(), vec![0u8; 100]);
        assert!(cache.held_bytes() <= 1000);
        // Larger than the whole cache: served, not stored.
        let big = cache.insert(cache.generation(), "big".into(), vec![1u8; 2000]);
        assert_eq!(big.bytes.len(), 2000);
        assert!(cache.get("big").is_none());
        cache.clear();
        assert_eq!(cache.held_bytes(), 0);
    }

    #[test]
    fn etags_are_strong_and_if_none_match_compares_weakly() {
        let c = CachedContent::new(b"hello".to_vec());
        assert!(c.etag.starts_with('"') && c.etag.ends_with('"'));
        assert_eq!(c.etag.len(), 66);
        assert!(if_none_match_hits(&c.etag, &c.etag));
        assert!(if_none_match_hits(&format!("W/{}", c.etag), &c.etag));
        assert!(if_none_match_hits(&format!("\"x\", {}", c.etag), &c.etag));
        assert!(if_none_match_hits("*", &c.etag));
        assert!(!if_none_match_hits("\"other\"", &c.etag));
        assert!(!if_none_match_hits("", &c.etag));
    }

    #[test]
    fn a_webs_document_is_derived_once_per_log() {
        let cache = ContentCache::new(Duration::from_secs(60));
        let mut calls = 0;
        let mut derive = |log: &[u8]| {
            cache
                .webs_document("did:webs:x", log, || {
                    calls += 1;
                    Ok::<_, ()>(log.to_vec())
                })
                .unwrap()
        };
        let a = derive(b"log-1");
        let b = derive(b"log-1");
        assert_eq!(a.etag, b.etag);
        let c = derive(b"log-2");
        assert_ne!(a.etag, c.etag, "a new log is a new derivation");
        drop(derive);
        assert_eq!(calls, 2);
    }
}

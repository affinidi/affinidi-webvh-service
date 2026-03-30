//! Simple in-memory content cache with TTL-based eviction.
//!
//! Used to cache DID document content (`did.jsonl`) to reduce store lookups
//! on the hot DID resolution path. Entries are evicted on read after TTL expires.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

struct CacheEntry {
    data: Vec<u8>,
    inserted_at: Instant,
}

/// Thread-safe content cache with TTL-based eviction.
///
/// Uses `RwLock<HashMap>` — reads only acquire a read lock (no contention
/// between concurrent resolves). Writes acquire a write lock (infrequent:
/// only on cache miss or invalidation).
pub struct ContentCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl ContentCache {
    /// Create a new cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Get cached content if it exists and hasn't expired.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let entries = self.entries.read().ok()?;
        let entry = entries.get(key)?;
        if entry.inserted_at.elapsed() < self.ttl {
            Some(entry.data.clone())
        } else {
            None // Expired — caller should fetch from store and re-insert
        }
    }

    /// Insert or update a cache entry.
    pub fn insert(&self, key: String, data: Vec<u8>) {
        if let Ok(mut entries) = self.entries.write() {
            entries.insert(
                key,
                CacheEntry {
                    data,
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    /// Invalidate a cache entry (call on publish/delete).
    pub fn invalidate(&self, key: &str) {
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(key);
        }
    }

    /// Remove all expired entries (call periodically from cleanup thread).
    pub fn evict_expired(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.retain(|_, entry| entry.inserted_at.elapsed() < self.ttl);
        }
    }
}

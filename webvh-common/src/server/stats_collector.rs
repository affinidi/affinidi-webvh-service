//! In-memory stats collector for high-throughput counter accumulation.
//!
//! Instead of writing to storage on every DID resolve/update, counters are
//! accumulated in memory and flushed periodically. This eliminates I/O from
//! the hot path and works identically across all storage backends since the
//! flush only uses `WriteBatch::insert()`.
//!
//! # Usage
//!
//! ```ignore
//! let collector = StatsCollector::new();
//!
//! // Hot path (nanoseconds, no I/O):
//! collector.record_resolve("my-mnemonic");
//! collector.record_update("my-mnemonic");
//!
//! // Periodic flush (writes accumulated deltas to storage):
//! let deltas = collector.drain_deltas();
//! // ... write deltas to storage via WriteBatch ...
//!
//! // Instant aggregate (no storage scan):
//! let agg = collector.get_aggregate();
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Per-DID counter deltas accumulated since the last flush.
#[derive(Debug, Default)]
struct MnemonicDeltas {
    resolves: u64,
    updates: u64,
    last_resolved_at: Option<u64>,
    last_updated_at: Option<u64>,
}

/// Per-DID time-series bucket deltas accumulated since the last flush.
/// Key: (mnemonic, bucket_epoch), Value: (resolve_delta, update_delta).
type BucketKey = (String, u64);

/// Snapshot of accumulated deltas for a single mnemonic, returned by `drain_deltas()`.
#[derive(Debug)]
pub struct DrainedStats {
    pub mnemonic: String,
    pub resolve_delta: u64,
    pub update_delta: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
}

/// Snapshot of accumulated time-series bucket deltas, returned by `drain_ts_deltas()`.
#[derive(Debug)]
pub struct DrainedBucket {
    pub mnemonic: String,
    pub epoch: u64,
    pub resolve_delta: u64,
    pub update_delta: u64,
}

/// Pre-computed server-wide aggregate, updated on every record call.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatsAggregate {
    pub total_dids: u64,
    pub total_resolves: u64,
    pub total_updates: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
}

impl Default for StatsAggregate {
    fn default() -> Self {
        Self {
            total_dids: 0,
            total_resolves: 0,
            total_updates: 0,
            last_resolved_at: None,
            last_updated_at: None,
        }
    }
}

const BUCKET_SECONDS: u64 = 300; // 5-minute buckets

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn bucket_epoch(ts: u64) -> u64 {
    ts / BUCKET_SECONDS * BUCKET_SECONDS
}

/// Thread-safe in-memory stats collector.
///
/// All public methods are non-async and lock-free on the hot path
/// (mutex is held only for HashMap insert/update, microseconds).
pub struct StatsCollector {
    /// Per-DID counter deltas since last flush.
    deltas: Mutex<HashMap<String, MnemonicDeltas>>,
    /// Per-DID time-series bucket deltas since last flush.
    ts_deltas: Mutex<HashMap<BucketKey, (u64, u64)>>,
    /// Running aggregate (base + in-flight deltas).
    agg_total_resolves: AtomicU64,
    agg_total_updates: AtomicU64,
    agg_last_resolved_at: AtomicU64,
    agg_last_updated_at: AtomicU64,
    agg_total_dids: AtomicU64,
}

impl StatsCollector {
    /// Create a new collector with zero counters.
    pub fn new() -> Self {
        Self {
            deltas: Mutex::new(HashMap::new()),
            ts_deltas: Mutex::new(HashMap::new()),
            agg_total_resolves: AtomicU64::new(0),
            agg_total_updates: AtomicU64::new(0),
            agg_last_resolved_at: AtomicU64::new(0),
            agg_last_updated_at: AtomicU64::new(0),
            agg_total_dids: AtomicU64::new(0),
        }
    }

    /// Seed the aggregate with values loaded from storage at startup.
    pub fn seed_aggregate(&self, agg: &StatsAggregate) {
        self.agg_total_dids.store(agg.total_dids, Ordering::Relaxed);
        self.agg_total_resolves
            .store(agg.total_resolves, Ordering::Relaxed);
        self.agg_total_updates
            .store(agg.total_updates, Ordering::Relaxed);
        self.agg_last_resolved_at
            .store(agg.last_resolved_at.unwrap_or(0), Ordering::Relaxed);
        self.agg_last_updated_at
            .store(agg.last_updated_at.unwrap_or(0), Ordering::Relaxed);
    }

    /// Set the total DID count (called after DID create/delete).
    pub fn set_total_dids(&self, count: u64) {
        self.agg_total_dids.store(count, Ordering::Relaxed);
    }

    /// Record a DID resolve event. Nanosecond cost, no I/O.
    pub fn record_resolve(&self, mnemonic: &str) {
        let now = now_epoch();
        let epoch = bucket_epoch(now);

        // Update per-DID deltas
        {
            let mut deltas = self.deltas.lock().unwrap();
            let entry = deltas
                .entry(mnemonic.to_string())
                .or_default();
            entry.resolves += 1;
            entry.last_resolved_at = Some(now);
        }

        // Update time-series bucket deltas
        {
            let mut ts = self.ts_deltas.lock().unwrap();
            let bucket = ts
                .entry((mnemonic.to_string(), epoch))
                .or_insert((0, 0));
            bucket.0 += 1;
            // Also update global bucket
            let global = ts
                .entry(("_all".to_string(), epoch))
                .or_insert((0, 0));
            global.0 += 1;
        }

        // Update aggregate atomics
        self.agg_total_resolves.fetch_add(1, Ordering::Relaxed);
        self.agg_last_resolved_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Record a DID update/publish event. Nanosecond cost, no I/O.
    pub fn record_update(&self, mnemonic: &str) {
        let now = now_epoch();
        let epoch = bucket_epoch(now);

        {
            let mut deltas = self.deltas.lock().unwrap();
            let entry = deltas
                .entry(mnemonic.to_string())
                .or_default();
            entry.updates += 1;
            entry.last_updated_at = Some(now);
        }

        {
            let mut ts = self.ts_deltas.lock().unwrap();
            let bucket = ts
                .entry((mnemonic.to_string(), epoch))
                .or_insert((0, 0));
            bucket.1 += 1;
            let global = ts
                .entry(("_all".to_string(), epoch))
                .or_insert((0, 0));
            global.1 += 1;
        }

        self.agg_total_updates.fetch_add(1, Ordering::Relaxed);
        self.agg_last_updated_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Drain all accumulated per-DID counter deltas.
    ///
    /// Returns the deltas and resets the internal map. Call this from
    /// the periodic flush task to get the work to write to storage.
    pub fn drain_deltas(&self) -> Vec<DrainedStats> {
        let mut deltas = self.deltas.lock().unwrap();
        let drained: Vec<DrainedStats> = deltas
            .drain()
            .map(|(mnemonic, d)| DrainedStats {
                mnemonic,
                resolve_delta: d.resolves,
                update_delta: d.updates,
                last_resolved_at: d.last_resolved_at,
                last_updated_at: d.last_updated_at,
            })
            .collect();
        drained
    }

    /// Drain all accumulated time-series bucket deltas.
    pub fn drain_ts_deltas(&self) -> Vec<DrainedBucket> {
        let mut ts = self.ts_deltas.lock().unwrap();
        let drained: Vec<DrainedBucket> = ts
            .drain()
            .map(|((mnemonic, epoch), (r, u))| DrainedBucket {
                mnemonic,
                epoch,
                resolve_delta: r,
                update_delta: u,
            })
            .collect();
        drained
    }

    /// Get the current server-wide aggregate (instant, no I/O).
    pub fn get_aggregate(&self) -> StatsAggregate {
        let last_resolved = self.agg_last_resolved_at.load(Ordering::Relaxed);
        let last_updated = self.agg_last_updated_at.load(Ordering::Relaxed);

        StatsAggregate {
            total_dids: self.agg_total_dids.load(Ordering::Relaxed),
            total_resolves: self.agg_total_resolves.load(Ordering::Relaxed),
            total_updates: self.agg_total_updates.load(Ordering::Relaxed),
            last_resolved_at: if last_resolved > 0 {
                Some(last_resolved)
            } else {
                None
            },
            last_updated_at: if last_updated > 0 {
                Some(last_updated)
            } else {
                None
            },
        }
    }
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

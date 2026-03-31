//! In-memory stats collector for high-throughput counter accumulation.
//!
//! Counters are accumulated in memory per-DID and drained periodically
//! for sync to the control plane (on webvh-server) or flush to storage
//! (on webvh-control). This eliminates I/O from the hot path.
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
//! // Periodic drain for sync (returns per-DID deltas, resets counters):
//! let deltas = collector.drain_for_sync();
//!
//! // Instant aggregate (lock-free atomic reads):
//! let agg = collector.get_aggregate();
//! ```

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::DidStatsDelta;

/// Per-DID counter deltas accumulated since the last drain.
#[derive(Debug, Default)]
struct MnemonicDeltas {
    resolves: u64,
    updates: u64,
    last_resolved_at: Option<u64>,
    last_updated_at: Option<u64>,
}

/// Server-wide aggregate snapshot, read from atomic counters.
#[derive(Debug, Clone, Default)]
pub struct StatsAggregate {
    pub total_dids: u64,
    pub total_resolves: u64,
    pub total_updates: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Thread-safe in-memory stats collector.
///
/// All public methods are non-async. The hot path (`record_resolve`,
/// `record_update`) holds a mutex only briefly for HashMap update.
/// Aggregate reads are fully lock-free via atomics.
pub struct StatsCollector {
    /// Per-DID counter deltas since last drain.
    deltas: Mutex<HashMap<String, MnemonicDeltas>>,
    /// Running aggregate counters (lock-free).
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
            agg_total_resolves: AtomicU64::new(0),
            agg_total_updates: AtomicU64::new(0),
            agg_last_resolved_at: AtomicU64::new(0),
            agg_last_updated_at: AtomicU64::new(0),
            agg_total_dids: AtomicU64::new(0),
        }
    }

    /// Seed the aggregate with values (e.g. loaded from storage at startup).
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

    /// Set the total DID count.
    pub fn set_total_dids(&self, count: u64) {
        self.agg_total_dids.store(count, Ordering::Relaxed);
    }

    /// Increment total DID count by 1 (call on DID create).
    pub fn increment_total_dids(&self) {
        self.agg_total_dids.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement total DID count by 1 (call on DID delete).
    pub fn decrement_total_dids(&self) {
        self.agg_total_dids.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment aggregate counters by the given deltas (used by the control
    /// plane when receiving sync data from servers).
    pub fn apply_deltas(
        &self,
        resolve_delta: u64,
        update_delta: u64,
        last_resolved_at: Option<u64>,
        last_updated_at: Option<u64>,
    ) {
        self.agg_total_resolves
            .fetch_add(resolve_delta, Ordering::Relaxed);
        self.agg_total_updates
            .fetch_add(update_delta, Ordering::Relaxed);
        if let Some(ts) = last_resolved_at {
            self.agg_last_resolved_at.fetch_max(ts, Ordering::Relaxed);
        }
        if let Some(ts) = last_updated_at {
            self.agg_last_updated_at.fetch_max(ts, Ordering::Relaxed);
        }
    }

    /// Record a DID resolve event. Nanosecond cost, no I/O.
    pub fn record_resolve(&self, mnemonic: &str) {
        let now = now_epoch();

        {
            let mut deltas = self.deltas.lock().unwrap();
            let entry = deltas.entry(mnemonic.to_string()).or_default();
            entry.resolves += 1;
            entry.last_resolved_at = Some(now);
        }

        self.agg_total_resolves.fetch_add(1, Ordering::Relaxed);
        self.agg_last_resolved_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Record a DID update/publish event. Nanosecond cost, no I/O.
    pub fn record_update(&self, mnemonic: &str) {
        let now = now_epoch();

        {
            let mut deltas = self.deltas.lock().unwrap();
            let entry = deltas.entry(mnemonic.to_string()).or_default();
            entry.updates += 1;
            entry.last_updated_at = Some(now);
        }

        self.agg_total_updates.fetch_add(1, Ordering::Relaxed);
        self.agg_last_updated_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Record arbitrary deltas for a DID (used by the control plane when
    /// receiving sync data from servers). Updates both per-DID map and aggregates.
    pub fn record_deltas(
        &self,
        mnemonic: &str,
        resolve_delta: u64,
        update_delta: u64,
        last_resolved_at: Option<u64>,
        last_updated_at: Option<u64>,
    ) {
        {
            let mut deltas = self.deltas.lock().unwrap();
            let entry = deltas.entry(mnemonic.to_string()).or_default();
            entry.resolves += resolve_delta;
            entry.updates += update_delta;
            if let Some(ts) = last_resolved_at {
                entry.last_resolved_at =
                    Some(entry.last_resolved_at.map_or(ts, |prev| prev.max(ts)));
            }
            if let Some(ts) = last_updated_at {
                entry.last_updated_at = Some(entry.last_updated_at.map_or(ts, |prev| prev.max(ts)));
            }
        }

        self.apply_deltas(
            resolve_delta,
            update_delta,
            last_resolved_at,
            last_updated_at,
        );
    }

    /// Drain all accumulated per-DID deltas for sync to the control plane.
    ///
    /// Returns the deltas as `DidStatsDelta` and resets the internal map.
    /// Returns an empty vec if nothing changed since the last drain.
    pub fn drain_for_sync(&self) -> Vec<DidStatsDelta> {
        let mut deltas = self.deltas.lock().unwrap();
        deltas
            .drain()
            .map(|(mnemonic, d)| DidStatsDelta {
                mnemonic,
                resolve_delta: d.resolves,
                update_delta: d.updates,
                last_resolved_at: d.last_resolved_at,
                last_updated_at: d.last_updated_at,
            })
            .collect()
    }

    /// Get the current server-wide aggregate (instant, lock-free).
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

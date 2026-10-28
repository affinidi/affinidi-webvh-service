//! In-memory stats collector for high-throughput counter accumulation.
//!
//! Counters are accumulated in memory per-DID and drained periodically
//! for sync to the control plane (on did-hosting-server) or flush to storage
//! (on did-hosting-control). This eliminates I/O from the hot path.
//!
//! Time-series buckets (5-minute resolution) are also tracked in memory,
//! keyed by the time of the event, and drained alongside per-DID deltas.
//! A writer that fails to store drained deltas or buckets requeues them.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::DidStatsDelta;

const BUCKET_SECS: u64 = 300; // 5-minute buckets

/// Series name of the server-wide time-series (`ts:_all:{epoch}`). Not a
/// valid DID path, so no DID's series can collide with it.
pub const ALL_SERIES: &str = "_all";

/// Most DIDs whose unwritten deltas a failed flush keeps. Far above the DIDs
/// any one service hosts; it bounds memory only against deltas for paths
/// that are not hosted here, which a peer's stats sync could otherwise
/// grow without limit while the store is failing.
pub const MAX_PENDING_DIDS: usize = 100_000;

/// Per-DID counter deltas accumulated since the last drain.
#[derive(Debug, Default)]
struct MnemonicDeltas {
    resolves: u64,
    updates: u64,
    last_resolved_at: Option<u64>,
    last_updated_at: Option<u64>,
}

/// Time-series bucket key: (mnemonic, epoch).
type BucketKey = (String, u64);

/// Server-wide aggregate snapshot, read from atomic counters.
#[derive(Debug, Clone, Default)]
pub struct StatsAggregate {
    pub total_dids: u64,
    pub total_resolves: u64,
    pub total_updates: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
}

/// A drained time-series bucket for batch writing.
pub struct DrainedBucket {
    pub mnemonic: String,
    pub epoch: u64,
    pub resolves: u64,
    pub updates: u64,
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn bucket_epoch(ts: u64) -> u64 {
    ts / BUCKET_SECS * BUCKET_SECS
}

/// Thread-safe in-memory stats collector.
///
/// All public methods are non-async. The hot path (`record_resolve`,
/// `record_update`) holds a mutex only briefly for HashMap update.
/// Aggregate reads are fully lock-free via atomics.
pub struct StatsCollector {
    /// Per-DID counter deltas since last drain.
    deltas: Mutex<HashMap<String, MnemonicDeltas>>,
    /// Time-series bucket deltas since last drain.
    buckets: Mutex<HashMap<BucketKey, (u64, u64)>>,
    /// Running aggregate counters (lock-free).
    agg_total_resolves: AtomicU64,
    agg_total_updates: AtomicU64,
    agg_last_resolved_at: AtomicU64,
    agg_last_updated_at: AtomicU64,
    agg_total_dids: AtomicU64,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self {
            deltas: Mutex::new(HashMap::new()),
            buckets: Mutex::new(HashMap::new()),
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

    pub fn set_total_dids(&self, count: u64) {
        self.agg_total_dids.store(count, Ordering::Relaxed);
    }

    pub fn increment_total_dids(&self) {
        self.agg_total_dids.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the DID count, stopping at zero: a count seeded or
    /// reconciled after a delete must not wrap.
    pub fn decrement_total_dids(&self) {
        let _ = self
            .agg_total_dids
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
    }

    /// Increment aggregate counters by the given deltas.
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
        let epoch = bucket_epoch(now);

        {
            let mut deltas = self.deltas.lock().unwrap();
            let entry = deltas.entry(mnemonic.to_string()).or_default();
            entry.resolves += 1;
            entry.last_resolved_at = Some(now);
        }

        // Update time-series buckets (per-DID + global)
        {
            let mut buckets = self.buckets.lock().unwrap();
            let b = buckets
                .entry((mnemonic.to_string(), epoch))
                .or_insert((0, 0));
            b.0 += 1;
            let g = buckets
                .entry((ALL_SERIES.to_string(), epoch))
                .or_insert((0, 0));
            g.0 += 1;
        }

        self.agg_total_resolves.fetch_add(1, Ordering::Relaxed);
        self.agg_last_resolved_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Record a DID update/publish event. Nanosecond cost, no I/O.
    pub fn record_update(&self, mnemonic: &str) {
        let now = now_epoch();
        let epoch = bucket_epoch(now);

        {
            let mut deltas = self.deltas.lock().unwrap();
            let entry = deltas.entry(mnemonic.to_string()).or_default();
            entry.updates += 1;
            entry.last_updated_at = Some(now);
        }

        {
            let mut buckets = self.buckets.lock().unwrap();
            let b = buckets
                .entry((mnemonic.to_string(), epoch))
                .or_insert((0, 0));
            b.1 += 1;
            let g = buckets
                .entry((ALL_SERIES.to_string(), epoch))
                .or_insert((0, 0));
            g.1 += 1;
        }

        self.agg_total_updates.fetch_add(1, Ordering::Relaxed);
        self.agg_last_updated_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Record arbitrary deltas for a DID (used by the control plane when
    /// receiving sync data from servers). Updates per-DID map, buckets, and aggregates.
    pub fn record_deltas(
        &self,
        mnemonic: &str,
        resolve_delta: u64,
        update_delta: u64,
        last_resolved_at: Option<u64>,
        last_updated_at: Option<u64>,
    ) {
        if resolve_delta == 0 && update_delta == 0 {
            return; // Skip empty deltas
        }

        let now = now_epoch();
        let epoch = bucket_epoch(now);

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

        // Update time-series buckets
        {
            let mut buckets = self.buckets.lock().unwrap();
            let b = buckets
                .entry((mnemonic.to_string(), epoch))
                .or_insert((0, 0));
            b.0 += resolve_delta;
            b.1 += update_delta;
            let g = buckets
                .entry((ALL_SERIES.to_string(), epoch))
                .or_insert((0, 0));
            g.0 += resolve_delta;
            g.1 += update_delta;
        }

        self.apply_deltas(
            resolve_delta,
            update_delta,
            last_resolved_at,
            last_updated_at,
        );
    }

    /// Drain all accumulated per-DID deltas for sync to the control plane.
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

    /// Rows waiting to be written: per-DID deltas plus time-series buckets.
    pub fn pending_rows(&self) -> usize {
        self.deltas.lock().unwrap().len() + self.buckets.lock().unwrap().len()
    }

    /// Return drained per-DID deltas that could not be written, so the next
    /// drain carries them again. Aggregates are not touched: they already
    /// counted these events when they were recorded.
    ///
    /// Deltas for a DID not already pending are dropped once
    /// [`MAX_PENDING_DIDS`] DIDs are; returns how many were dropped.
    pub fn requeue_deltas(&self, failed: Vec<DidStatsDelta>) -> usize {
        let mut deltas = self.deltas.lock().unwrap();
        let mut dropped = 0;
        for d in failed {
            if deltas.len() >= MAX_PENDING_DIDS && !deltas.contains_key(&d.mnemonic) {
                dropped += 1;
                continue;
            }
            let entry = deltas.entry(d.mnemonic).or_default();
            entry.resolves += d.resolve_delta;
            entry.updates += d.update_delta;
            entry.last_resolved_at = entry.last_resolved_at.max(d.last_resolved_at);
            entry.last_updated_at = entry.last_updated_at.max(d.last_updated_at);
        }
        dropped
    }

    /// Return drained time-series buckets that could not be written, so the
    /// next drain carries them again.
    pub fn requeue_buckets(&self, failed: Vec<DrainedBucket>) {
        let mut buckets = self.buckets.lock().unwrap();
        for b in failed {
            let entry = buckets.entry((b.mnemonic, b.epoch)).or_insert((0, 0));
            entry.0 += b.resolves;
            entry.1 += b.updates;
        }
    }

    /// Drain all accumulated time-series bucket deltas.
    pub fn drain_buckets(&self) -> Vec<DrainedBucket> {
        let mut buckets = self.buckets.lock().unwrap();
        buckets
            .drain()
            .map(|((mnemonic, epoch), (r, u))| DrainedBucket {
                mnemonic,
                epoch,
                resolves: r,
                updates: u,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requeued_deltas_merge_with_new_events() {
        let collector = StatsCollector::new();
        collector.record_resolve("alice");
        let drained = collector.drain_for_sync();
        collector.record_resolve("alice");

        collector.requeue_deltas(drained);

        let deltas = collector.drain_for_sync();
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].resolve_delta, 2);
        assert_eq!(
            collector.get_aggregate().total_resolves,
            2,
            "requeueing must not count the events again"
        );
    }

    #[test]
    fn requeue_stops_taking_new_dids_at_the_cap() {
        let collector = StatsCollector::new();
        let delta = |m: String| DidStatsDelta {
            mnemonic: m,
            resolve_delta: 1,
            update_delta: 0,
            last_resolved_at: None,
            last_updated_at: None,
        };
        let full: Vec<_> = (0..MAX_PENDING_DIDS)
            .map(|i| delta(format!("did-{i}")))
            .collect();
        assert_eq!(collector.requeue_deltas(full), 0);

        let dropped = collector.requeue_deltas(vec![delta("new".into()), delta("did-0".into())]);

        assert_eq!(
            dropped, 1,
            "a new DID is dropped, a pending one still merges"
        );
        let deltas = collector.drain_for_sync();
        assert_eq!(deltas.len(), MAX_PENDING_DIDS);
        let did_0 = deltas.iter().find(|d| d.mnemonic == "did-0");
        assert_eq!(did_0.map(|d| d.resolve_delta), Some(2));
    }

    #[test]
    fn requeued_buckets_merge_with_new_events() {
        let collector = StatsCollector::new();
        collector.record_update("alice");
        let drained = collector.drain_buckets();
        collector.record_update("alice");

        collector.requeue_buckets(drained);

        let mut buckets = collector.drain_buckets();
        buckets.sort_by(|a, b| a.mnemonic.cmp(&b.mnemonic));
        let counts: Vec<_> = buckets
            .iter()
            .map(|b| (b.mnemonic.as_str(), b.updates))
            .collect();
        assert_eq!(counts, [("_all", 2), ("alice", 2)]);
        assert!(
            collector.drain_buckets().is_empty(),
            "a drain empties the map"
        );
    }

    #[test]
    fn decrement_total_dids_stops_at_zero() {
        let collector = StatsCollector::new();
        collector.increment_total_dids();
        collector.decrement_total_dids();
        collector.decrement_total_dids();
        assert_eq!(collector.get_aggregate().total_dids, 0);
    }
}

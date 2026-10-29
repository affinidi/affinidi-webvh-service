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

/// Most DIDs with pending per-DID deltas. Far above the DIDs any one
/// service hosts; it bounds memory against deltas for paths that are not
/// hosted here, which a peer's stats sync could otherwise grow without
/// limit, and against a store that keeps refusing writes.
pub const MAX_PENDING_DIDS: usize = 100_000;

/// Most pending per-DID time-series buckets (the server-wide series is not
/// counted against it). Twice [`MAX_PENDING_DIDS`]: a DID active across
/// several 5-minute windows before a flush writes them has a bucket each.
pub const MAX_PENDING_BUCKETS: usize = 200_000;

/// Most per-DID deltas one stats sync carries. The control plane refuses a
/// larger sync, so an edge sends at most this many and keeps the rest for
/// its next sync.
pub const MAX_STATS_SYNC_DELTAS: usize = 10_000;

/// Oldest event time a synced delta can be filed under. Older (or future)
/// times come from a skewed peer clock and are filed at receipt instead.
pub const SYNCED_EVENT_MAX_AGE_SECS: u64 = 1800;

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
///
/// Both maps are capped ([`MAX_PENDING_DIDS`], [`MAX_PENDING_BUCKETS`]) on
/// every insert, so neither a peer's stats sync nor a store that keeps
/// refusing writes can grow them without bound. Counts that do not fit are
/// dropped from the per-DID rows and series only: the aggregate and the
/// server-wide series still count them.
pub struct StatsCollector {
    /// Per-DID counter deltas since last drain.
    deltas: Mutex<HashMap<String, MnemonicDeltas>>,
    /// Time-series bucket deltas since last drain.
    buckets: Mutex<HashMap<BucketKey, (u64, u64)>>,
    /// Whether this collector keeps time-series buckets. An edge does not:
    /// it only syncs per-DID deltas, so buckets would never be drained.
    track_timeseries: bool,
    /// Rows dropped at the caps since the last [`Self::take_dropped`].
    dropped: AtomicU64,
    /// When `take_dropped` last reported, for rate-limiting the warning.
    dropped_reported_at: AtomicU64,
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
            track_timeseries: true,
            dropped: AtomicU64::new(0),
            dropped_reported_at: AtomicU64::new(0),
            agg_total_resolves: AtomicU64::new(0),
            agg_total_updates: AtomicU64::new(0),
            agg_last_resolved_at: AtomicU64::new(0),
            agg_last_updated_at: AtomicU64::new(0),
            agg_total_dids: AtomicU64::new(0),
        }
    }

    /// A collector that keeps no time-series buckets, for an edge: it syncs
    /// only per-DID deltas to its control plane, so buckets would never be
    /// drained.
    pub fn without_timeseries() -> Self {
        Self {
            track_timeseries: false,
            ..Self::new()
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
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
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
        self.add_delta(mnemonic.to_string(), 1, 0, Some(now), None);
        self.add_bucket(mnemonic, bucket_epoch(now), 1, 0);
        self.agg_total_resolves.fetch_add(1, Ordering::Relaxed);
        self.agg_last_resolved_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Record a DID update/publish event. Nanosecond cost, no I/O.
    pub fn record_update(&self, mnemonic: &str) {
        let now = now_epoch();
        self.add_delta(mnemonic.to_string(), 0, 1, None, Some(now));
        self.add_bucket(mnemonic, bucket_epoch(now), 0, 1);
        self.agg_total_updates.fetch_add(1, Ordering::Relaxed);
        self.agg_last_updated_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Record arbitrary deltas for a DID (used by the control plane when
    /// receiving sync data from servers). Updates per-DID map, buckets, and aggregates.
    ///
    /// The deltas carry no per-event times, only the latest of each kind, so
    /// resolves are filed in the bucket of `last_resolved_at` and updates in
    /// that of `last_updated_at`: the time of the edge's latest event, not
    /// the time the sync arrived. A time in the future or older than
    /// [`SYNCED_EVENT_MAX_AGE_SECS`] (a skewed peer clock) is filed now.
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
        self.add_delta(
            mnemonic.to_string(),
            resolve_delta,
            update_delta,
            last_resolved_at,
            last_updated_at,
        );
        let event_epoch = |ts: Option<u64>| {
            let ts = ts
                .filter(|&t| t <= now && now - t <= SYNCED_EVENT_MAX_AGE_SECS)
                .unwrap_or(now);
            bucket_epoch(ts)
        };
        if resolve_delta > 0 {
            self.add_bucket(mnemonic, event_epoch(last_resolved_at), resolve_delta, 0);
        }
        if update_delta > 0 {
            self.add_bucket(mnemonic, event_epoch(last_updated_at), 0, update_delta);
        }

        self.apply_deltas(
            resolve_delta,
            update_delta,
            last_resolved_at,
            last_updated_at,
        );
    }

    /// Add to a DID's pending deltas, unless the map is at
    /// [`MAX_PENDING_DIDS`] and the DID is not already in it. Returns whether
    /// the deltas were kept.
    fn add_delta(
        &self,
        mnemonic: String,
        resolves: u64,
        updates: u64,
        last_resolved_at: Option<u64>,
        last_updated_at: Option<u64>,
    ) -> bool {
        let mut deltas = self.deltas.lock().unwrap();
        if deltas.len() >= MAX_PENDING_DIDS && !deltas.contains_key(&mnemonic) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let entry = deltas.entry(mnemonic).or_default();
        entry.resolves += resolves;
        entry.updates += updates;
        entry.last_resolved_at = entry.last_resolved_at.max(last_resolved_at);
        entry.last_updated_at = entry.last_updated_at.max(last_updated_at);
        true
    }

    /// Add to a DID's bucket and the server-wide bucket for `epoch`. The
    /// DID's bucket is dropped if the map is at [`MAX_PENDING_BUCKETS`] and
    /// it is new; the server-wide one, at most one per 5 minutes, never is.
    fn add_bucket(&self, mnemonic: &str, epoch: u64, resolves: u64, updates: u64) {
        if !self.track_timeseries {
            return;
        }
        let mut buckets = self.buckets.lock().unwrap();
        let key = (mnemonic.to_string(), epoch);
        if buckets.len() < MAX_PENDING_BUCKETS || buckets.contains_key(&key) {
            let b = buckets.entry(key).or_insert((0, 0));
            b.0 += resolves;
            b.1 += updates;
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        let g = buckets
            .entry((ALL_SERIES.to_string(), epoch))
            .or_insert((0, 0));
        g.0 += resolves;
        g.1 += updates;
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

    /// Return drained per-DID deltas that could not be written or sent, so
    /// the next drain carries them again. Aggregates are not touched: they
    /// already counted these events when they were recorded.
    ///
    /// Subject to the same cap as new events; returns how many were dropped.
    pub fn requeue_deltas(&self, failed: Vec<DidStatsDelta>) -> usize {
        failed
            .into_iter()
            .filter(|d| {
                !self.add_delta(
                    d.mnemonic.clone(),
                    d.resolve_delta,
                    d.update_delta,
                    d.last_resolved_at,
                    d.last_updated_at,
                )
            })
            .count()
    }

    /// Return drained time-series buckets that could not be written, so the
    /// next drain carries them again. Subject to the same cap as new events.
    pub fn requeue_buckets(&self, failed: Vec<DrainedBucket>) {
        let mut buckets = self.buckets.lock().unwrap();
        for b in failed {
            let key = (b.mnemonic, b.epoch);
            if buckets.len() >= MAX_PENDING_BUCKETS
                && key.0 != ALL_SERIES
                && !buckets.contains_key(&key)
            {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let entry = buckets.entry(key).or_insert((0, 0));
            entry.0 += b.resolves;
            entry.1 += b.updates;
        }
    }

    /// Rows dropped at the caps since the last report, at most once per
    /// `every_secs` so a sustained overflow logs one warning per period
    /// rather than one per flush. `None` when there is nothing to report
    /// or the period has not elapsed.
    pub fn take_dropped(&self, every_secs: u64) -> Option<u64> {
        let now = now_epoch();
        let last = self.dropped_reported_at.load(Ordering::Relaxed);
        if now.saturating_sub(last) < every_secs || self.dropped.load(Ordering::Relaxed) == 0 {
            return None;
        }
        self.dropped_reported_at.store(now, Ordering::Relaxed);
        Some(self.dropped.swap(0, Ordering::Relaxed))
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

    /// New events past the cap are dropped from the per-DID rows, not just
    /// requeued ones; the aggregate and the server-wide series still count
    /// them.
    #[test]
    fn recording_stops_taking_new_dids_at_the_cap() {
        let collector = StatsCollector::new();
        for i in 0..MAX_PENDING_DIDS {
            collector.record_deltas(&format!("did-{i}"), 1, 0, None, None);
        }
        collector.record_deltas("over", 1, 0, None, None);
        collector.record_deltas("did-0", 1, 0, None, None);

        let deltas = collector.drain_for_sync();
        assert_eq!(deltas.len(), MAX_PENDING_DIDS);
        assert!(deltas.iter().all(|d| d.mnemonic != "over"));
        assert_eq!(
            collector.get_aggregate().total_resolves,
            MAX_PENDING_DIDS as u64 + 2
        );
        let all: u64 = collector
            .drain_buckets()
            .iter()
            .filter(|b| b.mnemonic == ALL_SERIES)
            .map(|b| b.resolves)
            .sum();
        assert_eq!(all, MAX_PENDING_DIDS as u64 + 2);
        assert_eq!(collector.take_dropped(0), Some(1));
    }

    #[test]
    fn bucket_cap_drops_new_did_buckets_but_not_the_server_wide_series() {
        let collector = StatsCollector::new();
        let bucket = |m: &str, epoch: u64| DrainedBucket {
            mnemonic: m.into(),
            epoch,
            resolves: 1,
            updates: 0,
        };
        collector.requeue_buckets(
            (0..MAX_PENDING_BUCKETS as u64)
                .map(|i| bucket("did", i * BUCKET_SECS))
                .collect(),
        );
        collector.requeue_buckets(vec![bucket("other", 0), bucket(ALL_SERIES, 0)]);

        let drained = collector.drain_buckets();
        assert_eq!(drained.len(), MAX_PENDING_BUCKETS + 1);
        assert!(drained.iter().all(|b| b.mnemonic != "other"));
        assert!(drained.iter().any(|b| b.mnemonic == ALL_SERIES));
    }

    #[test]
    fn dropped_rows_are_reported_at_most_once_per_period() {
        let collector = StatsCollector::new();
        collector.dropped.store(3, Ordering::Relaxed);
        assert_eq!(collector.take_dropped(3600), Some(3));
        collector.dropped.store(2, Ordering::Relaxed);
        assert_eq!(collector.take_dropped(3600), None, "within the period");
        assert_eq!(collector.take_dropped(0), Some(2));
        assert_eq!(collector.take_dropped(0), None, "nothing new to report");
    }

    #[test]
    fn an_edge_collector_keeps_no_timeseries() {
        let collector = StatsCollector::without_timeseries();
        collector.record_resolve("alice");
        collector.record_update("alice");
        assert!(collector.drain_buckets().is_empty());
        assert_eq!(collector.drain_for_sync().len(), 1);
    }

    /// Synced deltas are filed under the edge's latest event time, unless
    /// that time is implausible.
    #[test]
    fn synced_deltas_are_bucketed_by_event_time() {
        let collector = StatsCollector::new();
        let now = now_epoch();
        let earlier = now - 2 * BUCKET_SECS;
        collector.record_deltas("alice", 2, 1, Some(earlier), Some(now + 3600));

        let mut buckets: Vec<_> = collector
            .drain_buckets()
            .into_iter()
            .filter(|b| b.mnemonic == "alice")
            .map(|b| (b.epoch, b.resolves, b.updates))
            .collect();
        buckets.sort();
        assert_eq!(
            buckets,
            [
                (bucket_epoch(earlier), 2, 0),
                (bucket_epoch(now), 0, 1), // a future time is filed now
            ]
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

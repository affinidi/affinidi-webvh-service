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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::DidStatsDelta;
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

use crate::server::stats_tiers::{BUCKET_SECS, StatsResolution, StatsTierConfig, TierState};

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

/// Add `n` to `counter`, stopping at `u64::MAX` rather than wrapping: a
/// synced delta comes from a peer, and a counter that wrapped would read as
/// almost nothing.
fn saturating_fetch_add(counter: &std::sync::atomic::AtomicU64, n: u64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(n))
    });
}

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

/// Lock one of the collector's maps. A panic while a map was held leaves
/// counts, not invariants, half-updated, so a poisoned lock is taken as it
/// stands rather than failing every later resolve.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
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
    /// Fine-ring buckets whose write failed after their DID's coarse row
    /// was written: retried on their own, so the coarse row does not count
    /// them twice.
    slot_retry: Mutex<HashMap<BucketKey, (u64, u64)>>,
    /// Which DIDs keep 5-minute detail (`stats_tiers`).
    tiers: std::sync::Arc<Mutex<TierState>>,
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
            slot_retry: Mutex::new(HashMap::new()),
            tiers: std::sync::Arc::new(Mutex::new(TierState::default())),
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
        self.subtract_total_dids(1);
    }

    /// Subtract `n` deleted DIDs from the count, stopping at zero.
    pub fn subtract_total_dids(&self, n: u64) {
        if n == 0 {
            return;
        }
        let _ = self
            .agg_total_dids
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                Some(c.saturating_sub(n))
            });
    }

    /// Increment aggregate counters by the given deltas.
    pub fn apply_deltas(
        &self,
        resolve_delta: u64,
        update_delta: u64,
        last_resolved_at: Option<u64>,
        last_updated_at: Option<u64>,
    ) {
        saturating_fetch_add(&self.agg_total_resolves, resolve_delta);
        saturating_fetch_add(&self.agg_total_updates, update_delta);
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
        self.add_delta(mnemonic, 1, 0, Some(now), None);
        self.add_bucket(mnemonic, bucket_epoch(now), 1, 0);
        self.agg_total_resolves.fetch_add(1, Ordering::Relaxed);
        self.agg_last_resolved_at.fetch_max(now, Ordering::Relaxed);
    }

    /// Record a DID update/publish event. Nanosecond cost, no I/O.
    pub fn record_update(&self, mnemonic: &str) {
        let now = now_epoch();
        self.add_delta(mnemonic, 0, 1, None, Some(now));
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
            mnemonic,
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
    /// the deltas were kept. A DID already pending is updated in place, so
    /// the hot path allocates its key only for a DID's first event since the
    /// last drain.
    fn add_delta(
        &self,
        mnemonic: &str,
        resolves: u64,
        updates: u64,
        last_resolved_at: Option<u64>,
        last_updated_at: Option<u64>,
    ) -> bool {
        let mut deltas = lock(&self.deltas);
        let entry = match deltas.get_mut(mnemonic) {
            Some(entry) => entry,
            None => {
                if deltas.len() >= MAX_PENDING_DIDS {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                deltas.entry(mnemonic.to_string()).or_default()
            }
        };
        entry.resolves = entry.resolves.saturating_add(resolves);
        entry.updates = entry.updates.saturating_add(updates);
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
        let mut buckets = lock(&self.buckets);
        let key = (mnemonic.to_string(), epoch);
        if buckets.len() < MAX_PENDING_BUCKETS || buckets.contains_key(&key) {
            let b = buckets.entry(key).or_insert((0, 0));
            b.0 = b.0.saturating_add(resolves);
            b.1 = b.1.saturating_add(updates);
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        let g = buckets
            .entry((ALL_SERIES.to_string(), epoch))
            .or_insert((0, 0));
        g.0 = g.0.saturating_add(resolves);
        g.1 = g.1.saturating_add(updates);
    }

    /// Drain all accumulated per-DID deltas for sync to the control plane.
    pub fn drain_for_sync(&self) -> Vec<DidStatsDelta> {
        let mut deltas = lock(&self.deltas);
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

    /// Rows waiting to be written: per-DID deltas, time-series buckets, and
    /// fine-ring writes being retried.
    pub fn pending_rows(&self) -> usize {
        lock(&self.deltas).len() + lock(&self.buckets).len() + lock(&self.slot_retry).len()
    }

    /// Drain what is due for writing at `now`: every bucket that has closed
    /// (so a busy DID is written once per bucket, not once per flush), the
    /// deltas of the DIDs those buckets belong to, and deltas with no bucket
    /// pending at all (their bucket was dropped at the cap, or this
    /// collector keeps no time series). Open buckets, and the deltas of DIDs
    /// whose only activity is in them, wait.
    pub fn drain_due(&self, now: u64) -> (Vec<DidStatsDelta>, Vec<DrainedBucket>) {
        let open_from = now / BUCKET_SECS * BUCKET_SECS;
        let (due_buckets, open_dids) = {
            let mut buckets = lock(&self.buckets);
            let closed: Vec<BucketKey> = buckets
                .keys()
                .filter(|(_, epoch)| *epoch < open_from)
                .cloned()
                .collect();
            let due: Vec<DrainedBucket> = closed
                .into_iter()
                .filter_map(|key| {
                    let (r, u) = buckets.remove(&key)?;
                    Some(DrainedBucket {
                        mnemonic: key.0,
                        epoch: key.1,
                        resolves: r,
                        updates: u,
                    })
                })
                .collect();
            let open: std::collections::HashSet<String> =
                buckets.keys().map(|(m, _)| m.clone()).collect();
            (due, open)
        };
        let closed_dids: std::collections::HashSet<&str> =
            due_buckets.iter().map(|b| b.mnemonic.as_str()).collect();
        let mut deltas = lock(&self.deltas);
        let due_dids: Vec<String> = deltas
            .keys()
            .filter(|m| closed_dids.contains(m.as_str()) || !open_dids.contains(*m))
            .cloned()
            .collect();
        let due_deltas = due_dids
            .into_iter()
            .filter_map(|m| {
                let d = deltas.remove(&m)?;
                Some(DidStatsDelta {
                    mnemonic: m,
                    resolve_delta: d.resolves,
                    update_delta: d.updates,
                    last_resolved_at: d.last_resolved_at,
                    last_updated_at: d.last_updated_at,
                })
            })
            .collect();
        (due_deltas, due_buckets)
    }

    /// A DID's counts not yet written, so a reader can add them to the
    /// stored totals and show live numbers whatever the flush cadence.
    pub fn pending_for(&self, mnemonic: &str) -> Option<DidStatsDelta> {
        let deltas = lock(&self.deltas);
        deltas.get(mnemonic).map(|d| DidStatsDelta {
            mnemonic: mnemonic.to_string(),
            resolve_delta: d.resolves,
            update_delta: d.updates,
            last_resolved_at: d.last_resolved_at,
            last_updated_at: d.last_updated_at,
        })
    }

    /// Keep fine-ring writes that failed, for the next flush to retry on
    /// their own. Not subject to the bucket cap: there is at most one per
    /// fine DID per bucket, and fine DIDs are capped.
    pub fn requeue_slots(&self, failed: Vec<DrainedBucket>) {
        let mut slots = lock(&self.slot_retry);
        for b in failed {
            let entry = slots.entry((b.mnemonic, b.epoch)).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(b.resolves);
            entry.1 = entry.1.saturating_add(b.updates);
        }
    }

    /// Fine-ring writes to retry.
    pub fn drain_slot_retry(&self) -> Vec<DrainedBucket> {
        lock(&self.slot_retry)
            .drain()
            .map(|((mnemonic, epoch), (r, u))| DrainedBucket {
                mnemonic,
                epoch,
                resolves: r,
                updates: u,
            })
            .collect()
    }

    /// Forget a deleted DID: drop its counts not yet written, its buckets,
    /// its fine-ring retries and its tiering state, so the next flush does
    /// not write its rows back. The aggregate and the server-wide series
    /// keep what they counted. A flush already writing the DID can still
    /// land one row after this; the caller deletes the rows afterwards.
    pub fn forget_did(&self, mnemonic: &str) {
        lock(&self.deltas).remove(mnemonic);
        lock(&self.buckets).retain(|(m, _), _| m != mnemonic);
        lock(&self.slot_retry).retain(|(m, _), _| m != mnemonic);
        self.tiers().forget(mnemonic);
    }

    /// The tiering state: policy, overrides, and promoted DIDs.
    pub fn tiers(&self) -> std::sync::MutexGuard<'_, TierState> {
        lock(&self.tiers)
    }

    /// A shared handle on the tiering state, for a writer that runs on its
    /// own task.
    pub fn tier_state(&self) -> std::sync::Arc<Mutex<TierState>> {
        self.tiers.clone()
    }

    /// Set the `[stats]` policy, keeping overrides and promotions.
    pub fn configure_tiers(&self, config: StatsTierConfig) {
        self.tiers().config = config;
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
                    &d.mnemonic,
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
        let mut buckets = lock(&self.buckets);
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
            entry.0 = entry.0.saturating_add(b.resolves);
            entry.1 = entry.1.saturating_add(b.updates);
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
        let mut buckets = lock(&self.buckets);
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

/// How often a service recounts its hosted DIDs from the store.
///
/// Creates, deletes, cleanups and purges keep the count current in between;
/// the recount corrects paths that do not, such as an offline `remove` or a
/// DID an edge receives by sync. It counts the `did:` keys without reading
/// the records, but on a metered store that is still a scan: keep it rare.
pub const DID_COUNT_RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Recount the hosted DIDs from the store and reset the collector's count.
///
/// Best effort: a create or delete that commits while the scan runs can be
/// lost from the count until the next recount. The count is for display.
pub async fn reconcile_total_dids(
    collector: &StatsCollector,
    dids_ks: &KeyspaceHandle,
) -> Result<(), AppError> {
    let count = dids_ks
        .prefix_count(crate::server::store::key_prefix::DID)
        .await?;
    collector.set_total_dids(count as u64);
    Ok(())
}

/// Delete a deleted DID's statistics: its `stats:` row, its override and,
/// when it had one, its fine ring, after [`StatsCollector::forget_did`] so
/// the flush does not write them back. Every path that removes a DID record
/// calls it: an explicit delete, the empty-slot cleanup and the domain
/// purge.
///
/// Stops at the first failed delete and returns it; the rows left are read
/// by nothing (a DID created later with the same mnemonic starts from its
/// own first flush, which replaces the `stats:` row).
pub async fn delete_did_stats(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    use crate::server::stats_tiers::{FINE_SLOTS, StoredDidStats, fine_key, pin_key, stats_key};

    let had_fine = collector.tiers().pin(mnemonic) == StatsResolution::Fine;
    collector.forget_did(mnemonic);
    let row: Option<StoredDidStats> = stats_ks.get(stats_key(mnemonic)).await?;
    let had_fine = had_fine
        || row
            .as_ref()
            .and_then(|r| r.coarse.as_ref())
            .is_some_and(|c| c.fine_since.is_some());
    stats_ks.remove(stats_key(mnemonic)).await?;
    stats_ks.remove(pin_key(mnemonic)).await?;
    if had_fine {
        for slot in 0..FINE_SLOTS {
            timeseries_ks
                .remove(fine_key(mnemonic, slot * BUCKET_SECS))
                .await?;
        }
    }
    Ok(())
}

/// Seed a control plane's collector from the store at startup: the
/// aggregate from every `stats:` row, the DID count from the `did:` records,
/// and the per-DID overrides from `statspin:` rows. One scan of the stats
/// keyspace serves both of its prefixes.
pub async fn seed_from_store(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    dids_ks: &KeyspaceHandle,
) -> StatsAggregate {
    let mut attempt = 0u32;
    let (agg, pins) = loop {
        attempt += 1;
        match read_seed(stats_ks, dids_ks).await {
            Ok(seed) => break seed,
            Err(e) if attempt < SEED_ATTEMPTS => {
                let wait = SEED_RETRY_BASE * 2u32.pow(attempt - 1);
                tracing::warn!(
                    error = %e,
                    attempt,
                    retry_in_ms = wait.as_millis() as u64,
                    "stats seed: store read failed, retrying"
                );
                tokio::time::sleep(wait).await;
            }
            Err(e) => {
                // Start from zero rather than not at all: the counters are for
                // display, the hourly DID recount corrects the count, and the
                // stored rows are untouched (the flush adds to them).
                tracing::error!(
                    error = %e,
                    attempts = attempt,
                    "stats seed: store read failed; aggregate starts from zero until restart"
                );
                break (StatsAggregate::default(), Vec::new());
            }
        }
    };
    collector.seed_aggregate(&agg);
    collector.tiers().load_pins(pins);
    agg
}

/// Attempts [`seed_from_store`] makes before giving up.
const SEED_ATTEMPTS: u32 = 4;
/// The first retry's wait; each later one doubles it.
const SEED_RETRY_BASE: std::time::Duration = std::time::Duration::from_millis(250);
/// Rows a page of the seed's `stats` walk reads.
const SEED_PAGE_ROWS: usize = 512;

/// One attempt at reading [`seed_from_store`]'s inputs, a page at a time.
async fn read_seed(
    stats_ks: &KeyspaceHandle,
    dids_ks: &KeyspaceHandle,
) -> Result<(StatsAggregate, Vec<(String, StatsResolution)>), AppError> {
    let mut agg = StatsAggregate::default();
    let mut pins = Vec::new();
    let mut walk = stats_ks.walk("stats", SEED_PAGE_ROWS);
    while let Some(rows) = walk.next_page().await? {
        for (key, value) in rows {
            if let Some(m) = key.strip_prefix(crate::server::stats_tiers::PIN_PREFIX.as_bytes()) {
                if let (Ok(m), Ok(pin)) = (
                    std::str::from_utf8(m),
                    serde_json::from_slice::<StatsResolution>(&value),
                ) {
                    pins.push((m.to_string(), pin));
                }
                continue;
            }
            if !key.starts_with(b"stats:") {
                continue;
            }
            if let Ok(s) = serde_json::from_slice::<crate::DidStats>(&value) {
                agg.total_resolves += s.total_resolves;
                agg.total_updates += s.total_updates;
                agg.last_resolved_at = agg.last_resolved_at.max(s.last_resolved_at);
                agg.last_updated_at = agg.last_updated_at.max(s.last_updated_at);
            }
        }
    }
    agg.total_dids = dids_ks
        .prefix_count(crate::server::store::key_prefix::DID)
        .await? as u64;
    Ok((agg, pins))
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "stats_collector_tests.rs"]
mod tests;

#[cfg(all(test, feature = "store-fjall"))]
mod store_tests {
    use super::*;
    use crate::server::config::StoreConfig;
    use crate::server::stats_tiers::{
        CoarseSeries, FineSlot, SeriesKind, StoredDidStats, fine_key, pin_key, stats_key,
    };
    use crate::server::store::Store;

    /// Deleting a DID's statistics removes every row it had (its `stats:`
    /// row, its override and its fine ring) and the counts not yet written,
    /// so the next flush has nothing of it to write back. Another DID's rows
    /// are untouched.
    #[tokio::test]
    async fn delete_did_stats_removes_every_row_and_what_is_pending() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open fjall");
        let stats_ks = store.keyspace("stats").unwrap();
        let ts_ks = store.keyspace("timeseries").unwrap();
        let now = now_epoch();

        let mut coarse = CoarseSeries::default();
        coarse.add(SeriesKind::Did, now, 1, 0);
        coarse.fine_since = Some(now);
        for m in ["gone", "kept"] {
            let row = StoredDidStats {
                coarse: Some(coarse.clone()),
                ..StoredDidStats::default()
            };
            stats_ks.insert(stats_key(m).as_str(), &row).await.unwrap();
            stats_ks
                .insert(pin_key(m).as_str(), &StatsResolution::Fine)
                .await
                .unwrap();
            ts_ks
                .insert(fine_key(m, now).as_str(), &FineSlot { e: now, r: 1, u: 0 })
                .await
                .unwrap();
        }
        let collector = StatsCollector::new();
        collector.tiers().set_pin("gone", StatsResolution::Fine);
        collector.record_resolve("gone");
        collector.record_resolve("kept");

        delete_did_stats(&collector, &stats_ks, &ts_ks, "gone")
            .await
            .unwrap();

        for key in [stats_key("gone"), pin_key("gone")] {
            assert!(
                stats_ks.get_raw(key.as_str()).await.unwrap().is_none(),
                "{key}"
            );
        }
        assert!(ts_ks.prefix_iter_raw("t5:gone:").await.unwrap().is_empty());
        assert_eq!(collector.tiers().pin("gone"), StatsResolution::Auto);
        assert!(collector.pending_for("gone").is_none());
        let (rows, buckets) = collector.drain_due(now + 10 * BUCKET_SECS);
        assert!(rows.iter().all(|d| d.mnemonic != "gone"));
        assert!(buckets.iter().all(|b| b.mnemonic != "gone"));

        assert!(
            stats_ks
                .get_raw(stats_key("kept").as_str())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            stats_ks
                .get_raw(pin_key("kept").as_str())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(ts_ks.prefix_iter_raw("t5:kept:").await.unwrap().len(), 1);
        assert!(
            rows.iter().any(|d| d.mnemonic == "kept"),
            "another DID's counts are kept"
        );
    }
}

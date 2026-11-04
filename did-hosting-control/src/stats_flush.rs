//! Writing statistics from the in-memory collector to the store.
//!
//! A flush writes three kinds of row (see `did_hosting_common::server::
//! stats_tiers` and `docs/stats-tiers.md`):
//!
//! - **A DID's row**, `stats:{mnemonic}`: its totals plus its coarse series
//!   (hourly and daily), and the tier decision. One per DID per closed
//!   5-minute bucket at most: the periodic flush writes only what is due
//!   ([`StatsCollector::drain_due`]), so a DID resolved all day is written
//!   12 times an hour, not 360.
//! - **The server-wide coarse row**, `c:_all`.
//! - **Fine-ring slots**, `t5:{mnemonic}:{slot}`: one per closed bucket of a
//!   DID in the fine tier, and of the server-wide series. Written after the
//!   row that decided the tier, and retried on their own if they fail, so a
//!   retry never counts the coarse row twice.
//!
//! Nothing is written under the legacy `ts:` prefix any more; the migration
//! (`stats_migration`) folds those rows into the new ones.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use did_hosting_common::DidStatsDelta;
use did_hosting_common::server::stats_collector::{ALL_SERIES, DrainedBucket, StatsCollector};
use did_hosting_common::server::stats_tiers::{
    ALL_COARSE_KEY, CoarseSeries, FineSlot, SeriesKind, StoredDidStats, Tier, TierState, fine_key,
    stats_key,
};
use tokio::sync::watch;
use tracing::{debug, error, warn};

use crate::config::STATS_FLUSH_INTERVAL;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Rows a flush writes at once. The rows are independent keys, so writing
/// several together takes the same store capacity in a fraction of the
/// time the storage task would otherwise spend waiting on round trips.
pub const STATS_FLUSH_CONCURRENCY: usize = 8;

/// Oldest time-series bucket a flush still writes. Older buckets are counts
/// the store has refused or the flush could not reach for this long; they
/// are dropped with a warning so a long outage cannot grow the backlog
/// without bound. Per-DID totals are never dropped by age: there is one row
/// per DID.
pub const STATS_BUCKET_MAX_AGE: Duration = Duration::from_secs(3600);

/// How long the shutdown flush may write before giving up, well inside a
/// container's usual 30-second termination grace period so the store is
/// still persisted afterwards.
pub const STATS_SHUTDOWN_FLUSH_DEADLINE: Duration = Duration::from_secs(15);

/// How often a warning about rows dropped at the collector's caps may repeat.
const STATS_DROP_WARN_SECS: u64 = 300;

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One row a stats flush writes.
enum StatsRow {
    /// A DID's totals and closed buckets, into `stats:{mnemonic}`.
    Did {
        mnemonic: String,
        delta: Option<DidStatsDelta>,
        buckets: Vec<DrainedBucket>,
    },
    /// Server-wide buckets, into `c:_all`.
    AllCoarse(Vec<DrainedBucket>),
    /// One bucket into its fine-ring slot.
    Slot(DrainedBucket),
}

/// What a flush takes from the collector.
#[derive(Clone, Copy)]
enum Drain {
    /// What is due at this time: closed buckets and their DIDs.
    Due(u64),
    /// Everything, open buckets included (shutdown).
    All,
}

/// Flush what is due from the collector, writing at most `max_rows` rows,
/// as of `now`. For tests and callers that need a fixed clock; the storage
/// task uses [`flush_stats_paced`].
///
/// Each row is its own read-modify-write, not one transaction over the
/// whole flush: on a metered store a transaction costs twice the write
/// units, and one throttled row would fail every row with it. Rows are
/// written [`STATS_FLUSH_CONCURRENCY`] at a time. The first failed batch
/// ends the flush; failed rows and every row not yet written go back to the
/// collector, as do rows past `max_rows`, so a failed flush loses no counts
/// while the process runs. A write that reports failure is read back first,
/// and counted as written if the store applied it (a timeout after the
/// write landed), so the retry does not count it twice.
pub async fn flush_stats_to_store(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    max_rows: usize,
    now: u64,
) -> Result<(), AppError> {
    flush_stats_rows(
        collector,
        stats_ks,
        timeseries_ks,
        max_rows,
        None,
        None,
        Drain::Due(now),
    )
    .await
}

/// The periodic flush: at most [`StatsFlushConfig::rows_per_flush`] rows,
/// written at `max_rows_per_second`, so the store sees the configured rate
/// rather than the whole budget at once.
///
/// It ends within one [`STATS_FLUSH_INTERVAL`]: when writes are slow (a
/// throttled store), what would start after that waits for the next flush,
/// so the flush timer keeps its interval and the rate achieved stays close
/// to the configured one.
///
/// Once `stop` reads `true` the flush stops pacing and writes nothing more:
/// what it has not written goes back to the collector, for the shutdown
/// flush ([`flush_remaining_stats`]) to write without waiting.
///
/// [`StatsFlushConfig::rows_per_flush`]: crate::config::StatsFlushConfig::rows_per_flush
pub async fn flush_stats_paced(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    budget: &crate::config::StatsFlushConfig,
    stop: watch::Receiver<bool>,
) -> Result<(), AppError> {
    let deadline = tokio::time::Instant::now() + STATS_FLUSH_INTERVAL;
    flush_stats_paced_until(collector, stats_ks, timeseries_ks, budget, stop, deadline).await
}

/// [`flush_stats_paced`], ending at `deadline`.
pub(crate) async fn flush_stats_paced_until(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    budget: &crate::config::StatsFlushConfig,
    stop: watch::Receiver<bool>,
    deadline: tokio::time::Instant,
) -> Result<(), AppError> {
    let pace = Pace {
        rows_per_second: budget.max_rows_per_second.max(1),
        stop,
    };
    flush_stats_rows(
        collector,
        stats_ks,
        timeseries_ks,
        budget.rows_per_flush(),
        Some(deadline),
        Some(pace),
        Drain::Due(now_epoch()),
    )
    .await
}

/// How a paced flush spaces its writes.
pub(crate) struct Pace {
    pub(crate) rows_per_second: u32,
    pub(crate) stop: watch::Receiver<bool>,
}

impl Pace {
    /// Wait until `at`. Returns `false`, at once, when `stop` is or turns
    /// `true` (or its sender is gone): the caller should end.
    pub(crate) async fn wait_until(&mut self, at: tokio::time::Instant) -> bool {
        if *self.stop.borrow() {
            return false;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(at) => true,
            _ = self.stop.wait_for(|stopping| *stopping) => false,
        }
    }
}

/// Flush every pending stats row, open buckets included, for shutdown, for
/// at most [`STATS_SHUTDOWN_FLUSH_DEADLINE`]. Rows that cannot be written by
/// then are lost with the process, so that is logged as an error.
pub async fn flush_remaining_stats(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
) {
    let deadline = tokio::time::Instant::now() + STATS_SHUTDOWN_FLUSH_DEADLINE;
    let result = flush_stats_rows(
        collector,
        stats_ks,
        timeseries_ks,
        usize::MAX,
        Some(deadline),
        None,
        Drain::All,
    )
    .await;
    let lost = collector.pending_rows();
    match result {
        Err(e) => error!(
            lost,
            "final stats flush failed; unwritten statistics are lost: {e}"
        ),
        Ok(()) if lost > 0 => error!(
            lost,
            "final stats flush ran out of time; unwritten statistics are lost"
        ),
        Ok(()) => {}
    }
}

async fn flush_stats_rows(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    max_rows: usize,
    deadline: Option<tokio::time::Instant>,
    mut pace: Option<Pace>,
    drain: Drain,
) -> Result<(), AppError> {
    if let Some(dropped) = collector.take_dropped(STATS_DROP_WARN_SECS) {
        warn!(
            dropped,
            "stats backlog full; per-DID statistics were dropped (the server-wide totals and series still count them)"
        );
    }

    let (deltas, buckets) = match drain {
        Drain::Due(now) => collector.drain_due(now),
        Drain::All => (collector.drain_for_sync(), collector.drain_buckets()),
    };
    let now = match drain {
        Drain::Due(now) => now,
        Drain::All => now_epoch(),
    };
    let mut rows = stats_flush_order(
        deltas,
        recent_buckets(buckets, now),
        recent_buckets(collector.drain_slot_retry(), now),
    );
    let mut failed = Vec::new();
    let mut failure = None;
    let mut written = 0usize;
    // When the next group of writes may start, for a paced flush.
    let mut next_start = tokio::time::Instant::now();

    while written < max_rows
        && !rows.is_empty()
        && deadline.is_none_or(|d| tokio::time::Instant::now() < d)
    {
        let mut n = STATS_FLUSH_CONCURRENCY
            .min(max_rows - written)
            .min(rows.len());
        if let Some(pace) = pace.as_mut() {
            // A group that could only start after the deadline waits for
            // the next flush instead: overrunning the interval would delay
            // that flush by a whole interval and halve the rate achieved.
            if deadline.is_some_and(|d| next_start >= d) || !pace.wait_until(next_start).await {
                break;
            }
            n = n.min(pace.rows_per_second as usize);
            next_start = tokio::time::Instant::now()
                + Duration::from_secs_f64(n as f64 / f64::from(pace.rows_per_second));
        }
        let mut set = tokio::task::JoinSet::new();
        for row in rows.drain(..n) {
            let stats_ks = stats_ks.clone();
            let timeseries_ks = timeseries_ks.clone();
            let tiers = collector.tier_state();
            set.spawn(async move {
                let result = write_row(&stats_ks, &timeseries_ks, &tiers, &row, now).await;
                (row, result)
            });
        }
        let mut follow_ups = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((row, Ok(fine))) => {
                    written += 1;
                    if fine {
                        follow_ups.extend(fine_buckets(row));
                    }
                }
                Ok((row, Err(e))) => {
                    failed.push(row);
                    failure.get_or_insert(e);
                }
                Err(e) => error!("stats row write task failed; its counts are lost: {e}"),
            }
        }
        // Fine slots go next, so a DID's detail lands with its row.
        for slot in follow_ups.into_iter().rev() {
            rows.push_front(StatsRow::Slot(slot));
        }
        if failure.is_some() {
            break;
        }
    }

    let deferred = failed.len() + rows.len();
    for row in failed.into_iter().chain(rows) {
        requeue(collector, row);
    }

    match failure {
        Some(e) => {
            warn!(
                written,
                deferred, "stats flush stopped; unwritten rows requeued"
            );
            Err(e)
        }
        None => {
            if written > 0 || deferred > 0 {
                debug!(written, deferred, "flushed stats rows to store");
            }
            Ok(())
        }
    }
}

/// Put an unwritten row back in the collector, where the next flush finds it.
fn requeue(collector: &StatsCollector, row: StatsRow) {
    match row {
        StatsRow::Did { delta, buckets, .. } => {
            collector.requeue_deltas(delta.into_iter().collect());
            collector.requeue_buckets(buckets);
        }
        StatsRow::AllCoarse(buckets) => collector.requeue_buckets(buckets),
        StatsRow::Slot(b) => collector.requeue_slots(vec![b]),
    }
}

/// The buckets a row's fine slots are written from.
fn fine_buckets(row: StatsRow) -> Vec<DrainedBucket> {
    match row {
        StatsRow::Did { buckets, .. } | StatsRow::AllCoarse(buckets) => buckets,
        StatsRow::Slot(_) => Vec::new(),
    }
}

/// Write a row; `true` when its buckets also go into fine slots.
async fn write_row(
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    tiers: &Mutex<TierState>,
    row: &StatsRow,
    now: u64,
) -> Result<bool, AppError> {
    match row {
        StatsRow::Did {
            mnemonic,
            delta,
            buckets,
        } => write_did_row(stats_ks, tiers, mnemonic, delta.as_ref(), buckets, now)
            .await
            .map(|tier| tier == Tier::Fine),
        StatsRow::AllCoarse(buckets) => write_all_coarse(timeseries_ks, buckets, now)
            .await
            .map(|()| true),
        StatsRow::Slot(b) => write_fine_slot(timeseries_ks, b).await.map(|()| false),
    }
}

/// The order a flush writes rows in: the server-wide series first (what the
/// dashboard charts), then fine slots being retried, then DIDs.
fn stats_flush_order(
    deltas: Vec<DidStatsDelta>,
    buckets: Vec<DrainedBucket>,
    retry_slots: Vec<DrainedBucket>,
) -> VecDeque<StatsRow> {
    let (all, per_did): (Vec<_>, Vec<_>) =
        buckets.into_iter().partition(|b| b.mnemonic == ALL_SERIES);
    let mut rows = VecDeque::new();
    if !all.is_empty() {
        rows.push_back(StatsRow::AllCoarse(all));
    }
    rows.extend(retry_slots.into_iter().map(StatsRow::Slot));

    let mut by_did: HashMap<String, (Option<DidStatsDelta>, Vec<DrainedBucket>)> = HashMap::new();
    for d in deltas {
        let key = d.mnemonic.clone();
        by_did.entry(key).or_default().0 = Some(d);
    }
    for b in per_did {
        by_did.entry(b.mnemonic.clone()).or_default().1.push(b);
    }
    rows.extend(
        by_did
            .into_iter()
            .map(|(mnemonic, (delta, buckets))| StatsRow::Did {
                mnemonic,
                delta,
                buckets,
            }),
    );
    rows
}

/// Drop drained buckets older than [`STATS_BUCKET_MAX_AGE`] and order the
/// rest newest first.
fn recent_buckets(buckets: Vec<DrainedBucket>, now: u64) -> Vec<DrainedBucket> {
    let cutoff = now.saturating_sub(STATS_BUCKET_MAX_AGE.as_secs());
    let (mut recent, old): (Vec<_>, Vec<_>) = buckets.into_iter().partition(|b| b.epoch >= cutoff);
    if !old.is_empty() {
        warn!(
            rows = old.len(),
            "dropping time-series buckets that could not be written within the maximum age"
        );
    }
    recent.sort_by_key(|b| std::cmp::Reverse(b.epoch));
    recent
}

/// Write `value` to `key`. If the write reports failure, read the row back:
/// only the storage task writes stats rows, so finding exactly `value`
/// means the store applied the write (a timeout after it landed) and it
/// must not be retried, or the retry would count it twice.
pub(crate) async fn write_stats_row(
    ks: &KeyspaceHandle,
    key: String,
    value: serde_json::Value,
) -> Result<(), AppError> {
    match ks.insert(key.as_str(), &value).await {
        Ok(()) => Ok(()),
        Err(e) => match ks.get::<serde_json::Value>(key.as_str()).await {
            Ok(Some(stored)) if stored == value => {
                debug!(key, "stats write reported failure but was applied");
                Ok(())
            }
            _ => Err(e),
        },
    }
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<serde_json::Value, AppError> {
    serde_json::to_value(v).map_err(|e| AppError::Internal(e.to_string()))
}

/// Add a DID's deltas and closed buckets to its `stats:{mnemonic}` row,
/// decide its tier from the result ([`TierState::observe`]), and write both.
/// A DID in the `off` tier keeps no series. Returns the tier.
async fn write_did_row(
    stats_ks: &KeyspaceHandle,
    tiers: &Mutex<TierState>,
    mnemonic: &str,
    delta: Option<&DidStatsDelta>,
    buckets: &[DrainedBucket],
    now: u64,
) -> Result<Tier, AppError> {
    let key = stats_key(mnemonic);
    let mut row: StoredDidStats = stats_ks.get(key.as_str()).await?.unwrap_or_default();
    if let Some(d) = delta {
        let t = &mut row.totals;
        t.total_resolves += d.resolve_delta;
        t.total_updates += d.update_delta;
        t.last_resolved_at = t.last_resolved_at.max(d.last_resolved_at);
        t.last_updated_at = t.last_updated_at.max(d.last_updated_at);
    }
    let mut series = row.coarse.take().unwrap_or_default();
    for b in buckets {
        series.add(SeriesKind::Did, b.epoch, b.resolves, b.updates);
    }
    let tier = tiers.lock().unwrap().observe(mnemonic, &mut series, now);
    row.coarse = match tier {
        Tier::Off => None,
        _ if series == CoarseSeries::default() => None,
        _ => Some(series),
    };
    write_stats_row(stats_ks, key, to_value(&row)?).await?;
    Ok(tier)
}

/// Add server-wide buckets to the `c:_all` coarse row.
async fn write_all_coarse(
    timeseries_ks: &KeyspaceHandle,
    buckets: &[DrainedBucket],
    now: u64,
) -> Result<(), AppError> {
    let mut series: CoarseSeries = timeseries_ks.get(ALL_COARSE_KEY).await?.unwrap_or_default();
    for b in buckets {
        series.add(SeriesKind::All, b.epoch, b.resolves, b.updates);
    }
    series.fine_since.get_or_insert(now);
    write_stats_row(
        timeseries_ks,
        ALL_COARSE_KEY.to_string(),
        to_value(&series)?,
    )
    .await
}

/// Add one bucket to its fine-ring slot, replacing the bucket the ring held
/// there before.
pub(crate) async fn write_fine_slot(
    timeseries_ks: &KeyspaceHandle,
    b: &DrainedBucket,
) -> Result<(), AppError> {
    let key = fine_key(&b.mnemonic, b.epoch);
    let held: FineSlot = timeseries_ks.get(key.as_str()).await?.unwrap_or_default();
    match held.add(b.epoch, b.resolves, b.updates) {
        Some(slot) => write_stats_row(timeseries_ks, key, to_value(&slot)?).await,
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "stats_flush_tests.rs"]
mod tests;

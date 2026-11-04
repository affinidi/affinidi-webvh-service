//! Moving statistics from the legacy `ts:{series}:{epoch}` rows to the
//! tiered format, and deleting the legacy rows once they are no longer
//! needed. Run in steps by the storage task, between flushes, so it never
//! races the flush on a row and never holds the task for long.
//!
//! - **Migrate.** Once, at startup, when the marker
//!   ([`MIGRATION_MARKER_KEY`]) is missing or incomplete: one scan of `ts:`,
//!   then for each series, its legacy buckets are added to its coarse series
//!   (`stats:{mnemonic}`, or `c:_all`) and, for a series in the fine tier,
//!   the last day's into its fine ring. Each series records the legacy
//!   buckets it has taken (`migrated_through`), so a restart part-way, or a
//!   second run, never counts a bucket twice. Series for DIDs that no longer
//!   exist are skipped.
//! - **Rollback.** An older binary writes `ts:` rows again. At startup, a
//!   server-wide `ts:` bucket newer than the marker's completion means one
//!   ran, so the migration runs again; `migrated_through` limits it to what
//!   that binary wrote.
//! - **Purge.** [`LEGACY_RETENTION_SECS`] after completion the legacy rows are
//!   deleted, paced, resumably. Until then an older binary rolled back to
//!   still finds them. `purge_legacy_now` does it at once (the CLI).
//!
//! See `docs/stats-tiers.md`.

use std::collections::{BTreeMap, VecDeque};

use did_hosting_common::did_ops::did_key;
use did_hosting_common::server::stats_collector::{ALL_SERIES, DrainedBucket, StatsCollector};
use did_hosting_common::server::stats_tiers::{
    ALL_COARSE_KEY, BUCKET_SECS, CoarseSeries, DAY_SECS, HOUR_SECS, LEGACY_RETENTION_SECS,
    MIGRATION_MARKER_KEY, MIGRATION_VERSION, MigrationMarker, SeriesKind, StoredDidStats, Tier,
    stats_key,
};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::StatsFlushConfig;
use crate::error::AppError;
use crate::stats_flush::{Pace, write_fine_slot, write_stats_row};
use crate::store::KeyspaceHandle;

/// How often the maintenance step looks again when there is nothing to do.
const IDLE_CHECK_SECS: u64 = HOUR_SECS;

/// One series' legacy buckets, `(epoch, resolves, updates)`, oldest first.
struct LegacySeries {
    name: String,
    buckets: Vec<(u64, u64, u64)>,
}

enum Phase {
    /// Not looked at the marker yet (startup).
    Start,
    /// Migrating these series.
    Migrating(VecDeque<LegacySeries>),
    /// Deleting these legacy keys.
    Purging(VecDeque<Vec<u8>>),
    /// Nothing to do until then.
    Idle(u64),
}

/// The keyspaces and state the migration works on.
pub struct StatsMaintenance {
    pub stats_ks: KeyspaceHandle,
    pub timeseries_ks: KeyspaceHandle,
    pub dids_ks: KeyspaceHandle,
    phase: Phase,
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parse a legacy key, `ts:{series}:{epoch}`.
fn parse_legacy_key(key: &[u8]) -> Option<(&str, u64)> {
    let key = std::str::from_utf8(key).ok()?.strip_prefix("ts:")?;
    let (series, epoch) = key.rsplit_once(':')?;
    Some((series, epoch.parse().ok()?))
}

impl StatsMaintenance {
    pub fn new(
        stats_ks: KeyspaceHandle,
        timeseries_ks: KeyspaceHandle,
        dids_ks: KeyspaceHandle,
    ) -> Self {
        Self {
            stats_ks,
            timeseries_ks,
            dids_ks,
            phase: Phase::Start,
        }
    }

    /// Whether there is work in hand (for tests and the CLI).
    pub fn busy(&self) -> bool {
        matches!(self.phase, Phase::Migrating(_) | Phase::Purging(_))
    }

    /// Do up to one flush's worth of maintenance (`budget.rows_per_flush()`
    /// writes), paced at the flush rate, stopping at once when `stop` turns
    /// `true`.
    pub async fn step(
        &mut self,
        collector: &StatsCollector,
        budget: &StatsFlushConfig,
        stop: watch::Receiver<bool>,
    ) -> Result<(), AppError> {
        let now = now_epoch();
        match &mut self.phase {
            Phase::Start => {
                self.phase = self.start(now).await?;
                Ok(())
            }
            Phase::Idle(at) if *at <= now => {
                self.phase = self.check_purge(now).await?;
                Ok(())
            }
            Phase::Idle(_) => Ok(()),
            Phase::Migrating(_) => self.migrate_some(collector, budget, stop, now).await,
            Phase::Purging(_) => self.purge_some(budget, stop, now).await,
        }
    }

    async fn marker(&self) -> Result<Option<MigrationMarker>, AppError> {
        self.timeseries_ks.get(MIGRATION_MARKER_KEY).await
    }

    async fn put_marker(&self, m: &MigrationMarker) -> Result<(), AppError> {
        self.timeseries_ks.insert(MIGRATION_MARKER_KEY, m).await
    }

    /// Decide what startup needs: a migration (none yet, one interrupted, or
    /// an older binary has run since), or nothing but a later purge check.
    async fn start(&self, now: u64) -> Result<Phase, AppError> {
        let marker = self.marker().await?;
        let needed = match &marker {
            None => true,
            Some(m) if m.completed_at.is_none() || m.version < MIGRATION_VERSION => true,
            Some(m) => {
                self.rolled_back_since(m.completed_at.unwrap_or(0), now)
                    .await?
            }
        };
        if !needed {
            return self.check_purge(now).await;
        }
        // One replica migrates at a time: the first to count this hour's
        // lease. A replica that dies part-way leaves the next hour's lease to
        // another; `migrated_through` makes overlapping work harmless.
        let lease = format!("meta:stats-migration-lease:{}", now / HOUR_SECS);
        if self.timeseries_ks.incr_raw(lease.as_str()).await? != 1 {
            info!("stats migration: another instance holds this hour's lease");
            return Ok(Phase::Idle(now + IDLE_CHECK_SECS));
        }
        let mut m = marker.unwrap_or_default();
        m.version = MIGRATION_VERSION;
        m.started_at = now;
        m.completed_at = None;
        m.legacy_purged_at = None;
        self.put_marker(&m).await?;

        let series = self.scan_legacy().await?;
        info!(
            series = series.len(),
            "stats migration: moving legacy time series to the tiered format"
        );
        Ok(Phase::Migrating(series.into()))
    }

    /// Whether an older binary wrote server-wide `ts:` buckets after the
    /// migration completed: it writes one every flush, so the last hour
    /// tells.
    async fn rolled_back_since(&self, completed_at: u64, now: u64) -> Result<bool, AppError> {
        let newest = now / BUCKET_SECS * BUCKET_SECS;
        for i in 0..(HOUR_SECS / BUCKET_SECS) {
            let epoch = newest.saturating_sub(i * BUCKET_SECS);
            if epoch + BUCKET_SECS <= completed_at {
                break;
            }
            let key = format!("ts:{ALL_SERIES}:{epoch}");
            if self.timeseries_ks.get_raw(key.as_str()).await?.is_some() {
                warn!(
                    "stats migration: legacy rows written since the migration (an older version \
                     ran); migrating them"
                );
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The one scan: every legacy row, grouped by series.
    async fn scan_legacy(&self) -> Result<Vec<LegacySeries>, AppError> {
        #[derive(serde::Deserialize, Default)]
        struct Bucket {
            #[serde(default)]
            r: u64,
            #[serde(default)]
            u: u64,
        }
        let raw = self.timeseries_ks.prefix_iter_raw("ts:").await?;
        let mut by_series: BTreeMap<String, Vec<(u64, u64, u64)>> = BTreeMap::new();
        for (key, value) in raw {
            let Some((series, epoch)) = parse_legacy_key(&key) else {
                continue;
            };
            let Ok(b) = serde_json::from_slice::<Bucket>(&value) else {
                continue;
            };
            by_series
                .entry(series.to_string())
                .or_default()
                .push((epoch, b.r, b.u));
        }
        Ok(by_series
            .into_iter()
            .map(|(name, mut buckets)| {
                buckets.sort_unstable();
                LegacySeries { name, buckets }
            })
            .collect())
    }

    async fn migrate_some(
        &mut self,
        collector: &StatsCollector,
        budget: &StatsFlushConfig,
        stop: watch::Receiver<bool>,
        now: u64,
    ) -> Result<(), AppError> {
        let mut pace = Pace {
            rows_per_second: budget.max_rows_per_second.max(1),
            stop,
        };
        let mut spent = 0usize;
        let mut next_start = tokio::time::Instant::now();
        loop {
            let Phase::Migrating(queue) = &mut self.phase else {
                return Ok(());
            };
            if spent >= budget.rows_per_flush() {
                return Ok(());
            }
            let Some(series) = queue.pop_front() else {
                let mut m = self.marker().await?.unwrap_or_default();
                m.completed_at = Some(now);
                self.put_marker(&m).await?;
                info!("stats migration: complete; legacy rows are kept for 30 days");
                self.phase = Phase::Idle(now + IDLE_CHECK_SECS);
                return Ok(());
            };
            if !pace.wait_until(next_start).await {
                queue.push_front(series);
                return Ok(());
            }
            let writes = match self.migrate_series(collector, &series, now).await {
                Ok(w) => w,
                Err(e) => {
                    // Put it back; the next step retries it.
                    if let Phase::Migrating(queue) = &mut self.phase {
                        queue.push_front(series);
                    }
                    return Err(e);
                }
            };
            spent += writes;
            next_start = tokio::time::Instant::now()
                + std::time::Duration::from_secs_f64(
                    writes as f64 / f64::from(pace.rows_per_second),
                );
        }
    }

    /// Migrate one series; returns the writes it made.
    async fn migrate_series(
        &self,
        collector: &StatsCollector,
        series: &LegacySeries,
        now: u64,
    ) -> Result<usize, AppError> {
        let server_wide = series.name == ALL_SERIES;
        if !server_wide && !self.dids_ks.contains_key(did_key(&series.name)).await? {
            return Ok(1); // a deleted DID's history: nothing to keep
        }
        let (mut coarse, mut row) = if server_wide {
            let c: Option<CoarseSeries> = self.timeseries_ks.get(ALL_COARSE_KEY).await?;
            (c.unwrap_or_default(), None)
        } else {
            let mut r: StoredDidStats = self
                .stats_ks
                .get(stats_key(&series.name))
                .await?
                .unwrap_or_default();
            (r.coarse.take().unwrap_or_default(), Some(r))
        };
        let watermark = coarse.migrated_through.unwrap_or(0);
        let fresh: Vec<_> = series
            .buckets
            .iter()
            .filter(|(e, _, _)| *e >= watermark)
            .copied()
            .collect();
        let Some(&(newest, _, _)) = fresh.last() else {
            return Ok(1);
        };
        let kind = if server_wide {
            SeriesKind::All
        } else {
            SeriesKind::Did
        };
        for &(e, r, u) in &fresh {
            coarse.add(kind, e, r, u);
        }
        coarse.migrated_through = Some(newest + BUCKET_SECS);

        let tier = if server_wide {
            Tier::Fine
        } else {
            collector.tiers().observe(&series.name, &mut coarse, now)
        };
        if tier == Tier::Fine {
            // The ring holds the last day: the copy below fills it.
            coarse.fine_since = Some(
                coarse
                    .fine_since
                    .map_or(now - DAY_SECS, |fs| fs.min(now - DAY_SECS)),
            );
        }

        // The row first: a crash before the slots are written leaves them
        // short, never counted twice.
        let mut writes = 1;
        match row.as_mut() {
            None => {
                let value =
                    serde_json::to_value(&coarse).map_err(|e| AppError::Internal(e.to_string()))?;
                write_stats_row(&self.timeseries_ks, ALL_COARSE_KEY.into(), value).await?;
            }
            Some(r) => {
                r.coarse = match tier {
                    Tier::Off => None,
                    _ => Some(coarse),
                };
                let value =
                    serde_json::to_value(&*r).map_err(|e| AppError::Internal(e.to_string()))?;
                write_stats_row(&self.stats_ks, stats_key(&series.name), value).await?;
            }
        }
        if tier == Tier::Fine {
            let day_ago = now.saturating_sub(DAY_SECS);
            for &(e, r, u) in fresh.iter().filter(|(e, _, _)| *e >= day_ago) {
                write_fine_slot(
                    &self.timeseries_ks,
                    &DrainedBucket {
                        mnemonic: series.name.clone(),
                        epoch: e,
                        resolves: r,
                        updates: u,
                    },
                )
                .await?;
                writes += 1;
            }
        }
        Ok(writes)
    }

    /// After the retention period, start deleting the legacy rows.
    async fn check_purge(&self, now: u64) -> Result<Phase, AppError> {
        let Some(m) = self.marker().await? else {
            return Ok(Phase::Idle(now + IDLE_CHECK_SECS));
        };
        let due = m
            .completed_at
            .is_some_and(|c| c + LEGACY_RETENTION_SECS <= now)
            && m.legacy_purged_at.is_none();
        if !due {
            return Ok(Phase::Idle(now + IDLE_CHECK_SECS));
        }
        self.start_purge().await
    }

    async fn start_purge(&self) -> Result<Phase, AppError> {
        let keys: VecDeque<Vec<u8>> = self
            .timeseries_ks
            .prefix_iter_raw("ts:")
            .await?
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        info!(rows = keys.len(), "stats: deleting legacy time-series rows");
        Ok(Phase::Purging(keys))
    }

    async fn purge_some(
        &mut self,
        budget: &StatsFlushConfig,
        stop: watch::Receiver<bool>,
        now: u64,
    ) -> Result<(), AppError> {
        let mut pace = Pace {
            rows_per_second: budget.max_rows_per_second.max(1),
            stop,
        };
        let mut next_start = tokio::time::Instant::now();
        for _ in 0..budget.rows_per_flush() {
            let Phase::Purging(keys) = &mut self.phase else {
                return Ok(());
            };
            let Some(key) = keys.pop_front() else {
                let mut m = self.marker().await?.unwrap_or_default();
                m.legacy_purged_at = Some(now);
                self.put_marker(&m).await?;
                info!("stats: legacy time-series rows deleted");
                self.phase = Phase::Idle(now + IDLE_CHECK_SECS);
                return Ok(());
            };
            if !pace.wait_until(next_start).await {
                keys.push_front(key);
                return Ok(());
            }
            if let Err(e) = self.timeseries_ks.remove(key.clone()).await {
                if let Phase::Purging(keys) = &mut self.phase {
                    keys.push_front(key);
                }
                return Err(e);
            }
            next_start = tokio::time::Instant::now()
                + std::time::Duration::from_secs_f64(1.0 / f64::from(pace.rows_per_second));
        }
        Ok(())
    }

    /// Migrate if needed, then delete the legacy rows now, without waiting
    /// for the retention period (the `stats purge-legacy` command). Not
    /// paced beyond `budget`; runs to completion.
    pub async fn purge_legacy_now(
        &mut self,
        collector: &StatsCollector,
        budget: &StatsFlushConfig,
    ) -> Result<usize, AppError> {
        let (_tx, stop) = watch::channel(false);
        self.phase = self.start(now_epoch()).await?;
        while matches!(self.phase, Phase::Migrating(_)) {
            self.migrate_some(collector, budget, stop.clone(), now_epoch())
                .await?;
        }
        if self.marker().await?.and_then(|m| m.completed_at).is_none() {
            return Err(AppError::Internal(
                "the migration has not completed (another instance may hold its lease)".into(),
            ));
        }
        self.phase = self.start_purge().await?;
        let Phase::Purging(keys) = &self.phase else {
            return Ok(0);
        };
        let n = keys.len();
        while matches!(self.phase, Phase::Purging(_)) {
            self.purge_some(budget, stop.clone(), now_epoch()).await?;
        }
        Ok(n)
    }
}

#[cfg(test)]
#[path = "stats_migration_tests.rs"]
mod tests;

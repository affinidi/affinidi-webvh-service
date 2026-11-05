//! Moving statistics from the legacy `ts:{series}:{epoch}` rows to the
//! tiered format, and deleting the legacy rows once they are no longer
//! needed. Run in steps by the storage task, between flushes, so it never
//! races the flush on a row and never holds the task for long.
//!
//! - **Migrate.** Once, at startup, when the marker
//!   ([`MIGRATION_MARKER_KEY`]) is missing or incomplete: `ts:` is read a
//!   page at a time ([`LEGACY_PAGE_ROWS`] keys), keeping only buckets within
//!   [`LEGACY_HORIZON_SECS`], and for each series, its legacy buckets are
//!   added to its coarse series
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
use did_hosting_common::server::store::RawKvPair;

/// How often the maintenance step looks again when there is nothing to do.
const IDLE_CHECK_SECS: u64 = HOUR_SECS;

/// Keys read a page (see [`KeyspaceHandle::prefix_page_raw`]).
///
/// What is held in memory meanwhile, about 24 bytes a bucket kept:
/// - pages in key order (fjall): one series at a time, until its rows end;
/// - pages in hash order (DynamoDB): every series, until the walk ends,
///   since a series' rows are spread across it;
/// - a backend that cannot page (Redis, Firestore, Cosmos DB): the whole
///   prefix, read at once.
///
/// In each case only buckets within [`LEGACY_HORIZON_SECS`] are kept, so the
/// bound is a month of history, not the deployment's age.
pub const LEGACY_PAGE_ROWS: usize = 1_000;

/// How far back legacy buckets are migrated. The longest chart is 30 days,
/// and a bucket older than that is never shown, so it is not kept; the
/// extra day covers a daily point straddling the window's start.
pub const LEGACY_HORIZON_SECS: u64 = 31 * DAY_SECS;

/// Most pages read in one step, so a long series does not hold the storage
/// task; the next steps read on.
const MAX_PAGES_PER_STEP: usize = 10;

/// How long to wait after a failed whole read (a backend that cannot page)
/// before reading again. Such a read starts from the beginning, so retrying
/// it every flush would re-read everything against a store already refusing.
const WHOLE_READ_RETRY_SECS: u64 = 300;

/// One series' legacy buckets, `(epoch, resolves, updates)`, oldest first.
struct LegacySeries {
    name: String,
    buckets: Vec<(u64, u64, u64)>,
}

enum Phase {
    /// Not looked at the marker yet (startup).
    Start,
    /// Migrating, reading the legacy rows as it goes.
    Migrating(Migrating),
    /// Deleting the legacy rows, reading their keys as it goes.
    Purging(Purging),
    /// Nothing to do until then.
    Idle(u64),
}

/// How far reading the legacy rows has got.
#[derive(Default)]
struct LegacyCursor {
    /// Where the next page starts (the last page's `next`).
    next: Option<Vec<u8>>,
    /// Every legacy row has been read.
    exhausted: bool,
    /// Do not read before this second (set by a failed whole read).
    retry_at: u64,
}

/// Where a migration is: series read and ready to fold, and those whose
/// rows may continue on a later page.
#[derive(Default)]
struct Migrating {
    ready: VecDeque<LegacySeries>,
    /// Pages in key order: the series the last page ended in.
    partial: Option<LegacySeries>,
    /// Pages in hash order: every series read so far, all held until the
    /// walk ends, since any later page may hold more of any of them.
    held: BTreeMap<String, Vec<(u64, u64, u64)>>,
    cursor: LegacyCursor,
}

/// Where a purge is: keys read and not yet deleted.
#[derive(Default)]
struct Purging {
    keys: VecDeque<Vec<u8>>,
    cursor: LegacyCursor,
}

#[derive(serde::Deserialize, Default)]
struct LegacyBucket {
    #[serde(default)]
    r: u64,
    #[serde(default)]
    u: u64,
}

/// A legacy row as `(series, (epoch, resolves, updates))`, or `None` if it
/// is not one or is older than `oldest`.
fn parse_legacy_row(key: &[u8], value: &[u8], oldest: u64) -> Option<(String, (u64, u64, u64))> {
    let (series, epoch) = parse_legacy_key(key)?;
    if epoch < oldest {
        return None;
    }
    let b: LegacyBucket = serde_json::from_slice(value).ok()?;
    Some((series.to_string(), (epoch, b.r, b.u)))
}

/// The keyspaces and state the migration works on.
pub struct StatsMaintenance {
    pub stats_ks: KeyspaceHandle,
    pub timeseries_ks: KeyspaceHandle,
    pub dids_ks: KeyspaceHandle,
    phase: Phase,
    page_rows: usize,
    /// Legacy rows deleted by this instance (for the CLI's report).
    purged_rows: usize,
    /// The hour whose migration lease this instance took, so a retry after
    /// a failure part-way through `start` does not mistake it for another
    /// instance's.
    lease_hour: Option<u64>,
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
            page_rows: LEGACY_PAGE_ROWS,
            purged_rows: 0,
            lease_hour: None,
        }
    }

    /// Read legacy rows `rows` at a time instead of [`LEGACY_PAGE_ROWS`].
    #[cfg(test)]
    pub(crate) fn with_page_rows(mut self, rows: usize) -> Self {
        self.page_rows = rows.max(1);
        self
    }

    /// Whether there is work in hand (for tests and the CLI).
    pub fn busy(&self) -> bool {
        matches!(self.phase, Phase::Migrating(_) | Phase::Purging(_))
    }

    /// Do up to one flush's worth of maintenance (`budget.rows_per_flush()`
    /// writes), paced at the flush rate, starting nothing after `deadline`
    /// (the end of the flush tick) and stopping at once when `stop` turns
    /// `true`.
    pub async fn step(
        &mut self,
        collector: &StatsCollector,
        budget: &StatsFlushConfig,
        stop: watch::Receiver<bool>,
        deadline: tokio::time::Instant,
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
            Phase::Migrating(_) => {
                self.migrate_some(collector, budget, stop, now, deadline)
                    .await
            }
            Phase::Purging(_) => self.purge_some(budget, stop, now, deadline).await,
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
    async fn start(&mut self, now: u64) -> Result<Phase, AppError> {
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
        let hour = now / HOUR_SECS;
        if self.lease_hour != Some(hour) {
            let lease = format!("meta:stats-migration-lease:{hour}");
            if self.timeseries_ks.incr_raw(lease.as_str()).await? != 1 {
                info!("stats migration: another instance holds this hour's lease");
                return Ok(Phase::Idle(now + IDLE_CHECK_SECS));
            }
            self.lease_hour = Some(hour);
        }
        let mut m = marker.unwrap_or_default();
        m.version = MIGRATION_VERSION;
        m.started_at = now;
        m.completed_at = None;
        m.legacy_purged_at = None;
        self.put_marker(&m).await?;

        // The legacy rows are read by the steps that follow, a page at a
        // time, so a failed read is retried from where it stopped rather
        // than here, under a lease this instance already counted.
        info!("stats migration: moving legacy time series to the tiered format");
        Ok(Phase::Migrating(Migrating::default()))
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

    /// The next legacy rows from `cursor`, and whether they are in key
    /// order: a page, or every row on a backend that cannot page. The
    /// cursor moves only on success; a failed whole read sets `retry_at`.
    async fn next_legacy_rows(
        &self,
        cursor: &mut LegacyCursor,
        now: u64,
    ) -> Result<(Vec<RawKvPair>, bool), AppError> {
        let page = self
            .timeseries_ks
            .prefix_page_raw("ts:", cursor.next.clone(), self.page_rows)
            .await?;
        let Some(page) = page else {
            return match self.timeseries_ks.prefix_iter_raw("ts:").await {
                Ok(all) => {
                    cursor.exhausted = true;
                    Ok((all, false))
                }
                Err(e) => {
                    cursor.retry_at = now + WHOLE_READ_RETRY_SECS;
                    Err(e)
                }
            };
        };
        cursor.exhausted = page.next.is_none();
        cursor.next = page.next;
        Ok((page.rows, page.ordered))
    }

    /// Read more legacy rows into `m`, keeping buckets within
    /// [`LEGACY_HORIZON_SECS`] of `now`.
    ///
    /// In key order, a series is ready once a row of another series follows
    /// it, or the rows run out. That relies on one series' rows being
    /// together in key order, which holds because a mnemonic has no `:`
    /// (path segments are `[a-z0-9-]`, a `did:webs` AID base64url). Out of
    /// key order (hash-ordered pages, or a whole read), every series is held
    /// until the rows run out.
    async fn read_legacy(&self, m: &mut Migrating, now: u64) -> Result<(), AppError> {
        let (rows, ordered) = self.next_legacy_rows(&mut m.cursor, now).await?;
        let oldest = now.saturating_sub(LEGACY_HORIZON_SECS);
        if !ordered {
            for (key, value) in rows {
                if let Some((series, bucket)) = parse_legacy_row(&key, &value, oldest) {
                    m.held.entry(series).or_default().push(bucket);
                }
            }
        } else {
            for (key, value) in rows {
                let Some((series, bucket)) = parse_legacy_row(&key, &value, oldest) else {
                    continue;
                };
                match &mut m.partial {
                    Some(p) if p.name == series => p.buckets.push(bucket),
                    partial => {
                        if let Some(done) = partial.replace(LegacySeries {
                            name: series,
                            buckets: vec![bucket],
                        }) {
                            m.ready.push_back(done);
                        }
                    }
                }
            }
        }
        if m.cursor.exhausted {
            m.ready.extend(m.partial.take());
            m.ready.extend(
                std::mem::take(&mut m.held)
                    .into_iter()
                    .map(|(name, buckets)| LegacySeries { name, buckets }),
            );
        }
        for series in &mut m.ready {
            series.buckets.sort_unstable();
        }
        Ok(())
    }

    async fn migrate_some(
        &mut self,
        collector: &StatsCollector,
        budget: &StatsFlushConfig,
        stop: watch::Receiver<bool>,
        now: u64,
        deadline: tokio::time::Instant,
    ) -> Result<(), AppError> {
        let mut pace = Pace {
            rows_per_second: budget.max_rows_per_second.max(1),
            stop,
        };
        let mut spent = 0usize;
        let mut pages = 0usize;
        let mut next_start = tokio::time::Instant::now();
        loop {
            let Phase::Migrating(m) = &mut self.phase else {
                return Ok(());
            };
            if spent >= budget.rows_per_flush() || tokio::time::Instant::now() >= deadline {
                return Ok(());
            }
            if m.ready.is_empty() && !m.cursor.exhausted {
                if pages >= MAX_PAGES_PER_STEP || now < m.cursor.retry_at {
                    return Ok(());
                }
                pages += 1;
                // A failed read leaves the phase as it was: the next step
                // reads the same page again (a whole read, after a pause).
                // Pages may be empty while more follow (a scan's keys outside
                // `ts:`), so pages, not rows, bound a step's reads.
                let mut state = std::mem::take(m);
                let result = self.read_legacy(&mut state, now).await;
                self.phase = Phase::Migrating(state);
                result?;
                continue;
            }
            let Some(series) = m.ready.pop_front() else {
                let mut m = self.marker().await?.unwrap_or_default();
                m.completed_at = Some(now);
                self.put_marker(&m).await?;
                info!("stats migration: complete; legacy rows are kept for 30 days");
                self.phase = Phase::Idle(now + IDLE_CHECK_SECS);
                return Ok(());
            };
            if next_start >= deadline || !pace.wait_until(next_start).await {
                m.ready.push_front(series);
                return Ok(());
            }
            let writes = match self.migrate_series(collector, &series, now).await {
                Ok(w) => w,
                Err(e) => {
                    // Put it back; the next step retries it.
                    if let Phase::Migrating(m) = &mut self.phase {
                        m.ready.push_front(series);
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
        info!("stats: deleting legacy time-series rows");
        Ok(Phase::Purging(Purging::default()))
    }

    /// Read more legacy keys into `p`, every bucket whatever its age. Keys
    /// are deleted behind the cursor, which stays a valid place to resume
    /// once the key it names is gone, in key order and in hash order alike.
    async fn read_purge_keys(&self, p: &mut Purging, now: u64) -> Result<(), AppError> {
        let (rows, _) = self.next_legacy_rows(&mut p.cursor, now).await?;
        p.keys.extend(rows.into_iter().map(|(k, _)| k));
        Ok(())
    }

    async fn purge_some(
        &mut self,
        budget: &StatsFlushConfig,
        stop: watch::Receiver<bool>,
        now: u64,
        deadline: tokio::time::Instant,
    ) -> Result<(), AppError> {
        let mut pace = Pace {
            rows_per_second: budget.max_rows_per_second.max(1),
            stop,
        };
        let mut next_start = tokio::time::Instant::now();
        let mut spent = 0usize;
        let mut pages = 0usize;
        while spent < budget.rows_per_flush() && tokio::time::Instant::now() < deadline {
            let Phase::Purging(p) = &mut self.phase else {
                return Ok(());
            };
            if p.keys.is_empty() && !p.cursor.exhausted {
                if pages >= MAX_PAGES_PER_STEP || now < p.cursor.retry_at {
                    return Ok(());
                }
                pages += 1;
                let mut state = std::mem::take(p);
                let result = self.read_purge_keys(&mut state, now).await;
                self.phase = Phase::Purging(state);
                result?;
                continue;
            }
            let Some(key) = p.keys.pop_front() else {
                let mut m = self.marker().await?.unwrap_or_default();
                m.legacy_purged_at = Some(now);
                self.put_marker(&m).await?;
                info!("stats: legacy time-series rows deleted");
                self.phase = Phase::Idle(now + IDLE_CHECK_SECS);
                return Ok(());
            };
            if next_start >= deadline || !pace.wait_until(next_start).await {
                p.keys.push_front(key);
                return Ok(());
            }
            if let Err(e) = self.timeseries_ks.remove(key.clone()).await {
                if let Phase::Purging(p) = &mut self.phase {
                    p.keys.push_front(key);
                }
                return Err(e);
            }
            spent += 1;
            self.purged_rows += 1;
            next_start = tokio::time::Instant::now()
                + std::time::Duration::from_secs_f64(1.0 / f64::from(pace.rows_per_second));
        }
        Ok(())
    }

    /// Migrate if needed, then delete the legacy rows now, without waiting
    /// for the retention period (the `stats purge-legacy` command). Not
    /// paced beyond `budget`; runs to completion. Returns the rows deleted.
    pub async fn purge_legacy_now(
        &mut self,
        collector: &StatsCollector,
        budget: &StatsFlushConfig,
    ) -> Result<usize, AppError> {
        let (_tx, stop) = watch::channel(false);
        // Runs to completion: each round gets a fresh deadline.
        let round = || tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
        self.phase = self.start(now_epoch()).await?;
        while matches!(self.phase, Phase::Migrating(_)) {
            self.migrate_some(collector, budget, stop.clone(), now_epoch(), round())
                .await?;
        }
        if self.marker().await?.and_then(|m| m.completed_at).is_none() {
            return Err(AppError::Internal(
                "the migration has not completed (another instance may hold its lease)".into(),
            ));
        }
        self.phase = self.start_purge().await?;
        let before = self.purged_rows;
        while matches!(self.phase, Phase::Purging(_)) {
            self.purge_some(budget, stop.clone(), now_epoch(), round())
                .await?;
        }
        Ok(self.purged_rows - before)
    }
}

#[cfg(test)]
#[path = "stats_migration_tests.rs"]
mod tests;

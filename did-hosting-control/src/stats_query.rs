//! Reading the tiered statistics for the usage charts.
//!
//! Every read is by key: one `stats:{mnemonic}` row (or `c:_all`) for the
//! coarse series, and, for a fine series over the last hour or day, the
//! ring slots that window covers. Nothing scans, so a chart costs the same
//! however long the service has run.
//!
//! Until the migration has completed (its marker exists), charts are read
//! from the legacy `ts:` rows instead, so nothing goes blank while it runs.

use did_hosting_common::server::stats_collector::ALL_SERIES;
use did_hosting_common::server::stats_tiers::{
    ALL_COARSE_KEY, BUCKET_SECS, CoarseSeries, DAY_SECS, FineSlot, HOUR_SECS, MIGRATION_MARKER_KEY,
    MigrationMarker, StoredDidStats, fine_key, stats_key,
};

use crate::control_tasks::queries::TimeSeriesPoint;
use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// A chart window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    LastHour,
    LastDay,
    LastWeek,
    Last30Days,
}

impl Range {
    /// From the legacy reader's range names (`1h`, `24h`, `7d`, `30d`).
    pub fn from_name(name: &str) -> Self {
        match name {
            "1h" => Self::LastHour,
            "7d" => Self::LastWeek,
            "30d" => Self::Last30Days,
            _ => Self::LastDay,
        }
    }

    pub fn seconds(self) -> u64 {
        match self {
            Self::LastHour => HOUR_SECS,
            Self::LastDay => DAY_SECS,
            Self::LastWeek => 7 * DAY_SECS,
            Self::Last30Days => 30 * DAY_SECS,
        }
    }

    /// Point width with 5-minute detail, as the legacy reader used.
    fn fine_step(self) -> u64 {
        match self {
            Self::LastHour => BUCKET_SECS,
            Self::LastDay => 900,
            Self::LastWeek => HOUR_SECS,
            Self::Last30Days => 4 * HOUR_SECS,
        }
    }

    /// Whether the fine ring (24 hours) covers this window.
    fn fine_covers(self) -> bool {
        matches!(self, Self::LastHour | Self::LastDay)
    }
}

/// A chart: its points, oldest first, and the width of each.
#[derive(Debug)]
pub struct Chart {
    pub points: Vec<TimeSeriesPoint>,
    pub bucket_seconds: u64,
}

/// Whether the migration to the tiered format has completed, so charts are
/// read from it.
pub async fn tiered_ready(timeseries_ks: &KeyspaceHandle) -> Result<bool, AppError> {
    let marker: Option<MigrationMarker> = timeseries_ks.get(MIGRATION_MARKER_KEY).await?;
    Ok(marker.is_some_and(|m| m.completed_at.is_some()))
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Sum `(start, resolves, updates)` points into steps of `step` seconds
/// covering the window ending at `now`, one point per step, empty ones
/// included.
fn into_steps(
    source: impl Iterator<Item = (u64, u64, u64)>,
    range: Range,
    step: u64,
    now: u64,
) -> Vec<TimeSeriesPoint> {
    let start = now.saturating_sub(range.seconds()) / step * step;
    let end = now / step * step;
    let n = ((end - start) / step + 1) as usize;
    let mut points: Vec<TimeSeriesPoint> = (0..n)
        .map(|i| TimeSeriesPoint {
            timestamp: start + i as u64 * step,
            resolves: 0,
            updates: 0,
        })
        .collect();
    for (at, r, u) in source {
        if at < start || at > end + step - 1 {
            continue;
        }
        let i = ((at - start) / step) as usize;
        if let Some(p) = points.get_mut(i) {
            p.resolves += r;
            p.updates += u;
        }
    }
    points
}

/// The fine slots covering `range`, as `(start, resolves, updates)`: a slot
/// that holds a different bucket (the ring has not reached it yet, or
/// passed it) counts as empty.
async fn read_fine(
    timeseries_ks: &KeyspaceHandle,
    series: &str,
    range: Range,
    now: u64,
) -> Result<Vec<(u64, u64, u64)>, AppError> {
    let first = now.saturating_sub(range.seconds()) / BUCKET_SECS * BUCKET_SECS;
    let last = now / BUCKET_SECS * BUCKET_SECS;
    let epochs: Vec<u64> = (first..=last).step_by(BUCKET_SECS as usize).collect();
    let mut out = Vec::with_capacity(epochs.len());
    // Bounded fan-out: a day is 288 reads.
    for chunk in epochs.chunks(16) {
        let mut set = tokio::task::JoinSet::new();
        for &epoch in chunk {
            let ks = timeseries_ks.clone();
            let key = fine_key(series, epoch);
            set.spawn(async move {
                let slot: Option<FineSlot> = ks.get(key.as_str()).await?;
                Ok::<_, AppError>(slot.filter(|s| s.e == epoch).map(|s| (s.e, s.r, s.u)))
            });
        }
        while let Some(joined) = set.join_next().await {
            let slot = joined.map_err(|e| AppError::Internal(e.to_string()))??;
            out.extend(slot);
        }
    }
    Ok(out)
}

/// Chart a coarse series: hourly points, or daily for a DID over 30 days
/// (it keeps 7 days of hours); the server-wide series keeps 30 days of
/// hours and charts them in 4-hour steps, as before.
fn coarse_chart(series: &CoarseSeries, range: Range, server_wide: bool, now: u64) -> Chart {
    let (step, daily) = match range {
        Range::Last30Days if server_wide => (4 * HOUR_SECS, false),
        Range::Last30Days => (DAY_SECS, true),
        _ => (HOUR_SECS, false),
    };
    let points = if daily {
        into_steps(series.daily(), range, step, now)
    } else {
        into_steps(series.hourly(), range, step, now)
    };
    Chart {
        points,
        bucket_seconds: step,
    }
}

/// Chart one series. 5-minute detail when the series has kept it since
/// before the window starts and the ring covers the window; otherwise its
/// coarse series, at the coarser `bucket_seconds` the response states.
async fn chart_series(
    timeseries_ks: &KeyspaceHandle,
    name: &str,
    coarse: Option<CoarseSeries>,
    range: Range,
    server_wide: bool,
    now: u64,
) -> Result<Chart, AppError> {
    let coarse = coarse.unwrap_or_default();
    let window_start = now.saturating_sub(range.seconds());
    let fine = range.fine_covers() && coarse.fine_since.is_some_and(|fs| fs <= window_start);
    if fine {
        let step = range.fine_step();
        let slots = read_fine(timeseries_ks, name, range, now).await?;
        return Ok(Chart {
            points: into_steps(slots.into_iter(), range, step, now),
            bucket_seconds: step,
        });
    }
    Ok(coarse_chart(&coarse, range, server_wide, now))
}

/// One DID's chart.
pub async fn did_chart(
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    mnemonic: &str,
    range: Range,
) -> Result<Chart, AppError> {
    let row: Option<StoredDidStats> = stats_ks.get(stats_key(mnemonic)).await?;
    chart_series(
        timeseries_ks,
        mnemonic,
        row.and_then(|r| r.coarse),
        range,
        false,
        now_epoch(),
    )
    .await
}

/// The server-wide chart.
pub async fn server_chart(timeseries_ks: &KeyspaceHandle, range: Range) -> Result<Chart, AppError> {
    let coarse: Option<CoarseSeries> = timeseries_ks.get(ALL_COARSE_KEY).await?;
    chart_series(timeseries_ks, ALL_SERIES, coarse, range, true, now_epoch()).await
}

/// A domain's chart: the sum of its DIDs' coarse series (hourly, or daily
/// over 30 days). One row read per DID; the fine rings are not summed,
/// because most of a domain's DIDs do not keep them.
pub async fn domain_chart(
    stats_ks: &KeyspaceHandle,
    mnemonics: &[String],
    range: Range,
) -> Result<Chart, AppError> {
    let now = now_epoch();
    let mut sum = CoarseSeries::default();
    for chunk in mnemonics.chunks(16) {
        let mut set = tokio::task::JoinSet::new();
        for m in chunk {
            let ks = stats_ks.clone();
            let key = stats_key(m);
            set.spawn(async move { ks.get::<StoredDidStats>(key.as_str()).await });
        }
        while let Some(joined) = set.join_next().await {
            let row = joined.map_err(|e| AppError::Internal(e.to_string()))??;
            if let Some(c) = row.and_then(|r| r.coarse) {
                merge(&mut sum.hours, &c.hours);
                merge(&mut sum.days, &c.days);
            }
        }
    }
    Ok(coarse_chart(&sum, range, false, now))
}

fn merge(into: &mut Vec<[u64; 3]>, from: &[[u64; 3]]) {
    for p in from {
        match into.binary_search_by_key(&p[0], |q| q[0]) {
            Ok(i) => {
                into[i][1] += p[1];
                into[i][2] += p[2];
            }
            Err(i) => into.insert(i, *p),
        }
    }
}

#[cfg(test)]
mod tests {
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::stats_tiers::SeriesKind;

    use super::*;
    use crate::store::Store;

    async fn keyspaces() -> (tempfile::TempDir, KeyspaceHandle, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open fjall");
        let s = store.keyspace("stats").unwrap();
        let t = store.keyspace("timeseries").unwrap();
        (dir, s, t)
    }

    fn total(c: &Chart) -> u64 {
        c.points.iter().map(|p| p.resolves).sum()
    }

    #[test]
    fn steps_cover_the_window_including_empty_ones() {
        let now = 100 * HOUR_SECS + 10;
        let pts = into_steps(
            [(now - 600, 2, 0), (now - 7200, 1, 1)].into_iter(),
            Range::LastHour,
            BUCKET_SECS,
            now,
        );
        assert_eq!(pts.len(), 13);
        assert_eq!(
            pts.iter().map(|p| p.resolves).sum::<u64>(),
            2,
            "outside dropped"
        );
        assert_eq!(pts.first().unwrap().timestamp % BUCKET_SECS, 0);
    }

    #[tokio::test]
    async fn a_coarse_did_is_charted_hourly_and_daily() {
        let (_d, stats_ks, ts_ks) = keyspaces().await;
        let now = now_epoch();
        let mut c = CoarseSeries::default();
        c.add(SeriesKind::Did, now - 2 * HOUR_SECS, 5, 0);
        c.add(SeriesKind::Did, now - 10 * DAY_SECS, 7, 0);
        let row = StoredDidStats {
            coarse: Some(c),
            ..StoredDidStats::default()
        };
        stats_ks
            .insert(stats_key("alice").as_str(), &row)
            .await
            .unwrap();

        let day = did_chart(&stats_ks, &ts_ks, "alice", Range::LastDay)
            .await
            .unwrap();
        assert_eq!(day.bucket_seconds, HOUR_SECS, "no fine ring: hourly");
        assert_eq!(total(&day), 5);
        let month = did_chart(&stats_ks, &ts_ks, "alice", Range::Last30Days)
            .await
            .unwrap();
        assert_eq!(month.bucket_seconds, DAY_SECS);
        assert_eq!(total(&month), 12);
        let none = did_chart(&stats_ks, &ts_ks, "nobody", Range::LastWeek)
            .await
            .unwrap();
        assert_eq!(total(&none), 0);
    }

    #[tokio::test]
    async fn a_fine_did_is_charted_from_its_ring_once_it_covers_the_window() {
        let (_d, stats_ks, ts_ks) = keyspaces().await;
        let now = now_epoch();
        let bucket = now / BUCKET_SECS * BUCKET_SECS - BUCKET_SECS;
        let mut c = CoarseSeries::default();
        c.add(SeriesKind::Did, bucket, 3, 0);
        c.fine_since = Some(now - 2 * HOUR_SECS);
        let row = StoredDidStats {
            coarse: Some(c),
            ..StoredDidStats::default()
        };
        stats_ks
            .insert(stats_key("alice").as_str(), &row)
            .await
            .unwrap();
        ts_ks
            .insert(
                fine_key("alice", bucket).as_str(),
                &FineSlot {
                    e: bucket,
                    r: 3,
                    u: 0,
                },
            )
            .await
            .unwrap();
        // A slot left from a day ago is not this window's.
        let stale = bucket - BUCKET_SECS;
        ts_ks
            .insert(
                fine_key("alice", stale).as_str(),
                &FineSlot {
                    e: stale - DAY_SECS,
                    r: 99,
                    u: 0,
                },
            )
            .await
            .unwrap();

        let hour = did_chart(&stats_ks, &ts_ks, "alice", Range::LastHour)
            .await
            .unwrap();
        assert_eq!(hour.bucket_seconds, BUCKET_SECS);
        assert_eq!(total(&hour), 3);
        // Fine for 2 hours only: the day falls back to hourly points.
        let day = did_chart(&stats_ks, &ts_ks, "alice", Range::LastDay)
            .await
            .unwrap();
        assert_eq!(day.bucket_seconds, HOUR_SECS);
        assert_eq!(total(&day), 3);
    }

    #[tokio::test]
    async fn a_domain_sums_its_dids_coarse_series() {
        let (_d, stats_ks, _ts) = keyspaces().await;
        let now = now_epoch();
        for (m, r) in [("a", 2), ("b", 3)] {
            let mut c = CoarseSeries::default();
            c.add(SeriesKind::Did, now - HOUR_SECS, r, 0);
            let row = StoredDidStats {
                coarse: Some(c),
                ..StoredDidStats::default()
            };
            stats_ks.insert(stats_key(m).as_str(), &row).await.unwrap();
        }
        let chart = domain_chart(
            &stats_ks,
            &["a".into(), "b".into(), "c".into()],
            Range::LastDay,
        )
        .await
        .unwrap();
        assert_eq!(total(&chart), 5);
    }
}

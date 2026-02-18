pub use affinidi_webvh_common::DidStats;

use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use serde::{Deserialize, Serialize};

fn stats_key(mnemonic: &str) -> String {
    format!("stats:{mnemonic}")
}

/// Get stats for a mnemonic. Returns default stats if none exist yet.
pub async fn get_stats(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<DidStats, AppError> {
    Ok(stats_ks
        .get(stats_key(mnemonic))
        .await?
        .unwrap_or_default())
}

/// Increment the resolve counter and update last_resolved_at.
pub async fn increment_resolves(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    let mut stats = get_stats(stats_ks, mnemonic).await?;
    stats.total_resolves += 1;
    stats.last_resolved_at = Some(crate::auth::session::now_epoch());
    stats_ks.insert(stats_key(mnemonic), &stats).await
}

/// Increment the update counter and update last_updated_at.
pub async fn increment_updates(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    let mut stats = get_stats(stats_ks, mnemonic).await?;
    stats.total_updates += 1;
    stats.last_updated_at = Some(crate::auth::session::now_epoch());
    stats_ks.insert(stats_key(mnemonic), &stats).await
}

/// Delete stats for a mnemonic.
pub async fn delete_stats(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    stats_ks.remove(stats_key(mnemonic)).await
}

/// Aggregate stats across all DIDs.
pub async fn aggregate_stats(stats_ks: &KeyspaceHandle) -> Result<DidStats, AppError> {
    let raw = stats_ks.prefix_iter_raw("stats:").await?;
    let mut agg = DidStats::default();
    for (_key, value) in raw {
        if let Ok(s) = serde_json::from_slice::<DidStats>(&value) {
            agg.total_resolves += s.total_resolves;
            agg.total_updates += s.total_updates;
            agg.last_resolved_at = match (agg.last_resolved_at, s.last_resolved_at) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            agg.last_updated_at = match (agg.last_updated_at, s.last_updated_at) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
    }
    Ok(agg)
}

// ---------------------------------------------------------------------------
// Time-series tracking (5-minute buckets, 30-day retention)
// ---------------------------------------------------------------------------

const BUCKET_SECONDS: u64 = 300; // 5 minutes
const RETENTION_SECONDS: u64 = 30 * 24 * 3600; // 30 days
const GLOBAL_MNEMONIC: &str = "_all";

#[derive(Serialize, Deserialize, Default)]
pub struct BucketData {
    pub r: u64,
    pub u: u64,
}

#[derive(Serialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub resolves: u64,
    pub updates: u64,
}

#[derive(Deserialize, Clone, Copy)]
pub enum TimeRange {
    #[serde(rename = "1h")]
    OneHour,
    #[serde(rename = "24h")]
    TwentyFourHours,
    #[serde(rename = "7d")]
    SevenDays,
    #[serde(rename = "30d")]
    ThirtyDays,
}

impl Default for TimeRange {
    fn default() -> Self {
        Self::TwentyFourHours
    }
}

fn bucket_epoch(ts: u64) -> u64 {
    ts / BUCKET_SECONDS * BUCKET_SECONDS
}

fn ts_key(mnemonic: &str, epoch: u64) -> String {
    format!("ts:{mnemonic}:{epoch:010}")
}

fn ts_prefix(mnemonic: &str) -> String {
    format!("ts:{mnemonic}:")
}

async fn increment_bucket(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
    resolve: bool,
) -> Result<(), AppError> {
    let epoch = bucket_epoch(now_epoch());
    let key = ts_key(mnemonic, epoch);
    let mut bucket: BucketData = stats_ks.get(key.as_str()).await?.unwrap_or_default();
    if resolve {
        bucket.r += 1;
    } else {
        bucket.u += 1;
    }
    stats_ks.insert(key, &bucket).await
}

/// Record a resolve event in time-series buckets (per-DID + global).
pub async fn record_timeseries_resolve(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    increment_bucket(stats_ks, mnemonic, true).await?;
    increment_bucket(stats_ks, GLOBAL_MNEMONIC, true).await
}

/// Record an update event in time-series buckets (per-DID + global).
pub async fn record_timeseries_update(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    increment_bucket(stats_ks, mnemonic, false).await?;
    increment_bucket(stats_ks, GLOBAL_MNEMONIC, false).await
}

impl TimeRange {
    /// Duration of this range in seconds.
    fn duration_secs(self) -> u64 {
        match self {
            Self::OneHour => 3600,
            Self::TwentyFourHours => 24 * 3600,
            Self::SevenDays => 7 * 24 * 3600,
            Self::ThirtyDays => 30 * 24 * 3600,
        }
    }

    /// Aggregation step size in seconds for display.
    fn step_secs(self) -> u64 {
        match self {
            Self::OneHour => 300,        // 5min → 12 points
            Self::TwentyFourHours => 900, // 15min → 96 points
            Self::SevenDays => 3600,     // 1hr → 168 points
            Self::ThirtyDays => 14400,   // 4hr → 180 points
        }
    }
}

/// Query time-series data for a mnemonic (or `_all` for server-wide).
pub async fn query_timeseries(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
    range: TimeRange,
) -> Result<Vec<TimeSeriesPoint>, AppError> {
    let now = now_epoch();
    let cutoff = now.saturating_sub(range.duration_secs());
    let step = range.step_secs();

    let raw = stats_ks.prefix_iter_raw(ts_prefix(mnemonic)).await?;

    // Collect raw buckets within range
    let prefix_len = ts_prefix(mnemonic).len();
    let mut buckets: Vec<(u64, BucketData)> = Vec::new();
    for (key, value) in &raw {
        let key_str = std::str::from_utf8(key).unwrap_or_default();
        if let Ok(epoch) = key_str[prefix_len..].parse::<u64>() {
            if epoch >= cutoff {
                if let Ok(data) = serde_json::from_slice::<BucketData>(value) {
                    buckets.push((epoch, data));
                }
            }
        }
    }

    // Aggregate into display intervals
    let start = bucket_epoch(cutoff);
    let end = bucket_epoch(now);
    let num_steps = ((end - start) / step + 1) as usize;
    let mut points: Vec<TimeSeriesPoint> = Vec::with_capacity(num_steps);
    let mut ts = start;
    while ts <= end {
        points.push(TimeSeriesPoint {
            timestamp: ts,
            resolves: 0,
            updates: 0,
        });
        ts += step;
    }

    for (epoch, data) in &buckets {
        let idx = ((*epoch - start) / step) as usize;
        if idx < points.len() {
            points[idx].resolves += data.r;
            points[idx].updates += data.u;
        }
    }

    Ok(points)
}

/// Remove all time-series buckets older than 30 days.
pub async fn cleanup_old_timeseries(stats_ks: &KeyspaceHandle) -> Result<u64, AppError> {
    let cutoff = now_epoch().saturating_sub(RETENTION_SECONDS);
    let raw = stats_ks.prefix_iter_raw("ts:").await?;
    let mut removed = 0u64;

    for (key, _value) in &raw {
        let key_str = std::str::from_utf8(key).unwrap_or_default();
        // Key format: ts:{mnemonic}:{epoch:010}
        if let Some(epoch_str) = key_str.rsplit(':').next() {
            if let Ok(epoch) = epoch_str.parse::<u64>() {
                if epoch < cutoff {
                    stats_ks.remove(key.clone()).await?;
                    removed += 1;
                }
            }
        }
    }

    Ok(removed)
}

/// Delete all time-series buckets for a specific mnemonic.
pub async fn delete_timeseries(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    let raw = stats_ks.prefix_iter_raw(ts_prefix(mnemonic)).await?;
    for (key, _value) in &raw {
        stats_ks.remove(key.clone()).await?;
    }
    Ok(())
}

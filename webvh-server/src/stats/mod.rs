//! Stats collection and storage.
//!
//! Hot-path operations (`record_resolve`, `record_update`) accumulate in the
//! in-memory `StatsCollector`. A periodic flush task drains the collector and
//! writes deltas to the storage backend via `WriteBatch`, which works
//! identically across all backends (fjall, redis, dynamodb, firestore, cosmosdb).

pub use affinidi_webvh_common::DidStats;
pub use affinidi_webvh_common::server::stats_collector::{StatsAggregate, StatsCollector};

use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

fn stats_key(mnemonic: &str) -> String {
    format!("stats:{mnemonic}")
}

/// Get stats for a mnemonic from storage. Returns default stats if none exist yet.
pub async fn get_stats(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<DidStats, AppError> {
    Ok(stats_ks
        .get(stats_key(mnemonic))
        .await?
        .unwrap_or_default())
}

/// Delete stats for a mnemonic.
pub async fn delete_stats(
    stats_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    stats_ks.remove(stats_key(mnemonic)).await
}

/// Load the aggregate from storage (full scan). Used once at startup to seed
/// the in-memory collector.
pub async fn load_aggregate(stats_ks: &KeyspaceHandle) -> Result<DidStats, AppError> {
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

/// Flush accumulated deltas from the collector to the storage backend.
///
/// Uses `WriteBatch` for atomicity where the backend supports it.
/// For each dirty mnemonic, reads the current stored value, merges the delta,
/// and writes back. This is a read-modify-write but only contends with other
/// flush cycles (not with the hot path).
pub async fn flush_to_storage(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    store: &Store,
) -> Result<(), AppError> {
    // --- Flush per-DID counter deltas ---
    let deltas = collector.drain_deltas();
    if !deltas.is_empty() {
        let mut batch = store.batch();
        for d in &deltas {
            let mut stats: DidStats = stats_ks
                .get(stats_key(&d.mnemonic))
                .await?
                .unwrap_or_default();
            stats.total_resolves += d.resolve_delta;
            stats.total_updates += d.update_delta;
            if let Some(t) = d.last_resolved_at {
                stats.last_resolved_at = Some(
                    stats.last_resolved_at.map_or(t, |prev| prev.max(t)),
                );
            }
            if let Some(t) = d.last_updated_at {
                stats.last_updated_at = Some(
                    stats.last_updated_at.map_or(t, |prev| prev.max(t)),
                );
            }
            batch.insert(stats_ks, stats_key(&d.mnemonic), &stats)?;
        }
        batch.commit().await?;
        debug!(count = deltas.len(), "flushed stats deltas to storage");
    }

    // --- Flush time-series bucket deltas ---
    let ts_deltas = collector.drain_ts_deltas();
    if !ts_deltas.is_empty() {
        let mut batch = store.batch();
        for b in &ts_deltas {
            let key = ts_key(&b.mnemonic, b.epoch);
            let mut bucket: BucketData = stats_ks
                .get(key.as_str())
                .await?
                .unwrap_or_default();
            bucket.r += b.resolve_delta;
            bucket.u += b.update_delta;
            batch.insert(stats_ks, key, &bucket)?;
        }
        batch.commit().await?;
        debug!(count = ts_deltas.len(), "flushed time-series deltas to storage");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Time-series tracking (5-minute buckets, 30-day retention)
// ---------------------------------------------------------------------------

const BUCKET_SECONDS: u64 = 300; // 5 minutes
const RETENTION_SECONDS: u64 = 30 * 24 * 3600; // 30 days

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
        if let Some(epoch_str) = key_str.get(prefix_len..)
            && let Ok(epoch) = epoch_str.parse::<u64>()
            && epoch >= cutoff
            && let Ok(data) = serde_json::from_slice::<BucketData>(value)
        {
            buckets.push((epoch, data));
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

/// Push aggregate stats to the control plane via HTTP.
pub async fn sync_to_control(
    http: &reqwest::Client,
    control_url: &str,
    server_did: &str,
    collector: &StatsCollector,
) {
    let agg = collector.get_aggregate();
    let payload = affinidi_webvh_common::StatsSyncPayload {
        server_did: server_did.to_string(),
        total_dids: agg.total_dids,
        total_resolves: agg.total_resolves,
        total_updates: agg.total_updates,
        last_resolved_at: agg.last_resolved_at,
        last_updated_at: agg.last_updated_at,
    };

    let url = format!("{control_url}/api/control/stats");
    if let Err(e) = http.post(&url).json(&payload).send().await {
        warn!(error = %e, url = %url, "failed to sync stats to control plane");
    }
}

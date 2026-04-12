//! Periodic background tasks shared across service crates.
//!
//! These functions are designed to be called from a `tokio::select!` loop in
//! any service that maintains a stats collector and a store.

use serde::{Deserialize, Serialize};
use tracing::debug;

use super::auth::session::now_epoch;
use super::error::AppError;
use super::stats_collector::StatsCollector;
use super::store::{KeyspaceHandle, Store};
use crate::DidStats;

/// Compact per-bucket payload stored in the stats keyspace.
#[derive(Serialize, Deserialize, Default)]
struct BucketData {
    r: u64,
    u: u64,
}

/// Flush accumulated stats from the in-memory collector to the store.
///
/// Drains both per-DID deltas and time-series buckets, then writes everything
/// in a single atomic batch. This ensures consistency between per-DID stats
/// and time-series data, and eliminates per-delta I/O from the receive path.
pub async fn flush_stats_to_store(
    collector: &StatsCollector,
    stats_ks: &KeyspaceHandle,
    dids_ks: &KeyspaceHandle,
    store: &Store,
) -> Result<(), AppError> {
    let deltas = collector.drain_for_sync();
    let buckets = collector.drain_buckets();

    if deltas.is_empty() && buckets.is_empty() {
        return Ok(());
    }

    let mut batch = store.batch();

    // Merge per-DID stat deltas
    for d in &deltas {
        let key = format!("stats:{}", d.mnemonic);
        let mut stats: DidStats = stats_ks.get(key.as_str()).await?.unwrap_or_default();
        stats.total_resolves += d.resolve_delta;
        stats.total_updates += d.update_delta;
        if let Some(t) = d.last_resolved_at {
            stats.last_resolved_at = Some(stats.last_resolved_at.map_or(t, |prev| prev.max(t)));
        }
        if let Some(t) = d.last_updated_at {
            stats.last_updated_at = Some(stats.last_updated_at.map_or(t, |prev| prev.max(t)));
        }
        batch.insert(stats_ks, key, &stats)?;
    }

    // Merge time-series bucket deltas
    for b in &buckets {
        let key = format!("ts:{}:{:010}", b.mnemonic, b.epoch);
        let mut bucket: BucketData = stats_ks.get(key.as_str()).await?.unwrap_or_default();
        bucket.r += b.resolves;
        bucket.u += b.updates;
        batch.insert(stats_ks, key, &bucket)?;
    }

    // Single atomic commit for everything
    batch.commit().await?;

    // Update total DID count (periodic reconciliation)
    if let Ok(dids) = dids_ks.prefix_iter_raw("did:").await {
        collector.set_total_dids(dids.len() as u64);
    }

    if !deltas.is_empty() || !buckets.is_empty() {
        debug!(
            did_deltas = deltas.len(),
            ts_buckets = buckets.len(),
            "flushed stats to store"
        );
    }
    Ok(())
}

/// Remove time-series buckets older than 30 days.
pub async fn cleanup_old_buckets(stats_ks: &KeyspaceHandle) -> Result<u64, AppError> {
    const RETENTION_SECS: u64 = 30 * 24 * 3600;
    let cutoff = now_epoch().saturating_sub(RETENTION_SECS);
    let raw = stats_ks.prefix_iter_raw("ts:").await?;
    let mut removed = 0u64;

    for (key, _) in &raw {
        let key_str = std::str::from_utf8(key).unwrap_or_default();
        // Key format: ts:{mnemonic}:{epoch:010}
        if let Some(epoch_str) = key_str.rsplit(':').next()
            && let Ok(epoch) = epoch_str.parse::<u64>()
            && epoch < cutoff
        {
            stats_ks.remove(key.clone()).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

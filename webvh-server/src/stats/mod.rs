pub use affinidi_webvh_common::DidStats;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

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

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Statistics for a hosted DID.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DidStats {
    pub total_resolves: u64,
    pub total_updates: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
}

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

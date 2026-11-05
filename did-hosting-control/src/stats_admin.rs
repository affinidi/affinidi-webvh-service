//! A DID's statistics override, and clearing its statistics on delete.
//!
//! The override ([`StatsResolution`]) lives at `statspin:{mnemonic}` in the
//! stats keyspace, apart from the `stats:` row the flush rewrites, so setting
//! it never races a flush. It is loaded into the collector at startup
//! (`seed_from_store`) and updated there when set, so the flush never reads
//! it. Another control-plane replica sees a change at its next start.
//!
//! **Who may set what.** `fine` costs writes and bypasses the cap on
//! automatic promotion, so only an admin may set it. A DID's owner may set
//! `auto`, `coarse` or `off`: less detail about their own DID, never more.

use did_hosting_common::server::stats_tiers::{
    StatsResolution, StoredDidStats, Tier, TierReason, pin_key, stats_key,
};
use tracing::{info, warn};

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// A DID's statistics tier as the control plane sees it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsTierInfo {
    /// The override, `auto` when none is set.
    pub resolution: StatsResolution,
    /// The tier that applies.
    pub tier: Tier,
    /// Why.
    pub reason: TierReason,
}

/// Set a DID's statistics override; returns the one it replaces.
///
/// The caller must own the DID or be an admin, and only an admin may set
/// [`StatsResolution::Fine`].
pub async fn set_stats_resolution(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    resolution: StatsResolution,
) -> Result<StatsResolution, AppError> {
    // Ownership (or admin), as every other per-DID operation.
    crate::did_ops::get_did_info(auth, state, mnemonic).await?;
    if resolution == StatsResolution::Fine && auth.role != Role::Admin {
        return Err(AppError::Forbidden(
            "only an admin can give a DID 5-minute statistics".into(),
        ));
    }
    let previous = state.stats_collector.tiers().pin(mnemonic);
    let key = pin_key(mnemonic);
    if resolution == StatsResolution::Auto {
        state.stats_ks.remove(key).await?;
    } else {
        state.stats_ks.insert(key.as_str(), &resolution).await?;
    }
    state.stats_collector.tiers().set_pin(mnemonic, resolution);
    info!(
        caller = %auth.did,
        mnemonic,
        from = previous.as_str(),
        to = resolution.as_str(),
        "statistics resolution set"
    );
    Ok(previous)
}

/// A DID's statistics tier: its override, and the tier its row last
/// recorded.
pub async fn stats_tier(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<StatsTierInfo, AppError> {
    crate::did_ops::get_did_info(auth, state, mnemonic).await?;
    let row: Option<StoredDidStats> = state.stats_ks.get(stats_key(mnemonic)).await?;
    let tiers = state.stats_collector.tiers();
    let (tier, reason) = tiers.tier_of(mnemonic, row.as_ref().and_then(|r| r.coarse.as_ref()));
    Ok(StatsTierInfo {
        resolution: tiers.pin(mnemonic),
        tier,
        reason,
    })
}

/// A DID's totals as they stand: the stored row plus the counts the
/// collector has not written yet. Rows are written once per closed 5-minute
/// bucket, so the stored totals alone can trail by a few minutes.
pub async fn live_did_stats(
    state: &AppState,
    mnemonic: &str,
) -> Result<did_hosting_common::DidStats, AppError> {
    let mut stats: did_hosting_common::DidStats = state
        .stats_ks
        .get(stats_key(mnemonic))
        .await?
        .unwrap_or_default();
    if let Some(d) = state.stats_collector.pending_for(mnemonic) {
        stats.total_resolves += d.resolve_delta;
        stats.total_updates += d.update_delta;
        stats.last_resolved_at = stats.last_resolved_at.max(d.last_resolved_at);
        stats.last_updated_at = stats.last_updated_at.max(d.last_updated_at);
    }
    Ok(stats)
}

/// Delete a DID's statistics: its row, its override, and its fine ring when
/// it had one. Best effort, after the DID itself is gone: a failure leaves
/// rows that nothing reads, and is logged.
pub async fn delete_did_stats(state: &AppState, mnemonic: &str) {
    if let Err(e) = did_hosting_common::server::stats_collector::delete_did_stats(
        &state.stats_collector,
        &state.stats_ks,
        &state.timeseries_ks,
        mnemonic,
    )
    .await
    {
        warn!(mnemonic, error = %e, "could not delete a deleted DID's statistics rows");
    }
}

#[cfg(test)]
#[path = "stats_admin_tests.rs"]
mod tests;

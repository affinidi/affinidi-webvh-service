use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;

use tracing::info;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;
use crate::stats::{DidStats, aggregate_stats, get_stats};

/// GET /stats/{mnemonic}
pub async fn get_did_stats(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<DidStats>, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    validate_mnemonic(mnemonic)?;

    // Verify the DID exists
    let key = format!("did:{mnemonic}");
    if !state.dids_ks.contains_key(key).await? {
        return Err(AppError::NotFound(format!("DID not found: {mnemonic}")));
    }

    let stats = get_stats(&state.stats_ks, mnemonic).await?;
    info!(did = %auth.did, mnemonic = %mnemonic, "DID stats retrieved");
    Ok(Json(stats))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatsResponse {
    pub total_dids: u64,
    pub total_resolves: u64,
    pub total_updates: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
}

/// GET /stats — aggregate stats across all DIDs
pub async fn get_server_stats(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ServerStatsResponse>, AppError> {
    let dids = state.dids_ks.prefix_iter_raw("did:").await?;
    let total_dids = dids.len() as u64;
    let agg = aggregate_stats(&state.stats_ks).await?;

    info!(did = %auth.did, total_dids, "server stats retrieved");

    Ok(Json(ServerStatsResponse {
        total_dids,
        total_resolves: agg.total_resolves,
        total_updates: agg.total_updates,
        last_resolved_at: agg.last_resolved_at,
        last_updated_at: agg.last_updated_at,
    }))
}

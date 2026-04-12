use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;

use tracing::info;

use affinidi_webvh_common::DidStats;
use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;

/// GET /stats/{mnemonic} — per-DID stats (in-memory only on server, returns default).
///
/// Authoritative per-DID stats live on the control plane. The server returns
/// what it has in-memory (which resets on restart).
pub async fn get_did_stats(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<DidStats>, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    validate_mnemonic(mnemonic)?;

    let key = format!("did:{mnemonic}");
    if !state.dids_ks.contains_key(key).await? {
        return Err(AppError::NotFound(format!("DID not found: {mnemonic}")));
    }

    info!(did = %auth.did, mnemonic = %mnemonic, "DID stats retrieved");
    Ok(Json(DidStats::default()))
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

/// GET /stats — instant aggregate from in-memory collector.
pub async fn get_server_stats(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ServerStatsResponse>, AppError> {
    let resp = if let Some(ref collector) = state.stats_collector {
        let agg = collector.get_aggregate();
        ServerStatsResponse {
            total_dids: agg.total_dids,
            total_resolves: agg.total_resolves,
            total_updates: agg.total_updates,
            last_resolved_at: agg.last_resolved_at,
            last_updated_at: agg.last_updated_at,
        }
    } else {
        let dids = state.dids_ks.prefix_iter_raw("did:").await?;
        ServerStatsResponse {
            total_dids: dids.len() as u64,
            total_resolves: 0,
            total_updates: 0,
            last_resolved_at: None,
            last_updated_at: None,
        }
    };

    info!(did = %auth.did, total_dids = resp.total_dids, "server stats retrieved");
    Ok(Json(resp))
}

//! DID management API routes for the control plane.
//!
//! These routes match what the UI expects (from `webvh-ui/lib/api.ts`).

use crate::auth::AuthClaims;
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;
use crate::server_push;
use affinidi_webvh_common::did_ops::LogMetadata;
use affinidi_webvh_common::{CheckNameResponse, DidListEntry, RequestUriResponse};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Strip leading slash from path-extracted mnemonics.
fn clean_mnemonic(m: &str) -> &str {
    m.trim_start_matches('/')
}

// ---------- POST /api/dids/check ----------

#[derive(Debug, Deserialize)]
pub struct CheckNameRequest {
    pub path: String,
}

pub async fn check_name(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<CheckNameRequest>,
) -> Result<Json<CheckNameResponse>, AppError> {
    let result = did_ops::check_name(&state, &req.path).await?;
    info!(did = %auth.did, path = %req.path, available = result.available, "name availability checked");
    Ok(Json(result))
}

// ---------- POST /api/dids ----------

#[derive(Debug, Deserialize, Default)]
pub struct RequestUriRequest {
    pub path: Option<String>,
}

pub async fn request_uri(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: Option<Json<RequestUriRequest>>,
) -> Result<(StatusCode, Json<RequestUriResponse>), AppError> {
    let path = body.and_then(|b| b.0.path);
    let result = did_ops::create_did(&auth, &state, path.as_deref()).await?;

    Ok((StatusCode::CREATED, Json(result)))
}

// ---------- GET /api/dids/{mnemonic} ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDetailResponse {
    pub mnemonic: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
    pub did_id: Option<String>,
    pub owner: String,
    pub disabled: bool,
    pub log: Option<LogMetadata>,
}

pub async fn get_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<DidDetailResponse>, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let (record, log_metadata) = did_ops::get_did_info(&auth, &state, mnemonic).await?;

    Ok(Json(DidDetailResponse {
        mnemonic: record.mnemonic,
        created_at: record.created_at,
        updated_at: record.updated_at,
        version_count: record.version_count,
        did_id: record.did_id,
        owner: record.owner,
        disabled: record.disabled,
        log: log_metadata,
    }))
}

// ---------- GET /api/log/{mnemonic} ----------

pub async fn get_did_log(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<Vec<affinidi_webvh_common::did_ops::LogEntryInfo>>, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let entries = did_ops::get_did_log(&auth, &state, mnemonic).await?;
    Ok(Json(entries))
}

// ---------- PUT /api/dids/{mnemonic} ----------

pub async fn upload_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    body: String,
) -> Result<StatusCode, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    did_ops::publish_did(&auth, &state, mnemonic, &body).await?;
    server_push::notify_servers_did(&state, mnemonic.to_string());
    Ok(StatusCode::NO_CONTENT)
}

// ---------- PUT /api/witness/{mnemonic} ----------

pub async fn upload_witness(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    body: String,
) -> Result<StatusCode, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    did_ops::upload_witness(&auth, &state, mnemonic, &body).await?;
    server_push::notify_servers_did(&state, mnemonic.to_string());
    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /api/dids/{mnemonic} ----------

pub async fn delete_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    did_ops::delete_did(&auth, &state, mnemonic).await?;
    server_push::notify_servers_delete(&state, mnemonic.to_string());
    Ok(StatusCode::NO_CONTENT)
}

// ---------- PUT /api/disable/{mnemonic} ----------

pub async fn disable_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    did_ops::set_did_disabled(&auth, &state, mnemonic, true).await?;
    server_push::notify_servers_did(&state, mnemonic.to_string());
    Ok(StatusCode::NO_CONTENT)
}

// ---------- PUT /api/enable/{mnemonic} ----------

pub async fn enable_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    did_ops::set_did_disabled(&auth, &state, mnemonic, false).await?;
    server_push::notify_servers_did(&state, mnemonic.to_string());
    Ok(StatusCode::NO_CONTENT)
}

// ---------- POST /api/rollback/{mnemonic} ----------

pub async fn rollback_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<DidDetailResponse>, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let (record, log_metadata) = did_ops::rollback_did(&auth, &state, mnemonic).await?;

    server_push::notify_servers_did(&state, mnemonic.to_string());

    Ok(Json(DidDetailResponse {
        mnemonic: record.mnemonic,
        created_at: record.created_at,
        updated_at: record.updated_at,
        version_count: record.version_count,
        did_id: record.did_id,
        owner: record.owner,
        disabled: record.disabled,
        log: log_metadata,
    }))
}

// ---------- GET /api/raw/{mnemonic} ----------

pub async fn get_raw_log(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<(StatusCode, [(axum::http::HeaderName, &'static str); 1], String), AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let content = did_ops::get_raw_log(&auth, &state, mnemonic).await?;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        content,
    ))
}

// ---------- GET /api/dids ----------

#[derive(Debug, Deserialize)]
pub struct ListDidsQuery {
    pub owner: Option<String>,
}

pub async fn list_dids(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListDidsQuery>,
) -> Result<Json<Vec<DidListEntry>>, AppError> {
    let entries = did_ops::list_dids(&auth, &state, query.owner.as_deref()).await?;
    Ok(Json(entries))
}

// ---------- GET /api/stats ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatsResponse {
    pub total_dids: u64,
    pub total_resolves: u64,
    pub total_updates: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
}

/// GET /api/stats — aggregates stats from all connected server instances.
///
/// If no servers have synced stats yet, falls back to counting local DID records.
pub async fn get_server_stats(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ServerStatsResponse>, AppError> {
    let mut total_dids = 0u64;
    let mut total_resolves = 0u64;
    let mut total_updates = 0u64;
    let mut last_resolved_at: Option<u64> = None;
    let mut last_updated_at: Option<u64> = None;
    let mut has_server_stats = false;

    // Aggregate across all server instances that have synced stats
    if let Ok(map) = state.server_stats.read() {
        for payload in map.values() {
            has_server_stats = true;
            total_dids += payload.total_dids;
            total_resolves += payload.total_resolves;
            total_updates += payload.total_updates;
            last_resolved_at = match (last_resolved_at, payload.last_resolved_at) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            last_updated_at = match (last_updated_at, payload.last_updated_at) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
    }

    // Fallback: if no servers have synced, count local DID records
    if !has_server_stats {
        let raw = state.dids_ks.prefix_iter_raw("did:").await?;
        total_dids = raw.len() as u64;
    }

    Ok(Json(ServerStatsResponse {
        total_dids,
        total_resolves,
        total_updates,
        last_resolved_at,
        last_updated_at,
    }))
}

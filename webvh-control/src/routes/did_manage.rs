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
use tracing::{debug, info};

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

// ---------- GET /api/timeseries ----------

#[derive(Debug, Serialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub resolves: u64,
    pub updates: u64,
}

#[derive(Debug, Deserialize)]
pub struct TimeseriesQuery {
    #[serde(default = "default_range")]
    pub range: String,
}

fn default_range() -> String {
    "24h".to_string()
}

/// GET /api/timeseries — returns empty time-series data.
///
/// The control plane doesn't serve DIDs directly and has no resolve counters.
/// Time-series data lives on each webvh-server instance. This endpoint exists
/// so the UI doesn't get an HTML fallback response.
pub async fn get_server_timeseries(
    _auth: AuthClaims,
    Query(params): Query<TimeseriesQuery>,
) -> Json<Vec<TimeSeriesPoint>> {
    debug!(range = %params.range, "timeseries requested (control plane — no data)");
    Json(Vec::new())
}

// ---------- GET /api/config ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponse {
    pub server_did: Option<String>,
    pub public_url: Option<String>,
    pub features: FeaturesResponse,
    pub server: ServerResponse,
    pub log: LogResponse,
    pub store: StoreResponse,
    pub auth: AuthResponse,
    pub limits: LimitsResponse,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeaturesResponse {
    pub didcomm: bool,
    pub rest_api: bool,
}

#[derive(Debug, Serialize)]
pub struct ServerResponse {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Serialize)]
pub struct LogResponse {
    pub level: String,
    pub format: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreResponse {
    pub data_dir: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub access_token_expiry: u64,
    pub refresh_token_expiry: u64,
    pub challenge_ttl: u64,
    pub session_cleanup_interval: u64,
    pub passkey_enrollment_ttl: u64,
    pub cleanup_ttl_minutes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitsResponse {
    pub upload_body_limit: u64,
    pub default_max_total_size: u64,
    pub default_max_did_count: u64,
}

/// GET /api/config — return server configuration (non-sensitive fields only).
pub async fn get_config(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Json<ConfigResponse> {
    let c = &state.config;
    Json(ConfigResponse {
        server_did: c.server_did.clone(),
        public_url: c.public_url.clone(),
        features: FeaturesResponse {
            didcomm: c.features.didcomm,
            rest_api: c.features.rest_api,
        },
        server: ServerResponse {
            host: c.server.host.clone(),
            port: c.server.port,
        },
        log: LogResponse {
            level: c.log.level.clone(),
            format: format!("{:?}", c.log.format).to_lowercase(),
        },
        store: StoreResponse {
            data_dir: c.store.data_dir.display().to_string(),
        },
        auth: AuthResponse {
            access_token_expiry: c.auth.access_token_expiry,
            refresh_token_expiry: c.auth.refresh_token_expiry,
            challenge_ttl: c.auth.challenge_ttl,
            session_cleanup_interval: c.auth.session_cleanup_interval,
            passkey_enrollment_ttl: c.auth.passkey_enrollment_ttl,
            cleanup_ttl_minutes: c.auth.cleanup_ttl_minutes,
        },
        limits: LimitsResponse {
            upload_body_limit: 10 * 1024 * 1024, // matches DefaultBodyLimit in routes
            default_max_total_size: 0,
            default_max_did_count: 0,
        },
    })
}

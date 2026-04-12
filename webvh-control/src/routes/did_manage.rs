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
) -> Result<
    (
        StatusCode,
        [(axum::http::HeaderName, &'static str); 1],
        String,
    ),
    AppError,
> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let content = did_ops::get_raw_log(&auth, &state, mnemonic).await?;
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        content,
    ))
}

// ---------- GET /api/dids ----------

#[derive(Debug, Deserialize)]
pub struct ListDidsQuery {
    pub owner: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn list_dids(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListDidsQuery>,
) -> Result<Json<Vec<DidListEntry>>, AppError> {
    let entries = did_ops::list_dids(
        &auth,
        &state,
        query.owner.as_deref(),
        query.limit,
        query.offset,
    )
    .await?;
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

/// GET /api/stats — O(1) aggregate from in-memory atomic counters.
pub async fn get_server_stats(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ServerStatsResponse>, AppError> {
    let agg = state.stats_collector.get_aggregate();
    Ok(Json(ServerStatsResponse {
        total_dids: agg.total_dids,
        total_resolves: agg.total_resolves,
        total_updates: agg.total_updates,
        last_resolved_at: agg.last_resolved_at,
        last_updated_at: agg.last_updated_at,
    }))
}

/// GET /api/stats/{mnemonic} — per-DID stats from persistent store.
pub async fn get_did_stats(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<affinidi_webvh_common::DidStats>, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    let key = format!("stats:{mnemonic}");
    let stats: affinidi_webvh_common::DidStats = state.stats_ks.get(key).await?.unwrap_or_default();
    Ok(Json(stats))
}

// ---------- GET /api/timeseries ----------

#[derive(Debug, Serialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub resolves: u64,
    pub updates: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TimeseriesQuery {
    #[serde(default = "default_range")]
    pub range: String,
}

fn default_range() -> String {
    "24h".to_string()
}

/// GET /api/timeseries — server-wide time-series data.
pub async fn get_server_timeseries(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Query(params): Query<TimeseriesQuery>,
) -> Result<Json<Vec<TimeSeriesPoint>>, AppError> {
    let points = query_timeseries(&state.stats_ks, "_all", &params.range).await?;
    Ok(Json(points))
}

/// GET /api/timeseries/{mnemonic} — per-DID time-series data.
pub async fn get_did_timeseries(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    Query(params): Query<TimeseriesQuery>,
) -> Result<Json<Vec<TimeSeriesPoint>>, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    let points = query_timeseries(&state.stats_ks, mnemonic, &params.range).await?;
    Ok(Json(points))
}

/// Query time-series buckets for a given mnemonic and range.
async fn query_timeseries(
    stats_ks: &affinidi_webvh_common::server::store::KeyspaceHandle,
    mnemonic: &str,
    range: &str,
) -> Result<Vec<TimeSeriesPoint>, AppError> {
    use serde::Deserialize;

    #[derive(Deserialize, Default)]
    struct BucketData {
        r: u64,
        u: u64,
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (duration, step) = match range {
        "1h" => (3600u64, 300u64),
        "7d" => (7 * 24 * 3600, 3600),
        "30d" => (30 * 24 * 3600, 14400),
        _ => (24 * 3600, 900), // default 24h
    };

    let cutoff = now.saturating_sub(duration);
    let start = cutoff / 300 * 300; // align to 5-min bucket
    let end = now / 300 * 300;

    let prefix = format!("ts:{mnemonic}:");
    let raw = stats_ks.prefix_iter_raw(prefix.as_str()).await?;

    // Collect raw buckets within range
    let prefix_len = prefix.len();
    let mut bucket_map: std::collections::HashMap<u64, (u64, u64)> =
        std::collections::HashMap::new();
    for (key, value) in &raw {
        let key_str = std::str::from_utf8(key).unwrap_or_default();
        if let Some(epoch_str) = key_str.get(prefix_len..)
            && let Ok(epoch) = epoch_str.parse::<u64>()
            && epoch >= cutoff
            && let Ok(data) = serde_json::from_slice::<BucketData>(value)
        {
            let entry = bucket_map.entry(epoch).or_insert((0, 0));
            entry.0 += data.r;
            entry.1 += data.u;
        }
    }

    // Build aggregated display points
    let mut points = Vec::new();
    let mut ts = start;
    while ts <= end {
        let mut resolves = 0u64;
        let mut updates = 0u64;
        // Aggregate all 5-min buckets within this step
        let mut bucket_ts = ts;
        while bucket_ts < ts + step && bucket_ts <= end {
            if let Some(&(r, u)) = bucket_map.get(&bucket_ts) {
                resolves += r;
                updates += u;
            }
            bucket_ts += 300;
        }
        points.push(TimeSeriesPoint {
            timestamp: ts,
            resolves,
            updates,
        });
        ts += step;
    }

    Ok(points)
}

// ---------- GET /api/config ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponse {
    /// Identity
    pub control_did: Option<String>,
    pub mediator_did: Option<String>,
    pub public_url: Option<String>,
    pub did_hosting_url: Option<String>,
    /// Connectivity
    pub didcomm_enabled: bool,
    pub rest_api_enabled: bool,
    pub listen_address: String,
    /// VTA
    pub vta_url: Option<String>,
    pub vta_did: Option<String>,
    /// Registry
    pub health_check_interval_secs: u64,
    pub configured_instances: u64,
    /// Auth
    pub access_token_expiry: u64,
    pub refresh_token_expiry: u64,
    pub passkey_enrollment_ttl: u64,
    /// Deployment
    pub deployment_mode: String,
    /// Storage & Logging
    pub data_dir: String,
    pub log_level: String,
    pub log_format: String,
}

/// GET /api/config — return control plane configuration (non-sensitive fields only).
pub async fn get_config(_auth: AuthClaims, State(state): State<AppState>) -> Json<ConfigResponse> {
    let c = &state.config;
    Json(ConfigResponse {
        control_did: c.server_did.clone(),
        mediator_did: c.mediator_did.clone(),
        public_url: c.public_url.clone(),
        did_hosting_url: c.did_hosting_url.clone(),
        didcomm_enabled: c.features.didcomm,
        rest_api_enabled: c.features.rest_api,
        deployment_mode: c.features.deployment_mode.clone(),
        listen_address: format!("{}:{}", c.server.host, c.server.port),
        vta_url: c.vta.url.clone(),
        vta_did: c.vta.did.clone(),
        health_check_interval_secs: c.registry.health_check_interval,
        configured_instances: c.registry.instances.len() as u64,
        access_token_expiry: c.auth.access_token_expiry,
        refresh_token_expiry: c.auth.refresh_token_expiry,
        passkey_enrollment_ttl: c.auth.passkey_enrollment_ttl,
        data_dir: c.store.data_dir.display().to_string(),
        log_level: c.log.level.clone(),
        log_format: format!("{:?}", c.log.format).to_lowercase(),
    })
}

// ---------- GET /api/services/overview ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceOverviewResponse {
    /// Control plane metadata
    pub control: ControlInfo,
    /// All registered service instances with enriched stats
    pub services: Vec<ServiceInfo>,
    /// Aggregate stats across all servers
    pub aggregate: AggregateStats,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlInfo {
    pub version: String,
    pub server_did: Option<String>,
    pub public_url: Option<String>,
    pub didcomm_enabled: bool,
    pub total_local_dids: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub instance_id: String,
    pub service_type: String,
    pub label: Option<String>,
    pub url: String,
    pub status: String,
    pub last_health_check: Option<u64>,
    pub registered_at: u64,
    pub did: Option<String>,
    /// Stats from the server's stats sync (None if this service hasn't synced stats)
    pub stats: Option<ServiceStats>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStats {
    pub total_dids: u64,
    pub total_resolves: u64,
    pub total_updates: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateStats {
    pub total_services: u64,
    pub active_services: u64,
    pub degraded_services: u64,
    pub unreachable_services: u64,
    pub total_dids: u64,
    pub total_resolves: u64,
    pub total_updates: u64,
}

/// GET /api/services/overview — full service topology with health and stats.
pub async fn get_services_overview(
    _auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<ServiceOverviewResponse>, AppError> {
    use crate::registry;

    let instances = registry::list_instances(&state.registry_ks).await?;

    // Get aggregate stats from the collector (O(1), lock-free)
    let agg = state.stats_collector.get_aggregate();

    let mut active = 0u64;
    let mut degraded = 0u64;
    let mut unreachable = 0u64;

    let mut services: Vec<ServiceInfo> = Vec::with_capacity(instances.len());

    for inst in &instances {
        match inst.status {
            registry::ServiceStatus::Active => active += 1,
            registry::ServiceStatus::Degraded => degraded += 1,
            registry::ServiceStatus::Unreachable => unreachable += 1,
        }

        let service_did = inst
            .metadata
            .get("did")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Per-service stats not available individually in the new model
        let stats: Option<ServiceStats> = None;

        let status_str = format!("{:?}", inst.status).to_lowercase();

        services.push(ServiceInfo {
            instance_id: inst.instance_id.clone(),
            service_type: format!("{:?}", inst.service_type).to_lowercase(),
            label: inst.label.clone(),
            url: inst.url.clone(),
            status: status_str,
            last_health_check: inst.last_health_check,
            registered_at: inst.registered_at,
            did: service_did,
            stats,
        });
    }

    // Count local DIDs on control plane
    let local_dids = state.dids_ks.prefix_iter_raw("did:").await?.len() as u64;

    Ok(Json(ServiceOverviewResponse {
        control: ControlInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            server_did: state.config.server_did.clone(),
            public_url: state.config.public_url.clone(),
            didcomm_enabled: state.config.features.didcomm,
            total_local_dids: local_dids,
        },
        aggregate: AggregateStats {
            total_services: services.len() as u64,
            active_services: active,
            degraded_services: degraded,
            unreachable_services: unreachable,
            total_dids: agg.total_dids.max(local_dids),
            total_resolves: agg.total_resolves,
            total_updates: agg.total_updates,
        },
        services,
    }))
}

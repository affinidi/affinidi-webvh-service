//! DID management API routes for the control plane.
//!
//! These routes match what the UI expects (from `did-hosting-ui/lib/api.ts`).

use crate::auth::{AdminAuth, AuthClaims};
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;
use crate::server_push;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use did_hosting_common::did_ops::LogMetadata;
use did_hosting_common::{
    CheckNameResponse, DidListEntry, DidRegisterRequest, DidRegisterResponse, RequestUriResponse,
};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Strip leading slash from path-extracted mnemonics.
fn clean_mnemonic(m: &str) -> &str {
    m.trim_start_matches('/')
}

/// The optional `?domain=` query the VTA sends on publish/delete as a
/// cross-tenant safety check (a DID's host IS its domain). `did_ops`
/// cross-checks it against the DID/slot and rejects a mismatch with
/// `did-management:unknown_domain`.
#[derive(Debug, Default, Deserialize)]
pub struct DomainQuery {
    #[serde(default)]
    pub domain: Option<String>,
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
    /// When true and `path` already exists, replaces the existing DID slot
    /// (caller must be admin or current owner of that path).
    #[serde(default)]
    pub force: bool,
    /// Optional explicit domain — same T34 resolution chain as
    /// `register_did_atomic`: explicit → caller's ACL default → system
    /// default → reject. Persisted on the new record so the multi-domain
    /// filters in the UI see it on the very first list call (without
    /// waiting for the M-01 sweep).
    pub domain: Option<String>,
}

pub async fn request_uri(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: Option<Json<RequestUriRequest>>,
) -> Result<(StatusCode, Json<RequestUriResponse>), AppError> {
    let (path, force, request_domain) = match body {
        Some(Json(b)) => (b.path, b.force, b.domain),
        None => (None, false, None),
    };
    // T34 domain resolution mirrors `register_did_atomic`. The reservation
    // path historically left `record.domain` empty and relied on the M-01
    // migration to backfill; that left the per-domain UI filter unable to
    // surface a freshly-created DID until the next sweep. Resolve up front
    // and persist on the record. When resolution fails (no domains
    // configured / no default / `Allowed([])` caller with no explicit),
    // proceed with `None`; publish-time backfill from `did_id` host
    // will tag the record. This preserves the legacy reservation
    // semantics for un-domained installs.
    let acl_scope =
        match did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did).await? {
            Some(e) => e.domains,
            None => did_hosting_common::server::domain::DomainScope::All,
        };
    let system_default = did_hosting_common::server::domain::get_default_domain(&state.store)
        .await
        .ok()
        .flatten();
    let resolved_domain = did_hosting_common::server::domain::resolve_request_domain(
        request_domain.as_deref(),
        &acl_scope,
        system_default.as_deref(),
    )
    .ok();
    let result = did_ops::create_did(
        &auth,
        &state,
        path.as_deref(),
        force,
        resolved_domain.as_deref(),
    )
    .await?;

    // No `notify_servers_delete` on force-replace: `create_did` only
    // reserves the mnemonic, so a delete fan-out would make downstream
    // resolvers serve 404 until the caller's follow-up `publish_did`
    // arrives. Atomic ownership-takeover with no resolvability gap is
    // `POST /api/dids/register` (`register_did_atomic`).

    Ok((StatusCode::CREATED, Json(result)))
}

// ---------- POST /api/dids/register ----------

/// Atomic claim-and-publish — see [`did_ops::register_did_atomic`] for the
/// full contract. The handler returns 200 (not 201) because the operation
/// is intentionally idempotent for the slot's owner; second-and-subsequent
/// calls just bump `version_count` and replace content.
pub async fn register_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<DidRegisterRequest>,
) -> Result<Json<DidRegisterResponse>, AppError> {
    // T26: resolve multi-shape body (legacy `did_log` OR new
    // `did_data` + `method`) into `(method, payload_bytes)`.
    let (method, payload) = req.resolve().map_err(AppError::Validation)?;
    if method != "webvh" {
        // Method-aware register paths (did:web etc.) land with T26's
        // follow-up plumbing through the `DidMethod` trait. For now,
        // refuse explicitly so callers don't see a webvh-validation
        // error against a did:web payload.
        return Err(AppError::Validation(format!(
            "registration via REST is currently webvh-only; received method = '{method}'. \
             Use PUT /api/dids/{{mnemonic}} with the appropriate Content-Type once \
             T26 follow-up wires per-method storage.",
        )));
    }
    let did_log = std::str::from_utf8(&payload)
        .map_err(|e| AppError::Validation(format!("webvh `did_data` is not valid UTF-8: {e}")))?;

    // T34: domain resolution — explicit request → ACL default →
    // system default → reject. The resolved domain is recorded for
    // audit clarity; the host-equality safety check against the
    // embedded `did_id` runs inside `register_did_atomic` via
    // `check_did_host_safety` (T20b), so a mismatch between the
    // resolved `domain` and the DID's host is caught downstream.
    let acl_scope =
        match did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did).await? {
            Some(e) => e.domains,
            None => did_hosting_common::server::domain::DomainScope::All,
        };
    let system_default = did_hosting_common::server::domain::get_default_domain(&state.store)
        .await
        .ok()
        .flatten();
    let resolved_domain = did_hosting_common::server::domain::resolve_request_domain(
        req.domain.as_deref(),
        &acl_scope,
        system_default.as_deref(),
    )
    .map_err(|e| AppError::Validation(e.to_string()))?;
    info!(
        did = %auth.did,
        path = %req.path,
        resolved_domain = %resolved_domain,
        explicit = req.domain.is_some(),
        "domain resolved for atomic register"
    );

    let result = did_ops::register_did_atomic(&auth, &state, &req.path, did_log, req.force).await?;

    // Push the (potentially replaced) log to downstream servers so their
    // resolvers see the new content right away. Same as `upload_did`.
    server_push::notify_servers_did(&state, result.mnemonic.clone());

    info!(
        did = %auth.did,
        path = %result.mnemonic,
        force = req.force,
        "DID atomically registered via REST"
    );

    Ok(Json(DidRegisterResponse {
        mnemonic: result.mnemonic,
        did_url: result.did_url,
    }))
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Agent names that currently resolve to this DID, local part only.
    /// Same contract as `DidListEntry::agent_names` — enabled entries only,
    /// omitted when there are none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_names: Vec<String>,
}

pub async fn get_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<DidDetailResponse>, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let (record, log_metadata) = did_ops::get_did_info(&auth, &state, mnemonic).await?;
    let agent_names = did_ops::resolvable_agent_names(&record);

    Ok(Json(DidDetailResponse {
        mnemonic: record.mnemonic,
        created_at: record.created_at,
        updated_at: record.updated_at,
        version_count: record.version_count,
        did_id: record.did_id,
        owner: record.owner,
        disabled: record.disabled,
        log: log_metadata,
        method: (!record.method.is_empty()).then(|| record.method.clone()),
        domain: (!record.domain.is_empty()).then(|| record.domain.clone()),
        agent_names,
    }))
}

// ---------- GET /api/log/{mnemonic} ----------

pub async fn get_did_log(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<Vec<did_hosting_common::did_ops::LogEntryInfo>>, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let entries = did_ops::get_did_log(&auth, &state, mnemonic).await?;
    Ok(Json(entries))
}

// ---------- PUT /api/dids/{mnemonic} ----------

/// `PUT /api/dids/{mnemonic}` — publish a new version of a hosted DID.
///
/// T26 content-type discriminator:
/// - `application/jsonl` (or absent / `application/jsonl+json`) →
///   webvh (the historical default; body is the did.jsonl text).
/// - `application/did+json` → did:web (single document upload). Not
///   yet wired through `publish_did`; returns 501 with a clear
///   message until the per-method publish path lands.
/// - Any other content-type → 415 with the same enumeration.
pub async fn upload_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    Query(dq): Query<DomainQuery>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Result<StatusCode, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or(s).trim().to_ascii_lowercase());

    let method = match content_type.as_deref() {
        // Default + explicit webvh content types.
        None | Some("application/jsonl") | Some("application/jsonl+json") | Some("text/plain") => {
            "webvh"
        }
        Some("application/did+json") | Some("application/json") => "web",
        Some(other) => {
            return Err(AppError::Validation(format!(
                "unsupported Content-Type '{other}' on PUT /api/dids/{{mnemonic}}; \
                 use 'application/jsonl' (webvh) or 'application/did+json' (web)",
            )));
        }
    };

    if method != "webvh" {
        return Err(AppError::Validation(format!(
            "method '{method}' publish via PUT not yet wired; T26 follow-up will \
             route per-method through `DidMethod::apply_update`",
        )));
    }

    did_ops::publish_did(&auth, &state, mnemonic, &body, dq.domain.as_deref()).await?;
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
    Query(dq): Query<DomainQuery>,
) -> Result<StatusCode, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    did_ops::delete_did(&auth, &state, mnemonic, dq.domain.as_deref()).await?;
    server_push::notify_servers_delete(&state, mnemonic.to_string());
    Ok(StatusCode::NO_CONTENT)
}

// ---------- PUT /api/owner/{mnemonic} ----------

#[derive(Debug, Deserialize)]
pub struct ChangeOwnerRequest {
    pub new_owner: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeOwnerResponse {
    pub mnemonic: String,
    pub owner: String,
    pub updated_at: u64,
}

pub async fn change_owner(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    Json(req): Json<ChangeOwnerRequest>,
) -> Result<Json<ChangeOwnerResponse>, AppError> {
    let mnemonic = clean_mnemonic(&mnemonic);
    let record = did_ops::change_did_owner(&auth, &state, mnemonic, &req.new_owner).await?;
    Ok(Json(ChangeOwnerResponse {
        mnemonic: record.mnemonic,
        owner: record.owner,
        updated_at: record.updated_at,
    }))
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
    let agent_names = did_ops::resolvable_agent_names(&record);

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
        method: (!record.method.is_empty()).then(|| record.method.clone()),
        domain: (!record.domain.is_empty()).then(|| record.domain.clone()),
        agent_names,
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
) -> Result<Json<did_hosting_common::DidStats>, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    let key = format!("stats:{mnemonic}");
    let stats: did_hosting_common::DidStats = state.stats_ks.get(key).await?.unwrap_or_default();
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
pub struct TimeseriesQuery {
    #[serde(default = "default_range")]
    pub range: String,
    /// Optional domain filter. When omitted, returns the cheap server-
    /// wide `_all` bucket. When set, the handler enumerates every DID
    /// whose record `domain` field matches (or whose embedded `did_id`
    /// host resolves to the same value, for legacy/pre-backfill slots)
    /// and sums their per-mnemonic buckets at read time. There is no
    /// per-domain rollup at write time — the buckets are indexed by
    /// mnemonic and aggregating on read keeps the hot path unchanged.
    pub domain: Option<String>,
}

fn default_range() -> String {
    "24h".to_string()
}

/// GET /api/timeseries — server-wide time-series data, optionally
/// filtered to a specific hosting domain via `?domain=`.
pub async fn get_server_timeseries(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Query(params): Query<TimeseriesQuery>,
) -> Result<Json<Vec<TimeSeriesPoint>>, AppError> {
    let points = match params.domain.as_deref() {
        None | Some("") => query_timeseries(&state.timeseries_ks, "_all", &params.range).await?,
        Some(domain) => query_timeseries_by_domain(&state, domain, &params.range).await?,
    };
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
    let points = query_timeseries(&state.timeseries_ks, mnemonic, &params.range).await?;
    Ok(Json(points))
}

/// Query time-series buckets for a given mnemonic and range.
///
/// Reads from the `timeseries_ks` keyspace (split out from
/// `stats_ks` in v0.7); the rows have shape
/// `ts:{mnemonic}:{bucket_epoch} -> {r,u}`. The literal `mnemonic`
/// `_all` is the server-wide aggregate.
async fn query_timeseries(
    timeseries_ks: &did_hosting_common::server::store::KeyspaceHandle,
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
    let raw = timeseries_ks.prefix_iter_raw(prefix.as_str()).await?;

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

/// Read-time per-domain timeseries aggregation.
///
/// Walks the `dids` keyspace, selects every record whose `domain`
/// matches (with a fallback to the host segment of `did_id` for slots
/// that haven't been backfilled yet), reads each mnemonic's per-DID
/// buckets, and sums them at the same step granularity as
/// `query_timeseries`. Cost is O(N_dids_in_domain × buckets_in_range);
/// the dashboard chart is not the hot path.
async fn query_timeseries_by_domain(
    state: &AppState,
    domain: &str,
    range: &str,
) -> Result<Vec<TimeSeriesPoint>, AppError> {
    use did_hosting_common::server::domain::extract_did_host;

    // 1. Enumerate matching mnemonics. The `dids` keyspace key shape is
    //    `did:{mnemonic}` for the record blob plus `owner:…` / content
    //    keys; filter on the `did:` prefix and skip anything that
    //    deserialises as something other than a `DidRecord`.
    let raw = state.dids_ks.prefix_iter_raw("did:").await?;
    let mut mnemonics: Vec<String> = Vec::new();
    for (_key, value) in &raw {
        let Ok(record) = serde_json::from_slice::<did_hosting_common::did_ops::DidRecord>(value)
        else {
            continue;
        };
        let matches = if !record.domain.is_empty() {
            record.domain == domain
        } else if let Some(did_id) = record.did_id.as_deref() {
            extract_did_host(did_id)
                .map(|h| h == domain)
                .unwrap_or(false)
        } else {
            false
        };
        if matches {
            mnemonics.push(record.mnemonic);
        }
    }

    // 2. Fan out per-mnemonic reads and merge the bucket maps. We could
    //    in theory short-circuit when the domain has zero DIDs, but the
    //    empty-result path below produces the same all-zeros series the
    //    chart already renders cleanly, so don't bother special-casing.
    use std::collections::HashMap;

    #[derive(serde::Deserialize, Default)]
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
        _ => (24 * 3600, 900),
    };
    let cutoff = now.saturating_sub(duration);
    let start = cutoff / 300 * 300;
    let end = now / 300 * 300;

    let mut bucket_map: HashMap<u64, (u64, u64)> = HashMap::new();
    for mnemonic in &mnemonics {
        let prefix = format!("ts:{mnemonic}:");
        let raw = state.timeseries_ks.prefix_iter_raw(prefix.as_str()).await?;
        let prefix_len = prefix.len();
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
    }

    let mut points = Vec::new();
    let mut ts = start;
    while ts <= end {
        let mut resolves = 0u64;
        let mut updates = 0u64;
        let mut bucket_ts = ts;
        let bucket_window_end = ts.saturating_add(step);
        while bucket_ts < bucket_window_end && bucket_ts <= end {
            if let Some(&(r, u)) = bucket_map.get(&bucket_ts) {
                resolves += r;
                updates += u;
            }
            bucket_ts = bucket_ts.saturating_add(300);
        }
        points.push(TimeSeriesPoint {
            timestamp: ts,
            resolves,
            updates,
        });
        ts = ts.saturating_add(step);
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
    /// Connectivity — `*_enabled` is what config turns on; `advertised_services`
    /// is what the control DID's document tells peers. See [`ControlInfo`].
    pub didcomm_enabled: bool,
    pub tsp_enabled: bool,
    /// `service[].type` values from the control plane's own DID document.
    /// `None` when no control DID is configured or it wouldn't resolve.
    /// Not sensitive — this document is published for anyone to resolve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertised_services: Option<Vec<String>>,
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

/// Resolve what the control plane's own DID document advertises.
///
/// `None` means "unknown", and both preconditions yield it: no configured
/// control DID, or no configured DID resolver.
///
/// Deliberately does **not** pass `None` through to
/// [`resolve_service_types`], which would build a throwaway `DIDCacheClient`
/// and hit the network. These run on request-handling paths — `GET
/// /api/config` is reachable by every authenticated user — so that fallback
/// would turn a page load into an unauthenticated-ish outbound fetch, once
/// per request. With a resolver configured, the shared client's cache makes
/// everything after the first call cheap.
async fn control_advertised_services(state: &AppState) -> Option<Vec<String>> {
    let did = state.config.server_did.as_deref()?;
    let resolver = state.did_resolver.as_ref()?;
    did_hosting_common::server::didcomm_profile::resolve_service_types(did, Some(resolver)).await
}

/// GET /api/config — return control plane configuration (non-sensitive fields only).
pub async fn get_config(_auth: AuthClaims, State(state): State<AppState>) -> Json<ConfigResponse> {
    let advertised_services = control_advertised_services(&state).await;
    let c = &state.config;
    Json(ConfigResponse {
        control_did: c.server_did.clone(),
        mediator_did: c.mediator_did.clone(),
        public_url: c.public_url.clone(),
        did_hosting_url: c.did_hosting_url.clone(),
        didcomm_enabled: c.features.didcomm,
        tsp_enabled: c.features.tsp,
        advertised_services,
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
    /// Whether the DIDComm transport is *enabled* in config
    /// (`features.didcomm`). What the operator asked for.
    pub didcomm_enabled: bool,
    /// Whether the TSP transport is *enabled* in config (`features.tsp`).
    pub tsp_enabled: bool,
    /// What the control plane's own DID document *advertises* — the
    /// `service[].type` values peers actually see when they resolve it.
    ///
    /// Distinct from the two `*_enabled` flags above, and the pair can
    /// legitimately disagree: a transport enabled but unadvertised is
    /// unreachable to peers, and one advertised but disabled is a
    /// black hole. The UI cross-checks them and warns on a mismatch.
    ///
    /// `None` when there is no configured control DID, or when it could
    /// not be resolved — in which case the UI can't make the comparison
    /// and says so rather than implying agreement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertised_services: Option<Vec<String>>,
    pub total_local_dids: u64,
    /// DID methods compiled into this binary, as enumerated by
    /// `did_hosting_common::method::enabled_methods()`. Each entry is a
    /// method name (e.g. `"webvh"`, `"web"`). Empty when the operator
    /// compiled with `--no-default-features` and no `method-*` feature
    /// — in that case the dispatcher refuses every DID op, and the UI
    /// renders a loud warning so the operator notices before any user
    /// hits the failure.
    pub enabled_methods: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub instance_id: String,
    pub service_type: String,
    pub label: Option<String>,
    pub url: String,
    pub status: String,
    /// `service[].type` values cached off this instance's DID document.
    /// See `registry::ServiceInstance::advertised_services`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertised_services: Option<Vec<String>>,
    /// Epoch seconds of the last successful resolve of the above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_checked_at: Option<u64>,
    /// Transport the last inbound message from this instance arrived on, and
    /// the last health ping to it went out on. **Observed**, not inferred from
    /// `advertised_services` — a TSP-advertising peer still reads `didcomm`
    /// here if that is what actually carried the traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_inbound_transport:
        Option<did_hosting_common::server::didcomm_profile::ObservedTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_inbound_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_outbound_transport:
        Option<did_hosting_common::server::didcomm_profile::ObservedTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_outbound_at: Option<u64>,
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
///
/// Admin-only: returns the same registry data that `/api/control/registry`
/// gates behind `AdminAuth` (internal instance URLs, IDs, server DIDs, health).
/// A non-admin DID has no business mapping the backend topology — exposing
/// internal service URLs aids SSRF / lateral movement and the instance IDs
/// feed directly into the `/api/proxy/{type}/{instance_id}/*` endpoint.
pub async fn get_services_overview(
    _auth: AdminAuth,
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
            advertised_services: inst.advertised_services.clone(),
            services_checked_at: inst.services_checked_at,
            last_inbound_transport: inst.last_inbound_transport,
            last_inbound_at: inst.last_inbound_at,
            last_outbound_transport: inst.last_outbound_transport,
            last_outbound_at: inst.last_outbound_at,
        });
    }

    // Count local DIDs on control plane
    let local_dids = state.dids_ks.prefix_iter_raw("did:").await?.len() as u64;

    // Resolve the control plane's own DID document so the UI can compare
    // what it *advertises* against what `features.*` says is *enabled*.
    // Best-effort: a resolve failure yields `None`, which the UI renders as
    // "couldn't check" rather than "nothing advertised".
    let control_services = control_advertised_services(&state).await;

    Ok(Json(ServiceOverviewResponse {
        control: ControlInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            server_did: state.config.server_did.clone(),
            public_url: state.config.public_url.clone(),
            didcomm_enabled: state.config.features.didcomm,
            tsp_enabled: state.config.features.tsp,
            advertised_services: control_services,
            total_local_dids: local_dids,
            enabled_methods: did_hosting_common::method::enabled_methods().to_vec(),
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

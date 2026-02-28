use crate::auth::AuthClaims;
use crate::did_ops::{self, LogEntryInfo, LogMetadata};
use crate::error::AppError;
use crate::mnemonic::{is_path_available, validate_custom_path};
use crate::server::AppState;
use affinidi_webvh_common::{CheckNameResponse, DidListEntry, RequestUriResponse};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;

// ---------- POST /dids/check ----------

#[derive(Debug, Deserialize)]
pub struct CheckNameRequest {
    pub path: String,
}

pub async fn check_name(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<CheckNameRequest>,
) -> Result<Json<CheckNameResponse>, AppError> {
    validate_custom_path(&req.path)?;
    let available = is_path_available(&state.dids_ks, &req.path).await?;
    info!(did = %auth.did, path = %req.path, available, "name availability checked");
    Ok(Json(CheckNameResponse {
        available,
        path: req.path,
    }))
}

// ---------- POST /dids ----------

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

    Ok((
        StatusCode::CREATED,
        Json(RequestUriResponse {
            mnemonic: result.mnemonic,
            did_url: result.did_url,
        }),
    ))
}

// ---------- GET /dids/{mnemonic} ----------

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
    let mnemonic = mnemonic.trim_start_matches('/');
    let result = did_ops::get_did_info(&auth, &state, mnemonic).await?;

    Ok(Json(DidDetailResponse {
        mnemonic: result.record.mnemonic,
        created_at: result.record.created_at,
        updated_at: result.record.updated_at,
        version_count: result.record.version_count,
        did_id: result.record.did_id,
        owner: result.record.owner,
        disabled: result.record.disabled,
        log: result.log_metadata,
    }))
}

// ---------- GET /dids/{mnemonic}/log ----------

pub async fn get_did_log(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<Vec<LogEntryInfo>>, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    let entries = did_ops::get_did_log(&auth, &state, mnemonic).await?;
    Ok(Json(entries))
}

// ---------- PUT /dids/{mnemonic} ----------

pub async fn upload_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    body: String,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    did_ops::publish_did(&auth, &state, mnemonic, &body).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- PUT /dids/{mnemonic}/witness ----------

pub async fn upload_witness(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    body: String,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    did_ops::upload_witness(&auth, &state, mnemonic, &body).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /dids/{mnemonic} ----------

pub async fn delete_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    did_ops::delete_did(&auth, &state, mnemonic).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- PUT /dids/{mnemonic}/disable ----------

pub async fn disable_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    did_ops::set_did_disabled(&auth, &state, mnemonic, true).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- PUT /dids/{mnemonic}/enable ----------

pub async fn enable_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    did_ops::set_did_disabled(&auth, &state, mnemonic, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- GET /dids ----------

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

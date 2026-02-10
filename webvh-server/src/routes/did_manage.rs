use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use affinidi_webvh_common::{CheckNameResponse, DidListEntry, RequestUriResponse};

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::mnemonic::{generate_unique_mnemonic, is_path_available, validate_custom_path};
use crate::server::AppState;
use crate::stats;
use crate::store::KeyspaceHandle;
use tracing::info;

/// A record tracking a hosted DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRecord {
    pub owner: String,
    pub mnemonic: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
}

fn did_key(mnemonic: &str) -> String {
    format!("did:{mnemonic}")
}

fn content_log_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:log")
}

fn content_witness_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:witness")
}

fn owner_key(did: &str, mnemonic: &str) -> String {
    format!("owner:{did}:{mnemonic}")
}

/// Load a DID record and verify the caller is the owner (or admin).
async fn get_authorized_record(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    auth: &AuthClaims,
) -> Result<DidRecord, AppError> {
    let record: DidRecord = dids_ks
        .get(did_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;
    if record.owner != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden("not the owner of this DID".into()));
    }
    Ok(record)
}

// ---------- POST /dids/check ----------

#[derive(Debug, Deserialize)]
pub struct CheckNameRequest {
    pub path: String,
}

pub async fn check_name(
    _auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<CheckNameRequest>,
) -> Result<Json<CheckNameResponse>, AppError> {
    validate_custom_path(&req.path)?;
    let available = is_path_available(&state.dids_ks, &req.path).await?;
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
    let mnemonic = match body.and_then(|b| b.0.path) {
        Some(custom_path) => {
            validate_custom_path(&custom_path)?;
            if !is_path_available(&state.dids_ks, &custom_path).await? {
                return Err(AppError::Conflict(format!(
                    "path '{custom_path}' is already taken"
                )));
            }
            custom_path
        }
        None => generate_unique_mnemonic(&state.dids_ks).await?,
    };

    let now = now_epoch();
    let record = DidRecord {
        owner: auth.did.clone(),
        mnemonic: mnemonic.clone(),
        created_at: now,
        updated_at: now,
        version_count: 0,
    };

    // Store DID record
    state.dids_ks.insert(did_key(&mnemonic), &record).await?;

    // Store owner reverse index
    state
        .dids_ks
        .insert_raw(
            owner_key(&auth.did, &mnemonic),
            mnemonic.as_bytes().to_vec(),
        )
        .await?;

    // Build the public DID URL
    let base_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.server.host, state.config.server.port));

    let did_url = format!("{base_url}/{mnemonic}/did.jsonl");

    info!(did = %auth.did, mnemonic = %mnemonic, "URI requested");

    Ok((
        StatusCode::CREATED,
        Json(RequestUriResponse { mnemonic, did_url }),
    ))
}

// ---------- PUT /dids/{mnemonic} ----------

pub async fn upload_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    body: String,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    if body.is_empty() {
        return Err(AppError::Validation("did.jsonl content cannot be empty".into()));
    }

    // Store content
    state
        .dids_ks
        .insert_raw(content_log_key(&mnemonic), body.into_bytes())
        .await?;

    // Update record
    record.updated_at = now_epoch();
    record.version_count += 1;
    state.dids_ks.insert(did_key(&mnemonic), &record).await?;

    // Increment stats
    stats::increment_updates(&state.stats_ks, &mnemonic).await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "did.jsonl uploaded");

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
    get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    if body.is_empty() {
        return Err(AppError::Validation(
            "did-witness.json content cannot be empty".into(),
        ));
    }

    // Store witness content
    state
        .dids_ks
        .insert_raw(content_witness_key(&mnemonic), body.into_bytes())
        .await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "did-witness.json uploaded");

    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /dids/{mnemonic} ----------

pub async fn delete_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    let record = get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    // Remove all associated data
    state.dids_ks.remove(did_key(&mnemonic)).await?;
    state.dids_ks.remove(content_log_key(&mnemonic)).await?;
    state.dids_ks.remove(content_witness_key(&mnemonic)).await?;
    state
        .dids_ks
        .remove(owner_key(&record.owner, &mnemonic))
        .await?;

    // Remove stats
    stats::delete_stats(&state.stats_ks, &mnemonic).await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "DID deleted");

    Ok(StatusCode::NO_CONTENT)
}

// ---------- GET /dids ----------

pub async fn list_dids(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<Vec<DidListEntry>>, AppError> {
    let prefix = format!("owner:{}:", auth.did);
    let raw = state.dids_ks.prefix_iter_raw(prefix).await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let mnemonic = String::from_utf8(value)
            .map_err(|e| AppError::Internal(format!("invalid mnemonic bytes: {e}")))?;
        if let Some(record) = state
            .dids_ks
            .get::<DidRecord>(did_key(&mnemonic))
            .await?
        {
            entries.push(DidListEntry {
                mnemonic: record.mnemonic,
                created_at: record.created_at,
                updated_at: record.updated_at,
                version_count: record.version_count,
            });
        }
    }

    info!(did = %auth.did, count = entries.len(), "DIDs listed");

    Ok(Json(entries))
}

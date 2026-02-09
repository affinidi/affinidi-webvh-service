use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::mnemonic::generate_unique_mnemonic;
use crate::server::AppState;
use crate::stats;
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

// ---------- POST /dids ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestUriResponse {
    pub mnemonic: String,
    pub did_url: String,
}

pub async fn request_uri(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<RequestUriResponse>), AppError> {
    let mnemonic = generate_unique_mnemonic(&state.dids_ks).await?;

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
    let config = state.config.read().await;
    let base_url = config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", config.server.host, config.server.port));
    drop(config);

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
    let mut record: DidRecord = state
        .dids_ks
        .get(did_key(&mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;

    // Only owner or admin can upload
    if record.owner != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden("not the owner of this DID".into()));
    }

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
    let record: DidRecord = state
        .dids_ks
        .get(did_key(&mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;

    // Only owner or admin can upload
    if record.owner != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden("not the owner of this DID".into()));
    }

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
    let record: DidRecord = state
        .dids_ks
        .get(did_key(&mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;

    // Only owner or admin can delete
    if record.owner != auth.did && auth.role != Role::Admin {
        return Err(AppError::Forbidden("not the owner of this DID".into()));
    }

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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidListEntry {
    pub mnemonic: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
}

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

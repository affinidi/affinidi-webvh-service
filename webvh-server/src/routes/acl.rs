use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use tracing::{info, warn};

use crate::acl::{
    AclEntry, Role, delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::AppState;

// ---------- GET /acl ----------

#[derive(Debug, Serialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Serialize)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    pub created_at: u64,
    pub max_total_size: Option<u64>,
    pub max_did_count: Option<u64>,
}

impl From<AclEntry> for AclEntryResponse {
    fn from(e: AclEntry) -> Self {
        AclEntryResponse {
            did: e.did,
            role: e.role,
            label: e.label,
            created_at: e.created_at,
            max_total_size: e.max_total_size,
            max_did_count: e.max_did_count,
        }
    }
}

pub async fn list_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<AclListResponse>, AppError> {
    let all_entries = list_acl_entries(&state.acl_ks).await?;
    let entries: Vec<AclEntryResponse> =
        all_entries.into_iter().map(AclEntryResponse::from).collect();
    info!(caller = %auth.0.did, count = entries.len(), "ACL listed");
    Ok(Json(AclListResponse { entries }))
}

// ---------- POST /acl ----------

#[derive(Debug, Deserialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    #[serde(default)]
    pub max_total_size: Option<u64>,
    #[serde(default)]
    pub max_did_count: Option<u64>,
}

pub async fn create_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<AclEntryResponse>), AppError> {
    // Check if entry already exists
    if get_acl_entry(&state.acl_ks, &req.did).await?.is_some() {
        warn!(caller = %auth.0.did, target_did = %req.did, "ACL create rejected: entry already exists");
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for DID: {}",
            req.did
        )));
    }

    let entry = AclEntry {
        did: req.did,
        role: req.role,
        label: req.label,
        created_at: now_epoch(),
        max_total_size: req.max_total_size,
        max_did_count: req.max_did_count,
    };

    store_acl_entry(&state.acl_ks, &entry).await?;

    info!(caller = %auth.0.did, did = %entry.did, role = %entry.role, "ACL entry created");
    Ok((StatusCode::CREATED, Json(AclEntryResponse::from(entry))))
}

// ---------- PUT /acl/{did} ----------

#[derive(Debug, Deserialize)]
pub struct UpdateAclRequest {
    pub label: Option<String>,
    pub max_total_size: Option<u64>,
    pub max_did_count: Option<u64>,
}

pub async fn update_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<AclEntryResponse>, AppError> {
    let mut entry = get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    if let Some(label) = req.label {
        entry.label = Some(label);
    }
    if req.max_total_size.is_some() {
        entry.max_total_size = req.max_total_size;
    }
    if req.max_did_count.is_some() {
        entry.max_did_count = req.max_did_count;
    }

    store_acl_entry(&state.acl_ks, &entry).await?;

    info!(
        caller = %auth.0.did,
        did = %did,
        max_total_size = ?entry.max_total_size,
        max_did_count = ?entry.max_did_count,
        label = ?entry.label,
        "ACL entry updated"
    );
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- DELETE /acl/{did} ----------

pub async fn delete_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    // Prevent self-deletion
    if auth.0.did == did {
        warn!(caller = %auth.0.did, "ACL delete rejected: attempted self-deletion");
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    // Verify entry exists
    get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    delete_acl_entry(&state.acl_ks, &did).await?;

    info!(caller = %auth.0.did, did = %did, "ACL entry deleted");
    Ok(StatusCode::NO_CONTENT)
}

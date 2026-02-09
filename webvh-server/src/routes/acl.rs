use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use tracing::info;

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
}

impl From<AclEntry> for AclEntryResponse {
    fn from(e: AclEntry) -> Self {
        AclEntryResponse {
            did: e.did,
            role: e.role,
            label: e.label,
            created_at: e.created_at,
        }
    }
}

pub async fn list_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<AclListResponse>, AppError> {
    let acl = state.acl_ks.clone();
    let all_entries = list_acl_entries(&acl).await?;
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
}

pub async fn create_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<AclEntryResponse>), AppError> {
    let acl = state.acl_ks.clone();

    // Check if entry already exists
    if get_acl_entry(&acl, &req.did).await?.is_some() {
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
    };

    store_acl_entry(&acl, &entry).await?;

    info!(caller = %auth.0.did, did = %entry.did, role = %entry.role, "ACL entry created");
    Ok((StatusCode::CREATED, Json(AclEntryResponse::from(entry))))
}

// ---------- DELETE /acl/{did} ----------

pub async fn delete_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    // Prevent self-deletion
    if auth.0.did == did {
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    let acl = state.acl_ks.clone();

    // Verify entry exists
    get_acl_entry(&acl, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found for DID: {did}")))?;

    delete_acl_entry(&acl, &did).await?;

    info!(caller = %auth.0.did, did = %did, "ACL entry deleted");
    Ok(StatusCode::NO_CONTENT)
}

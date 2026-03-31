//! ACL management routes for the control plane.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use tracing::info;

use serde::{Deserialize, Serialize};

use crate::acl::{self, AclEntry};
use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::AppState;
use affinidi_webvh_common::server::acl::Role;

#[derive(Serialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntry>,
}

// ---------- GET /api/acl ----------

pub async fn list_acl(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<AclListResponse>, AppError> {
    let entries = acl::list_acl_entries(&state.acl_ks).await?;
    Ok(Json(AclListResponse { entries }))
}

// ---------- POST /api/acl ----------

pub async fn create_acl(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(mut entry): Json<AclEntry>,
) -> Result<(StatusCode, Json<AclEntry>), AppError> {
    // Check if entry already exists
    if acl::get_acl_entry(&state.acl_ks, &entry.did)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for {}",
            entry.did
        )));
    }
    entry.created_at = now_epoch();
    acl::store_acl_entry(&state.acl_ks, &entry).await?;
    info!(did = %entry.did, role = %entry.role, "ACL entry created");
    Ok((StatusCode::CREATED, Json(entry)))
}

// ---------- PUT /api/acl/{did} ----------

#[derive(Deserialize)]
pub struct UpdateAclRequest {
    pub role: Option<Role>,
    pub label: Option<String>,
    pub max_total_size: Option<u64>,
    pub max_did_count: Option<u64>,
}

pub async fn update_acl(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(updates): Json<UpdateAclRequest>,
) -> Result<Json<AclEntry>, AppError> {
    let mut entry = acl::get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found: {did}")))?;

    if let Some(role) = updates.role {
        entry.role = role;
    }
    if updates.label.is_some() {
        entry.label = updates.label;
    }
    if updates.max_total_size.is_some() {
        entry.max_total_size = updates.max_total_size;
    }
    if updates.max_did_count.is_some() {
        entry.max_did_count = updates.max_did_count;
    }

    acl::store_acl_entry(&state.acl_ks, &entry).await?;
    info!(did = %entry.did, role = %entry.role, "ACL entry updated");
    Ok(Json(entry))
}

// ---------- DELETE /api/acl/{did} ----------

pub async fn delete_acl(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    acl::delete_acl_entry(&state.acl_ks, &did).await?;
    info!(did = %did, "ACL entry deleted");
    Ok(StatusCode::NO_CONTENT)
}

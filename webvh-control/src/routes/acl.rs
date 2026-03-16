//! ACL management routes for the control plane.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use tracing::info;

use serde::Serialize;

use crate::acl::{self, AclEntry};
use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::AppState;

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
    if acl::get_acl_entry(&state.acl_ks, &entry.did).await?.is_some() {
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

pub async fn update_acl(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(mut entry): Json<AclEntry>,
) -> Result<Json<AclEntry>, AppError> {
    // Ensure DID in path matches body
    entry.did = did;
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

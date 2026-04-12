use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::acl::{AclEntry, Role, get_acl_entry, list_acl_entries, store_acl_entry};
use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::AppState;

#[derive(Serialize)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    pub created_at: u64,
}

impl From<&AclEntry> for AclEntryResponse {
    fn from(entry: &AclEntry) -> Self {
        Self {
            did: entry.did.clone(),
            role: entry.role.to_string(),
            label: entry.label.clone(),
            created_at: entry.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Deserialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateAclRequest {
    pub role: Option<String>,
    pub label: Option<String>,
}

pub async fn list_acl(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<AclListResponse>, AppError> {
    let entries = list_acl_entries(&state.acl_ks).await?;
    let responses: Vec<AclEntryResponse> = entries.iter().map(AclEntryResponse::from).collect();
    Ok(Json(AclListResponse { entries: responses }))
}

pub async fn create_acl(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<AclEntryResponse>), AppError> {
    // Parse role
    let role = Role::from_str(&req.role)
        .map_err(|_| AppError::Validation(format!("invalid role: {}", req.role)))?;

    // Check for duplicates
    if get_acl_entry(&state.acl_ks, &req.did).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for {}",
            req.did
        )));
    }

    let entry = AclEntry {
        did: req.did,
        role,
        label: req.label,
        created_at: now_epoch(),
        max_total_size: None,
        max_did_count: None,
    };

    store_acl_entry(&state.acl_ks, &entry).await?;

    Ok((StatusCode::CREATED, Json(AclEntryResponse::from(&entry))))
}

pub async fn update_acl(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(req): Json<UpdateAclRequest>,
) -> Result<Json<AclEntryResponse>, AppError> {
    let mut entry = get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found: {did}")))?;

    if let Some(role_str) = &req.role {
        entry.role = Role::from_str(role_str)
            .map_err(|_| AppError::Validation(format!("invalid role: {role_str}")))?;
    }
    if let Some(label) = req.label {
        entry.label = if label.is_empty() { None } else { Some(label) };
    }

    store_acl_entry(&state.acl_ks, &entry).await?;

    Ok(Json(AclEntryResponse::from(&entry)))
}

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

    // Verify entry exists
    if get_acl_entry(&state.acl_ks, &did).await?.is_none() {
        return Err(AppError::NotFound(format!("ACL entry not found: {did}")));
    }

    crate::acl::delete_acl_entry(&state.acl_ks, &did).await?;

    Ok(StatusCode::NO_CONTENT)
}

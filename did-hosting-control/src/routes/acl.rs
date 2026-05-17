//! ACL management routes for the control plane.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use tracing::{info, warn};

use crate::acl::{self, AclEntry};
use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::AppState;
use did_hosting_common::server::acl::{
    AclEntryResponse, AclListResponse, CreateAclRequest, UpdateAclRequest, validate_did_format,
};
use did_hosting_common::server::domain::{DomainScope, get_default_domain};

// ---------- GET /api/acl ----------

pub async fn list_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<AclListResponse>, AppError> {
    let entries = acl::list_acl_entries(&state.acl_ks).await?;
    let entries = entries.into_iter().map(AclEntryResponse::from).collect();
    info!(caller = %auth.0.did, "ACL listed");
    Ok(Json(AclListResponse { entries }))
}

// ---------- POST /api/acl ----------

pub async fn create_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<(StatusCode, Json<AclEntryResponse>), AppError> {
    // Canonicalise + validate before any storage I/O so a typo-bearing DID
    // (e.g. trailing whitespace, control chars, missing `did:` prefix)
    // never lands as a key — silent mismatches with `check_acl` would
    // otherwise lock the operator out of the system they just configured.
    let did = validate_did_format(&req.did)?;

    // Check if entry already exists
    if acl::get_acl_entry(&state.acl_ks, &did).await?.is_some() {
        warn!(caller = %auth.0.did, target_did = %did, "ACL create rejected: entry already exists");
        return Err(AppError::Conflict(format!(
            "ACL entry already exists for {did}"
        )));
    }
    // Default-`domains` policy per `docs/multi-domain-spec.md` §3:
    //
    // - Explicit value in the request → honour it verbatim.
    // - Owner without explicit `domains` → `AllowedWithDefault(
    //   [system_default], system_default)`. Restrictive by default;
    //   admin can broaden via PUT after creation.
    // - Admin / Service without explicit `domains` → `All`. Role-based
    //   access already constrains the surface for these.
    //
    // If no system default is configured yet (fresh deployment, no
    // domains seeded), Owner fallback can't substitute a default →
    // fall back to `All` and warn. T18's bootstrap_domains should
    // close this gap on first boot; this branch only fires on edge
    // cases where ACL is created before any domain.
    let role_is_owner = matches!(req.role, did_hosting_common::server::acl::Role::Owner);
    let domains = match req.domains {
        Some(scope) => scope,
        None if role_is_owner => {
            match get_default_domain(&state.store).await? {
                Some(default) => {
                    DomainScope::AllowedWithDefault {
                        domains: vec![default.clone()],
                        default,
                    }
                }
                None => {
                    warn!(
                        caller = %auth.0.did,
                        target_did = %did,
                        "ACL create: Owner without `domains` and no system default — falling back to All"
                    );
                    DomainScope::All
                }
            }
        }
        None => DomainScope::All,
    };
    let entry = AclEntry {
        did,
        role: req.role,
        label: req.label,
        created_at: now_epoch(),
        max_total_size: req.max_total_size,
        max_did_count: req.max_did_count,
        domains,
    };
    acl::store_acl_entry(&state.acl_ks, &entry).await?;
    info!(caller = %auth.0.did, did = %entry.did, role = %entry.role, "ACL entry created");
    Ok((StatusCode::CREATED, Json(AclEntryResponse::from(entry))))
}

// ---------- PUT /api/acl/{did} ----------

pub async fn update_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(updates): Json<UpdateAclRequest>,
) -> Result<Json<AclEntryResponse>, AppError> {
    let did = validate_did_format(&did)?;
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
    if let Some(domains) = updates.domains {
        entry.domains = domains;
    }

    acl::store_acl_entry(&state.acl_ks, &entry).await?;
    info!(caller = %auth.0.did, did = %entry.did, role = %entry.role, "ACL entry updated");
    Ok(Json(AclEntryResponse::from(entry)))
}

// ---------- DELETE /api/acl/{did} ----------

pub async fn delete_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<StatusCode, AppError> {
    let did = validate_did_format(&did)?;

    // Prevent self-deletion
    if auth.0.did == did {
        warn!(caller = %auth.0.did, "ACL delete rejected: attempted self-deletion");
        return Err(AppError::Conflict(
            "cannot delete your own ACL entry".into(),
        ));
    }

    // Verify entry exists
    acl::get_acl_entry(&state.acl_ks, &did)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("ACL entry not found: {did}")))?;

    acl::delete_acl_entry(&state.acl_ks, &did).await?;
    info!(caller = %auth.0.did, did = %did, "ACL entry deleted");
    Ok(StatusCode::NO_CONTENT)
}

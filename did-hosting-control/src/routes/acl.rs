//! ACL management routes for the control plane.
//!
//! ## Deprecation notice (v0.7.0)
//!
//! These four routes (`GET/POST /api/acl`, `PUT/DELETE /api/acl/{did}`)
//! are **deprecated** as of v0.7.0 in favour of the new Trust Tasks
//! surface at `POST /api/trust-tasks`. Every response from this
//! module carries:
//!
//! - `Deprecation: true`
//! - `Sunset: <ETA>` — the release these routes will be removed
//! - `Link: </api/trust-tasks>; rel="successor-version"`
//!
//! Per-call structured warn-logs flag each hit so operators can see
//! which clients are still on the legacy path. Removal target: **v0.8.0**.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
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

/// `Sunset` header value — the release after which these routes are
/// removed. Per RFC 8594 the value is an HTTP-date; we pick a fixed
/// far-future date that aligns with the v0.8.0 release cut. Operators
/// can override at the reverse-proxy layer if they need a specific
/// retirement date pinned to their deployment.
const SUNSET_DATE: &str = "Mon, 01 Dec 2026 00:00:00 GMT";
const SUCCESSOR_LINK: &str = "</api/trust-tasks>; rel=\"successor-version\"";

/// Attach the deprecation triple-header to any successful response.
/// Wraps `Json(body)` so call sites stay one-liners.
fn deprecated<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut resp = (status, Json(body)).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::HeaderName::from_static("deprecation"),
        HeaderValue::from_static("true"),
    );
    headers.insert(
        header::HeaderName::from_static("sunset"),
        HeaderValue::from_static(SUNSET_DATE),
    );
    headers.insert(header::LINK, HeaderValue::from_static(SUCCESSOR_LINK));
    resp
}

/// Emit the structured per-call deprecation log line — exactly one
/// line per legacy-route hit. Operators tail this to find clients
/// that need to migrate before v0.8.0.
fn warn_deprecated(route: &'static str, caller: &str) {
    warn!(
        legacy_route = route,
        caller = %caller,
        successor = "POST /api/trust-tasks",
        sunset = SUNSET_DATE,
        "legacy ACL route used; migrate to /api/trust-tasks before v0.8.0"
    );
}

// ---------- GET /api/acl ----------

pub async fn list_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    warn_deprecated("GET /api/acl", &auth.0.did);
    let entries = acl::list_acl_entries(&state.acl_ks).await?;
    let entries = entries.into_iter().map(AclEntryResponse::from).collect();
    info!(caller = %auth.0.did, "ACL listed");
    Ok(deprecated(StatusCode::OK, AclListResponse { entries }))
}

// ---------- POST /api/acl ----------

pub async fn create_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateAclRequest>,
) -> Result<Response, AppError> {
    warn_deprecated("POST /api/acl", &auth.0.did);
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
        None if role_is_owner => match get_default_domain(&state.store).await? {
            Some(default) => DomainScope::AllowedWithDefault {
                domains: vec![default.clone()],
                default,
            },
            None => {
                warn!(
                    caller = %auth.0.did,
                    target_did = %did,
                    "ACL create: Owner without `domains` and no system default — falling back to All"
                );
                DomainScope::All
            }
        },
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
    Ok(deprecated(
        StatusCode::CREATED,
        AclEntryResponse::from(entry),
    ))
}

// ---------- PUT /api/acl/{did} ----------

pub async fn update_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
    Json(updates): Json<UpdateAclRequest>,
) -> Result<Response, AppError> {
    warn_deprecated("PUT /api/acl/{did}", &auth.0.did);
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
    Ok(deprecated(StatusCode::OK, AclEntryResponse::from(entry)))
}

// ---------- DELETE /api/acl/{did} ----------

pub async fn delete_acl(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Response, AppError> {
    warn_deprecated("DELETE /api/acl/{did}", &auth.0.did);
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
    // 204 No Content with no body; still attach deprecation headers.
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::HeaderName::from_static("deprecation"),
        HeaderValue::from_static("true"),
    );
    headers.insert(
        header::HeaderName::from_static("sunset"),
        HeaderValue::from_static(SUNSET_DATE),
    );
    headers.insert(header::LINK, HeaderValue::from_static(SUCCESSOR_LINK));
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_hosting_common::server::acl::{AclEntryResponse, AclListResponse, Role};
    use did_hosting_common::server::domain::DomainScope;

    /// Pin the `Deprecation` / `Sunset` / `Link` header triple on the
    /// helper that every legacy ACL route uses for its response. A
    /// regression here means clients lose the migration signal —
    /// catch it at compile-time rather than waiting for a v0.8.0
    /// removal to surprise downstream.
    #[test]
    fn deprecated_helper_emits_full_header_triple() {
        let resp = deprecated(StatusCode::OK, AclListResponse { entries: vec![] });
        assert_eq!(
            resp.headers()
                .get("deprecation")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            resp.headers().get("sunset").and_then(|v| v.to_str().ok()),
            Some(SUNSET_DATE)
        );
        assert_eq!(
            resp.headers()
                .get(header::LINK)
                .and_then(|v| v.to_str().ok()),
            Some(SUCCESSOR_LINK)
        );
    }

    /// Wrapping a `CREATED` response preserves the status (some
    /// responses use 200, some 201) AND attaches the triple.
    #[test]
    fn deprecated_helper_preserves_inner_status() {
        let entry = did_hosting_common::server::acl::AclEntry {
            did: "did:web:carol.example".into(),
            role: Role::Owner,
            label: None,
            created_at: 0,
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        };
        let resp = deprecated(StatusCode::CREATED, AclEntryResponse::from(entry));
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(resp.headers().contains_key("deprecation"));
    }
}

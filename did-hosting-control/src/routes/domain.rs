//! REST endpoints for the multi-domain feature.
//!
//! Two routes today (T17):
//!
//! - `GET /api/domains` — Admin only. Lists every configured domain
//!   with full metadata. Backs the Domains admin view in the UI.
//! - `GET /api/me/domains` — Any authenticated caller. Lists the
//!   subset of domains the caller's ACL entry allows them to operate
//!   on; non-Admin callers never see the full list.
//!
//! T8b (REST router wrapping) will move these from plain
//! `axum::Router::route()` to `TrustTaskRouter::route_with_task(...,
//! TASK_DOMAIN_LIST_1_0)` / `..._ME_DOMAINS_1_0`. The handler
//! signatures stay; only the wiring in `super::mod` changes.
//!
//! Mutating routes (create / update / disable / set-default) land
//! together in T33 as Trust-Task-bound endpoints.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use tracing::info;

use crate::auth::{AdminAuth, AuthClaims};
use crate::error::AppError;
use crate::server::AppState;
use did_hosting_common::server::acl;
use did_hosting_common::server::domain::{self, DomainEntry, DomainScope};

/// Body for both list endpoints. `default` carries the current
/// default-domain pointer so the UI can highlight it without a second
/// round-trip.
#[derive(Debug, Serialize)]
pub struct DomainListResponse {
    pub domains: Vec<DomainEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// `GET /api/domains` — Admin lists every configured domain.
pub async fn list_domains(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<DomainListResponse>, AppError> {
    let mut domains = domain::list_domains(&state.store).await?;
    // Stable ordering for UI / scripts — by name. Storage backends
    // don't promise iter order; sort here so responses are
    // deterministic.
    domains.sort_by(|a, b| a.name.cmp(&b.name));
    let default = domain::get_default_domain(&state.store).await?;
    info!(caller = %auth.0.did, count = domains.len(), "admin listed domains");
    Ok(Json(DomainListResponse { domains, default }))
}

/// `GET /api/me/domains` — any authenticated caller; returns only the
/// domains their ACL scope allows them to operate on.
///
/// Semantics:
/// - `Admin` / `Service` roles see every domain (same as
///   `GET /api/domains` body, minus the structural separation).
/// - `Owner` with `DomainScope::All` sees every domain.
/// - `Owner` with `Allowed` / `AllowedWithDefault` sees only the
///   listed domains.
///
/// The `default` field carries the **caller's** default (per
/// `AllowedWithDefault.default`) when set, else falls back to the
/// system default. UI uses this to pre-select the right domain on the
/// DID-create form.
pub async fn list_my_domains(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<DomainListResponse>, AppError> {
    let all = domain::list_domains(&state.store).await?;

    // Resolve the caller's ACL entry. A missing entry shouldn't
    // happen for an authenticated caller (auth itself requires an
    // ACL row) — but be defensive: treat as scope = All.
    let scope = match acl::get_acl_entry(&state.acl_ks, &auth.did).await? {
        Some(entry) => entry.domains,
        None => DomainScope::All,
    };

    // Admin / Service roles short-circuit per spec §3 — full list
    // regardless of scope field. (Service is an internal-account role
    // that doesn't usually call this endpoint; including for symmetry
    // with the auth-extractor's gating elsewhere.)
    let role_overrides_scope = matches!(
        auth.role,
        crate::acl::Role::Admin | crate::acl::Role::Service
    );

    let mut domains: Vec<DomainEntry> = if role_overrides_scope {
        all
    } else {
        all.into_iter().filter(|d| scope.allows(&d.name)).collect()
    };
    domains.sort_by(|a, b| a.name.cmp(&b.name));

    // Default: caller's `AllowedWithDefault.default` if set, else
    // system default (so a caller without an explicit default still
    // gets a sensible hint).
    let default = match scope.default_domain() {
        Some(d) => Some(d.to_string()),
        None => domain::get_default_domain(&state.store).await?,
    };

    info!(
        caller = %auth.did,
        count = domains.len(),
        "caller listed scoped domains"
    );
    Ok(Json(DomainListResponse { domains, default }))
}

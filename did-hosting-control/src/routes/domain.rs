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
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::auth::{AdminAuth, AuthClaims};
use crate::error::AppError;
use crate::server::AppState;
use did_hosting_common::server::acl;
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::domain::{
    self, DomainBranding, DomainEntry, DomainQuota, DomainScope, DomainStatus, DomainUrlScheme,
    normalize_domain_name,
};
use did_hosting_common::server::pending_purge;

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

// ===========================================================================
// T33: mutating routes (Admin-only)
// ===========================================================================

/// `POST /api/domains` request body.
#[derive(Debug, Deserialize)]
pub struct CreateDomainRequest {
    /// Canonical-or-not name; the handler normalises (lowercase +
    /// IDNA + optional path prefix). A non-canonical input is
    /// rejected with a clear error pointing at the expected form.
    pub name: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub scheme: Option<DomainUrlScheme>,
    #[serde(default)]
    pub branding: Option<DomainBranding>,
    #[serde(default)]
    pub witnesses: Option<Vec<String>>,
    #[serde(default)]
    pub watchers: Option<Vec<String>>,
    #[serde(default)]
    pub quota: Option<DomainQuota>,
    /// When true the new domain is marked as `well_known_enabled`.
    /// Used by the `/.well-known/did.*` resolution path.
    #[serde(default)]
    pub well_known_enabled: bool,
    /// When true, set the new domain as the system default after
    /// creation. The previous default is unflagged in the same call.
    #[serde(default)]
    pub set_as_default: bool,
}

/// `POST /api/domains` — Admin creates a new domain.
pub async fn create_domain_route(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainEntry>), AppError> {
    let canonical = normalize_domain_name(&req.name)?;
    let entry = DomainEntry {
        name: canonical.clone(),
        label: req.label,
        scheme: req.scheme.unwrap_or(DomainUrlScheme::Https),
        status: DomainStatus::Active,
        created_at: now_epoch(),
        default_domain: false,
        branding: req.branding,
        witnesses: req.witnesses,
        watchers: req.watchers,
        quota: req.quota,
        well_known_enabled: req.well_known_enabled,
        disabled_at: None,
        purge_at: None,
    };
    domain::create_domain(&state.store, &entry).await?;
    if req.set_as_default {
        domain::set_default_domain(&state.store, &canonical).await?;
    }
    let stored = domain::get_domain(&state.store, &canonical)
        .await?
        .ok_or_else(|| AppError::Internal(format!("domain '{canonical}' missing after create")))?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(&state, &stored).await;
    info!(
        caller = %auth.0.did,
        domain = %canonical,
        set_as_default = req.set_as_default,
        fanout_sent = sent,
        fanout_failed = failed,
        "domain created"
    );
    Ok((StatusCode::CREATED, Json(stored)))
}

/// `PUT /api/domains/{name}` request body. Subset of `DomainEntry`
/// fields that operators may rotate without recreating the domain.
/// Names are immutable (the underlying `update_domain` enforces this).
#[derive(Debug, Deserialize)]
pub struct UpdateDomainRequest {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub scheme: Option<DomainUrlScheme>,
    #[serde(default)]
    pub branding: Option<DomainBranding>,
    #[serde(default)]
    pub witnesses: Option<Vec<String>>,
    #[serde(default)]
    pub watchers: Option<Vec<String>>,
    #[serde(default)]
    pub quota: Option<DomainQuota>,
    #[serde(default)]
    pub well_known_enabled: Option<bool>,
}

/// `PUT /api/domains/{name}` — Admin updates metadata. Status,
/// default-flag, and created_at are preserved; use the dedicated
/// disable / enable / set-default routes for those.
pub async fn update_domain_route(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<DomainEntry>, AppError> {
    let canonical = normalize_domain_name(&name)?;
    let mut entry = domain::get_domain(&state.store, &canonical)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("domain '{canonical}'")))?;
    if let Some(label) = req.label {
        entry.label = Some(label);
    }
    if let Some(scheme) = req.scheme {
        entry.scheme = scheme;
    }
    if let Some(branding) = req.branding {
        entry.branding = Some(branding);
    }
    if let Some(witnesses) = req.witnesses {
        entry.witnesses = Some(witnesses);
    }
    if let Some(watchers) = req.watchers {
        entry.watchers = Some(watchers);
    }
    if let Some(quota) = req.quota {
        entry.quota = Some(quota);
    }
    if let Some(wk) = req.well_known_enabled {
        entry.well_known_enabled = wk;
    }
    domain::update_domain(&state.store, &canonical, &entry).await?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(&state, &entry).await;
    info!(
        caller = %auth.0.did,
        domain = %canonical,
        fanout_sent = sent,
        fanout_failed = failed,
        "domain updated"
    );
    Ok(Json(entry))
}

/// `POST /api/domains/{name}/disable` — Admin disables a domain.
/// Refused when the domain is the current default (operator must
/// re-point default first per the spec retain-then-purge rules).
pub async fn disable_domain_route(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<DomainEntry>, AppError> {
    let canonical = normalize_domain_name(&name)?;
    let grace_seconds = pending_purge::parse_grace_string(
        &state.config.hosting.disable_purge_grace,
    )
    .map_err(|e| {
        AppError::Internal(format!(
            "config [hosting] disable_purge_grace='{}' is invalid: {e}",
            state.config.hosting.disable_purge_grace
        ))
    })?;
    domain::disable_domain(
        &state.store,
        &canonical,
        now_epoch(),
        grace_seconds,
        &auth.0.did,
    )
    .await?;
    let entry = domain::get_domain(&state.store, &canonical)
        .await?
        .ok_or_else(|| AppError::Internal(format!("domain '{canonical}' missing after disable")))?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(&state, &entry).await;
    info!(
        caller = %auth.0.did,
        domain = %canonical,
        grace_seconds,
        fanout_sent = sent,
        fanout_failed = failed,
        "domain disabled (soft-delete scheduled)"
    );
    Ok(Json(entry))
}

/// `POST /api/domains/{name}/enable` — Admin re-enables a previously
/// disabled domain. No-op when already active.
pub async fn enable_domain_route(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<DomainEntry>, AppError> {
    let canonical = normalize_domain_name(&name)?;
    domain::enable_domain(&state.store, &canonical).await?;
    let entry = domain::get_domain(&state.store, &canonical)
        .await?
        .ok_or_else(|| AppError::Internal(format!("domain '{canonical}' missing after enable")))?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(&state, &entry).await;
    info!(
        caller = %auth.0.did,
        domain = %canonical,
        fanout_sent = sent,
        fanout_failed = failed,
        "domain enabled"
    );
    Ok(Json(entry))
}

/// Query string for [`delete_domain_route`].
#[derive(Debug, Deserialize)]
pub struct DeleteDomainQuery {
    /// When `true`, fan out a `domain.purge/1.0` (T30) DIDComm message
    /// to every server instance whose `served_domains` lists this
    /// domain before deleting the local record. Default `false` — the
    /// existing "delete record only" semantics are preserved.
    #[serde(default)]
    pub purge_servers: bool,
}

/// `DELETE /api/domains/{name}` — Admin force-deletes a disabled
/// domain, bypassing the `hosting.disable_purge_grace` window the
/// background sweep otherwise waits out.
///
/// Two-step safety mirrors the existing flow: the domain must already
/// be disabled (operator already saw the "503 + cooling-off" copy and
/// re-pointed the default if needed). Refusing on Active means a
/// single fat-finger can't wipe a live domain. Refusing on default is
/// enforced by `delete_domain_record` itself and surfaces as `Conflict`.
///
/// `?purge_servers=true` extends the call to a one-click "purge + delete":
/// each registry instance whose `served_domains` includes this domain
/// receives a `domain.purge/1.0` DIDComm message (T30) before the
/// control-plane record is removed. The purge is fire-and-forget on
/// the DIDComm side — `handle_domain_ack` will drop the domain out of
/// `served_domains` as servers ack back, but the local delete proceeds
/// without waiting.
///
/// The pending-purge row (if any) is cancelled after the record is
/// removed so the next sweep doesn't try to delete a row that's
/// already gone.
pub async fn delete_domain_route(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(opts): Query<DeleteDomainQuery>,
) -> Result<StatusCode, AppError> {
    let canonical = normalize_domain_name(&name)?;
    let entry = domain::get_domain(&state.store, &canonical)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("domain '{canonical}'")))?;
    if entry.status == DomainStatus::Active {
        return Err(AppError::Conflict(format!(
            "cannot delete '{canonical}' — domain is Active; disable it first"
        )));
    }

    // Optional: fanout MSG_DOMAIN_PURGE to every server instance
    // serving this domain. Best-effort per instance — a failure to
    // enqueue for one server must not block the others or the local
    // delete. Anything we miss here will surface in the audit log;
    // operators can fire `/purge` manually on those servers.
    let mut purged_servers: u32 = 0;
    if opts.purge_servers {
        match crate::registry::list_instances(&state.registry_ks).await {
            Ok(instances) => {
                for inst in instances {
                    if !inst.served_domains.iter().any(|d| d == &canonical) {
                        continue;
                    }
                    let Some(target_did) = inst.metadata.get("did").and_then(|v| v.as_str()) else {
                        warn!(
                            instance_id = %inst.instance_id,
                            "purge fanout: instance has no `did` in metadata — skipping"
                        );
                        continue;
                    };
                    match crate::server_push::send_domain_purge(&state, target_did, &canonical)
                        .await
                    {
                        Ok(()) => purged_servers += 1,
                        Err(e) => warn!(
                            instance_id = %inst.instance_id,
                            target_did,
                            error = %e,
                            "purge fanout: send_domain_purge failed; continuing"
                        ),
                    }
                }
            }
            Err(e) => warn!(
                error = %e,
                "purge fanout: failed to list registry instances; skipping fanout"
            ),
        }
    }

    domain::delete_domain_record(&state.store, &canonical).await?;
    // Best-effort: any pending_purge row was either consumed by the
    // sweep or never scheduled (legacy disable before the feature
    // shipped). Either way, leaving a stale row would be harmless but
    // ugly in audit logs.
    let _ = pending_purge::cancel(&state.store, &canonical).await;
    info!(
        caller = %auth.0.did,
        domain = %canonical,
        purge_servers = opts.purge_servers,
        purged_servers,
        "domain force-deleted (admin override of grace window)"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/domains/{name}/set-default` — Admin makes a domain the
/// new system default. Fails if the target is disabled (per spec).
pub async fn set_default_domain_route(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<DomainEntry>, AppError> {
    let canonical = normalize_domain_name(&name)?;
    domain::set_default_domain(&state.store, &canonical).await?;
    let entry = domain::get_domain(&state.store, &canonical)
        .await?
        .ok_or_else(|| {
            AppError::Internal(format!("domain '{canonical}' missing after set-default"))
        })?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(&state, &entry).await;
    info!(
        caller = %auth.0.did,
        domain = %canonical,
        fanout_sent = sent,
        fanout_failed = failed,
        "domain set as default"
    );
    Ok(Json(entry))
}

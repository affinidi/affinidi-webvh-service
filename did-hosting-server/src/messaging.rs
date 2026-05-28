//! DIDComm sync handlers for the DID Hosting server edge node.
//!
//! The server is a read-only node that receives `sync-update` and
//! `sync-delete` messages from the control plane via the mediator.
//! All DID provisioning (VTA protocol) is handled by the control plane.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, MiddlewareResult, Next, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    middleware_fn, trust_ping_handler,
};
use serde_json::{Value, json};
use tracing::{info, warn};

use did_hosting_common::didcomm_types::*;
use did_hosting_common::server::problem_report::log_problem_report;

// (The ACL helpers used to be needed here for per-handler `Admin|Service` checks
// on the domain ops; the wave-2 follow-up replaced those with
// `require_control_plane` so the ACL surface is no longer touched from this file.)
use crate::server::AppState;

/// Sync messages overwrite or delete arbitrary DIDs by mnemonic, so they must
/// originate from the configured control plane — not merely any Service-role
/// DID in the local ACL. If no `control_did` is configured all sync messages
/// are rejected, which is correct: a server without a control plane has no
/// legitimate sender for them.
fn require_control_plane(sender: &str, state: &AppState) -> Result<(), (String, Value)> {
    if state.config.control_did.as_deref() != Some(sender) {
        warn!(
            did = sender,
            "sync message rejected: sender is not the configured control plane"
        );
        return Err(problem_report(
            "e.p.did.unauthorized",
            "sync messages must originate from the configured control plane",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the DIDComm router for the DID Hosting server.
///
/// Handles only sync messages from the control plane (sync-update,
/// sync-delete) and domain assignment messages (assign / unassign,
/// T28). VTA provisioning is handled by the control plane.
pub fn build_server_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route(MSG_SERVER_REGISTER_ACK, handler_fn(handle_register_ack))?
        .route(MSG_HEALTH_PING, handler_fn(handle_health_ping))?
        .route(MSG_STATS_ACK, handler_fn(ignore_handler))?
        .route(MSG_SYNC_UPDATE, handler_fn(handle_sync_update))?
        .route(MSG_SYNC_DELETE, handler_fn(handle_sync_delete))?
        .route(MSG_DOMAIN_ASSIGN, handler_fn(handle_domain_assign))?
        .route(MSG_DOMAIN_UNASSIGN, handler_fn(handle_domain_unassign))?
        .route(MSG_DOMAIN_PURGE, handler_fn(handle_domain_purge))?
        .route(MSG_DOMAIN_UPSERT, handler_fn(handle_domain_upsert))?
        .fallback(handler_fn(handle_fallback))
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_sender_did(true),
        )
        .layer(middleware_fn(filtered_request_logging)))
}

/// Request logging middleware that silences noisy health/stats messages.
async fn filtered_request_logging(
    ctx: HandlerContext,
    message: Message,
    meta: affinidi_messaging_didcomm::UnpackMetadata,
    next: Next,
) -> MiddlewareResult {
    const QUIET: &[&str] = &[
        MSG_HEALTH_PING,
        MSG_HEALTH_PONG,
        MSG_STATS_ACK,
        MESSAGE_PICKUP_STATUS_TYPE,
    ];

    let msg_type = message.typ.clone();
    let result = next.run(ctx, message, meta).await;

    if !QUIET.iter().any(|t| msg_type == *t) {
        let status = match &result {
            Ok(Some(_)) => "ok(response)",
            Ok(None) => "ok(empty)",
            Err(_) => "error",
        };
        info!(message_type = %msg_type, status, "DIDComm request processed");
    }

    result
}

// ---------------------------------------------------------------------------
// Registration ack
// ---------------------------------------------------------------------------

async fn handle_register_ack(
    _ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let instance_id = message
        .body
        .get("instance_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    info!(instance_id, "registration acknowledged by control plane");
    Ok(None)
}

// ---------------------------------------------------------------------------
// Health ping (control plane → server → control plane)
// ---------------------------------------------------------------------------

async fn handle_health_ping(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let did_count = state
        .dids_ks
        .prefix_iter_raw("did:")
        .await
        .map(|v| v.len() as u64)
        .unwrap_or(0);

    Ok(Some(
        DIDCommResponse::new(
            MSG_HEALTH_PONG.to_string(),
            json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "did_count": did_count,
            }),
        )
        .thid(message.id.clone()),
    ))
}

// ---------------------------------------------------------------------------
// Sync handlers (control plane → server via mediator)
// ---------------------------------------------------------------------------

async fn handle_sync_update(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;

    let (response_type, response_body) = match do_sync_update(sender, &state, &message).await {
        Ok(r) => r,
        Err(e) => problem_report("e.p.did.internal-error", &e),
    };

    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

async fn handle_sync_delete(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;

    let (response_type, response_body) = match do_sync_delete(sender, &state, &message).await {
        Ok(r) => r,
        Err(e) => problem_report("e.p.did.internal-error", &e),
    };

    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

async fn handle_fallback(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = ctx.sender_did.as_deref();
    if log_problem_report("server", sender, &message) {
        return Ok(None);
    }
    warn!(
        sender = sender.unwrap_or("unknown"),
        msg_type = %message.typ,
        "unknown message type — ignoring"
    );
    Ok(None)
}

// ---------------------------------------------------------------------------
// Sync message handling
// ---------------------------------------------------------------------------

async fn do_sync_update(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use crate::control_register::apply_single_update;
    use did_hosting_common::DidSyncUpdate;

    if let Err(report) = require_control_plane(sender, state) {
        return Ok(report);
    }

    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or("missing 'mnemonic' in sync-update")?;
    let did_id = msg
        .body
        .get("did_id")
        .and_then(|v| v.as_str())
        .ok_or("missing 'did_id' in sync-update")?;
    let log_content = msg
        .body
        .get("log_content")
        .and_then(|v| v.as_str())
        .ok_or("missing 'log_content' in sync-update")?;
    let witness_content = msg
        .body
        .get("witness_content")
        .and_then(|v| v.as_str())
        .map(String::from);
    let version_count = msg
        .body
        .get("version_count")
        .and_then(|v| v.as_u64())
        .ok_or("missing 'version_count' in sync-update")?;

    let update = DidSyncUpdate {
        mnemonic: mnemonic.to_string(),
        did_id: did_id.to_string(),
        log_content: log_content.to_string(),
        witness_content,
        version_count,
    };

    apply_single_update(&state.dids_ks, &state.store, &update, &state.did_cache)
        .await
        .map_err(|e| e.to_string())?;

    info!(
        did = sender,
        mnemonic = %mnemonic,
        version_count,
        "applied DID sync update from control plane via mediator"
    );

    Ok((
        MSG_SYNC_UPDATE_ACK.to_string(),
        json!({ "mnemonic": mnemonic, "status": "applied" }),
    ))
}

async fn do_sync_delete(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use crate::did_ops;

    if let Err(report) = require_control_plane(sender, state) {
        return Ok(report);
    }

    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or("missing 'mnemonic' in sync-delete")?;

    let record: Option<did_ops::DidRecord> = state
        .dids_ks
        .get(did_ops::did_key(mnemonic))
        .await
        .unwrap_or(None);

    if let Some(record) = record {
        let mut batch = state.store.batch();
        batch.remove(&state.dids_ks, did_ops::did_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::content_log_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::content_witness_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::owner_key(&record.owner, mnemonic));
        batch.remove(&state.dids_ks, did_ops::watcher_sync_key(mnemonic));
        batch.commit().await.map_err(|e| e.to_string())?;

        info!(did = sender, mnemonic = %mnemonic, "deleted DID via sync from control plane");
    } else {
        info!(mnemonic = %mnemonic, "sync delete: DID not found locally");
    }

    Ok((
        MSG_SYNC_DELETE_ACK.to_string(),
        json!({ "mnemonic": mnemonic, "status": "deleted" }),
    ))
}

// ---------------------------------------------------------------------------
// Domain assignment (T28, control plane → server)
// ---------------------------------------------------------------------------
//
// The control plane is the source of truth for which domains a server
// hosts. Both handlers are idempotent — re-assigning an already-
// assigned domain or unassigning an unknown domain returns a status
// ack rather than an error. Only Admin or Service-role callers are
// allowed; an ACL'd Service role is what the control-plane DID gets
// at register time (see `control_register::run`).

async fn handle_domain_assign(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    let (response_type, response_body) = match do_domain_assign(sender, &state, &message).await {
        Ok(r) => r,
        Err(e) => problem_report("e.p.domain.internal-error", &e),
    };
    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

async fn handle_domain_unassign(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    let (response_type, response_body) = match do_domain_unassign(sender, &state, &message).await {
        Ok(r) => r,
        Err(e) => problem_report("e.p.domain.internal-error", &e),
    };
    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

async fn do_domain_assign(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use did_hosting_common::server::assignment::{AssignOutcome, assign};
    use did_hosting_common::server::domain::normalize_domain_name;
    use did_hosting_common::server::pending_purge::{self, CancelOutcome};

    // Domain ops are at least as destructive as sync (`domain.purge`
    // deletes every DID under the name); apply the same control-plane
    // pinning rather than the looser Admin|Service ACL check that
    // accepts any peer admin / sibling service. Closes the gap where
    // a stale admin enrollment or compromised sibling could send a
    // forged domain.{assign,unassign,purge,upsert} and mutate this
    // server's local assignments.
    if let Err(report) = require_control_plane(sender, state) {
        return Ok(report);
    }

    let domain_raw = msg
        .body
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("missing 'domain' in domain/assign")?;
    let domain = normalize_domain_name(domain_raw).map_err(|e| e.to_string())?;

    let now = crate::auth::session::now_epoch();
    let outcome = assign(&state.store, &domain, sender, now)
        .await
        .map_err(|e| e.to_string())?;

    let (status, log_msg) = match &outcome {
        AssignOutcome::Created(_) => ("assigned", "domain assigned"),
        AssignOutcome::Existing(_) => ("already_assigned", "domain re-assign no-op"),
    };

    // T30: re-assign within the grace window cancels any pending
    // purge. Audit-log the cancellation so an operator can answer
    // "did my data survive the unassign / re-assign round trip?".
    let cancelled = pending_purge::cancel(&state.store, &domain)
        .await
        .map_err(|e| e.to_string())?;
    if let CancelOutcome::Removed(prev) = cancelled {
        info!(
            did = sender,
            domain = %domain,
            scheduled_at = prev.scheduled_at,
            grace_seconds = prev.grace_seconds,
            "domain re-assign cancelled pending purge — data retained"
        );
    }

    info!(
        did = sender,
        domain = %domain,
        status,
        "{log_msg}"
    );

    Ok((
        MSG_DOMAIN_ASSIGN_ACK.to_string(),
        json!({ "domain": domain, "status": status }),
    ))
}

async fn do_domain_unassign(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use did_hosting_common::server::assignment::{UnassignOutcome, unassign};
    use did_hosting_common::server::domain::normalize_domain_name;
    use did_hosting_common::server::pending_purge::{self, parse_grace_string};

    // See do_domain_assign — control-plane pinning, not Admin|Service.
    if let Err(report) = require_control_plane(sender, state) {
        return Ok(report);
    }

    let domain_raw = msg
        .body
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("missing 'domain' in domain/unassign")?;
    let domain = normalize_domain_name(domain_raw).map_err(|e| e.to_string())?;

    let outcome = unassign(&state.store, &domain)
        .await
        .map_err(|e| e.to_string())?;

    let (status, log_msg) = match &outcome {
        UnassignOutcome::Removed(_) => ("unassigned", "domain unassigned"),
        UnassignOutcome::Missing => ("not_assigned", "domain unassign no-op"),
    };

    // T30: schedule a grace-period purge. Idempotent — overwriting an
    // existing pending purge just resets the timer, which is the
    // right behaviour for "operator unassigned, then unassigned
    // again". Stops at the schedule step here; the actual purge sweep
    // (which deletes DID records whose domain matches) lands in T30's
    // follow-up.
    if matches!(outcome, UnassignOutcome::Removed(_)) {
        // Source the grace from `config.hosting.unassigned_purge_grace`.
        // A misconfigured / unparseable value defaults to 2h and emits
        // a warn — the server keeps working with a sensible default
        // rather than failing the unassign entirely.
        let grace_seconds = parse_grace_string(&state.config.hosting.unassigned_purge_grace)
            .unwrap_or_else(|e| {
                warn!(
                    error = %e,
                    config = %state.config.hosting.unassigned_purge_grace,
                    "unassigned_purge_grace unparseable; defaulting to 2h"
                );
                2 * 60 * 60
            });
        let now = crate::auth::session::now_epoch();
        if let Err(e) = pending_purge::schedule(
            &state.store,
            &domain,
            now,
            grace_seconds,
            "grace-expired",
            sender,
        )
        .await
        {
            warn!(
                error = %e,
                domain = %domain,
                "failed to schedule pending purge; domain is unassigned but \
                 data retention is unbounded until manual cleanup"
            );
        } else {
            info!(
                did = sender,
                domain = %domain,
                grace_seconds,
                "pending purge scheduled"
            );
        }
    }

    info!(
        did = sender,
        domain = %domain,
        status,
        "{log_msg}"
    );

    Ok((
        MSG_DOMAIN_UNASSIGN_ACK.to_string(),
        json!({ "domain": domain, "status": status }),
    ))
}

async fn handle_domain_purge(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    let (response_type, response_body) = match do_domain_purge(sender, &state, &message).await {
        Ok(r) => r,
        Err(e) => problem_report("e.p.domain.internal-error", &e),
    };
    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

/// Handle `MSG_DOMAIN_PURGE` — admin "Purge now" Trust Task.
///
/// Bypasses the grace period and immediately deletes every DID
/// record on the named domain. The unassignment must already have
/// happened (the domain is removed from KS_ASSIGNMENTS); admins can
/// run an explicit unassign-then-purge sequence, or purge a domain
/// whose grace timer is still running. Either way the pending
/// purge entry (if any) is cleared after the synchronous purge.
async fn do_domain_purge(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use did_hosting_common::server::assignment;
    use did_hosting_common::server::domain::normalize_domain_name;
    use did_hosting_common::server::domain_purge::purge_domain_dids;
    use did_hosting_common::server::pending_purge;

    // See do_domain_assign — control-plane pinning. domain.purge wipes
    // every DID under the name; a peer admin / sibling service should
    // never reach this handler.
    if let Err(report) = require_control_plane(sender, state) {
        return Ok(report);
    }

    let domain_raw = msg
        .body
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("missing 'domain' in domain/purge")?;
    let domain = normalize_domain_name(domain_raw).map_err(|e| e.to_string())?;

    // Freshness check — defends against the replay-after-reassign-
    // within-grace scenario:
    //   1. Operator unassigns foo.example → control plane queues
    //      purge → mediator goes down before delivery.
    //   2. Operator changes their mind, re-assigns foo.example within
    //      the grace window; server stores a new KS_ASSIGNMENTS row
    //      with a fresh `assigned_at`.
    //   3. Mediator comes back, delivers the stale purge.
    //   4. Without this check, the data the operator chose to keep
    //      gets wiped.
    // If a current assignment row exists AND the message's
    // `created_time` is older than the assignment's `assigned_at`,
    // refuse the purge. Messages without `created_time` are treated
    // as fresh for backwards compatibility — older DIDComm peers
    // don't set the header, and the existing `MAX_AGE_SECS` outbox
    // sweep already drops very stale messages on the wire.
    if let Ok(Some(current)) = assignment::get(&state.store, &domain).await {
        let msg_created = msg.created_time.unwrap_or(0);
        if msg_created != 0 && msg_created < current.assigned_at {
            warn!(
                did = sender,
                domain = %domain,
                msg_created_time = msg_created,
                assignment_assigned_at = current.assigned_at,
                "domain/purge refused: message older than current assignment (likely a stale purge replayed after reassign-within-grace)"
            );
            return Ok(problem_report(
                "e.p.domain.stale-purge",
                "purge message predates the current assignment; refusing to wipe data that has since been re-assigned",
            ));
        }
    }

    let report = purge_domain_dids(&state.store, &domain, "admin-immediate")
        .await
        .map_err(|e| e.to_string())?;

    // Clear any pending purge — the synchronous purge supersedes it.
    let _ = pending_purge::cancel(&state.store, &domain).await;

    info!(
        did = sender,
        domain = %domain,
        deleted = report.deleted,
        skipped_no_domain = report.skipped_no_domain,
        skipped_other_domain = report.skipped_other_domain,
        "domain purged via admin Purge Now"
    );

    Ok((
        MSG_DOMAIN_PURGE_ACK.to_string(),
        json!({
            "domain": domain,
            "deleted": report.deleted,
            "skipped_no_domain": report.skipped_no_domain,
        }),
    ))
}

async fn handle_domain_upsert(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    let (response_type, response_body) = match do_domain_upsert(sender, &state, &message).await {
        Ok(r) => r,
        Err(e) => problem_report("e.p.domain.internal-error", &e),
    };
    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

/// Handle `MSG_DOMAIN_UPSERT`. Single-message replication of any
/// `DomainEntry` mutation from the control plane (create, update,
/// disable, enable).
///
/// Behaviour:
/// - Upserts the local DomainEntry — `create_domain` if absent,
///   `update_domain` otherwise.
/// - If the incoming entry is `Disabled` and carries
///   `disabled_at` + `purge_at`, schedules a `disable-grace`
///   pending_purge so this server's sweeper eventually deletes the
///   entry + all DIDs hosted under the domain.
/// - If the incoming entry is `Active`, cancels any pending purge —
///   this is how a re-enable within the grace window cancels the
///   removal on the server side.
///
/// Idempotent. Re-sending the same entry produces an
/// `already_current` status in the ack rather than churn.
async fn do_domain_upsert(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use did_hosting_common::server::domain::{
        DISABLE_PURGE_REASON, DomainEntry, DomainStatus, create_domain, get_domain,
        normalize_domain_name, update_domain,
    };
    use did_hosting_common::server::pending_purge;

    // See do_domain_assign — control-plane pinning. domain.upsert
    // mutates the canonical domain record and silently changes
    // status / metadata; restrict to the configured control plane.
    if let Err(report) = require_control_plane(sender, state) {
        return Ok(report);
    }

    let entry: DomainEntry = serde_json::from_value(msg.body.clone())
        .map_err(|e| format!("malformed 'entry' in domain/upsert (expected a DomainEntry): {e}"))?;
    let canonical = normalize_domain_name(&entry.name).map_err(|e| e.to_string())?;
    if canonical != entry.name {
        return Err(format!(
            "domain/upsert sender sent non-canonical name '{}' (expected '{canonical}')",
            entry.name
        ));
    }

    let existed = get_domain(&state.store, &canonical)
        .await
        .map_err(|e| e.to_string())?
        .is_some();
    if existed {
        update_domain(&state.store, &canonical, &entry)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        create_domain(&state.store, &entry)
            .await
            .map_err(|e| e.to_string())?;
    }

    // Status-driven side effects.
    let status_str = match entry.status {
        DomainStatus::Active => {
            // Re-enable cancels any in-flight grace timer.
            let _ = pending_purge::cancel(&state.store, &canonical).await;
            "active"
        }
        DomainStatus::Disabled => {
            if let (Some(disabled_at), Some(purge_at)) = (entry.disabled_at, entry.purge_at) {
                let grace_seconds = purge_at.saturating_sub(disabled_at);
                if let Err(e) = pending_purge::schedule(
                    &state.store,
                    &canonical,
                    disabled_at,
                    grace_seconds,
                    DISABLE_PURGE_REASON,
                    sender,
                )
                .await
                {
                    warn!(
                        error = %e,
                        domain = %canonical,
                        "domain/upsert: failed to schedule pending purge — local entry disabled, but grace sweep won't fire"
                    );
                }
            } else {
                warn!(
                    domain = %canonical,
                    "domain/upsert: status=Disabled but timestamps missing — no grace timer scheduled"
                );
            }
            "disabled"
        }
    };

    let action = if existed { "updated" } else { "created" };
    info!(
        did = sender,
        domain = %canonical,
        action,
        status = status_str,
        "domain entry replicated"
    );

    Ok((
        MSG_DOMAIN_UPSERT_ACK.to_string(),
        json!({
            "domain": canonical,
            "action": action,
            "status": status_str,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_sender(ctx: &HandlerContext) -> Result<&str, DIDCommServiceError> {
    ctx.sender_did
        .as_deref()
        .map(|did| did.split('#').next().unwrap_or(did))
        .ok_or_else(|| DIDCommServiceError::Internal("missing sender DID".into()))
}

fn problem_report(code: &str, comment: &str) -> (String, Value) {
    (
        MSG_PROBLEM_REPORT.to_string(),
        json!({ "code": code, "comment": comment }),
    )
}

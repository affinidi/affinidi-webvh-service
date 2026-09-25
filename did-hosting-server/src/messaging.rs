//! Control-plane → edge operations for the DID Hosting server.
//!
//! The server is a read-only node: the control plane pushes it DID sync
//! (`sync/update`, `sync/batch`, `sync/delete`) and domain operations
//! (`domain/assign`, `unassign`, `purge`, `upsert`). All DID provisioning is
//! handled by the control plane.
//!
//! ## Every operation is a document the control plane signed
//!
//! These operations overwrite, delete or purge hosted DIDs, so the only thing
//! allowed to trigger them is the configured control plane — and "the control
//! plane" means *a document signed by the control plane's DID*, not a message a
//! transport reported as coming from it. Each operation travels as a Trust Task
//! document (inside the DIDComm trust-task envelope, or as a TSP frame) and is
//! applied only after [`verify_control_plane`] has established, from the
//! document's own proof, that:
//!
//! - its `issuer` is exactly `control_did`, and the proof's
//!   `verificationMethod` is one of that DID's keys;
//! - it is addressed to this server (`recipient == server_did`);
//! - it is fresh (`issuedAt`) and not a replay of a document already applied.
//!
//! The cores below take a [`VerifiedControlPlane`], which only that function
//! constructs, so an unverified path to them does not type-check. The
//! transport's own report of the sender is used for nothing but a consistency
//! check against the proof.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, MiddlewareResult, Next, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    middleware_fn, trust_ping_handler,
};
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use did_hosting_common::didcomm_types::*;
use did_hosting_common::server::problem_report::log_problem_report;
use did_hosting_common::server::replay::ReplayCache;
use did_hosting_common::server::trust_tasks::{TransportBoundVerifier, verify_sender_bound};

use crate::server::AppState;

/// The control-plane operations this server applies. Each is a signed Trust
/// Task document; see the module docs.
pub const CONTROL_PLANE_OPS: &[&str] = &[
    MSG_SYNC_UPDATE,
    MSG_SYNC_BATCH,
    MSG_SYNC_DELETE,
    MSG_DOMAIN_ASSIGN,
    MSG_DOMAIN_UNASSIGN,
    MSG_DOMAIN_PURGE,
    MSG_DOMAIN_UPSERT,
];

/// Documents already applied, keyed on `(issuer, document id)`. Process-wide:
/// an edge has exactly one control plane, and the cache only needs to outlive
/// the freshness window.
static REPLAY_CACHE: std::sync::LazyLock<ReplayCache> = std::sync::LazyLock::new(ReplayCache::new);

/// Proof that a document was signed by the configured control plane, addressed
/// to this server, fresh, and not previously applied. Constructed only by
/// [`verify_control_plane`].
#[derive(Debug)]
pub struct VerifiedControlPlane {
    /// The control plane's DID (the proven issuer).
    pub did: String,
    /// The document's signed `issuedAt`, epoch seconds.
    pub issued_at: u64,
}

/// The proof verifier this server checks control-plane documents with, built
/// over its DID resolver. `None` when no resolver is configured, in which case
/// no control-plane document can be accepted.
pub fn state_verifier(state: &AppState) -> Option<TransportBoundVerifier> {
    state
        .did_resolver
        .clone()
        .map(TransportBoundVerifier::with_did_cache)
}

/// Establish that `doc` comes from the configured control plane. See the module
/// docs for what is checked. `transport_sender` is the carrying transport's
/// report, which must agree with the proof but is never sufficient alone.
pub async fn verify_control_plane<P>(
    state: &AppState,
    transport_sender: Option<&str>,
    doc: &trust_tasks_rs::TrustTask<P>,
    verifier: &TransportBoundVerifier,
) -> Result<VerifiedControlPlane, trust_tasks_rs::RejectReason>
where
    P: serde::Serialize + Send + Sync,
{
    use trust_tasks_rs::RejectReason;

    // No configured control plane → no legitimate sender for these ops.
    let control_did =
        state
            .config
            .control_did
            .as_deref()
            .ok_or_else(|| RejectReason::PermissionDenied {
                reason: "this server has no configured control plane".into(),
            })?;
    let my_did =
        state
            .config
            .server_did
            .as_deref()
            .ok_or_else(|| RejectReason::PermissionDenied {
                reason: "this server has no configured DID".into(),
            })?;
    let did = verify_sender_bound(doc, Some(control_did), transport_sender, my_did, verifier)
        .await
        .map_err(|e| {
            warn!(
                sender = transport_sender.unwrap_or("unknown"),
                type_uri = %doc.type_uri,
                error = %e,
                "control-plane document rejected: not signed by the configured control plane"
            );
            e.reject_reason()
        })?;
    match REPLAY_CACHE.check(&did, &doc.id) {
        Ok(()) => {}
        Err(did_hosting_common::server::replay::ReplayError::Duplicate) => {
            warn!(did, doc_id = %doc.id, "control-plane document rejected: replay");
            return Err(RejectReason::IdConflict);
        }
        Err(did_hosting_common::server::replay::ReplayError::Full) => {
            warn!(did, doc_id = %doc.id, "control-plane document deferred: replay cache full");
            return Err(RejectReason::Unavailable { retry_after: None });
        }
    }
    let issued_at = doc
        .issued_at
        .map(|t| t.timestamp().max(0) as u64)
        .unwrap_or_default();
    Ok(VerifiedControlPlane { did, issued_at })
}

/// Apply one control-plane operation document and return the (unsigned) reply
/// document: the op's `#response` on success, a `trust-task-error` otherwise.
///
/// Shared by the DIDComm envelope route and the TSP handler. Returns `None`
/// for a type that is not a control-plane operation.
pub async fn dispatch_control_plane_op(
    state: &AppState,
    transport_sender: Option<&str>,
    doc: trust_tasks_rs::TrustTask<Value>,
    verifier: &TransportBoundVerifier,
) -> Option<trust_tasks_rs::TrustTask<Value>> {
    let type_uri = doc.type_uri.to_string();
    if !CONTROL_PLANE_OPS.contains(&type_uri.as_str()) {
        return None;
    }
    let reply_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let control = match verify_control_plane(state, transport_sender, &doc, verifier).await {
        Ok(c) => c,
        Err(reason) => return Some(error_value(doc.reject_with(reply_id, reason))),
    };

    let result = match type_uri.as_str() {
        MSG_SYNC_UPDATE => do_sync_update(&control, state, &doc.payload).await,
        MSG_SYNC_BATCH => do_sync_batch(&control, state, &doc.payload).await,
        MSG_SYNC_DELETE => do_sync_delete(&control, state, &doc.payload).await,
        MSG_DOMAIN_ASSIGN => do_domain_assign(&control, state, &doc.payload).await,
        MSG_DOMAIN_UNASSIGN => do_domain_unassign(&control, state, &doc.payload).await,
        MSG_DOMAIN_PURGE => do_domain_purge(&control, state, &doc.payload).await,
        MSG_DOMAIN_UPSERT => do_domain_upsert(&control, state, &doc.payload).await,
        _ => unreachable!("CONTROL_PLANE_OPS gates this match"),
    };
    Some(match result {
        Ok((ack_type, body)) if ack_type != MSG_PROBLEM_REPORT => {
            let reply = doc.respond_with(reply_id, body);
            debug_assert_eq!(reply.type_uri.to_string(), ack_type);
            reply
        }
        Ok((_, body)) => error_value(
            doc.reject_with(
                reply_id,
                trust_tasks_rs::RejectReason::TaskFailed {
                    reason: body
                        .get("comment")
                        .and_then(Value::as_str)
                        .unwrap_or("the operation was refused")
                        .to_string(),
                    details: Some(body),
                },
            ),
        ),
        Err(e) => error_value(doc.reject_with(
            reply_id,
            trust_tasks_rs::RejectReason::TaskFailed {
                reason: e,
                details: None,
            },
        )),
    })
}

/// An error document as the untyped reply shape the transports carry.
fn error_value(err: trust_tasks_rs::ErrorResponse) -> trust_tasks_rs::TrustTask<Value> {
    let value = serde_json::to_value(&err).expect("error document serialises");
    serde_json::from_value(value).expect("error document re-reads as a TrustTask")
}

/// Sign a reply document with this server's identity so the control plane can
/// attribute it, returning it ready for the wire.
///
/// Error documents are signed too: a signed, non-retryable refusal is what lets
/// the control plane stop re-sending an op this server will never apply (an
/// unsigned one settles nothing there). A reply this server cannot sign is
/// dropped — the control plane refuses unsigned acks.
pub async fn seal_reply(
    state: &AppState,
    reply: trust_tasks_rs::TrustTask<Value>,
) -> Option<Value> {
    let (Some(identity), Some(server_did)) = (
        state.identity.as_deref(),
        state.config.server_did.as_deref(),
    ) else {
        warn!("cannot sign reply: service identity or server_did not loaded");
        return None;
    };
    let secret = match did_hosting_common::server::trust_tasks::identity_signing_secret(
        identity, server_did,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "cannot sign reply");
            return None;
        }
    };
    match did_hosting_common::server::trust_tasks::sign_document(&reply, &secret).await {
        Ok(signed) => serde_json::to_value(&signed).ok(),
        Err(e) => {
            warn!(error = %e, "cannot sign reply");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the DIDComm router for the DID Hosting server.
///
/// Every control-plane operation arrives as a signed Trust Task document in
/// the trust-task envelope; there are no bare-message routes for them.
pub fn build_server_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        // Trust-task documents carried over DIDComm. The same documents arrive
        // over TSP as raw frames (`crate::tsp`), and both land in the same
        // dispatchers — that is the transport-agnostic swap.
        .route(
            trust_tasks_didcomm::ENVELOPE_TYPE,
            handler_fn(handle_trust_tasks_envelope),
        )?
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
        MESSAGE_PICKUP_STATUS_TYPE,
        trust_tasks_didcomm::ENVELOPE_TYPE,
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

/// Inbound trust-task document carried in a DIDComm envelope.
///
/// The reply is returned rather than sent, so the messaging framework routes it
/// back over the same connection — a ping that arrived here is ponged here.
async fn handle_trust_tasks_envelope(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    // A routing hint only: every privileged document is authorised on its
    // proof, and this is merely required to agree with it.
    let sender = ctx.sender_did.as_deref();

    let doc: trust_tasks_rs::TrustTask<Value> = match serde_json::from_value(message.body.clone()) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                sender,
                error = %e,
                "trust-tasks envelope: inner body did not parse as TrustTask<Value>"
            );
            return Ok(None);
        }
    };

    let Some(reply) = dispatch_inbound_document(&state, sender, doc).await else {
        return Ok(None);
    };
    Ok(Some(
        DIDCommResponse::new(trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), reply)
            .thid(message.id.clone()),
    ))
}

/// Route an inbound Trust Task document — from either transport — to the
/// control-plane operations or the infrastructure ops, returning the sealed
/// reply, if any.
pub async fn dispatch_inbound_document(
    state: &AppState,
    sender: Option<&str>,
    doc: trust_tasks_rs::TrustTask<Value>,
) -> Option<Value> {
    let type_uri = doc.type_uri.to_string();
    if CONTROL_PLANE_OPS.contains(&type_uri.as_str()) {
        let Some(verifier) = state_verifier(state) else {
            warn!(%type_uri, "control-plane document refused: no DID resolver configured to verify it");
            return None;
        };
        let reply = dispatch_control_plane_op(state, sender, doc, &verifier).await?;
        return seal_reply(state, reply).await;
    }
    if crate::trust_tasks_infra::owns(&type_uri) {
        let reply = crate::trust_tasks_infra::dispatch(state, sender, doc).await?;
        return seal_reply(state, reply).await;
    }
    warn!(
        sender,
        %type_uri,
        "trust task of a type this server does not implement"
    );
    None
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
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), String> {
    let mnemonic = apply_sync_update_body(state, body).await?;
    debug!(did = %control.did, %mnemonic, "applied sync update");
    Ok((
        MSG_SYNC_UPDATE_ACK.to_string(),
        json!({ "mnemonic": mnemonic, "status": "applied" }),
    ))
}

/// A batch of sync updates in one message (`body.updates[]`, each the shape
/// [`do_sync_update`] applies).
///
/// Best-effort per entry: a single bad update is logged and skipped, matching
/// the per-DID path — whose failures are fire-and-forget over TSP — so one
/// malformed entry can't strand the rest of the batch. Anything skipped is
/// re-sent on the next delta sync.
async fn do_sync_batch(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), String> {
    let updates = body
        .get("updates")
        .and_then(|v| v.as_array())
        .ok_or("missing 'updates' array in sync-batch")?;

    let mut applied = 0usize;
    let mut failed = 0usize;
    for update in updates {
        match apply_sync_update_body(state, update).await {
            Ok(_) => applied += 1,
            Err(e) => {
                failed += 1;
                warn!(error = %e, "sync-batch: skipping an update that failed to apply");
            }
        }
    }
    debug!(
        did = %control.did,
        applied,
        failed,
        count = updates.len(),
        "applied DID sync batch from control plane"
    );
    Ok((
        MSG_SYNC_BATCH_ACK.to_string(),
        json!({ "applied": applied, "failed": failed }),
    ))
}

/// Apply one sync-update body — the shape `MSG_SYNC_UPDATE` carries and each
/// element of a `MSG_SYNC_BATCH`. Returns the mnemonic on success. Runs the
/// own-DID rotation check, so a batched update to the server's own DID is
/// treated exactly like a single one.
async fn apply_sync_update_body(state: &AppState, body: &Value) -> Result<String, String> {
    use crate::control_register::apply_single_update;
    use did_hosting_common::DidSyncUpdate;

    let mnemonic = body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or("missing 'mnemonic' in sync-update")?;
    let did_id = body
        .get("did_id")
        .and_then(|v| v.as_str())
        .ok_or("missing 'did_id' in sync-update")?;
    let log_content = body
        .get("log_content")
        .and_then(|v| v.as_str())
        .ok_or("missing 'log_content' in sync-update")?;
    let witness_content = body
        .get("witness_content")
        .and_then(|v| v.as_str())
        .map(String::from);
    let version_count = body
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

    apply_single_update(
        &state.dids_ks,
        &state.store,
        &update,
        &state.did_cache,
        state.config.public_url.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Duplicate of the canonical info line in
    // `control_register::apply_single_update`; keep it at debug so each synced
    // DID logs once at info, not twice.
    debug!(
        mnemonic = %mnemonic,
        version_count,
        "applied DID sync update from control plane via mediator"
    );

    // The second way this server's own DID can change: a control plane pushed a
    // new log entry for it. Same rotation check as the direct publish path.
    crate::identity_rotation::on_did_published(state, mnemonic).await;

    Ok(mnemonic.to_string())
}

async fn do_sync_delete(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), String> {
    use crate::did_ops;

    let mnemonic = body
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

        info!(did = %control.did, mnemonic = %mnemonic, "deleted DID via sync from control plane");
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
// ack rather than an error. Only documents signed by the configured control
// plane reach these cores (see `VerifiedControlPlane`).

async fn do_domain_assign(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), String> {
    use did_hosting_common::server::assignment::{AssignOutcome, assign};
    use did_hosting_common::server::domain::normalize_domain_name;
    use did_hosting_common::server::pending_purge::{self, CancelOutcome};

    let domain_raw = body
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("missing 'domain' in domain/assign")?;
    let domain = normalize_domain_name(domain_raw).map_err(|e| e.to_string())?;

    let now = crate::auth::session::now_epoch();
    let outcome = assign(&state.store, &domain, &control.did, now)
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
            did = %control.did,
            domain = %domain,
            scheduled_at = prev.scheduled_at,
            grace_seconds = prev.grace_seconds,
            "domain re-assign cancelled pending purge — data retained"
        );
    }

    info!(
        did = %control.did,
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
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), String> {
    use did_hosting_common::server::assignment::{UnassignOutcome, unassign};
    use did_hosting_common::server::domain::normalize_domain_name;
    use did_hosting_common::server::pending_purge::{self, parse_grace_string};

    let domain_raw = body
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
            &control.did,
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
                did = %control.did,
                domain = %domain,
                grace_seconds,
                "pending purge scheduled"
            );
        }
    }

    info!(
        did = %control.did,
        domain = %domain,
        status,
        "{log_msg}"
    );

    Ok((
        MSG_DOMAIN_UNASSIGN_ACK.to_string(),
        json!({ "domain": domain, "status": status }),
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
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), String> {
    use did_hosting_common::server::assignment;
    use did_hosting_common::server::domain::normalize_domain_name;
    use did_hosting_common::server::domain_purge::purge_domain_dids;
    use did_hosting_common::server::pending_purge;

    let domain_raw = body
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
    // If a current assignment row exists AND the document's signed
    // `issuedAt` is older than the assignment's `assigned_at`, refuse the
    // purge. `issuedAt` is covered by the control plane's proof, so unlike
    // the DIDComm `created_time` this used to read it is always present and
    // cannot be restamped in transit.
    if let Ok(Some(current)) = assignment::get(&state.store, &domain).await
        && control.issued_at < current.assigned_at
    {
        warn!(
            did = %control.did,
            domain = %domain,
            issued_at = control.issued_at,
            assignment_assigned_at = current.assigned_at,
            "domain/purge refused: document older than current assignment (likely a stale purge replayed after reassign-within-grace)"
        );
        return Ok(problem_report(
            "e.p.domain.stale-purge",
            "purge message predates the current assignment; refusing to wipe data that has since been re-assigned",
        ));
    }

    let report = purge_domain_dids(&state.store, &domain, "admin-immediate")
        .await
        .map_err(|e| e.to_string())?;

    // Clear any pending purge — the synchronous purge supersedes it.
    let _ = pending_purge::cancel(&state.store, &domain).await;

    info!(
        did = %control.did,
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
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), String> {
    use did_hosting_common::server::domain::{
        DISABLE_PURGE_REASON, DomainEntry, DomainStatus, create_domain, get_domain,
        normalize_domain_name, update_domain,
    };
    use did_hosting_common::server::pending_purge;

    let entry: DomainEntry = serde_json::from_value(body.clone())
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
                    &control.did,
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
        did = %control.did,
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

fn problem_report(code: &str, comment: &str) -> (String, Value) {
    (
        MSG_PROBLEM_REPORT.to_string(),
        json!({ "code": code, "comment": comment }),
    )
}

//! Control-plane → edge operations for the DID Hosting server.
//!
//! The server is a read-only node: the control plane pushes it DID sync
//! (`webvh/sync/update/0.2`, `sync/batch/0.1`, `sync/delete/0.2`) and domain
//! replication (`did-management/replica/domain/{upsert,assign,unassign,purge}`).
//! All DID provisioning is handled by the control plane.
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
//! A document that does not verify gets **no reply at all**: a signed refusal
//! would settle a directive the control plane never sent. A document that
//! verifies, but whose proven issuer is some other DID, is refused with the
//! task's declared `notAuthorized` code — a signed, non-retryable answer, as
//! each of these specifications requires.
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
    MSG_REPLICA_DOMAIN_ASSIGN,
    MSG_REPLICA_DOMAIN_UNASSIGN,
    MSG_REPLICA_DOMAIN_PURGE,
    MSG_REPLICA_DOMAIN_UPSERT,
    MSG_SERVER_METRICS,
];

/// `did-management/server/metrics/0.1`: this edge's operational metrics,
/// answered to its control plane only.
pub const MSG_SERVER_METRICS: &str =
    "https://trusttasks.org/spec/did-management/server/metrics/0.1";

/// The `notAuthorized` code `type_uri`'s specification declares: its proven
/// issuer is not this server's configured control plane.
fn not_authorized_code(type_uri: &str) -> Option<trust_tasks_rs::DeclaredErrorCode> {
    use trust_tasks_rs::specs::did_management::replica::domain::{assign, purge, unassign, upsert};
    Some(match type_uri {
        MSG_SYNC_UPDATE => sync_update::error_codes::NOT_AUTHORIZED,
        MSG_SYNC_BATCH => sync_batch::error_codes::NOT_AUTHORIZED,
        MSG_SYNC_DELETE => sync_delete::error_codes::NOT_AUTHORIZED,
        MSG_REPLICA_DOMAIN_ASSIGN => assign::v0_1::error_codes::NOT_AUTHORIZED,
        MSG_REPLICA_DOMAIN_UNASSIGN => unassign::v0_1::error_codes::NOT_AUTHORIZED,
        MSG_REPLICA_DOMAIN_PURGE => purge::v0_1::error_codes::NOT_AUTHORIZED,
        MSG_REPLICA_DOMAIN_UPSERT => upsert::v0_1::error_codes::NOT_AUTHORIZED,
        _ => return None,
    })
}

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

/// Build the proof verifier this server checks control-plane documents with,
/// over its DID resolver: the workspace's one construction,
/// [`did_hosting_common::server::trust_tasks::build_verifier`]. Built once, at
/// startup, and kept in [`AppState::trust_tasks_verifier`].
pub fn build_verifier(
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
) -> Option<std::sync::Arc<TransportBoundVerifier>> {
    did_hosting_common::server::trust_tasks::build_verifier(did_resolver)
}

/// The shared proof verifier (see [`build_verifier`]). `None` when no resolver
/// is configured, in which case no control-plane document can be accepted.
pub fn state_verifier(state: &AppState) -> Option<std::sync::Arc<TransportBoundVerifier>> {
    state.trust_tasks_verifier.clone()
}

/// Why a document was not accepted as the control plane's.
#[derive(Debug)]
pub enum Refusal {
    /// The document did not verify — no proof, a bad one, not addressed to
    /// this server, stale, a replay — or this server cannot check it. It gets
    /// no reply; the reason is kept for logs and tests.
    Unverified(trust_tasks_rs::RejectReason),
    /// The document verified, but its proven issuer is not this server's
    /// configured control plane. Answered with the task's `notAuthorized`.
    NotAuthorized {
        /// The proven issuer.
        issuer: String,
    },
}

impl Refusal {
    /// The framework rejection this refusal is logged (or answered) as.
    pub fn reject_reason(&self) -> trust_tasks_rs::RejectReason {
        match self {
            Refusal::Unverified(reason) => reason.clone(),
            Refusal::NotAuthorized { issuer } => trust_tasks_rs::RejectReason::PermissionDenied {
                reason: format!("{issuer} is not this server's control plane"),
            },
        }
    }
}

/// Establish that `doc` comes from the configured control plane. See the module
/// docs for what is checked. `transport_sender` is the carrying transport's
/// report, which must agree with the proof but is never sufficient alone.
pub async fn verify_control_plane<P>(
    state: &AppState,
    transport_sender: Option<&str>,
    doc: &trust_tasks_rs::TrustTask<P>,
    verifier: &TransportBoundVerifier,
) -> Result<VerifiedControlPlane, Refusal>
where
    P: serde::Serialize + Send + Sync,
{
    use trust_tasks_rs::RejectReason;

    // No configured control plane → no legitimate sender for these ops.
    let control_did = state.config.control_did.as_deref().ok_or_else(|| {
        Refusal::Unverified(RejectReason::PermissionDenied {
            reason: "this server has no configured control plane".into(),
        })
    })?;
    let my_did = state.config.server_did.as_deref().ok_or_else(|| {
        Refusal::Unverified(RejectReason::PermissionDenied {
            reason: "this server has no configured DID".into(),
        })
    })?;
    // The proof is checked against the in-band issuer, whoever that is, so a
    // well-formed document from another party can be told apart from one that
    // does not verify at all — only the first is answered.
    let did = verify_sender_bound(doc, None, transport_sender, my_did, verifier)
        .await
        .map_err(|e| {
            if e.is_transient() {
                warn!(
                    control_did,
                    type_uri = %doc.type_uri,
                    error = %e,
                    "control-plane document not verified: the signer's DID could not be \
                     resolved from this server (is its did.jsonl reachable?); it will be re-sent"
                );
            } else {
                warn!(
                    sender = transport_sender.unwrap_or("unknown"),
                    type_uri = %doc.type_uri,
                    error = %e,
                    "control-plane document rejected: it does not verify"
                );
            }
            Refusal::Unverified(e.reject_reason())
        })?;
    match REPLAY_CACHE.check(&did, &doc.id) {
        Ok(()) => {}
        Err(did_hosting_common::server::replay::ReplayError::Duplicate) => {
            warn!(did, doc_id = %doc.id, "control-plane document rejected: replay");
            return Err(Refusal::Unverified(RejectReason::IdConflict));
        }
        Err(did_hosting_common::server::replay::ReplayError::Full) => {
            warn!(did, doc_id = %doc.id, "control-plane document deferred: replay cache full");
            return Err(Refusal::Unverified(RejectReason::Unavailable {
                retry_after: None,
            }));
        }
    }
    if did != control_did {
        warn!(
            issuer = %did,
            control_did,
            type_uri = %doc.type_uri,
            "control-plane document refused: signed by a DID that is not this server's control plane"
        );
        return Err(Refusal::NotAuthorized { issuer: did });
    }
    let issued_at = doc
        .issued_at
        .map(|t| t.timestamp().max(0) as u64)
        .unwrap_or_default();
    Ok(VerifiedControlPlane { did, issued_at })
}

/// What [`dispatch_control_plane_op`] produced.
#[derive(Debug)]
pub enum ControlPlaneReply {
    /// The document came from the control plane; this reply — the op's
    /// `#response`, or a `trust-task-error` for an op that failed — is signed
    /// and sent back.
    Reply(trust_tasks_rs::TrustTask<Value>),
    /// The document failed [`verify_control_plane`]. Nothing is sent back: a
    /// signed refusal would settle an op that did not come from the control
    /// plane, or answer a stranger. The error document is kept for logs and
    /// tests only.
    Unverified(trust_tasks_rs::TrustTask<Value>),
}

impl ControlPlaneReply {
    /// The reply document, whichever kind it is.
    pub fn into_document(self) -> trust_tasks_rs::TrustTask<Value> {
        match self {
            ControlPlaneReply::Reply(d) | ControlPlaneReply::Unverified(d) => d,
        }
    }
}

/// Why a control-plane operation failed after the document was verified.
#[derive(Debug)]
pub(crate) enum OpError {
    /// The op is wrong and always will be (malformed, refused by policy, a log
    /// that does not verify): reported non-retryable, so the control plane
    /// stops re-sending it.
    Refused(String),
    /// Refused, under a code the op's specification declares.
    Declared(trust_tasks_rs::DeclaredErrorCode, String),
    /// This server could not apply it just now (storage, I/O): reported
    /// retryable, so the control plane keeps it queued.
    Transient(String),
}

impl From<&str> for OpError {
    fn from(e: &str) -> Self {
        OpError::Refused(e.to_string())
    }
}

impl From<String> for OpError {
    fn from(e: String) -> Self {
        OpError::Refused(e)
    }
}

impl From<crate::error::AppError> for OpError {
    fn from(e: crate::error::AppError) -> Self {
        use crate::error::AppError;
        match e {
            AppError::Io(_)
            | AppError::Store(_)
            | AppError::SecretStore(_)
            | AppError::Internal(_) => OpError::Transient(e.to_string()),
            other => OpError::Refused(other.to_string()),
        }
    }
}

impl OpError {
    fn reject_reason(self) -> trust_tasks_rs::ErrorPayload {
        match self {
            OpError::Refused(reason) => trust_tasks_rs::RejectReason::TaskFailed {
                reason,
                details: None,
            }
            .into(),
            OpError::Declared(code, message) => {
                trust_tasks_rs::ErrorPayload::from(code).with_message(message)
            }
            OpError::Transient(reason) => {
                warn!(%reason, "control-plane op not applied (transient); the control plane will re-send it");
                trust_tasks_rs::RejectReason::InternalError { reason }.into()
            }
        }
    }
}

/// Apply one control-plane operation document and return the (unsigned) reply.
///
/// Shared by the DIDComm envelope route and the TSP handler. Returns `None`
/// for a type that is not a control-plane operation.
pub async fn dispatch_control_plane_op(
    state: &AppState,
    transport_sender: Option<&str>,
    doc: trust_tasks_rs::TrustTask<Value>,
    verifier: &TransportBoundVerifier,
) -> Option<ControlPlaneReply> {
    let type_uri = doc.type_uri.to_string();
    if !CONTROL_PLANE_OPS.contains(&type_uri.as_str()) {
        return None;
    }
    let reply_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let control = match verify_control_plane(state, transport_sender, &doc, verifier).await {
        Ok(c) => c,
        Err(Refusal::NotAuthorized { issuer }) => {
            let message = format!("{issuer} is not this server's control plane");
            // A task that declares its own `notAuthorized` is refused with it;
            // `server/metrics` declares none, and gets the framework's.
            let payload = match not_authorized_code(&type_uri) {
                Some(code) => trust_tasks_rs::ErrorPayload::from(code).with_message(message),
                None => trust_tasks_rs::RejectReason::PermissionDenied { reason: message }.into(),
            };
            return Some(ControlPlaneReply::Reply(error_value(
                doc.reject_with(reply_id, payload),
            )));
        }
        Err(refusal) => {
            return Some(ControlPlaneReply::Unverified(error_value(
                doc.reject_with(reply_id, refusal.reject_reason()),
            )));
        }
    };

    let result = match type_uri.as_str() {
        MSG_SYNC_UPDATE => do_sync_update(&control, state, &doc.payload).await,
        MSG_SYNC_BATCH => do_sync_batch(&control, state, &doc.payload).await,
        MSG_SYNC_DELETE => do_sync_delete(&control, state, &doc.payload).await,
        MSG_REPLICA_DOMAIN_ASSIGN => do_domain_assign(&control, state, &doc.payload).await,
        MSG_REPLICA_DOMAIN_UNASSIGN => do_domain_unassign(&control, state, &doc.payload).await,
        MSG_REPLICA_DOMAIN_PURGE => do_domain_purge(&control, state, &doc.payload).await,
        MSG_REPLICA_DOMAIN_UPSERT => do_domain_upsert(&control, state, &doc.payload).await,
        MSG_SERVER_METRICS => do_server_metrics(state, &doc.payload).await,
        _ => unreachable!("CONTROL_PLANE_OPS gates this match"),
    };
    Some(ControlPlaneReply::Reply(match result {
        Ok((ack_type, body)) => {
            let reply = doc.respond_with(reply_id, body);
            debug_assert_eq!(reply.type_uri.to_string(), ack_type);
            reply
        }
        Err(e) => error_value(doc.reject_with(reply_id, e.reject_reason())),
    }))
}

/// An error document as the untyped reply shape the transports carry.
fn error_value(err: trust_tasks_rs::ErrorResponse) -> trust_tasks_rs::TrustTask<Value> {
    let value = serde_json::to_value(&err).expect("error document serialises");
    serde_json::from_value(value).expect("error document re-reads as a TrustTask")
}

/// Sign a reply document with this server's identity so the control plane can
/// attribute it, returning it ready for the wire.
///
/// Error documents for ops that came from the control plane are signed too: a
/// signed, non-retryable refusal is what lets the control plane stop re-sending
/// an op this server will never apply (an unsigned one settles nothing there).
/// A document that did not verify as the control plane's gets no reply at all
/// ([`ControlPlaneReply::Unverified`]). A reply this server cannot sign is
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
    let Some((typ, body)) =
        run_trust_tasks_envelope(&state, ctx.sender_did.as_deref(), &message).await
    else {
        return Ok(None);
    };
    Ok(Some(
        DIDCommResponse::new(typ, body).thid(message.id.clone()),
    ))
}

/// The DIDComm envelope entry point, without the messaging framework around
/// it: read the Trust Task document the envelope carries, dispatch it, and
/// return the reply envelope's type and body. `None` when there is nothing to
/// answer.
pub async fn run_trust_tasks_envelope(
    state: &AppState,
    sender: Option<&str>,
    message: &Message,
) -> Option<(String, Value)> {
    let doc: trust_tasks_rs::TrustTask<Value> = match serde_json::from_value(message.body.clone()) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                sender,
                error = %e,
                "trust-tasks envelope: inner body did not parse as TrustTask<Value>"
            );
            return None;
        }
    };
    let reply = dispatch_inbound_document(state, sender, doc).await?;
    Some((trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), reply))
}

/// Route an inbound Trust Task document — from either transport — to the
/// control-plane operations or the infrastructure ops, returning the sealed
/// reply, if any.
pub async fn dispatch_inbound_document(
    state: &AppState,
    sender: Option<&str>,
    doc: trust_tasks_rs::TrustTask<Value>,
) -> Option<Value> {
    // A reply to a request this edge sent (its reconcile listing) goes to the
    // task awaiting it, which verifies it; it is never dispatched as a request.
    let doc = crate::replication::deliver_reply(doc)?;
    let type_uri = doc.type_uri.to_string();
    if CONTROL_PLANE_OPS.contains(&type_uri.as_str()) {
        let Some(verifier) = state_verifier(state) else {
            warn!(%type_uri, "control-plane document refused: no DID resolver configured to verify it");
            return None;
        };
        return match dispatch_control_plane_op(state, sender, doc, &verifier).await? {
            ControlPlaneReply::Reply(reply) => seal_reply(state, reply).await,
            ControlPlaneReply::Unverified(_) => None,
        };
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

use trust_tasks_rs::specs::webvh::sync::{
    batch::v0_1 as sync_batch, delete::v0_2 as sync_delete, update::v0_2 as sync_update,
};

/// Read a control-plane payload into its generated type. The schemas are
/// closed, so a member they do not define — 0.1's snake_case among them — is
/// refused rather than ignored.
fn payload<P: serde::de::DeserializeOwned>(body: &Value, what: &str) -> Result<P, OpError> {
    serde_json::from_value(body.clone())
        .map_err(|e| OpError::Refused(format!("{what} payload does not fit its schema: {e}")))
}

/// A reply body through its generated type, so it leaves only in the shape its
/// schema allows.
fn reply<R: serde::Serialize + serde::de::DeserializeOwned>(
    body: Value,
    what: &str,
) -> Result<Value, OpError> {
    let typed: R = serde_json::from_value(body)
        .map_err(|e| OpError::Transient(format!("{what} reply does not fit its schema: {e}")))?;
    serde_json::to_value(typed).map_err(|e| OpError::Transient(e.to_string()))
}

/// `webvh/sync/update/0.2`.
async fn do_sync_update(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), OpError> {
    let update: sync_update::Payload = payload(body, "sync/update")?;
    let entry = sync_entry(
        update.mnemonic.to_string(),
        update.did_id.to_string(),
        update.log_content.to_string(),
        update.witness_content.map(|w| w.to_string()),
        update.version_count.get(),
        update.disabled,
    );
    let status = apply_sync_entry(state, &entry).await?;
    debug!(did = %control.did, mnemonic = %entry.mnemonic, ?status, "applied sync update");
    Ok((
        MSG_SYNC_UPDATE_ACK.to_string(),
        reply::<sync_update::Response>(
            json!({ "mnemonic": entry.mnemonic, "status": status_str(status) }),
            "sync/update",
        )?,
    ))
}

/// `webvh/sync/batch/0.1`: one outcome per entry. A refused entry is reported
/// with its code and the rest still apply; an entry this server could not
/// apply *just now* makes the whole batch retryable, because re-applying the
/// entries that did land is a no-op and acknowledging the batch would settle it
/// with that entry missing.
async fn do_sync_batch(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), OpError> {
    let batch: sync_batch::Payload = payload(body, "sync/batch")?;
    let count = batch.updates.len();
    let mut results = Vec::with_capacity(count);
    let mut transient: Option<String> = None;
    for update in batch.updates {
        let entry = sync_entry(
            update.mnemonic.to_string(),
            update.did_id.to_string(),
            update.log_content.to_string(),
            update.witness_content.map(|w| w.to_string()),
            update.version_count.get(),
            update.disabled,
        );
        match apply_sync_entry(state, &entry).await {
            Ok(status) => {
                results.push(json!({ "mnemonic": entry.mnemonic, "status": status_str(status) }))
            }
            Err(OpError::Declared(code, e)) => {
                warn!(mnemonic = %entry.mnemonic, error = %e, "sync-batch: entry refused");
                results.push(
                    json!({ "mnemonic": entry.mnemonic, "status": "refused", "code": code.code }),
                );
            }
            Err(OpError::Refused(e)) => {
                warn!(mnemonic = %entry.mnemonic, error = %e, "sync-batch: entry refused");
                results.push(json!({
                    "mnemonic": entry.mnemonic,
                    "status": "refused",
                    "code": sync_update::error_codes::INVALID_LOG.code,
                }));
            }
            Err(OpError::Transient(e)) => {
                warn!(mnemonic = %entry.mnemonic, error = %e, "sync-batch: entry could not be applied just now");
                transient.get_or_insert(e);
            }
        }
    }
    if let Some(e) = transient {
        return Err(OpError::Transient(format!(
            "a sync-batch entry could not be applied just now: {e}"
        )));
    }
    debug!(did = %control.did, count, "applied DID sync batch from control plane");
    Ok((
        MSG_SYNC_BATCH_ACK.to_string(),
        reply::<sync_batch::Response>(json!({ "results": results }), "sync/batch")?,
    ))
}

fn sync_entry(
    mnemonic: String,
    did_id: String,
    log_content: String,
    witness_content: Option<String>,
    version_count: u64,
    disabled: bool,
) -> did_hosting_common::DidSyncUpdate {
    did_hosting_common::DidSyncUpdate {
        mnemonic,
        did_id,
        log_content,
        witness_content,
        version_count,
        disabled,
    }
}

fn status_str(status: crate::control_register::SyncApplied) -> &'static str {
    match status {
        crate::control_register::SyncApplied::Applied => "applied",
        crate::control_register::SyncApplied::Unchanged => "unchanged",
    }
}

/// Apply one sync entry — a `sync/update` payload, or one element of a
/// `sync/batch`. Runs the own-DID rotation check, so a batched update to the
/// server's own DID is treated exactly like a single one.
async fn apply_sync_entry(
    state: &AppState,
    update: &did_hosting_common::DidSyncUpdate,
) -> Result<crate::control_register::SyncApplied, OpError> {
    use crate::control_register::{SyncApplied, apply_single_update};

    // The log must hold exactly the entries the source counted.
    let entries = update
        .log_content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count() as u64;
    if entries != update.version_count {
        return Err(OpError::Declared(
            sync_update::error_codes::INVALID_LOG,
            format!(
                "versionCount is {} but logContent holds {entries} entries",
                update.version_count
            ),
        ));
    }

    let status = apply_single_update(
        &state.dids_ks,
        &state.store,
        update,
        &state.did_cache,
        state.config.public_url.as_deref(),
    )
    .await
    .map_err(sync_refusal)?;

    if status == SyncApplied::Applied {
        // The second way this server's own DID can change: a control plane
        // pushed a new log entry for it. Same rotation check as a direct publish.
        crate::identity_rotation::on_did_published(state, &update.mnemonic).await;
    }
    Ok(status)
}

/// Classify a failed sync apply under the codes `sync/update/0.2` declares.
fn sync_refusal(e: crate::error::AppError) -> OpError {
    use crate::error::AppError;
    match e {
        AppError::Validation(message) => {
            let code = if message.contains("deactivated") {
                sync_update::error_codes::DEACTIVATED
            } else if message.contains("not an extension")
                || message.contains("rollback")
                || message.contains("high-water")
                || message.contains("refusing to replace")
            {
                sync_update::error_codes::HISTORY_REWRITE
            } else {
                sync_update::error_codes::INVALID_LOG
            };
            OpError::Declared(code, message)
        }
        other => OpError::from(other),
    }
}

/// `webvh/sync/delete/0.2`: stop serving the slot and drop its log, witness
/// proofs and derived agent-name index in one change. The high-water marks
/// stay, so a re-publish cannot roll the DID back.
async fn do_sync_delete(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), OpError> {
    use crate::did_ops;

    let delete: sync_delete::Payload = payload(body, "sync/delete")?;
    let mnemonic = delete.mnemonic.as_str();

    let record: Option<did_ops::DidRecord> = state
        .dids_ks
        .get(did_ops::did_key(mnemonic))
        .await
        .map_err(OpError::from)?;

    let status = if let Some(record) = record {
        let host = record
            .did_id
            .as_deref()
            .and_then(|d| did_hosting_common::server::domain::safety::extract_did_host(d).ok())
            .unwrap_or_default();
        let mut batch = state.store.batch();
        batch.remove(&state.dids_ks, did_ops::did_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::content_log_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::content_witness_key(mnemonic));
        batch.remove(&state.dids_ks, did_ops::owner_key(&record.owner, mnemonic));
        batch.remove(&state.dids_ks, did_ops::watcher_sync_key(mnemonic));
        for name in &record.agent_names {
            batch.remove(
                &state.dids_ks,
                did_hosting_common::did_ops::agent_name_key(&host, &name.name),
            );
        }
        batch.commit().await.map_err(OpError::from)?;
        state
            .did_cache
            .invalidate(&did_ops::content_log_key(mnemonic));
        info!(did = %control.did, mnemonic = %mnemonic, "deleted DID via sync from control plane");
        "deleted"
    } else {
        info!(mnemonic = %mnemonic, "sync delete: DID not held here");
        "absent"
    };

    Ok((
        MSG_SYNC_DELETE_ACK.to_string(),
        reply::<sync_delete::Response>(
            json!({ "mnemonic": mnemonic, "status": status }),
            "sync/delete",
        )?,
    ))
}

// ---------------------------------------------------------------------------
// Domain replication (control plane → server)
// ---------------------------------------------------------------------------
//
// The control plane is the source of record for which domains a server hosts
// and for each domain's record. Every directive is idempotent. Only documents
// signed by the configured control plane reach these cores (see
// `VerifiedControlPlane`).

use trust_tasks_rs::specs::did_management::replica::domain::{
    assign::v0_1 as replica_assign, purge::v0_1 as replica_purge,
    unassign::v0_1 as replica_unassign, upsert::v0_1 as replica_upsert,
};

/// A directive's domain, which the control plane must already have put in
/// canonical form: two spellings of one domain must never become two records.
fn canonical_domain(name: &str, what: &str) -> Result<String, OpError> {
    let canonical = did_hosting_common::server::domain::normalize_domain_name(name)
        .map_err(|e| OpError::Refused(format!("{what}: `{name}` is not a domain name: {e}")))?;
    if canonical != name {
        return Err(OpError::Refused(format!(
            "{what}: `{name}` is not in canonical form (expected `{canonical}`)"
        )));
    }
    Ok(canonical)
}

fn rfc3339(secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0).unwrap_or_default()
}

/// `replica/domain/assign/0.1`: record the assignment on this server's own
/// clock — refreshing it when the domain is already assigned, since that time
/// is what the purge freshness rule compares against — and cancel any purge
/// scheduled for the domain.
async fn do_domain_assign(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), OpError> {
    use did_hosting_common::server::assignment::record_assignment;
    use did_hosting_common::server::pending_purge::{self, CancelOutcome};

    let directive: replica_assign::Payload = payload(body, "replica/domain/assign")?;
    let domain = canonical_domain(&directive.domain, "replica/domain/assign")?;

    let now = did_hosting_common::server::auth::session::now_epoch();
    record_assignment(&state.store, &domain, &control.did, now)
        .await
        .map_err(OpError::from)?;

    // A re-assign within the grace window cancels the pending purge. Logged so
    // an operator can answer "did my data survive the unassign / re-assign
    // round trip?".
    if let CancelOutcome::Removed(prev) = pending_purge::cancel(&state.store, &domain)
        .await
        .map_err(OpError::from)?
    {
        info!(
            did = %control.did,
            domain = %domain,
            scheduled_at = prev.scheduled_at,
            grace_seconds = prev.grace_seconds,
            "domain re-assign cancelled pending purge — data retained"
        );
    }
    info!(did = %control.did, domain = %domain, "domain assigned");

    Ok((
        MSG_REPLICA_DOMAIN_ASSIGN_ACK.to_string(),
        reply::<replica_assign::Response>(
            json!({ "domain": domain, "status": "applied" }),
            "replica/domain/assign",
        )?,
    ))
}

/// This server's unassignment grace, from `hosting.unassigned_purge_grace`.
fn unassign_grace_seconds(state: &AppState) -> u64 {
    use did_hosting_common::server::pending_purge::parse_grace_string;
    // A misconfigured value falls back to 2h with a warning, so an unassign
    // still schedules a purge rather than failing outright.
    parse_grace_string(&state.config.hosting.unassigned_purge_grace).unwrap_or_else(|e| {
        warn!(
            error = %e,
            config = %state.config.hosting.unassigned_purge_grace,
            "unassigned_purge_grace unparseable; defaulting to 2h"
        );
        2 * 60 * 60
    })
}

/// `replica/domain/unassign/0.1`: remove the assignment and schedule the
/// domain's deletion at this server's clock plus its grace. The answer always
/// states the schedule now in force: a domain this server does not serve keeps
/// any existing schedule, or answers `purgeAt` = now when it holds nothing.
async fn do_domain_unassign(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), OpError> {
    use did_hosting_common::server::assignment::{UnassignOutcome, unassign};
    use did_hosting_common::server::pending_purge;

    let directive: replica_unassign::Payload = payload(body, "replica/domain/unassign")?;
    let domain = canonical_domain(&directive.domain, "replica/domain/unassign")?;

    let now = did_hosting_common::server::auth::session::now_epoch();
    let outcome = unassign(&state.store, &domain)
        .await
        .map_err(OpError::from)?;

    let purge_at = match outcome {
        UnassignOutcome::Removed(_) => {
            let grace_seconds = unassign_grace_seconds(state);
            // A failed schedule is retried: answering `scheduled` would settle a
            // directive whose deletion was never arranged.
            pending_purge::schedule(
                &state.store,
                &domain,
                now,
                grace_seconds,
                "grace-expired",
                &control.did,
            )
            .await
            .map_err(OpError::from)?;
            info!(did = %control.did, domain = %domain, grace_seconds, "domain unassigned; purge scheduled");
            now.saturating_add(grace_seconds)
        }
        UnassignOutcome::Missing => {
            match pending_purge::get(&state.store, &domain)
                .await
                .map_err(OpError::from)?
            {
                Some(existing) => existing.scheduled_at.saturating_add(existing.grace_seconds),
                None => now,
            }
        }
    };

    Ok((
        MSG_REPLICA_DOMAIN_UNASSIGN_ACK.to_string(),
        reply::<replica_unassign::Response>(
            json!({ "domain": domain, "status": "scheduled", "purgeAt": rfc3339(purge_at) }),
            "replica/domain/unassign",
        )?,
    ))
}

/// `replica/domain/purge/0.1`: delete every slot this server holds on the
/// domain now, unless it holds an assignment of the domain made after the
/// directive was issued.
async fn do_domain_purge(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), OpError> {
    use did_hosting_common::server::assignment;
    use did_hosting_common::server::domain_purge::purge_domain_dids;
    use did_hosting_common::server::pending_purge;

    let directive: replica_purge::Payload = payload(body, "replica/domain/purge")?;
    let domain = canonical_domain(&directive.domain, "replica/domain/purge")?;

    // Freshness. Directives wait in the control plane's outbox and may arrive
    // late: an operator who unassigns a domain, then re-assigns it within the
    // grace window, must not have the data they chose to keep wiped by the
    // original purge arriving afterwards. The document's signed `issuedAt` is
    // compared with the assignment time this server recorded on its own clock.
    // A lookup failure must not skip the check: it is retried, not assumed away.
    if let Some(current) = assignment::get(&state.store, &domain)
        .await
        .map_err(OpError::from)?
        && control.issued_at < current.assigned_at
    {
        warn!(
            did = %control.did,
            domain = %domain,
            issued_at = control.issued_at,
            assigned_at = current.assigned_at,
            "replica/domain/purge refused: issued before the current assignment"
        );
        return Err(OpError::Declared(
            replica_purge::error_codes::STALE_PURGE,
            "the purge predates this server's current assignment of the domain; nothing was deleted"
                .into(),
        ));
    }

    let report = purge_domain_dids(&state.store, &domain, "admin-immediate")
        .await
        .map_err(OpError::from)?;
    if report.failed > 0 {
        return Err(OpError::Transient(format!(
            "{} slot(s) on {domain} could not be deleted just now",
            report.failed
        )));
    }
    state.did_cache.clear();

    // The immediate purge supersedes any scheduled one.
    pending_purge::cancel(&state.store, &domain)
        .await
        .map_err(OpError::from)?;

    info!(
        did = %control.did,
        domain = %domain,
        removed = report.deleted,
        skipped_no_domain = report.skipped_no_domain,
        "domain purged on the control plane's directive"
    );

    Ok((
        MSG_REPLICA_DOMAIN_PURGE_ACK.to_string(),
        reply::<replica_purge::Response>(
            json!({ "domain": domain, "status": "purged", "removed": report.deleted }),
            "replica/domain/purge",
        )?,
    ))
}

/// `replica/domain/upsert/0.1`: this server's copy of the domain record
/// becomes the carried entry. `status: disabled` schedules the domain's purge
/// at `entry.purgeAt`; `status: active` cancels any scheduled purge.
/// Re-applying the same entry is a no-op in effect, and answered `applied`.
async fn do_domain_upsert(
    control: &VerifiedControlPlane,
    state: &AppState,
    body: &Value,
) -> Result<(String, Value), OpError> {
    use did_hosting_common::server::domain::{
        DISABLE_PURGE_REASON, DomainStatus, create_domain, get_domain, normalize_domain_name,
        update_domain, wire,
    };
    use did_hosting_common::server::pending_purge;

    let directive: replica_upsert::Payload = payload(body, "replica/domain/upsert")?;
    let name = directive.entry.name.clone();
    let canonical = normalize_domain_name(&name).map_err(|e| {
        OpError::Declared(
            replica_upsert::error_codes::NON_CANONICAL_NAME,
            format!("`{name}` is not a domain name: {e}"),
        )
    })?;
    if canonical != name {
        return Err(OpError::Declared(
            replica_upsert::error_codes::NON_CANONICAL_NAME,
            format!("`{name}` is not in canonical form (expected `{canonical}`)"),
        ));
    }
    let entry_value =
        serde_json::to_value(&directive.entry).map_err(|e| OpError::Transient(e.to_string()))?;
    let entry = wire::from_spec(&entry_value)
        .map_err(|e| OpError::Refused(format!("replica/domain/upsert: {e}")))?;

    let existed = get_domain(&state.store, &canonical)
        .await
        .map_err(OpError::from)?
        .is_some();
    if existed {
        update_domain(&state.store, &canonical, &entry)
            .await
            .map_err(OpError::from)?;
    } else {
        create_domain(&state.store, &entry)
            .await
            .map_err(OpError::from)?;
    }

    match entry.status {
        DomainStatus::Active => {
            // Re-enable cancels any in-flight grace timer.
            pending_purge::cancel(&state.store, &canonical)
                .await
                .map_err(OpError::from)?;
        }
        DomainStatus::Disabled => match (entry.disabled_at, entry.purge_at) {
            (Some(disabled_at), Some(purge_at)) => {
                pending_purge::schedule(
                    &state.store,
                    &canonical,
                    disabled_at,
                    purge_at.saturating_sub(disabled_at),
                    DISABLE_PURGE_REASON,
                    &control.did,
                )
                .await
                .map_err(OpError::from)?;
            }
            _ => warn!(
                domain = %canonical,
                "replica/domain/upsert: status=disabled without disabledAt/purgeAt — no purge scheduled"
            ),
        },
    }

    info!(
        did = %control.did,
        domain = %canonical,
        action = if existed { "updated" } else { "created" },
        status = ?entry.status,
        "domain entry replicated"
    );

    Ok((
        MSG_REPLICA_DOMAIN_UPSERT_ACK.to_string(),
        reply::<replica_upsert::Response>(
            json!({ "name": canonical, "status": "applied" }),
            "replica/domain/upsert",
        )?,
    ))
}

// ---------------------------------------------------------------------------
// Metrics (control plane → server)
// ---------------------------------------------------------------------------

/// `server/metrics/0.1`, answered to the control plane: the replication
/// freshness the staleness bound is measured on, and the process counters.
/// There is no Prometheus endpoint on an edge; this is the only read of them.
async fn do_server_metrics(state: &AppState, body: &Value) -> Result<(String, Value), OpError> {
    use trust_tasks_rs::specs::did_management::server::metrics::v0_1 as metrics;

    let _: metrics::Payload = payload(body, "server/metrics")?;
    let now = did_hosting_common::server::auth::session::now_epoch();
    let status = &state.replication;
    let bound = state.config.replication.staleness_bound_secs;
    let gauge = |name: &str, value: u64| json!({ "name": name, "value": value });
    let mut gauges = vec![
        gauge(
            "did_hosting_replication_reconcile_age_seconds",
            status.age(now),
        ),
        gauge("did_hosting_replication_staleness_bound_seconds", bound),
        gauge(
            "did_hosting_replication_fresh",
            u64::from(status.is_fresh(now, bound)),
        ),
        gauge("did_hosting_replication_stale_slots", status.stale_slots()),
    ];
    if let Some(at) = status.last_reconciled_at() {
        gauges.push(gauge("did_hosting_replication_last_reconciled_at", at));
    }
    #[allow(unused_mut)]
    let mut counters = vec![gauge(
        "did_hosting_replication_repaired_total",
        status.repaired_total(),
    )];
    #[cfg(feature = "metrics")]
    counters.extend(
        did_hosting_common::server::metrics::counters()
            .into_iter()
            .map(|(name, value)| json!({ "name": name, "value": value })),
    );
    Ok((
        format!("{MSG_SERVER_METRICS}#response"),
        reply::<metrics::Response>(
            json!({
                "snapshot": {
                    "takenAt": chrono::Utc::now(),
                    "counters": counters,
                    "gauges": gauges,
                    "histograms": [],
                }
            }),
            "server/metrics",
        )?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    fn payload_of(err: OpError) -> Value {
        let doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "type": MSG_SYNC_UPDATE,
            "payload": {},
        }))
        .unwrap();
        serde_json::to_value(doc.reject_with("urn:uuid:x", err.reject_reason())).unwrap()["payload"]
            .clone()
    }

    /// A storage or I/O failure is this server's momentary problem: reported
    /// retryable, so the control plane keeps the op queued instead of settling it.
    #[test]
    fn storage_failures_are_retryable() {
        for e in [
            AppError::Store("disk full".into()),
            AppError::Internal("lock poisoned".into()),
            AppError::Io(std::io::Error::other("eio")),
        ] {
            let err = OpError::from(e);
            assert!(matches!(err, OpError::Transient(_)), "{err:?}");
            assert_eq!(payload_of(err)["retryable"], true);
        }
    }

    /// A refusal is final: reported non-retryable, so the control plane stops.
    #[test]
    fn refusals_are_final() {
        for err in [
            OpError::from(AppError::Validation("not an extension".into())),
            OpError::from("missing 'mnemonic'"),
        ] {
            assert!(matches!(err, OpError::Refused(_)), "{err:?}");
            assert_eq!(payload_of(err)["retryable"], false);
        }
    }
}

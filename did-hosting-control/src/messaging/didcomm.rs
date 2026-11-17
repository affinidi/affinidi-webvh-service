//! The DIDComm side of the inbound listener: the framework router, request
//! logging, the fallback for message types no route claims, and the
//! Trust Tasks envelope handler that hands a document to the gate.

use super::*;

// ---------------------------------------------------------------------------
// Inbound router (framework-managed)
// ---------------------------------------------------------------------------

/// Build the DIDComm router for the control plane's inbound messages.
///
/// Handles the full VTA provisioning protocol (authenticate, did/request,
/// did/publish, etc.) as well as sync acknowledgements from servers.
pub fn build_control_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        // Standard DIDComm
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        // Every DID-management, auth and infrastructure operation arrives as a
        // signed Trust Task document in the trust-task envelope below; the
        // bare-message routes that used to sit here authorised on the
        // transport's report of the sender alone and have been removed. A peer
        // still sending one gets `handle_fallback`'s problem report naming the
        // type, not a silent timeout.
        // Trust Tasks envelope — routes every Trust Task through the same
        // `dispatch_trust_task_doc` the HTTPS transport hits at
        // `POST /api/trust-tasks`.
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
pub(super) async fn filtered_request_logging(
    ctx: HandlerContext,
    message: Message,
    meta: affinidi_messaging_didcomm::UnpackMetadata,
    next: Next,
) -> MiddlewareResult {
    let msg_type = logged_type(&message);
    let result = next.run(ctx, message, meta).await;

    if !is_quiet(&msg_type) {
        let status = match &result {
            Ok(Some(_)) => "ok(response)",
            Ok(None) => "ok(empty)",
            Err(_) => "error",
        };
        info!(message_type = %msg_type, status, "DIDComm request processed");
    }

    result
}

/// Message types the request log leaves out: the periodic health and stats
/// exchanges, one or more per edge per minute.
pub(super) const QUIET_TYPES: &[&str] = &[
    MSG_HEALTH_PING,
    MSG_HEALTH_PONG,
    MSG_STATS_SYNC,
    MSG_STATS_ACK,
    MESSAGE_PICKUP_STATUS_TYPE,
];

/// Whether `msg_type` (as [`logged_type`] reports it) is left out of the
/// request log.
pub(super) fn is_quiet(msg_type: &str) -> bool {
    QUIET_TYPES.contains(&msg_type)
}

/// The type a message is logged under: for a trust-task envelope, which
/// every task now arrives in, the type of the document inside it; otherwise
/// the message's own.
pub(super) fn logged_type(message: &Message) -> String {
    if message.typ == trust_tasks_didcomm::ENVELOPE_TYPE
        && let Some(inner) = message.body.get("type").and_then(Value::as_str)
    {
        return inner.to_string();
    }
    message.typ.clone()
}
/// Answer a message this router has no arm for with a problem-report, so the
/// caller fails immediately and *knows which task we refused*.
///
/// Dropping an unrouted type silently — which this did — turns every retirement
/// into a mystery timeout on the client. When #144 retired `did/publish/0.1` and
/// the `agent-name` set/enable/disable trio, a VTA still sending them got no
/// reply at all: it burned its full 30s `send_and_wait` and surfaced
/// "bad gateway: request timed out" with no mention of the task, on four
/// separate operations. The retirements were correct; the silence is what made
/// them expensive to diagnose. Naming the type turns a 30s dead end into an
/// immediate, greppable error, and does so for the *next* retirement too.
///
/// Threading to `message.id` is load-bearing: callers demux replies by thread
/// id, so an unthreaded problem-report is discarded and the caller waits out its
/// timeout anyway — the bug would look unfixed.
///
/// The reply is the standard DIDComm `report-problem/2.0` message: the
/// message it answers is a bare DIDComm message, not a Trust Task document,
/// so neither a `trust-task-error` nor a Trust Task URI (this used to send
/// `did-management/did/problem-report/0.1`, which no specification pins and
/// no peer reads) is its answer. A VTA reads it as a problem report
/// (`vta_sdk::didcomm_session`).
///
/// Loop-safe: an inbound problem-report returns above, before we would reply,
/// and `is_problem_report` matches the type we emit — so a peer that cannot
/// route our reply logs and drops it rather than answering back.
pub(super) async fn handle_fallback(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = ctx.sender_did.as_deref();
    if log_problem_report("control", sender, &message) {
        return Ok(None);
    }
    warn!(
        sender = sender.unwrap_or("unknown"),
        msg_type = %message.typ,
        "inbound DIDComm: unhandled message type — replying with a problem-report"
    );
    let (typ, body) = run_unsupported_task(&message.typ);
    Ok(Some(
        DIDCommResponse::new(typ, body).thid(message.id.clone()),
    ))
}

/// The problem-report [`handle_fallback`] answers an unrouted type with.
///
/// Returns `(typ, body)` rather than a `DIDCommResponse` for the same reason
/// the `run_*` helpers in this module do: the response type exposes no getters,
/// so a test can only assert what the builder was handed. The threading stays at
/// the call site, where `message.id` lives.
pub(super) fn run_unsupported_task(msg_type: &str) -> (String, Value) {
    (
        affinidi_messaging_didcomm_service::transport::PROBLEM_REPORT_TYPE.to_string(),
        json!({
            "code": "e.p.msg.unsupported-task",
            // The type is the whole diagnostic: a retired task, a typo, and a
            // peer predating the task are indistinguishable without it, and the
            // caller cannot log what it was never told.
            "comment": format!(
                "this control plane has no handler for `{msg_type}` — it may have been retired, \
                 or this peer may be a version that predates it"
            ),
        }),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn require_sender(ctx: &HandlerContext) -> Result<&str, DIDCommServiceError> {
    ctx.sender_did
        .as_deref()
        .map(|did| did.split('#').next().unwrap_or(did))
        .ok_or_else(|| DIDCommServiceError::Internal("missing sender DID".into()))
}

// ---------------------------------------------------------------------------
// Trust Tasks envelope handler
// ---------------------------------------------------------------------------

/// DIDComm handler for the Trust Tasks envelope
/// (`https://trusttasks.org/binding/didcomm/0.1/envelope`).
///
/// `message.body` is the JSON of the inner `TrustTask<Value>` document
/// (per the binding's wire shape — see `trust-tasks-didcomm/src/pack.rs`).
/// `ctx.sender_did` is the messaging layer's report of who sent it: a routing
/// hint that [`dispatch_trust_task_doc`] requires to agree with the document's
/// proof, never an authorisation on its own.
///
/// We construct a [`DidcommHandler`] reporting `local = server_did`
/// and `peer = sender`, then hand the document to the shared
/// [`dispatch_trust_task_doc`] core. The result is repacked as a new DIDComm
/// message of the same envelope type so the same routing rules
/// (mediator pickup, attachment, etc.) apply.
pub(super) async fn handle_trust_tasks_envelope(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    debug!(sender = sender, "inbound DIDComm: trust-tasks envelope");
    match run_trust_tasks_envelope(&state, sender, &message).await? {
        Some((response_type, response_body)) => Ok(Some(
            DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
        )),
        None => Ok(None),
    }
}

/// Compute the wire-level `(response_type, response_body)` tuple for
/// an inbound trust-tasks envelope. Extracted from
/// `handle_trust_tasks_envelope` so the dispatch + body-parse +
/// repack logic is testable without an `ATM`-backed
/// [`HandlerContext`]. Returns `None` for a document that was itself an
/// answer (a pong, an acknowledgement, a peer's error: [`RoutedReply::Terminal`],
/// the normal end of an exchange), and for the SPEC.md §8.1 routing exception
/// (identity-mismatch with no transport sender) — unreachable on the
/// dispatcher's `require_sender_did(true)` gate, so only that one is logged as
/// an invariant break.
pub(crate) async fn run_trust_tasks_envelope(
    state: &AppState,
    sender: &str,
    message: &Message,
) -> Result<Option<(String, Value)>, DIDCommServiceError> {
    // Per-type document size, the same gate the HTTPS and TSP transports
    // apply before their own parse (`size`). The DIDComm messaging layer
    // has already decoded `message.body` into a `Value` by the time it
    // reaches us — there is no raw pre-parse buffer left to peek — so the
    // check runs against its re-serialised bytes instead. That still
    // refuses an oversized document before anything below does the
    // heavier work of typed parsing, proof verification or dispatch, which
    // is the property the gate exists for.
    //
    // A document large enough to need its claimed (not yet verified)
    // issuer's ACL entry is charged against that sender's large-document
    // budget first (`vid:{sender}` — the transport's own authenticated
    // report of who sent it, not yet the document's proven issuer).
    let body_bytes = serde_json::to_vec(&message.body).unwrap_or_default();
    let large_doc_charge =
        match did_hosting_common::server::trust_tasks::size::check_for_known_issuer(
            &body_bytes,
            &crate::control_tasks::SERVED_TRUST_TASK_URIS,
            &state.acl_ks,
            &state.large_document_budget,
            &format!("vid:{sender}"),
        )
        .await
        {
            Ok(charge) => charge,
            Err(err) => {
                let body =
                    serde_json::to_value(&err).expect("trust-task-error document serialises");
                return Ok(Some((trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), body)));
            }
        };

    let doc: trust_tasks_rs::TrustTask<Value> = match serde_json::from_value(message.body.clone()) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                sender = sender,
                error = %e,
                "trust-tasks envelope: inner body did not parse as TrustTask<Value>"
            );
            // Mirror the routed-error pattern from the HTTPS
            // transport: build a `malformed_request` document and
            // pack it back inside the same envelope type so the
            // sender sees a consistent error shape across transports.
            let err_doc = body_parse_error(&e.to_string());
            let body =
                serde_json::to_value(&err_doc).expect("trust-task-error document serialises");
            return Ok(Some((trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), body)));
        }
    };

    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| DIDCommServiceError::Internal("server_did not configured".into()))?;

    // Replay protection is not here: a DIDComm message id is chosen per
    // message by whoever sends it, so a captured document re-wrapped in a new
    // message would sail past a `(sender, message.id)` check. The unified
    // dispatcher keys its replay cache on `(proven issuer, document id)`
    // instead — both covered by the document's own proof.
    let transport =
        trust_tasks_didcomm::DidcommHandler::new(my_vid.to_string(), sender.to_string());

    // Route through the unified trust-task dispatcher — the same entry TSP and
    // HTTPS use. Every family is reachable here: the typed
    // `did-hosting/*/1.0` protocol, auth, infra, ACL + discovery, and the
    // legacy `MSG_*` bridge.
    let verifier = require_verifier(state)?;
    let reply = dispatch_trust_task_doc(
        state,
        sender,
        None,
        None,
        &transport,
        doc,
        verifier,
        large_doc_charge,
    )
    .await?;
    // A pong, an acknowledgement or a peer's error is answered by nothing:
    // the exchange is over, and that is not worth a log line.
    if reply.is_terminal() {
        return Ok(None);
    }
    match reply.into_document() {
        Some(body) => Ok(Some((trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), body))),
        None => {
            // SPEC §8.1 routing exception: identity-mismatch with no
            // transport sender. Unreachable under `require_sender_did(true)`;
            // if it fires, the invariant has broken.
            tracing::error!(
                should_not_happen = true,
                sender = sender,
                "trust-tasks envelope: dispatch suppressed (identity_mismatch w/ no transport sender)"
            );
            Ok(None)
        }
    }
}

/// Build the same body-parse `trust-task-error` document that the
/// HTTPS transport uses, kept here so the two transports emit
/// byte-identical error shapes for parse failures.
pub(crate) fn body_parse_error(reason: &str) -> trust_tasks_rs::ErrorResponse {
    use trust_tasks_rs::{ErrorPayload, RejectReason, TrustTask};
    let reject = RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    };
    let payload: ErrorPayload = reject.into();
    TrustTask {
        id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        thread_id: None,
        // The body never parsed, so there is no request to read an enclosing
        // exchange from (SPEC §4.9.2).
        parent_thread_id: None,
        // No ceremony, for the same reason as `parent_thread_id` above: SPEC
        // §7.1 carries the member forward from the request so a reply stays
        // inside its enactment, and here there is no request to carry it from.
        ceremony: None,
        type_uri: did_hosting_common::server::trust_tasks::framework_error_type_uri(),
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    }
}

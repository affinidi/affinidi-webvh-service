//! DIDComm listener for the witness service.
//!
//! Uses the `affinidi-messaging-didcomm-service` framework for mediator
//! connection management, message dispatch, and response packing/sending.
//!
//! **This listener serves no witness protocol.** It once routed `authenticate`,
//! `witness/proof-request` and `witness/list-request` — a second implementation
//! of operations the REST API already serves and which `witness_client`, the
//! only client of this service in the estate, has always used over HTTP
//! (`/api/auth/*`, `POST /api/proof/{witness_id}`, `GET /api/witnesses`).
//! Nothing ever spoke the DIDComm forms, so they are gone rather than kept as
//! a parallel surface to keep in step.
//!
//! What remains is the mediator presence the service does depend on: trust-ping
//! and message-pickup status, and a listener for `identity_rotation` to drain a
//! superseded generation through. Adding a witness operation here again should
//! mean deciding it belongs on DIDComm, not restoring a mirror of the REST API.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, RequestLogging, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    trust_ping_handler,
};
use serde_json::json;
use tracing::warn;

use did_hosting_common::server::problem_report::log_problem_report;

use crate::server::AppState;

/// Emitted by the fallback for a message type this listener does not serve.
///
/// The only witness-specific type left. `authenticate`, `witness/proof-request`
/// and `witness/list-request` are gone: they were a second implementation of
/// operations the REST API already serves and `witness_client` already uses
/// (`/api/auth/*`, `POST /api/proof/{witness_id}`, `GET /api/witnesses`), and
/// nothing in the estate ever spoke the DIDComm forms.
const MSG_WITNESS_PROBLEM_REPORT: &str = "https://affinidi.com/webvh/1.0/witness/problem-report";

/// Build the DIDComm router for the witness service.
pub fn build_witness_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .fallback(handler_fn(handle_fallback))
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_sender_did(true),
        )
        .layer(RequestLogging))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_fallback(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = ctx.sender_did.as_deref();

    // Inbound problem-reports describe failures on the remote side; log
    // them with full context and don't echo another problem-report back
    // (that would create a ping-pong loop).
    if log_problem_report("witness", sender, &message) {
        return Ok(None);
    }

    warn!(
        sender = sender.unwrap_or("unknown"),
        msg_type = %message.typ,
        "unknown DIDComm message type"
    );
    Ok(Some(
        DIDCommResponse::new(
            MSG_WITNESS_PROBLEM_REPORT,
            json!({
                "code": "e.p.witness.unknown-type",
                "comment": format!("unknown message type: {}", message.typ),
            }),
        )
        .thid(message.id.clone()),
    ))
}

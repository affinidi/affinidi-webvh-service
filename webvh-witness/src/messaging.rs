//! DIDComm listener for the witness service.
//!
//! Uses the `affinidi-messaging-didcomm-service` framework for mediator
//! connection management, message dispatch, and response packing/sending.
//!
//! Every witness operation arrives as a signed Trust Task document inside the
//! framework's DIDComm trust-task envelope, and is handed to
//! [`crate::trust_tasks::dispatch_inbound_document`] — the same dispatch the
//! TSP handler and `POST /api/trust-tasks` use. There are no bare-message
//! routes. What else remains is the mediator presence the service depends on:
//! trust-ping and message-pickup status.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, RequestLogging, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    trust_ping_handler,
};
use serde_json::Value;
use tracing::warn;

use did_hosting_common::server::problem_report::log_problem_report;

use crate::server::AppState;
use crate::trust_tasks::{Via, dispatch_inbound_document};

/// Build the DIDComm router for the witness service.
pub fn build_witness_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
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
        .layer(RequestLogging))
}

/// Inbound trust-task document carried in a DIDComm envelope. The reply is
/// returned, so the framework routes it back over the same connection.
async fn handle_trust_tasks_envelope(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
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
/// answer. `sender` is a routing hint that must agree with the proof.
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
                "trust-tasks envelope: inner body is not a Trust Task document"
            );
            return None;
        }
    };
    let reply = dispatch_inbound_document(state, Via::Didcomm, sender, doc).await?;
    Some((trust_tasks_didcomm::ENVELOPE_TYPE.to_string(), reply))
}

async fn handle_fallback(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = ctx.sender_did.as_deref();
    // Inbound problem-reports describe failures on the remote side; log them
    // and never answer (that would create a ping-pong loop).
    if log_problem_report("witness", sender, &message) {
        return Ok(None);
    }
    warn!(
        sender = sender.unwrap_or("unknown"),
        msg_type = %message.typ,
        "unknown DIDComm message type — ignoring"
    );
    Ok(None)
}

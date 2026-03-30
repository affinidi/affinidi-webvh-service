//! DIDComm message routing and handlers for the witness service.
//!
//! Uses the `affinidi-messaging-didcomm-service` framework for mediator
//! connection management, message dispatch, and response packing/sending.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MessagePolicy,
    RequestLogging, Router, TRUST_PING_TYPE, MESSAGE_PICKUP_STATUS_TYPE,
    handler_fn, ignore_handler, trust_ping_handler,
};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::acl::check_acl;
use crate::auth::session::create_authenticated_session;
use crate::error::AppError;
use crate::server::AppState;

// WebVH witness message types
const MSG_AUTHENTICATE: &str = "https://affinidi.com/webvh/1.0/authenticate";
const MSG_AUTHENTICATE_RESPONSE: &str = "https://affinidi.com/webvh/1.0/authenticate-response";
const MSG_WITNESS_PROOF_REQUEST: &str = "https://affinidi.com/webvh/1.0/witness/proof-request";
const MSG_WITNESS_PROOF_RESPONSE: &str = "https://affinidi.com/webvh/1.0/witness/proof-response";
const MSG_WITNESS_LIST_REQUEST: &str = "https://affinidi.com/webvh/1.0/witness/list-request";
const MSG_WITNESS_LIST: &str = "https://affinidi.com/webvh/1.0/witness/list";
const MSG_WITNESS_PROBLEM_REPORT: &str = "https://affinidi.com/webvh/1.0/witness/problem-report";

/// Build the DIDComm router for the witness service.
pub fn build_witness_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route(MSG_AUTHENTICATE, handler_fn(handle_authenticate))?
        .route(MSG_WITNESS_PROOF_REQUEST, handler_fn(handle_proof_request))?
        .route(MSG_WITNESS_LIST_REQUEST, handler_fn(handle_list_request))?
        .fallback(handler_fn(handle_fallback))
        .layer(MessagePolicy::new().require_encrypted(true).require_sender_did(true))
        .layer(RequestLogging))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_authenticate(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;

    let (response_type, response_body) = match do_authenticate(&state, sender).await {
        Ok(r) => r,
        Err(e) => error_response(&e),
    };

    Ok(Some(DIDCommResponse::new(response_type, response_body)
        .thid(message.id.clone())))
}

async fn handle_proof_request(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;

    let (response_type, response_body) = match check_acl(&state.acl_ks, sender).await {
        Ok(_) => match do_proof_request(&state, &message).await {
            Ok(r) => r,
            Err(e) => error_response(&e),
        },
        Err(e) => error_response(&e),
    };

    Ok(Some(DIDCommResponse::new(response_type, response_body)
        .thid(message.id.clone())))
}

async fn handle_list_request(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;

    let (response_type, response_body) = match check_acl(&state.acl_ks, sender).await {
        Ok(_) => match do_list_request(&state).await {
            Ok(r) => r,
            Err(e) => error_response(&e),
        },
        Err(e) => error_response(&e),
    };

    Ok(Some(DIDCommResponse::new(response_type, response_body)
        .thid(message.id.clone())))
}

async fn handle_fallback(
    _ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    warn!(type_ = %message.typ, "unknown DIDComm message type");
    Ok(Some(DIDCommResponse::new(
        MSG_WITNESS_PROBLEM_REPORT,
        json!({
            "code": "e.p.witness.unknown-type",
            "comment": format!("unknown message type: {}", message.typ),
        }),
    )
    .thid(message.id.clone())))
}

// ---------------------------------------------------------------------------
// Business logic (unchanged from previous implementation)
// ---------------------------------------------------------------------------

async fn do_authenticate(
    state: &AppState,
    sender_base: &str,
) -> Result<(String, Value), AppError> {
    let role = check_acl(&state.acl_ks, sender_base).await?;

    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    let tokens = create_authenticated_session(
        &state.sessions_ks,
        jwt_keys,
        sender_base,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
    )
    .await?;

    info!(did = sender_base, role = %role, "mediator auth: session created");

    Ok((
        MSG_AUTHENTICATE_RESPONSE.to_string(),
        json!({
            "session_id": tokens.session_id,
            "access_token": tokens.access_token,
            "access_expires_at": tokens.access_expires_at,
            "refresh_token": tokens.refresh_token,
            "refresh_expires_at": tokens.refresh_expires_at,
        }),
    ))
}

async fn do_proof_request(
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), AppError> {
    let witness_id = msg
        .body
        .get("witness_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("missing witness_id".into()))?;

    let version_id = msg
        .body
        .get("version_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("missing version_id".into()))?;

    let (version_id, proof) = crate::witness_ops::sign_witness_proof(
        &state.witnesses_ks,
        state.signer.as_ref(),
        witness_id,
        version_id,
    )
    .await?;

    let proof_json = serde_json::to_value(&proof)?;

    Ok((
        MSG_WITNESS_PROOF_RESPONSE.to_string(),
        json!({
            "version_id": version_id,
            "proof": proof_json,
        }),
    ))
}

async fn do_list_request(state: &AppState) -> Result<(String, Value), AppError> {
    let records = crate::witness_ops::list_witnesses(&state.witnesses_ks).await?;
    let witnesses: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "witness_id": r.witness_id,
                "did": r.did,
                "label": r.label,
            })
        })
        .collect();

    Ok((MSG_WITNESS_LIST.to_string(), json!({ "witnesses": witnesses })))
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

fn error_response(e: &AppError) -> (String, Value) {
    warn!(error = %e, "error handling DIDComm message");
    (
        MSG_WITNESS_PROBLEM_REPORT.to_string(),
        json!({
            "code": "e.p.witness.internal-error",
            "comment": e.to_string(),
        }),
    )
}

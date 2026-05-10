//! DIDComm v2 protocol handler for DID management operations over HTTP.
//!
//! All messages are received and returned as **JWS-signed-but-not-encrypted**
//! DIDComm envelopes via a single `POST /api/didcomm` endpoint.
//! Business-logic errors come back as packed `did/problem-report` messages;
//! transport-level errors as HTTP errors.
//!
//! # Confidentiality asymmetry
//!
//! This route is **signed-only**. The framework-routed mediator path
//! (`crate::messaging::build_control_router`) enforces
//! `MessagePolicy::require_encrypted(true)` for end-to-end encryption.
//! Operators with payloads that include sensitive material (DID logs
//! that embed verification methods, `new_owner` DIDs being transferred
//! to) should prefer the mediator-routed channel for that reason.
//!
//! # Shared dispatcher
//!
//! The VTA `MSG_*` arms (request, register, publish, witness-publish,
//! info-request, list-request, delete, change-owner) are dispatched
//! through `crate::messaging::dispatch_did_op`, the same function the
//! mediator-routed transport calls. This guarantees both transports
//! emit the same wire-level error codes for identical inputs and
//! cover the same set of message types — a regression in either
//! transport surfaces in the other's tests too.
//!
//! `trust-ping` and `discover-features` (DIDComm protocol-level
//! messages, not VTA-level) are handled inline because they need
//! `server_did` for response construction; the framework path handles
//! them via the framework crate's built-in handlers.

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::message::pack;
use affinidi_tdk::messaging::protocols::discover_features::DiscoverFeatures;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_webvh_common::didcomm_types::*;
use affinidi_webvh_common::server::didcomm_unpack;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::messaging;
use crate::server::AppState;

const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const DISCOVER_FEATURES_QUERY_TYPE: &str = "https://didcomm.org/discover-features/2.0/queries";

// ---------------------------------------------------------------------------
// Main handler — POST /api/didcomm
// ---------------------------------------------------------------------------

pub async fn handle(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: String,
) -> Result<Response, AppError> {
    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    // sender_base is the JWS-verified DID (unpack_signed enforces from == signer).
    let (msg, sender_base) = didcomm_unpack::unpack_signed(&body, did_resolver)
        .await
        .map_err(|e| AppError::Validation(format!("failed to unpack DIDComm message: {e}")))?;

    if sender_base != auth.did {
        return Err(AppError::Forbidden(
            "DIDComm 'from' does not match authenticated DID".into(),
        ));
    }

    let server_did = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| AppError::Internal("server_did not configured".into()))?;

    // Replay gate: same `(sender, msg.id)` cache the framework router
    // checks. A captured signed envelope replayed within the freshness
    // window would otherwise re-trigger state-changing operations (the
    // signature is still valid; the freshness check still passes).
    if let Err(e) = state.replay_cache.check_and_insert(&auth.did, &msg.id) {
        let code = e.didcomm_code();
        let comment = e.user_message();
        warn!(code, comment = %comment, msg_id = %msg.id, did = %auth.did, "DIDComm replay rejected");
        // Build a problem-report response in-line, since we don't want
        // to surface a generic AppError 4xx for a replay (it's a
        // DIDComm-protocol-level rejection, the wire body should be
        // a packed DIDComm message).
        let response_msg = Message::build(
            uuid::Uuid::new_v4().to_string(),
            MSG_PROBLEM_REPORT.to_string(),
            json!({ "code": code, "comment": comment }),
        )
        .from(server_did.to_string())
        .to(sender_base.to_string())
        .thid(msg.id.clone())
        .created_time(now_epoch())
        .finalize();
        let signing_key = state
            .signing_key_bytes
            .as_ref()
            .ok_or_else(|| AppError::Internal("server signing key not configured".into()))?;
        let kid = format!("{server_did}#key-0");
        let packed = pack::pack_signed(&response_msg, &kid, signing_key)
            .map_err(|e| AppError::Internal(format!("failed to pack DIDComm response: {e}")))?;
        return Ok((
            StatusCode::OK,
            [("content-type", "application/didcomm-signed+json")],
            packed,
        )
            .into_response());
    }

    let (response_type, response_body) = match dispatch(&auth, &state, &msg, server_did).await {
        Ok(result) => result,
        Err(err) => {
            let code = err.didcomm_code();
            let comment = err.user_message();
            warn!(
                code,
                comment = %comment,
                msg_type = %msg.typ,
                did = %auth.did,
                "DIDComm protocol error"
            );
            (
                MSG_PROBLEM_REPORT.to_string(),
                json!({ "code": code, "comment": comment }),
            )
        }
    };

    let response_msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        response_type,
        response_body,
    )
    .from(server_did.to_string())
    .to(sender_base.to_string())
    .thid(msg.id.clone())
    .created_time(now_epoch())
    .finalize();

    let signing_key = state
        .signing_key_bytes
        .as_ref()
        .ok_or_else(|| AppError::Internal("server signing key not configured".into()))?;
    let kid = format!("{server_did}#key-0");
    let packed = pack::pack_signed(&response_msg, &kid, signing_key)
        .map_err(|e| AppError::Internal(format!("failed to pack DIDComm response: {e}")))?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/didcomm-signed+json")],
        packed,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Route a verified inbound message to the right handler.
///
/// VTA `MSG_*` types are forwarded to the shared
/// `messaging::dispatch_did_op` so the framework-routed and HTTP-signed
/// transports walk the same dispatch table. `trust-ping` and
/// `discover-features` are kept inline because they're DIDComm
/// protocol-level (not VTA-level) and need `server_did` to build the
/// reply envelope.
async fn dispatch(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
    server_did: &str,
) -> Result<(String, Value), AppError> {
    match msg.typ.as_str() {
        TRUST_PING_TYPE => handle_trust_ping(msg, server_did),
        DISCOVER_FEATURES_QUERY_TYPE => handle_discover_features(msg, server_did),
        // Everything else is a VTA `MSG_*` — delegate to the shared
        // dispatcher. This includes MSG_DID_REQUEST, MSG_DID_REGISTER,
        // MSG_DID_PUBLISH, MSG_WITNESS_PUBLISH, MSG_INFO_REQUEST,
        // MSG_LIST_REQUEST, MSG_DELETE, MSG_DID_CHANGE_OWNER, plus
        // anything new added to messaging::dispatch_did_op in the
        // future — automatically picked up here, no separate wiring.
        _ => messaging::dispatch_did_op(auth, state, msg).await,
    }
}

// ---------------------------------------------------------------------------
// Inline handlers for DIDComm protocol-level messages
// ---------------------------------------------------------------------------
//
// These are NOT VTA messages — they're standard DIDComm 2.0 protocols
// that the framework-routed transport handles via the framework crate's
// built-in handlers. We replicate them here for parity on the HTTP-
// signed transport.

fn handle_trust_ping(ping: &Message, server_did: &str) -> Result<(String, Value), AppError> {
    let sender_did = ping
        .from
        .as_deref()
        .ok_or_else(|| AppError::Validation("trust-ping has no 'from' DID".into()))?;

    info!(from = sender_did, "received trust-ping");

    let pong = TrustPing::default()
        .generate_pong_message(ping, Some(server_did))
        .map_err(|e| AppError::Internal(format!("trust-ping pong generation failed: {e}")))?;

    Ok((pong.typ.clone(), pong.body.clone()))
}

fn handle_discover_features(
    query_msg: &Message,
    server_did: &str,
) -> Result<(String, Value), AppError> {
    let sender_did = query_msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Validation("discover-features query has no 'from' DID".into()))?;

    info!(from = sender_did, "received discover-features query");

    let features = DiscoverFeatures {
        protocols: vec![
            "https://didcomm.org/trust-ping/2.0".into(),
            "https://didcomm.org/discover-features/2.0".into(),
            "https://affinidi.com/webvh/1.0".into(),
        ],
        goal_codes: vec![],
        headers: vec![],
    };

    let disclosure = features
        .generate_disclosure_message(server_did, sender_did, query_msg, None)
        .map_err(|e| {
            AppError::Internal(format!(
                "discover-features disclosure generation failed: {e}"
            ))
        })?;

    Ok((disclosure.typ.clone(), disclosure.body.clone()))
}

// Per-arm dispatcher coverage lives in `messaging::tests::dispatch_did_op_*`
// — both transports share the same dispatcher, so testing it once is
// sufficient. The wire-level transport (envelope pack/unpack, JWS
// verify) is exercised by the e2e mediator tests in `tests/`.

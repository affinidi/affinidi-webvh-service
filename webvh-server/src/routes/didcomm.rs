//! DIDComm v2 protocol handler for DID management operations.
//!
//! All messages are received and returned as DIDComm signed messages via a single
//! `POST /api/didcomm` endpoint. Business-logic errors are returned as packed
//! `did/problem-report` messages; transport-level errors are returned as HTTP errors.

use affinidi_tdk::didcomm::{Message, UnpackOptions};
use affinidi_tdk::messaging::protocols::discover_features::DiscoverFeatures;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Message type constants
// ---------------------------------------------------------------------------

const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const DISCOVER_FEATURES_QUERY_TYPE: &str = "https://didcomm.org/discover-features/2.0/queries";

const MSG_DID_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/request";
const MSG_DID_OFFER: &str = "https://affinidi.com/webvh/1.0/did/offer";
const MSG_DID_PUBLISH: &str = "https://affinidi.com/webvh/1.0/did/publish";
const MSG_DID_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/confirm";
const MSG_WITNESS_PUBLISH: &str = "https://affinidi.com/webvh/1.0/did/witness-publish";
const MSG_WITNESS_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/witness-confirm";
const MSG_INFO_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/info-request";
const MSG_INFO: &str = "https://affinidi.com/webvh/1.0/did/info";
const MSG_LIST_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/list-request";
const MSG_LIST: &str = "https://affinidi.com/webvh/1.0/did/list";
const MSG_DELETE: &str = "https://affinidi.com/webvh/1.0/did/delete";
const MSG_DELETE_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/delete-confirm";
const MSG_PROBLEM_REPORT: &str = "https://affinidi.com/webvh/1.0/did/problem-report";

// ---------------------------------------------------------------------------
// Protocol error (maps to DIDComm problem-report)
// ---------------------------------------------------------------------------

struct ProtocolError {
    code: String,
    comment: String,
}

impl ProtocolError {
    fn new(code: impl Into<String>, comment: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            comment: comment.into(),
        }
    }
}

/// Convert an [`AppError`] into a [`ProtocolError`] with an appropriate DIDComm error code.
fn map_app_error(err: AppError) -> ProtocolError {
    let comment = err.to_string();
    let code = match &err {
        AppError::Unauthorized(_) | AppError::Forbidden(_) => "e.p.did.unauthorized",
        AppError::QuotaExceeded(msg) => {
            if msg.contains("size") {
                "e.p.did.size-exceeded"
            } else {
                "e.p.did.quota-exceeded"
            }
        }
        AppError::Conflict(_) => "e.p.did.path-unavailable",
        AppError::NotFound(_) => "e.p.did.mnemonic-not-found",
        AppError::Validation(msg) => {
            if msg.contains("log entry") || msg.contains("jsonl") || msg.contains("JSONL") {
                "e.p.did.invalid-log"
            } else if msg.contains("path") {
                "e.p.did.path-invalid"
            } else if msg.contains("witness") {
                "e.p.did.witness-invalid"
            } else {
                "e.p.did.validation-error"
            }
        }
        _ => "e.p.did.internal-error",
    };
    ProtocolError::new(code, comment)
}

// ---------------------------------------------------------------------------
// Main handler — POST /api/didcomm
// ---------------------------------------------------------------------------

/// Receives a DIDComm signed message, routes it by `type`, and returns a
/// packed DIDComm response (or problem-report on business-logic errors).
pub async fn handle(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: String,
) -> Result<Response, AppError> {
    let (did_resolver, secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    // Unpack the incoming DIDComm message
    let (msg, _metadata) = Message::unpack_string(
        &body,
        did_resolver,
        secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .map_err(|e| AppError::Validation(format!("failed to unpack DIDComm message: {e}")))?;

    // Verify the DIDComm sender matches the authenticated DID
    let sender_did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Validation("DIDComm message missing 'from' field".into()))?;
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);
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

    // Dispatch to sub-handler; convert business errors into problem-reports
    let (response_type, response_body) = match dispatch(&auth, &state, &msg, server_did).await {
        Ok(result) => result,
        Err(pe) => {
            warn!(
                code = %pe.code,
                comment = %pe.comment,
                msg_type = %msg.type_,
                did = %auth.did,
                "DIDComm protocol error"
            );
            (
                MSG_PROBLEM_REPORT.to_string(),
                json!({ "code": pe.code, "comment": pe.comment }),
            )
        }
    };

    // Build response DIDComm message
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

    // Sign with the server's Ed25519 key
    let kid = format!("{server_did}#key-0");
    let (packed, _meta) = response_msg
        .pack_signed(&kid, did_resolver, secrets_resolver)
        .await
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

async fn dispatch(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
    server_did: &str,
) -> Result<(String, Value), ProtocolError> {
    match msg.type_.as_str() {
        TRUST_PING_TYPE => handle_trust_ping(msg, server_did),
        DISCOVER_FEATURES_QUERY_TYPE => handle_discover_features(msg, server_did),
        MSG_DID_REQUEST => handle_did_request(auth, state, msg).await,
        MSG_DID_PUBLISH => handle_did_publish(auth, state, msg).await,
        MSG_WITNESS_PUBLISH => handle_witness_publish(auth, state, msg).await,
        MSG_INFO_REQUEST => handle_info_request(auth, state, msg).await,
        MSG_LIST_REQUEST => handle_list_request(auth, state, msg).await,
        MSG_DELETE => handle_delete(auth, state, msg).await,
        other => Err(ProtocolError::new(
            "e.p.did.unknown-type",
            format!("unknown message type: {other}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Sub-handlers
// ---------------------------------------------------------------------------

/// `trust-ping/2.0/ping` -> `trust-ping/2.0/ping-response`
///
/// Returns the pong message type and body directly; the caller packs it.
fn handle_trust_ping(
    ping: &Message,
    server_did: &str,
) -> Result<(String, Value), ProtocolError> {
    let sender_did = ping
        .from
        .as_deref()
        .ok_or_else(|| ProtocolError::new("e.p.trust-ping.no-from", "trust-ping has no 'from' DID"))?;

    info!(from = sender_did, "received trust-ping");

    let pong = TrustPing::default()
        .generate_pong_message(ping, Some(server_did))
        .map_err(|e| ProtocolError::new("e.p.trust-ping.error", e.to_string()))?;

    Ok((pong.type_.clone(), pong.body.clone()))
}

/// `discover-features/2.0/queries` -> `discover-features/2.0/disclose`
///
/// Returns the disclosure message type and body; the caller packs it.
fn handle_discover_features(
    query_msg: &Message,
    server_did: &str,
) -> Result<(String, Value), ProtocolError> {
    let sender_did = query_msg
        .from
        .as_deref()
        .ok_or_else(|| {
            ProtocolError::new(
                "e.p.discover-features.no-from",
                "discover-features query has no 'from' DID",
            )
        })?;

    info!(from = sender_did, "received discover-features query");

    // Build a DiscoverFeatures state with our supported protocols
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
        .map_err(|e| ProtocolError::new("e.p.discover-features.error", e.to_string()))?;

    Ok((disclosure.type_.clone(), disclosure.body.clone()))
}

/// `did/request` -> `did/offer`
async fn handle_did_request(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let path = msg.body.get("path").and_then(|v| v.as_str());

    let result = did_ops::create_did(auth, state, path)
        .await
        .map_err(map_app_error)?;

    let server_did = state.config.server_did.as_deref().unwrap_or_default();

    Ok((
        MSG_DID_OFFER.to_string(),
        json!({
            "mnemonic": result.mnemonic,
            "did_url": result.did_url,
            "server_did": server_did,
        }),
    ))
}

/// `did/publish` -> `did/confirm`
async fn handle_did_publish(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProtocolError::new("e.p.did.invalid-log", "missing 'mnemonic' in body"))?;

    let did_log = msg
        .body
        .get("did_log")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProtocolError::new("e.p.did.invalid-log", "missing 'did_log' in body"))?;

    let result = did_ops::publish_did(auth, state, mnemonic, did_log)
        .await
        .map_err(map_app_error)?;

    Ok((
        MSG_DID_CONFIRM.to_string(),
        json!({
            "did_id": result.did_id,
            "did_url": result.did_url,
            "version_id": result.version_id,
            "version_count": result.version_count,
        }),
    ))
}

/// `did/witness-publish` -> `did/witness-confirm`
async fn handle_witness_publish(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProtocolError::new("e.p.did.witness-invalid", "missing 'mnemonic' in body")
        })?;

    let witness = msg.body.get("witness").ok_or_else(|| {
        ProtocolError::new("e.p.did.witness-invalid", "missing 'witness' in body")
    })?;

    let witness_str = serde_json::to_string(witness)
        .map_err(|e| ProtocolError::new("e.p.did.witness-invalid", e.to_string()))?;

    if witness_str.is_empty() || witness_str == "null" {
        return Err(ProtocolError::new(
            "e.p.did.witness-invalid",
            "witness content cannot be empty",
        ));
    }

    let result = did_ops::upload_witness(auth, state, mnemonic, &witness_str)
        .await
        .map_err(map_app_error)?;

    Ok((
        MSG_WITNESS_CONFIRM.to_string(),
        json!({
            "mnemonic": mnemonic,
            "witness_url": result.witness_url,
        }),
    ))
}

/// `did/info-request` -> `did/info`
async fn handle_info_request(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProtocolError::new("e.p.did.mnemonic-not-found", "missing 'mnemonic' in body")
        })?;

    let result = did_ops::get_did_info(auth, state, mnemonic)
        .await
        .map_err(map_app_error)?;

    let log_metadata_json = result
        .log_metadata
        .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);

    Ok((
        MSG_INFO.to_string(),
        json!({
            "mnemonic": result.record.mnemonic,
            "did_id": result.record.did_id,
            "did_url": result.did_url,
            "owner": result.record.owner,
            "created_at": result.record.created_at,
            "updated_at": result.record.updated_at,
            "version_count": result.record.version_count,
            "content_size": result.record.content_size,
            "stats": {
                "total_resolves": result.stats.total_resolves,
                "total_updates": result.stats.total_updates,
                "last_resolved_at": result.stats.last_resolved_at,
                "last_updated_at": result.stats.last_updated_at,
            },
            "log_metadata": log_metadata_json,
        }),
    ))
}

/// `did/list-request` -> `did/list`
async fn handle_list_request(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let requested_owner = msg.body.get("owner").and_then(|v| v.as_str());

    let entries = did_ops::list_dids(auth, state, requested_owner)
        .await
        .map_err(map_app_error)?;

    let entries_json: Vec<Value> = entries
        .into_iter()
        .map(|e| {
            json!({
                "mnemonic": e.mnemonic,
                "did_id": e.did_id,
                "created_at": e.created_at,
                "updated_at": e.updated_at,
                "version_count": e.version_count,
                "total_resolves": e.total_resolves,
            })
        })
        .collect();

    Ok((MSG_LIST.to_string(), json!({ "dids": entries_json })))
}

/// `did/delete` -> `did/delete-confirm`
async fn handle_delete(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProtocolError::new("e.p.did.mnemonic-not-found", "missing 'mnemonic' in body")
        })?;

    let result = did_ops::delete_did(auth, state, mnemonic)
        .await
        .map_err(map_app_error)?;

    Ok((
        MSG_DELETE_CONFIRM.to_string(),
        json!({
            "mnemonic": result.mnemonic,
            "did_id": result.did_id,
        }),
    ))
}

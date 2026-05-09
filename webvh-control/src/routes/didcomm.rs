//! DIDComm v2 protocol handler for DID management operations.
//!
//! All messages are received and returned as DIDComm signed messages via a single
//! `POST /api/didcomm` endpoint. Business-logic errors are returned as packed
//! `did/problem-report` messages; transport-level errors are returned as HTTP errors.

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
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;
use crate::server_push;

const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const DISCOVER_FEATURES_QUERY_TYPE: &str = "https://didcomm.org/discover-features/2.0/queries";

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

pub async fn handle(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: String,
) -> Result<Response, AppError> {
    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    // sender_base is the JWS-verified DID (unpack_signed enforced from == signer).
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

    let (response_type, response_body) = match dispatch(&auth, &state, &msg, server_did).await {
        Ok(result) => result,
        Err(pe) => {
            warn!(
                code = %pe.code,
                comment = %pe.comment,
                msg_type = %msg.typ,
                did = %auth.did,
                "DIDComm protocol error"
            );
            (
                MSG_PROBLEM_REPORT.to_string(),
                json!({ "code": pe.code, "comment": pe.comment }),
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

async fn dispatch(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
    server_did: &str,
) -> Result<(String, Value), ProtocolError> {
    match msg.typ.as_str() {
        TRUST_PING_TYPE => handle_trust_ping(msg, server_did),
        DISCOVER_FEATURES_QUERY_TYPE => handle_discover_features(msg, server_did),
        MSG_DID_REQUEST => handle_did_request(auth, state, msg).await,
        MSG_DID_PUBLISH => handle_did_publish(auth, state, msg).await,
        MSG_WITNESS_PUBLISH => handle_witness_publish(auth, state, msg).await,
        MSG_INFO_REQUEST => handle_info_request(auth, state, msg).await,
        MSG_LIST_REQUEST => handle_list_request(auth, state, msg).await,
        MSG_DELETE => handle_delete(auth, state, msg).await,
        MSG_DID_CHANGE_OWNER => handle_change_owner(auth, state, msg).await,
        other => Err(ProtocolError::new(
            "e.p.did.unknown-type",
            format!("unknown message type: {other}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Sub-handlers
// ---------------------------------------------------------------------------

fn handle_trust_ping(ping: &Message, server_did: &str) -> Result<(String, Value), ProtocolError> {
    let sender_did = ping.from.as_deref().ok_or_else(|| {
        ProtocolError::new("e.p.trust-ping.no-from", "trust-ping has no 'from' DID")
    })?;

    info!(from = sender_did, "received trust-ping");

    let pong = TrustPing::default()
        .generate_pong_message(ping, Some(server_did))
        .map_err(|e| ProtocolError::new("e.p.trust-ping.error", e.to_string()))?;

    Ok((pong.typ.clone(), pong.body.clone()))
}

fn handle_discover_features(
    query_msg: &Message,
    server_did: &str,
) -> Result<(String, Value), ProtocolError> {
    let sender_did = query_msg.from.as_deref().ok_or_else(|| {
        ProtocolError::new(
            "e.p.discover-features.no-from",
            "discover-features query has no 'from' DID",
        )
    })?;

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
        .map_err(|e| ProtocolError::new("e.p.discover-features.error", e.to_string()))?;

    Ok((disclosure.typ.clone(), disclosure.body.clone()))
}

async fn handle_did_request(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let path = msg.body.get("path").and_then(|v| v.as_str());
    let force = msg
        .body
        .get("force")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let result = did_ops::create_did(auth, state, path, force)
        .await
        .map_err(map_app_error)?;

    // No fan-out on force-replace: see `routes/did_manage::request_uri`.

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

    did_ops::publish_did(auth, state, mnemonic, did_log)
        .await
        .map_err(map_app_error)?;

    // Read back the record for protocol response fields
    let record: affinidi_webvh_common::did_ops::DidRecord = state
        .dids_ks
        .get(affinidi_webvh_common::did_ops::did_key(mnemonic))
        .await
        .map_err(|e| ProtocolError::new("e.p.did.internal-error", e.to_string()))?
        .ok_or_else(|| {
            ProtocolError::new("e.p.did.internal-error", "record missing after publish")
        })?;

    let base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .unwrap_or("http://localhost");
    let did_url = format!("{base_url}/{mnemonic}/did.jsonl");

    server_push::notify_servers_did(state, mnemonic.to_string());

    Ok((
        MSG_DID_CONFIRM.to_string(),
        json!({
            "did_id": record.did_id,
            "did_url": did_url,
            "version_id": record.did_id,
            "version_count": record.version_count,
        }),
    ))
}

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

    did_ops::upload_witness(auth, state, mnemonic, &witness_str)
        .await
        .map_err(map_app_error)?;

    let base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .unwrap_or("http://localhost");
    let witness_url = format!("{base_url}/{mnemonic}/did-witness.json");

    server_push::notify_servers_did(state, mnemonic.to_string());

    Ok((
        MSG_WITNESS_CONFIRM.to_string(),
        json!({
            "mnemonic": mnemonic,
            "witness_url": witness_url,
        }),
    ))
}

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

    let (record, log_metadata) = did_ops::get_did_info(auth, state, mnemonic)
        .await
        .map_err(map_app_error)?;

    let stats_key = format!("stats:{mnemonic}");
    let did_stats: affinidi_webvh_common::DidStats = state
        .stats_ks
        .get(stats_key)
        .await
        .unwrap_or(None)
        .unwrap_or_default();

    let log_metadata_json = log_metadata
        .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);

    let base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .unwrap_or("http://localhost");
    let did_url = format!("{base_url}/{mnemonic}/did.jsonl");

    Ok((
        MSG_INFO.to_string(),
        json!({
            "mnemonic": record.mnemonic,
            "did_id": record.did_id,
            "did_url": did_url,
            "owner": record.owner,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "version_count": record.version_count,
            "content_size": record.content_size,
            "stats": {
                "total_resolves": did_stats.total_resolves,
                "total_updates": did_stats.total_updates,
                "last_resolved_at": did_stats.last_resolved_at,
                "last_updated_at": did_stats.last_updated_at,
            },
            "log_metadata": log_metadata_json,
        }),
    ))
}

async fn handle_list_request(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let requested_owner = msg.body.get("owner").and_then(|v| v.as_str());

    let entries = did_ops::list_dids(auth, state, requested_owner, None, None)
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

    let did_id = did_ops::delete_did(auth, state, mnemonic)
        .await
        .map_err(map_app_error)?;

    server_push::notify_servers_delete(state, mnemonic.to_string());

    Ok((
        MSG_DELETE_CONFIRM.to_string(),
        json!({
            "mnemonic": mnemonic,
            "did_id": did_id,
        }),
    ))
}

async fn handle_change_owner(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), ProtocolError> {
    let mnemonic = msg
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProtocolError::new("e.p.did.validation-error", "missing 'mnemonic' in body")
        })?;

    let new_owner = msg
        .body
        .get("new_owner")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProtocolError::new("e.p.did.validation-error", "missing 'new_owner' in body")
        })?;

    let record = did_ops::change_did_owner(auth, state, mnemonic, new_owner)
        .await
        .map_err(map_app_error)?;

    Ok((
        MSG_DID_CHANGE_OWNER_CONFIRM.to_string(),
        json!({
            "mnemonic": record.mnemonic,
            "owner": record.owner,
            "updated_at": record.updated_at,
        }),
    ))
}

//! DIDComm message routing and handlers for the WebVH server.
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

use crate::acl::{Role, check_acl};
use crate::auth::AuthClaims;
use crate::auth::session::create_authenticated_session;
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Message type constants
// ---------------------------------------------------------------------------

const MSG_AUTHENTICATE: &str = "https://affinidi.com/webvh/1.0/authenticate";
const MSG_AUTH_RESPONSE: &str = "https://affinidi.com/webvh/1.0/authenticate-response";

// WebVH DID management message types
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

// Sync message types (control plane → server via mediator)
const MSG_SYNC_UPDATE: &str = "https://affinidi.com/webvh/1.0/did/sync-update";
const MSG_SYNC_UPDATE_ACK: &str = "https://affinidi.com/webvh/1.0/did/sync-update-ack";
const MSG_SYNC_DELETE: &str = "https://affinidi.com/webvh/1.0/did/sync-delete";
const MSG_SYNC_DELETE_ACK: &str = "https://affinidi.com/webvh/1.0/did/sync-delete-ack";

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the DIDComm router for the WebVH server.
pub fn build_server_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route(MSG_AUTHENTICATE, handler_fn(handle_authenticate))?
        .route(MSG_SYNC_UPDATE, handler_fn(handle_sync_update))?
        .route(MSG_SYNC_DELETE, handler_fn(handle_sync_delete))?
        .route(MSG_DID_REQUEST, handler_fn(handle_webvh_message))?
        .route(MSG_DID_PUBLISH, handler_fn(handle_webvh_message))?
        .route(MSG_WITNESS_PUBLISH, handler_fn(handle_webvh_message))?
        .route(MSG_INFO_REQUEST, handler_fn(handle_webvh_message))?
        .route(MSG_LIST_REQUEST, handler_fn(handle_webvh_message))?
        .route(MSG_DELETE, handler_fn(handle_webvh_message))?
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

    let (response_type, response_body) = match check_acl(&state.acl_ks, sender).await {
        Ok(role) => {
            let jwt_keys = state
                .jwt_keys
                .as_ref()
                .ok_or_else(|| DIDCommServiceError::Internal("JWT keys not configured".into()))?;

            match create_authenticated_session(
                &state.sessions_ks,
                jwt_keys,
                sender,
                &role,
                state.config.auth.access_token_expiry,
                state.config.auth.refresh_token_expiry,
            )
            .await
            {
                Ok(tokens) => {
                    info!(did = sender, role = %role, "mediator auth: session created");
                    (
                        MSG_AUTH_RESPONSE.to_string(),
                        json!({
                            "session_id": tokens.session_id,
                            "access_token": tokens.access_token,
                            "access_expires_at": tokens.access_expires_at,
                            "refresh_token": tokens.refresh_token,
                            "refresh_expires_at": tokens.refresh_expires_at,
                        }),
                    )
                }
                Err(e) => problem_report("e.p.did.internal-error", &e.to_string()),
            }
        }
        Err(e) => {
            let code = map_app_error_code(&e);
            warn!(code, did = sender, "mediator auth: ACL denied");
            problem_report(code, &e.to_string())
        }
    };

    Ok(Some(DIDCommResponse::new(response_type, response_body)
        .thid(message.id.clone())))
}

async fn handle_webvh_message(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;

    let (response_type, response_body) = match check_acl(&state.acl_ks, sender).await {
        Ok(role) => {
            let auth = AuthClaims {
                did: sender.to_string(),
                role,
            };
            match dispatch_did_op(&auth, &state, &message).await {
                Ok(result) => result,
                Err(e) => {
                    let code = map_app_error_code(&e);
                    warn!(code, msg_type = %message.typ, did = sender, "DIDComm protocol error");
                    problem_report(code, &e.to_string())
                }
            }
        }
        Err(e) => {
            let code = map_app_error_code(&e);
            warn!(code, msg_type = %message.typ, did = sender, "mediator: ACL denied");
            problem_report(code, &e.to_string())
        }
    };

    Ok(Some(DIDCommResponse::new(response_type, response_body)
        .thid(message.id.clone())))
}

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

    Ok(Some(DIDCommResponse::new(response_type, response_body)
        .thid(message.id.clone())))
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

    Ok(Some(DIDCommResponse::new(response_type, response_body)
        .thid(message.id.clone())))
}

async fn handle_fallback(
    _ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    warn!(msg_type = %message.typ, "unknown message type — ignoring");
    Ok(None)
}

// ---------------------------------------------------------------------------
// Sync message handling (control plane → server via mediator)
// ---------------------------------------------------------------------------

async fn do_sync_update(
    sender: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), String> {
    use crate::control_register::apply_single_update;
    use affinidi_webvh_common::DidSyncUpdate;

    let role = check_acl(&state.acl_ks, sender).await.map_err(|e| e.to_string())?;
    if !matches!(role, Role::Admin | Role::Service) {
        warn!(did = sender, "sync message rejected: requires admin or service role");
        return Ok(problem_report("e.p.did.unauthorized", "admin or service role required for sync messages"));
    }

    let mnemonic = msg.body.get("mnemonic").and_then(|v| v.as_str())
        .ok_or("missing 'mnemonic' in sync-update")?;
    let did_id = msg.body.get("did_id").and_then(|v| v.as_str())
        .ok_or("missing 'did_id' in sync-update")?;
    let log_content = msg.body.get("log_content").and_then(|v| v.as_str())
        .ok_or("missing 'log_content' in sync-update")?;
    let witness_content = msg.body.get("witness_content")
        .and_then(|v| v.as_str())
        .map(String::from);
    let version_count = msg.body.get("version_count").and_then(|v| v.as_u64())
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
    let role = check_acl(&state.acl_ks, sender).await.map_err(|e| e.to_string())?;
    if !matches!(role, Role::Admin | Role::Service) {
        warn!(did = sender, "sync message rejected: requires admin or service role");
        return Ok(problem_report("e.p.did.unauthorized", "admin or service role required for sync messages"));
    }

    let mnemonic = msg.body.get("mnemonic").and_then(|v| v.as_str())
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
// DID operation dispatch (mirrors routes/didcomm.rs dispatch)
// ---------------------------------------------------------------------------

async fn dispatch_did_op(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), AppError> {
    match msg.typ.as_str() {
        MSG_DID_REQUEST => {
            let path = msg.body.get("path").and_then(|v| v.as_str());
            let result = did_ops::create_did(auth, state, path).await?;
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
        MSG_DID_PUBLISH => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let did_log = msg
                .body
                .get("did_log")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'did_log' in body".into()))?;
            let result = did_ops::publish_did(auth, state, mnemonic, did_log).await?;
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
        MSG_WITNESS_PUBLISH => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let witness = msg
                .body
                .get("witness")
                .ok_or_else(|| AppError::Validation("missing 'witness' in body".into()))?;
            let witness_str = serde_json::to_string(witness)?;
            if witness_str.is_empty() || witness_str == "null" {
                return Err(AppError::Validation(
                    "witness content cannot be empty".into(),
                ));
            }
            let result = did_ops::upload_witness(auth, state, mnemonic, &witness_str).await?;
            Ok((
                MSG_WITNESS_CONFIRM.to_string(),
                json!({
                    "mnemonic": mnemonic,
                    "witness_url": result.witness_url,
                }),
            ))
        }
        MSG_INFO_REQUEST => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let result = did_ops::get_did_info(auth, state, mnemonic).await?;
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
        MSG_LIST_REQUEST => {
            let requested_owner = msg.body.get("owner").and_then(|v| v.as_str());
            let entries = did_ops::list_dids(auth, state, requested_owner).await?;
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
        MSG_DELETE => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let result = did_ops::delete_did(auth, state, mnemonic).await?;
            Ok((
                MSG_DELETE_CONFIRM.to_string(),
                json!({
                    "mnemonic": result.mnemonic,
                    "did_id": result.did_id,
                }),
            ))
        }
        other => Err(AppError::Validation(format!(
            "unknown message type: {other}"
        ))),
    }
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

/// Map an AppError to a DIDComm error code string.
fn map_app_error_code(err: &AppError) -> &'static str {
    match err {
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
    }
}

//! DIDComm messaging for the control plane.
//!
//! **Inbound:** Uses the `affinidi-messaging-didcomm-service` framework for
//! mediator connection, message dispatch, and response handling. Handles
//! the full VTA provisioning protocol (did/request, did/publish, etc.)
//! as well as sync acknowledgements from servers.
//!
//! **Outbound:** Sync push messages are sent via `server_push.rs` using the
//! shared `DIDCommService` — no separate ATM connection needed.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, MiddlewareResult, Next, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    middleware_fn, trust_ping_handler,
};
use affinidi_webvh_common::did_ops::did_key;
use affinidi_webvh_common::didcomm_types::*;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::acl::check_acl;
use crate::auth::AuthClaims;
use crate::auth::session::create_authenticated_session;
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;
use crate::server_push;

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
        // VTA provisioning protocol
        .route(MSG_AUTHENTICATE, handler_fn(handle_authenticate))?
        .route(MSG_DID_REQUEST, handler_fn(handle_webvh_message))?
        .route(MSG_DID_PUBLISH, handler_fn(handle_webvh_message))?
        .route(MSG_WITNESS_PUBLISH, handler_fn(handle_webvh_message))?
        .route(MSG_INFO_REQUEST, handler_fn(handle_webvh_message))?
        .route(MSG_LIST_REQUEST, handler_fn(handle_webvh_message))?
        .route(MSG_DELETE, handler_fn(handle_webvh_message))?
        // Server registration
        .route(MSG_SERVER_REGISTER, handler_fn(handle_server_register))?
        // Health pong from servers
        .route(MSG_HEALTH_PONG, handler_fn(handle_health_pong))?
        // Stats sync from servers
        .route(MSG_STATS_SYNC, handler_fn(handle_stats_sync))?
        // Sync acknowledgements from servers
        .route(MSG_SYNC_UPDATE_ACK, handler_fn(handle_sync_ack))?
        .route(MSG_SYNC_DELETE_ACK, handler_fn(handle_sync_ack))?
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
        MSG_HEALTH_PING,
        MSG_HEALTH_PONG,
        MSG_STATS_SYNC,
        MSG_STATS_ACK,
        MESSAGE_PICKUP_STATUS_TYPE,
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

// ---------------------------------------------------------------------------
// VTA provisioning handlers
// ---------------------------------------------------------------------------

async fn handle_authenticate(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    info!(sender = sender, msg_type = %message.typ, "inbound DIDComm: authenticate");

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

    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

async fn handle_webvh_message(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    info!(sender = sender, msg_type = %message.typ, "inbound DIDComm: webvh message");

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
                    let comment = e.to_string();
                    warn!(code, comment, msg_type = %message.typ, did = sender, "DIDComm protocol error");
                    problem_report(code, &comment)
                }
            }
        }
        Err(e) => {
            let code = map_app_error_code(&e);
            let comment = e.to_string();
            warn!(code, comment, msg_type = %message.typ, did = sender, "mediator: ACL denied");
            problem_report(code, &comment)
        }
    };

    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

// ---------------------------------------------------------------------------
// DID operation dispatch
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

            did_ops::publish_did(auth, state, mnemonic, did_log).await?;

            // Read back the record for protocol response fields
            let record: affinidi_webvh_common::did_ops::DidRecord = state
                .dids_ks
                .get(did_key(mnemonic))
                .await?
                .ok_or_else(|| AppError::Internal("record missing after publish".into()))?;

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

            did_ops::upload_witness(auth, state, mnemonic, &witness_str).await?;

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
        MSG_INFO_REQUEST => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let (record, log_metadata) = did_ops::get_did_info(auth, state, mnemonic).await?;

            // Get stats for this DID
            let stats_key = format!("stats:{mnemonic}");
            let did_stats: affinidi_webvh_common::DidStats =
                state.stats_ks.get(stats_key).await?.unwrap_or_default();

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
        MSG_LIST_REQUEST => {
            let requested_owner = msg.body.get("owner").and_then(|v| v.as_str());
            let entries = did_ops::list_dids(auth, state, requested_owner, None, None).await?;
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
            let did_id = did_ops::delete_did(auth, state, mnemonic).await?;

            server_push::notify_servers_delete(state, mnemonic.to_string());

            Ok((
                MSG_DELETE_CONFIRM.to_string(),
                json!({
                    "mnemonic": mnemonic,
                    "did_id": did_id,
                }),
            ))
        }
        other => Err(AppError::Validation(format!(
            "unknown message type: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Sync acknowledgement handler
// ---------------------------------------------------------------------------

async fn handle_sync_ack(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = ctx.sender_did.as_deref().unwrap_or("unknown");
    let status = message
        .body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let mnemonic = message
        .body
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let ack_type = if message.typ.contains("update") {
        "update"
    } else {
        "delete"
    };
    info!(
        sender,
        mnemonic, status, ack_type, "DID sync: server acknowledged {ack_type}"
    );
    Ok(None)
}

// ---------------------------------------------------------------------------
// Stats sync handler (server → control plane via DIDComm)
// ---------------------------------------------------------------------------

async fn handle_stats_sync(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    use crate::routes::stats_sync;

    let sender = require_sender(&ctx)?;

    // Validate ACL
    if check_acl(&state.acl_ks, sender).await.is_err() {
        warn!(
            did = sender,
            "stats sync via DIDComm rejected: DID not in ACL"
        );
        return Ok(Some(
            DIDCommResponse::new(
                MSG_PROBLEM_REPORT.to_string(),
                json!({ "code": "e.p.stats.unauthorized", "comment": "DID not in ACL" }),
            )
            .thid(message.id.clone()),
        ));
    }

    let seq = message
        .body
        .get("seq")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let server_did = message
        .body
        .get("server_did")
        .and_then(|v| v.as_str())
        .unwrap_or(sender);

    // Idempotency check (reuse REST handler's static map)
    if !stats_sync::accept_seq(server_did, seq) {
        debug!(server_did, seq, "stats sync via DIDComm: stale sequence");
        return Ok(Some(
            DIDCommResponse::new(
                MSG_STATS_ACK.to_string(),
                json!({ "status": "skipped", "reason": "stale_seq" }),
            )
            .thid(message.id.clone()),
        ));
    }

    // Record deltas
    if let Some(deltas) = message.body.get("did_deltas").and_then(|v| v.as_array()) {
        for d in deltas {
            let mnemonic = d.get("mnemonic").and_then(|v| v.as_str()).unwrap_or("");
            if mnemonic.is_empty() {
                continue;
            }
            let resolve_delta = d.get("resolve_delta").and_then(|v| v.as_u64()).unwrap_or(0);
            let update_delta = d.get("update_delta").and_then(|v| v.as_u64()).unwrap_or(0);
            let last_resolved_at = d.get("last_resolved_at").and_then(|v| v.as_u64());
            let last_updated_at = d.get("last_updated_at").and_then(|v| v.as_u64());

            state.stats_collector.record_deltas(
                mnemonic,
                resolve_delta,
                update_delta,
                last_resolved_at,
                last_updated_at,
            );
        }
    }

    let delta_count = message
        .body
        .get("did_deltas")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    debug!(
        server_did,
        seq, delta_count, "stats sync via DIDComm accepted"
    );

    Ok(Some(
        DIDCommResponse::new(MSG_STATS_ACK.to_string(), json!({ "status": "accepted" }))
            .thid(message.id.clone()),
    ))
}

// ---------------------------------------------------------------------------
// Health pong handler (server → control plane)
// ---------------------------------------------------------------------------

async fn handle_health_pong(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    use crate::registry::{self, ServiceStatus};

    let sender = require_sender(&ctx)?;
    let status = message
        .body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let version = message
        .body
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    debug!(sender, status, version, "health pong received from server");

    // Find the instance by sender DID and mark it active
    let instance_id = sender.replace(':', "_");
    let now = crate::auth::session::now_epoch();
    if let Err(e) = registry::update_instance_status(
        &state.registry_ks,
        &instance_id,
        ServiceStatus::Active,
        now,
    )
    .await
    {
        warn!(instance_id, error = %e, "failed to update instance status from health pong");
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Server registration handler
// ---------------------------------------------------------------------------

async fn handle_server_register(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    use crate::acl::check_acl;
    use crate::registry::{self, ServiceInstance, ServiceStatus, ServiceType};

    let sender = require_sender(&ctx)?;
    info!(
        sender = sender,
        "inbound DIDComm: server registration request"
    );

    // Require pre-approved ACL entry — the server DID must already be in the
    // ACL (added by an admin) before it can register.
    let role = match check_acl(&state.acl_ks, sender).await {
        Ok(role) => role,
        Err(_) => {
            warn!(
                did = sender,
                "server registration rejected: DID not in ACL (requires pre-approval)"
            );
            return Ok(Some(
                DIDCommResponse::new(
                    MSG_PROBLEM_REPORT.to_string(),
                    json!({
                        "code": "e.p.registration.unauthorized",
                        "comment": "server DID must be pre-approved in the ACL before registering"
                    }),
                )
                .thid(message.id.clone()),
            ));
        }
    };

    let public_url = message
        .body
        .get("public_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let label = message
        .body
        .get("label")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Use the sender DID as a stable instance ID (one registration per DID)
    let instance_id = sender.replace(':', "_");

    let instance = ServiceInstance {
        instance_id: instance_id.clone(),
        service_type: ServiceType::Server,
        label,
        url: public_url.to_string(),
        status: ServiceStatus::Active,
        last_health_check: None,
        registered_at: crate::auth::session::now_epoch(),
        metadata: json!({ "did": sender }),
    };

    if let Err(e) = registry::register_instance(&state.registry_ks, &instance).await {
        warn!(did = sender, error = %e, "server registration failed");
        return Ok(Some(
            DIDCommResponse::new(
                MSG_PROBLEM_REPORT.to_string(),
                json!({
                    "code": "e.p.registration.internal-error",
                    "comment": e.to_string()
                }),
            )
            .thid(message.id.clone()),
        ));
    }

    info!(
        did = sender,
        instance_id = %instance_id,
        public_url = public_url,
        role = %role,
        "server registered via DIDComm"
    );

    // Push all existing DIDs to the newly registered server
    server_push::sync_all_dids_to_server(&state, sender.to_string());

    Ok(Some(
        DIDCommResponse::new(
            MSG_SERVER_REGISTER_ACK.to_string(),
            json!({
                "instance_id": instance_id,
                "status": "registered",
            }),
        )
        .thid(message.id.clone()),
    ))
}

async fn handle_fallback(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = ctx.sender_did.as_deref().unwrap_or("unknown");

    // Log problem-report bodies so errors from the remote side are visible
    if message.typ.contains("problem-report") {
        let code = message
            .body
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let comment = message
            .body
            .get("comment")
            .and_then(|v| v.as_str())
            .unwrap_or("(no comment)");
        warn!(
            sender = sender,
            code = code,
            comment = comment,
            "inbound DIDComm: problem-report from remote"
        );
    } else {
        warn!(sender = sender, msg_type = %message.typ, "inbound DIDComm: unhandled message type — ignoring");
    }

    Ok(None)
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

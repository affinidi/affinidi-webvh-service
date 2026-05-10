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
use affinidi_webvh_common::server::problem_report::log_problem_report;
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
        .route(MSG_DID_REGISTER, handler_fn(handle_webvh_message))?
        .route(MSG_DID_PUBLISH, handler_fn(handle_webvh_message))?
        .route(MSG_WITNESS_PUBLISH, handler_fn(handle_webvh_message))?
        .route(MSG_INFO_REQUEST, handler_fn(handle_webvh_message))?
        .route(MSG_LIST_REQUEST, handler_fn(handle_webvh_message))?
        .route(MSG_DELETE, handler_fn(handle_webvh_message))?
        .route(MSG_DID_CHANGE_OWNER, handler_fn(handle_webvh_message))?
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

    let (response_type, response_body) = run_authenticate(&state, sender).await?;

    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

/// Compute the wire-level (response_type, response_body) for an inbound
/// `MSG_AUTHENTICATE`. Extracted so it's directly testable without needing
/// an `ATM`-backed `HandlerContext`.
///
/// On `Err(...)`, the router drops to its `error_handler` and returns a
/// generic problem report — reserved for misconfigured states (no JWT key
/// loaded). All ACL/session failures land in the `Ok(...)` tuple as
/// problem-report bodies so the wire-level error code is stable.
async fn run_authenticate(
    state: &AppState,
    sender: &str,
) -> Result<(String, Value), DIDCommServiceError> {
    let pair = match check_acl(&state.acl_ks, sender).await {
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
    Ok(pair)
}

async fn handle_webvh_message(
    ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = require_sender(&ctx)?;
    info!(sender = sender, msg_type = %message.typ, "inbound DIDComm: webvh message");

    let (response_type, response_body) = run_webvh_dispatch(&state, sender, &message).await;

    Ok(Some(
        DIDCommResponse::new(response_type, response_body).thid(message.id.clone()),
    ))
}

/// Compute the wire-level (response_type, response_body) for any inbound
/// VTA management message — wraps the ACL check, replay-cache gate, and
/// `dispatch_did_op` so the auth + dispatch pipeline is testable as a
/// single unit, without an `ATM`-backed `HandlerContext`. Always
/// returns a tuple; ACL denials, replay rejections, and dispatch
/// errors surface as problem-report bodies.
async fn run_webvh_dispatch(state: &AppState, sender: &str, message: &Message) -> (String, Value) {
    // Replay gate: reject any (sender, msg.id) we've seen within the
    // freshness window. Runs after ACL so an unauthenticated flood
    // can't poison the cache for legitimate senders.
    match check_acl(&state.acl_ks, sender).await {
        Ok(role) => {
            if let Err(e) = state.replay_cache.check_and_insert(sender, &message.id) {
                let code = map_app_error_code(&e);
                warn!(code, msg_type = %message.typ, did = sender, msg_id = %message.id, "DIDComm replay rejected");
                return problem_report(code, &e.to_string());
            }
            let auth = AuthClaims {
                did: sender.to_string(),
                role,
            };
            match dispatch_did_op(&auth, state, message).await {
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
    }
}

// ---------------------------------------------------------------------------
// DID operation dispatch
// ---------------------------------------------------------------------------

/// Single transport-agnostic dispatch table for VTA DID-management
/// `MSG_*` types.
///
/// Both DIDComm transports — the framework router (mediator-routed,
/// E2E-encrypted) and the HTTP-signed `POST /api/didcomm` route
/// (signed-but-not-encrypted) — call this. Without it, the two had
/// drifted: the HTTP-signed dispatcher was missing `MSG_DID_REGISTER`
/// entirely, and the two emitted different protocol error codes for
/// identical wire conditions. See
/// `docs/dispatcher-consolidation-design.md` for the rationale.
pub async fn dispatch_did_op(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), AppError> {
    match msg.typ.as_str() {
        MSG_DID_REQUEST => {
            let path = msg.body.get("path").and_then(|v| v.as_str());
            let force = msg
                .body
                .get("force")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let result = did_ops::create_did(auth, state, path, force).await?;
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
        MSG_DID_REGISTER => {
            // Atomic claim-and-publish — see did_ops::register_did_atomic.
            // Body shape mirrors `DidRegisterRequest` from webvh-common.
            let path = msg
                .body
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'path' in body".into()))?;
            let did_log = msg
                .body
                .get("did_log")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'did_log' in body".into()))?;
            let force = msg
                .body
                .get("force")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let result = did_ops::register_did_atomic(auth, state, path, did_log, force).await?;
            server_push::notify_servers_did(state, result.mnemonic.clone());

            let server_did = state.config.server_did.as_deref().unwrap_or_default();
            Ok((
                MSG_DID_REGISTER_CONFIRM.to_string(),
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
        MSG_DID_CHANGE_OWNER => {
            let mnemonic = msg
                .body
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'mnemonic' in body".into()))?;
            let new_owner = msg
                .body
                .get("new_owner")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::Validation("missing 'new_owner' in body".into()))?;
            let record = did_ops::change_did_owner(auth, state, mnemonic, new_owner).await?;
            Ok((
                MSG_DID_CHANGE_OWNER_CONFIRM.to_string(),
                json!({
                    "mnemonic": record.mnemonic,
                    "owner": record.owner,
                    "updated_at": record.updated_at,
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

    // Apply the same URL allowlist that the REST `register_service`
    // route enforces. Without this gate, an ACL'd Service-role caller
    // could register an arbitrary URL (cloud-metadata IP, RFC1918,
    // attacker-controlled host) and then wait for an Admin to hit
    // `/api/proxy/server/{instance_id}/...` — `proxy_to_service` would
    // forward the Admin's `Authorization: Bearer ...` to that URL.
    if let Err(e) =
        registry::validate_registered_url(public_url, &state.config.registry.url_allowlist)
    {
        warn!(
            did = sender,
            requested = public_url,
            "DIDComm server registration rejected: URL host not in registry.url_allowlist",
        );
        return Ok(Some(
            DIDCommResponse::new(
                MSG_PROBLEM_REPORT.to_string(),
                json!({
                    "code": "e.p.registration.unauthorized",
                    "comment": e.user_message(),
                }),
            )
            .thid(message.id.clone()),
        ));
    }

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
    let sender = ctx.sender_did.as_deref();
    if log_problem_report("control", sender, &message) {
        return Ok(None);
    }
    warn!(
        sender = sender.unwrap_or("unknown"),
        msg_type = %message.typ,
        "inbound DIDComm: unhandled message type — ignoring"
    );
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

/// Map an internal `AppError` to its DIDComm protocol error code.
///
/// Thin wrapper around `AppError::didcomm_code()` — kept as a function
/// alias so the existing call sites (and the
/// `map_app_error_code_pinned_table` test) don't need to chase the
/// rename. The shared implementation in `webvh-common::server::error`
/// is backed by `ValidationKind` / `QuotaKind` tags rather than
/// substring sniffing, so a wording change in any
/// `AppError::Validation("...")` literal can no longer silently
/// re-route the protocol code.
fn map_app_error_code(err: &AppError) -> &'static str {
    err.didcomm_code()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    use affinidi_messaging_didcomm::Message;
    use affinidi_webvh_common::did_ops::{DidRecord, did_key, owner_key};
    use affinidi_webvh_common::server::acl::{AclEntry, Role, store_acl_entry};
    use affinidi_webvh_common::server::config::{
        AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
    };
    use affinidi_webvh_common::server::stats_collector::StatsCollector;
    use affinidi_webvh_common::server::store::Store;
    use serde_json::json;

    use crate::auth::AuthClaims;
    use crate::config::{AppConfig, RegistryConfig};
    use crate::server::AppState;

    use super::*;

    /// Build a minimal `AppState` backed by a tempdir-rooted fjall store. The
    /// returned `_dir` guard must outlive `state` — when it drops, fjall
    /// removes the partition files on disk.
    async fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.expect("open store");
        let sessions_ks = store.keyspace("sessions").expect("sessions ks");
        let acl_ks = store.keyspace("acl").expect("acl ks");
        let registry_ks = store.keyspace("registry").expect("registry ks");
        let dids_ks = store.keyspace("dids").expect("dids ks");
        let stats_ks = store.keyspace("stats").expect("stats ks");

        let config = AppConfig {
            features: FeaturesConfig::default(),
            server_did: Some("did:webvh:test:control.example.com".into()),
            mediator_did: None,
            public_url: Some("http://control.test".into()),
            did_hosting_url: Some("http://control.test".into()),
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: store_config,
            auth: AuthConfig::default(),
            secrets: SecretsConfig::default(),
            vta: VtaConfig::default(),
            registry: RegistryConfig::default(),
            config_path: PathBuf::new(),
        };

        let state = AppState {
            store: store.clone(),
            sessions_ks,
            acl_ks,
            registry_ks,
            dids_ks,
            config: Arc::new(config),
            did_resolver: None,
            secrets_resolver: None,
            jwt_keys: None,
            webauthn: None,
            http_client: reqwest::Client::new(),
            didcomm_service: Arc::new(OnceLock::new()),
            stats_collector: Arc::new(StatsCollector::new()),
            stats_ks,
            signing_key_bytes: None,
            replay_cache: Arc::new(crate::replay::ReplayCache::new()),
            path_locks: crate::path_locks::PathLocks::new(),
        };

        (state, dir)
    }

    fn owner_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role: Role::Owner,
        }
    }

    fn admin_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role: Role::Admin,
        }
    }

    fn build_msg(typ: &str, body: serde_json::Value) -> Message {
        Message::build("msg-id".to_string(), typ.to_string(), body).finalize()
    }

    /// Seed a fully-formed `DidRecord` with both the `did:` and `owner:`
    /// index entries so list/info/delete dispatch arms have data to read.
    async fn seed_did(state: &AppState, owner_did: &str, mnemonic: &str) {
        let record = DidRecord {
            owner: owner_did.into(),
            mnemonic: mnemonic.into(),
            created_at: 1,
            updated_at: 1,
            version_count: 1,
            did_id: Some(format!("did:webvh:abc:{mnemonic}")),
            content_size: 42,
            disabled: false,
            deleted_at: None,
        };
        state
            .dids_ks
            .insert(did_key(mnemonic), &record)
            .await
            .expect("seed did record");
        state
            .dids_ks
            .insert_raw(owner_key(owner_did, mnemonic), mnemonic.as_bytes().to_vec())
            .await
            .expect("seed owner index");
    }

    /// Unknown DIDComm message types must surface as `Validation` so the
    /// protocol-error mapper sends `e.p.did.validation-error`. Pinning this
    /// keeps the wire-level contract stable when handlers are added or
    /// renamed.
    #[tokio::test]
    async fn dispatch_did_op_unknown_type_returns_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg("https://affinidi.com/webvh/1.0/not-a-real-type", json!({}));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg)
            .await
            .expect_err("unknown type must error");
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("unknown message type")));
        assert_eq!(map_app_error_code(&err), "e.p.did.validation-error");
    }

    #[tokio::test]
    async fn dispatch_did_op_publish_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DID_PUBLISH, json!({ "did_log": "irrelevant" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    #[tokio::test]
    async fn dispatch_did_op_publish_missing_did_log_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DID_PUBLISH, json!({ "mnemonic": "alpha-beta" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("did_log")));
    }

    #[tokio::test]
    async fn dispatch_did_op_witness_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_WITNESS_PUBLISH, json!({ "witness": {} }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    #[tokio::test]
    async fn dispatch_did_op_witness_missing_witness_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_WITNESS_PUBLISH, json!({ "mnemonic": "alpha-beta" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("witness")));
    }

    #[tokio::test]
    async fn dispatch_did_op_witness_null_body_rejected() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_WITNESS_PUBLISH,
            json!({ "mnemonic": "alpha-beta", "witness": null }),
        );
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("witness")));
    }

    #[tokio::test]
    async fn dispatch_did_op_info_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_INFO_REQUEST, json!({}));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    #[tokio::test]
    async fn dispatch_did_op_delete_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DELETE, json!({}));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    /// Owners with no DIDs see an empty list — verifies the success-path
    /// shape (`MSG_LIST` + `{ dids: [] }`) end-to-end with a real keyspace
    /// scan.
    #[tokio::test]
    async fn dispatch_did_op_list_request_empty_returns_empty_array() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let auth = owner_auth("did:example:caller");

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_LIST);
        let dids = body.get("dids").and_then(|v| v.as_array()).expect("dids[]");
        assert!(dids.is_empty(), "expected empty list, got {dids:?}");
    }

    /// Listing returns DIDs the caller owns, with the wire-level keys the
    /// VTA SDK consumes (`mnemonic`, `did_id`, `version_count`,
    /// `total_resolves`, etc.). Pinning the shape avoids silent drift if
    /// `DidListEntry` ever sprouts new fields.
    #[tokio::test]
    async fn dispatch_did_op_list_request_returns_owner_dids() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did(&state, owner, "alpha-beta").await;
        seed_did(&state, owner, "gamma-delta").await;
        // A different owner's DID must not leak into the response.
        seed_did(&state, "did:example:other", "eta-theta").await;

        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_LIST);

        let dids = body.get("dids").and_then(|v| v.as_array()).expect("dids[]");
        assert_eq!(dids.len(), 2, "owner sees only their own DIDs: {dids:?}");
        let mnemonics: std::collections::HashSet<&str> = dids
            .iter()
            .filter_map(|d| d.get("mnemonic").and_then(|v| v.as_str()))
            .collect();
        assert!(mnemonics.contains("alpha-beta"));
        assert!(mnemonics.contains("gamma-delta"));
        assert!(!mnemonics.contains("eta-theta"));

        // Spot-check one entry's wire shape.
        let entry = dids
            .iter()
            .find(|d| d.get("mnemonic").and_then(|v| v.as_str()) == Some("alpha-beta"))
            .unwrap();
        assert!(entry.get("did_id").is_some());
        assert_eq!(entry.get("version_count").and_then(|v| v.as_u64()), Some(1));
        assert!(entry.get("total_resolves").is_some());
    }

    /// IDOR regression: an owner whose DID is a string-prefix of another
    /// owner's DID must NOT see the longer-DID owner's mnemonics. Owner-
    /// index keys are `owner:{did}:{mnemonic}` and DIDs naturally contain
    /// colons, so the prefix iteration is ambiguous between
    /// `did:web:tenant` and `did:web:tenant:server`. `list_dids` must
    /// re-check `record.owner == target_owner` after the iteration.
    #[tokio::test]
    async fn dispatch_did_op_list_request_filters_did_prefix_collision() {
        let (state, _dir) = test_state().await;
        let short = "did:example:tenant";
        let long = "did:example:tenant:server";
        seed_did(&state, short, "short-mn").await;
        seed_did(&state, long, "long-mn").await;

        // Caller is the SHORT-DID owner. Without the fix, the iterator
        // returns both `owner:did:example:tenant:short-mn` and
        // `owner:did:example:tenant:server:long-mn`.
        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let auth = owner_auth(short);
        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_LIST);
        let dids = body.get("dids").and_then(|v| v.as_array()).expect("dids[]");
        assert_eq!(
            dids.len(),
            1,
            "prefix collision must not leak the longer-DID owner's records: {dids:?}"
        );
        assert_eq!(
            dids[0].get("mnemonic").and_then(|v| v.as_str()),
            Some("short-mn")
        );
    }

    /// Admin role with no `owner` filter sees every DID across owners —
    /// pins the admin-listing branch in `did_ops::list_dids`.
    #[tokio::test]
    async fn dispatch_did_op_list_request_admin_sees_all_owners() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "alpha-beta").await;
        seed_did(&state, "did:example:owner-b", "gamma-delta").await;

        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let auth = admin_auth("did:example:admin");

        let (_typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        let dids = body.get("dids").and_then(|v| v.as_array()).unwrap();
        assert_eq!(dids.len(), 2, "admin must see DIDs from every owner");
    }

    /// Deleting a non-existent mnemonic surfaces as `NotFound`, which the
    /// protocol mapper turns into `e.p.did.mnemonic-not-found`.
    #[tokio::test]
    async fn dispatch_did_op_delete_unknown_mnemonic_not_found() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DELETE, json!({ "mnemonic": "ghost-token" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
        assert_eq!(map_app_error_code(&err), "e.p.did.mnemonic-not-found");
    }

    /// `MSG_INFO_REQUEST` against a non-existent mnemonic is `NotFound` —
    /// covers the read-side counterpart to the delete case above and
    /// guards the wire-level "mnemonic-not-found" code.
    #[tokio::test]
    async fn dispatch_did_op_info_unknown_mnemonic_not_found() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_INFO_REQUEST, json!({ "mnemonic": "ghost-token" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.mnemonic-not-found");
    }

    /// Cross-owner access is forbidden — Owner role can only see their own
    /// DIDs. Admins bypass this; regression-locks both branches of the
    /// `get_authorized_record` check.
    #[tokio::test]
    async fn dispatch_did_op_info_cross_owner_forbidden() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "alpha-beta").await;

        let msg = build_msg(MSG_INFO_REQUEST, json!({ "mnemonic": "alpha-beta" }));
        let attacker = owner_auth("did:example:attacker");

        let err = dispatch_did_op(&attacker, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.unauthorized");

        // Admin sees through.
        let admin = admin_auth("did:example:admin");
        let (typ, body) = dispatch_did_op(&admin, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_INFO);
        assert_eq!(
            body.get("mnemonic").and_then(|v| v.as_str()),
            Some("alpha-beta")
        );
    }

    /// A `MSG_DID_REQUEST` with no path generates a fresh mnemonic, persists
    /// a `DidRecord` owned by the caller, and replies with `MSG_DID_OFFER`
    /// carrying the wire-level fields the SDK consumes.
    #[tokio::test]
    async fn dispatch_did_op_did_request_generates_record_and_offer() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        let msg = build_msg(MSG_DID_REQUEST, json!({}));
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_DID_OFFER);

        let mnemonic = body
            .get("mnemonic")
            .and_then(|v| v.as_str())
            .expect("offer has mnemonic")
            .to_string();
        let did_url = body
            .get("did_url")
            .and_then(|v| v.as_str())
            .expect("offer has did_url");
        assert!(
            did_url.ends_with(&format!("/{mnemonic}/did.jsonl")),
            "did_url shape: {did_url}"
        );
        assert!(body.get("server_did").is_some());

        // Verify the record landed in the dids keyspace, owned by the caller.
        let record: DidRecord = state
            .dids_ks
            .get(did_key(&mnemonic))
            .await
            .unwrap()
            .expect("record persisted");
        assert_eq!(record.owner, owner);
        assert_eq!(record.version_count, 0);
    }

    /// Reserving a custom path that's already taken returns `Conflict`,
    /// which the mapper sends back as `e.p.did.path-unavailable`.
    #[tokio::test]
    async fn dispatch_did_op_did_request_taken_path_conflict() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "shared-path").await;

        let msg = build_msg(MSG_DID_REQUEST, json!({ "path": "shared-path" }));
        let auth = owner_auth("did:example:owner-b");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.path-unavailable");
    }

    /// `.well-known` is admin-only; non-admins get `Forbidden` →
    /// `e.p.did.unauthorized`.
    #[tokio::test]
    async fn dispatch_did_op_did_request_well_known_forbidden_for_owner() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DID_REQUEST, json!({ "path": ".well-known" }));
        let auth = owner_auth("did:example:owner-a");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.unauthorized");
    }

    /// ACL gate covers DIDComm authentication and DID ops alike. This pins
    /// the integration: a DID added to the ACL with role `Owner` resolves
    /// through `check_acl` to that role — the input `handle_authenticate`
    /// uses to mint a JWT and `handle_webvh_message` uses for dispatch.
    #[tokio::test]
    async fn check_acl_returns_role_for_seeded_did() {
        use affinidi_webvh_common::server::acl::check_acl;

        let (state, _dir) = test_state().await;
        let did = "did:example:owner-a";
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: did.into(),
                role: Role::Owner,
                label: None,
                created_at: 0,
                max_total_size: None,
                max_did_count: None,
            },
        )
        .await
        .unwrap();

        let role = check_acl(&state.acl_ks, did).await.unwrap();
        assert_eq!(role, Role::Owner);

        // DID not in ACL → Forbidden.
        let err = check_acl(&state.acl_ks, "did:example:stranger")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    /// Build an `AppState` plus a seeded ACL entry and a real `JwtKeys`,
    /// so the authenticate pipeline produces decodable tokens. The ACL
    /// step gates everything downstream — without it, `run_authenticate`
    /// short-circuits with a problem report.
    async fn auth_ready_state(
        sender_did: &str,
        role: Role,
    ) -> (AppState, tempfile::TempDir, Arc<crate::auth::jwt::JwtKeys>) {
        let (mut state, dir) = test_state().await;

        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: sender_did.into(),
                role,
                label: None,
                created_at: 0,
                max_total_size: None,
                max_did_count: None,
            },
        )
        .await
        .unwrap();

        let keys = Arc::new(
            crate::auth::jwt::JwtKeys::from_ed25519_bytes(&[3u8; 32])
                .expect("test JWT keys construct"),
        );
        state.jwt_keys = Some(keys.clone());
        (state, dir, keys)
    }

    /// Successful `MSG_AUTHENTICATE` flow: ACL allows, session is created,
    /// the response is `MSG_AUTH_RESPONSE` with a JWT that decodes back to
    /// the caller's DID + role. Pins both the wire-level body shape and
    /// the JWT contents the SDK relies on.
    #[tokio::test]
    async fn run_authenticate_authorized_returns_decodable_jwt() {
        let sender = "did:example:caller-a";
        let (state, _dir, keys) = auth_ready_state(sender, Role::Owner).await;

        let (typ, body) = run_authenticate(&state, sender)
            .await
            .expect("authenticate must not fail when ACL + JWT are configured");
        assert_eq!(typ, MSG_AUTH_RESPONSE);

        let session_id = body
            .get("session_id")
            .and_then(|v| v.as_str())
            .expect("session_id present");
        assert!(!session_id.is_empty());

        let access = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .expect("access_token present");
        let claims = keys.decode(access).expect("access token decodes");
        assert_eq!(claims.sub, sender);
        assert_eq!(claims.aud, "WebVH");
        assert_eq!(claims.role, "owner");
        assert_eq!(claims.session_id, session_id);
        assert!(claims.exp > claims.iat);
        assert!(!claims.jti.is_empty());

        // Refresh token is opaque; just assert it's present.
        assert!(
            body.get("refresh_token").and_then(|v| v.as_str()).is_some(),
            "refresh_token missing"
        );
    }

    /// `MSG_AUTHENTICATE` from a DID that isn't in the ACL must surface as
    /// a problem-report body with `e.p.did.unauthorized` — never as a
    /// `MSG_AUTH_RESPONSE`. Pinning this prevents an ACL bypass from
    /// silently still issuing a JWT.
    #[tokio::test]
    async fn run_authenticate_unauthorized_did_returns_problem_report() {
        let (state, _dir, _keys) = auth_ready_state("did:example:authorized", Role::Owner).await;

        let (typ, body) = run_authenticate(&state, "did:example:stranger")
            .await
            .unwrap();
        assert_eq!(typ, MSG_PROBLEM_REPORT);
        assert_eq!(
            body.get("code").and_then(|v| v.as_str()),
            Some("e.p.did.unauthorized")
        );
    }

    /// `run_webvh_dispatch` mirrors the `handle_webvh_message` wrapper:
    /// non-ACL'd senders get a problem report with `e.p.did.unauthorized`
    /// regardless of the request shape. Pins the auth gate at the
    /// dispatcher level (defense-in-depth alongside `MessagePolicy`).
    #[tokio::test]
    async fn run_webvh_dispatch_unauthorized_sender_problem_report() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_LIST_REQUEST, json!({}));

        let (typ, body) = run_webvh_dispatch(&state, "did:example:stranger", &msg).await;
        assert_eq!(typ, MSG_PROBLEM_REPORT);
        assert_eq!(
            body.get("code").and_then(|v| v.as_str()),
            Some("e.p.did.unauthorized")
        );
    }

    /// Replay gate: re-submitting the same `(sender, msg.id)` after a
    /// successful dispatch surfaces as `e.p.did.validation-error` with
    /// a "replay-detected" comment. Pinning this at the wrapper level
    /// catches a regression where the replay cache is not consulted
    /// before dispatch (e.g. a future refactor that moves the cache
    /// check into a per-arm handler).
    #[tokio::test]
    async fn run_webvh_dispatch_replay_rejected() {
        let sender = "did:example:authorized";
        let (state, _dir, _keys) = auth_ready_state(sender, Role::Owner).await;
        let msg = build_msg(MSG_LIST_REQUEST, json!({}));

        // First call goes through.
        let (typ, _) = run_webvh_dispatch(&state, sender, &msg).await;
        assert_eq!(typ, MSG_LIST);

        // Same `(sender, msg.id)` — replay.
        let (typ, body) = run_webvh_dispatch(&state, sender, &msg).await;
        assert_eq!(typ, MSG_PROBLEM_REPORT);
        assert_eq!(
            body.get("code").and_then(|v| v.as_str()),
            Some("e.p.did.validation-error")
        );
        let comment = body.get("comment").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            comment.contains("replay-detected"),
            "replay rejection should mention 'replay-detected', got: {comment}"
        );
    }

    /// ACL'd `MSG_LIST_REQUEST` from a sender with no DIDs returns
    /// `MSG_LIST` with an empty array — full happy-path through the ACL
    /// gate + dispatcher.
    #[tokio::test]
    async fn run_webvh_dispatch_authorized_list_returns_empty() {
        let sender = "did:example:authorized";
        let (state, _dir, _keys) = auth_ready_state(sender, Role::Owner).await;

        let msg = build_msg(MSG_LIST_REQUEST, json!({}));
        let (typ, body) = run_webvh_dispatch(&state, sender, &msg).await;
        assert_eq!(typ, MSG_LIST);
        let dids = body.get("dids").and_then(|v| v.as_array()).expect("dids[]");
        assert!(dids.is_empty());
    }

    /// Validation errors from `dispatch_did_op` get translated into the
    /// right protocol code by `map_app_error_code`. Covers the wrapper's
    /// glue path between dispatcher and wire-level error reporting.
    #[tokio::test]
    async fn run_webvh_dispatch_validation_error_maps_to_protocol_code() {
        let sender = "did:example:authorized";
        let (state, _dir, _keys) = auth_ready_state(sender, Role::Owner).await;

        // Missing `mnemonic` — `dispatch_did_op` returns Validation,
        // wrapper wraps as MSG_PROBLEM_REPORT with e.p.did.validation-error.
        let msg = build_msg(MSG_INFO_REQUEST, json!({}));
        let (typ, body) = run_webvh_dispatch(&state, sender, &msg).await;
        assert_eq!(typ, MSG_PROBLEM_REPORT);
        assert_eq!(
            body.get("code").and_then(|v| v.as_str()),
            Some("e.p.did.validation-error")
        );
    }

    /// Pin the AppError → DIDComm protocol-code mapping. The handler set is
    /// the wire-level contract for every external VTA, and the substring
    /// matches inside this function are easy to break with a wording change
    /// in any `AppError::*` literal elsewhere.
    #[test]
    fn map_app_error_code_pinned_table() {
        let cases: &[(AppError, &str)] = &[
            (
                AppError::Unauthorized("nope".into()),
                "e.p.did.unauthorized",
            ),
            (AppError::Forbidden("nope".into()), "e.p.did.unauthorized"),
            (
                AppError::QuotaExceeded("upload size cap exceeded".into()),
                "e.p.did.size-exceeded",
            ),
            (
                AppError::QuotaExceeded("monthly quota reached".into()),
                "e.p.did.quota-exceeded",
            ),
            (
                AppError::Conflict("path already in use".into()),
                "e.p.did.path-unavailable",
            ),
            (
                AppError::NotFound("did not found".into()),
                "e.p.did.mnemonic-not-found",
            ),
            // Tagged validations route via `ValidationKind`, not by
            // sniffing the message text — pinning these via the
            // `AppError::validation()` constructor ensures the tag is
            // the load-bearing input.
            (
                AppError::validation(
                    affinidi_webvh_common::server::error::ValidationKind::InvalidLog,
                    "invalid log entry on line 3",
                ),
                "e.p.did.invalid-log",
            ),
            (
                AppError::validation(
                    affinidi_webvh_common::server::error::ValidationKind::InvalidLog,
                    "malformed JSONL body",
                ),
                "e.p.did.invalid-log",
            ),
            (
                AppError::validation(
                    affinidi_webvh_common::server::error::ValidationKind::InvalidPath,
                    "path component reserved",
                ),
                "e.p.did.path-invalid",
            ),
            (
                AppError::validation(
                    affinidi_webvh_common::server::error::ValidationKind::InvalidWitness,
                    "witness signature failed",
                ),
                "e.p.did.witness-invalid",
            ),
            (
                AppError::validation(
                    affinidi_webvh_common::server::error::ValidationKind::Other,
                    "something else broke",
                ),
                "e.p.did.validation-error",
            ),
            // An untagged Validation (no `[tag]` prefix) falls through to
            // the generic code rather than re-routing based on wording.
            (
                AppError::Validation("missing 'mnemonic' in body".into()),
                "e.p.did.validation-error",
            ),
            (AppError::Internal("oops".into()), "e.p.did.internal-error"),
        ];
        for (err, expected) in cases {
            let got = map_app_error_code(err);
            assert_eq!(
                got, *expected,
                "map_app_error_code({err:?}) = {got}, expected {expected}",
            );
        }
    }

    /// `MSG_DID_CHANGE_OWNER` with no `mnemonic` body field is a validation
    /// error — wire-level contract for malformed clients.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_missing_mnemonic_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(
            MSG_DID_CHANGE_OWNER,
            json!({ "new_owner": "did:example:new" }),
        );
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("mnemonic")));
    }

    /// `MSG_DID_CHANGE_OWNER` with no `new_owner` body field is a validation
    /// error.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_missing_new_owner_validation() {
        let (state, _dir) = test_state().await;
        let msg = build_msg(MSG_DID_CHANGE_OWNER, json!({ "mnemonic": "alpha-beta" }));
        let auth = owner_auth("did:example:caller");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("new_owner")));
    }

    /// Owner can transfer their own DID to another ACL'd DID. Confirms the
    /// success path and the wire-level confirm body shape.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_success() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        let new_owner = "did:example:owner-b";
        seed_did(&state, owner, "alpha-beta").await;

        // Both old and new owners must be in the ACL for change-owner to
        // succeed — defense-in-depth.
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: new_owner.into(),
                role: Role::Owner,
                label: None,
                created_at: 0,
                max_total_size: None,
                max_did_count: None,
            },
        )
        .await
        .unwrap();

        let msg = build_msg(
            MSG_DID_CHANGE_OWNER,
            json!({ "mnemonic": "alpha-beta", "new_owner": new_owner }),
        );
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_DID_CHANGE_OWNER_CONFIRM);
        assert_eq!(body.get("owner").and_then(|v| v.as_str()), Some(new_owner));

        // Owner index swapped: old owner has none, new owner has one.
        let old_idx = state
            .dids_ks
            .prefix_iter_raw(format!("owner:{owner}:"))
            .await
            .unwrap();
        assert!(old_idx.is_empty(), "old owner index should be cleared");
        let new_idx = state
            .dids_ks
            .prefix_iter_raw(format!("owner:{new_owner}:"))
            .await
            .unwrap();
        assert_eq!(new_idx.len(), 1, "new owner should have one entry");
    }

    /// Cross-owner change-owner is forbidden — only the current owner or an
    /// admin may transfer.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_cross_owner_forbidden() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "alpha-beta").await;
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did: "did:example:target".into(),
                role: Role::Owner,
                label: None,
                created_at: 0,
                max_total_size: None,
                max_did_count: None,
            },
        )
        .await
        .unwrap();

        let msg = build_msg(
            MSG_DID_CHANGE_OWNER,
            json!({ "mnemonic": "alpha-beta", "new_owner": "did:example:target" }),
        );
        let attacker = owner_auth("did:example:attacker");

        let err = dispatch_did_op(&attacker, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(map_app_error_code(&err), "e.p.did.unauthorized");
    }

    /// New owner must be in the ACL — prevents transferring a DID to an
    /// identity that can never authenticate to claim it.
    #[tokio::test]
    async fn dispatch_did_op_change_owner_unknown_new_owner_validation() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did(&state, owner, "alpha-beta").await;

        let msg = build_msg(
            MSG_DID_CHANGE_OWNER,
            json!({ "mnemonic": "alpha-beta", "new_owner": "did:example:not-in-acl" }),
        );
        let auth = owner_auth(owner);

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("not in the ACL")));
    }

    /// Force-replace via `MSG_DID_REQUEST` with `force: true` succeeds when
    /// the requester is the current owner, replacing the existing slot.
    #[tokio::test]
    async fn dispatch_did_op_did_request_force_replaces_when_owner() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner-a";
        seed_did(&state, owner, "shared-path").await;
        // Seed log content so we can verify it gets cleared.
        state
            .dids_ks
            .insert_raw(
                affinidi_webvh_common::did_ops::content_log_key("shared-path"),
                b"old log".to_vec(),
            )
            .await
            .unwrap();

        let msg = build_msg(
            MSG_DID_REQUEST,
            json!({ "path": "shared-path", "force": true }),
        );
        let auth = owner_auth(owner);

        let (typ, body) = dispatch_did_op(&auth, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_DID_OFFER);
        assert_eq!(
            body.get("mnemonic").and_then(|v| v.as_str()),
            Some("shared-path")
        );

        // Old log content has been wiped; new record has version_count 0.
        let log = state
            .dids_ks
            .get_raw(affinidi_webvh_common::did_ops::content_log_key(
                "shared-path",
            ))
            .await
            .unwrap();
        assert!(log.is_none(), "old log content should be wiped");
        let record: DidRecord = state
            .dids_ks
            .get(did_key("shared-path"))
            .await
            .unwrap()
            .expect("record present");
        assert_eq!(record.version_count, 0);
        assert_eq!(record.owner, owner);
    }

    /// Force-replace by a different owner is forbidden — `force` only works
    /// for admin or current owner of the existing path.
    #[tokio::test]
    async fn dispatch_did_op_did_request_force_forbidden_for_other_owner() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "shared-path").await;

        let msg = build_msg(
            MSG_DID_REQUEST,
            json!({ "path": "shared-path", "force": true }),
        );
        let auth = owner_auth("did:example:owner-b");

        let err = dispatch_did_op(&auth, &state, &msg).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    /// Admins can force-replace any DID — the caller becomes the new owner.
    #[tokio::test]
    async fn dispatch_did_op_did_request_force_admin_takes_ownership() {
        let (state, _dir) = test_state().await;
        seed_did(&state, "did:example:owner-a", "shared-path").await;

        let admin = admin_auth("did:example:admin");
        let msg = build_msg(
            MSG_DID_REQUEST,
            json!({ "path": "shared-path", "force": true }),
        );

        let (typ, _body) = dispatch_did_op(&admin, &state, &msg).await.unwrap();
        assert_eq!(typ, MSG_DID_OFFER);

        let record: DidRecord = state
            .dids_ks
            .get(did_key("shared-path"))
            .await
            .unwrap()
            .expect("record present");
        assert_eq!(record.owner, "did:example:admin");
    }
}

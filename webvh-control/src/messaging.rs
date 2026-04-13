//! DIDComm messaging for the control plane.
//!
//! **Inbound:** Uses the `affinidi-messaging-didcomm-service` framework for
//! mediator connection, message dispatch, and response handling. Handles
//! the full VTA provisioning protocol (did/request, did/publish, etc.)
//! as well as sync acknowledgements from servers.
//!
//! **Outbound:** Keeps raw ATM connection for proactive sync push messages
//! (`send_sync_update`, `send_sync_delete`) used by `server_push.rs`.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, RequestLogging, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    trust_ping_handler,
};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::discover_features::DiscoverFeatures;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_webvh_common::did_ops::did_key;
use affinidi_webvh_common::didcomm_types::*;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::acl::check_acl;
use crate::auth::AuthClaims;
use crate::auth::session::{create_authenticated_session, now_epoch};
use crate::config::AppConfig;
use crate::did_ops;
use crate::error::AppError;
use crate::secret_store::ServerSecrets;
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
        // Sync acknowledgements from servers
        .route(MSG_SYNC_UPDATE_ACK, handler_fn(handle_sync_ack))?
        .route(MSG_SYNC_DELETE_ACK, handler_fn(handle_sync_ack))?
        .fallback(handler_fn(handle_fallback))
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_sender_did(true),
        )
        .layer(RequestLogging))
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
    debug!(
        sender = sender,
        mnemonic = mnemonic,
        status = status,
        msg_type = %message.typ,
        "sync acknowledgement received"
    );
    Ok(None)
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

// ---------------------------------------------------------------------------
// Outbound: ATM connection for proactive sync push
// ---------------------------------------------------------------------------

/// Initialize a raw ATM connection for outbound DIDComm messaging.
///
/// This is separate from the framework-managed inbound connection because the
/// framework doesn't expose ATM handles for proactive message sending.
pub async fn init_outbound_atm(
    config: &AppConfig,
    control_did: &str,
    secrets: &ServerSecrets,
) -> Option<(Arc<ATM>, Arc<ATMProfile>)> {
    let mediator_did = match &config.mediator_did {
        Some(m) => m.clone(),
        None => {
            warn!("mediator_did not configured — outbound DIDComm messaging disabled");
            return None;
        }
    };

    let tdk = TDKSharedState::default().await;

    let (signing_kid, ka_kid) = resolve_key_ids(control_did).await;

    match Secret::from_multibase(&secrets.signing_key, Some(&signing_kid)) {
        Ok(secret) => {
            tdk.secrets_resolver.insert(secret).await;
            debug!(kid = %signing_kid, "outbound signing secret loaded");
        }
        Err(e) => {
            warn!("failed to decode signing_key: {e} — outbound messaging disabled");
            return None;
        }
    }

    match Secret::from_multibase(&secrets.key_agreement_key, Some(&ka_kid)) {
        Ok(secret) => {
            tdk.secrets_resolver.insert(secret).await;
            debug!(kid = %ka_kid, "outbound key-agreement secret loaded");
        }
        Err(e) => {
            warn!("failed to decode key_agreement_key: {e} — outbound messaging disabled");
            return None;
        }
    }

    let features = DiscoverFeatures {
        protocols: vec![
            "https://didcomm.org/trust-ping/2.0".into(),
            "https://didcomm.org/discover-features/2.0".into(),
            "https://affinidi.com/webvh/1.0".into(),
        ],
        goal_codes: vec![],
        headers: vec![],
    };

    let atm_config = match ATMConfig::builder()
        .with_inbound_message_channel(100)
        .with_discovery_features(features)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to build ATM config: {e} — outbound messaging disabled");
            return None;
        }
    };

    let atm = match ATM::new(atm_config, Arc::new(tdk)).await {
        Ok(a) => a,
        Err(e) => {
            warn!("failed to create ATM: {e} — outbound messaging disabled");
            return None;
        }
    };

    let profile =
        match ATMProfile::new(&atm, None, control_did.to_string(), Some(mediator_did)).await {
            Ok(p) => Arc::new(p),
            Err(e) => {
                warn!("failed to create ATM profile: {e} — outbound messaging disabled");
                return None;
            }
        };

    if let Err(e) = atm.profile_enable_websocket(&profile).await {
        warn!("failed to enable websocket: {e} — outbound messaging disabled");
        return None;
    }

    let atm = Arc::new(atm);

    info!("outbound DIDComm connection established");
    Some((atm, profile))
}

/// Resolve the DID document and extract key IDs for signing and key agreement.
async fn resolve_key_ids(did: &str) -> (String, String) {
    let fallback_signing = format!("{did}#key-0");
    let fallback_ka = format!("{did}#key-1");

    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver for key-ID lookup: {e} — using fallback key IDs");
            return (fallback_signing, fallback_ka);
        }
    };

    match did_resolver.resolve(did).await {
        Ok(response) => {
            let doc = &response.doc;

            let ka_kid = match doc.key_agreement.first() {
                Some(vr) => {
                    let kid = vr.get_id().to_string();
                    info!(kid = %kid, "DID doc keyAgreement key ID");
                    kid
                }
                None => {
                    warn!("DID document has no keyAgreement — using fallback {fallback_ka}");
                    fallback_ka
                }
            };

            let signing_kid = match doc.authentication.first() {
                Some(vr) => {
                    let kid = vr.get_id().to_string();
                    info!(kid = %kid, "DID doc authentication key ID");
                    kid
                }
                None => {
                    warn!("DID document has no authentication — using fallback {fallback_signing}");
                    fallback_signing
                }
            };

            (signing_kid, ka_kid)
        }
        Err(e) => {
            warn!("failed to resolve DID {did}: {e} — using fallback key IDs");
            (fallback_signing, fallback_ka)
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound: send sync messages via mediator
// ---------------------------------------------------------------------------

/// Send a DID sync update to a specific server DID via the mediator.
pub async fn send_sync_update(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    control_did: &str,
    target_did: &str,
    update: &affinidi_webvh_common::DidSyncUpdate,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({
        "mnemonic": update.mnemonic,
        "did_id": update.did_id,
        "log_content": update.log_content,
        "witness_content": update.witness_content,
        "version_count": update.version_count,
    });

    let msg = affinidi_messaging_didcomm::Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_SYNC_UPDATE.to_string(),
        body,
    )
    .from(control_did.to_string())
    .to(target_did.to_string())
    .created_time(now_epoch())
    .finalize();

    let (packed, _) = atm
        .pack_encrypted(&msg, target_did, Some(control_did), Some(control_did))
        .await?;

    atm.send_message(profile, &packed, &msg.id, false, false)
        .await?;

    debug!(
        target = target_did,
        mnemonic = %update.mnemonic,
        "sent sync-update via mediator"
    );

    Ok(())
}

/// Send a DID delete notification to a specific server DID via the mediator.
pub async fn send_sync_delete(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    control_did: &str,
    target_did: &str,
    mnemonic: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({
        "mnemonic": mnemonic,
    });

    let msg = affinidi_messaging_didcomm::Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_SYNC_DELETE.to_string(),
        body,
    )
    .from(control_did.to_string())
    .to(target_did.to_string())
    .created_time(now_epoch())
    .finalize();

    let (packed, _) = atm
        .pack_encrypted(&msg, target_did, Some(control_did), Some(control_did))
        .await?;

    atm.send_message(profile, &packed, &msg.id, false, false)
        .await?;

    debug!(
        target = target_did,
        mnemonic = %mnemonic,
        "sent sync-delete via mediator"
    );

    Ok(())
}

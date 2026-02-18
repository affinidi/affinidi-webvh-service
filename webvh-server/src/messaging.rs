//! DIDComm mediator connection and inbound message handling.
//!
//! Connects to a mediator via WebSocket using the `affinidi-messaging-sdk` (ATM)
//! and processes inbound DIDComm messages as they arrive via live-streaming.

use std::sync::Arc;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::discover_features::DiscoverFeatures;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use serde_json::{Value, json};
use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

use crate::acl::check_acl;
use crate::auth::AuthClaims;
use crate::auth::session::{create_authenticated_session, now_epoch};
use crate::config::AppConfig;
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Message type constants
// ---------------------------------------------------------------------------

const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const DISCOVER_FEATURES_QUERY_TYPE: &str = "https://didcomm.org/discover-features/2.0/queries";
const MESSAGE_PICKUP_STATUS_TYPE: &str = "https://didcomm.org/messagepickup/3.0/status";
const MSG_AUTHENTICATE: &str = "https://affinidi.com/webvh/1.0/authenticate";

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
const MSG_AUTH_RESPONSE: &str = "https://affinidi.com/webvh/1.0/authenticate-response";

// ---------------------------------------------------------------------------
// Mediator connection
// ---------------------------------------------------------------------------

/// Initialize the DIDComm connection to the mediator.
///
/// Connects to the configured mediator over WebSocket and prepares the ATM
/// and profile for inbound message handling.
///
/// Returns `Some((Arc<ATM>, Arc<ATMProfile>))` on success.
pub async fn init_didcomm_connection(
    config: &AppConfig,
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    server_did: &str,
) -> Option<(Arc<ATM>, Arc<ATMProfile>)> {
    let mediator_did = match &config.mediator_did {
        Some(m) => m.clone(),
        None => {
            warn!("mediator_did not configured — inbound message handling disabled");
            return None;
        }
    };

    // Create TDK shared state and copy server secrets from the shared resolver
    let tdk = TDKSharedState::default().await;

    let signing_id = format!("{server_did}#key-0");
    let ka_id = format!("{server_did}#key-1");

    if let Some(secret) = secrets_resolver.get_secret(&signing_id).await {
        tdk.secrets_resolver.insert(secret).await;
    } else {
        warn!("server signing secret not found — messaging disabled");
        return None;
    }

    if let Some(secret) = secrets_resolver.get_secret(&ka_id).await {
        tdk.secrets_resolver.insert(secret).await;
    } else {
        warn!("server key-agreement secret not found — messaging disabled");
        return None;
    }

    // Register discoverable protocols
    let features = DiscoverFeatures {
        protocols: vec![
            "https://didcomm.org/trust-ping/2.0".into(),
            "https://didcomm.org/discover-features/2.0".into(),
            "https://affinidi.com/webvh/1.0".into(),
        ],
        goal_codes: vec![],
        headers: vec![],
    };

    // Build ATM with inbound message channel and discoverable features
    let atm_config = match ATMConfig::builder()
        .with_inbound_message_channel(100)
        .with_discovery_features(features)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to build ATM config: {e} — messaging disabled");
            return None;
        }
    };

    let atm = match ATM::new(atm_config, Arc::new(tdk)).await {
        Ok(a) => a,
        Err(e) => {
            warn!("failed to create ATM: {e} — messaging disabled");
            return None;
        }
    };

    // Create profile with mediator
    let profile = match ATMProfile::new(&atm, None, server_did.to_string(), Some(mediator_did))
        .await
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!("failed to create ATM profile: {e} — messaging disabled");
            return None;
        }
    };

    // Enable WebSocket (auto-starts live streaming from mediator)
    if let Err(e) = atm.profile_enable_websocket(&profile).await {
        warn!("failed to enable websocket: {e} — messaging disabled");
        return None;
    }

    let atm = Arc::new(atm);

    info!("messaging initialized — connected to mediator");
    Some((atm, profile))
}

// ---------------------------------------------------------------------------
// Inbound message loop
// ---------------------------------------------------------------------------

/// Run the DIDComm inbound message loop until shutdown is signaled.
///
/// Receives messages from the ATM inbound channel and dispatches them to
/// protocol handlers. Exits when `shutdown_rx` fires or the channel closes.
pub async fn run_didcomm_loop(
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    server_did: &str,
    state: &AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let mut rx: broadcast::Receiver<WebSocketResponses> = match atm.get_inbound_channel() {
        Some(rx) => rx,
        None => {
            warn!("no inbound channel available — messaging disabled");
            return;
        }
    };

    info!("DIDComm message loop started");

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(WebSocketResponses::MessageReceived(msg, _metadata)) => {
                        dispatch_message(atm, profile, server_did, state, &msg).await;
                    }
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match atm.unpack(&packed).await {
                            Ok((msg, _metadata)) => {
                                dispatch_message(atm, profile, server_did, state, &msg).await;
                            }
                            Err(e) => {
                                warn!("failed to unpack inbound message: {e}");
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("inbound message channel lagged, missed {n} messages");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("inbound message channel closed — stopping message loop");
                        break;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("shutdown signal received — stopping DIDComm message loop");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Message dispatch
// ---------------------------------------------------------------------------

async fn dispatch_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    server_did: &str,
    state: &AppState,
    msg: &Message,
) {
    match msg.type_.as_str() {
        TRUST_PING_TYPE => {
            if let Err(e) = handle_trust_ping(atm, profile, server_did, msg).await {
                warn!("failed to handle trust-ping: {e}");
            }
        }
        DISCOVER_FEATURES_QUERY_TYPE => {
            if let Err(e) = handle_discover_features(atm, profile, server_did, msg).await {
                warn!("failed to handle discover-features query: {e}");
            }
        }
        MESSAGE_PICKUP_STATUS_TYPE => {
            // Mediator status notifications — safe to ignore
        }
        MSG_AUTHENTICATE => {
            if let Err(e) = handle_authenticate(atm, profile, server_did, state, msg).await {
                warn!("failed to handle authenticate: {e}");
            }
        }
        t if t.starts_with("https://affinidi.com/webvh/1.0/did/") => {
            if let Err(e) = handle_webvh_message(atm, profile, server_did, state, msg).await {
                warn!("failed to handle webvh message: {e}");
            }
        }
        other => {
            warn!(msg_type = other, "unknown message type — ignoring");
        }
    }

    // Always delete the message from the mediator after processing
    if let Err(e) = atm.delete_message_background(profile, &msg.id).await {
        warn!("failed to delete message from mediator: {e}");
    }
}

// ---------------------------------------------------------------------------
// Trust ping
// ---------------------------------------------------------------------------

async fn handle_trust_ping(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    server_did: &str,
    ping: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sender_did = ping
        .from
        .as_deref()
        .ok_or("trust-ping has no 'from' DID — cannot send pong")?;

    info!(from = sender_did, "received trust-ping");

    let pong = TrustPing::default().generate_pong_message(ping, Some(server_did))?;

    let (packed, _) = atm
        .pack_encrypted(&pong, sender_did, Some(server_did), Some(server_did), None)
        .await?;

    atm.send_message(profile, &packed, &pong.id, false, false)
        .await?;

    info!(to = sender_did, "sent trust-pong");
    Ok(())
}

// ---------------------------------------------------------------------------
// Discover Features
// ---------------------------------------------------------------------------

async fn handle_discover_features(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    server_did: &str,
    query_msg: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sender_did = query_msg
        .from
        .as_deref()
        .ok_or("discover-features query has no 'from' DID")?;

    info!(from = sender_did, "received discover-features query");

    // Use ATM's discoverable state to calculate the disclosure
    let state = atm.discover_features().get_discoverable_state();
    let features = state.read().await;
    let disclosure = features.generate_disclosure_message(
        server_did,
        sender_did,
        query_msg,
        None, // auto-calculate from registered state
    )?;
    drop(features);

    let (packed, _) = atm
        .pack_encrypted(
            &disclosure,
            sender_did,
            Some(server_did),
            Some(server_did),
            None,
        )
        .await?;

    atm.send_message(profile, &packed, &disclosure.id, false, false)
        .await?;

    info!(to = sender_did, "sent discover-features disclosure");
    Ok(())
}

// ---------------------------------------------------------------------------
// Authenticate (challenge-less mediator auth)
// ---------------------------------------------------------------------------

async fn handle_authenticate(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    server_did: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sender_did = msg
        .from
        .as_deref()
        .ok_or("authenticate message has no 'from' DID")?;
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);

    // Check ACL and get role
    let role = check_acl(&state.acl_ks, sender_base).await?;

    // Get JWT keys
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    // Create authenticated session with tokens
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

    // Build response message
    let response = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_AUTH_RESPONSE.to_string(),
        json!({
            "session_id": tokens.session_id,
            "access_token": tokens.access_token,
            "access_expires_at": tokens.access_expires_at,
            "refresh_token": tokens.refresh_token,
            "refresh_expires_at": tokens.refresh_expires_at,
        }),
    )
    .from(server_did.to_string())
    .to(sender_base.to_string())
    .thid(msg.id.clone())
    .created_time(now_epoch())
    .finalize();

    let (packed, _) = atm
        .pack_encrypted(
            &response,
            sender_base,
            Some(server_did),
            Some(server_did),
            None,
        )
        .await?;

    atm.send_message(profile, &packed, &response.id, false, false)
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// WebVH DID management messages
// ---------------------------------------------------------------------------

async fn handle_webvh_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    server_did: &str,
    state: &AppState,
    msg: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sender_did = msg
        .from
        .as_deref()
        .ok_or("webvh message has no 'from' DID")?;
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);

    // Check ACL and construct AuthClaims
    let role = check_acl(&state.acl_ks, sender_base).await?;
    let auth = AuthClaims {
        did: sender_base.to_string(),
        role,
    };

    // Dispatch to the appropriate did_ops function
    let (response_type, response_body) = match dispatch_did_op(&auth, state, msg).await {
        Ok(result) => result,
        Err(e) => {
            let comment = e.to_string();
            let code = map_app_error_code(&e);
            warn!(
                code = code,
                comment = %comment,
                msg_type = %msg.type_,
                did = sender_base,
                "DIDComm protocol error"
            );
            (
                MSG_PROBLEM_REPORT.to_string(),
                json!({ "code": code, "comment": comment }),
            )
        }
    };

    // Build response DIDComm message
    let response = Message::build(
        uuid::Uuid::new_v4().to_string(),
        response_type,
        response_body,
    )
    .from(server_did.to_string())
    .to(sender_base.to_string())
    .thid(msg.id.clone())
    .created_time(now_epoch())
    .finalize();

    let (packed, _) = atm
        .pack_encrypted(
            &response,
            sender_base,
            Some(server_did),
            Some(server_did),
            None,
        )
        .await?;

    atm.send_message(profile, &packed, &response.id, false, false)
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// DID operation dispatch (mirrors routes/didcomm.rs dispatch)
// ---------------------------------------------------------------------------

async fn dispatch_did_op(
    auth: &AuthClaims,
    state: &AppState,
    msg: &Message,
) -> Result<(String, Value), AppError> {
    match msg.type_.as_str() {
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

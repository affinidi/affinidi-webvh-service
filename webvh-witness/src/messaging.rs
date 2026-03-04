use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::discover_features::DiscoverFeatures;
use affinidi_tdk::messaging::protocols::trust_ping::TrustPing;
use affinidi_tdk::messaging::transports::websockets::WebSocketResponses;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::{Value, json};
use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};

use crate::acl::check_acl;
use crate::auth::session::{create_authenticated_session, now_epoch};
use crate::config::AppConfig;
use crate::error::AppError;
use crate::secret_store::ServerSecrets;
use crate::server::AppState;

// Standard DIDComm protocol message types
const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const DISCOVER_FEATURES_QUERY_TYPE: &str = "https://didcomm.org/discover-features/2.0/queries";

// WebVH witness message types
const MSG_AUTHENTICATE: &str = "https://affinidi.com/webvh/1.0/authenticate";
const MSG_AUTHENTICATE_RESPONSE: &str = "https://affinidi.com/webvh/1.0/authenticate-response";
const MSG_WITNESS_PROOF_REQUEST: &str = "https://affinidi.com/webvh/1.0/witness/proof-request";
const MSG_WITNESS_PROOF_RESPONSE: &str = "https://affinidi.com/webvh/1.0/witness/proof-response";
const MSG_WITNESS_LIST_REQUEST: &str = "https://affinidi.com/webvh/1.0/witness/list-request";
const MSG_WITNESS_LIST: &str = "https://affinidi.com/webvh/1.0/witness/list";
const MSG_WITNESS_PROBLEM_REPORT: &str = "https://affinidi.com/webvh/1.0/witness/problem-report";

/// Resolve the actual key IDs from the server's DID document.
///
/// Reuses an existing `DIDCacheClient` when available, falling back to creating
/// a temporary resolver if `None` is passed.
async fn resolve_server_key_ids(
    server_did: &str,
    existing_resolver: Option<&DIDCacheClient>,
) -> (String, String) {
    let fallback_signing = format!("{server_did}#key-0");
    let fallback_ka = format!("{server_did}#key-1");

    // Use the provided resolver, or create a one-shot instance.
    let owned;
    let did_resolver = match existing_resolver {
        Some(r) => r,
        None => match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
            Ok(r) => {
                owned = r;
                &owned
            }
            Err(e) => {
                warn!("failed to resolve DID for key IDs: {e} — using fallback");
                return (fallback_signing, fallback_ka);
            }
        },
    };

    match did_resolver.resolve(server_did).await {
        Ok(response) => {
            let doc = &response.doc;

            let ka_kid = match doc.key_agreement.first() {
                Some(vr) => {
                    let kid = vr.get_id().to_string();
                    info!(kid = %kid, "DID doc keyAgreement key ID");
                    kid
                }
                None => {
                    warn!("server DID document has no keyAgreement — using fallback {fallback_ka}");
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
                    warn!("server DID document has no authentication — using fallback {fallback_signing}");
                    fallback_signing
                }
            };

            (signing_kid, ka_kid)
        }
        Err(e) => {
            warn!("failed to resolve server DID {server_did}: {e} — using fallback key IDs");
            (fallback_signing, fallback_ka)
        }
    }
}

/// Initialize the DIDComm connection to the mediator.
pub async fn init_didcomm_connection(
    config: &AppConfig,
    server_did: &str,
    secrets: &ServerSecrets,
    did_resolver: Option<&DIDCacheClient>,
) -> Option<(Arc<ATM>, Arc<ATMProfile>)> {
    let mediator_did = match &config.mediator_did {
        Some(did) => did.clone(),
        None => {
            info!("mediator_did not configured — DIDComm messaging disabled");
            return None;
        }
    };

    // Resolve actual key IDs from the DID document
    let (signing_kid, ka_kid) = resolve_server_key_ids(server_did, did_resolver).await;

    // Create TDK shared state
    let tdk = TDKSharedState::default().await;

    // Insert secrets with resolved KIDs
    match Secret::from_multibase(&secrets.signing_key, Some(&signing_kid)) {
        Ok(secret) => {
            tdk.secrets_resolver.insert(secret).await;
            debug!(kid = %signing_kid, "DIDComm signing secret loaded");
        }
        Err(e) => {
            warn!("failed to decode signing_key for DIDComm: {e}");
            return None;
        }
    }

    match Secret::from_multibase(&secrets.key_agreement_key, Some(&ka_kid)) {
        Ok(secret) => {
            tdk.secrets_resolver.insert(secret).await;
            debug!(kid = %ka_kid, "DIDComm key agreement secret loaded");
        }
        Err(e) => {
            warn!("failed to decode key_agreement_key for DIDComm: {e}");
            return None;
        }
    }

    // Configure discovery features
    let features = DiscoverFeatures {
        protocols: vec![
            "https://didcomm.org/trust-ping/2.0".into(),
            "https://didcomm.org/discover-features/2.0".into(),
            "https://affinidi.com/webvh/1.0/witness".into(),
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
            warn!("failed to build ATM config: {e}");
            return None;
        }
    };

    let atm = match ATM::new(atm_config, Arc::new(tdk)).await {
        Ok(a) => a,
        Err(e) => {
            warn!("failed to create ATM: {e}");
            return None;
        }
    };

    let profile = match ATMProfile::new(&atm, None, server_did.to_string(), Some(mediator_did))
        .await
    {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!("failed to create ATM profile: {e}");
            return None;
        }
    };

    // Enable WebSocket streaming
    if let Err(e) = atm.profile_enable_websocket(&profile).await {
        warn!("failed to enable WebSocket: {e}");
        return None;
    }

    let atm = Arc::new(atm);

    info!("DIDComm connection established for {server_did}");
    Some((atm, profile))
}

/// Run the DIDComm message processing loop until shutdown.
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
            let _ = shutdown_rx.changed().await;
            return;
        }
    };

    info!("DIDComm message loop started");

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(WebSocketResponses::MessageReceived(msg, _)) => {
                        dispatch_message(atm, profile, server_did, state, &msg).await;
                        if let Err(e) = atm.delete_message_background(profile, &msg.id).await {
                            warn!("failed to delete message: {e}");
                        }
                    }
                    Ok(WebSocketResponses::PackedMessageReceived(packed)) => {
                        match atm.unpack(&packed).await {
                            Ok((msg, _)) => {
                                dispatch_message(atm, profile, server_did, state, &msg).await;
                                if let Err(e) = atm.delete_message_background(profile, &msg.id).await {
                                    warn!("failed to delete message: {e}");
                                }
                            }
                            Err(e) => warn!("failed to unpack message: {e}"),
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "DIDComm channel lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("DIDComm channel closed");
                        break;
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                break;
            }
        }
    }
}

async fn dispatch_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    server_did: &str,
    state: &AppState,
    msg: &Message,
) {
    let sender_did = msg.from.as_deref().unwrap_or("unknown");
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);

    debug!(type_ = %msg.type_, from = %sender_did, "received DIDComm message");

    // Standard DIDComm protocols — handled separately (different response pattern)
    match msg.type_.as_str() {
        TRUST_PING_TYPE => {
            if let Err(e) = handle_trust_ping(atm, profile, server_did, msg).await {
                warn!("failed to handle trust-ping: {e}");
            }
            return;
        }
        DISCOVER_FEATURES_QUERY_TYPE => {
            if let Err(e) = handle_discover_features(atm, profile, server_did, msg).await {
                warn!("failed to handle discover-features query: {e}");
            }
            return;
        }
        _ => {}
    }

    let result: Result<(String, Value), AppError> = match msg.type_.as_str() {
        MSG_AUTHENTICATE => handle_authenticate(state, server_did, msg).await,
        MSG_WITNESS_PROOF_REQUEST => match check_acl(&state.acl_ks, sender_base).await {
            Ok(_) => handle_proof_request(state, msg).await,
            Err(e) => Err(e),
        },
        MSG_WITNESS_LIST_REQUEST => match check_acl(&state.acl_ks, sender_base).await {
            Ok(_) => handle_list_request(state).await,
            Err(e) => Err(e),
        },
        other => {
            warn!(type_ = %other, "unknown DIDComm message type");
            Ok((
                MSG_WITNESS_PROBLEM_REPORT.to_string(),
                json!({
                    "code": "e.p.witness.unknown-type",
                    "comment": format!("unknown message type: {other}"),
                }),
            ))
        }
    };

    let (response_type, response_body) = match result {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "error handling DIDComm message");
            (
                MSG_WITNESS_PROBLEM_REPORT.to_string(),
                json!({
                    "code": "e.p.witness.internal-error",
                    "comment": e.to_string(),
                }),
            )
        }
    };

    // Build and send response
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

    match atm
        .pack_encrypted(
            &response,
            sender_base,
            Some(server_did),
            Some(server_did),
            None,
        )
        .await
    {
        Ok((packed, _)) => {
            if let Err(e) = atm
                .send_message(profile, &packed, &response.id, false, false)
                .await
            {
                warn!(error = %e, "failed to send DIDComm response");
            }
        }
        Err(e) => warn!(error = %e, "failed to pack DIDComm response"),
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

    let state = atm.discover_features().get_discoverable_state();
    let features = state.read().await;
    let disclosure = features.generate_disclosure_message(
        server_did,
        sender_did,
        query_msg,
        None,
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
// Authentication
// ---------------------------------------------------------------------------

async fn handle_authenticate(
    state: &AppState,
    _server_did: &str,
    msg: &Message,
) -> Result<(String, Value), AppError> {
    let sender_did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("missing sender".into()))?;
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);

    // Check ACL and create session
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

async fn handle_proof_request(
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

async fn handle_list_request(state: &AppState) -> Result<(String, Value), AppError> {
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

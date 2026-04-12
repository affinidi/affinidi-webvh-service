//! DIDComm messaging for the control plane.
//!
//! **Inbound:** Uses the `affinidi-messaging-didcomm-service` framework for
//! mediator connection, message dispatch, and response handling.
//!
//! **Outbound:** Keeps raw ATM connection for proactive sync push messages
//! (`send_sync_update`, `send_sync_delete`) used by `server_push.rs`.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, HandlerContext, RequestLogging, Router,
    TRUST_PING_TYPE, MESSAGE_PICKUP_STATUS_TYPE,
    handler_fn, ignore_handler, trust_ping_handler,
};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::messaging::protocols::discover_features::DiscoverFeatures;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::auth::session::now_epoch;
use crate::config::AppConfig;
use crate::secret_store::ServerSecrets;

// ---------------------------------------------------------------------------
// Message type constants
// ---------------------------------------------------------------------------

// Sync message types (control plane → server/witness via mediator)
pub const MSG_SYNC_UPDATE: &str = "https://affinidi.com/webvh/1.0/did/sync-update";
pub const MSG_SYNC_UPDATE_ACK: &str = "https://affinidi.com/webvh/1.0/did/sync-update-ack";
pub const MSG_SYNC_DELETE: &str = "https://affinidi.com/webvh/1.0/did/sync-delete";
pub const MSG_SYNC_DELETE_ACK: &str = "https://affinidi.com/webvh/1.0/did/sync-delete-ack";

// ---------------------------------------------------------------------------
// Inbound router (framework-managed)
// ---------------------------------------------------------------------------

/// Build the DIDComm router for the control plane's inbound messages.
pub fn build_control_router() -> Result<Router, DIDCommServiceError> {
    Ok(Router::new()
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route(MSG_SYNC_UPDATE_ACK, handler_fn(handle_sync_ack))?
        .route(MSG_SYNC_DELETE_ACK, handler_fn(handle_sync_ack))?
        .fallback(handler_fn(ignore_handler))
        .layer(RequestLogging))
}

async fn handle_sync_ack(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender = ctx.sender_did.as_deref().unwrap_or("unknown");
    let status = message.body.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
    let mnemonic = message.body.get("mnemonic").and_then(|v| v.as_str()).unwrap_or("unknown");
    debug!(
        sender = sender,
        mnemonic = mnemonic,
        status = status,
        msg_type = %message.typ,
        "sync acknowledgement received"
    );
    Ok(None)
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
        .pack_encrypted(
            &msg,
            target_did,
            Some(control_did),
            Some(control_did),
        )
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
        .pack_encrypted(
            &msg,
            target_did,
            Some(control_did),
            Some(control_did),
        )
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

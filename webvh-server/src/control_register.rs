//! Control plane registration — announces this server to the control plane
//! via DIDComm through the mediator.
//!
//! On startup, the server sends a `server/register` DIDComm message to the
//! control plane's DID. The control plane validates the server's DID against
//! its ACL (must be pre-approved with service role) and adds it to the
//! service registry.
//!
//! Also provides `apply_single_update` for applying sync'd DID content
//! received from the control plane (used by `messaging.rs`).

use std::sync::Arc;

use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_webvh_common::DidSyncUpdate;
use affinidi_webvh_common::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, owner_key, validate_did_jsonl,
};
use affinidi_webvh_common::didcomm_types::MSG_SERVER_REGISTER;
use serde_json::json;
use tracing::{error, info, warn};

use crate::secret_store::ServerSecrets;
use crate::server::AppState;
use crate::store::{KeyspaceHandle, Store};

// ---------------------------------------------------------------------------
// DIDComm registration with control plane
// ---------------------------------------------------------------------------

/// Register this server with the control plane via DIDComm.
///
/// Sends a `server/register` message to the control plane's DID through
/// the mediator. The control plane must have the server's DID pre-approved
/// in its ACL.
///
/// Retries with exponential backoff (5s → 60s, max 20 attempts).
pub async fn register_via_didcomm(state: &AppState, secrets: &ServerSecrets) {
    let server_did = match &state.config.server_did {
        Some(did) => did.clone(),
        None => {
            warn!("cannot register: server_did not configured");
            return;
        }
    };

    let control_did = match &state.config.control_did {
        Some(did) => did.clone(),
        None => {
            info!("no control_did configured — skipping registration");
            return;
        }
    };

    let mediator_did = match &state.config.mediator_did {
        Some(did) => did.clone(),
        None => {
            warn!("cannot register: mediator_did not configured");
            return;
        }
    };

    let public_url = state.config.public_url.clone().unwrap_or_default();

    info!(
        server_did = %server_did,
        control_did = %control_did,
        "registering with control plane via DIDComm"
    );

    // Build a short-lived ATM connection for sending the register message
    let tdk = TDKSharedState::default().await;

    // Load secrets for signing and key agreement
    let signing_kid = format!("{server_did}#key-0");
    let ka_kid = format!("{server_did}#key-1");

    if let Ok(secret) = Secret::from_multibase(&secrets.signing_key, Some(&signing_kid)) {
        tdk.secrets_resolver.insert(secret).await;
    } else {
        warn!("failed to decode signing key — cannot register");
        return;
    }

    if let Ok(secret) = Secret::from_multibase(&secrets.key_agreement_key, Some(&ka_kid)) {
        tdk.secrets_resolver.insert(secret).await;
    } else {
        warn!("failed to decode key agreement key — cannot register");
        return;
    }

    let atm_config = match ATMConfig::builder()
        .with_inbound_message_channel(10)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to build ATM config: {e}");
            return;
        }
    };

    let atm = match ATM::new(atm_config, Arc::new(tdk)).await {
        Ok(a) => a,
        Err(e) => {
            warn!("failed to create ATM: {e}");
            return;
        }
    };

    let profile = match ATMProfile::new(&atm, None, server_did.clone(), Some(mediator_did)).await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            warn!("failed to create ATM profile: {e}");
            return;
        }
    };

    // Build the register message
    let body = json!({
        "public_url": public_url,
        "label": "webvh-server",
    });

    let msg = affinidi_messaging_didcomm::Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_SERVER_REGISTER.to_string(),
        body,
    )
    .from(server_did.clone())
    .to(control_did.clone())
    .created_time(crate::auth::session::now_epoch())
    .finalize();

    // Retry with exponential backoff
    let mut backoff = 5u64;
    for attempt in 1..=20u32 {
        match atm
            .pack_encrypted(&msg, &control_did, Some(&server_did), Some(&server_did))
            .await
        {
            Ok((packed, _)) => {
                match atm
                    .send_message(&profile, &packed, &msg.id, false, false)
                    .await
                {
                    Ok(_) => {
                        info!(
                            attempt,
                            control_did = %control_did,
                            "server registration message sent to control plane"
                        );
                        return;
                    }
                    Err(e) => {
                        warn!(
                            attempt,
                            error = %e,
                            backoff_secs = backoff,
                            "failed to send registration message — retrying"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    attempt,
                    error = %e,
                    backoff_secs = backoff,
                    "failed to pack registration message — retrying"
                );
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }

    error!("server registration failed after 20 attempts — giving up");
}

// ---------------------------------------------------------------------------
// DID sync helpers (used by messaging.rs for sync-update handling)
// ---------------------------------------------------------------------------

/// Apply DID updates received from the control plane.
///
/// Each update is validated and stored atomically. Failures are logged
/// as warnings and do not affect other updates.
pub async fn apply_did_updates(
    dids_ks: &KeyspaceHandle,
    store: &Store,
    updates: &[DidSyncUpdate],
    did_cache: &crate::cache::ContentCache,
) {
    for update in updates {
        if let Err(e) = apply_single_update(dids_ks, store, update, did_cache).await {
            warn!(
                mnemonic = %update.mnemonic,
                error = %e,
                "failed to apply DID sync update"
            );
        }
    }
}

/// Apply a single DID sync update atomically.
pub async fn apply_single_update(
    dids_ks: &KeyspaceHandle,
    store: &Store,
    update: &DidSyncUpdate,
    did_cache: &crate::cache::ContentCache,
) -> Result<(), crate::error::AppError> {
    use crate::auth::session::now_epoch;

    // Validate the JSONL content
    validate_did_jsonl(&update.log_content).map_err(crate::error::AppError::Validation)?;

    let now = now_epoch();
    let record = DidRecord {
        owner: "system".to_string(),
        mnemonic: update.mnemonic.clone(),
        created_at: now,
        updated_at: now,
        version_count: update.version_count,
        did_id: Some(update.did_id.clone()),
        content_size: update.log_content.len() as u64,
        disabled: false,
        deleted_at: None,
    };

    let mut batch = store.batch();
    batch.insert(dids_ks, did_key(&update.mnemonic), &record)?;
    batch.insert_raw(
        dids_ks,
        content_log_key(&update.mnemonic),
        update.log_content.as_bytes().to_vec(),
    );
    batch.insert_raw(
        dids_ks,
        owner_key("system", &update.mnemonic),
        update.mnemonic.as_bytes().to_vec(),
    );
    if let Some(ref witness) = update.witness_content {
        batch.insert_raw(
            dids_ks,
            content_witness_key(&update.mnemonic),
            witness.as_bytes().to_vec(),
        );
    }
    batch.commit().await?;

    did_cache.invalidate(&content_log_key(&update.mnemonic));

    info!(
        mnemonic = %update.mnemonic,
        did = %update.did_id,
        "applied DID sync update from control plane"
    );

    Ok(())
}

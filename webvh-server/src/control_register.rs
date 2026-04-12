//! Control plane registration — announces this server to the control plane
//! using DIDComm challenge-response authentication and reports preloaded DIDs
//! for synchronisation.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_webvh_common::{ControlClient, DidSyncEntry, DidSyncUpdate, RegisterServiceRequest};
use tracing::{error, info, warn};

use crate::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, owner_key, validate_did_jsonl,
};
use crate::store::{KeyspaceHandle, Store};

/// Parameters for control plane registration.
pub struct ControlRegistrationParams<'a> {
    pub control_url: &'a str,
    pub server_did: &'a str,
    pub signing_secret: &'a Secret,
    pub public_url: &'a str,
    pub label: Option<&'a str>,
    pub dids_ks: &'a KeyspaceHandle,
    pub store: &'a Store,
    pub did_cache: &'a crate::cache::ContentCache,
}

/// Register with the control plane, retrying with exponential backoff.
///
/// Keeps retrying until registration succeeds. Backoff starts at 5s and
/// caps at 60s. Designed to run as a background task so the server can
/// start serving while waiting for the control plane to become available.
pub async fn register_with_control_retry(params: &ControlRegistrationParams<'_>) {
    const MAX_RETRIES: u32 = 20; // ~10 minutes with exponential backoff
    let mut backoff = 5u64;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        if register_with_control(params).await {
            return;
        }
        if attempt >= MAX_RETRIES {
            error!("control plane registration failed after {attempt} attempts — giving up");
            return;
        }
        info!(
            attempt,
            max = MAX_RETRIES,
            backoff_secs = backoff,
            "retrying control plane registration"
        );
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

/// Register this server instance with the control plane via DIDComm auth.
///
/// 1. Authenticates with the control plane using DIDComm challenge-response
/// 2. Collects preloaded (system-owned) DIDs from the store
/// 3. Sends registration request with DID sync data
/// 4. Applies any DID updates received from the control plane
///
/// Returns `true` on success, `false` on failure (logged as warnings).
pub async fn register_with_control(params: &ControlRegistrationParams<'_>) -> bool {
    let ControlRegistrationParams {
        control_url,
        server_did,
        signing_secret,
        public_url,
        label,
        dids_ks,
        store,
        did_cache,
    } = params;

    // 1. Authenticate with control plane via DIDComm
    let mut client = ControlClient::new(control_url);
    if let Err(e) = client.authenticate(server_did, signing_secret).await {
        warn!(
            control_url = %control_url,
            error = %e,
            "failed to authenticate with control plane"
        );
        return false;
    }

    // 2. Collect preloaded DIDs (system-owned)
    let preloaded_dids = collect_preloaded_dids(dids_ks).await;

    // 3. Register service with DID sync
    let req = RegisterServiceRequest {
        service_type: "server".to_string(),
        url: public_url.to_string(),
        label: label.map(String::from),
        preloaded_dids,
    };

    match client.register_service(&req).await {
        Ok(resp) => {
            if let Some(ref hosting_url) = resp.did_hosting_url {
                info!(did_hosting_url = %hosting_url, "control plane provided DID hosting URL");
            }
            info!(
                control_url = %control_url,
                instance_id = %resp.instance_id,
                did_updates = resp.did_updates.len(),
                "registered with control plane"
            );

            // 4. Apply any DID updates from the control plane
            if !resp.did_updates.is_empty() {
                apply_did_updates(dids_ks, store, &resp.did_updates, did_cache).await;
            }
            true
        }
        Err(e) => {
            warn!(
                control_url = %control_url,
                error = %e,
                "control plane registration failed"
            );
            false
        }
    }
}

/// Collect all system-owned (preloaded) DIDs from the store.
async fn collect_preloaded_dids(dids_ks: &KeyspaceHandle) -> Vec<DidSyncEntry> {
    let entries = match dids_ks.prefix_iter_raw("owner:system:").await {
        Ok(entries) => entries,
        Err(e) => {
            warn!("failed to iterate system DIDs: {e}");
            return Vec::new();
        }
    };

    let prefix = b"owner:system:";
    let mut result = Vec::new();
    for (key, _value) in &entries {
        // Key format: "owner:system:{mnemonic}"
        let mnemonic = if key.starts_with(prefix) {
            match std::str::from_utf8(&key[prefix.len()..]) {
                Ok(m) => m.to_string(),
                Err(_) => continue,
            }
        } else {
            continue;
        };

        // Look up the DidRecord to get metadata
        match dids_ks.get::<DidRecord>(did_key(&mnemonic)).await {
            Ok(Some(record)) => {
                result.push(DidSyncEntry {
                    mnemonic,
                    did_id: record.did_id,
                    version_count: record.version_count,
                    updated_at: record.updated_at,
                });
            }
            Ok(None) => {
                // Orphaned owner key, skip
                continue;
            }
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "failed to read DID record");
                continue;
            }
        }
    }

    result
}

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
    validate_did_jsonl(&update.log_content)?;

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

//! Fire-and-forget push of DID state changes to registered server instances
//! via the DIDComm mediator.
//!
//! When a DID is created, updated, or deleted on the control plane, these
//! functions send DIDComm messages via the shared `DIDCommService` to all
//! active server instances. Messages are routed through the mediator's
//! store-and-forward — no point-to-point connections are made.

use std::future::Future;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_webvh_common::DidSyncUpdate;
use affinidi_webvh_common::did_ops::{self, DidRecord};
use affinidi_webvh_common::didcomm_types::*;
use serde_json::json;
use tracing::{info, warn};

use crate::auth::session::now_epoch;
use crate::registry::{self, ServiceType};
use crate::server::AppState;

/// Push all existing published DIDs to a single server via the mediator.
///
/// Called after a server registers via DIDComm so it receives the full DID set.
pub fn sync_all_dids_to_server(state: &AppState, server_did: String) {
    let dids_ks = state.dids_ks.clone();
    let config = state.config.clone();
    let didcomm = state.didcomm_service.clone();

    tokio::spawn(async move {
        let svc = match didcomm.get() {
            Some(svc) => svc,
            None => return,
        };

        let control_did = match &config.server_did {
            Some(did) => did.as_str(),
            None => return,
        };

        // Iterate all published DIDs
        let raw = match dids_ks.prefix_iter_raw("did:").await {
            Ok(raw) => raw,
            Err(e) => {
                warn!(error = %e, "sync_all_dids: failed to iterate DIDs");
                return;
            }
        };

        let mut count = 0u64;
        for (_key, value) in raw {
            let record: DidRecord = match serde_json::from_slice(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Skip empty/unpublished slots
            if record.version_count == 0 {
                continue;
            }

            // Read log content
            let log_content = match dids_ks
                .get_raw(did_ops::content_log_key(&record.mnemonic))
                .await
            {
                Ok(Some(bytes)) => match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => continue,
                },
                _ => continue,
            };

            // Read witness content (optional)
            let witness_content = match dids_ks
                .get_raw(did_ops::content_witness_key(&record.mnemonic))
                .await
            {
                Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
                _ => None,
            };

            let did_id = record.did_id.unwrap_or_default();
            let update = DidSyncUpdate {
                mnemonic: record.mnemonic.clone(),
                did_id,
                log_content,
                witness_content,
                version_count: record.version_count,
            };

            if let Err(e) = send_with_retry(
                || send_sync_update(svc, control_did, &server_did, &update),
                3,
            )
            .await
            {
                warn!(
                    server_did = %server_did,
                    mnemonic = %record.mnemonic,
                    error = %e,
                    "failed to push DID during initial sync"
                );
            } else {
                count += 1;
            }
        }

        if count > 0 {
            info!(
                server_did = %server_did,
                count,
                "initial DID sync complete for newly registered server"
            );
        }
    });
}

/// Push the current state of a DID to all active server instances via the mediator.
pub fn notify_servers_did(state: &AppState, mnemonic: String) {
    let registry_ks = state.registry_ks.clone();
    let dids_ks = state.dids_ks.clone();
    let config = state.config.clone();
    let didcomm = state.didcomm_service.clone();

    tokio::spawn(async move {
        let svc = match didcomm.get() {
            Some(svc) => svc,
            None => {
                warn!(mnemonic = %mnemonic, "DID sync skipped: DIDComm service not connected");
                return;
            }
        };

        let control_did = match &config.server_did {
            Some(did) => did.as_str(),
            None => {
                warn!(mnemonic = %mnemonic, "DID sync skipped: server_did not configured");
                return;
            }
        };

        info!(mnemonic = %mnemonic, "DID changed — preparing sync to servers");

        // Read the DID record
        let record = match dids_ks.get::<DidRecord>(did_ops::did_key(&mnemonic)).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                warn!(mnemonic = %mnemonic, "DID sync: record not found in store");
                return;
            }
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "DID sync: failed to read record");
                return;
            }
        };

        // Read log content
        let log_content = match dids_ks.get_raw(did_ops::content_log_key(&mnemonic)).await {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => {
                    warn!(mnemonic = %mnemonic, "DID sync: invalid UTF-8 in log content");
                    return;
                }
            },
            Ok(None) => {
                warn!(mnemonic = %mnemonic, "DID sync: no log content found");
                return;
            }
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "DID sync: failed to read log");
                return;
            }
        };

        // Read witness content (optional)
        let witness_content = match dids_ks
            .get_raw(did_ops::content_witness_key(&mnemonic))
            .await
        {
            Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
            _ => None,
        };

        let did_id = record.did_id.unwrap_or_default();

        let update = DidSyncUpdate {
            mnemonic: mnemonic.clone(),
            did_id,
            log_content,
            witness_content,
            version_count: record.version_count,
        };

        // Get server DIDs from registry
        let servers = match get_active_servers(&registry_ks).await {
            Some(s) => s,
            None => {
                warn!(mnemonic = %mnemonic, "DID sync: no active servers in registry");
                return;
            }
        };

        info!(
            mnemonic = %mnemonic,
            server_count = servers.len(),
            "pushing DID update to servers"
        );

        for (server_did, instance_id) in &servers {
            if let Err(e) = send_with_retry(
                || send_sync_update(svc, control_did, server_did, &update),
                3,
            )
            .await
            {
                warn!(
                    server_did,
                    instance_id,
                    mnemonic = %mnemonic,
                    error = %e,
                    "DID sync: failed to push update after retries"
                );
            } else {
                info!(
                    server_did,
                    instance_id,
                    mnemonic = %mnemonic,
                    version_count = update.version_count,
                    "DID sync: update sent to server"
                );
            }
        }
    });
}

/// Notify all active server instances that a DID has been deleted, via the mediator.
pub fn notify_servers_delete(state: &AppState, mnemonic: String) {
    let registry_ks = state.registry_ks.clone();
    let config = state.config.clone();
    let didcomm = state.didcomm_service.clone();

    tokio::spawn(async move {
        let svc = match didcomm.get() {
            Some(svc) => svc,
            None => {
                warn!(mnemonic = %mnemonic, "DID delete sync skipped: DIDComm service not connected");
                return;
            }
        };

        let control_did = match &config.server_did {
            Some(did) => did.as_str(),
            None => {
                warn!(mnemonic = %mnemonic, "DID delete sync skipped: server_did not configured");
                return;
            }
        };

        info!(mnemonic = %mnemonic, "DID deleted — preparing sync to servers");

        let servers = match get_active_servers(&registry_ks).await {
            Some(s) => s,
            None => {
                warn!(mnemonic = %mnemonic, "DID delete sync: no active servers in registry");
                return;
            }
        };

        for (server_did, instance_id) in &servers {
            if let Err(e) = send_with_retry(
                || send_sync_delete(svc, control_did, server_did, &mnemonic),
                3,
            )
            .await
            {
                warn!(
                    server_did,
                    instance_id,
                    mnemonic = %mnemonic,
                    error = %e,
                    "DID sync: failed to push delete after retries"
                );
            } else {
                info!(
                    server_did,
                    instance_id,
                    mnemonic = %mnemonic,
                    "DID sync: delete sent to server"
                );
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get active server DIDs and instance IDs from the registry.
async fn get_active_servers(
    registry_ks: &crate::store::KeyspaceHandle,
) -> Option<Vec<(String, String)>> {
    let instances = match registry::list_instances(registry_ks).await {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "server push: failed to list instances");
            return None;
        }
    };

    let servers: Vec<_> = instances
        .into_iter()
        .filter(|i| {
            i.service_type == ServiceType::Server && i.status == registry::ServiceStatus::Active
        })
        .filter_map(|i| {
            let did = i.metadata.get("did")?.as_str()?.to_string();
            Some((did, i.instance_id))
        })
        .collect();

    if servers.is_empty() {
        None
    } else {
        Some(servers)
    }
}

async fn send_sync_update(
    svc: &DIDCommService,
    control_did: &str,
    target_did: &str,
    update: &DidSyncUpdate,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({
        "mnemonic": update.mnemonic,
        "did_id": update.did_id,
        "log_content": update.log_content,
        "witness_content": update.witness_content,
        "version_count": update.version_count,
    });

    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_SYNC_UPDATE.to_string(),
        body,
    )
    .from(control_did.to_string())
    .to(target_did.to_string())
    .created_time(now_epoch())
    .finalize();

    svc.send_message("control", msg, target_did)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

async fn send_sync_delete(
    svc: &DIDCommService,
    control_did: &str,
    target_did: &str,
    mnemonic: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({
        "mnemonic": mnemonic,
    });

    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_SYNC_DELETE.to_string(),
        body,
    )
    .from(control_did.to_string())
    .to(target_did.to_string())
    .created_time(now_epoch())
    .finalize();

    svc.send_message("control", msg, target_did)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

/// Retry a send operation with exponential backoff.
async fn send_with_retry<F, Fut, E>(make_future: F, max_retries: u32) -> Result<(), E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let mut backoff = 2u64;
    for attempt in 0..=max_retries {
        match make_future().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt == max_retries {
                    return Err(e);
                }
                warn!(attempt = attempt + 1, backoff_secs = backoff, error = %e, "DID push failed, retrying");
                tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
        }
    }
    unreachable!()
}

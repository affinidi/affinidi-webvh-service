//! Fire-and-forget push of DID state changes to registered server instances
//! via the DIDComm mediator.
//!
//! When a DID is created, updated, or deleted on the control plane, these
//! functions send DIDComm messages via the mediator to all active server
//! instances. Messages are encrypted and routed through the mediator —
//! no point-to-point connections are made.

use affinidi_webvh_common::did_ops::{self, DidRecord};
use affinidi_webvh_common::DidSyncUpdate;
use tracing::{info, warn};

use crate::messaging;
use crate::registry::{self, ServiceType};
use crate::server::AppState;

/// Push the current state of a DID to all active server instances via the mediator.
///
/// Reads the DID's log and witness content from the control plane store,
/// then sends a `did/sync-update` DIDComm message to each server's DID
/// via `pack_encrypted` + `atm.send_message` through the mediator.
pub fn notify_servers_did(state: &AppState, mnemonic: String) {
    let registry_ks = state.registry_ks.clone();
    let dids_ks = state.dids_ks.clone();
    let config = state.config.clone();
    let atm = match state.atm.clone() {
        Some(atm) => atm,
        None => return, // No mediator connection — silently skip
    };
    let profile = match state.atm_profile.clone() {
        Some(p) => p,
        None => return,
    };

    tokio::spawn(async move {
        let control_did = match &config.server_did {
            Some(did) => did.as_str(),
            None => return,
        };

        // Read the DID record
        let record = match dids_ks
            .get::<DidRecord>(did_ops::did_key(&mnemonic))
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "server push: failed to read record");
                return;
            }
        };

        // Read log content
        let log_content = match dids_ks
            .get_raw(did_ops::content_log_key(&mnemonic))
            .await
        {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => {
                    warn!(mnemonic = %mnemonic, "server push: invalid UTF-8 in log content");
                    return;
                }
            },
            Ok(None) => return,
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "server push: failed to read log");
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

        // Get server DIDs from registry metadata
        let instances = match registry::list_instances(&registry_ks).await {
            Ok(instances) => instances,
            Err(e) => {
                warn!(error = %e, "server push: failed to list instances");
                return;
            }
        };

        let servers: Vec<_> = instances
            .into_iter()
            .filter(|i| {
                i.service_type == ServiceType::Server
                    && i.status == registry::ServiceStatus::Active
            })
            .collect();

        for server in &servers {
            // The server's DID is stored in the instance metadata during registration
            let server_did = match server.metadata.get("did").and_then(|v| v.as_str()) {
                Some(did) => did,
                None => {
                    warn!(
                        instance_id = %server.instance_id,
                        url = %server.url,
                        "server push: instance has no DID in metadata — cannot send via mediator"
                    );
                    continue;
                }
            };

            match messaging::send_sync_update(&atm, &profile, control_did, server_did, &update)
                .await
            {
                Ok(()) => {
                    info!(
                        server_did = server_did,
                        mnemonic = %mnemonic,
                        "pushed DID update to server via mediator"
                    );
                }
                Err(e) => {
                    warn!(
                        server_did = server_did,
                        mnemonic = %mnemonic,
                        error = %e,
                        "failed to push DID update via mediator"
                    );
                }
            }
        }
    });
}

/// Notify all active server instances that a DID has been deleted, via the mediator.
pub fn notify_servers_delete(state: &AppState, mnemonic: String) {
    let registry_ks = state.registry_ks.clone();
    let config = state.config.clone();
    let atm = match state.atm.clone() {
        Some(atm) => atm,
        None => return,
    };
    let profile = match state.atm_profile.clone() {
        Some(p) => p,
        None => return,
    };

    tokio::spawn(async move {
        let control_did = match &config.server_did {
            Some(did) => did.as_str(),
            None => return,
        };

        let instances = match registry::list_instances(&registry_ks).await {
            Ok(instances) => instances,
            Err(e) => {
                warn!(error = %e, "server push (delete): failed to list instances");
                return;
            }
        };

        let servers: Vec<_> = instances
            .into_iter()
            .filter(|i| {
                i.service_type == ServiceType::Server
                    && i.status == registry::ServiceStatus::Active
            })
            .collect();

        for server in &servers {
            let server_did = match server.metadata.get("did").and_then(|v| v.as_str()) {
                Some(did) => did,
                None => {
                    warn!(
                        instance_id = %server.instance_id,
                        "server push (delete): instance has no DID in metadata"
                    );
                    continue;
                }
            };

            match messaging::send_sync_delete(&atm, &profile, control_did, server_did, &mnemonic)
                .await
            {
                Ok(()) => {
                    info!(
                        server_did = server_did,
                        mnemonic = %mnemonic,
                        "pushed DID delete to server via mediator"
                    );
                }
                Err(e) => {
                    warn!(
                        server_did = server_did,
                        mnemonic = %mnemonic,
                        error = %e,
                        "failed to push DID delete via mediator"
                    );
                }
            }
        }
    });
}

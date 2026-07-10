//! Control plane registration — announces this server to the control plane
//! via DIDComm through the shared mediator connection.
//!
//! On startup, the server sends a `server/register` DIDComm message to the
//! control plane's DID using the `DIDCommService::send_message()` API.
//! The control plane validates the server's DID against its ACL (must be
//! pre-approved with service role) and adds it to the service registry.
//!
//! Also provides `apply_single_update` for applying sync'd DID content
//! received from the control plane (used by `messaging.rs`).

use std::sync::atomic::{AtomicBool, Ordering};

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::DIDCommService;
use did_hosting_common::DidSyncUpdate;
use did_hosting_common::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, extract_service_types, owner_key,
    validate_did_jsonl,
};
use did_hosting_common::didcomm_types::MSG_SERVER_REGISTER;
use did_hosting_common::server::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
use did_hosting_common::server::domain::{DomainStatus, list_domains};
use serde_json::json;
use tracing::{info, warn};

use crate::server::AppState;
use crate::store::{KeyspaceHandle, Store};

/// Tracks whether this server has successfully registered with the control plane.
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Returns true if the server has successfully sent a registration message.
pub fn is_registered() -> bool {
    REGISTERED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// DIDComm registration with control plane
// ---------------------------------------------------------------------------

/// Register this server with the control plane via DIDComm.
///
/// Uses the shared `DIDCommService` connection to send a `server/register`
/// message. Retries with exponential backoff (5s → 60s, max 20 attempts).
///
/// The `DIDCommService` must be initialized before calling this.
pub async fn register_via_didcomm(state: &AppState, didcomm_svc: &DIDCommService) {
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

    info!(
        server_did = %server_did,
        control_did = %control_did,
        "registering with control plane via DIDComm"
    );

    // Ensure the control plane DID is in the server's ACL so it can send
    // sync-update and sync-delete messages that pass the ACL check.
    match get_acl_entry(&state.acl_ks, &control_did).await {
        Ok(Some(entry)) => {
            info!(
                control_did = %control_did,
                role = %entry.role,
                "control plane DID already in ACL"
            );
        }
        Ok(None) => {
            let entry = AclEntry {
                did: control_did.clone(),
                role: Role::Service,
                label: Some("control-plane".to_string()),
                created_at: crate::auth::session::now_epoch(),
                max_total_size: None,
                max_did_count: None,

                domains: did_hosting_common::server::domain::DomainScope::All,
            };
            if let Err(e) = store_acl_entry(&state.acl_ks, &entry).await {
                warn!(error = %e, "failed to add control plane DID to ACL");
            } else {
                info!(control_did = %control_did, "added control plane DID to ACL with service role");
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to check ACL for control plane DID");
        }
    }

    let public_url = state.config.public_url.clone().unwrap_or_default();

    // Wait for the mediator connection to be established before sending
    if let Err(e) = didcomm_svc
        .wait_connected("server", std::time::Duration::from_secs(30))
        .await
    {
        warn!(error = %e, "timed out waiting for mediator connection — skipping registration");
        return;
    }

    // T27: declare capabilities to the control plane on registration.
    // `enabled_methods` is the compile-time set from common; an older
    // control plane that hasn't picked up the T27 fields will simply
    // ignore them.
    let enabled_methods: Vec<&str> = did_hosting_common::method::enabled_methods().to_vec();

    // Report locally-active domains so the control plane's registry view
    // (and the UI's "domains assigned to this server" panel) reflects what
    // this server is actually serving. Disabled domains are intentionally
    // omitted — they're not handing out DID data publicly.
    //
    // Failures here used to silently send `served_domains: []`. Combined
    // with the (post-MED-3) handle_domain_ack mirror logic on the
    // control plane, a transient store error during registration
    // would swing the registry view from "fully populated" to "empty"
    // on every re-register, and a subsequent `?purge_servers=true`
    // fanout would skip this server because the registry briefly
    // lied. Instead, fail the registration attempt so the existing
    // retry loop kicks in — registration with an outdated
    // `served_domains` list is worse than briefly being unregistered.
    let served_domains: Vec<String> = match list_domains(&state.store).await {
        Ok(entries) => entries
            .into_iter()
            .filter(|d| matches!(d.status, DomainStatus::Active))
            .map(|d| d.name)
            .collect(),
        Err(e) => {
            warn!(
                error = %e,
                "failed to list local domains for registration — aborting this register attempt; retry loop will pick it up"
            );
            return;
        }
    };

    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_SERVER_REGISTER.to_string(),
        json!({
            "public_url": public_url,
            "label": "did-hosting-server",
            "enabled_methods": enabled_methods,
            "served_domains": served_domains,
            "protocol_version": "1.0",
        }),
    )
    .from(server_did.clone())
    .to(control_did.clone())
    .created_time(crate::auth::session::now_epoch())
    .finalize();

    // Send with built-in retry (waits for reconnection between attempts)
    match didcomm_svc
        .send_message_with_retry(
            "server",
            msg,
            &control_did,
            10,
            std::time::Duration::from_secs(5),
        )
        .await
    {
        Ok(()) => {
            REGISTERED.store(true, Ordering::Relaxed);
            info!(control_did = %control_did, "server registered with control plane");
        }
        Err(e) => {
            warn!(
                error = %e,
                "server registration failed — will accept sync but may not receive pushes"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// DID sync helpers (used by messaging.rs for sync-update handling)
// ---------------------------------------------------------------------------

/// Apply DID updates received from the control plane.
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

        // T12: legacy construction site; T13 migration fills `domain`.
        method: "webvh".to_string(),
        domain: String::new(),

        // Derive from the synced log rather than trusting the control
        // plane to send a services list — the log is the authority, and
        // this keeps the edge node's badges consistent with what it serves.
        services: extract_service_types(&update.log_content),
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

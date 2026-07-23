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
    AgentNameEntry, DidRecord, agent_name_key, content_log_key, content_witness_key, did_key,
    extract_agent_names, extract_service_types, owner_key, validate_did_jsonl,
};
use did_hosting_common::didcomm_types::MSG_SERVER_REGISTER;
use did_hosting_common::server::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
use did_hosting_common::server::didcomm_profile::{
    PeerTransport, TransportFallback, resolve_transport,
};
use did_hosting_common::server::domain::safety::extract_did_host;
use did_hosting_common::server::domain::{DomainStatus, list_domains};
use did_hosting_common::server::mnemonic::validate_agent_name_binding;
use did_hosting_common::server::trust_tasks::send::{
    Retry, build_request, send_trust_task_with_retry,
};
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

    // Report the DIDs we already hold (mnemonic → version) so the control
    // plane sends only what we're missing or behind on, instead of re-pushing
    // every DID on every boot. Compact by design — mnemonic + version, not the
    // logs. A store-iteration failure degrades to an empty list, i.e. a full
    // sync, which is safe (just not optimal).
    let preloaded_dids: Vec<serde_json::Value> = match state.dids_ks.prefix_iter_raw("did:").await {
        Ok(raw) => raw
            .into_iter()
            .filter_map(|(_k, v)| serde_json::from_slice::<DidRecord>(&v).ok())
            .filter(|r| r.version_count > 0)
            .map(|r| json!({ "mnemonic": r.mnemonic, "version_count": r.version_count }))
            .collect(),
        Err(e) => {
            warn!(error = %e, "failed to enumerate local DIDs for registration — control plane will full-sync");
            Vec::new()
        }
    };

    let body = json!({
        "public_url": public_url,
        "label": "did-hosting-server",
        "enabled_methods": enabled_methods,
        "served_domains": served_domains,
        "protocol_version": "1.0",
        // Tells the control plane it may send infrastructure ops (health ping)
        // as trust tasks, and therefore over whichever transport this server's
        // DID document advertises. An older control plane ignores the field.
        "trust_task_capable": true,
        // Tells the control plane it may coalesce DID sync updates into
        // `MSG_SYNC_BATCH` messages instead of one frame per DID. An older
        // control plane ignores this and sends singles.
        "sync_batch": true,
        // Delta-sync hint: the DIDs we already hold, so the control plane only
        // pushes changes. An older control plane ignores this and full-syncs.
        "preloaded_dids": preloaded_dids,
    });

    // Framing follows the transport, and for one hard reason: a **TSP-only**
    // server has no DIDComm wire on which to send the legacy
    // `MSG_SERVER_REGISTER` message, so its only way into the registry is a
    // trust task over TSP. Meanwhile a DIDComm-reachable server keeps sending
    // the legacy message, because an *older* control plane has no
    // `trust_tasks_infra` arm and would bounce a register trust task into
    // `bridge_did_management` — which has never heard of `server/register` —
    // leaving the server silently unregistered.
    //
    // Once every control plane in a fleet understands the trust task, this
    // branch collapses to `send_trust_task` unconditionally. Discovery
    // (`trust-task-discovery/0.1`) is the principled way to detect that; it is
    // deliberately not attempted here.
    let control_speaks_tsp = matches!(
        resolve_transport(&control_did, state.did_resolver.as_ref()).await,
        Some((PeerTransport::Tsp, _))
    );

    // This node's configured mediator, used as the send fallback when the
    // peer's document advertises no transport (see `resolve_send_binding`).
    let fallback = TransportFallback::from_config(
        state.config.mediator_did.as_deref(),
        state.config.features.tsp,
    );

    let outcome = if control_speaks_tsp {
        match build_request(MSG_SERVER_REGISTER, &server_did, &control_did, body) {
            Ok(doc) => send_trust_task_with_retry(
                didcomm_svc,
                "server",
                &server_did,
                &control_did,
                &doc,
                &fallback,
                state.did_resolver.as_ref(),
                Retry {
                    attempts: 10,
                    delay: std::time::Duration::from_secs(5),
                },
            )
            .await
            .map(|transport| {
                info!(?transport, "server registration sent as trust task");
            }),
            Err(e) => Err(e),
        }
    } else {
        let msg = Message::build(
            uuid::Uuid::new_v4().to_string(),
            MSG_SERVER_REGISTER.to_string(),
            body,
        )
        .from(server_did.clone())
        .to(control_did.clone())
        .created_time(crate::auth::session::now_epoch())
        .finalize();

        // Send with built-in retry (waits for reconnection between attempts)
        didcomm_svc
            .send_message_with_retry(
                "server",
                msg,
                &control_did,
                10,
                std::time::Duration::from_secs(5),
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    };

    match outcome {
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

    // Agent names are scoped to the hosting domain, and the DID identifier is
    // where that domain is authoritative — `extract_did_host` percent-decodes
    // the authority (`localhost%3A8534` -> `localhost:8534`) so it matches the
    // form a name carries. An unparseable identifier yields no names rather
    // than failing the sync: a DID we cannot parse is one we should not be
    // serving names for anyway.
    let did_host = extract_did_host(&update.did_id).unwrap_or_default();

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

        // Same argument, and here it carries security weight: agent names
        // come from the signed document's `alsoKnownAs`, never from the
        // push. An edge therefore *cannot* serve a name the DID does not
        // claim, so the agent-name specification's Layer-1 rule holds by
        // construction rather than by remembering to check it — even if the
        // control plane is compromised or buggy.
        //
        // A name absent from the new log is absent here, which is what makes
        // the stale-index cleanup below correct.
        //
        // The claim check is Layer-1 and holds by construction. Entitlement —
        // *may this DID claim this name* — is the control plane's job, and a
        // name that reaches here has already passed it. The one case worth
        // re-checking is the community name (`{domain}/@`), which is the
        // domain's own identity: cheap to verify against the mnemonic, and the
        // single most valuable name to get wrong, so it does not rely on the
        // push being honest. `validate_agent_name_binding` also drops reserved
        // names for the same reason.
        agent_names: extract_agent_names(&update.log_content, &did_host)
            .into_iter()
            .filter(|name| validate_agent_name_binding(name, &update.mnemonic).is_ok())
            .map(|name| AgentNameEntry {
                name,
                enabled: true,
                created_at: now,
            })
            .collect(),
    };

    // Read the record we are replacing so stale name-index entries can be
    // retired in the same batch. Without this, a name removed from
    // `alsoKnownAs` would keep resolving from a leftover index entry — the
    // document would stop claiming it while the edge kept serving it, which is
    // precisely the state Layer-1 exists to prevent.
    let previous: Option<DidRecord> = dids_ks.get(did_key(&update.mnemonic)).await.ok().flatten();

    let mut batch = store.batch();
    batch.insert(dids_ks, did_key(&update.mnemonic), &record)?;

    if let Some(prev) = previous.as_ref() {
        for old in &prev.agent_names {
            if !record.agent_names.iter().any(|n| n.name == old.name) {
                batch.remove(dids_ks, agent_name_key(&did_host, &old.name));
            }
        }
    }
    for entry in &record.agent_names {
        batch.insert_raw(
            dids_ks,
            agent_name_key(&did_host, &entry.name),
            update.mnemonic.as_bytes().to_vec(),
        );
    }
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

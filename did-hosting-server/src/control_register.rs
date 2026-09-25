//! Control plane registration — announces this server to the control plane
//! via DIDComm through the shared mediator connection.
//!
//! On startup, the server sends a signed `server/register` trust task to the
//! control plane's DID over whichever binding its DID document advertises.
//! The control plane validates the server's DID against its ACL (must be
//! pre-approved with service role) and adds it to the service registry.
//!
//! Also provides `apply_single_update` for applying sync'd DID content
//! received from the control plane (used by `messaging.rs`).

use std::sync::atomic::{AtomicBool, Ordering};

use affinidi_messaging_didcomm_service::DIDCommService;
use did_hosting_common::DidSyncUpdate;
use did_hosting_common::did_ops::{
    AgentNameEntry, DidRecord, agent_name_key, content_log_key, content_witness_key, did_key,
    extract_agent_names, extract_service_types, owner_key,
};
use did_hosting_common::didcomm_types::MSG_SERVER_REGISTER;
use did_hosting_common::server::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
use did_hosting_common::server::didcomm_profile::TransportFallback;
use did_hosting_common::server::domain::safety::extract_did_host;
use did_hosting_common::server::domain::{DomainStatus, list_domains};
use did_hosting_common::server::mnemonic::validate_agent_name_binding;
use did_hosting_common::server::trust_tasks::send::{
    Retry, build_signed_request, send_trust_task_with_retry,
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

    // Always a signed trust task. Registration makes this server a sync target
    // for every tenant's DIDs, so the control plane admits it only on a
    // document this server's DID signed (see `do_server_register`); the
    // bare-message form it replaced carried no proof and is no longer routed.
    // The binding — TSP or the DIDComm envelope — follows the control plane's
    // DID document.
    let fallback = TransportFallback::from_config(
        state.config.mediator_did.as_deref(),
        state.config.features.tsp,
    );
    let signer = match state.identity.as_deref() {
        Some(identity) => {
            match did_hosting_common::server::trust_tasks::identity_signing_secret(
                identity,
                &server_did,
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "cannot register: no signing key for this server's DID");
                    return;
                }
            }
        }
        None => {
            warn!(
                "cannot register: service identity not loaded, so the registration cannot be signed"
            );
            return;
        }
    };

    let outcome = match build_signed_request(
        MSG_SERVER_REGISTER,
        &server_did,
        &control_did,
        body,
        &signer,
    )
    .await
    {
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
    public_url: Option<&str>,
) {
    for update in updates {
        if let Err(e) = apply_single_update(dids_ks, store, update, did_cache, public_url).await {
            warn!(
                mnemonic = %update.mnemonic,
                error = %e,
                "failed to apply DID sync update"
            );
        }
    }
}

/// What [`verify_update`] established about an update.
struct VerifiedUpdate {
    /// The DID's stable identity: the SCID for webvh, the identifier for webs.
    identity: String,
    #[cfg(feature = "method-webs")]
    webs_document: Option<serde_json::Value>,
}

/// The last DID a slot served. Kept after a delete (see `apply_single_update`).
#[derive(serde::Serialize, serde::Deserialize)]
struct SlotHighWater {
    identity: String,
    did_id: String,
    method: String,
}

/// The high-water log key for a DID identity (SCID / webs identifier).
fn high_water_identity_key(identity: &str) -> String {
    format!("hw:id:{identity}")
}

/// The high-water record key for a slot.
fn high_water_slot_key(mnemonic: &str) -> String {
    format!("hw:slot:{mnemonic}")
}

/// Verify a sync update before it replaces anything:
///
/// 1. **Binding** — the identifier the push names is the one the log
///    establishes, and it resolves at exactly this slot on a host this server
///    serves (its public URL or an assigned domain). A valid log cannot be
///    filed under another slot or served for another host.
/// 2. **Chain** — webvh: every entry's hash, proof against the authorised
///    `updateKeys`, pre-rotation and parameter transition, and the witness
///    proofs when witnesses are configured; webs: the full key event log.
/// 3. **History** — the log must strictly extend every history this edge has
///    ever served for the same DID: the log it holds now, and the high-water
///    log it kept for that DID's identity, which a delete does not clear. A
///    rollback, a fork, a resurrected deactivation or a re-created DID that
///    starts over are all refused. A slot that held a different DID may be
///    re-used by a new one (a new DID is a new identity with its own history);
///    a slot never changes method.
async fn verify_update(
    dids_ks: &KeyspaceHandle,
    store: &Store,
    update: &DidSyncUpdate,
    synced_method: &str,
    public_url: Option<&str>,
) -> Result<VerifiedUpdate, crate::error::AppError> {
    use crate::error::AppError;
    use did_hosting_common::did_ops::verify_log_extends;

    verify_binding(store, update, synced_method, public_url).await?;

    let held = dids_ks
        .get_raw(content_log_key(&update.mnemonic))
        .await?
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let held_record: Option<DidRecord> = dids_ks.get(did_key(&update.mnemonic)).await?;
    let slot_mark: Option<SlotHighWater> =
        dids_ks.get(high_water_slot_key(&update.mnemonic)).await?;
    for method in held_record
        .as_ref()
        .map(|r| r.method.as_str())
        .into_iter()
        .chain(slot_mark.as_ref().map(|m| m.method.as_str()))
    {
        if method != synced_method {
            return Err(AppError::Validation(format!(
                "slot {} holds a {method} DID; refusing to replace it with a {synced_method} log",
                update.mnemonic
            )));
        }
    }

    let identity = match synced_method {
        "webvh" => {
            did_hosting_common::did_ops::verify_did_log_and_witness_proofs(
                &update.log_content,
                update.witness_content.as_deref(),
            )
            .map_err(AppError::Validation)?;
            webvh_scid(&update.did_id).ok_or_else(|| {
                AppError::Validation(format!("{} is not a did:webvh identifier", update.did_id))
            })?
        }
        _ => update.did_id.clone(),
    };

    #[cfg(feature = "method-webs")]
    let webs_document = if synced_method == "webs" {
        let derived = did_hosting_common::method::webs::Webs::verify_artifacts(
            &update.did_id,
            update.log_content.as_bytes(),
            None,
        )
        .map_err(|e| AppError::Validation(e.to_string()))?;
        Some(
            serde_json::from_slice::<serde_json::Value>(&derived)
                .map_err(|e| AppError::Internal(e.to_string()))?,
        )
    } else {
        None
    };
    #[cfg(not(feature = "method-webs"))]
    if synced_method != "webvh" {
        return Err(AppError::Validation(format!(
            "this server cannot verify {synced_method} logs"
        )));
    }

    // Every history of this same DID the edge has served.
    let high_water = dids_ks
        .get_raw(high_water_identity_key(&identity))
        .await?
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let held_identity = held_record
        .as_ref()
        .and_then(|r| r.did_id.as_deref())
        .map(|id| match synced_method {
            "webvh" => webvh_scid(id).unwrap_or_default(),
            _ => id.to_string(),
        });
    let same_did_held = held.filter(|_| held_identity.as_deref() == Some(identity.as_str()));
    for previous in [same_did_held, high_water].into_iter().flatten() {
        match synced_method {
            "webvh" => verify_log_extends(Some(&previous), &update.log_content)
                .map_err(AppError::Validation)?,
            #[cfg(feature = "method-webs")]
            _ => did_hosting_common::method::webs::Webs::verify_continuation(
                &update.did_id,
                previous.as_bytes(),
                update.log_content.as_bytes(),
            )
            .map_err(|e| AppError::Validation(e.to_string()))?,
            #[cfg(not(feature = "method-webs"))]
            _ => unreachable!("refused above"),
        }
    }

    Ok(VerifiedUpdate {
        identity,
        #[cfg(feature = "method-webs")]
        webs_document,
    })
}

/// The SCID of a `did:webvh:{scid}:…` identifier.
fn webvh_scid(did_id: &str) -> Option<String> {
    did_id
        .strip_prefix("did:webvh:")?
        .split(':')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Step 1 of [`verify_update`]: the identifier is the log's, and it resolves
/// at this slot on a host this server serves.
async fn verify_binding(
    store: &Store,
    update: &DidSyncUpdate,
    synced_method: &str,
    public_url: Option<&str>,
) -> Result<(), crate::error::AppError> {
    use crate::error::AppError;

    if synced_method == "webvh" {
        match did_hosting_common::did_ops::extract_did_id(&update.log_content) {
            Some(id) if id == update.did_id => {}
            other => {
                return Err(AppError::Validation(format!(
                    "sync update names {} but its log establishes {}",
                    update.did_id,
                    other.as_deref().unwrap_or("no DID")
                )));
            }
        }
    }

    // The hosts this server serves: its public URL and each assigned domain.
    let mut bases: Vec<String> = public_url.map(str::to_string).into_iter().collect();
    for entry in did_hosting_common::server::assignment::list(store).await? {
        let host = entry.domain.split('/').next().unwrap_or(&entry.domain);
        bases.push(format!("https://{host}"));
        bases.push(format!("https://{}", entry.domain));
    }
    if bases.is_empty() {
        return Err(AppError::Validation(
            "this server has no public URL or assigned domain to bind synced DIDs to".into(),
        ));
    }

    let bound = match synced_method {
        "webvh" => bases.iter().any(|base| {
            did_hosting_common::did_ops::validate_did_id_matches_request(
                &update.did_id,
                &update.mnemonic,
                base,
            )
            .is_ok()
        }),
        // did:webs:{host}:{path…}:{aid} — the slot is the path including the
        // AID, so the identifier must end in exactly that.
        _ => {
            let host = extract_did_host(&update.did_id).unwrap_or_default();
            let suffix = format!(":{}", update.mnemonic.replace('/', ":"));
            update.did_id.ends_with(&suffix)
                && bases.iter().any(|base| {
                    url::Url::parse(base).ok().is_some_and(|u| {
                        let authority = match u.port() {
                            Some(p) => format!("{}:{p}", u.host_str().unwrap_or_default()),
                            None => u.host_str().unwrap_or_default().to_string(),
                        };
                        authority == host
                    })
                })
        }
    };
    if !bound {
        return Err(AppError::Validation(format!(
            "{} does not resolve at slot {} on a host this server serves",
            update.did_id, update.mnemonic
        )));
    }
    Ok(())
}

/// Apply a single DID sync update atomically.
///
/// `public_url` is this server's configured public URL, one of the bases a
/// synced DID's identifier may be hosted under (with each assigned domain).
pub async fn apply_single_update(
    dids_ks: &KeyspaceHandle,
    store: &Store,
    update: &DidSyncUpdate,
    did_cache: &crate::cache::ContentCache,
    public_url: Option<&str>,
) -> Result<(), crate::error::AppError> {
    use crate::auth::session::now_epoch;

    let now = now_epoch();

    // Agent names are scoped to the hosting domain, and the DID identifier is
    // where that domain is authoritative — `extract_did_host` percent-decodes
    // the authority (`localhost%3A8534` -> `localhost:8534`) so it matches the
    // form a name carries. An unparseable identifier yields no names rather
    // than failing the sync: a DID we cannot parse is one we should not be
    // serving names for anyway.
    let did_host = extract_did_host(&update.did_id).unwrap_or_default();

    // Which method is being synced. An edge must tag the record with the
    // method that actually verified the content: `resolve_webs` will only
    // answer for a record tagged `webs`, so a did:webs log landing here as
    // `webvh` would be stored and then served by nobody.
    let synced_method =
        did_hosting_common::method::detect_method(update.log_content.as_bytes()).unwrap_or("webvh");

    // The edge verifies what it is asked to serve itself, rather than trusting
    // the control plane to have done so: a compromised or buggy control plane
    // must not be able to make an edge serve a log the DID's own keys never
    // authorised, an old version of one, or one filed under another slot.
    // See `verify_update` for the full list.
    let verified = verify_update(dids_ks, store, update, synced_method, public_url).await?;
    #[cfg(feature = "method-webs")]
    let webs_document = verified.webs_document;

    // Services and agent names both come from the current DID document,
    // wherever this method keeps it — the last log entry's `state` for
    // webvh, the derivation from the key event log for webs.
    #[cfg(feature = "method-webs")]
    let (synced_services, synced_names) = match webs_document.as_ref() {
        Some(doc) => (
            Some(did_hosting_common::did::service_types_from_doc(doc)),
            did_hosting_common::did_ops::agent_names_from_document(doc, &did_host),
        ),
        None => (
            extract_service_types(&update.log_content),
            extract_agent_names(&update.log_content, &did_host),
        ),
    };
    #[cfg(not(feature = "method-webs"))]
    let (synced_services, synced_names) = (
        extract_service_types(&update.log_content),
        extract_agent_names(&update.log_content, &did_host),
    );

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

        // Tagged from the content, not from the push. T13's migration
        // fills `domain` for legacy webvh records; a did:webs record
        // needs it from the start, because its identifier — and so the
        // document derived on every read — cannot be rebuilt without it.
        method: synced_method.to_string(),
        domain: if synced_method == "webs" {
            did_host.clone()
        } else {
            String::new()
        },

        // Derive from the synced log rather than trusting the control
        // plane to send a services list — the log is the authority, and
        // this keeps the edge node's badges consistent with what it serves.
        services: synced_services,

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
        agent_names: synced_names
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
    // High-water marks: the furthest history this edge has served for this DID
    // and for this slot. Never removed — not by `sync/delete`, not by a domain
    // purge — so a delete followed by a re-sync cannot roll either back.
    batch.insert_raw(
        dids_ks,
        high_water_identity_key(&verified.identity),
        update.log_content.as_bytes().to_vec(),
    );
    batch.insert(
        dids_ks,
        high_water_slot_key(&update.mnemonic),
        &SlotHighWater {
            identity: verified.identity.clone(),
            did_id: update.did_id.clone(),
            method: synced_method.to_string(),
        },
    )?;
    batch.commit().await?;

    did_cache.invalidate(&content_log_key(&update.mnemonic));

    info!(
        mnemonic = %update.mnemonic,
        did = %update.did_id,
        "applied DID sync update from control plane"
    );

    Ok(())
}

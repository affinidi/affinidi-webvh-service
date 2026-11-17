//! Control plane registration — announces this server to the control plane
//! via DIDComm through the shared mediator connection.
//!
//! On startup, the server sends a signed `server/register` trust task to the
//! control plane's DID over whichever binding its DID document advertises.
//! The control plane validates the server's DID against its ACL (must be
//! pre-approved with service role) and adds it to the service registry. The
//! edge keeps no ACL of its own: the only party it takes directives from is
//! the configured `control_did`, established from each document's proof.
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
use did_hosting_common::didcomm_types::{MSG_SERVER_REGISTER, REGISTER_EXT_NAMESPACE};
use did_hosting_common::server::didcomm_profile::TransportFallback;
use did_hosting_common::server::domain::safety::extract_did_host;
use did_hosting_common::server::domain::{DomainStatus, list_domains};
use did_hosting_common::server::mnemonic::validate_agent_name_binding;
use did_hosting_common::server::trust_tasks::send::{
    Peers, Retry, build_signed_request, send_trust_task_with_retry,
};
use did_hosting_common::tasks::did_management::server::register;
use serde_json::json;
use tracing::{info, warn};

use crate::server::AppState;
use crate::store::{KeyspaceHandle, Store};
use did_hosting_common::server::path_locks::PathLocks;

/// Tracks whether this server has successfully registered with the control plane.
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Returns true if the server has successfully sent a registration message.
pub fn is_registered() -> bool {
    REGISTERED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// DIDComm registration with control plane
// ---------------------------------------------------------------------------

/// Register this server with the control plane.
///
/// Sends a signed `server/register` Trust Task over the transport the control
/// plane's DID document advertises (`send_trust_task_with_retry`). Retries a
/// fixed 10 attempts, 5s apart (no backoff).
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
    // with the control plane mirroring `served_domains` into its
    // registry on each registration, a transient store error during registration
    // would swing the registry view from "fully populated" to "empty"
    // on every re-register, and a subsequent domain purge with `purgeServers`
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

    let preloaded_dids = preloaded_dids(state).await;

    // `did-management/server/register/0.2`. The payload is closed, so this
    // service's own hints ride under `ext`, in its namespace.
    let body = json!({
        // The control plane keys the registry by the signer's DID with `:`
        // replaced, and refuses any other `instanceId`.
        "instanceId": did_hosting_common::server::trust_tasks::infra::instance_id_for(&server_did),
        "did": server_did,
        "publicUrl": public_url,
        "label": "did-hosting-server",
        "enabledMethods": enabled_methods,
        "servedDomains": served_domains,
        "protocolVersion": "1.0",
        "ext": {
            (REGISTER_EXT_NAMESPACE): {
                // Tells the control plane it may coalesce DID sync updates
                // into `MSG_SYNC_BATCH` messages instead of one frame per DID.
                "sync_batch": true,
                // Delta-sync hint: the DIDs we already hold, so the control
                // plane only pushes changes.
                "preloaded_dids": preloaded_dids,
            }
        },
    });
    // Hold the body to the pinned schema before signing it: the control plane
    // refuses a register payload that does not parse as the generated type.
    if let Err(e) = serde_json::from_value::<register::v0_2::Payload>(body.clone()) {
        warn!(error = %e, "cannot register: the register payload does not match server/register/0.2");
        return;
    }

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
            Peers::new(
                state.did_resolver.as_ref(),
                state.trust_tasks_verifier.as_deref(),
            ),
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

/// The slot holding this edge's *own* DID, when it hosts it (a self-hosted
/// `did:webvh` edge: setup imports the DID into the edge's store at
/// `mnemonic_from_did(server_did)`).
///
/// That slot is local edge state the control plane never published, so it is
/// kept out of every exchange that reconciles the edge against the control
/// plane's listing: it is not reported in `preloaded_dids` (the control plane
/// would queue a `sync/delete` for it), not counted as `extra` by the
/// reconcile (the edge would be "stale" for ever), and a `sync/delete` of it
/// is refused (the edge would delete the DID its own signatures verify
/// against).
pub fn own_did_mnemonic(state: &AppState) -> Option<String> {
    state
        .config
        .server_did
        .as_deref()
        .and_then(did_hosting_common::server::identity::mnemonic_from_did)
}

/// The DIDs this edge already holds (mnemonic → DID + version), reported at
/// registration so the control plane sends only what the edge is missing or
/// behind on, instead of re-pushing every DID on every boot. Compact by
/// design — mnemonic + version, not the logs. A store-iteration failure
/// degrades to an empty list, i.e. a full sync, which is safe (just not
/// optimal). The edge's own DID is never reported ([`own_did_mnemonic`]).
pub async fn preloaded_dids(state: &AppState) -> Vec<serde_json::Value> {
    let own = own_did_mnemonic(state);
    // A page of records at a time: only the compact summaries are kept.
    let mut out = Vec::new();
    let mut pages = state.dids_ks.walk("did:", crate::paging::DID_PAGE_ROWS);
    loop {
        match pages.next_page().await {
            Ok(Some(rows)) => out.extend(
                rows.into_iter()
                    .filter_map(|(_k, v)| serde_json::from_slice::<DidRecord>(&v).ok())
                    .filter(|r| r.version_count > 0)
                    .filter(|r| own.as_deref() != Some(r.mnemonic.as_str()))
                    // `did_id` names *which* DID the slot holds: a DID deleted
                    // and re-created at the same mnemonic has a new identifier,
                    // so the control plane re-pushes on an identity mismatch
                    // even when the version counts happen to agree.
                    .map(|r| {
                        json!({
                            "mnemonic": r.mnemonic,
                            "did_id": r.did_id,
                            "version_count": r.version_count,
                            // So a disable this edge missed is re-sent too.
                            "disabled": r.disabled,
                        })
                    }),
            ),
            Ok(None) => return out,
            Err(e) => {
                warn!(error = %e, "failed to enumerate local DIDs for registration — control plane will full-sync");
                return Vec::new();
            }
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
    caches: &crate::cache::ResolutionCaches,
    locks: &PathLocks,
    public_url: Option<&str>,
) {
    for update in updates {
        if let Err(e) = apply_single_update(dids_ks, store, update, caches, locks, public_url).await
        {
            warn!(
                mnemonic = %update.mnemonic,
                error = %e,
                "failed to apply DID sync update"
            );
        }
    }
}

/// What [`verify_chain`] established about an update.
struct VerifiedChain {
    #[cfg(feature = "method-webs")]
    webs_document: Option<serde_json::Value>,
}

/// The lock key serialising every write to `mnemonic`'s slot on an edge.
pub fn slot_lock_key(mnemonic: &str) -> String {
    format!("edge-slot:{mnemonic}")
}

/// The lock key serialising every write to one DID identity's high-water
/// mark (two slots can hold logs of the same DID). Taken after the slot's.
pub fn identity_lock_key(identity: &str) -> String {
    format!("edge-identity:{identity}")
}

/// The last DID a slot served. Kept after a delete (see `apply_single_update`).
#[derive(serde::Serialize, serde::Deserialize)]
struct SlotHighWater {
    identity: String,
    did_id: String,
    method: String,
}

/// The key prefix of a DID identity's high-water log.
pub(crate) const HIGH_WATER_IDENTITY_PREFIX: &str = "hw:id:";

/// The key prefix of a slot's high-water record.
pub(crate) const HIGH_WATER_SLOT_PREFIX: &str = "hw:slot:";

/// The high-water log key for a DID identity (SCID / webs identifier).
fn high_water_identity_key(identity: &str) -> String {
    format!("{HIGH_WATER_IDENTITY_PREFIX}{identity}")
}

/// The high-water record key for a slot.
fn high_water_slot_key(mnemonic: &str) -> String {
    format!("{HIGH_WATER_SLOT_PREFIX}{mnemonic}")
}

/// The methods whose logs carry a history an edge holds them to: every
/// replacement must extend what was served before.
/// A `did:webs` log is checked only by a build with `method-webs`.
pub(crate) fn has_history(method: &str) -> bool {
    method == "webvh" || (method == "webs" && cfg!(feature = "method-webs"))
}

/// Verify a sync update before it replaces anything. Three checks, split by
/// what they need:
///
/// 1. **Binding** ([`verify_binding`]) — the identifier the push names is the
///    one the log establishes, and it resolves at exactly this slot on a host
///    this server serves (its public URL or an assigned domain). A valid log
///    cannot be filed under another slot or served for another host.
/// 2. **Chain** (this function) — webvh: every entry's hash, proof against
///    the authorised `updateKeys`, pre-rotation and parameter transition, and
///    the witness proofs when witnesses are configured; webs: the full key
///    event log. Pure CPU over the update alone, so it runs on a blocking
///    thread and before any lock is taken: verifying one slot's log never
///    holds up another slot's sync.
/// 3. **History** ([`verify_history`]) — under the slot's lock: the log must
///    strictly extend every history this edge has ever served for the same
///    DID. A rollback, a fork, a resurrected deactivation or a re-created DID
///    that starts over are all refused. A slot that held a different DID may
///    be re-used by a new one (a new DID is a new identity with its own
///    history); a slot never changes method.
fn verify_chain(
    update: &DidSyncUpdate,
    synced_method: &str,
) -> Result<VerifiedChain, crate::error::AppError> {
    use crate::error::AppError;

    match synced_method {
        "webvh" => did_hosting_common::did_ops::verify_did_log_and_witness_proofs(
            &update.log_content,
            update.witness_content.as_deref(),
        )
        .map_err(AppError::invalid)?,
        // Verified below, with the document it derives.
        #[cfg(feature = "method-webs")]
        "webs" => {}
        other => return Err(cannot_verify(other)),
    }

    #[cfg(feature = "method-webs")]
    let webs_document = if synced_method == "webs" {
        let derived = did_hosting_common::method::webs::Webs::verify_artifacts(
            &update.did_id,
            update.log_content.as_bytes(),
            None,
        )
        .map_err(|e| AppError::invalid(e.to_string()))?;
        Some(
            serde_json::from_slice::<serde_json::Value>(&derived)
                .map_err(|e| AppError::Internal(e.to_string()))?,
        )
    } else {
        None
    };

    Ok(VerifiedChain {
        #[cfg(feature = "method-webs")]
        webs_document,
    })
}

/// The DID identity a log's history is kept under: the SCID for webvh, the
/// identifier for webs.
pub(crate) fn history_identity(
    did_id: &str,
    method: &str,
) -> Result<String, crate::error::AppError> {
    match method {
        "webvh" => webvh_scid(did_id).ok_or_else(|| {
            crate::error::AppError::invalid(format!("{did_id} is not a did:webvh identifier"))
        }),
        "webs" => Ok(did_id.to_string()),
        other => Err(cannot_verify(other)),
    }
}

/// Step 3 of a sync's verification, shared with every other path that
/// replaces a hosted log: the log must strictly extend every history this
/// edge has served for the same DID — the log it holds now, and the
/// high-water mark kept for the DID's identity, which a delete does not
/// clear — and a slot never changes method. Returns the DID's identity (SCID
/// for webvh, the identifier for webs), to be recorded with
/// [`stage_high_water`] in the same batch that stores the log.
///
/// The log itself must already have been verified (chain, proofs): the mark
/// compares version ids, which identify a prefix only of a verified chain.
/// Callers hold the slot's and the identity's sync locks.
pub(crate) async fn verify_history(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    did_id: &str,
    log_content: &str,
    method: &str,
) -> Result<String, crate::error::AppError> {
    use crate::error::{AppError, ValidationKind};

    let held_record: Option<DidRecord> = dids_ks.get(did_key(mnemonic)).await?;
    let slot_mark: Option<SlotHighWater> = dids_ks.get(high_water_slot_key(mnemonic)).await?;
    for held_method in held_record
        .as_ref()
        .map(|r| r.method.as_str())
        .into_iter()
        .chain(slot_mark.as_ref().map(|m| m.method.as_str()))
    {
        if held_method != method {
            return Err(AppError::validation(
                ValidationKind::HistoryRewrite,
                format!(
                    "slot {mnemonic} holds a {held_method} DID; refusing to replace it with a {method} log"
                ),
            ));
        }
    }

    let identity = history_identity(did_id, method)?;

    // The furthest history of this same DID the edge has served. Every path
    // that writes a log stages the mark with it, so the mark covers the log
    // held now; that log is compared itself only where no mark exists yet (a
    // store written before marks were kept).
    match dids_ks.get_raw(high_water_identity_key(&identity)).await? {
        Some(bytes) => HighWaterMark::parse(method, &bytes)?.admits(method, did_id, log_content)?,
        None => {
            let held_identity = held_record
                .as_ref()
                .and_then(|r| r.did_id.as_deref())
                .map(|id| history_identity(id, method).unwrap_or_default());
            if held_identity.as_deref() == Some(identity.as_str())
                && let Some(held) = dids_ks.get_raw(content_log_key(mnemonic)).await?
            {
                verify_extends(method, did_id, &String::from_utf8_lossy(&held), log_content)?;
            }
        }
    }
    Ok(identity)
}

/// Whether `next` strictly extends `previous`, two logs of the same DID: the
/// history check [`verify_history`] applies to each history it holds.
pub(crate) fn verify_extends(
    method: &str,
    did_id: &str,
    previous: &str,
    next: &str,
) -> Result<(), crate::error::AppError> {
    use crate::error::{AppError, ValidationKind};
    use did_hosting_common::did_ops::LogExtendError;
    #[cfg(feature = "method-webs")]
    use did_hosting_common::method::MethodError;
    match method {
        "webvh" => {
            did_hosting_common::did_ops::verify_log_extends(Some(previous), next).map_err(|e| {
                let kind = match e {
                    LogExtendError::Deactivated => ValidationKind::Deactivated,
                    LogExtendError::HistoryRewrite { .. } => ValidationKind::HistoryRewrite,
                };
                AppError::validation(kind, e.to_string())
            })
        }
        #[cfg(feature = "method-webs")]
        "webs" => did_hosting_common::method::webs::Webs::verify_continuation(
            did_id,
            previous.as_bytes(),
            next.as_bytes(),
        )
        .map_err(|e| match e {
            MethodError::HistoryRewrite(_) => {
                AppError::validation(ValidationKind::HistoryRewrite, e.to_string())
            }
            e => AppError::invalid(e.to_string()),
        }),
        other => {
            let _ = did_id;
            Err(cannot_verify(other))
        }
    }
}

/// The refusal for a log of a method this edge does not host from a sync.
fn cannot_verify(method: &str) -> crate::error::AppError {
    crate::error::AppError::invalid(format!("this server cannot verify {method} logs"))
}

/// The furthest history an edge has served for one DID identity, kept under
/// `hw:id:{identity}` after the DID is deleted so a re-publish cannot roll it
/// back.
///
/// For did:webvh it is compact: the version id of every entry served, and
/// whether one of them deactivated the DID. A version id (`{n}-{hash}`) hashes
/// its entry together with the previous version id, so in a verified chain
/// equal ids at a position mean an identical prefix — the comparison a full
/// copy of the log was kept for, at a few dozen bytes per entry. A did:webs
/// key event log is compared by its controller's own continuation rules
/// (`Webs::verify_continuation`), which need the stream, so its mark keeps
/// the stream.
///
/// Rows written before this format held the whole log as bare text; they are
/// read as the mark that log implies, and rewritten at boot by
/// [`migrate_high_water_marks`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HighWaterMark {
    /// The format, `1`. A legacy row (a bare log) carries no such member,
    /// which is how the two are told apart.
    hw_mark: u8,
    /// did:webvh: every served entry's `versionId`, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    version_ids: Vec<String>,
    /// did:webvh: an entry served deactivated the DID; nothing may follow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    deactivated: bool,
    /// did:webs: the key event log served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log: Option<String>,
}

const HIGH_WATER_MARK_FORMAT: u8 = 1;

/// A webvh log's entries' version ids and whether any entry deactivates.
fn webvh_history(log: &str) -> Result<(Vec<String>, bool), crate::error::AppError> {
    let mut ids = Vec::new();
    let mut deactivated = false;
    for line in log.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let entry: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| crate::error::AppError::invalid(format!("unreadable log entry: {e}")))?;
        let id = entry
            .get("versionId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::error::AppError::invalid("a log entry has no versionId"))?;
        ids.push(id.to_string());
        deactivated |= entry
            .get("parameters")
            .and_then(|p| p.get("deactivated"))
            .and_then(|d| d.as_bool())
            .unwrap_or(false);
    }
    Ok((ids, deactivated))
}

impl HighWaterMark {
    /// The mark of a verified `log` of `method`.
    pub(crate) fn of_log(method: &str, log: &str) -> Result<Self, crate::error::AppError> {
        Ok(match method {
            "webvh" => {
                let (version_ids, deactivated) = webvh_history(log)?;
                Self {
                    hw_mark: HIGH_WATER_MARK_FORMAT,
                    version_ids,
                    deactivated,
                    log: None,
                }
            }
            _ => Self {
                hw_mark: HIGH_WATER_MARK_FORMAT,
                version_ids: Vec::new(),
                deactivated: false,
                log: Some(log.to_string()),
            },
        })
    }

    /// A stored row: a mark, or a legacy row holding the log itself.
    pub(crate) fn parse(method: &str, bytes: &[u8]) -> Result<Self, crate::error::AppError> {
        match serde_json::from_slice::<Self>(bytes) {
            Ok(mark) if mark.hw_mark == HIGH_WATER_MARK_FORMAT => Ok(mark),
            _ => {
                let log = String::from_utf8_lossy(bytes);
                // A legacy log this cannot condense is compared as the log.
                Ok(Self::of_log(method, &log).unwrap_or_else(|_| Self {
                    hw_mark: HIGH_WATER_MARK_FORMAT,
                    version_ids: Vec::new(),
                    deactivated: false,
                    log: Some(log.into_owned()),
                }))
            }
        }
    }

    /// Whether `bytes` is a row in this format (not a legacy log).
    pub(crate) fn is_current(bytes: &[u8]) -> bool {
        serde_json::from_slice::<Self>(bytes).is_ok_and(|m| m.hw_mark == HIGH_WATER_MARK_FORMAT)
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a high-water mark serialises")
    }

    /// Whether `next`, a verified log of the same DID, extends the history
    /// this mark records: [`verify_extends`]'s rule, on the mark.
    pub(crate) fn admits(
        &self,
        method: &str,
        did_id: &str,
        next: &str,
    ) -> Result<(), crate::error::AppError> {
        use crate::error::{AppError, ValidationKind};
        use did_hosting_common::did_ops::LogExtendError;
        if let Some(log) = &self.log {
            return verify_extends(method, did_id, log, next);
        }
        let (next_ids, _) = webvh_history(next)?;
        let held = self.version_ids.len();
        if next_ids.len() < held || next_ids[..held] != self.version_ids[..] {
            let e = LogExtendError::HistoryRewrite {
                held,
                received: next_ids.len(),
            };
            return Err(AppError::validation(
                ValidationKind::HistoryRewrite,
                e.to_string(),
            ));
        }
        if self.deactivated && next_ids.len() != held {
            return Err(AppError::validation(
                ValidationKind::Deactivated,
                LogExtendError::Deactivated.to_string(),
            ));
        }
        Ok(())
    }

    /// Whether this mark records a history that extends (or equals) `older`'s.
    fn extends(&self, older: &Self, method: &str, did_id: &str) -> bool {
        match (&self.log, &older.log) {
            (Some(this), Some(that)) => verify_extends(method, did_id, that, this).is_ok(),
            (None, None) => {
                let held = older.version_ids.len();
                self.version_ids.len() >= held
                    && self.version_ids[..held] == older.version_ids[..]
                    && !(older.deactivated && self.version_ids.len() != held)
            }
            _ => false,
        }
    }
}

/// For a restore: what to do with a high-water mark `incoming` (either
/// format) for `identity` that a backup carries. `true` when it may be
/// written (nothing is held for that identity, or it extends what is held);
/// `false` when what is held already extends it, so the held mark is kept.
/// Two marks that diverge are refused: a restore never moves a mark back or
/// onto another history.
pub(crate) async fn high_water_to_restore(
    dids_ks: &KeyspaceHandle,
    identity: &str,
    incoming: &[u8],
) -> Result<bool, crate::error::AppError> {
    let Some(held) = dids_ks.get_raw(high_water_identity_key(identity)).await? else {
        return Ok(true);
    };
    // A webs identity is its identifier; a webvh identity is the bare SCID.
    let method = if identity.starts_with("did:webs:") {
        "webs"
    } else {
        "webvh"
    };
    if !has_history(method) {
        // This build cannot compare the two: keep the held one.
        return Ok(false);
    }
    let held = HighWaterMark::parse(method, &held)?;
    let incoming = HighWaterMark::parse(method, incoming)?;
    if incoming.extends(&held, method, identity) {
        return Ok(true);
    }
    if held.extends(&incoming, method, identity) {
        return Ok(false);
    }
    Err(crate::error::AppError::invalid(format!(
        "the backup's history for {identity} diverges from the one this store has served"
    )))
}

/// Record, in `batch`, the high-water marks for a log that passed
/// [`verify_history`]: the furthest history served for the DID's `identity`
/// (a compact [`HighWaterMark`]), and which DID (and method) the slot last
/// held. Never removed — not by `sync/delete`, not by a domain purge, not by
/// a local delete — so a delete followed by a re-publish cannot roll either
/// back: they are the tombstones that hold a deleted DID's history, a few
/// hundred bytes each.
pub(crate) fn stage_high_water(
    batch: &mut crate::store::WriteBatch,
    dids_ks: &KeyspaceHandle,
    identity: &str,
    mnemonic: &str,
    did_id: &str,
    method: &str,
    log_content: &str,
) -> Result<(), crate::error::AppError> {
    batch.insert_raw(
        dids_ks,
        high_water_identity_key(identity),
        HighWaterMark::of_log(method, log_content)?.to_bytes(),
    );
    batch.insert(
        dids_ks,
        high_water_slot_key(mnemonic),
        &SlotHighWater {
            identity: identity.to_string(),
            did_id: did_id.to_string(),
            method: method.to_string(),
        },
    )?;
    Ok(())
}

/// Rewrite every high-water row still holding a whole log (written before
/// the compact `HighWaterMark`) as the mark that log implies. Idempotent;
/// run at boot. Returns how many rows were rewritten.
pub async fn migrate_high_water_marks(
    dids_ks: &KeyspaceHandle,
    store: &Store,
) -> Result<usize, crate::error::AppError> {
    let mut rewritten = 0;
    let mut pages = dids_ks.walk(HIGH_WATER_IDENTITY_PREFIX, 64);
    while let Some(rows) = pages.next_page().await? {
        let mut batch = store.batch();
        let mut staged = 0;
        for (key, value) in rows {
            if HighWaterMark::is_current(&value) {
                continue;
            }
            let identity =
                String::from_utf8_lossy(&key[HIGH_WATER_IDENTITY_PREFIX.len()..]).into_owned();
            let method = if identity.starts_with("did:webs:") {
                "webs"
            } else {
                "webvh"
            };
            match HighWaterMark::of_log(method, &String::from_utf8_lossy(&value)) {
                Ok(mark) => {
                    batch.insert_raw(dids_ks, key, mark.to_bytes());
                    staged += 1;
                }
                // Left as it is: still read (and refused against) as a log.
                Err(e) => warn!(%identity, error = %e, "high-water row not migrated"),
            }
        }
        if staged > 0 {
            batch.commit_in_parts().await?;
            rewritten += staged;
        }
    }
    Ok(rewritten)
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

/// Step 1 of a sync's verification (see [`verify_chain`]): the identifier is the log's, and it resolves
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
                return Err(AppError::invalid(format!(
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
        return Err(AppError::invalid(
            "this server has no public URL or assigned domain to bind synced DIDs to",
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
        "webs" => {
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
        other => return Err(cannot_verify(other)),
    };
    if !bound {
        return Err(AppError::invalid(format!(
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
    caches: &crate::cache::ResolutionCaches,
    locks: &PathLocks,
    public_url: Option<&str>,
) -> Result<SyncApplied, crate::error::AppError> {
    use did_hosting_common::server::auth::session::now_epoch;

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
    // Only a method whose history this edge checks is accepted: a `did:web`
    // document (or anything not recognisably a DID log) is refused rather
    // than stored unchecked under a tag no resolver here serves.
    let synced_method =
        match did_hosting_common::method::detect_method(update.log_content.as_bytes()) {
            Some("webvh") => "webvh",
            #[cfg(feature = "method-webs")]
            Some("webs") => "webs",
            Some(other) => return Err(cannot_verify(other)),
            None => {
                return Err(crate::error::AppError::invalid(
                    "the synced log is not a DID log of any method this server hosts",
                ));
            }
        };

    // Nothing to write when this edge already holds exactly this state: the
    // same log, the same witness proofs and the same disabled flag. Checked
    // first, without a lock and without verifying anything: what is held was
    // verified when it was written, and answering `unchanged` writes nothing.
    // (Checked again under the lock below, before writing.)
    if holds_exactly(dids_ks, update).await?.is_some() {
        let _slot_guard = locks.guard(&slot_lock_key(&update.mnemonic)).await;
        let _identity_guard = locks
            .guard(&identity_lock_key(&history_identity(
                &update.did_id,
                synced_method,
            )?))
            .await;
        if let Some(prev) = holds_exactly(dids_ks, update).await? {
            reassert_agent_names(dids_ks, store, &prev).await?;
            return Ok(SyncApplied::Unchanged);
        }
    }

    // The edge verifies what it is asked to serve itself, rather than trusting
    // the control plane to have done so: a compromised or buggy control plane
    // must not be able to make an edge serve a log the DID's own keys never
    // authorised, an old version of one, or one filed under another slot.
    // See `verify_chain` for the full list. Binding and chain first, with no
    // lock held — the chain (every proof in the log) on a blocking thread —
    // then the history, under the slot's lock, against what is held.
    verify_binding(store, update, synced_method, public_url).await?;
    let chain = {
        let update = update.clone();
        let method = synced_method.to_string();
        tokio::task::spawn_blocking(move || verify_chain(&update, &method))
            .await
            .map_err(|e| {
                crate::error::AppError::Internal(format!("log verification panicked: {e}"))
            })??
    };
    #[cfg(feature = "method-webs")]
    let webs_document = chain.webs_document;
    #[cfg(not(feature = "method-webs"))]
    let _ = chain;

    // The slot's lock, then the DID's: everything from here reads what this
    // edge holds and writes on that basis.
    let _slot_guard = locks.guard(&slot_lock_key(&update.mnemonic)).await;
    let _identity_guard = locks
        .guard(&identity_lock_key(&history_identity(
            &update.did_id,
            synced_method,
        )?))
        .await;
    if let Some(prev) = holds_exactly(dids_ks, update).await? {
        // Nothing to write for the slot itself, but its name-index entries
        // are re-asserted: an index entry lost to an earlier bug (or any
        // other way) must be repairable by a re-sync, and a re-sync of an
        // unchanged log only ever lands here.
        reassert_agent_names(dids_ks, store, &prev).await?;
        return Ok(SyncApplied::Unchanged);
    }
    let identity = verify_history(
        dids_ks,
        &update.mnemonic,
        &update.did_id,
        &update.log_content,
        synced_method,
    )
    .await?;
    let previous: Option<DidRecord> = dids_ks.get(did_key(&update.mnemonic)).await?;

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
        // The source's disabled state travels with the content: a disabled
        // slot stops resolving here until an update carries `false`.
        disabled: update.disabled,
        disabled_by_admin: false,
        deleted_at: None,

        // Tagged from the content, not from the push: the host the DID
        // identifier names. Every method needs it from the start — a domain
        // purge (`replica/domain/purge`, or the unassignment grace sweep)
        // selects the slots it deletes by it, so an untagged slot would
        // outlive the purge of its domain; and a did:webs identifier, with the
        // document derived from it on every read, cannot be rebuilt without it.
        method: synced_method.to_string(),
        domain: did_host.clone(),

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

    // `previous` (read above) is the record being replaced, so stale
    // name-index entries can be retired in the same batch. Without this, a name
    // removed from `alsoKnownAs` would keep resolving from a leftover index
    // entry — the document would stop claiming it while the edge kept serving
    // it, which is precisely the state Layer-1 exists to prevent.

    let mut batch = store.batch();
    batch.insert(dids_ks, did_key(&update.mnemonic), &record)?;

    // An index entry is retired only while it still names *this* slot: a name
    // that moved from this DID to another may already point at the new holder
    // (its update applied first — an outbox retry, or batch ordering), and
    // removing that would make `/@name` 404 here with nothing to repair it.
    if let Some(prev) = previous.as_ref() {
        let prev_host = prev
            .did_id
            .as_deref()
            .and_then(|d| extract_did_host(d).ok())
            .unwrap_or_else(|| did_host.clone());
        for old in &prev.agent_names {
            if !record.agent_names.iter().any(|n| n.name == old.name) {
                let key = agent_name_key(&prev_host, &old.name);
                if index_names_slot(dids_ks, &key, &update.mnemonic).await? {
                    batch.remove(dids_ks, key);
                }
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
    // An absent `witnessContent` means the slot holds no witness proofs — never
    // "unchanged" — so any held proofs go.
    match update.witness_content {
        Some(ref witness) => batch.insert_raw(
            dids_ks,
            content_witness_key(&update.mnemonic),
            witness.as_bytes().to_vec(),
        ),
        None => batch.remove(dids_ks, content_witness_key(&update.mnemonic)),
    }
    // High-water marks: the furthest history this edge has served for this DID
    // and for this slot (see `stage_high_water`).
    stage_high_water(
        &mut batch,
        dids_ks,
        &identity,
        &update.mnemonic,
        &update.did_id,
        synced_method,
        &update.log_content,
    )?;
    batch.commit().await?;

    caches.forget_did(&update.mnemonic);

    info!(
        mnemonic = %update.mnemonic,
        did = %update.did_id,
        disabled = update.disabled,
        "applied DID sync update from control plane"
    );

    Ok(SyncApplied::Applied)
}

/// The record this edge holds for `update`'s slot when it already holds
/// exactly `update`'s state: the same DID, log, witness proofs and disabled
/// flag.
async fn holds_exactly(
    dids_ks: &KeyspaceHandle,
    update: &DidSyncUpdate,
) -> Result<Option<DidRecord>, crate::error::AppError> {
    let Some(prev) = dids_ks.get::<DidRecord>(did_key(&update.mnemonic)).await? else {
        return Ok(None);
    };
    let exact = prev.did_id.as_deref() == Some(update.did_id.as_str())
        && prev.disabled == update.disabled
        && dids_ks
            .get_raw(content_log_key(&update.mnemonic))
            .await?
            .is_some_and(|held| held == update.log_content.as_bytes())
        && dids_ks
            .get_raw(content_witness_key(&update.mnemonic))
            .await?
            .map(|w| String::from_utf8_lossy(&w).into_owned())
            == update.witness_content;
    Ok(exact.then_some(prev))
}

/// Whether the agent-name index entry at `key` points at `mnemonic`.
pub(crate) async fn index_names_slot(
    dids_ks: &KeyspaceHandle,
    key: &str,
    mnemonic: &str,
) -> Result<bool, crate::error::AppError> {
    Ok(dids_ks
        .get_raw(key.to_string())
        .await?
        .is_some_and(|held| held == mnemonic.as_bytes()))
}

/// Write back any of `record`'s own agent-name index entries that have gone
/// missing, or that point at a slot whose record no longer claims the name
/// (a leftover). An entry naming another slot that does claim the name is
/// left alone: two documents claiming one name is the control plane's to
/// settle, never an edge's.
async fn reassert_agent_names(
    dids_ks: &KeyspaceHandle,
    store: &Store,
    record: &DidRecord,
) -> Result<(), crate::error::AppError> {
    if record.agent_names.is_empty() {
        return Ok(());
    }
    let host = record
        .did_id
        .as_deref()
        .and_then(|d| extract_did_host(d).ok())
        .unwrap_or_default();
    let mut batch = store.batch();
    let mut repaired = Vec::new();
    for entry in &record.agent_names {
        let key = agent_name_key(&host, &entry.name);
        let stale = match dids_ks.get_raw(key.clone()).await? {
            None => true,
            Some(held) if held == record.mnemonic.as_bytes() => false,
            Some(held) => {
                let other = String::from_utf8_lossy(&held).into_owned();
                !dids_ks
                    .get::<DidRecord>(did_key(&other))
                    .await?
                    .is_some_and(|r| r.agent_names.iter().any(|n| n.name == entry.name))
            }
        };
        if stale {
            batch.insert_raw(dids_ks, key, record.mnemonic.as_bytes().to_vec());
            repaired.push(entry.name.clone());
        }
    }
    if !repaired.is_empty() {
        batch.commit().await?;
        warn!(
            mnemonic = %record.mnemonic,
            names = ?repaired,
            "re-asserted agent-name index entries the edge had lost"
        );
    }
    Ok(())
}

/// What [`apply_single_update`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncApplied {
    /// The edge now holds and serves exactly the submitted state.
    Applied,
    /// It already held that state; nothing was written.
    Unchanged,
}

#[cfg(test)]
mod high_water_tests {
    use super::*;
    use crate::bootstrap::test_logs;
    use crate::error::ValidationKind;
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::store::KS_DIDS;

    async fn store() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open store");
        let ks = store.keyspace(KS_DIDS).unwrap();
        (dir, store, ks)
    }

    #[tokio::test]
    async fn a_mark_is_compact_and_admits_only_extensions() {
        let logs = test_logs::versions("example.com", "alice", 3).await;
        let did = did_hosting_common::did_ops::extract_did_id(&logs[0]).unwrap();
        let mark = HighWaterMark::of_log("webvh", &logs[1]).unwrap();
        assert_eq!(mark.version_ids.len(), 2);
        assert!(mark.log.is_none(), "a webvh mark keeps no copy of the log");
        assert!(
            mark.to_bytes().len() * 4 < logs[1].len(),
            "{} bytes for a {}-byte log",
            mark.to_bytes().len(),
            logs[1].len()
        );
        // Itself and anything after it; never anything before it.
        mark.admits("webvh", &did, &logs[1]).unwrap();
        mark.admits("webvh", &did, &logs[2]).unwrap();
        let err = mark.admits("webvh", &did, &logs[0]).unwrap_err();
        assert_eq!(err.validation_kind(), ValidationKind::HistoryRewrite);
        // Another DID's history at the same length is a fork.
        let other = test_logs::versions("example.com", "alice", 2).await;
        let err = mark.admits("webvh", &did, &other[1]).unwrap_err();
        assert_eq!(err.validation_kind(), ValidationKind::HistoryRewrite);
        // Round-trips, and is told apart from a legacy row.
        assert!(HighWaterMark::is_current(&mark.to_bytes()));
        assert!(!HighWaterMark::is_current(logs[0].as_bytes()));
        assert_eq!(
            HighWaterMark::parse("webvh", &mark.to_bytes()).unwrap(),
            mark
        );
    }

    #[tokio::test]
    async fn a_legacy_full_log_mark_is_honoured_then_migrated() {
        let (_dir, store, ks) = store().await;
        let logs = test_logs::versions("example.com", "alice", 3).await;
        let did = did_hosting_common::did_ops::extract_did_id(&logs[0]).unwrap();
        let scid = webvh_scid(&did).unwrap();
        // A row written before compact marks: the whole v2 log.
        ks.insert_raw(high_water_identity_key(&scid), logs[1].as_bytes().to_vec())
            .await
            .unwrap();

        let rollback = |log: String| {
            let ks = ks.clone();
            let did = did.clone();
            async move { verify_history(&ks, "alice", &did, &log, "webvh").await }
        };
        assert!(
            rollback(logs[0].clone()).await.is_err(),
            "legacy mark refuses a rollback"
        );

        assert_eq!(migrate_high_water_marks(&ks, &store).await.unwrap(), 1);
        let row = ks
            .get_raw(high_water_identity_key(&scid))
            .await
            .unwrap()
            .unwrap();
        assert!(HighWaterMark::is_current(&row));
        assert_eq!(
            HighWaterMark::parse("webvh", &row).unwrap(),
            HighWaterMark::of_log("webvh", &logs[1]).unwrap()
        );
        assert!(rollback(logs[0].clone()).await.is_err(), "still refused");
        assert_eq!(
            rollback(logs[2].clone()).await.unwrap(),
            scid,
            "an extension is accepted"
        );
        assert_eq!(
            migrate_high_water_marks(&ks, &store).await.unwrap(),
            0,
            "idempotent"
        );
    }

    #[tokio::test]
    async fn a_restore_compares_marks_of_either_format() {
        let (_dir, _store, ks) = store().await;
        let logs = test_logs::versions("example.com", "alice", 3).await;
        let did = did_hosting_common::did_ops::extract_did_id(&logs[0]).unwrap();
        let scid = webvh_scid(&did).unwrap();
        ks.insert_raw(
            high_water_identity_key(&scid),
            HighWaterMark::of_log("webvh", &logs[1]).unwrap().to_bytes(),
        )
        .await
        .unwrap();
        // A backup's legacy row further on is written; one behind is not.
        assert!(
            high_water_to_restore(&ks, &scid, logs[2].as_bytes())
                .await
                .unwrap()
        );
        assert!(
            !high_water_to_restore(&ks, &scid, logs[0].as_bytes())
                .await
                .unwrap()
        );
        let fork = test_logs::versions("example.com", "alice", 2).await;
        assert!(
            high_water_to_restore(&ks, &scid, fork[1].as_bytes())
                .await
                .is_err()
        );
    }
}

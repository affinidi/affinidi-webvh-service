//! The agent-name registry: reconciling it against a published document
//! ([`reconcile_agent_names`]), the per-name locks, the declarative
//! `agent-name/update` and `agent-name/remove` verbs, and the availability and
//! listing reads.

use did_hosting_common::did_ops::{
    AgentNameEntry, DidRecord, agent_name_key, content_log_key, did_key,
};
use did_hosting_common::server::agent_name_index;
use did_hosting_common::server::error::AgentNameError;
use did_hosting_common::server::mnemonic::{validate_agent_name, validate_agent_name_binding};
use tracing::{debug, info, warn};

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;

use super::quota::hold_size_quota;
use super::register::prepare_republish;
use super::{
    ensure_slot_domain_matches, get_authorized_record, invalidate_cached_content, stage_index,
    validate_slot_mnemonic, validate_slot_path_shape,
};

/// Publish (upload) a did.jsonl log for an existing DID slot.
/// Reconcile the authoritative agent-name registry against a just-published
/// document, returning the index changes to fold into the commit batch:
/// `(names to point at this DID, names to retire)`.
///
/// The control plane is the source of record for DID hosting — a name is
/// *served* iff the signed document claims it via `alsoKnownAs`. So a plain
/// publish (the VTA editing the document) keeps the registry in step:
/// - each name the document claims → asserted **enabled** (created-at preserved
///   if it already existed), and its index points here;
/// - a previously-enabled name the document no longer claims → **released**
///   (dropped from the registry, its index retired);
/// - a **parked** (`enabled == false`) entry the document doesn't claim →
///   **kept**, because parking deliberately drops the name from the document
///   while holding the reservation. A parked name that reappears in the
///   document is resumed (becomes enabled).
///
/// The explicit agent-name ops (`set`/`enable`/`disable`/`remove`) manage the
/// registry directly and don't go through here; this is only the plain-publish
/// path, which previously left the registry untouched — so a name bound by
/// editing `alsoKnownAs` was never registered, and later parking it failed.
///
/// # The preconditions are not optional here
///
/// Reconciling is not the same as trusting. `extract_agent_names` proves only
/// that an `alsoKnownAs` entry parses as an agent name on *this* domain — it
/// does not check the name is claimable, and the `agent-names` grammar is far
/// laxer than [`validate_agent_name`]'s. So this path applies the same
/// preconditions the explicit `set` verb does, and for the same reasons:
///
/// - **Reserved names are refused.** `@admin` / `@support` / `@security` are a
///   ready-made phishing primitive; `set` rejects them, and a publish that
///   claims one must not be the way around that.
/// - **The community name is refused for every slot but the root DID.**
///   `{domain}/@` is the domain's own identity, so a tenant putting it in its
///   `alsoKnownAs` is the sharpest form of the same attack. See
///   [`validate_agent_name_binding`].
/// - **A name held by another DID is refused.** Otherwise a plain publish
///   silently repoints the index at the publisher, and Layer-1 verification
///   cannot detect it: after the hijack the document genuinely claims the name
///   and the index genuinely points at the hijacker, so a resolver's
///   `alsoKnownAs` round-trip passes. The victim's name just stops resolving.
///
/// The invariant both rules exist to hold: **a name only ever changes owner
/// through an explicit `remove` by its current holder.**
///
/// A claimed name that is merely *malformed* under our grammar (uppercase, too
/// short, dotted — all of which `AgentName::parse` accepts) is skipped rather
/// than refused. It is unserveable anyway (the resolve route re-validates and
/// 404s), so registering it would only add an unreachable index entry, and
/// failing the publish over an `alsoKnownAs` entry that was never an agent name
/// in our sense would break unrelated documents.
///
/// Callers must hold `state.path_locks.guard(mnemonic)`, and must keep the
/// returned [`AgentNameLocks`] alive until their batch commits. The slot lock
/// alone does not serialise two *different* slots claiming the same name, so
/// this function also takes the per-name lock of every name it checks or
/// retires (see [`lock_agent_names`]); the collision check and the index write
/// it authorises are one critical section only while those are held.
///
/// `claims` is the set of names the published document asserts on `domain`,
/// already extracted by the publishing method — `Publication::agent_names`.
/// Taking the extracted list rather than the raw content is what lets this
/// stay method-agnostic: the names come from `alsoKnownAs` either way, but
/// only the method knows where its current document lives (a webvh log entry's
/// `state`, a did:web document as published, or the document a did:webs key
/// event log verified into). The Layer-1 rule — a node cannot serve a name the
/// DID does not claim — is unchanged; it is enforced one step earlier.
pub(super) async fn reconcile_agent_names(
    state: &AppState,
    record: &mut DidRecord,
    mnemonic: &str,
    claims: &[String],
    domain: &str,
    now: u64,
) -> Result<(Vec<String>, Vec<String>, AgentNameLocks), AppError> {
    let mut candidates = Vec::new();
    for name in claims.iter().cloned() {
        match validate_agent_name_binding(&name, mnemonic) {
            Ok(()) => {}
            // Reserved is a refusal, not a skip — see above. This also covers a
            // non-root slot claiming the community name `{domain}/@`, which
            // `validate_agent_name_binding` reports as `Reserved`.
            Err(AppError::AgentName(AgentNameError::Reserved)) => {
                warn!(
                    mnemonic = %mnemonic,
                    name = %name,
                    "publish claims a reserved agent name; refusing"
                );
                return Err(AgentNameError::Reserved.into());
            }
            // Unserveable, so not worth failing an otherwise valid publish.
            Err(_) => {
                debug!(
                    mnemonic = %mnemonic,
                    name = %name,
                    "alsoKnownAs entry is not a valid agent name; not registering"
                );
                continue;
            }
        }
        candidates.push(name);
    }

    // Every name this call may write or retire: the valid claims, plus the
    // names the record currently serves (candidates for release).
    let locks = lock_agent_names(
        state,
        candidates
            .iter()
            .map(String::as_str)
            .chain(
                record
                    .agent_names
                    .iter()
                    .filter(|e| e.enabled)
                    .map(|e| e.name.as_str()),
            )
            .map(|name| agent_name_key(domain, name)),
    )
    .await;

    let mut claimed = Vec::new();
    for name in candidates {
        // Held by another DID on this domain? Refuse the whole publish. The
        // caller controls their own document, so the remedy is theirs: drop
        // the claim and republish. Nobody else can put a document into this
        // state, so this cannot be used to wedge someone's key rotation.
        if agent_name_held_by_other(state, domain, &name, mnemonic).await? {
            warn!(
                mnemonic = %mnemonic,
                name = %name,
                "publish claims an agent name held by another DID; refusing"
            );
            return Err(AgentNameError::Taken.into());
        }

        claimed.push(name);
    }

    let is_claimed = |n: &str| claimed.iter().any(|c| c == n);

    // Names this DID served and no longer claims. Retiring the index entry is
    // only correct while it still points here — a stale registry entry left by
    // an earlier hijack must not delete the current holder's index.
    let mut released = Vec::new();
    for entry in record.agent_names.iter().filter(|e| e.enabled) {
        if is_claimed(&entry.name) {
            continue;
        }
        let ours = state
            .dids_ks
            .get_raw(agent_name_key(domain, &entry.name))
            .await?
            .is_some_and(|bytes| bytes == mnemonic.as_bytes());
        if ours {
            released.push(entry.name.clone());
        }
    }

    let mut next: Vec<AgentNameEntry> = record
        .agent_names
        .iter()
        .filter(|e| !e.enabled && !is_claimed(&e.name))
        .cloned()
        .collect();
    for name in &claimed {
        let created_at = record
            .agent_names
            .iter()
            .find(|e| &e.name == name)
            .map(|e| e.created_at)
            .unwrap_or(now);
        next.push(AgentNameEntry {
            name: name.clone(),
            enabled: true,
            created_at,
        });
    }
    record.agent_names = next;

    Ok((claimed, released, locks))
}

/// Per-name locks held across an agent-name check and the commit it
/// authorises. Dropping it releases them.
pub(crate) type AgentNameLocks = Vec<did_hosting_common::server::path_locks::PathGuard>;

/// Take the per-name write lock for each agent-name index key in `index_keys`.
///
/// The index key `name:{domain}:{name}` is shared by every slot on the
/// domain, so a lock on the claiming slot does not stop a second slot from
/// passing the same "is it free?" check at the same moment. Every code path
/// that reads the index to decide a write — claiming, retiring, deleting —
/// takes these locks first.
///
/// Ordering, to stay deadlock-free: the slot lock (`path_locks.guard(mnemonic)`)
/// is always taken first, and the name locks after it in sorted order. Nothing
/// takes a slot lock while holding a name lock.
///
/// The keys live in the same `PathLocks` map as slot paths
/// ([`agent_name_index::lock_key`]).
pub(crate) async fn lock_agent_names(
    state: &AppState,
    index_keys: impl IntoIterator<Item = String>,
) -> AgentNameLocks {
    agent_name_index::lock_names(&state.path_locks, index_keys).await
}

/// Whether the index entry for `name` on `domain` belongs to a slot other
/// than `mnemonic`. The caller holds the name's lock.
///
/// An entry that points at a slot which no longer exists, or whose record no
/// longer lists the name, is a leftover — the record and its index entry are
/// always written in one batch, so a live holder lists the name. Such an entry
/// does not hold the name.
pub(super) async fn agent_name_held_by_other(
    state: &AppState,
    domain: &str,
    name: &str,
    mnemonic: &str,
) -> Result<bool, AppError> {
    let Some(holder) = state.dids_ks.get_raw(agent_name_key(domain, name)).await? else {
        return Ok(false);
    };
    if holder == mnemonic.as_bytes() {
        return Ok(false);
    }
    let Ok(holder) = String::from_utf8(holder) else {
        // Unreadable: keep treating the name as taken.
        return Ok(true);
    };
    let record: Option<DidRecord> = state.dids_ks.get(did_key(&holder)).await?;
    Ok(record.is_some_and(|r| r.agent_names.iter().any(|e| e.name == name)))
}

// ---------------------------------------------------------------------------
// Agent names
// ---------------------------------------------------------------------------

/// Which agent-name operation a request carries. Selects the `alsoKnownAs`
/// direction the submitted document must satisfy and the registry mutation
/// applied on commit.
///
/// `Activate` / `Park` are the two values of the declarative
/// `did-management/agent-name/update/0.1` `state` field (`active` /
/// `parked`); `Remove` is the separate destructive
/// `did-management/agent-name/remove/0.1` task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AgentNameOp {
    /// `state: active` — bind a free name, refresh an existing binding, or
    /// resume a parked one; the document MUST claim the name.
    Activate,
    /// Release a name for anyone to reclaim; the document MUST no longer claim
    /// it. Destructive.
    Remove,
    /// `state: parked` — kept reserved, but stops resolving; the document MUST
    /// no longer claim it.
    Park,
}

/// Desired binding state carried by `did-management/agent-name/update/0.1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AgentNameState {
    Active,
    Parked,
}

impl AgentNameOp {
    /// Whether the submitted document must claim the name for this operation.
    ///
    /// `active` makes a name resolvable, so the signed document has to
    /// claim it; `remove`/`parked` take it out of service, so the document
    /// must *not* — this is what keeps the served state and the signed
    /// document from ever diverging (the spec's Layer-1 invariant).
    fn requires_claim(self) -> bool {
        matches!(self, AgentNameOp::Activate)
    }
}

/// Set the binding state of an agent name per
/// `did-management/agent-name/update/0.1` — the declarative replacement for
/// the retired set / enable / disable verb trio.
///
/// `Active` binds a free name (`example.com/@alice`), refreshes an existing
/// binding, or resumes a parked one; the submitted signed document
/// (`did_log`, the spec's `didData`) must claim the name via `alsoKnownAs`.
/// `Parked` stops the name resolving while keeping its reservation; the
/// document must no longer claim it. Requesting the state the binding is
/// already in is an idempotent refresh, per the spec.
pub async fn update_agent_name(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    request_domain: Option<&str>,
    desired: AgentNameState,
) -> Result<DidRecord, AppError> {
    let op = match desired {
        AgentNameState::Active => AgentNameOp::Activate,
        AgentNameState::Parked => AgentNameOp::Park,
    };
    apply_agent_name_op(auth, state, mnemonic, name, did_log, request_domain, op).await
}

/// Release an agent name so anyone may reclaim it. The submitted document must
/// no longer claim the name via `alsoKnownAs`. Destructive. This service does
/// not require a stepped-up (`aal2`) session for it, here or at the
/// Trust-Task surface: the owner (a VTA) is expected to gate it behind its
/// own operator step-up before signing the request.
/// See `did-management/agent-name/remove`.
pub async fn remove_agent_name(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    request_domain: Option<&str>,
) -> Result<DidRecord, AppError> {
    apply_agent_name_op(
        auth,
        state,
        mnemonic,
        name,
        did_log,
        request_domain,
        AgentNameOp::Remove,
    )
    .await
}

/// The name-index side-effect an agent-name op folds into its commit batch.
pub(super) enum IndexWrite {
    /// Point `name:{domain}:{name}` at this mnemonic.
    Insert,
    /// Retire the index entry — the name is released.
    Remove,
    /// Leave the index untouched — a parked name stays reserved.
    Keep,
}

/// The shared engine behind the four agent-name verbs.
///
/// Authorizes the caller and publishes the submitted document as a new DID
/// version (via [`prepare_republish`]), enforces the verb's `alsoKnownAs`
/// gate, applies the verb's registry precondition + mutation, and commits the
/// new log, the updated record, and the name-index change in **one batch** —
/// so a name and the document that claims it can never disagree, even across a
/// crash.
#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_agent_name_op(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    request_domain: Option<&str>,
    op: AgentNameOp,
) -> Result<DidRecord, AppError> {
    use crate::auth::session::now_epoch;

    // Canonical local part. `validate_agent_name_binding` enforces the grammar,
    // rejects reserved names (`@admin`, `@support`, …), and refuses the
    // community name (`/@`) for any slot but the root DID — all before any
    // lookup.
    validate_agent_name_binding(name, mnemonic)?;
    let name = name.strip_prefix('@').unwrap_or(name).to_string();

    // Serialise the read-modify-write on this slot: the collision check, the
    // registry mutation, and the index write must not interleave with another
    // op on the same DID.
    validate_slot_path_shape(mnemonic)?;
    let slot_guard = state.path_locks.guard(mnemonic).await;

    // Authorize + verify the submitted document + advance the record. This
    // yields not_owner / invalid_did_data / unknown_domain exactly as a plain
    // publish would.
    let (mut record, domain, publication) =
        prepare_republish(auth, state, mnemonic, did_log, request_domain).await?;

    // The gate: does the submitted document claim the name on this domain?
    // The names come from the publishing method's own reading of
    // `alsoKnownAs`, canonicalised through the `agent-names` crate, so the
    // comparison is byte-identical to what a resolver will later do.
    let names = publication.agent_names(&domain);
    let claimed = names.iter().any(|n| n == &name);
    let quota_guard = hold_size_quota(state, auth, mnemonic, record.content_size).await?;
    if claimed != op.requires_claim() {
        return Err(AgentNameError::AlsoKnownAsMismatch.into());
    }

    let index_key = agent_name_key(&domain, &name);
    // The slot lock above does not cover the index entry, which every slot on
    // the domain shares: hold the name's own lock from the check to the commit.
    let name_locks = lock_agent_names(state, [index_key.clone()]).await;

    // Verb-specific precondition + registry mutation, yielding the index
    // side-effect to fold into the commit batch below.
    let index_write = match op {
        AgentNameOp::Activate => {
            // A name already bound to a *different* DID on this domain is
            // taken; the same DID re-activating is an idempotent refresh, and
            // a parked entry is resumed (upsert flips `enabled` back on).
            if agent_name_held_by_other(state, &domain, &name, mnemonic).await? {
                return Err(AgentNameError::Taken.into());
            }
            upsert_agent_name(&mut record.agent_names, &name, now_epoch());
            IndexWrite::Insert
        }
        AgentNameOp::Park => {
            let entry = record
                .agent_names
                .iter_mut()
                .find(|e| e.name == name)
                .ok_or(AgentNameError::NotFound)?;
            // Declarative: parking an already-parked name is an idempotent
            // refresh (the submitted document still republishes), not a
            // conflict — the spec has no already_disabled error class.
            entry.enabled = false;
            // Keep the index: a parked name stays reserved, so a later
            // `active` claim by another DID still sees it as taken. The
            // name's own `enabled` flag is what stops it resolving.
            IndexWrite::Keep
        }
        AgentNameOp::Remove => {
            let before = record.agent_names.len();
            record.agent_names.retain(|e| e.name != name);
            if record.agent_names.len() == before {
                return Err(AgentNameError::NotFound.into());
            }
            // Retire the index entry only while it points at this slot. A
            // registry entry this slot kept from an earlier double claim must
            // not delete the current holder's index.
            let ours = state
                .dids_ks
                .get_raw(index_key.clone())
                .await?
                .is_some_and(|bytes| bytes == mnemonic.as_bytes());
            if ours {
                IndexWrite::Remove
            } else {
                IndexWrite::Keep
            }
        }
    };

    // Commit the new document version, the updated record, and the name-index
    // change in one atomic batch — the guarantee the specification requires.
    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        did_log.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    match index_write {
        IndexWrite::Insert => {
            batch.insert_raw(&state.dids_ks, index_key, mnemonic.as_bytes().to_vec())
        }
        IndexWrite::Remove => batch.remove(&state.dids_ks, index_key),
        IndexWrite::Keep => {}
    }
    // Every update publishes a new version, so the edges need it — queued in
    // the same commit.
    let sync = crate::server_push::stage_did_sync(
        state,
        &mut batch,
        mnemonic,
        crate::server_push::DidChange::Published { log: did_log },
    )
    .await;
    let previous: Option<DidRecord> = state.dids_ks.get(did_key(mnemonic)).await?;
    let usage = stage_index(state, &mut batch, previous.as_ref(), Some(&record)).await?;
    batch.commit().await?;
    sync.finish(state).await;
    // As in `register_did_atomic`: not held across the identity check below.
    drop(name_locks);
    drop(slot_guard);
    invalidate_cached_content(state, mnemonic);
    drop(quota_guard);
    drop(usage);

    state.stats_collector.record_update(mnemonic);

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        name = %name,
        ?op,
        version = record.version_count,
        "agent name updated on control plane"
    );

    // Same rationale as `register_did_atomic`: a new document version was committed,
    // so if it was the service's own DID, re-resolve and rotate if needed.
    crate::identity_rotation::on_did_published(state, mnemonic).await;

    Ok(record)
}

/// Add a name to the registry, or refresh an existing entry to enabled.
pub(super) fn upsert_agent_name(names: &mut Vec<AgentNameEntry>, name: &str, now: u64) {
    if let Some(entry) = names.iter_mut().find(|e| e.name == name) {
        entry.enabled = true;
    } else {
        names.push(AgentNameEntry {
            name: name.to_string(),
            enabled: true,
            created_at: now,
        });
    }
}

/// Availability of an agent name on a hosting domain.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentNameAvailability {
    pub name: String,
    pub domain: String,
    /// Free to claim: neither reserved nor already bound on this domain.
    pub available: bool,
    /// On the host's reserved list (`@admin`, `@support`, …) — unavailable but
    /// a well-formed name, distinct from a grammar error (which is a 400).
    pub reserved: bool,
}

/// Check whether an agent name can be claimed on `domain`.
///
/// A reserved name is reported as `available: false, reserved: true` rather
/// than an error, so a UI can explain *why*; a grammatically invalid name is a
/// client error (`AppError::Validation`). Availability is domain-scoped: the
/// same name may be free on one domain and taken on another.
///
/// The community name (`{domain}/@`) reports as reserved. This probe carries no
/// mnemonic, so it cannot know whether the asker is the root DID — and the
/// honest answer to "can I claim this" is no for every caller but one, whose
/// binding happens at provisioning rather than through this surface. Answering
/// `available` here would invite a claim that
/// [`validate_agent_name_binding`] then refuses.
pub async fn check_agent_name(
    state: &AppState,
    domain: &str,
    name: &str,
) -> Result<AgentNameAvailability, AppError> {
    let bare = name.strip_prefix('@').unwrap_or(name).to_string();
    let reserved = if bare.is_empty() {
        true
    } else {
        match validate_agent_name(&bare) {
            Ok(()) => false,
            Err(AppError::AgentName(AgentNameError::Reserved)) => true,
            // A malformed name (bad grammar) is a client error, not "unavailable".
            Err(e) => return Err(e),
        }
    };
    // Same rule a claim applies: a leftover index entry does not hold a name.
    // No slot has an empty mnemonic, so every live holder counts as "other".
    let taken = agent_name_held_by_other(state, domain, &bare, "").await?;
    Ok(AgentNameAvailability {
        available: !reserved && !taken,
        reserved,
        name: bare,
        domain: domain.to_string(),
    })
}

/// Read a hosted DID's agent-name registry — the authoritative forward view,
/// including *parked* entries.
///
/// The registry is the only place a parked name is visible: disabling drops it
/// from the document's `alsoKnownAs` by design, so a client reading the DID
/// document alone cannot tell a parked name from one that was never bound, and
/// so cannot offer to resume it.
///
/// Returns the slot's domain alongside the entries because a bare local part
/// (`alice`) only means something within a domain (`example.com/@alice`); the
/// domain is empty for un-domained legacy slots.
pub async fn list_agent_names(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    request_domain: Option<&str>,
) -> Result<(String, Vec<AgentNameEntry>), AppError> {
    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;
    ensure_slot_domain_matches(&record, request_domain)?;

    let domain = if !record.domain.is_empty() {
        record.domain.clone()
    } else {
        record
            .did_id
            .as_deref()
            .and_then(|d| did_hosting_common::server::domain::extract_did_host(d).ok())
            .unwrap_or_default()
    };
    debug!(
        did = %auth.did,
        mnemonic = %mnemonic,
        count = record.agent_names.len(),
        "agent names listed"
    );
    Ok((domain, record.agent_names))
}

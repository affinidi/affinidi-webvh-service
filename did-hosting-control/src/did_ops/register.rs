//! Creating and publishing a slot: reserving a path ([`create_did`]), the
//! atomic claim-and-publish ([`register_did_atomic`]), the front half every
//! new-version publish shares ([`prepare_republish`]), and the path
//! availability probe ([`check_name`]).

use bip39::Language;
use did_hosting_common::CheckNameResponse;
use did_hosting_common::did_ops::{
    self, DidRecord, agent_name_key, content_log_key, content_witness_key, did_key, owner_key,
};
use did_hosting_common::method::publication::Publication;
use did_hosting_common::server::mnemonic::{validate_custom_path, validate_mnemonic};
use rand::random_range;
use tracing::{info, warn};

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::store::KeyspaceHandle;

use super::agent_names::reconcile_agent_names;
use super::quota::{check_did_count_limit, check_total_size_limit, owner_quota_guard};
use super::{
    check_did_host_safety, ensure_requested_domain_matches_did, get_authorized_record,
    invalidate_cached_content, publication_error, stage_index, validate_slot_mnemonic,
};

// ---------------------------------------------------------------------------
// Mnemonic generation (same logic as did-hosting-server/src/mnemonic.rs)
// ---------------------------------------------------------------------------

pub(super) fn random_mnemonic() -> String {
    let wordlist = Language::English.word_list();
    let w1 = wordlist[random_range(0..wordlist.len())];
    let w2 = wordlist[random_range(0..wordlist.len())];
    format!("{w1}-{w2}")
}

pub(super) async fn generate_unique_mnemonic(dids_ks: &KeyspaceHandle) -> Result<String, AppError> {
    for _ in 0..100 {
        let mnemonic = random_mnemonic();
        let key = format!("did:{mnemonic}");
        if !dids_ks.contains_key(key).await? {
            return Ok(mnemonic);
        }
    }
    Err(AppError::Internal(
        "failed to generate unique mnemonic after 100 attempts".into(),
    ))
}

pub(super) async fn is_path_available(
    dids_ks: &KeyspaceHandle,
    path: &str,
) -> Result<bool, AppError> {
    Ok(!dids_ks.contains_key(format!("did:{path}")).await?)
}

/// Resolve a custom path during create, applying force-replace semantics.
///
/// The caller must hold `state.path_locks.guard(custom_path)`, so the slot
/// read here is still the slot when the caller commits.
///
/// If the path is free, returns `None`. If taken and `force` is false,
/// returns `Conflict(conflict_msg)`. If taken and `force` is true, the caller
/// must be an admin or the current owner of that path, and the existing
/// record is returned: the caller removes its log content, witness and (for
/// another owner) owner-index **in the same batch** that writes the new
/// record. Committed separately, a failure or crash in between left the
/// slot's old record pointing at content that was already gone. Stats are
/// left intact (separate keyspace).
pub(super) async fn resolve_path_for_create(
    state: &AppState,
    custom_path: &str,
    auth: &AuthClaims,
    force: bool,
    conflict_msg: &str,
) -> Result<Option<DidRecord>, AppError> {
    use did_hosting_common::server::acl::Role;

    let Some(existing) = state.dids_ks.get::<DidRecord>(did_key(custom_path)).await? else {
        return Ok(None);
    };

    if !force {
        return Err(AppError::Conflict(conflict_msg.to_string()));
    }

    if existing.owner != auth.did && auth.role != Role::Admin {
        warn!(
            caller = %auth.did,
            owner = %existing.owner,
            mnemonic = %custom_path,
            "force replace denied: not the owner or admin"
        );
        return Err(AppError::Forbidden(
            "force replace requires admin or current owner".into(),
        ));
    }

    Ok(Some(existing))
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Create a new DID slot (reserve a mnemonic/path).
///
/// When `force` is true and the requested path already exists, the caller
/// (admin or current owner of that path) replaces the existing slot — the
/// old DID's log content, witness, and owner-index are removed and the
/// caller becomes the new owner. Without `force`, a path collision returns
/// `Conflict` as before.
/// `domain` is the resolved domain to persist on the new record. `None`
/// is accepted for callers (older DIDComm paths, tests) that don't yet
/// route through the resolver; the M-01 backfill sweep will tag those
/// records on next run.
pub async fn create_did(
    auth: &AuthClaims,
    state: &AppState,
    path: Option<&str>,
    force: bool,
    domain: Option<&str>,
) -> Result<DidRecord, AppError> {
    use crate::auth::session::now_epoch;
    use did_hosting_common::server::acl::Role;

    // Every branch returns holding the slot's per-path write lock — the same
    // one `register_did_atomic` and the agent-name ops take — so the availability
    // check (or the force-replace read) and the commit below are one step.
    // Without it, two creates of one free path both saw it free and both
    // committed: the later silently replaced the earlier caller's slot and
    // left the earlier owner's index entry pointing at a DID it no longer
    // owned.
    let (mnemonic, _path_guard, replaced) = match path {
        Some(custom_path) => {
            let conflict_msg = if custom_path == ".well-known" {
                if auth.role != Role::Admin {
                    return Err(AppError::Forbidden(
                        "only admins can create the root DID".into(),
                    ));
                }
                "root DID (.well-known) already exists".to_string()
            } else {
                validate_custom_path(custom_path)?;
                format!("path '{custom_path}' is already taken")
            };
            let guard = state.path_locks.guard(custom_path).await;
            let replaced =
                resolve_path_for_create(state, custom_path, auth, force, &conflict_msg).await?;
            (custom_path.to_string(), guard, replaced)
        }
        None => {
            let mut claimed = None;
            for _ in 0..8 {
                let candidate = generate_unique_mnemonic(&state.dids_ks).await?;
                let guard = state.path_locks.guard(&candidate).await;
                // Re-checked under the lock: another create may have taken
                // the random name between generation and locking.
                if is_path_available(&state.dids_ks, &candidate).await? {
                    claimed = Some((candidate, guard, None));
                    break;
                }
            }
            claimed.ok_or_else(|| AppError::Internal("failed to claim a unique mnemonic".into()))?
        }
    };

    let now = now_epoch();
    let mut record = DidRecord {
        owner: auth.did.clone(),
        mnemonic: mnemonic.clone(),
        created_at: now,
        updated_at: now,
        version_count: 0,
        did_id: None,
        content_size: 0,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,

        method: "webvh".to_string(),
        // Persist the resolved domain so the per-domain UI filters and
        // the dashboard's per-domain stat cards see the new DID on the
        // very next list call. A caller that passes `None` (a
        // `did/check-name` reservation whose domain could not be resolved,
        // tests) still produces an empty string, which the first publish
        // backfills from the DID's host.
        domain: domain.unwrap_or("").to_string(),

        // An empty slot — no log, so no document to read services from.
        // `register_did_atomic` fills this on first upload.
        services: None,
        agent_names: Vec::new(),
    };
    // A force-replace is not a resume: a suspended slot stays suspended,
    // and one an admin suspended stays so until an admin resumes it.
    if let Some(existing) = replaced.as_ref() {
        record.disabled = existing.disabled;
        record.disabled_by_admin = existing.disabled_by_admin;
    }

    // Per-account DID-count quota (SEC-4045 W3). Only a slot this owner does not
    // already hold counts against the cap — a force-replace of the caller's own
    // slot is not a net-new DID, so it must not be refused at the cap.
    let adds_slot = replaced
        .as_ref()
        .is_none_or(|existing| existing.owner != auth.did);
    let _quota_guard = owner_quota_guard(state, &auth.did).await;
    if adds_slot {
        check_did_count_limit(auth, state).await?;
    }

    // The force-replace's removal of the old slot's content and the new
    // record are one atomic write.
    let mut batch = state.store.batch();
    if let Some(existing) = replaced.as_ref() {
        batch.remove(&state.dids_ks, content_log_key(&mnemonic));
        batch.remove(&state.dids_ks, content_witness_key(&mnemonic));
        if existing.owner != auth.did {
            batch.remove(&state.dids_ks, owner_key(&existing.owner, &mnemonic));
        }
    }
    batch.insert(&state.dids_ks, did_key(&mnemonic), &record)?;
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&auth.did, &mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    let _usage = stage_index(state, &mut batch, replaced.as_ref(), Some(&record)).await?;
    batch.commit().await?;
    if replaced.is_none() {
        state.stats_collector.increment_total_dids();
    }
    if let Some(existing) = replaced.as_ref() {
        invalidate_cached_content(state, &mnemonic);
        info!(
            caller = %auth.did,
            prev_owner = %existing.owner,
            mnemonic = %mnemonic,
            "force-replaced existing DID"
        );
    }

    info!(did = %auth.did, mnemonic = %mnemonic, "DID URI created on control plane");

    // The record as written, so the caller need not read it back.
    Ok(record)
}

/// Atomic claim-and-publish for a DID at a known path.
///
/// Solves the resolvability gap in the retired two-step
/// `request_uri` → `did/publish` flow: between those two calls a
/// previously-resolvable slot is empty, so any in-flight resolver hits
/// 404. This op writes the new mnemonic record + log content + owner
/// index in a single batch, so a resolver's GET returns either the old
/// content or the new content — never absent.
///
/// Auth model:
/// - Slot does not exist → caller becomes owner (same as
///   reserving a fresh path with [`create_did`]).
/// - Slot exists, caller is current owner → idempotent re-publish.
///   Witness is preserved (it's the owner's own).
/// - Slot exists, caller is admin AND `force == true` AND owner
///   differs → admin takeover. Old witness is cleared (it was
///   signed for the prior DID/owner). Old owner-index entry is
///   removed.
/// - Slot exists, any other case → `Forbidden`.
///
/// Content validation:
/// - `did_log` must parse as valid did.jsonl whose latest entry
///   resolves to a `did:webvh:` identifier.
/// - That identifier's host (and optional port) must match this
///   server's hosting URL, AND its path component must match the
///   requested `path`. This stops an admin from uploading
///   arbitrary `did.jsonl` content under a path they happen to own
///   that names a different host or path — claim-jumping.
///
/// The stages, in order — the locks are taken in exactly this order (slot,
/// owner quota, agent names, index usage), the order every other writer of
/// a slot takes them in:
///
/// 1. `validate_register_path`: no storage I/O;
/// 2. the slot's path lock, held through the commit;
/// 3. `verify_registration`: the publication, and the host and domain
///    checks;
/// 4. `authorize_slot`: who may write the slot;
/// 5. `hold_register_quota`: the owner's quota lock and its caps;
/// 6. `registered_record`, then `reconcile_agent_names` (the per-name
///    locks): the record as it will be written;
/// 7. `commit_registration`: one batch, with the outbox and index;
/// 8. the locks released, then `after_registration`: stats, the log line,
///    and the service's own identity check.
pub async fn register_did_atomic(
    auth: &AuthClaims,
    state: &AppState,
    path: &str,
    did_log: &str,
    force: bool,
    domain: Option<&str>,
) -> Result<DidRecord, AppError> {
    use crate::auth::session::now_epoch;

    validate_register_path(auth, path, did_log)?;

    // Hold the per-path write lock from here through the commit below —
    // covering the `existing_log`/`existing_witness` read, the
    // witness-threshold verification that trusts it, and the write. Without
    // this, a concurrent publish/register on the same path could commit a
    // longer, already-witnessed log *between* this read and this call's own
    // commit; this call's `verify_publication` would have computed
    // `previously_published` from the stale, shorter snapshot it read
    // first, exempting from the witness threshold entries that are, by the
    // time this call writes, already published and meant to require one — a
    // real witness-threshold bypass, not merely a lost update. Locking only
    // around the later record-read + write (as this used to) closes the
    // lost-update race but not this one, since `verify_publication` had
    // already run — and had already decided which entries need a proof —
    // before the lock was ever taken.
    let path_guard = state.path_locks.guard(path).await;

    let (publication, did_id) = verify_registration(state, auth, path, did_log, domain).await?;

    // `path_guard`, acquired above, already covers this read: without it,
    // two concurrent fresh-slot calls could both observe `existing == None`,
    // both build records, and both commit — fjall batches are atomic
    // per-commit but not conditional, so the second would silently
    // overwrite the first.
    let existing: Option<DidRecord> = state.dids_ks.get(did_key(path)).await?;
    let owner_changed = authorize_slot(auth, path, force, existing.as_ref())?;
    let quota_guard = hold_register_quota(state, auth, existing.as_ref(), did_log.len()).await?;

    let now = now_epoch();
    let mut new_record = registered_record(
        auth,
        path,
        did_log,
        &did_id,
        &publication,
        existing.as_ref(),
        owner_changed,
        now,
    );

    // Reconcile the authoritative registry against what the document claims —
    // the control plane is the source of record, so a name registered at
    // create/publish time must land in the registry (and its index), not only
    // via the explicit agent-name ops. Parked entries are preserved.
    //
    // Reserved and already-held names are refused here exactly as on the
    // publish path; the `_path_guard` above plus the per-name locks
    // `reconcile_agent_names` returns are the critical section the collision
    // check needs. A fresh slot is the *easiest* place to attempt a
    // name capture — nothing else about registering constrains what the
    // submitted document may claim.
    let reg_domain =
        did_hosting_common::server::domain::extract_did_host(&did_id).unwrap_or_default();
    let (claimed, released, name_locks) = reconcile_agent_names(
        state,
        &mut new_record,
        path,
        &publication.agent_names(&reg_domain),
        &reg_domain,
        now,
    )
    .await?;

    let usage = commit_registration(
        state,
        auth,
        path,
        did_log,
        existing.as_ref(),
        owner_changed,
        &new_record,
        &AgentNameChanges {
            domain: &reg_domain,
            claimed: &claimed,
            released: &released,
        },
    )
    .await?;
    // Released before the identity check below, which can reach the network
    // when this is the service's own DID; nothing after this point reads or
    // writes the slot or its names.
    drop(name_locks);
    drop(path_guard);
    invalidate_cached_content(state, path);
    drop(usage);
    drop(quota_guard);

    after_registration(
        state,
        auth,
        path,
        existing.is_none(),
        new_record.version_count,
        owner_changed,
    )
    .await;

    // The record as written. Answer from it rather than reading it back: on an
    // eventually consistent store that read can miss the write, and the caller
    // would be told a stored DID failed.
    Ok(new_record)
}

/// The checks of a registration that need no storage I/O, so a bad request
/// is refused before any.
///
/// `.well-known` is the root slot, not a custom path: its leading dot fails
/// the mnemonic charset rules, so `validate_custom_path` rejects it by
/// design. Use the root-aware `validate_mnemonic` (as publish / resolve /
/// every other slot-addressed op does) and gate root on admin, mirroring
/// `create_did`. Registering the root DID is how an operator who self-hosts
/// this domain publishes the domain's own did:webvh; the owner / `force`
/// checks still decide whether an occupied root slot may be taken over.
///
/// Which method is being published decides how the path is spelled. A
/// did:webs slot ends in the identifier's AID — case-sensitive base64url —
/// which the shared lowercase-only grammar rejects outright, so it needs its
/// own validator. See `validate_webs_mnemonic` for why the shared rule is
/// not simply loosened.
fn validate_register_path(auth: &AuthClaims, path: &str, did_log: &str) -> Result<(), AppError> {
    use did_hosting_common::server::acl::Role;

    if path == ".well-known" && auth.role != Role::Admin {
        return Err(AppError::Forbidden(
            "only admins can register the root DID".into(),
        ));
    }
    let submitted_method = did_hosting_common::method::detect_method(did_log.as_bytes());
    if submitted_method == Some("webs") {
        did_hosting_common::server::mnemonic::validate_webs_mnemonic(path)?;
    } else {
        validate_mnemonic(path)?;
    }
    Ok(())
}

/// Verify a registration's publication and the identifier it names: the
/// publication with its own method's verifier, then the host and domain
/// checks. Returns the publication and its DID. The caller holds the slot's
/// path lock.
async fn verify_registration(
    state: &AppState,
    auth: &AuthClaims,
    path: &str,
    did_log: &str,
    domain: Option<&str>,
) -> Result<(Publication, String), AppError> {
    // The slot's currently stored log and witness proofs, if any — a
    // fresh registration has neither, a re-register of an existing slot
    // (owner republishing through `did/register` rather than `did/publish`)
    // has both. For webvh, `verify_publication` uses these to tell
    // already-published entries (which must still meet their witness
    // threshold, from the stored witness content) from the new tail this
    // call is adding (exempt — its proofs arrive later via
    // `webvh/witness/publish`). See `did_ops::verify_did_log_for_publish`.
    let existing_log = state.dids_ks.get_raw(content_log_key(path)).await?;
    let existing_witness = state.dids_ks.get_raw(content_witness_key(path)).await?;

    // Verify the publication with its own method's verifier, and reduce
    // it to the facts the shared tail needs. For webvh this runs
    // the full log-proof chain, enforcing the witness threshold on
    // already-published entries only; for webs it verifies the key event
    // log and proves the stream establishes the AID this slot's identifier
    // ends in.
    let publication = did_hosting_common::method::publication::verify_publication(
        domain.unwrap_or_default(),
        path,
        did_log.as_bytes(),
        existing_log.as_deref(),
        existing_witness.as_deref(),
    )
    .map_err(publication_error)?;

    let server_base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .ok_or_else(|| {
            AppError::Internal(
                "server has neither did_hosting_url nor public_url configured; cannot validate DID host"
                    .into(),
            )
        })?;

    let did_id = publication.did_id.clone().ok_or_else(|| {
        AppError::invalid("did_log's latest entry has no resolvable did:webvh state.id")
    })?;

    // Multi-domain safety check. Runs before the legacy
    // `validate_did_id_matches_request` host equality check. In
    // multi-domain deployments where the embedded DID host is on a
    // configured-but-non-default domain, this is the authoritative
    // check; the legacy validator's host comparison is redundant.
    // For legacy single-domain deployments where `did_hosting_url`
    // host == the only domain, both checks pass for valid DIDs.
    // Permissive when the `domains` keyspace is empty — see
    // `assert_did_host_allowed_when_domains_configured` doc.
    check_did_host_safety(state, auth, &did_id).await?;

    // Only for methods whose identifier is embedded in the content. A
    // did:webs identifier is *built* from the slot, so comparing it back
    // against that slot would be a tautology — the real binding is that
    // the key event log establishes the AID the identifier ends in, and
    // `verify_publication` has already enforced it.
    //
    // The same holds for the caller's explicit `domain`: a did:webs
    // identifier is built *from* it, so it agrees by construction. A
    // did:webvh identifier is not — it is read from the signed log — so the
    // domain the caller says it is publishing into must be the DID's host,
    // or the request is refused as `unknown_domain` before anything is
    // written, exactly as `publish_did` refuses it.
    if publication.method != "webs" {
        did_ops::validate_did_id_matches_request(&did_id, path, server_base_url)
            .map_err(AppError::invalid)?;
        ensure_requested_domain_matches_did(domain, &did_id)?;
    }
    Ok((publication, did_id))
}

/// Whether `auth` may write the slot `existing` holds, and whether doing so
/// changes its owner: its own slot or a fresh one (`false`), or an admin's
/// forced takeover of another's (`true`). Anything else is `Forbidden`.
fn authorize_slot(
    auth: &AuthClaims,
    path: &str,
    force: bool,
    existing: Option<&DidRecord>,
) -> Result<bool, AppError> {
    use did_hosting_common::server::acl::Role;

    match existing {
        Some(rec) if rec.owner == auth.did => Ok(false),
        Some(rec) => {
            // Slot owned by someone else.
            if auth.role != Role::Admin {
                warn!(
                    caller = %auth.did,
                    owner = %rec.owner,
                    path = %path,
                    "atomic-register denied: not the owner of this slot"
                );
                return Err(AppError::Forbidden(
                    "slot is owned by a different DID".into(),
                ));
            }
            if !force {
                warn!(
                    caller = %auth.did,
                    owner = %rec.owner,
                    path = %path,
                    "atomic-register denied: admin takeover requires force=true"
                );
                return Err(AppError::Forbidden(
                    "admin takeover of a slot owned by another DID requires force=true".into(),
                ));
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Take the caller's quota lock and check its caps (SEC-4045 W3). A fresh
/// slot counts against `max_did_count`; the published log counts against
/// `max_total_size` (old size 0 for a fresh slot, else the slot's current
/// content_size). Both helpers are admin-exempt and no-op when the ACL sets
/// no cap. Hold the returned guard through the commit.
async fn hold_register_quota(
    state: &AppState,
    auth: &AuthClaims,
    existing: Option<&DidRecord>,
    new_size: usize,
) -> Result<did_hosting_common::server::path_locks::PathGuard, AppError> {
    let quota_guard = owner_quota_guard(state, &auth.did).await;
    if existing.is_none() {
        check_did_count_limit(auth, state).await?;
    }
    let old_content_size = existing.map(|r| r.content_size).unwrap_or(0);
    check_total_size_limit(auth, state, old_content_size, new_size as u64).await?;
    Ok(quota_guard)
}

/// The record a registration writes, before its agent names are reconciled
/// against the document.
// One argument per fact the record is built from; a struct would only rename them.
#[allow(clippy::too_many_arguments)]
fn registered_record(
    auth: &AuthClaims,
    path: &str,
    did_log: &str,
    did_id: &str,
    publication: &Publication,
    existing: Option<&DidRecord>,
    owner_changed: bool,
    now: u64,
) -> DidRecord {
    // Preserve created_at when the same owner is re-publishing; reset
    // on takeover or fresh allocation.
    let (created_at, version_count) = match (existing, owner_changed) {
        (Some(rec), false) => (rec.created_at, rec.version_count + 1),
        _ => (now, 1),
    };

    DidRecord {
        owner: auth.did.clone(),
        mnemonic: path.to_string(),
        created_at,
        updated_at: now,
        version_count,
        did_id: Some(did_id.to_string()),
        content_size: did_log.len() as u64,
        // A re-register publishes content; it does not resume a suspended
        // slot. Only `did/set-state` does, and only an admin may lift a
        // suspension an admin made.
        disabled: existing.is_some_and(|r| r.disabled),
        disabled_by_admin: existing.is_some_and(|r| r.disabled_by_admin),
        deleted_at: None,

        // Tagged from the verifier that actually accepted this content,
        // never from a caller-supplied label — a record whose `method`
        // disagreed with its bytes would be served by the wrong
        // resolver.
        method: publication.method.to_string(),
        // Every method's record carries its domain: the per-domain listing
        // and UI filter key on it, and a did:webs record's identifier cannot
        // be rebuilt without it. (This used to be written empty for webvh,
        // which wiped the domain a reserved slot or an earlier publish had
        // recorded every time its owner re-registered.)
        //
        // Taken from the DID rather than from the request parameter so
        // it lands in the same *decoded* form every other record uses
        // (`extract_did_host` percent-decodes `%3A` back to `:`). The
        // edge derives its copy the same way, so the two agree; storing
        // the raw parameter here would make the control plane and its
        // edges disagree about the domain of the same DID. A DID whose
        // host cannot be read keeps whatever the slot already recorded.
        domain: did_hosting_common::server::domain::extract_did_host(did_id)
            .ok()
            .filter(|h| !h.is_empty())
            .or_else(|| existing.map(|r| r.domain.clone()).filter(|d| !d.is_empty()))
            .unwrap_or_default(),

        services: publication.services(),

        // Start from the existing registry (this path also re-registers an
        // EXISTING slot, where `Vec::new()` would silently drop every name),
        // then reconcile against the new document. The carry-over is what
        // preserves a *parked* name — deliberately absent from `alsoKnownAs`,
        // so the log alone can't express the reservation.
        //
        // An admin takeover is the exception: a parked name is the previous
        // holder's reservation, and does not pass to the new owner with the
        // slot. Every carried name is treated as served, so the reconcile
        // keeps only those the new document claims and releases the rest,
        // index entries included.
        agent_names: existing
            .map(|r| {
                let mut names = r.agent_names.clone();
                if owner_changed {
                    for entry in &mut names {
                        entry.enabled = true;
                    }
                }
                names
            })
            .unwrap_or_default(),
    }
}

/// The agent-name index changes a reconcile decided, in `domain`.
struct AgentNameChanges<'a> {
    domain: &'a str,
    claimed: &'a [String],
    released: &'a [String],
}

/// Write a registration as one atomic batch: record, log content, owner
/// index, agent-name index; plus old-owner cleanup on takeover. From a
/// resolver's perspective there is no point at which the slot is
/// half-updated — either old-content/old-record or new-content/new-record.
/// The sync to every server and watcher commits with the slot
/// (transactional outbox) and is sent once it has.
///
/// Returns the index usage guards `stage_index` took, which the caller
/// releases after the slot's own locks.
// One argument per part of the write; a struct would only rename them.
#[allow(clippy::too_many_arguments)]
async fn commit_registration(
    state: &AppState,
    auth: &AuthClaims,
    path: &str,
    did_log: &str,
    existing: Option<&DidRecord>,
    owner_changed: bool,
    new_record: &DidRecord,
    names: &AgentNameChanges<'_>,
) -> Result<Vec<did_hosting_common::server::path_locks::PathGuard>, AppError> {
    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(path),
        did_log.as_bytes().to_vec(),
    );
    if owner_changed {
        let prev = existing.expect("owner_changed => existing record present");
        // Stale witness; signed for the prior DID identifier.
        batch.remove(&state.dids_ks, content_witness_key(path));
        batch.remove(&state.dids_ks, owner_key(&prev.owner, path));
    }
    batch.insert(&state.dids_ks, did_key(path), new_record)?;
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&auth.did, path),
        path.as_bytes().to_vec(),
    );
    for name in names.claimed {
        batch.insert_raw(
            &state.dids_ks,
            agent_name_key(names.domain, name),
            path.as_bytes().to_vec(),
        );
    }
    for name in names.released {
        batch.remove(&state.dids_ks, agent_name_key(names.domain, name));
    }
    let sync = crate::server_push::stage_did_sync(
        state,
        &mut batch,
        path,
        crate::server_push::DidChange::Published { log: did_log },
    )
    .await;
    let usage = stage_index(state, &mut batch, existing, Some(new_record)).await?;
    batch.commit().await?;
    sync.finish(state).await;
    Ok(usage)
}

/// What follows a committed registration, once its locks are released.
async fn after_registration(
    state: &AppState,
    auth: &AuthClaims,
    path: &str,
    fresh: bool,
    version: u64,
    owner_changed: bool,
) {
    if fresh {
        state.stats_collector.increment_total_dids();
    }

    // A new log entry was committed, so advance the update counters — the
    // control plane is authoritative for stats (standalone or daemon mode);
    // without this, updates would only surface via stats-sync from a remote
    // edge and sit at zero in self-hosted deployments.
    state.stats_collector.record_update(path);

    info!(
        did = %auth.did,
        path = %path,
        version,
        owner_changed,
        "DID atomically registered on control plane"
    );

    // If the DID just published was the service's *own*, its keys or services
    // may have changed: re-resolve and rotate the identity now rather than at
    // the next backstop reload. This is the live publish path (`did/register`),
    // so without it a rotation of our own DID would go unnoticed for up to
    // `DEFAULT_RELOAD_INTERVAL`, with the served document advertising keys the
    // listener has not loaded.
    //
    // Safe to call on every register: it compares mnemonics first (no network),
    // and a publish of our own DID that didn't change the identity resolves the
    // document once and no-ops. It deliberately does not fail the register — the
    // log entry is committed and correct either way, and a rotation that can't
    // proceed logs loudly rather than rolling back a valid publish.
    crate::identity_rotation::on_did_published(state, path).await;
}

/// Shared front-half of a new-version publish: authorize the caller, verify
/// the submitted log's cryptographic proofs, run the host/domain safety
/// checks, and advance the loaded record's version/size/did_id/services/domain
/// fields — the work every agent-name operation (and the test-only
/// `publish_did`) does identically before it commits.
///
/// Returns the prepared, **uncommitted** record, the DID's resolved hosting
/// domain (the authority an agent name is scoped to), and the verified
/// [`Publication`]. The caller commits the record, optionally alongside extra
/// batch operations, so a single implementation of the authorize/verify/safety
/// pipeline backs both the plain publish and the name-binding ops.
pub(super) async fn prepare_republish(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    did_log: &str,
    request_domain: Option<&str>,
) -> Result<(DidRecord, String, Publication), AppError> {
    use crate::auth::session::now_epoch;

    // The stored record decides how this slot's path is spelled; see
    // `validate_slot_mnemonic`.
    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;

    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    // A slot does not change method. Allowing it would let a publish
    // swap a did:webvh log for a did:webs stream under the same path —
    // the identifier would change out from under everyone already
    // resolving it, while the record kept its owner and its agent names.
    //
    // Checked *before* verification, on the shape of the bytes alone.
    // Verifying first would make the refusal depend on the foreign
    // payload being independently valid: a malformed did:webvh log sent
    // to a did:webs slot would be reported as a broken log rather than
    // as the method swap it is, which tells the caller to fix the wrong
    // thing. `detect_method` is also what `verify_publication` dispatches
    // on, so the two cannot disagree about what was submitted.
    if let Some(submitted) = did_hosting_common::method::detect_method(did_log.as_bytes())
        && submitted != record.method
    {
        return Err(AppError::invalid(format!(
            "slot '{mnemonic}' hosts a did:{} DID; it cannot be republished as did:{submitted}",
            record.method,
        )));
    }

    // Verify with the publishing method's own verifier. For webvh this
    // walks the full chain, enforcing the witness threshold on
    // already-published entries only (the new tail's proofs arrive later
    // via `webvh/witness/publish` — see
    // `did_ops::verify_did_log_for_publish`); for webs it verifies the key
    // event log and refuses an update that rewinds or forks it.
    let existing = state
        .dids_ks
        .get_raw(content_log_key(mnemonic).as_str())
        .await?;
    let existing_witness = state
        .dids_ks
        .get_raw(content_witness_key(mnemonic).as_str())
        .await?;
    let publication = did_hosting_common::method::publication::verify_publication(
        &record.domain,
        mnemonic,
        did_log.as_bytes(),
        existing.as_deref(),
        existing_witness.as_deref(),
    )
    .map_err(publication_error)?;

    let new_size = did_log.len() as u64;
    let did_id_val = publication.did_id.clone();

    // Per-account total-size quota (SEC-4045 W3). The republished log replaces
    // this slot's current content, so the owner's usage moves by
    // `new_size - record.content_size`. `record.content_size` is still the OLD
    // size here (it is overwritten below). Admin-exempt; no-op with no ACL cap.
    // An early refusal only: the caller re-checks under the owner's quota lock
    // and holds it through its commit ([`hold_size_quota`]).
    check_total_size_limit(auth, state, record.content_size, new_size).await?;

    // The same safety check as register_did_atomic — the embedded
    // DID's host must be a configured active domain on this server
    // and allowed by the caller's ACL. This updates an existing slot,
    // but a malicious or buggy client could push a log entry pointing
    // at a different host than the one originally registered — this
    // catches that without trusting the stored record's old `did_id`.
    if let Some(did_id) = did_id_val.as_deref() {
        check_did_host_safety(state, auth, did_id).await?;
    }

    // Cross-check the caller's explicit `?domain=` against the DID's actual
    // host (a DID's host IS its domain). The VTA re-sends its intended domain
    // on publish to catch a misconfigured caller before the log lands on the
    // wrong tenant's slot; without this check the parameter was silently
    // ignored and the advertised `did-management:unknown_domain` rejection did
    // not exist on the wire.
    if let Some(did_id) = did_id_val.as_deref() {
        ensure_requested_domain_matches_did(request_domain, did_id)?;
    }

    record.updated_at = now_epoch();
    record.version_count += 1;
    record.did_id = did_id_val.clone();
    record.content_size = new_size;

    // Recompute the badge cache from the document we're about to store.
    // Unconditional, not a fill-if-empty: a publish can add or drop a
    // service (e.g. a node that stops advertising DIDComm), so a stale
    // non-empty cache is just as wrong as a missing one. Also self-heals a
    // legacy `None` if the M-02 boot sweep hasn't reached this record.
    record.services = publication.services();

    // Backfill `record.domain` from the embedded DID's host on first
    // publish for records that pre-date the `request_uri` resolver fix
    // (older slots created with the buggy code path that always stored
    // `domain: ""`). Without this the per-domain UI filter would keep
    // hiding the DID until the M-01 sweep next runs. New DIDs reserved
    // through `create_did` already carry the resolved domain — this
    // only mutates empty entries, so it's idempotent.
    if record.domain.is_empty()
        && let Some(did_id) = did_id_val.as_deref()
        && let Ok(host) = did_hosting_common::server::domain::extract_did_host(did_id)
    {
        record.domain = host;
    }

    // The hosting domain an agent name is scoped to: the record's tagged
    // domain, or the DID's own host if a legacy record still carries none.
    let domain = if !record.domain.is_empty() {
        record.domain.clone()
    } else {
        did_id_val
            .as_deref()
            .and_then(|d| did_hosting_common::server::domain::extract_did_host(d).ok())
            .unwrap_or_default()
    };

    Ok((record, domain, publication))
}

/// Check if a custom path is available.
pub async fn check_name(state: &AppState, path: &str) -> Result<CheckNameResponse, AppError> {
    validate_custom_path(path)?;
    let available = is_path_available(&state.dids_ks, path).await?;
    Ok(CheckNameResponse {
        available,
        path: path.to_string(),
    })
}

//! DID management business logic for the control plane.
//!
//! The control plane is the source of truth for all DIDs. Functions here
//! operate on the control plane's `dids` keyspace and use the shared types
//! from `did-hosting-common::did_ops`.

use bip39::Language;
use did_hosting_common::did_ops::{
    self, AgentNameEntry, DidRecord, LogEntryInfo, LogMetadata, agent_name_key, content_log_key,
    content_witness_key, did_key, extract_agent_names, owner_key,
};
use did_hosting_common::server::error::AgentNameError;
use did_hosting_common::server::mnemonic::{
    validate_agent_name, validate_custom_path, validate_mnemonic,
};
use did_hosting_common::{CheckNameResponse, DidListEntry, RequestUriResponse};
use rand::random_range;
use tracing::{debug, info, warn};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;
use crate::store::KeyspaceHandle;

/// Run the T20 safety check before any storage write on an inbound
/// create / publish.
///
/// Looks up the caller's `AclEntry` from `state.acl_ks` and delegates
/// to [`did_hosting_common::server::domain::
/// assert_did_host_allowed_when_domains_configured`] — which is
/// permissive when the `domains` keyspace is empty (legacy / test
/// state) and strict otherwise.
///
/// Pulled out as a helper so `register_did_atomic` and `publish_did`
/// can share the call without duplicating the ACL lookup.
async fn check_did_host_safety(
    state: &AppState,
    auth: &AuthClaims,
    did_id: &str,
) -> Result<(), AppError> {
    use did_hosting_common::server::acl::{AclEntry, get_acl_entry};
    use did_hosting_common::server::domain::DomainScope;

    // Look up the caller's ACL entry. In production an authenticated
    // caller always has one — the auth extractor enforces it.
    // In unit-test paths that call did_ops directly without seeding
    // the ACL keyspace, the entry is absent; fall back to a synthetic
    // entry with `domains: DomainScope::All` (the role from the JWT
    // claims). That matches the legacy pre-T20b behaviour where no
    // domain restriction applied at all — production gates this on
    // the auth path, tests get the legacy permissive shape.
    let acl_entry = match get_acl_entry(&state.acl_ks, &auth.did).await? {
        Some(e) => e,
        None => AclEntry {
            did: auth.did.clone(),
            role: auth.role.clone(),
            label: None,
            created_at: 0,
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        },
    };
    did_hosting_common::server::domain::assert_did_host_allowed_when_domains_configured(
        &state.store,
        &acl_entry,
        did_id,
    )
    .await
}

// Re-export for convenience
pub use did_hosting_common::did_ops::{
    extract_did_id, extract_log_metadata, extract_service_types,
};

// ---------------------------------------------------------------------------
// JSONL validation (wraps the common version with AppError)
// ---------------------------------------------------------------------------

/// Run the structural + cryptographic-proof validation pipeline on a
/// `did.jsonl` body before commit. Wraps
/// `did-hosting-common::did_ops::verify_did_log_proofs` with the local
/// `AppError::Validation(InvalidLog)` tag so the dispatcher emits
/// `e.p.did.invalid-log` on any chain failure (parse, signature,
/// parameter-transition, post-deactivation tamper).
///
/// Replaces the previous structural-only `validate_did_jsonl` — proof
/// verification subsumes the parse check, so callers only need this
/// one function before commit.
fn verify_did_log_proofs(content: &str) -> Result<(), AppError> {
    use did_hosting_common::server::error::ValidationKind;
    did_ops::verify_did_log_proofs(content)
        .map_err(|m| AppError::validation(ValidationKind::InvalidLog, m))
}

// ---------------------------------------------------------------------------
// Mnemonic generation (same logic as did-hosting-server/src/mnemonic.rs)
// ---------------------------------------------------------------------------

fn random_mnemonic() -> String {
    let wordlist = Language::English.word_list();
    let w1 = wordlist[random_range(0..wordlist.len())];
    let w2 = wordlist[random_range(0..wordlist.len())];
    format!("{w1}-{w2}")
}

async fn generate_unique_mnemonic(dids_ks: &KeyspaceHandle) -> Result<String, AppError> {
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

async fn is_path_available(dids_ks: &KeyspaceHandle, path: &str) -> Result<bool, AppError> {
    Ok(!dids_ks.contains_key(format!("did:{path}")).await?)
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Load a DID record and verify the caller is the owner (or admin).
async fn get_authorized_record(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    auth: &AuthClaims,
) -> Result<DidRecord, AppError> {
    use crate::acl::Role;

    let record: DidRecord = dids_ks
        .get(did_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;
    if record.owner != auth.did && auth.role != Role::Admin {
        warn!(
            caller = %auth.did,
            owner = %record.owner,
            mnemonic = %mnemonic,
            "access denied: not the owner of this DID"
        );
        return Err(AppError::Forbidden("not the owner of this DID".into()));
    }
    Ok(record)
}

/// Resolve a custom path during create, applying force-replace semantics.
///
/// If the path is free, returns it unchanged. If taken and `force` is false,
/// returns `Conflict(conflict_msg)`. If taken and `force` is true, the caller
/// must be an admin or the current owner of that path; the existing log
/// content, witness, and owner-index are removed so the slot can be
/// reused. Stats are left intact (separate keyspace).
async fn resolve_path_for_create(
    state: &AppState,
    custom_path: &str,
    auth: &AuthClaims,
    force: bool,
    conflict_msg: &str,
) -> Result<String, AppError> {
    use crate::acl::Role;

    if is_path_available(&state.dids_ks, custom_path).await? {
        return Ok(custom_path.to_string());
    }

    if !force {
        return Err(AppError::Conflict(conflict_msg.to_string()));
    }

    let existing: DidRecord = state
        .dids_ks
        .get(did_key(custom_path))
        .await?
        .ok_or_else(|| AppError::Internal("path conflict but record missing".into()))?;

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

    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, content_log_key(custom_path));
    batch.remove(&state.dids_ks, content_witness_key(custom_path));
    if existing.owner != auth.did {
        batch.remove(&state.dids_ks, owner_key(&existing.owner, custom_path));
    }
    batch.commit().await?;

    info!(
        caller = %auth.did,
        prev_owner = %existing.owner,
        mnemonic = %custom_path,
        "force-replacing existing DID"
    );

    Ok(custom_path.to_string())
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
) -> Result<RequestUriResponse, AppError> {
    use crate::acl::Role;
    use crate::auth::session::now_epoch;

    let mnemonic = match path {
        Some(custom_path) if custom_path == ".well-known" => {
            if auth.role != Role::Admin {
                return Err(AppError::Forbidden(
                    "only admins can create the root DID".into(),
                ));
            }
            resolve_path_for_create(
                state,
                custom_path,
                auth,
                force,
                "root DID (.well-known) already exists",
            )
            .await?
        }
        Some(custom_path) => {
            validate_custom_path(custom_path)?;
            let conflict_msg = format!("path '{custom_path}' is already taken");
            resolve_path_for_create(state, custom_path, auth, force, &conflict_msg).await?
        }
        None => generate_unique_mnemonic(&state.dids_ks).await?,
    };

    let now = now_epoch();
    let record = DidRecord {
        owner: auth.did.clone(),
        mnemonic: mnemonic.clone(),
        created_at: now,
        updated_at: now,
        version_count: 0,
        did_id: None,
        content_size: 0,
        disabled: false,
        deleted_at: None,

        method: "webvh".to_string(),
        // Persist the resolved domain so the per-domain UI filters and
        // the dashboard's per-domain stat cards see the new DID on the
        // very next list call. Callers that pass `None` (older DIDComm
        // paths, tests) still produce an empty string and rely on the
        // M-01 sweep, but the REST `request_uri` handler now always
        // resolves a concrete value up front.
        domain: domain.unwrap_or("").to_string(),

        // An empty slot — no log, so no document to read services from.
        // `publish_did` fills this on first upload.
        services: None,
        agent_names: Vec::new(),
    };

    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(&mnemonic), &record)?;
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&auth.did, &mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.commit().await?;

    // Build the DID URL using the did_hosting_url if configured, else public_url
    let base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .unwrap_or("http://localhost");
    let did_url = format!("{base_url}/{mnemonic}/did.jsonl");

    info!(did = %auth.did, mnemonic = %mnemonic, "DID URI created on control plane");

    Ok(RequestUriResponse { mnemonic, did_url })
}

/// Atomic claim-and-publish for a DID at a known path.
///
/// Solves the resolvability gap in the two-step
/// `request_uri` → `publish_did` flow: between those two calls a
/// previously-resolvable slot is empty, so any in-flight resolver hits
/// 404. This op writes the new mnemonic record + log content + owner
/// index in a single batch, so a resolver's GET returns either the old
/// content or the new content — never absent.
///
/// Auth model:
/// - Slot does not exist → caller becomes owner (same as
///   `request_uri` for a fresh path).
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
pub async fn register_did_atomic(
    auth: &AuthClaims,
    state: &AppState,
    path: &str,
    did_log: &str,
    force: bool,
) -> Result<RequestUriResponse, AppError> {
    use crate::acl::Role;
    use crate::auth::session::now_epoch;

    // 1. Cheap validations first — bail out before any storage I/O.
    //    Proof verification subsumes structural validation; a single
    //    pass catches both parse errors and signature failures.
    //
    //    `.well-known` is the root slot, not a custom path: its leading
    //    dot fails the mnemonic charset rules, so `validate_custom_path`
    //    rejects it by design. Use the root-aware `validate_mnemonic`
    //    (as publish / resolve / every other slot-addressed op does) and
    //    gate root on admin, mirroring `create_did`. Registering the root
    //    DID is how an operator who self-hosts this domain publishes the
    //    domain's own did:webvh; the owner / `force` checks below still
    //    decide whether an occupied root slot may be taken over.
    if path == ".well-known" && auth.role != Role::Admin {
        return Err(AppError::Forbidden(
            "only admins can register the root DID".into(),
        ));
    }
    validate_mnemonic(path)?;
    verify_did_log_proofs(did_log)?;

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

    let did_id = extract_did_id(did_log).ok_or_else(|| {
        AppError::Validation("did_log's latest entry has no resolvable did:webvh state.id".into())
    })?;

    // T20b: multi-domain safety check. Runs before the legacy
    // `validate_did_id_matches_request` host equality check. In
    // multi-domain deployments where the embedded DID host is on a
    // configured-but-non-default domain, this is the authoritative
    // check; the legacy validator's host comparison is redundant.
    // For legacy single-domain deployments where `did_hosting_url`
    // host == the only domain, both checks pass for valid DIDs.
    // Permissive when the `domains` keyspace is empty — see
    // `assert_did_host_allowed_when_domains_configured` doc.
    check_did_host_safety(state, auth, &did_id).await?;

    did_ops::validate_did_id_matches_request(&did_id, path, server_base_url)
        .map_err(AppError::Validation)?;

    // Hold the per-path write lock for the read + build + commit
    // window. Without this, two concurrent fresh-slot calls could both
    // observe `existing == None`, both build records, and both commit
    // — fjall batches are atomic per-commit but not conditional, so
    // the second would silently overwrite the first. The lock is held
    // until this function returns; dropped automatically on `?` early
    // exit too.
    let _path_guard = state.path_locks.guard(path).await;

    let existing: Option<DidRecord> = state.dids_ks.get(did_key(path)).await?;

    let owner_changed = match &existing {
        Some(rec) if rec.owner == auth.did => false,
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
            true
        }
        None => false,
    };

    // Preserve created_at when the same owner is re-publishing; reset
    // on takeover or fresh allocation.
    let now = now_epoch();
    let (created_at, version_count) = match (&existing, owner_changed) {
        (Some(rec), false) => (rec.created_at, rec.version_count + 1),
        _ => (now, 1),
    };

    let mut new_record = DidRecord {
        owner: auth.did.clone(),
        mnemonic: path.to_string(),
        created_at,
        updated_at: now,
        version_count,
        did_id: Some(did_id.clone()),
        content_size: did_log.len() as u64,
        disabled: false,
        deleted_at: None,

        // T12: legacy construction site; T13 migration fills `domain`.
        method: "webvh".to_string(),
        domain: String::new(),

        services: extract_service_types(did_log),

        // Start from the existing registry (this path also re-registers an
        // EXISTING slot, where `Vec::new()` would silently drop every name),
        // then reconcile against the new document below. The carry-over is what
        // preserves a *parked* name — deliberately absent from `alsoKnownAs`,
        // so the log alone can't express the reservation.
        agent_names: existing
            .as_ref()
            .map(|r| r.agent_names.clone())
            .unwrap_or_default(),
    };

    // Reconcile the authoritative registry against what the document claims —
    // the control plane is the source of record, so a name registered at
    // create/publish time must land in the registry (and its index), not only
    // via the explicit agent-name ops. Parked entries are preserved.
    //
    // Reserved and already-held names are refused here exactly as on the
    // publish path; the `_path_guard` above is the critical section the
    // collision check needs. A fresh slot is the *easiest* place to attempt a
    // name capture — nothing else about registering constrains what the
    // submitted document may claim.
    let reg_domain =
        did_hosting_common::server::domain::extract_did_host(&did_id).unwrap_or_default();
    let (claimed, released) =
        reconcile_agent_names(state, &mut new_record, path, did_log, &reg_domain, now).await?;

    // 4. Single-batch atomic write: record, log content, owner index, agent-name
    //    index; plus old-owner cleanup on takeover. From a resolver's
    //    perspective there is no point at which the slot is half-updated —
    //    either old-content/old-record or new-content/new-record.
    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(path),
        did_log.as_bytes().to_vec(),
    );
    if owner_changed {
        let prev = existing
            .as_ref()
            .expect("owner_changed => existing record present");
        // Stale witness; signed for the prior DID identifier.
        batch.remove(&state.dids_ks, content_witness_key(path));
        batch.remove(&state.dids_ks, owner_key(&prev.owner, path));
    }
    batch.insert(&state.dids_ks, did_key(path), &new_record)?;
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&auth.did, path),
        path.as_bytes().to_vec(),
    );
    for name in &claimed {
        batch.insert_raw(
            &state.dids_ks,
            agent_name_key(&reg_domain, name),
            path.as_bytes().to_vec(),
        );
    }
    for name in &released {
        batch.remove(&state.dids_ks, agent_name_key(&reg_domain, name));
    }
    batch.commit().await?;

    // Same rationale as `publish_did`: the atomic register path commits
    // a new log entry, so it must advance the update counters when the
    // control plane is authoritative for stats.
    state.stats_collector.record_update(path);

    let did_url = format!("{}/{path}/did.jsonl", server_base_url.trim_end_matches('/'));

    info!(
        did = %auth.did,
        path = %path,
        version = version_count,
        owner_changed,
        "DID atomically registered on control plane"
    );

    Ok(RequestUriResponse {
        mnemonic: path.to_string(),
        did_url,
    })
}

/// Shared front-half of a new-version publish: authorize the caller, verify
/// the submitted log's cryptographic proofs, run the host/domain safety
/// checks, and advance the loaded record's version/size/did_id/services/domain
/// fields — the work `publish_did` and every agent-name operation do
/// identically before they commit.
///
/// Returns the prepared, **uncommitted** record and the DID's resolved hosting
/// domain (the authority an agent name is scoped to). The caller commits it,
/// optionally alongside extra batch operations, so a single implementation of
/// the authorize/verify/safety pipeline backs both the plain publish and the
/// name-binding ops.
async fn prepare_republish(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    did_log: &str,
    request_domain: Option<&str>,
) -> Result<(DidRecord, String), AppError> {
    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    // Proof verification subsumes the structural check. The
    // didwebvh-rs verifier walks the chain, validates each entry's
    // signature against `parameters.updateKeys`, and rejects any
    // tampered or post-deactivation entries.
    verify_did_log_proofs(did_log)?;

    let new_size = did_log.len() as u64;
    let did_id_val = extract_did_id(did_log);

    // T20b: same safety check as register_did_atomic — the embedded
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
    if let Some(requested) = request_domain.filter(|d| !d.is_empty())
        && let Some(did_id) = did_id_val.as_deref()
    {
        let host = did_hosting_common::server::domain::extract_did_host(did_id)?;
        if !requested.eq_ignore_ascii_case(&host) {
            return Err(AppError::Validation(format!(
                "did-management:unknown_domain — requested domain `{requested}` does \
                 not match the DID's host `{host}`",
            )));
        }
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
    record.services = extract_service_types(did_log);

    // Backfill `record.domain` from the embedded DID's host on first
    // publish for records that pre-date the `request_uri` resolver fix
    // (older slots created with the buggy code path that always stored
    // `domain: ""`). Without this the per-domain UI filter would keep
    // hiding the DID until the M-01 sweep next runs. New DIDs created
    // through `request_uri` already carry the resolved domain — this
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

    Ok((record, domain))
}

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
/// laxer than [`validate_agent_name`]'s. So this path applies the same two
/// preconditions the explicit `set` verb does, and for the same reasons:
///
/// - **Reserved names are refused.** `@admin` / `@support` / `@security` are a
///   ready-made phishing primitive; `set` rejects them, and a publish that
///   claims one must not be the way around that.
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
/// Callers must hold `state.path_locks.guard(mnemonic)`: the collision check
/// below and the index write it authorises have to be one critical section, or
/// two concurrent publishes each see a free name and both claim it.
async fn reconcile_agent_names(
    state: &AppState,
    record: &mut DidRecord,
    mnemonic: &str,
    did_log: &str,
    domain: &str,
    now: u64,
) -> Result<(Vec<String>, Vec<String>), AppError> {
    let mut claimed = Vec::new();
    for name in extract_agent_names(did_log, domain) {
        match validate_agent_name(&name) {
            Ok(()) => {}
            // Reserved is a refusal, not a skip — see above.
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

        // Held by another DID on this domain? Refuse the whole publish. The
        // caller controls their own document, so the remedy is theirs: drop
        // the claim and republish. Nobody else can put a document into this
        // state, so this cannot be used to wedge someone's key rotation.
        if let Some(bytes) = state.dids_ks.get_raw(agent_name_key(domain, &name)).await?
            && bytes != mnemonic.as_bytes()
        {
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

    Ok((claimed, released))
}

pub async fn publish_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    did_log: &str,
    request_domain: Option<&str>,
) -> Result<(), AppError> {
    // Serialise the read-modify-write on this slot. `reconcile_agent_names`
    // checks the name index and then writes it, and the agent-name verbs take
    // the same lock — without it a publish and a `set` on the same DID, or two
    // publishes claiming the same free name, interleave between check and
    // commit.
    let _guard = state.path_locks.guard(mnemonic).await;

    let (mut record, domain) =
        prepare_republish(auth, state, mnemonic, did_log, request_domain).await?;
    let new_size = record.content_size;
    let now = record.updated_at;

    // Keep the authoritative registry in step with what the document claims —
    // applying the same preconditions `set` does, so this path cannot be used
    // to capture a reserved name or take one from another DID.
    let (claimed, released) =
        reconcile_agent_names(state, &mut record, mnemonic, did_log, &domain, now).await?;

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        did_log.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    for name in &claimed {
        batch.insert_raw(
            &state.dids_ks,
            agent_name_key(&domain, name),
            mnemonic.as_bytes().to_vec(),
        );
    }
    for name in &released {
        batch.remove(&state.dids_ks, agent_name_key(&domain, name));
    }
    batch.commit().await?;

    // Mirror did-hosting-server's `record_update` call so total_updates /
    // last_updated_at advance when the control plane is the authoritative
    // store (standalone or daemon mode). Without this, updates only
    // surface via stats-sync from a remote server, so they sit at zero
    // in self-hosted deployments.
    state.stats_collector.record_update(mnemonic);

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        size = new_size,
        version = record.version_count,
        "did.jsonl published on control plane"
    );

    // If the DID just published was the service's *own*, its keys or services
    // may have changed. Re-resolve and rotate the identity if so.
    //
    // Safe to call on every publish: it compares mnemonics first (no network),
    // and a publish of our own DID that didn't change the identity resolves the
    // document once and no-ops. It deliberately does not fail the publish — the
    // log entry is committed and correct either way, and a rotation that can't
    // proceed logs loudly rather than rolling back a valid publish.
    crate::identity_rotation::on_did_published(state, mnemonic).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Agent names
// ---------------------------------------------------------------------------

/// Which agent-name verb a request carries. Selects the `alsoKnownAs`
/// direction the submitted document must satisfy and the registry mutation
/// applied on commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentNameOp {
    /// Bind (or refresh) a name; the document MUST claim it.
    Set,
    /// Release a name for anyone to reclaim; the document MUST no longer claim
    /// it. Destructive.
    Remove,
    /// Resume serving a parked name; the document MUST claim it again.
    Enable,
    /// Park a name — kept reserved, but stops resolving; the document MUST no
    /// longer claim it.
    Disable,
}

impl AgentNameOp {
    /// Whether the submitted document must claim the name for this verb.
    ///
    /// `set`/`enable` make a name resolvable, so the signed document has to
    /// claim it; `remove`/`disable` take it out of service, so the document
    /// must *not* — this is what keeps the served state and the signed
    /// document from ever diverging (the spec's Layer-1 invariant).
    fn requires_claim(self) -> bool {
        matches!(self, AgentNameOp::Set | AgentNameOp::Enable)
    }
}

/// Bind a human-memorable agent name to a hosted DID (`example.com/@alice`),
/// or refresh an existing binding.
///
/// The caller submits the new signed DID document (`did_log`) whose
/// `alsoKnownAs` claims the name; the host verifies the claim and commits the
/// name binding and the new document version in one batch, so there is never a
/// moment where the name resolves but the document does not claim it. See the
/// `did-management/agent-name/set` Trust Task specification.
pub async fn set_agent_name(
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
        AgentNameOp::Set,
    )
    .await
}

/// Release an agent name so anyone may reclaim it. The submitted document must
/// no longer claim the name via `alsoKnownAs`. Destructive — consumers gate
/// this behind operator step-up (enforced at the Trust-Task surface, not here).
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

/// Resume serving a previously parked (disabled) agent name. The submitted
/// document must claim the name again. See `did-management/agent-name/enable`.
pub async fn enable_agent_name(
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
        AgentNameOp::Enable,
    )
    .await
}

/// Park an agent name: it stops resolving but stays reserved to this DID (so
/// nobody else can claim it). The submitted document must no longer claim the
/// name. Consumers gate this behind operator step-up (enforced at the
/// Trust-Task surface, not here). See `did-management/agent-name/disable`.
pub async fn disable_agent_name(
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
        AgentNameOp::Disable,
    )
    .await
}

/// The name-index side-effect an agent-name op folds into its commit batch.
enum IndexWrite {
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
async fn apply_agent_name_op(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    request_domain: Option<&str>,
    op: AgentNameOp,
) -> Result<DidRecord, AppError> {
    use crate::auth::session::now_epoch;

    // Canonical local part. `validate_agent_name` enforces the grammar and
    // rejects reserved names (`@admin`, `@support`, …) before any lookup.
    validate_agent_name(name)?;
    let name = name.strip_prefix('@').unwrap_or(name).to_string();

    // Serialise the read-modify-write on this slot: the collision check, the
    // registry mutation, and the index write must not interleave with another
    // op on the same DID.
    let _guard = state.path_locks.guard(mnemonic).await;

    // Authorize + verify the submitted document + advance the record. This
    // yields not_owner / invalid_did_data / unknown_domain exactly as a plain
    // publish would.
    let (mut record, domain) =
        prepare_republish(auth, state, mnemonic, did_log, request_domain).await?;

    // The gate: does the submitted document claim the name on this domain?
    // `extract_agent_names` canonicalises through the `agent-names` crate, so
    // the comparison is byte-identical to what a resolver will later do.
    let claimed = extract_agent_names(did_log, &domain)
        .iter()
        .any(|n| n == &name);
    if claimed != op.requires_claim() {
        return Err(AgentNameError::AlsoKnownAsMismatch.into());
    }

    let index_key = agent_name_key(&domain, &name);

    // Verb-specific precondition + registry mutation, yielding the index
    // side-effect to fold into the commit batch below.
    let index_write = match op {
        AgentNameOp::Set => {
            // A name already bound to a *different* DID on this domain is
            // taken; the same DID re-setting is an idempotent refresh.
            if let Some(bytes) = state.dids_ks.get_raw(index_key.clone()).await?
                && bytes != mnemonic.as_bytes()
            {
                return Err(AgentNameError::Taken.into());
            }
            upsert_agent_name(&mut record.agent_names, &name, now_epoch());
            IndexWrite::Insert
        }
        AgentNameOp::Enable => {
            let entry = record
                .agent_names
                .iter_mut()
                .find(|e| e.name == name)
                .ok_or(AgentNameError::NotFound)?;
            if entry.enabled {
                return Err(AgentNameError::NotDisabled.into());
            }
            entry.enabled = true;
            IndexWrite::Insert
        }
        AgentNameOp::Disable => {
            let entry = record
                .agent_names
                .iter_mut()
                .find(|e| e.name == name)
                .ok_or(AgentNameError::NotFound)?;
            if !entry.enabled {
                return Err(AgentNameError::AlreadyDisabled.into());
            }
            entry.enabled = false;
            // Keep the index: a parked name stays reserved, so a later `set`
            // by another DID still sees it as taken. The name's own `enabled`
            // flag is what stops it resolving.
            IndexWrite::Keep
        }
        AgentNameOp::Remove => {
            let before = record.agent_names.len();
            record.agent_names.retain(|e| e.name != name);
            if record.agent_names.len() == before {
                return Err(AgentNameError::NotFound.into());
            }
            IndexWrite::Remove
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
    batch.commit().await?;

    state.stats_collector.record_update(mnemonic);

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        name = %name,
        ?op,
        version = record.version_count,
        "agent name updated on control plane"
    );

    // Same rationale as `publish_did`: a new document version was committed,
    // so if it was the service's own DID, re-resolve and rotate if needed.
    crate::identity_rotation::on_did_published(state, mnemonic).await;

    Ok(record)
}

/// Add a name to the registry, or refresh an existing entry to enabled.
fn upsert_agent_name(names: &mut Vec<AgentNameEntry>, name: &str, now: u64) {
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

/// Upload witness content for a DID.
pub async fn upload_witness(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    witness_content: &str,
) -> Result<(), AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    use did_hosting_common::server::error::ValidationKind;
    if witness_content.is_empty() {
        return Err(AppError::validation(
            ValidationKind::InvalidWitness,
            "did-witness.json content cannot be empty",
        ));
    }

    serde_json::from_str::<serde_json::Value>(witness_content).map_err(|e| {
        AppError::validation(
            ValidationKind::InvalidWitness,
            format!("did-witness.json must be valid JSON: {e}"),
        )
    })?;

    state
        .dids_ks
        .insert_raw(
            content_witness_key(mnemonic),
            witness_content.as_bytes().to_vec(),
        )
        .await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "did-witness.json uploaded on control plane");

    Ok(())
}

/// Get detailed information about a DID.
pub async fn get_did_info(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<(DidRecord, Option<LogMetadata>), AppError> {
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let log_metadata = match state.dids_ks.get_raw(content_log_key(mnemonic)).await? {
        Some(bytes) => {
            let content = String::from_utf8(bytes).unwrap_or_default();
            Some(extract_log_metadata(&content))
        }
        None => None,
    };

    debug!(did = %auth.did, mnemonic = %mnemonic, "DID info retrieved from control plane");

    Ok((record, log_metadata))
}

/// Get parsed log entries for a DID.
pub async fn get_did_log(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<Vec<LogEntryInfo>, AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    let content = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))?;

    Ok(did_ops::parse_log_entries(&content))
}

/// Get the raw JSONL content for a DID log as a plain string.
pub async fn get_raw_log(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<String, AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    String::from_utf8(bytes).map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))
}

/// List DIDs owned by the caller (or by a specific owner if admin).
/// When the caller is admin and no `requested_owner` is provided, returns all DIDs.
pub async fn list_dids(
    auth: &AuthClaims,
    state: &AppState,
    requested_owner: Option<&str>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<Vec<DidListEntry>, AppError> {
    use crate::acl::Role;

    if auth.role == Role::Admin && requested_owner.is_none() {
        return list_all_dids(state).await;
    }

    let target_owner = if auth.role == Role::Admin {
        requested_owner.unwrap_or(&auth.did)
    } else {
        &auth.did
    };

    let prefix = format!("owner:{target_owner}:");
    let raw = state.dids_ks.prefix_iter_raw(prefix).await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let mnemonic = String::from_utf8(value)
            .map_err(|e| AppError::Internal(format!("invalid mnemonic bytes: {e}")))?;
        if let Some(record) = state.dids_ks.get::<DidRecord>(did_key(&mnemonic)).await? {
            // Owner-index keys are `owner:{did}:{mnemonic}`. DIDs naturally
            // contain colons (e.g. `did:webvh:scid:host:path`), so a DID
            // that is a string-prefix of another (e.g. `did:web:tenant`
            // vs `did:web:tenant:server`) shares the prefix and the
            // iterator returns rows belonging to the longer DID. Re-check
            // the record's owner to filter those out — without this, a
            // tenant whose DID is a prefix of another would see the
            // other tenant's mnemonics in their dashboard.
            if record.owner != target_owner {
                continue;
            }
            let stats_key = format!("stats:{mnemonic}");
            let did_stats: did_hosting_common::DidStats =
                state.stats_ks.get(stats_key).await?.unwrap_or_default();
            entries.push(DidListEntry {
                mnemonic: record.mnemonic,
                owner: record.owner,
                created_at: record.created_at,
                updated_at: record.updated_at,
                version_count: record.version_count,
                did_id: record.did_id,
                total_resolves: did_stats.total_resolves,
                disabled: record.disabled,
                method: (!record.method.is_empty()).then(|| record.method.clone()),
                domain: (!record.domain.is_empty()).then(|| record.domain.clone()),
                services: record.services,
            });
        }
    }

    // Apply pagination
    let offset = offset.unwrap_or(0);
    let limit = limit.unwrap_or(1000);
    let total = entries.len();
    let entries: Vec<_> = entries.into_iter().skip(offset).take(limit).collect();

    info!(did = %auth.did, owner = %target_owner, total, returned = entries.len(), "DIDs listed on control plane");

    Ok(entries)
}

/// List all DIDs in the store (admin only).
async fn list_all_dids(state: &AppState) -> Result<Vec<DidListEntry>, AppError> {
    let raw = state.dids_ks.prefix_iter_raw("did:").await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: DidRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let stats_key = format!("stats:{}", record.mnemonic);
        let did_stats: did_hosting_common::DidStats =
            state.stats_ks.get(stats_key).await?.unwrap_or_default();
        entries.push(DidListEntry {
            mnemonic: record.mnemonic,
            owner: record.owner,
            created_at: record.created_at,
            updated_at: record.updated_at,
            version_count: record.version_count,
            did_id: record.did_id,
            total_resolves: did_stats.total_resolves,
            disabled: record.disabled,
            method: (!record.method.is_empty()).then(|| record.method.clone()),
            domain: (!record.domain.is_empty()).then(|| record.domain.clone()),
            services: record.services,
        });
    }

    info!(
        count = entries.len(),
        "all DIDs listed (admin) on control plane"
    );

    Ok(entries)
}

/// Delete a DID and all its associated data.
pub async fn delete_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    request_domain: Option<&str>,
) -> Result<Option<String>, AppError> {
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let did_id = record.did_id.clone();

    // Cross-check the caller's explicit `?domain=` against the slot's domain
    // before deleting — same `did-management:unknown_domain` guard as publish,
    // so a misconfigured caller can't delete the wrong tenant's slot. Prefer
    // the persisted `record.domain`; fall back to the DID's embedded host for
    // legacy slots that never had a domain resolved.
    if let Some(requested) = request_domain.filter(|d| !d.is_empty()) {
        let slot_domain = if !record.domain.is_empty() {
            record.domain.clone()
        } else {
            did_id
                .as_deref()
                .and_then(|d| did_hosting_common::server::domain::extract_did_host(d).ok())
                .unwrap_or_default()
        };
        if !slot_domain.is_empty() && !requested.eq_ignore_ascii_case(&slot_domain) {
            return Err(AppError::Validation(format!(
                "did-management:unknown_domain — requested domain `{requested}` does \
                 not match the slot's domain `{slot_domain}`",
            )));
        }
    }

    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, did_key(mnemonic));
    batch.remove(&state.dids_ks, content_log_key(mnemonic));
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    batch.remove(&state.dids_ks, owner_key(&record.owner, mnemonic));
    batch.commit().await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "DID deleted on control plane");

    Ok(did_id)
}

/// Transfer ownership of a DID to a different DID.
///
/// The caller must be the current owner or an admin. The new owner must
/// already exist in the ACL — this prevents transferring a DID to an
/// identity that can never authenticate to claim it.
pub async fn change_did_owner(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    new_owner: &str,
) -> Result<DidRecord, AppError> {
    use did_hosting_common::server::acl::{get_acl_entry, validate_did_format};

    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;

    // Same per-path write lock as `register_did_atomic` — owner-change
    // is also a read-modify-write on the same key, so concurrent
    // transfers from the same caller could otherwise race the
    // updated_at / owner-index update.
    let _path_guard = state.path_locks.guard(mnemonic).await;

    // Authorize the caller against the existing record first — keeps the
    // error class stable (Forbidden, not Validation) when an unauthorized
    // caller submits a malformed target. Any new-owner format check after
    // this point only runs for authorized callers.
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    // Canonicalise (trim + format check) before any storage I/O so a
    // typo in the new-owner DID can't silently mismatch later
    // `check_acl` lookups. Same validator the ACL routes use.
    let new_owner = validate_did_format(new_owner)?;

    if record.owner == new_owner {
        return Ok(record);
    }

    if get_acl_entry(&state.acl_ks, &new_owner).await?.is_none() {
        return Err(AppError::Validation(format!(
            "new owner '{new_owner}' is not in the ACL — add them first"
        )));
    }

    let prev_owner = std::mem::replace(&mut record.owner, new_owner.clone());
    record.updated_at = now_epoch();

    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.remove(&state.dids_ks, owner_key(&prev_owner, mnemonic));
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&new_owner, mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.commit().await?;

    info!(
        caller = %auth.did,
        prev_owner = %prev_owner,
        new_owner = %new_owner,
        mnemonic = %mnemonic,
        "DID owner changed on control plane"
    );

    Ok(record)
}

/// Toggle the `disabled` flag on a DID record.
pub async fn set_did_disabled(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    disabled: bool,
) -> Result<(), AppError> {
    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;
    record.disabled = disabled;
    state.dids_ks.insert(did_key(mnemonic), &record).await?;
    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        disabled,
        "DID disabled state updated on control plane"
    );
    Ok(())
}

/// Roll back (remove) the last log entry from a DID's JSONL content.
pub async fn rollback_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<(DidRecord, Option<LogMetadata>), AppError> {
    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    let content = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))?;

    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 {
        return Err(AppError::Validation(
            "cannot rollback: DID log must have at least 2 entries".into(),
        ));
    }

    let truncated_lines = &lines[..lines.len() - 1];
    let truncated = truncated_lines.join("\n");

    let new_did_id = extract_did_id(&truncated);
    let new_size = truncated.len() as u64;

    record.version_count = truncated_lines.len() as u64;
    record.did_id = new_did_id;
    record.content_size = new_size;
    record.updated_at = now_epoch();
    // Rolling back can retract a service — if the dropped entry was the
    // one that added `TSPTransport`, the badge must go with it.
    record.services = extract_service_types(&truncated);

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        truncated.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    batch.commit().await?;

    let log_metadata = Some(extract_log_metadata(&truncated));

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        remaining = truncated_lines.len(),
        "DID log entry rolled back on control plane"
    );

    Ok((record, log_metadata))
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
pub async fn check_agent_name(
    state: &AppState,
    domain: &str,
    name: &str,
) -> Result<AgentNameAvailability, AppError> {
    let bare = name.strip_prefix('@').unwrap_or(name).to_string();
    let reserved = match validate_agent_name(&bare) {
        Ok(()) => false,
        Err(AppError::AgentName(AgentNameError::Reserved)) => true,
        // A malformed name (bad grammar) is a client error, not "unavailable".
        Err(e) => return Err(e),
    };
    let taken = state
        .dids_ks
        .get_raw(agent_name_key(domain, &bare))
        .await?
        .is_some();
    Ok(AgentNameAvailability {
        available: !reserved && !taken,
        reserved,
        name: bare,
        domain: domain.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Tests for register_did_atomic, publish_did stats counters, etc.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_atomic {
    use super::*;
    use did_hosting_common::server::store::{
        KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
    };
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use did_hosting_common::DidRegisterRequest;
    use did_hosting_common::did::{DidDocumentOptions, build_did_document, create_log_entry};
    use did_hosting_common::server::config::{
        AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
    };
    use did_hosting_common::server::stats_collector::StatsCollector;
    use did_hosting_common::server::store::Store;

    use crate::acl::Role;
    use crate::config::{AppConfig, RegistryConfig};
    use crate::server::AppState;

    /// Build a real signed did:webvh log entry for testing.
    ///
    /// Generates a fresh Ed25519 signing key per call, builds the DID
    /// document via the same `build_did_document` helper production
    /// uses, and signs the log entry via `create_log_entry` — the
    /// resulting jsonl passes the cryptographic-proof verifier in
    /// `verify_did_log_proofs`. Replaces an earlier static fixture
    /// that string-replaced `state.id` and so produced an entry whose
    /// proof was correctly-formed but signed for a different DID.
    ///
    /// `scid` parameter is ignored — the SCID is derived from the
    /// signed log entry. Kept in the signature for call-site
    /// compatibility with the prior helper; tests that asserted a
    /// specific scid have been updated to read it from the resulting
    /// record's `did_id`.
    async fn build_test_did_log(_scid: &str, host_encoded: &str, path: &str) -> String {
        let signing = Secret::generate_ed25519(None, None);
        let signing_pub_mb = signing
            .get_public_keymultibase()
            .expect("signing public key multibase");
        let doc = build_did_document(
            host_encoded,
            path,
            &signing_pub_mb,
            &DidDocumentOptions::default(),
        );
        let (_scid, jsonl) = create_log_entry(&doc, &signing)
            .await
            .expect("create_log_entry");
        jsonl
    }

    /// Same as [`build_test_did_log`] but the document advertises the
    /// requested transports, so the `services` cache has something to read.
    async fn build_test_did_log_with_transports(
        host_encoded: &str,
        path: &str,
        tsp: bool,
        didcomm: bool,
    ) -> String {
        const MED: &str = "did:webvh:QmMED:mediator.example.com";
        let signing = Secret::generate_ed25519(None, None);
        let signing_pub_mb = signing
            .get_public_keymultibase()
            .expect("signing public key multibase");
        let doc = build_did_document(
            host_encoded,
            path,
            &signing_pub_mb,
            &DidDocumentOptions {
                key_agreement_multibase: None,
                mediator_endpoint: didcomm.then_some(MED),
                tsp_endpoint: tsp.then_some(MED),
            },
        );
        let (_scid, jsonl) = create_log_entry(&doc, &signing)
            .await
            .expect("create_log_entry");
        jsonl
    }

    async fn stored_services(state: &AppState, path: &str) -> Option<Vec<String>> {
        let record: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record");
        record.services
    }

    async fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.expect("open store");
        let sessions_ks = store.keyspace(KS_SESSIONS).expect("sessions ks");
        let acl_ks = store.keyspace(KS_ACL).expect("acl ks");
        let registry_ks = store.keyspace(KS_REGISTRY).expect("registry ks");
        let dids_ks = store.keyspace(KS_DIDS).expect("dids ks");
        let stats_ks = store.keyspace(KS_STATS).expect("stats ks");

        let config = AppConfig {
            features: FeaturesConfig::default(),
            server_did: Some("did:webvh:test:control.example.com".into()),
            mediator_did: None,
            public_url: Some("http://control.test".into()),
            did_hosting_url: Some("http://control.test".into()),
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: store_config,
            auth: AuthConfig::default(),
            secrets: SecretsConfig::default(),
            vta: VtaConfig::default(),
            registry: RegistryConfig::default(),
            trust_tasks: Default::default(),
            hosting: Default::default(),
            identity: Default::default(),
            config_path: PathBuf::new(),
        };

        let state = AppState {
            store: store.clone(),
            sessions_ks,
            acl_ks,
            registry_ks,
            dids_ks,
            config: Arc::new(config),
            did_resolver: None,
            secrets_resolver: None,
            identity: None,
            trust_tasks_verifier: None,
            jwt_keys: None,
            webauthn: None,
            http_client: reqwest::Client::new(),
            didcomm_service: Arc::new(OnceLock::new()),
            stats_collector: Arc::new(StatsCollector::new()),
            stats_ks: stats_ks.clone(),
            timeseries_ks: store.keyspace(KS_TIMESERIES).expect("timeseries ks"),
            signing_key_bytes: None,
            replay_cache: Arc::new(crate::replay::ReplayCache::new()),
            path_locks: crate::path_locks::PathLocks::new(),
            acl_locks: did_hosting_common::server::path_locks::PathLocks::new(),
            pending_challenges: Arc::new(crate::pending_challenges::PendingChallengeTracker::new()),
            ip_rate_limiter: Arc::new(crate::rate_limit::IpRateLimiter::new()),
            pending_confirms: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            outbox_notify: Arc::new(tokio::sync::Notify::new()),
        };

        (state, dir)
    }

    fn owner_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role: Role::Owner,
            session_pubkey_b58btc: None,
            session_id: String::new(),
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
        }
    }

    fn admin_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role: Role::Admin,
            session_pubkey_b58btc: None,
            session_id: String::new(),
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
        }
    }

    /// Fresh slot, well-formed did.jsonl, caller becomes owner.
    #[tokio::test]
    async fn fresh_slot_succeeds_and_writes_atomically() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "alpha";
        let did_log = build_test_did_log("scid-alpha", "control.test", path).await;

        let result = register_did_atomic(&owner_auth(owner), &state, path, &did_log, false)
            .await
            .expect("fresh-slot register should succeed");
        assert_eq!(result.mnemonic, path);
        assert_eq!(result.did_url, "http://control.test/alpha/did.jsonl");

        // Record + log + owner-index all present after the single batch commit.
        let record: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record");
        assert_eq!(record.owner, owner);
        assert_eq!(record.version_count, 1);
        // SCID is derived from the signed log entry, so its exact
        // value depends on the freshly-generated signing key. Pin
        // the prefix and the host:path suffix instead.
        let did_id = record.did_id.as_deref().expect("did_id present");
        assert!(
            did_id.starts_with("did:webvh:") && did_id.ends_with(":control.test:alpha"),
            "did_id must be did:webvh:<scid>:control.test:alpha; got {did_id}"
        );

        let log = state
            .dids_ks
            .get_raw(content_log_key(path))
            .await
            .unwrap()
            .expect("log");
        assert_eq!(log, did_log.as_bytes());

        let owner_idx = state.dids_ks.get_raw(owner_key(owner, path)).await.unwrap();
        assert!(owner_idx.is_some(), "owner index must be written");
    }

    /// Same owner re-registering: idempotent path. Slot stays owned by the
    /// same DID; version_count bumps; created_at preserved; new content
    /// replaces old without ever leaving the slot empty.
    #[tokio::test]
    async fn owner_re_register_is_idempotent() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "beta";

        let log_v1 = build_test_did_log("scid-beta", "control.test", path).await;
        let r1 = register_did_atomic(&owner_auth(owner), &state, path, &log_v1, false)
            .await
            .unwrap();
        let rec_v1: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();

        // Same owner re-registers (potentially with new log content). No
        // intermediate empty state — old content is replaced in-batch.
        let log_v2 = build_test_did_log("scid-beta", "control.test", path).await;
        let r2 = register_did_atomic(&owner_auth(owner), &state, path, &log_v2, false)
            .await
            .expect("idempotent re-register should succeed without force");
        assert_eq!(r1.mnemonic, r2.mnemonic);

        let rec_v2: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
        assert_eq!(rec_v2.owner, owner);
        assert_eq!(rec_v2.version_count, rec_v1.version_count + 1);
        assert_eq!(
            rec_v2.created_at, rec_v1.created_at,
            "owner re-register must preserve created_at"
        );
    }

    /// A different non-admin caller hitting an existing slot is forbidden,
    /// regardless of force.
    #[tokio::test]
    async fn other_owner_without_admin_forbidden() {
        let (state, _dir) = test_state().await;
        let path = "gamma";
        let owner_a = "did:example:owner-a";
        let owner_b = "did:example:owner-b";
        let log = build_test_did_log("scid-gamma", "control.test", path).await;

        register_did_atomic(&owner_auth(owner_a), &state, path, &log, false)
            .await
            .unwrap();

        // Without force.
        let err = register_did_atomic(&owner_auth(owner_b), &state, path, &log, false)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));

        // With force — still 403, since caller is not admin.
        let err = register_did_atomic(&owner_auth(owner_b), &state, path, &log, true)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    /// Admin without force on a slot owned by someone else is forbidden —
    /// `force` is the explicit "yes really take this from the previous
    /// owner" gate.
    #[tokio::test]
    async fn admin_takeover_requires_force() {
        let (state, _dir) = test_state().await;
        let path = "delta";
        let log = build_test_did_log("scid-delta", "control.test", path).await;

        register_did_atomic(
            &owner_auth("did:example:owner-a"),
            &state,
            path,
            &log,
            false,
        )
        .await
        .unwrap();

        let err = register_did_atomic(&admin_auth("did:example:admin"), &state, path, &log, false)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(ref m) if m.contains("force")));
    }

    /// Admin with force succeeds; caller becomes the new owner; old
    /// owner-index entry is removed; old witness is cleared (was signed
    /// for the prior DID identifier).
    #[tokio::test]
    async fn admin_takeover_with_force_succeeds() {
        let (state, _dir) = test_state().await;
        let path = "epsilon";
        let owner_a = "did:example:owner-a";
        let admin = "did:example:admin";
        let log = build_test_did_log("scid-epsilon", "control.test", path).await;

        register_did_atomic(&owner_auth(owner_a), &state, path, &log, false)
            .await
            .unwrap();
        // Seed a witness file as if the original owner had uploaded one.
        state
            .dids_ks
            .insert_raw(content_witness_key(path), b"prior-witness".to_vec())
            .await
            .unwrap();

        register_did_atomic(&admin_auth(admin), &state, path, &log, true)
            .await
            .expect("admin force takeover should succeed");

        let rec: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
        assert_eq!(rec.owner, admin);
        assert_eq!(rec.version_count, 1, "takeover resets version_count");

        // Old owner-index entry removed; new one present.
        assert!(
            state
                .dids_ks
                .get_raw(owner_key(owner_a, path))
                .await
                .unwrap()
                .is_none(),
            "old owner-index entry must be removed on takeover"
        );
        assert!(
            state
                .dids_ks
                .get_raw(owner_key(admin, path))
                .await
                .unwrap()
                .is_some(),
            "new owner-index entry must be present after takeover"
        );

        // Stale witness cleared.
        assert!(
            state
                .dids_ks
                .get_raw(content_witness_key(path))
                .await
                .unwrap()
                .is_none(),
            "prior witness must be cleared on takeover (signed for prior DID)"
        );
    }

    /// did_log's path component doesn't match the requested slot — rejected
    /// before any storage write.
    #[tokio::test]
    async fn mismatched_did_path_rejected() {
        let (state, _dir) = test_state().await;
        // Log claims path "wrong-path" but request is for path "right-path".
        let log = build_test_did_log("scid-x", "control.test", "wrong-path").await;
        let err = register_did_atomic(
            &owner_auth("did:example:owner"),
            &state,
            "right-path",
            &log,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("path")));
        assert!(
            state
                .dids_ks
                .get_raw(did_key("right-path"))
                .await
                .unwrap()
                .is_none(),
            "no record must be written when validation fails"
        );
    }

    /// did_log claims a different host — claim-jumping prevention.
    #[tokio::test]
    async fn mismatched_did_host_rejected() {
        let (state, _dir) = test_state().await;
        let log = build_test_did_log("scid-x", "other-host.example", "valid-path").await;
        let err = register_did_atomic(
            &owner_auth("did:example:owner"),
            &state,
            "valid-path",
            &log,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("host")));
    }

    // ---- T20b: multi-domain safety check ----

    /// Seed an active domain for tests that exercise the new
    /// multi-domain safety check. Returns the canonical name.
    async fn seed_active_domain(state: &AppState, name: &str) -> String {
        use did_hosting_common::server::domain::{
            create_domain,
            types::{DomainEntry, DomainStatus, DomainUrlScheme},
        };
        let entry = DomainEntry {
            name: name.into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Active,
            created_at: 0,
            default_domain: true,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        };
        create_domain(&state.store, &entry).await.unwrap();
        name.into()
    }

    /// Seed an ACL entry for a caller with an explicit DomainScope.
    async fn seed_caller_acl(
        state: &AppState,
        did: &str,
        role: Role,
        scope: did_hosting_common::server::domain::DomainScope,
    ) {
        use crate::acl::store_acl_entry;
        use did_hosting_common::server::acl::AclEntry;
        let entry = AclEntry {
            did: did.into(),
            role,
            label: None,
            created_at: 0,
            max_total_size: None,
            max_did_count: None,
            domains: scope,
        };
        store_acl_entry(&state.acl_ks, &entry).await.unwrap();
    }

    /// With a domain configured and the caller's ACL scoped to it,
    /// a DID on that domain registers normally.
    #[tokio::test]
    async fn register_with_domain_seeded_owner_scoped_to_matching_host() {
        use did_hosting_common::server::domain::DomainScope;
        let (state, _dir) = test_state().await;
        let owner = "did:example:scoped";
        seed_active_domain(&state, "control.test").await;
        seed_caller_acl(
            &state,
            owner,
            Role::Owner,
            DomainScope::Allowed {
                domains: vec!["control.test".into()],
            },
        )
        .await;

        let did_log = build_test_did_log("scid-ok", "control.test", "alpha").await;
        let result = register_did_atomic(&owner_auth(owner), &state, "alpha", &did_log, false)
            .await
            .expect("scoped owner on matching host must succeed");
        assert_eq!(result.mnemonic, "alpha");
    }

    /// Same domain configured, but the caller's ACL allows only
    /// `domain-a` while the DID is on `domain-b`. The legacy host
    /// validator would already reject this (host != public_url),
    /// but the safety check fires first and returns Forbidden (403)
    /// rather than Validation (400) — distinct error codes are how
    /// the UI tells "we don't serve that domain" from "you can't
    /// post there".
    #[tokio::test]
    async fn register_acl_rejects_host_outside_allowed_scope() {
        use did_hosting_common::server::domain::DomainScope;
        let (state, _dir) = test_state().await;
        let owner = "did:example:scoped";
        // Two active domains: control.test AND domain-b.example.
        seed_active_domain(&state, "control.test").await;
        {
            use did_hosting_common::server::domain::{
                create_domain,
                types::{DomainEntry, DomainStatus, DomainUrlScheme},
            };
            create_domain(
                &state.store,
                &DomainEntry {
                    name: "domain-b.example".into(),
                    label: None,
                    scheme: DomainUrlScheme::Https,
                    status: DomainStatus::Active,
                    created_at: 0,
                    default_domain: false,
                    branding: None,
                    witnesses: None,
                    watchers: None,
                    quota: None,
                    well_known_enabled: false,
                    disabled_at: None,
                    purge_at: None,
                },
            )
            .await
            .unwrap();
        }
        // Caller's ACL only allows control.test.
        seed_caller_acl(
            &state,
            owner,
            Role::Owner,
            DomainScope::Allowed {
                domains: vec!["control.test".into()],
            },
        )
        .await;

        let did_log = build_test_did_log("scid-evil", "domain-b.example", "alpha").await;
        let err = register_did_atomic(&owner_auth(owner), &state, "alpha", &did_log, false)
            .await
            .expect_err("ACL must reject host outside scope");
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "expected Forbidden, got {err:?}"
        );
        // No record written.
        assert!(
            state
                .dids_ks
                .get_raw(did_key("alpha"))
                .await
                .unwrap()
                .is_none(),
            "no record may be written when ACL rejects the host"
        );
    }

    /// `Admin` role short-circuits the ACL scope check — admins can
    /// write to any **active** domain regardless of their ACL
    /// `domains` field.
    #[tokio::test]
    async fn register_admin_can_write_any_active_domain() {
        use did_hosting_common::server::domain::DomainScope;
        let (state, _dir) = test_state().await;
        let admin = "did:example:admin";
        seed_active_domain(&state, "control.test").await;
        seed_caller_acl(
            &state,
            admin,
            Role::Admin,
            DomainScope::Allowed {
                domains: vec!["irrelevant.example".into()],
            },
        )
        .await;

        let did_log = build_test_did_log("scid-admin", "control.test", "alpha").await;
        register_did_atomic(&admin_auth(admin), &state, "alpha", &did_log, false)
            .await
            .expect("admin role overrides ACL domain scope");
    }

    /// Malformed did.jsonl is rejected by `validate_did_jsonl`.
    #[tokio::test]
    async fn invalid_did_log_rejected() {
        let (state, _dir) = test_state().await;
        let err = register_did_atomic(
            &owner_auth("did:example:owner"),
            &state,
            "any-path",
            "not valid jsonl",
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    /// A root did:webvh — `did:webvh:{SCID}:<host>`, no path segments,
    /// resolving at `https://<host>/.well-known/did.jsonl` — registers at
    /// the reserved `.well-known` slot.
    ///
    /// Regression: `register_did_atomic` used to validate `path` with
    /// `validate_custom_path`, which rejects `.well-known` by design (the
    /// leading dot is not in the `[a-z0-9-]` segment charset). An operator
    /// self-hosting their domain therefore could not publish the domain's
    /// own DID through register at all — every attempt came back
    /// `e.p.did.path-invalid`, and no other `path` value works either
    /// (empty is rejected by the dispatcher, and any legal mnemonic would
    /// fail the DID↔path equality check below).
    #[tokio::test]
    async fn register_root_did_at_well_known_as_admin() {
        let (state, _dir) = test_state().await;
        // Empty mnemonic ⇒ root DID for the host.
        let did_log = build_test_did_log("scid-root", "control.test", "").await;

        register_did_atomic(
            &admin_auth("did:example:admin"),
            &state,
            ".well-known",
            &did_log,
            false,
        )
        .await
        .expect("admin may register the root DID at the .well-known slot");

        let record: DidRecord = state
            .dids_ks
            .get(did_key(".well-known"))
            .await
            .unwrap()
            .expect("root slot record written");
        assert_eq!(record.mnemonic, ".well-known");
        assert_eq!(
            record.did_id.as_deref(),
            extract_did_id(&did_log).as_deref(),
            "the root slot must hold the registered root DID"
        );
    }

    /// Root is admin-only, mirroring `create_did`'s carve-out — a domain's
    /// root slot can belong to only one tenant, so an owner-role caller
    /// must not be able to claim it.
    #[tokio::test]
    async fn register_root_did_forbidden_for_non_admin() {
        let (state, _dir) = test_state().await;
        let did_log = build_test_did_log("scid-root", "control.test", "").await;

        let err = register_did_atomic(
            &owner_auth("did:example:owner"),
            &state,
            ".well-known",
            &did_log,
            false,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Forbidden(_)),
            "non-admin root register must be Forbidden, got {err:?}"
        );
    }

    /// The root carve-out is exactly `.well-known` and nothing else — any
    /// other dot-prefixed path still fails the segment charset rules, even
    /// for an admin. Guards against widening `validate_mnemonic` into a
    /// general escape hatch.
    #[tokio::test]
    async fn register_rejects_other_dotted_paths_even_for_admin() {
        let (state, _dir) = test_state().await;
        let did_log = build_test_did_log("scid-dot", "control.test", "hidden").await;

        let err = register_did_atomic(
            &admin_auth("did:example:admin"),
            &state,
            ".hidden",
            &did_log,
            false,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Validation(_)),
            "dotted non-root path must still be rejected, got {err:?}"
        );
    }

    /// Smoke test: the wire request type round-trips with default `force`
    /// and the legacy `did_log` field still parses (T26 backwards-compat).
    #[test]
    fn did_register_request_round_trip_defaults_force_false() {
        let raw = r#"{"path":"alpha","did_log":"line"}"#;
        let req: DidRegisterRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.path, "alpha");
        assert_eq!(req.did_log.as_deref(), Some("line"));
        assert!(!req.force, "force must default to false");
        let (method, payload) = req.resolve().unwrap();
        assert_eq!(method, "webvh");
        assert_eq!(payload, b"line");
    }

    /// Pin the stats-counter behaviour: every successful
    /// `register_did_atomic` advances the aggregate `total_updates` and the
    /// per-DID `last_updated_at`. Without this the dashboards / `MSG_INFO`
    /// response will report zero updates in self-hosted (control-plane-as-
    /// authoritative) deployments. Mirrors did-hosting-server::publish_did's
    /// `record_update` call.
    #[tokio::test]
    async fn register_did_atomic_records_update_stats() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "stats-fresh";
        let did_log = build_test_did_log("scid-stats", "control.test", path).await;

        let before = state.stats_collector.get_aggregate().total_updates;
        register_did_atomic(&owner_auth(owner), &state, path, &did_log, false)
            .await
            .unwrap();
        let after = state.stats_collector.get_aggregate().total_updates;
        assert_eq!(
            after,
            before + 1,
            "fresh atomic register must advance total_updates by 1"
        );

        // A second register by the same owner advances again — the counter
        // tracks log-write operations, not unique DIDs.
        register_did_atomic(&owner_auth(owner), &state, path, &did_log, false)
            .await
            .unwrap();
        let after_two = state.stats_collector.get_aggregate().total_updates;
        assert_eq!(
            after_two,
            after + 1,
            "idempotent re-register must also advance total_updates"
        );
    }

    /// Mirror coverage for the `publish_did` path. Pre-create a slot via
    /// `create_did` (which does NOT bump update stats — it only reserves
    /// the mnemonic), then publish a log against it and assert the counter
    /// only moves on the publish.
    #[tokio::test]
    async fn publish_did_records_update_stats() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "stats-publish";
        let did_log = build_test_did_log("scid-publish", "control.test", path).await;

        // Reserve the slot. create_did is the "request URI" step — it
        // doesn't write log content and shouldn't bump update counters.
        let baseline = state.stats_collector.get_aggregate().total_updates;
        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .unwrap();
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline,
            "create_did is a slot reservation; must NOT count as an update"
        );

        // Publish flips the counter.
        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .unwrap();
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline + 1,
            "publish_did must record an update on success"
        );

        // Republishing advances again.
        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .unwrap();
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline + 2,
            "subsequent publishes must keep advancing total_updates"
        );
    }

    /// F5: the caller's explicit `?domain=` is cross-checked against the DID's
    /// host (a DID's host IS its domain). A mismatch is rejected as
    /// `did-management:unknown_domain`; a match or an omitted domain publishes.
    #[tokio::test]
    async fn publish_cross_checks_explicit_domain_against_did_host() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "domain-xcheck";
        // The DID's host — i.e. its domain — is `control.test`.
        let did_log = build_test_did_log("scid-domain", "control.test", path).await;
        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .unwrap();

        // No domain stated → unchanged behaviour: publishes.
        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .expect("omitted domain still publishes");

        // Matching domain → publishes.
        publish_did(
            &owner_auth(owner),
            &state,
            path,
            &did_log,
            Some("control.test"),
        )
        .await
        .expect("matching domain publishes");

        // Mismatched domain → rejected before the log lands.
        let err = publish_did(
            &owner_auth(owner),
            &state,
            path,
            &did_log,
            Some("evil.example"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("unknown_domain")),
            "mismatched domain must be rejected as unknown_domain, got {err:?}"
        );
    }

    /// Failed publishes (auth denied, validation error, missing slot) must
    /// NOT bump the counter — `record_update` runs only after the storage
    /// commit returns Ok. Pinning this prevents drift if someone moves the
    /// call earlier in the function.
    #[tokio::test]
    async fn failed_publish_does_not_record_update() {
        let (state, _dir) = test_state().await;
        let owner_a = "did:example:owner-a";
        let owner_b = "did:example:owner-b";
        let path = "stats-fail";
        let did_log = build_test_did_log("scid-fail", "control.test", path).await;

        // Reserve as owner-a, then have owner-b try to publish.
        create_did(&owner_auth(owner_a), &state, Some(path), false, None)
            .await
            .unwrap();

        let baseline = state.stats_collector.get_aggregate().total_updates;
        let err = publish_did(&owner_auth(owner_b), &state, path, &did_log, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline,
            "auth-denied publish must NOT record an update"
        );

        // Validation failure on the JSONL body — still no counter movement.
        let err = publish_did(&owner_auth(owner_a), &state, path, "not-jsonl", None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline,
            "validation-failed publish must NOT record an update"
        );
    }

    /// Concurrency: two parallel `register_did_atomic` calls on the same
    /// fresh path serialise via the per-path write lock — exactly one
    /// wins, the other races the lock. Without the lock both could
    /// observe `existing == None`, both build version_count=1 records,
    /// and both commit; the second silently overwrites the first.
    ///
    /// We can't deterministically pick which caller wins (the loser
    /// could be either), but we CAN assert (a) both calls succeed
    /// without panicking, (b) the on-disk record reflects exactly one
    /// of the two callers (not a mash-up), (c) the version_count is 2
    /// (the second call's idempotent re-register bumps it from the
    /// first call's 1).
    #[tokio::test]
    async fn concurrent_register_serialises() {
        let (state, _dir) = test_state().await;
        let owner_a = "did:example:owner-a".to_string();
        let path = "race-path";
        let log_a = build_test_did_log("scid-race", "control.test", path).await;
        let log_b = log_a.clone();

        let auth_a = owner_auth(&owner_a);
        let auth_b = owner_auth(&owner_a); // same owner, different concurrent attempts

        let state_a = state.clone();
        let state_b = state.clone();
        let path_a = path.to_string();
        let path_b = path.to_string();

        let task_a = tokio::spawn(async move {
            register_did_atomic(&auth_a, &state_a, &path_a, &log_a, false).await
        });
        let task_b = tokio::spawn(async move {
            register_did_atomic(&auth_b, &state_b, &path_b, &log_b, false).await
        });

        let r_a = task_a.await.unwrap();
        let r_b = task_b.await.unwrap();
        // Both calls succeed because they're from the same owner — the
        // second is treated as an idempotent re-publish and bumps
        // version_count.
        assert!(
            r_a.is_ok() && r_b.is_ok(),
            "both same-owner registers should succeed; got a={r_a:?}, b={r_b:?}"
        );

        let record: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record present after race");
        assert_eq!(record.owner, owner_a);
        // Two sequential commits via the lock => version_count == 2.
        // Without the lock, the race could land on 1 (both observe
        // None and both write version_count=1).
        assert_eq!(
            record.version_count, 2,
            "both register calls must have committed in sequence; got version_count={}",
            record.version_count
        );
    }

    /// `create_did(..., Some("tenant.example"))` MUST persist the
    /// caller-supplied domain on the DidRecord. This is the bug
    /// b0e2fb11 fixed: previously `RequestUriRequest` had no
    /// `domain` field, every record landed with `domain: ""`, and the
    /// per-domain UI filters / dashboard stats hid the freshly-
    /// created DID until the M-01 backfill sweep next ran. Pinning
    /// the persisted value guards against the next regression in
    /// `request_uri` / `dispatch_did_op` forgetting to thread the
    /// resolver output through.
    #[tokio::test]
    async fn create_did_persists_caller_supplied_domain() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "alpha-domain";

        create_did(
            &owner_auth(owner),
            &state,
            Some(path),
            false,
            Some("tenant.example"),
        )
        .await
        .expect("create_did with domain should succeed");

        let record: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record");
        assert_eq!(
            record.domain, "tenant.example",
            "domain on the DidRecord MUST equal the caller-supplied value"
        );
    }

    /// `create_did(..., None)` MUST leave `domain` empty — the field
    /// is the resolver's responsibility, not a synthetic default.
    /// Older DIDComm paths and tests pass None; the M-01 sweep + the
    /// publish-time backfill (see next test) populate it later.
    #[tokio::test]
    async fn create_did_with_no_domain_leaves_field_empty() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "alpha-no-domain";

        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .expect("create_did without domain should succeed");

        let record: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record");
        assert_eq!(
            record.domain, "",
            "domain on the DidRecord MUST be empty when create_did was called with None"
        );
    }

    /// `publish_did` MUST backfill `record.domain` from the
    /// `did_id`'s host segment when the persisted field is empty —
    /// e.g. for slots created via the older DIDComm `MSG_DID_REQUEST`
    /// path that didn't thread a domain through. Idempotent: a
    /// record whose `domain` is already populated is unchanged.
    #[tokio::test]
    async fn publish_did_backfills_empty_domain_from_did_id() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "alpha-backfill";
        let did_log = build_test_did_log("scid-backfill", "control.test", path).await;

        // Reserve the slot with `domain: None` so the persisted value
        // is empty (mirrors the older DIDComm path's behaviour
        // pre-b0e2fb11).
        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .unwrap();
        let before: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record");
        assert_eq!(before.domain, "", "test precondition: domain starts empty");

        // Publish. The did:webvh log encodes `control.test` as the
        // host, so the backfill should pull it through.
        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .unwrap();
        let after: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record");
        assert_eq!(
            after.domain, "control.test",
            "publish_did must populate domain from the did_id host segment when the persisted value is empty"
        );

        // Subsequent publishes leave the populated value alone —
        // backfill only runs when `record.domain.is_empty()`. Confirm
        // by re-publishing the same log and checking the field
        // didn't change to something else (or get cleared).
        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .unwrap();
        let after_again: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record");
        assert_eq!(
            after_again.domain, "control.test",
            "publish_did backfill must be idempotent — a populated domain stays put"
        );
    }

    // ---- service badge cache (DidRecord.services) ----

    /// An empty slot has no document, so `services` must be `None`
    /// ("unknown"), never `Some(vec![])` ("read it, advertises nothing").
    #[tokio::test]
    async fn create_did_leaves_services_unknown() {
        let (state, _dir) = test_state().await;
        create_did(
            &owner_auth("did:example:owner"),
            &state,
            Some("slot"),
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stored_services(&state, "slot").await, None);
    }

    /// `publish_did` caches the document's services, in document order
    /// (TSP before DIDComm, matching the VTA templates).
    #[tokio::test]
    async fn publish_did_caches_advertised_services() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "with-transports";
        let did_log = build_test_did_log_with_transports("control.test", path, true, true).await;

        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .unwrap();
        assert_eq!(
            stored_services(&state, path).await,
            None,
            "precondition: no document yet"
        );

        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .unwrap();

        assert_eq!(
            stored_services(&state, path).await,
            Some(vec![
                "TSPTransport".to_string(),
                "DIDCommMessaging".to_string()
            ])
        );
    }

    /// A document with no services caches as `Some(vec![])` — we read it and
    /// it advertises nothing — which is distinct from the `None` above.
    #[tokio::test]
    async fn publish_did_caches_empty_services_for_bare_document() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "bare";
        let did_log = build_test_did_log("scid", "control.test", path).await;

        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .unwrap();
        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .unwrap();

        assert_eq!(stored_services(&state, path).await, Some(vec![]));
    }

    /// The cache is *recomputed* on every publish, not filled-if-empty. A
    /// server that stops advertising TSP must lose the badge — a
    /// fill-if-empty implementation would keep showing the stale one.
    #[tokio::test]
    async fn publish_did_retracts_a_dropped_service() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "drops-tsp";

        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .unwrap();

        let both = build_test_did_log_with_transports("control.test", path, true, true).await;
        publish_did(&owner_auth(owner), &state, path, &both, None)
            .await
            .unwrap();
        assert!(
            stored_services(&state, path)
                .await
                .unwrap()
                .contains(&"TSPTransport".to_string()),
            "precondition: TSP advertised"
        );

        // Re-publish a document that advertises DIDComm only.
        let didcomm_only =
            build_test_did_log_with_transports("control.test", path, false, true).await;
        publish_did(&owner_auth(owner), &state, path, &didcomm_only, None)
            .await
            .unwrap();

        assert_eq!(
            stored_services(&state, path).await,
            Some(vec!["DIDCommMessaging".to_string()]),
            "TSPTransport must be retracted once the document stops advertising it"
        );
    }

    /// A legacy record (pre-`services`) self-heals on its next publish. The
    /// M-02 boot sweep normally gets there first; this is the belt-and-braces
    /// path for a record the sweep deferred (unparseable log) or one written
    /// before the sweep ran.
    #[tokio::test]
    async fn publish_did_backfills_services_on_legacy_record() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "legacy";
        let did_log = build_test_did_log_with_transports("control.test", path, true, false).await;

        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .unwrap();
        // Force the on-disk record into the legacy shape.
        let mut rec: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
        rec.services = None;
        state.dids_ks.insert(did_key(path), &rec).await.unwrap();

        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .unwrap();

        assert_eq!(
            stored_services(&state, path).await,
            Some(vec!["TSPTransport".to_string()])
        );
    }

    /// The cached services reach the wire type the DID list renders from,
    /// without `list_dids` reading any log bytes.
    #[tokio::test]
    async fn list_dids_surfaces_cached_services() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "listed";
        let did_log = build_test_did_log_with_transports("control.test", path, true, true).await;

        create_did(&owner_auth(owner), &state, Some(path), false, None)
            .await
            .unwrap();
        publish_did(&owner_auth(owner), &state, path, &did_log, None)
            .await
            .unwrap();

        let entries = list_dids(&owner_auth(owner), &state, None, None, None)
            .await
            .expect("list_dids");
        let entry = entries
            .iter()
            .find(|e| e.mnemonic == path)
            .expect("published DID in list");
        assert_eq!(
            entry.services,
            Some(vec![
                "TSPTransport".to_string(),
                "DIDCommMessaging".to_string()
            ])
        );
    }

    // -----------------------------------------------------------------------
    // Agent names
    // -----------------------------------------------------------------------

    /// A signed did:webvh log whose document claims the given agent names via
    /// `alsoKnownAs`. Each name is written as `<host>/@<name>`, the form
    /// `agent-names` parses and `extract_agent_names` matches on. `host` is the
    /// decoded authority (no port-encoding) so it equals the DID's host.
    async fn build_test_did_log_with_names(host: &str, path: &str, names: &[&str]) -> String {
        let signing = Secret::generate_ed25519(None, None);
        let signing_pub_mb = signing
            .get_public_keymultibase()
            .expect("signing public key multibase");
        let mut doc =
            build_did_document(host, path, &signing_pub_mb, &DidDocumentOptions::default());
        if !names.is_empty() {
            let aka: Vec<String> = names.iter().map(|n| format!("{host}/@{n}")).collect();
            doc["alsoKnownAs"] = serde_json::json!(aka);
        }
        let (_scid, jsonl) = create_log_entry(&doc, &signing)
            .await
            .expect("create_log_entry");
        jsonl
    }

    async fn get_record(state: &AppState, path: &str) -> DidRecord {
        state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record")
    }

    async fn index_target(state: &AppState, domain: &str, name: &str) -> Option<String> {
        state
            .dids_ks
            .get_raw(agent_name_key(domain, name))
            .await
            .unwrap()
            .map(|b| String::from_utf8(b).unwrap())
    }

    /// Register a fresh DID at `path` on host `control.test`, owned by `owner`.
    async fn register_owned(state: &AppState, owner: &str, path: &str) {
        let log = build_test_did_log("scid", "control.test", path).await;
        register_did_atomic(&owner_auth(owner), state, path, &log, false)
            .await
            .expect("register");
    }

    /// Happy path: the document claims the name, so it binds — the entry is
    /// enabled, the index points at the slot, and the version advances.
    #[tokio::test]
    async fn set_agent_name_binds_when_document_claims_it() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-set";
        register_owned(&state, owner, path).await;
        let before = get_record(&state, path).await.version_count;

        let log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        let record = set_agent_name(&owner_auth(owner), &state, path, "alice", &log, None)
            .await
            .expect("set should bind a claimed name");

        assert!(
            record
                .agent_names
                .iter()
                .any(|e| e.name == "alice" && e.enabled),
            "alice must be present and enabled"
        );
        assert_eq!(
            record.version_count,
            before + 1,
            "publish must bump version"
        );
        assert_eq!(
            index_target(&state, "control.test", "alice")
                .await
                .as_deref(),
            Some(path),
            "index must point at the slot"
        );
        // A leading '@' on the argument is tolerated and canonicalised away.
        let record = get_record(&state, path).await;
        assert!(record.agent_names.iter().any(|e| e.name == "alice"));
    }

    /// The security test: a document that does not claim the name is rejected,
    /// and — because the write is one batch — nothing is committed. No orphaned
    /// index entry, no registry entry, no version bump.
    #[tokio::test]
    async fn set_agent_name_rejects_and_commits_nothing_on_mismatch() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-mismatch";
        register_owned(&state, owner, path).await;
        let before = get_record(&state, path).await.version_count;

        // Document claims a *different* name than the one requested.
        let log = build_test_did_log_with_names("control.test", path, &["bob"]).await;
        let err = set_agent_name(&owner_auth(owner), &state, path, "alice", &log, None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::AgentName(AgentNameError::AlsoKnownAsMismatch)
        ));

        let record = get_record(&state, path).await;
        assert!(
            record.agent_names.is_empty(),
            "no registry entry may be written on a rejected set"
        );
        assert_eq!(
            record.version_count, before,
            "a rejected set must not advance the version"
        );
        assert_eq!(
            index_target(&state, "control.test", "alice").await,
            None,
            "no index entry may leak on a rejected set (atomicity)"
        );
    }

    /// A reserved name is refused up front with the typed error, before any
    /// document work.
    #[tokio::test]
    async fn set_agent_name_rejects_reserved() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-reserved";
        register_owned(&state, owner, path).await;

        let log = build_test_did_log_with_names("control.test", path, &["admin"]).await;
        let err = set_agent_name(&owner_auth(owner), &state, path, "admin", &log, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::AgentName(AgentNameError::Reserved)));
    }

    /// A name bound to one DID cannot be taken by another on the same domain;
    /// the same DID re-setting it is an idempotent refresh.
    #[tokio::test]
    async fn set_agent_name_collision_is_taken_but_same_owner_refreshes() {
        let (state, _dir) = test_state().await;
        let owner_a = "did:example:a";
        let owner_b = "did:example:b";
        register_owned(&state, owner_a, "slot-a").await;
        register_owned(&state, owner_b, "slot-b").await;

        let log_a = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
        set_agent_name(
            &owner_auth(owner_a),
            &state,
            "slot-a",
            "alice",
            &log_a,
            None,
        )
        .await
        .expect("first bind");

        // A different DID claiming the same name on the same domain is taken.
        let log_b = build_test_did_log_with_names("control.test", "slot-b", &["alice"]).await;
        let err = set_agent_name(
            &owner_auth(owner_b),
            &state,
            "slot-b",
            "alice",
            &log_b,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::AgentName(AgentNameError::Taken)));

        // The original owner re-setting is fine (idempotent refresh).
        let log_a2 = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
        set_agent_name(
            &owner_auth(owner_a),
            &state,
            "slot-a",
            "alice",
            &log_a2,
            None,
        )
        .await
        .expect("idempotent re-set by the same owner");
        assert_eq!(
            index_target(&state, "control.test", "alice")
                .await
                .as_deref(),
            Some("slot-a")
        );
    }

    /// Seed a `DidRecord` directly on an arbitrary host. `register_did_atomic`
    /// pins the DID host to the server's configured host, so multi-domain
    /// tests seed the record rather than register it. The name ops themselves
    /// carry no such host-pin — they scope by the record's domain.
    async fn seed_record_on_host(state: &AppState, owner: &str, path: &str, host: &str) {
        let record = DidRecord {
            owner: owner.to_string(),
            mnemonic: path.to_string(),
            created_at: 0,
            updated_at: 0,
            version_count: 1,
            did_id: Some(format!("did:webvh:seed:{host}:{path}")),
            content_size: 0,
            disabled: false,
            deleted_at: None,
            method: "webvh".to_string(),
            domain: host.to_string(),
            services: None,
            agent_names: Vec::new(),
        };
        state
            .dids_ks
            .insert(did_key(path), &record)
            .await
            .expect("seed record");
    }

    /// The same name on two different domains does not collide — names are
    /// domain-scoped by the `name:{domain}:{name}` index key.
    #[tokio::test]
    async fn set_agent_name_is_domain_scoped() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";

        for (host, path) in [("one.example", "slot-one"), ("two.example", "slot-two")] {
            seed_record_on_host(&state, owner, path, host).await;
            let named = build_test_did_log_with_names(host, path, &["alice"]).await;
            set_agent_name(&owner_auth(owner), &state, path, "alice", &named, None)
                .await
                .expect("bind alice on this domain");
        }

        assert_eq!(
            index_target(&state, "one.example", "alice")
                .await
                .as_deref(),
            Some("slot-one")
        );
        assert_eq!(
            index_target(&state, "two.example", "alice")
                .await
                .as_deref(),
            Some("slot-two")
        );
    }

    /// A non-owner (non-admin) cannot bind a name.
    #[tokio::test]
    async fn set_agent_name_requires_owner() {
        let (state, _dir) = test_state().await;
        register_owned(&state, "did:example:owner", "slot-auth").await;

        let log = build_test_did_log_with_names("control.test", "slot-auth", &["alice"]).await;
        let err = set_agent_name(
            &owner_auth("did:example:intruder"),
            &state,
            "slot-auth",
            "alice",
            &log,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    /// Disable parks a name: the entry stays (disabled) and the index is kept
    /// so the name remains reserved. The submitting document must drop the
    /// name.
    #[tokio::test]
    async fn disable_agent_name_parks_but_keeps_reservation() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-disable";
        register_owned(&state, owner, path).await;

        let set_log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        set_agent_name(&owner_auth(owner), &state, path, "alice", &set_log, None)
            .await
            .expect("set");

        // Disabling with a document that STILL claims the name is a mismatch.
        let still_claims = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        let err = disable_agent_name(
            &owner_auth(owner),
            &state,
            path,
            "alice",
            &still_claims,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            AppError::AgentName(AgentNameError::AlsoKnownAsMismatch)
        ));

        // Disabling with a document that drops the name parks it.
        let dropped = build_test_did_log_with_names("control.test", path, &[]).await;
        let record = disable_agent_name(&owner_auth(owner), &state, path, "alice", &dropped, None)
            .await
            .expect("disable");
        assert!(
            record
                .agent_names
                .iter()
                .any(|e| e.name == "alice" && !e.enabled),
            "alice must remain present but disabled"
        );
        assert_eq!(
            index_target(&state, "control.test", "alice")
                .await
                .as_deref(),
            Some(path),
            "a parked name keeps its index entry (stays reserved)"
        );

        // Disabling again is a no-op error.
        let dropped2 = build_test_did_log_with_names("control.test", path, &[]).await;
        let err = disable_agent_name(&owner_auth(owner), &state, path, "alice", &dropped2, None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::AgentName(AgentNameError::AlreadyDisabled)
        ));
    }

    /// Enable resumes a parked name; the document must claim it again.
    #[tokio::test]
    async fn enable_agent_name_resumes_a_parked_name() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-enable";
        register_owned(&state, owner, path).await;

        let set_log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        set_agent_name(&owner_auth(owner), &state, path, "alice", &set_log, None)
            .await
            .expect("set");

        // Enabling an already-enabled name is refused.
        let claims = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        let err = enable_agent_name(&owner_auth(owner), &state, path, "alice", &claims, None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::AgentName(AgentNameError::NotDisabled)
        ));

        // Park it, then re-enable with a document that claims it again.
        let dropped = build_test_did_log_with_names("control.test", path, &[]).await;
        disable_agent_name(&owner_auth(owner), &state, path, "alice", &dropped, None)
            .await
            .expect("disable");
        let reclaim = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        let record = enable_agent_name(&owner_auth(owner), &state, path, "alice", &reclaim, None)
            .await
            .expect("enable");
        assert!(
            record
                .agent_names
                .iter()
                .any(|e| e.name == "alice" && e.enabled)
        );
    }

    /// Enabling a name that was never bound is a not-found.
    #[tokio::test]
    async fn enable_agent_name_unknown_is_not_found() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-enable-unknown";
        register_owned(&state, owner, path).await;

        let claims = build_test_did_log_with_names("control.test", path, &["ghost"]).await;
        let err = enable_agent_name(&owner_auth(owner), &state, path, "ghost", &claims, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::AgentName(AgentNameError::NotFound)));
    }

    /// Remove releases a name: the entry and the index entry both go, freeing
    /// the name for anyone to reclaim. The document must drop the name.
    #[tokio::test]
    async fn remove_agent_name_releases_the_name() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-remove";
        register_owned(&state, owner, path).await;

        let set_log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        set_agent_name(&owner_auth(owner), &state, path, "alice", &set_log, None)
            .await
            .expect("set");

        // Removing with a document that still claims the name is a mismatch.
        let still_claims = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        let err = remove_agent_name(
            &owner_auth(owner),
            &state,
            path,
            "alice",
            &still_claims,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            AppError::AgentName(AgentNameError::AlsoKnownAsMismatch)
        ));

        // Removing with a document that drops it releases the name.
        let dropped = build_test_did_log_with_names("control.test", path, &[]).await;
        let record = remove_agent_name(&owner_auth(owner), &state, path, "alice", &dropped, None)
            .await
            .expect("remove");
        assert!(
            !record.agent_names.iter().any(|e| e.name == "alice"),
            "alice must be gone from the registry"
        );
        assert_eq!(
            index_target(&state, "control.test", "alice").await,
            None,
            "the index entry must be retired so the name is free"
        );

        // Removing again is not-found.
        let dropped2 = build_test_did_log_with_names("control.test", path, &[]).await;
        let err = remove_agent_name(&owner_auth(owner), &state, path, "alice", &dropped2, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::AgentName(AgentNameError::NotFound)));
    }

    /// Availability check: reserved → unavailable+reserved; free → available;
    /// bound → unavailable; malformed → error.
    #[tokio::test]
    async fn check_agent_name_reports_availability() {
        let (state, _dir) = test_state().await;

        // A reserved name is unavailable but flagged reserved (not an error).
        let r = check_agent_name(&state, "control.test", "admin")
            .await
            .unwrap();
        assert!(!r.available && r.reserved);

        // A free, well-formed name is available.
        let r = check_agent_name(&state, "control.test", "alice")
            .await
            .unwrap();
        assert!(r.available && !r.reserved);

        // Once bound, it is no longer available (and not reserved).
        let owner = "did:example:owner";
        register_owned(&state, owner, "slot-chk").await;
        let log = build_test_did_log_with_names("control.test", "slot-chk", &["alice"]).await;
        set_agent_name(&owner_auth(owner), &state, "slot-chk", "alice", &log, None)
            .await
            .unwrap();
        let r = check_agent_name(&state, "control.test", "alice")
            .await
            .unwrap();
        assert!(!r.available && !r.reserved);

        // A different domain is unaffected — availability is domain-scoped.
        let r = check_agent_name(&state, "other.test", "alice")
            .await
            .unwrap();
        assert!(r.available);

        // A grammatically invalid name is a client error, not "unavailable".
        assert!(check_agent_name(&state, "control.test", "a").await.is_err());
    }

    // -----------------------------------------------------------------------
    // Registry reconciliation on plain publish (the control plane is the
    // source of record for names, not just the explicit agent-name ops).
    // -----------------------------------------------------------------------

    /// A name bound by a *plain publish* (edit alsoKnownAs, no `set` call) is
    /// registered — enabled entry + index — and can then be parked. This is the
    /// integration fix: the UI binds via publish and parks via the registry op,
    /// which previously failed with `NotFound`.
    #[tokio::test]
    async fn publish_registers_a_claimed_name_so_park_works() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-recon";
        register_owned(&state, owner, path).await;

        // Simulate the UI bind: publish a version that claims @alice.
        let bind = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        publish_did(&owner_auth(owner), &state, path, &bind, None)
            .await
            .expect("publish");
        let rec = get_record(&state, path).await;
        assert!(
            rec.agent_names
                .iter()
                .any(|e| e.name == "alice" && e.enabled),
            "a name claimed by a plain publish must be registered enabled"
        );
        assert_eq!(
            index_target(&state, "control.test", "alice")
                .await
                .as_deref(),
            Some(path),
            "plain publish must write the name index"
        );

        // Parking it now succeeds (previously NotFound — the bug).
        let park = build_test_did_log_with_names("control.test", path, &[]).await;
        let rec = disable_agent_name(&owner_auth(owner), &state, path, "alice", &park, None)
            .await
            .expect("park a publish-bound name");
        assert!(
            rec.agent_names
                .iter()
                .any(|e| e.name == "alice" && !e.enabled)
        );
    }

    /// A publish that drops a previously-served name releases it (entry + index
    /// gone) — served state follows the signed document.
    #[tokio::test]
    async fn publish_releases_a_dropped_name() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-rel";
        register_owned(&state, owner, path).await;

        let bind = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        publish_did(&owner_auth(owner), &state, path, &bind, None)
            .await
            .unwrap();
        let drop = build_test_did_log_with_names("control.test", path, &[]).await;
        publish_did(&owner_auth(owner), &state, path, &drop, None)
            .await
            .unwrap();

        let rec = get_record(&state, path).await;
        assert!(!rec.agent_names.iter().any(|e| e.name == "alice"));
        assert_eq!(index_target(&state, "control.test", "alice").await, None);
    }

    /// A parked (disabled) name is NOT collateral damage of a later plain
    /// publish that doesn't claim it — the reservation is held even though the
    /// document omits the name.
    #[tokio::test]
    async fn publish_preserves_a_parked_name() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-park";
        register_owned(&state, owner, path).await;

        let bind = build_test_did_log_with_names("control.test", path, &["alice"]).await;
        publish_did(&owner_auth(owner), &state, path, &bind, None)
            .await
            .unwrap();
        let park = build_test_did_log_with_names("control.test", path, &[]).await;
        disable_agent_name(&owner_auth(owner), &state, path, "alice", &park, None)
            .await
            .unwrap();

        // Some later, unrelated publish (still not claiming alice).
        let other = build_test_did_log_with_names("control.test", path, &[]).await;
        publish_did(&owner_auth(owner), &state, path, &other, None)
            .await
            .unwrap();

        let rec = get_record(&state, path).await;
        assert!(
            rec.agent_names
                .iter()
                .any(|e| e.name == "alice" && !e.enabled),
            "a parked name survives a plain publish that omits it"
        );
        assert_eq!(
            index_target(&state, "control.test", "alice")
                .await
                .as_deref(),
            Some(path),
            "a parked name keeps its index reservation"
        );
    }

    // -----------------------------------------------------------------------
    // Agent names: the publish path applies the same preconditions as `set`
    //
    // Reconciling the registry from `alsoKnownAs` must not become a way around
    // the checks the explicit verb makes. Each of these mirrors a `set_*` test
    // above, driven through a plain publish instead.
    // -----------------------------------------------------------------------

    /// `set` refuses a reserved name; a publish claiming one must too, or
    /// `@admin` is a one-`PUT` phishing primitive.
    #[tokio::test]
    async fn publish_cannot_capture_a_reserved_name() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-pub-reserved";
        register_owned(&state, owner, path).await;
        let before = get_record(&state, path).await.version_count;

        let log = build_test_did_log_with_names("control.test", path, &["admin"]).await;
        let err = publish_did(&owner_auth(owner), &state, path, &log, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::AgentName(AgentNameError::Reserved)),
            "expected Reserved, got {err:?}"
        );

        assert_eq!(
            index_target(&state, "control.test", "admin").await,
            None,
            "a refused publish must not write the index"
        );
        assert_eq!(
            get_record(&state, path).await.version_count,
            before,
            "a refused publish must not advance the version"
        );
    }

    /// The hijack. Layer-1 cannot catch this one: after the overwrite the
    /// hijacker's document genuinely claims the name and the index genuinely
    /// points at them, so a resolver's `alsoKnownAs` round-trip passes and the
    /// victim's name simply stops resolving. It has to be refused here.
    #[tokio::test]
    async fn publish_cannot_hijack_a_name_held_by_another_did() {
        let (state, _dir) = test_state().await;
        let owner_a = "did:example:a";
        let owner_b = "did:example:b";
        register_owned(&state, owner_a, "slot-a").await;
        register_owned(&state, owner_b, "slot-b").await;

        let log_a = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
        publish_did(&owner_auth(owner_a), &state, "slot-a", &log_a, None)
            .await
            .expect("owner A binds alice");

        // B publishes a document claiming A's name.
        let log_b = build_test_did_log_with_names("control.test", "slot-b", &["alice"]).await;
        let err = publish_did(&owner_auth(owner_b), &state, "slot-b", &log_b, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::AgentName(AgentNameError::Taken)),
            "expected Taken, got {err:?}"
        );

        assert_eq!(
            index_target(&state, "control.test", "alice")
                .await
                .as_deref(),
            Some("slot-a"),
            "the name must still resolve to its holder"
        );
        assert!(
            get_record(&state, "slot-a")
                .await
                .agent_names
                .iter()
                .any(|e| e.name == "alice" && e.enabled),
            "the holder's registry entry must be untouched"
        );
        assert!(
            !get_record(&state, "slot-b")
                .await
                .agent_names
                .iter()
                .any(|e| e.name == "alice"),
            "the hijacker must not end up registered"
        );

        // The control: the holder re-publishing its own name is not a
        // collision, it is a refresh.
        publish_did(&owner_auth(owner_a), &state, "slot-a", &log_a, None)
            .await
            .expect("re-publishing one's own name must still work");
    }

    /// Parking deliberately keeps the reservation, so a parked name is exactly
    /// what an opportunist would try to take — `disable` holds the index for
    /// this reason, and the publish path must honour it.
    #[tokio::test]
    async fn publish_cannot_hijack_a_parked_name() {
        let (state, _dir) = test_state().await;
        let owner_a = "did:example:a";
        let owner_b = "did:example:b";
        register_owned(&state, owner_a, "slot-a").await;
        register_owned(&state, owner_b, "slot-b").await;

        let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
        publish_did(&owner_auth(owner_a), &state, "slot-a", &bind, None)
            .await
            .unwrap();
        let park = build_test_did_log_with_names("control.test", "slot-a", &[]).await;
        disable_agent_name(&owner_auth(owner_a), &state, "slot-a", "alice", &park, None)
            .await
            .expect("park");

        let log_b = build_test_did_log_with_names("control.test", "slot-b", &["alice"]).await;
        let err = publish_did(&owner_auth(owner_b), &state, "slot-b", &log_b, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::AgentName(AgentNameError::Taken)),
            "expected Taken, got {err:?}"
        );
        assert!(
            get_record(&state, "slot-a")
                .await
                .agent_names
                .iter()
                .any(|e| e.name == "alice" && !e.enabled),
            "the parked reservation must survive the attempt"
        );
    }

    /// A fresh slot is the easiest place to try a capture — nothing else about
    /// registering constrains what the submitted document may claim.
    #[tokio::test]
    async fn register_cannot_capture_a_held_or_reserved_name() {
        let (state, _dir) = test_state().await;
        let owner_a = "did:example:a";
        let owner_b = "did:example:b";
        register_owned(&state, owner_a, "slot-a").await;
        let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
        publish_did(&owner_auth(owner_a), &state, "slot-a", &bind, None)
            .await
            .unwrap();

        // Register a brand-new slot whose first document claims A's name.
        let log_b = build_test_did_log_with_names("control.test", "slot-new", &["alice"]).await;
        let err = register_did_atomic(&owner_auth(owner_b), &state, "slot-new", &log_b, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::AgentName(AgentNameError::Taken)),
            "expected Taken, got {err:?}"
        );
        assert_eq!(
            index_target(&state, "control.test", "alice")
                .await
                .as_deref(),
            Some("slot-a"),
        );

        // …and the same for a reserved name on a fresh slot.
        let log_r = build_test_did_log_with_names("control.test", "slot-res", &["support"]).await;
        let err = register_did_atomic(&owner_auth(owner_b), &state, "slot-res", &log_r, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::AgentName(AgentNameError::Reserved)),
            "expected Reserved, got {err:?}"
        );
    }

    /// `AgentName::parse` is far laxer than our grammar — it accepts uppercase,
    /// single characters, dots. Such an entry is unserveable (the resolve route
    /// re-validates and 404s), so it is skipped, not refused: failing the
    /// publish would break documents whose `alsoKnownAs` was never meant as an
    /// agent name in our sense.
    #[tokio::test]
    async fn publish_skips_an_unserveable_name_instead_of_failing() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "slot-lax";
        register_owned(&state, owner, path).await;

        // "Bob" is a well-formed agent-name URI but not a valid name here.
        let log = build_test_did_log_with_names("control.test", path, &["Bob", "alice"]).await;
        publish_did(&owner_auth(owner), &state, path, &log, None)
            .await
            .expect("an unserveable entry must not fail the publish");

        let rec = get_record(&state, path).await;
        assert!(
            rec.agent_names.iter().any(|e| e.name == "alice"),
            "the valid name still registers"
        );
        assert!(
            !rec.agent_names.iter().any(|e| e.name == "Bob"),
            "the invalid one must not enter the registry"
        );
        assert_eq!(
            index_target(&state, "control.test", "Bob").await,
            None,
            "nor the index"
        );
    }

    /// Releasing retires the index only while it still points here. A registry
    /// entry left over from before the guards existed must not become a way to
    /// delete the current holder's index.
    #[tokio::test]
    async fn publish_release_does_not_retire_another_dids_index() {
        let (state, _dir) = test_state().await;
        let owner_a = "did:example:a";
        let owner_b = "did:example:b";
        register_owned(&state, owner_a, "slot-a").await;
        register_owned(&state, owner_b, "slot-b").await;

        // A holds alice legitimately.
        let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
        publish_did(&owner_auth(owner_a), &state, "slot-a", &bind, None)
            .await
            .unwrap();

        // B's record carries a stale enabled entry for alice (the state an
        // earlier hijack would have left behind), while the index points at A.
        let mut rec_b = get_record(&state, "slot-b").await;
        rec_b.agent_names.push(AgentNameEntry {
            name: "alice".to_string(),
            enabled: true,
            created_at: 0,
        });
        state
            .dids_ks
            .insert(did_key("slot-b"), &rec_b)
            .await
            .unwrap();

        // B publishes without claiming alice: its own stale entry goes, but the
        // index belongs to A and must survive.
        let drop = build_test_did_log_with_names("control.test", "slot-b", &[]).await;
        publish_did(&owner_auth(owner_b), &state, "slot-b", &drop, None)
            .await
            .unwrap();

        assert!(
            !get_record(&state, "slot-b")
                .await
                .agent_names
                .iter()
                .any(|e| e.name == "alice"),
            "B drops its stale entry"
        );
        assert_eq!(
            index_target(&state, "control.test", "alice")
                .await
                .as_deref(),
            Some("slot-a"),
            "A's index entry must survive B's release"
        );
    }
}

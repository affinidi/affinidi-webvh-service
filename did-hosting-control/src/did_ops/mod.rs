//! DID management business logic for the control plane.
//!
//! The control plane is the source of truth for all DIDs. Functions here
//! operate on the control plane's `dids` keyspace and use the shared types
//! from `did-hosting-common::did_ops`.
//!
//! This module holds the helpers every operation shares; the operations live
//! in submodules and are re-exported here:
//!
//! - `register` — reserve a slot, the atomic claim-and-publish, and the
//!   front half every new-version publish shares;
//! - `agent_names` — the agent-name registry: reconcile, locks and verbs;
//! - `quota` — per-account count and size limits;
//! - `lifecycle` — read, suspend and delete a slot;
//! - `owner` — owner transfers and offers;
//! - `list` — the paged listing;
//! - `rollback` — rolling a did:webvh log back;
//! - `witness` — storing witness proofs;
//! - `resolve` — agent name to DID, and back.

use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::did_index;
use did_hosting_common::server::error::ValidationKind;
use did_hosting_common::server::mnemonic::validate_mnemonic;
use tracing::warn;

// What the test modules reach through `super::*`.
#[cfg(test)]
use did_hosting_common::did_ops::{
    AgentNameEntry, agent_name_key, content_log_key, content_witness_key, owner_key,
};
#[cfg(test)]
use did_hosting_common::server::error::AgentNameError;
#[cfg(test)]
use tracing::info;

use crate::auth::AuthClaims;
use crate::server::{AppState, CacheChange};
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::store::KeyspaceHandle;

mod agent_names;
mod lifecycle;
mod list;
mod owner;
mod quota;
mod register;
mod resolve;
mod rollback;
mod witness;

pub use agent_names::{
    AgentNameAvailability, AgentNameState, check_agent_name, list_agent_names, remove_agent_name,
    update_agent_name,
};
pub use lifecycle::{delete_did, get_did_info, get_raw_log, set_did_disabled};
pub use list::{ListFilter, ListPage, list_dids_page, owner_mnemonics_on_domain};
pub use owner::{
    OWNER_TRANSFER_OFFER_TTL_SECS, OwnerChange, OwnerChangeError, TransferOffer, change_did_owner,
};
pub use register::{check_name, create_did, register_did_atomic};
pub use resolve::{
    MAX_RESOLVE_DIDS, resolve_agent_name_to_did, resolve_agent_names, resolve_did_or_agent_name,
};
pub use rollback::rollback_did_to;
pub use witness::upload_witness;

// The tests reach the submodules' crate-private helpers through `super::*`.
#[cfg(test)]
use self::{agent_names::*, list::*, quota::*, register::*};

/// Evict what resolution cached about `mnemonic` (its log, witness file
/// and record), if this process also serves resolution from the same store
/// (the unified daemon).
///
/// Call this after every commit that changes or removes `content_log_key`,
/// `content_witness_key`, or the record's `disabled`/`deleted_at`/`did_id`
/// — create (replacing a slot), register, publish, agent-name set/remove,
/// witness publish, disable, rollback, delete. A
/// no-op for a standalone control plane; see `AppState::cache_invalidate`'s
/// doc.
fn invalidate_cached_content(state: &AppState, mnemonic: &str) {
    if let Some(invalidate) = &state.cache_invalidate {
        invalidate(CacheChange::Did(mnemonic));
    }
}

/// Run the multi-domain safety check before any storage write on an
/// inbound create / publish.
///
/// Looks up the caller's `AclEntry` from `state.acl_ks` and delegates
/// to [`did_hosting_common::server::domain::
/// assert_did_host_allowed_when_domains_configured`] — which is
/// permissive when the `domains` keyspace is empty (legacy / test
/// state) and strict otherwise.
///
/// Pulled out as a helper so `register_did_atomic` and
/// [`prepare_republish`] can share the call without duplicating the ACL
/// lookup.
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
    // claims). That matches the legacy behaviour, before domain scoping, where no
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

/// Cross-check a caller's explicit domain against the host of the DID it is
/// publishing (a DID's host IS its domain).
///
/// The VTA re-sends the domain it intends on `did/register` and on publish to
/// catch a misconfigured caller before the log lands on the wrong tenant's
/// slot, and documents a `did-management:unknown_domain` rejection when the
/// two disagree (R3.6: a safety parameter the client sends must be enforced,
/// never accepted and ignored). An absent or empty domain means "no explicit
/// claim" and passes. Compared in the decoded form `extract_did_host`
/// returns, case-insensitively, as a hostname is.
fn ensure_requested_domain_matches_did(
    request_domain: Option<&str>,
    did_id: &str,
) -> Result<(), AppError> {
    let Some(requested) = request_domain.filter(|d| !d.is_empty()) else {
        return Ok(());
    };
    let host = did_hosting_common::server::domain::extract_did_host(did_id)?;
    if !requested.eq_ignore_ascii_case(&host) {
        return Err(AppError::validation(
            ValidationKind::UnknownDomain,
            format!(
                "did-management:unknown_domain — requested domain `{requested}` does \
                 not match the DID's host `{host}`",
            ),
        ));
    }
    Ok(())
}

// Re-export for convenience
pub use did_hosting_common::did_ops::{
    extract_did_id, extract_log_metadata, extract_service_types,
};

// ---------------------------------------------------------------------------
// JSONL validation (wraps the common version with AppError)
// ---------------------------------------------------------------------------

/// Tag a failed publication with `AppError::invalid(InvalidLog)` so the
/// DIDComm dispatcher emits `e.p.did.invalid-log`.
///
/// The tag is wire contract, not cosmetics: clients branch on that code to
/// tell "your DID data did not verify" from "you are not the owner" or "that
/// domain is not yours". It applies to every method — a webvh chain failure
/// (parse, signature, parameter transition, post-deactivation tamper) and a
/// webs key-event-log failure (SAID, digest chain, pre-rotation, witness
/// receipts) are the same answer to the caller: the content you published does
/// not verify.
fn publication_error(e: did_hosting_common::method::MethodError) -> AppError {
    AppError::validation(ValidationKind::InvalidLog, e.to_string())
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Validate the path of an operation on an existing slot.
///
/// The stored record decides the grammar, as on the publish path: a did:webs
/// slot ends in its identifier's AID, case-sensitive base64url, which the
/// shared lowercase-only grammar rejects, so only a slot already recorded as
/// did:webs is accepted under `validate_webs_mnemonic`. Reading the method
/// from the record rather than from anything the caller submits means a
/// request cannot pick the looser grammar for itself. A path the shared
/// grammar accepts needs no storage read.
pub(crate) async fn validate_slot_mnemonic(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    let shared = validate_mnemonic(mnemonic);
    if shared.is_ok()
        || did_hosting_common::server::mnemonic::validate_webs_mnemonic(mnemonic).is_err()
    {
        return shared;
    }
    let record = dids_ks.get::<DidRecord>(did_key(mnemonic)).await?;
    if record
        .as_ref()
        .is_some_and(|r| is_webs_record_for(r, mnemonic))
    {
        Ok(())
    } else {
        shared
    }
}

/// Whether `record` is a `did:webs` record held at `mnemonic`: the method
/// says so, the record names this same path, and its identifier is a
/// `did:webs` whose final segment is the path's last segment (the AID).
/// The webs grammar is chosen only when all three agree, so a record whose
/// method field disagrees with what it holds never widens the path rules.
fn is_webs_record_for(record: &DidRecord, mnemonic: &str) -> bool {
    let aid = mnemonic.rsplit('/').next().unwrap_or(mnemonic);
    record.method == "webs"
        && record.mnemonic == mnemonic
        && record
            .did_id
            .as_deref()
            .is_some_and(|d| d.starts_with("did:webs:") && d.rsplit(':').next() == Some(aid))
}

/// Load a DID record and verify the caller is the owner (or admin).
async fn get_authorized_record(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    auth: &AuthClaims,
) -> Result<DidRecord, AppError> {
    use did_hosting_common::server::acl::Role;

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

/// Stage the derived rows ([`did_index`]: the owner's usage counter and the
/// domain index) that writing `new` over `old` changes, into `batch`. Call it
/// last, just before the commit, and hold the returned guards through it.
async fn stage_index(
    state: &AppState,
    batch: &mut did_hosting_common::server::store::WriteBatch,
    old: Option<&DidRecord>,
    new: Option<&DidRecord>,
) -> Result<Vec<did_hosting_common::server::path_locks::PathGuard>, AppError> {
    did_index::stage_record_change(batch, &state.dids_ks, Some(&state.path_locks), old, new).await
}

/// Refuse a path no slot can have before taking its lock, so a malformed
/// path does not add an entry to the lock map. Accepts either grammar —
/// [`prepare_republish`] applies the one the stored record calls for once the
/// lock is held — and reports the shared grammar's error when both fail.
fn validate_slot_path_shape(mnemonic: &str) -> Result<(), AppError> {
    validate_mnemonic(mnemonic).or_else(|e| {
        did_hosting_common::server::mnemonic::validate_webs_mnemonic(mnemonic).map_err(|_| e)
    })
}

/// Cross-check a caller's explicit domain against the slot's own domain.
///
/// A DID's host IS its domain, so a caller naming a different one is either
/// misconfigured or reaching for another tenant's slot — reject before acting
/// rather than silently ignoring the parameter. Prefers the persisted
/// `record.domain`; falls back to the DID's embedded host for legacy slots
/// that never had a domain resolved, and passes when neither is known (an
/// un-domained install has nothing to compare against).
pub(crate) fn ensure_slot_domain_matches(
    record: &DidRecord,
    request_domain: Option<&str>,
) -> Result<(), AppError> {
    let Some(requested) = request_domain.filter(|d| !d.is_empty()) else {
        return Ok(());
    };
    let slot_domain = if !record.domain.is_empty() {
        record.domain.clone()
    } else {
        record
            .did_id
            .as_deref()
            .and_then(|d| did_hosting_common::server::domain::extract_did_host(d).ok())
            .unwrap_or_default()
    };
    if !slot_domain.is_empty() && !requested.eq_ignore_ascii_case(&slot_domain) {
        return Err(AppError::validation(
            ValidationKind::UnknownDomain,
            format!(
                "did-management:unknown_domain — requested domain `{requested}` does \
             not match the slot's domain `{slot_domain}`",
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod test_helpers;

#[cfg(test)]
#[path = "agent_name_reconcile_tests.rs"]
mod agent_name_reconcile_tests;
#[cfg(test)]
#[path = "agent_name_tests.rs"]
mod agent_name_tests;
#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "list_tests.rs"]
mod list_tests;
#[cfg(test)]
#[path = "register_tests.rs"]
mod register_tests;
#[cfg(test)]
#[path = "webs_record_tests.rs"]
mod webs_record_tests;
#[cfg(all(test, feature = "method-webs"))]
#[path = "webs_register_tests.rs"]
mod webs_register_tests;
#[cfg(test)]
#[path = "witness_tests.rs"]
mod witness_tests;

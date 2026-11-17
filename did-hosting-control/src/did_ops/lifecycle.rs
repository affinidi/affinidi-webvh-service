//! Reading a slot ([`get_did_info`], [`get_raw_log`]), suspending and
//! resuming it ([`set_did_disabled`]), and deleting it ([`delete_did`]).

use did_hosting_common::did_ops::{
    DidRecord, LogMetadata, content_log_key, content_witness_key, did_key, owner_key,
};
use did_hosting_common::server::agent_name_index;
use tracing::{debug, info, warn};

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;

use super::agent_names::lock_agent_names;
use super::owner::transfer_offer_key;
use super::{
    check_did_host_safety, ensure_slot_domain_matches, extract_log_metadata, get_authorized_record,
    invalidate_cached_content, stage_index, validate_slot_mnemonic,
};

/// Get detailed information about a DID.
pub async fn get_did_info(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<(DidRecord, Option<LogMetadata>), AppError> {
    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    // The metadata is read from a did:webvh log's last line. A did:webs
    // slot stores a key event stream, which has none of those fields.
    let stored_log = if record.method == "webs" {
        None
    } else {
        state.dids_ks.get_raw(content_log_key(mnemonic)).await?
    };
    let log_metadata = match stored_log {
        Some(bytes) => {
            let content = String::from_utf8(bytes).unwrap_or_default();
            Some(extract_log_metadata(&content))
        }
        None => None,
    };

    debug!(did = %auth.did, mnemonic = %mnemonic, "DID info retrieved from control plane");

    Ok((record, log_metadata))
}

/// Get the raw JSONL content for a DID log as a plain string.
pub async fn get_raw_log(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<String, AppError> {
    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    String::from_utf8(bytes).map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))
}

/// Delete a DID and all its associated data.
pub async fn delete_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    request_domain: Option<&str>,
) -> Result<Option<String>, AppError> {
    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;
    // The per-path write lock, held from the read through the commit: the
    // record is re-read under it, so the owner-index entry removed is the
    // current owner's even if a transfer committed just before.
    let _path_guard = state.path_locks.guard(mnemonic).await;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;
    // Deleting is a hard delete, and a later re-register starts a fresh,
    // active slot: deleting a slot an admin suspended would lift the
    // suspension, so it is the admin's to do.
    refuse_lifting_admin_suspension(auth, &record, mnemonic, "delete")?;

    let did_id = record.did_id.clone();

    // Re-check the caller's DomainScope at time-of-use, as create/publish do at
    // create-time (SEC-4045 W7). Ownership alone is not enough: a domain-scoped
    // Owner who came to own a DID on another domain would otherwise destroy it.
    // Only a published slot has a DID to host-check.
    if let Some(did_id) = did_id.as_deref() {
        check_did_host_safety(state, auth, did_id).await?;
    }

    ensure_slot_domain_matches(&record, request_domain)?;

    // The slot's agent names are released with it. Otherwise the index keeps
    // pointing at a slot that no longer exists, and the names read as taken
    // to everyone else. Only entries that point here are removed.
    let _name_locks = lock_agent_names(state, agent_name_index::index_keys(&record)).await;
    let released_names = agent_name_index::owned_keys(&state.dids_ks, &record).await?;

    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, did_key(mnemonic));
    batch.remove(&state.dids_ks, content_log_key(mnemonic));
    batch.remove(&state.sessions_ks, transfer_offer_key(mnemonic));
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    batch.remove(&state.dids_ks, owner_key(&record.owner, mnemonic));
    // The delete reaches every server (and the watchers it was published to)
    // through rows committed with it.
    let sync = crate::server_push::stage_did_sync(
        state,
        &mut batch,
        mnemonic,
        crate::server_push::DidChange::Deleted,
    )
    .await;
    let usage = stage_index(state, &mut batch, Some(&record), None).await?;
    batch.commit().await?;
    drop(usage);
    sync.finish(state).await;
    invalidate_cached_content(state, mnemonic);

    // The names go in a write of their own, after the record: a slot can hold
    // more names than one transactional write takes on some backends
    // (DynamoDB's is 100 items), and that must not make the slot undeletable.
    // A name whose removal fails or is cut short by a crash is harmless — an
    // index entry pointing at a slot that no longer exists does not hold the
    // name (`agent_name_held_by_other`) — so this logs rather than fails.
    if !released_names.is_empty() {
        let mut names_batch = state.store.batch();
        for key in released_names {
            names_batch.remove(&state.dids_ks, key);
        }
        if let Err(e) = names_batch.commit_in_parts().await {
            warn!(
                mnemonic = %mnemonic,
                error = %e,
                "DID deleted; some of its agent-name index entries were not removed"
            );
        }
    }
    state.stats_collector.decrement_total_dids();
    crate::stats_admin::delete_did_stats(state, mnemonic).await;

    info!(did = %auth.did, mnemonic = %mnemonic, "DID deleted on control plane");

    Ok(did_id)
}

/// Refuse `action` by anyone but an admin on a slot an admin suspended: it
/// would lift the suspension.
pub(super) fn refuse_lifting_admin_suspension(
    auth: &AuthClaims,
    record: &DidRecord,
    mnemonic: &str,
    action: &str,
) -> Result<(), AppError> {
    if record.disabled_by_admin && auth.role != did_hosting_common::server::acl::Role::Admin {
        warn!(
            caller = %auth.did,
            mnemonic = %mnemonic,
            action,
            "denied: the slot was suspended by an admin"
        );
        return Err(AppError::Forbidden(
            "this DID was suspended by an admin; only an admin can resume or delete it".into(),
        ));
    }
    Ok(())
}

/// Toggle the `disabled` flag on a DID record.
pub async fn set_did_disabled(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    disabled: bool,
) -> Result<DidRecord, AppError> {
    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;
    // This writes the whole record back, so it must be read under the same
    // per-path lock every other record writer holds — otherwise a publish
    // committing in between is silently reverted to the stale copy.
    let _path_guard = state.path_locks.guard(mnemonic).await;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;
    // Re-check DomainScope at time-of-use (SEC-4045 W7).
    if let Some(did_id) = record.did_id.as_deref() {
        check_did_host_safety(state, auth, did_id).await?;
    }
    let is_admin = auth.role == did_hosting_common::server::acl::Role::Admin;
    if disabled {
        // An admin's suspension is recorded as such, so the owner cannot
        // lift it; an owner suspending an admin-suspended slot changes nothing.
        record.disabled_by_admin |= is_admin;
    } else if record.disabled_by_admin {
        refuse_lifting_admin_suspension(auth, &record, mnemonic, "resume")?;
        record.disabled_by_admin = false;
    }
    record.disabled = disabled;
    // The state travels to edges with the slot's content, queued in the same
    // commit.
    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    let sync = crate::server_push::stage_did_sync(
        state,
        &mut batch,
        mnemonic,
        crate::server_push::DidChange::Updated,
    )
    .await;
    batch.commit().await?;
    sync.finish(state).await;
    invalidate_cached_content(state, mnemonic);
    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        disabled,
        "DID disabled state updated on control plane"
    );
    // The record as written, so the caller need not read it back.
    Ok(record)
}

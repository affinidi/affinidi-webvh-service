//! Moving a slot to another owner: an administrator's transfer, or an owner's
//! offer that moves the slot when the recipient accepts
//! ([`change_did_owner`]).

use did_hosting_common::did_ops::{DidRecord, did_key, owner_key};
use tracing::{info, warn};

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;

use super::quota::{owner_quota_guard, owner_usage};
use super::resolve::resolve_did_or_agent_name;
use super::{
    check_did_host_safety, ensure_slot_domain_matches, stage_index, validate_slot_mnemonic,
};

/// How long an owner's offer of a slot waits for the recipient to accept it.
pub const OWNER_TRANSFER_OFFER_TTL_SECS: u64 = 72 * 60 * 60;

/// A slot an owner has offered to another DID, waiting for that DID to
/// accept. Kept in the sessions keyspace, beside the other short-lived
/// ceremonies, and swept once `expires_at` passes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransferOffer {
    /// The slot's owner when the offer was made. The offer lapses if the slot
    /// changes owner (or is deleted and registered again) before acceptance.
    pub from: String,
    /// The DID that may accept.
    pub to: String,
    pub created_at: u64,
    pub expires_at: u64,
}

pub(super) fn transfer_offer_key(mnemonic: &str) -> String {
    format!("did_xfer:{mnemonic}")
}

/// What [`change_did_owner`] did.
#[derive(Debug)]
pub struct OwnerChange {
    /// The slot's record as it now stands.
    pub record: DidRecord,
    /// Set when the slot did not move: its owner offered it, and it moves
    /// when the recipient accepts.
    pub offer: Option<TransferOffer>,
}

/// Why [`change_did_owner`] refused.
#[derive(Debug)]
pub enum OwnerChangeError {
    /// The recipient may not hold this slot: no ACL entry, a role that holds
    /// no DIDs, a domain scope that excludes it, or no room in its quota.
    /// The message names the check that failed; only an administrator or
    /// the recipient itself (accepting an offer made to it) ever sees it.
    TargetNotAuthorized(String),
    /// Anything else, as the other DID operations report it.
    Failed(AppError),
}

impl From<AppError> for OwnerChangeError {
    fn from(e: AppError) -> Self {
        Self::Failed(e)
    }
}

impl std::fmt::Display for OwnerChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetNotAuthorized(m) => write!(f, "{m}"),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

/// Whether `recipient` may hold `record`: an ACL entry whose role holds DIDs,
/// a domain scope that covers the slot, and room in its count and size
/// quotas for it. The same limits `did/register` applies to the recipient's
/// own registrations, so a slot cannot be handed to someone who could not
/// have registered it.
pub(super) async fn check_recipient_may_hold(
    state: &AppState,
    record: &DidRecord,
    recipient: &str,
) -> Result<(), OwnerChangeError> {
    use did_hosting_common::server::acl::Role;
    use did_hosting_common::server::acl::get_acl_entry;
    use did_hosting_common::server::domain::{
        assert_acl_allows_host, assert_did_host_allowed_when_domains_configured,
    };

    let refused = |why: String| OwnerChangeError::TargetNotAuthorized(why);
    let Some(entry) = get_acl_entry(&state.acl_ks, recipient).await? else {
        return Err(refused(format!(
            "'{recipient}' has no ACL entry, so it cannot own a DID here"
        )));
    };
    if matches!(entry.role, Role::Service | Role::MetricsReader) {
        return Err(refused(format!(
            "'{recipient}' holds the {} role, which cannot own DIDs",
            entry.role
        )));
    }
    let scope = |e: AppError| match e {
        AppError::Forbidden(_) => refused(format!(
            "'{recipient}' is not scoped to the domain this DID is hosted on{}",
            if record.domain.is_empty() {
                String::new()
            } else {
                format!(" ('{}')", record.domain)
            }
        )),
        other => OwnerChangeError::Failed(other),
    };
    if !record.domain.is_empty() {
        assert_acl_allows_host(&entry, &record.domain).map_err(scope)?;
    }
    if let Some(did_id) = record.did_id.as_deref() {
        assert_did_host_allowed_when_domains_configured(&state.store, &entry, did_id)
            .await
            .map_err(scope)?;
    }
    if entry.role != Role::Admin {
        let max_count = entry.effective_max_did_count(u64::MAX);
        let max_size = entry.effective_max_total_size(u64::MAX);
        if max_count != u64::MAX || max_size != u64::MAX {
            let (count, total) = owner_usage(state, recipient).await?;
            if count >= max_count {
                return Err(refused(format!(
                    "'{recipient}' is at its DID count limit ({max_count})"
                )));
            }
            if total.saturating_add(record.content_size) > max_size {
                return Err(refused(format!(
                    "'{recipient}' has no room for this DID in its total size limit \
                     ({max_size} bytes)"
                )));
            }
        }
    }
    Ok(())
}

/// Transfer ownership of a DID to a different DID.
///
/// A slot only moves to a DID that agreed to take it, or by an administrator:
///
/// - **An administrator** moves it at once.
/// - **Its owner** offers it: the offer is recorded for
///   [`OWNER_TRANSFER_OFFER_TTL_SECS`] and the slot stays where it is
///   ([`OwnerChange::offer`] is set). A new offer replaces the last; naming
///   the owner itself withdraws it. Nothing about the recipient is looked up
///   or disclosed to the owner — whether it is in the ACL, its scope or its
///   quota — so an offer is no probe of the ACL.
/// - **The recipient** accepts by sending the same request naming itself.
///   It must hold the live offer from the slot's current owner.
///
/// Whichever way the slot moves, the recipient must be able to hold it
/// (`check_recipient_may_hold`): an ACL entry whose role owns DIDs, a
/// domain scope covering the slot, and room in its quotas.
///
/// `request_domain`, when given, must be the slot's domain
/// (`ensure_slot_domain_matches`); it is checked once the caller is known
/// to have standing on the slot, before anything is written.
pub async fn change_did_owner(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    new_owner: &str,
    request_domain: Option<&str>,
) -> Result<OwnerChange, OwnerChangeError> {
    use did_hosting_common::server::acl::Role;

    use crate::auth::session::now_epoch;

    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;

    // Same per-path write lock as `register_did_atomic` — owner-change
    // is also a read-modify-write on the same key, so concurrent
    // transfers from the same caller could otherwise race the
    // updated_at / owner-index update. The offer row is read and written
    // under it too.
    let _path_guard = state.path_locks.guard(mnemonic).await;

    let mut record: DidRecord = state
        .dids_ks
        .get(did_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;
    let is_admin = auth.role == Role::Admin;
    let is_owner = record.owner == auth.did;
    let offer_key = transfer_offer_key(mnemonic);

    if !is_admin && !is_owner {
        // Only an acceptance: the caller names itself and holds the live
        // offer from the slot's current owner. Anything else is refused
        // exactly as before — "not the owner" — so neither an offer's
        // existence nor its recipient is disclosed.
        let now = now_epoch();
        let offer: Option<TransferOffer> = state.sessions_ks.get(offer_key.clone()).await?;
        let accepting = offer.as_ref().is_some_and(|o| {
            // Made for this slot as it stands: by its owner, since it was
            // registered (not for an earlier slot at the same path).
            o.to == auth.did
                && o.from == record.owner
                && o.created_at >= record.created_at
                && now <= o.expires_at
        }) && resolve_did_or_agent_name(state, new_owner)
            .await
            .is_ok_and(|named| named == auth.did);
        if !accepting {
            warn!(
                caller = %auth.did,
                owner = %record.owner,
                mnemonic = %mnemonic,
                "access denied: not the owner of this DID, and no transfer offer to accept"
            );
            return Err(AppError::Forbidden("not the owner of this DID".into()).into());
        }
        ensure_slot_domain_matches(&record, request_domain)?;
        // The acceptor's own standing — its domain scope at time of use, and
        // its quota — which it is told about as any of its writes would be.
        let _quota_guard = owner_quota_guard(state, &auth.did).await;
        check_recipient_may_hold(state, &record, &auth.did).await?;
        let recipient = auth.did.clone();
        let prev_owner =
            commit_owner_change(state, mnemonic, &mut record, &recipient, &offer_key).await?;
        info!(
            caller = %auth.did,
            prev_owner = %prev_owner,
            new_owner = %recipient,
            mnemonic = %mnemonic,
            "DID owner changed on control plane: recipient accepted the owner's offer"
        );
        return Ok(OwnerChange {
            record,
            offer: None,
        });
    }

    ensure_slot_domain_matches(&record, request_domain)?;

    // Re-check the caller's DomainScope at time-of-use (SEC-4045 W7), mirroring
    // create/publish; ownership is not a substitute for domain scoping.
    if let Some(did_id) = record.did_id.as_deref() {
        check_did_host_safety(state, auth, did_id).await?;
    }

    // Canonicalise (trim + format check) before any storage I/O so a
    // typo in the new-owner DID can't silently mismatch later
    // `check_acl` lookups.
    //
    // An agent name is accepted and resolved to its DID, for the same reason
    // the ACL routes accept one: `record.owner` is compared against an
    // authenticated DID, so the stored value must be a DID, and a name typed
    // here is input convenience that is resolved exactly once. Ownership then
    // stays with the DID the name pointed at — releasing and re-claiming the
    // name later transfers nothing.
    let new_owner = resolve_did_or_agent_name(state, new_owner).await?;

    if record.owner == new_owner {
        // Naming the current owner withdraws any outstanding offer.
        state.sessions_ks.remove(offer_key).await?;
        return Ok(OwnerChange {
            record,
            offer: None,
        });
    }

    if !is_admin {
        let now = now_epoch();
        let offer = TransferOffer {
            from: record.owner.clone(),
            to: new_owner.clone(),
            created_at: now,
            expires_at: now + OWNER_TRANSFER_OFFER_TTL_SECS,
        };
        state.sessions_ks.insert(offer_key, &offer).await?;
        info!(
            caller = %auth.did,
            offered_to = %new_owner,
            mnemonic = %mnemonic,
            expires_at = offer.expires_at,
            "DID ownership offered; it moves when the recipient accepts"
        );
        return Ok(OwnerChange {
            record,
            offer: Some(offer),
        });
    }

    let _quota_guard = owner_quota_guard(state, &new_owner).await;
    check_recipient_may_hold(state, &record, &new_owner).await?;
    let prev_owner =
        commit_owner_change(state, mnemonic, &mut record, &new_owner, &offer_key).await?;
    info!(
        caller = %auth.did,
        prev_owner = %prev_owner,
        new_owner = %new_owner,
        mnemonic = %mnemonic,
        "DID owner changed on control plane"
    );
    Ok(OwnerChange {
        record,
        offer: None,
    })
}

/// Move `record` to `new_owner`, swap its owner index and drop any
/// outstanding offer for the slot, in one batch. Returns the previous owner.
/// The caller holds the slot's path lock.
pub(super) async fn commit_owner_change(
    state: &AppState,
    mnemonic: &str,
    record: &mut DidRecord,
    new_owner: &str,
    offer_key: &str,
) -> Result<String, AppError> {
    use crate::auth::session::now_epoch;

    let previous = record.clone();
    let prev_owner = std::mem::replace(&mut record.owner, new_owner.to_string());
    record.updated_at = now_epoch();

    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(mnemonic), &*record)?;
    batch.remove(&state.dids_ks, owner_key(&prev_owner, mnemonic));
    batch.insert_raw(
        &state.dids_ks,
        owner_key(new_owner, mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.remove(&state.sessions_ks, offer_key.to_string());
    let _usage = stage_index(state, &mut batch, Some(&previous), Some(record)).await?;
    batch.commit().await?;
    Ok(prev_owner)
}

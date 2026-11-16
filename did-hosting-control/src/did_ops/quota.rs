//! Per-account quota enforcement (SEC-4045 W3): the owner's usage, the
//! per-owner quota lock, and the DID-count and total-size limits a write is
//! checked against before it commits.

use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::did_index;
use did_hosting_common::server::error::{AppError, QuotaKind};
use tracing::warn;

use crate::auth::AuthClaims;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Per-account quota enforcement (SEC-4045 W3)
// ---------------------------------------------------------------------------
//
// The edge server enforces `max_did_count` / `max_total_size`; the control
// plane — the authoritative write side, and in daemon mode the ONLY write path
// — did not, so an admin-set per-account quota was silently a no-op. The
// control plane has no global default limit (unlike the edge config), so a
// `None` ACL max means "no cap" and preserves prior behaviour; a quota only
// bites once an admin sets one on the caller's ACL entry.

/// The caller's current usage: (owned-slot count, summed `content_size`),
/// one read of its `usage:` counter, which every record write keeps current
/// in the same batch ([`stage_index`]).
pub(super) async fn owner_usage(state: &AppState, owner: &str) -> Result<(u64, u64), AppError> {
    let usage = did_index::owner_usage(&state.dids_ks, owner).await?;
    Ok((usage.count, usage.bytes))
}

/// The per-owner lock held from a quota check through the commit it
/// authorises. Quota usage is summed over all of an owner's slots, so the slot
/// lock alone lets two writes to different slots (a register and an accepted
/// transfer, say) each see room for one more and both commit. Always taken
/// after the slot's path lock, never before it.
pub(super) async fn owner_quota_guard(
    state: &AppState,
    owner: &str,
) -> did_hosting_common::server::path_locks::PathGuard {
    state
        .path_locks
        .guard(&format!("::owner-quota:{owner}"))
        .await
}

/// Take the caller's quota lock and check its total-size quota for replacing
/// `mnemonic`'s stored content with `new_size` bytes. Hold the returned guard
/// through the commit of that content, and release it with the slot's guard:
/// a publish is checked against usage that no other write of the same owner
/// can change before it lands. Taken after the slot lock and before any
/// agent-name lock.
pub(super) async fn hold_size_quota(
    state: &AppState,
    auth: &AuthClaims,
    mnemonic: &str,
    new_size: u64,
) -> Result<did_hosting_common::server::path_locks::PathGuard, AppError> {
    let guard = owner_quota_guard(state, &auth.did).await;
    let old_size = state
        .dids_ks
        .get::<DidRecord>(did_key(mnemonic))
        .await?
        .map(|r| r.content_size)
        .unwrap_or(0);
    check_total_size_limit(auth, state, old_size, new_size).await?;
    Ok(guard)
}

/// Enforce the caller's per-account `max_did_count` before adding a new slot.
/// Admin-exempt. `None` ACL max (or no ACL entry) means no cap.
pub(super) async fn check_did_count_limit(
    auth: &AuthClaims,
    state: &AppState,
) -> Result<(), AppError> {
    use did_hosting_common::server::acl::Role;
    if auth.role == Role::Admin {
        return Ok(());
    }
    let Some(entry) =
        did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did).await?
    else {
        return Ok(());
    };
    let max = entry.effective_max_did_count(u64::MAX);
    if max == u64::MAX {
        return Ok(());
    }
    let (count, _) = owner_usage(state, &auth.did).await?;
    if count >= max {
        warn!(did = %auth.did, count, max, "DID count quota exceeded (control)");
        return Err(AppError::quota(
            QuotaKind::Count,
            format!("DID count limit reached ({max})"),
        ));
    }
    Ok(())
}

/// Enforce the caller's per-account `max_total_size` before a write that grows
/// stored content. `old_size` is what the target slot already contributes (0
/// for a fresh slot); `new_size` is what it will contribute after the write.
/// Admin-exempt; `None` ACL max (or no ACL entry) means no cap.
pub(super) async fn check_total_size_limit(
    auth: &AuthClaims,
    state: &AppState,
    old_size: u64,
    new_size: u64,
) -> Result<(), AppError> {
    use did_hosting_common::server::acl::Role;
    if auth.role == Role::Admin {
        return Ok(());
    }
    let Some(entry) =
        did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did).await?
    else {
        return Ok(());
    };
    let max = entry.effective_max_total_size(u64::MAX);
    if max == u64::MAX {
        return Ok(());
    }
    let (_, total) = owner_usage(state, &auth.did).await?;
    let proposed = total.saturating_sub(old_size).saturating_add(new_size);
    if proposed > max {
        warn!(did = %auth.did, proposed, max, "total size quota exceeded (control)");
        return Err(AppError::quota(
            QuotaKind::Size,
            format!("total content size limit reached ({max} bytes)"),
        ));
    }
    Ok(())
}

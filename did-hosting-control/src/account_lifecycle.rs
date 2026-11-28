//! The inactivity lifecycle of self-registered accounts: disabled when unused,
//! purged when left disabled, restored by their holder's renewal.
//!
//! A self-registered account (`crate::account_register`) is kept alive by
//! its holder's signed tasks — `account/renew`, sent by its software at start
//! and daily, or any other — and by resolutions of its DIDs. When neither has
//! happened for its domain's `inactivity_days`, [`sweep_once`] disables its
//! DIDs (they stop resolving: the ordinary disabled-slot behaviour, synced to
//! the edges); `grace_days` later it deletes them, the ACL entry and the
//! account. The holder's renewal restores a disabled account until then.
//!
//! Before each step the holder is told, with a signed
//! `did-management/account/expiry-notice/0.1` sent to its DID over the
//! transport its document advertises: `disablePending` 14 and 3 days ahead,
//! `disabled` at disablement, `purgePending` a day before the purge. Delivery
//! is best effort — a notice the transport did not take is tried again on the
//! next tick, and a holder whose document advertises no transport is never
//! reached; `account/status` answers the same question on demand.
//!
//! An account's lifecycle acts on its DIDs with the holder's own claims
//! ([`holder_claims`]), so a disablement is the owner's kind, which the
//! holder's renewal may lift — never an administrator's suspension.

use std::time::Duration;

use serde_json::json;
use tracing::{debug, info, warn};
use trust_tasks_rs::Payload as _;

use did_hosting_common::DidStats;
use did_hosting_common::server::account::{self as account, AccountRecord, AccountState, voucher};
use did_hosting_common::server::acl::{self as acl, AclEntry, Role};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::error::AppError;
use did_hosting_common::tasks::did_management::account::expiry_notice::v0_1 as expiry_notice;

use crate::auth::AuthClaims;
use crate::server::AppState;

/// How often the lifecycle runs. Its steps are days apart, so an hour's
/// lateness changes nothing a holder can see.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

const DAY_SECS: u64 = 24 * 3600;

/// How long before disablement each `disablePending` notice goes out.
const WARN_BEFORE_DAYS: [u64; 2] = [14, 3];

/// How long before the purge the `purgePending` notice goes out.
const PURGE_WARN_SECS: u64 = DAY_SECS;

/// How long a holder's activity is trusted before it is written again: a
/// liveness timestamp, not an audit trail.
const TOUCH_INTERVAL_SECS: u64 = DAY_SECS;

/// The claims the lifecycle acts on a guest's DIDs with: the holder's own.
pub(crate) fn holder_claims(record: &AccountRecord) -> AuthClaims {
    AuthClaims {
        did: record.subject.clone(),
        role: Role::Owner,
        session_id: String::new(),
        session_pubkey_b58btc: None,
        amr: vec!["lifecycle".to_string()],
        acr: "aal1".to_string(),
    }
}

/// Record that the holder of `subject`'s account was just active, at most
/// once per [`TOUCH_INTERVAL_SECS`]. A no-op for a subject with no account
/// record. Never restores a disabled account: only a renewal does.
pub(crate) async fn touch(state: &AppState, subject: &str) {
    let now = now_epoch();
    match account::get(&state.acl_ks, subject).await {
        Ok(Some(mut record))
            if record.state != AccountState::Disabled
                && now.saturating_sub(record.last_active_at) >= TOUCH_INTERVAL_SECS =>
        {
            record.last_active_at = now;
            if record.state == AccountState::Warned {
                record.state = AccountState::Active;
                record.notices_sent.clear();
            }
            if let Err(e) = account::save(&state.acl_ks, &record).await {
                warn!(%subject, error = %e, "could not record guest activity");
            }
        }
        Ok(_) => {}
        Err(e) => warn!(%subject, error = %e, "could not read self-registered account"),
    }
}

/// Re-enable the slots the lifecycle disabled for inactivity. A slot that is
/// gone, or that an administrator suspended meanwhile, is left as it is.
pub(crate) async fn restore(state: &AppState, record: &AccountRecord) -> Result<(), AppError> {
    let auth = holder_claims(record);
    for mnemonic in &record.expiry_disabled {
        match crate::did_ops::set_did_disabled(&auth, state, mnemonic, false).await {
            Ok(_) | Err(AppError::NotFound(_)) => {}
            Err(e) => {
                warn!(subject = %record.subject, %mnemonic, error = %e,
                      "self-registered account restore: a slot stays disabled");
            }
        }
    }
    info!(target: "audit", event = "account.restored", subject = %record.subject,
          slots = record.expiry_disabled.len(), "self-registered account's DIDs restored");
    Ok(())
}

/// One pass over every self-registered account. Returns how many changed state.
pub async fn sweep_once(state: &AppState) -> usize {
    let now = now_epoch();
    if let Err(e) = voucher::sweep_expired(&state.acl_ks, now).await {
        warn!(error = %e, "account lifecycle: could not sweep lapsed voucher records");
    }
    let records = match account::list(&state.acl_ks).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "account lifecycle: could not list accounts");
            return 0;
        }
    };
    let mut changed = 0;
    for record in records {
        match step(state, record, now).await {
            Ok(true) => changed += 1,
            Ok(false) => {}
            Err(e) => warn!(error = %e, "account lifecycle: an account was not stepped"),
        }
    }
    changed
}

/// Move one account along its lifecycle, if it is due. `true` when its state
/// changed.
async fn step(state: &AppState, mut record: AccountRecord, now: u64) -> Result<bool, AppError> {
    let Some(entry) = acl::get_acl_entry(&state.acl_ks, &record.subject).await? else {
        // The entry was removed (an administrator's `acl/revoke`): the
        // account goes with it.
        account::remove(&state.acl_ks, &record.subject).await?;
        return Ok(true);
    };
    // An exempt account, or an administrator's own, never expires.
    if entry.role == Role::Admin || record.exempt {
        return Ok(false);
    }
    // The domain's terms as they stand, open or closed: closing a domain to
    // new registrations does not stop its accounts' lifecycle.
    let Some(policy) = crate::control_tasks::account::policy_of(state, &record.domain)
        .await?
        .filter(|p| p.inactivity_days > 0)
    else {
        return Ok(false);
    };
    let slots =
        crate::did_ops::owner_mnemonics_on_domain(state, &record.subject, &record.domain).await?;

    match record.state {
        AccountState::Active | AccountState::Warned => {
            let mut alive = record.last_active_at;
            for slot in &slots {
                if let Ok(Some(stats)) = state
                    .stats_ks
                    .get::<DidStats>(did_hosting_common::server::stats_tiers::stats_key(slot))
                    .await
                    && let Some(at) = stats.last_resolved_at
                {
                    alive = alive.max(at);
                }
            }
            let disable_at = alive.saturating_add(u64::from(policy.inactivity_days) * DAY_SECS);
            if now >= disable_at {
                disable(state, &mut record, &entry, &slots, now).await?;
                return Ok(true);
            }
            // Revived by resolutions since the warning: back to active.
            if record.state == AccountState::Warned
                && now + WARN_BEFORE_DAYS[0] * DAY_SECS < disable_at
            {
                record.state = AccountState::Active;
                record.notices_sent.clear();
                account::save(&state.acl_ks, &record).await?;
                return Ok(true);
            }
            let mut stepped = false;
            for days in WARN_BEFORE_DAYS {
                let stage = format!("disablePending:{days}");
                if now + days * DAY_SECS >= disable_at && !record.notices_sent.contains(&stage) {
                    if record.state == AccountState::Active {
                        record.state = AccountState::Warned;
                        stepped = true;
                    }
                    if notify(state, &record, &entry, "disablePending").await {
                        record.notices_sent.push(stage);
                    }
                    account::save(&state.acl_ks, &record).await?;
                    break;
                }
            }
            Ok(stepped)
        }
        AccountState::Disabled => {
            let disabled_at = record.disabled_at.unwrap_or(record.last_active_at);
            let purge_at = disabled_at.saturating_add(u64::from(policy.grace_days) * DAY_SECS);
            if now >= purge_at {
                purge(state, &record, &slots).await?;
                return Ok(true);
            }
            for stage in ["disabled", "purgePending"] {
                let due = stage == "disabled" || now + PURGE_WARN_SECS >= purge_at;
                if due && !record.notices_sent.iter().any(|s| s == stage) {
                    if notify(state, &record, &entry, stage).await {
                        record.notices_sent.push(stage.to_string());
                        account::save(&state.acl_ks, &record).await?;
                    }
                    break;
                }
            }
            Ok(false)
        }
    }
}

/// Disable the account's DIDs for inactivity, remembering which, and tell
/// the holder.
async fn disable(
    state: &AppState,
    record: &mut AccountRecord,
    entry: &AclEntry,
    slots: &[String],
    now: u64,
) -> Result<(), AppError> {
    let auth = holder_claims(record);
    let mut disabled = Vec::new();
    for mnemonic in slots {
        let current: Option<did_hosting_common::did_ops::DidRecord> = state
            .dids_ks
            .get(did_hosting_common::did_ops::did_key(mnemonic))
            .await?;
        // A slot already disabled — by its owner or an administrator — is not
        // the lifecycle's to restore later.
        if current.is_none_or(|r| r.disabled) {
            continue;
        }
        crate::did_ops::set_did_disabled(&auth, state, mnemonic, true).await?;
        disabled.push(mnemonic.clone());
    }
    record.state = AccountState::Disabled;
    record.disabled_at = Some(now);
    record.expiry_disabled = disabled;
    record.notices_sent.clear();
    if notify(state, record, entry, "disabled").await {
        record.notices_sent.push("disabled".into());
    }
    account::save(&state.acl_ks, record).await?;
    info!(target: "audit", event = "account.disabled", subject = %record.subject,
          domain = %record.domain, slots = record.expiry_disabled.len(),
          "self-registered account disabled for inactivity");
    Ok(())
}

/// Delete the account's DIDs, its ACL entry, its sessions and its record.
async fn purge(state: &AppState, record: &AccountRecord, slots: &[String]) -> Result<(), AppError> {
    let auth = holder_claims(record);
    for mnemonic in slots {
        match crate::did_ops::delete_did(&auth, state, mnemonic, None).await {
            Ok(_) | Err(AppError::NotFound(_)) => {}
            Err(e) => {
                // Leave the account to be tried again next tick rather than
                // strand a DID with no account to own it.
                warn!(subject = %record.subject, %mnemonic, error = %e,
                      "account lifecycle: a DID was not deleted; the purge waits");
                return Err(e);
            }
        }
    }
    {
        let _guard = state
            .acl_locks
            .guard(did_hosting_common::server::trust_tasks::ACL_WRITE_LOCK_KEY)
            .await;
        acl::delete_acl_entry(&state.acl_ks, &record.subject).await?;
    }
    if let Err(e) = did_hosting_common::server::acl_removal::withdraw_removed_member(
        &state.sessions_ks,
        &record.subject,
    )
    .await
    {
        warn!(subject = %record.subject, error = %e, "account purge: sessions not withdrawn");
    }
    account::remove(&state.acl_ks, &record.subject).await?;
    info!(target: "audit", event = "account.purged", subject = %record.subject,
          domain = %record.domain, slots = slots.len(),
          "self-registered account purged after its grace period");
    Ok(())
}

/// Send `stage`'s expiry notice to the holder. `true` when a transport took
/// it.
async fn notify(state: &AppState, record: &AccountRecord, entry: &AclEntry, stage: &str) -> bool {
    use did_hosting_common::server::didcomm_profile::TransportFallback;
    use did_hosting_common::server::trust_tasks::send::{
        Peers, build_signed_request, send_trust_task,
    };

    let Some(svc) = state.didcomm_service.get().cloned() else {
        debug!(subject = %record.subject, "expiry notice deferred: messaging not started");
        return false;
    };
    let Some(control_did) = state.config.server_did.clone() else {
        return false;
    };
    let signer = match crate::signing::control_signing_secret(state, &control_did) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "expiry notice: cannot sign");
            return false;
        }
    };
    let terms = crate::control_tasks::account::policy_of(state, &record.domain)
        .await
        .ok()
        .flatten();
    let payload = json!({
        "stage": stage,
        "account": crate::control_tasks::account::account_json(record, entry, terms.as_ref()),
    });
    let doc = match build_signed_request(
        expiry_notice::Payload::TYPE_URI,
        &control_did,
        &record.subject,
        payload,
        &signer,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "expiry notice: could not build");
            return false;
        }
    };
    // Only what the holder's document advertises: never this service's own
    // mediator guessed for a document that names none.
    let fallback = TransportFallback::from_config(None, false);
    match send_trust_task(
        &svc,
        "control",
        &control_did,
        &record.subject,
        &doc,
        &fallback,
        Peers::new(
            state.did_resolver.as_ref(),
            state.trust_tasks_verifier.as_deref(),
        ),
    )
    .await
    {
        Ok(_) => {
            // Handed to the transport, not delivered: nothing acknowledges a
            // notice (R1.1), and `account/status` is the holder's backstop.
            info!(target: "audit", event = "account.notice_handed_off", subject = %record.subject,
                  stage, "self-registered account expiry notice handed to transport");
            true
        }
        Err(e) => {
            debug!(subject = %record.subject, stage, error = %e,
                   "expiry notice not delivered; retried next tick");
            false
        }
    }
}

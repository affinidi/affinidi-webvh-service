//! `did-management/account/*`: self-registered accounts, the invites that
//! admit them, and each domain's terms for them.
//!
//! - `account/register/0.1` — a party with no account registers its own
//!   self-certifying `did:webvh`. The gate has already admitted it and checked
//!   its proof against the submitted log ([`crate::account_register`]); this
//!   row re-checks the evidence under its lock, enforces the domain's
//!   capacity, commits, and only then consumes the evidence and grants the
//!   owner's ACL entry.
//! - `account/renew/0.1`, `account/status/0.1` — the holder keeps its account
//!   alive and reads where it stands.
//! - `account/invite/{issue,list,revoke}/0.1` — an administrator's invites.
//! - `account/policy/{list,set}/0.1` — an administrator's runtime terms per
//!   domain: open or closed, the trusted authorising parties, path prefixes,
//!   quotas and lifecycle (`did_hosting_common::server::account::policy`).
//!
//! A self-registered account is an ordinary owner. What sets it apart, while
//! its [`AccountRecord`] exists, is its domain's terms: every DID it holds sits
//! under the path prefixes ([`ensure_account_path`]), it holds no agent names
//! ([`super::Cx::auth_unrestricted`]), its quotas are the terms' (or the
//! service's ordinary ones), and it expires when unused
//! (`crate::account_lifecycle`).

use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::StandardCode;

use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::account::{
    self as account, AccountRecord, AccountState, Referral,
    invite::{self, InviteState, Revocation},
    policy::{self, SelfRegistrationPolicy, TrustedIssuer},
    voucher,
};
use did_hosting_common::server::acl::{self as acl, AclEntry, Role};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::config::GuestAdmission;
use did_hosting_common::server::domain::{DomainScope, normalize_domain_name};
use did_hosting_common::server::error::{AppError, QuotaKind};
use did_hosting_common::server::passkey::invite::Issuer;
use did_hosting_common::tasks::did_management::account::{
    exempt,
    invite::{issue, list as invite_list, revoke},
    policy::{list as policy_list, set as policy_set},
    register, renew, status,
};

use super::{Cx, TaskError, at, spec_record, typed};
use crate::account_register::{Admitted, SELF_REGISTERED_LABEL};
use crate::auth::AuthClaims;
use crate::server::AppState;

const DAY_SECS: u64 = 24 * 3600;

/// The `amr` a self-registered account's first registration carries: its own
/// log, not a login, authenticated it.
const AMR: &str = "webvh-log";

/// `domain`'s stored terms, open or closed.
pub(crate) async fn policy_of(
    state: &AppState,
    domain: &str,
) -> Result<Option<SelfRegistrationPolicy>, AppError> {
    policy::get(&state.acl_ks, domain).await
}

/// Refuse a self-registered account a slot outside its domain's
/// `path_prefixes`. Every slot it takes — its own, and any further DID its
/// quota allows — sits under them, so it cannot squat the domain's other
/// paths. Any other account, or a domain with no terms: nothing to check.
pub(crate) async fn ensure_account_path(
    state: &AppState,
    auth: &AuthClaims,
    path: &str,
) -> Result<(), TaskError> {
    let Some(record) = account::get(&state.acl_ks, &auth.did)
        .await?
        .filter(|r| !r.exempt)
    else {
        return Ok(());
    };
    match policy_of(state, &record.domain).await? {
        Some(terms) if !terms.admits_path(path) => Err(TaskError::Standard(
            StandardCode::PermissionDenied,
            format!(
                "a self-registered account holds DIDs only under {:?} on `{}`",
                terms.path_prefixes, record.domain
            ),
        )),
        _ => Ok(()),
    }
}

/// When an account would be disabled, and when a disabled one is purged,
/// under `terms`. `(None, None)` for an account that does not expire.
pub(crate) fn lifecycle_instants(
    record: &AccountRecord,
    entry: &AclEntry,
    terms: Option<&SelfRegistrationPolicy>,
) -> (Option<u64>, Option<u64>) {
    // An exempt account, or an administrator's own, never expires.
    let Some(terms) =
        terms.filter(|t| t.inactivity_days > 0 && entry.role != Role::Admin && !record.exempt)
    else {
        return (None, None);
    };
    match record.state {
        AccountState::Disabled => (
            None,
            Some(
                record
                    .disabled_at
                    .unwrap_or(record.last_active_at)
                    .saturating_add(u64::from(terms.grace_days) * DAY_SECS),
            ),
        ),
        AccountState::Active | AccountState::Warned => (
            Some(
                record
                    .last_active_at
                    .saturating_add(u64::from(terms.inactivity_days) * DAY_SECS),
            ),
            None,
        ),
    }
}

fn referral_json(r: &Referral, with_verified: bool) -> Value {
    let mut body = serde_json::Map::new();
    if let Some(via) = &r.via {
        body.insert("via".into(), json!(via));
    }
    if let Some(label) = &r.label {
        body.insert("label".into(), json!(label));
    }
    if with_verified {
        body.insert("verified".into(), json!(r.verified));
    }
    Value::Object(body)
}

/// A `HostingAccount`, as every `account/*` response carries it.
pub(crate) fn account_json(
    record: &AccountRecord,
    entry: &AclEntry,
    terms: Option<&SelfRegistrationPolicy>,
) -> Value {
    let (disable_at, purge_at) = lifecycle_instants(record, entry, terms);
    let mut body = serde_json::Map::new();
    body.insert("subject".into(), json!(record.subject));
    body.insert("role".into(), json!(entry.role.to_string()));
    body.insert("domain".into(), json!(record.domain));
    body.insert("state".into(), json!(record.state.as_str()));
    // An account an administrator created was admitted by nothing.
    if !record.admitted_by.is_empty() {
        body.insert("admission".into(), json!(record.admission.as_str()));
    }
    body.insert("registeredAt".into(), json!(at(record.registered_at)));
    body.insert("lastActiveAt".into(), json!(at(record.last_active_at)));
    if let Some(t) = disable_at {
        body.insert("disableAt".into(), json!(at(t)));
    }
    if let Some(t) = purge_at {
        body.insert("purgeAt".into(), json!(at(t)));
    }
    if let Some(n) = entry.max_did_count {
        body.insert("maxDidCount".into(), json!(n));
    }
    if let Some(n) = entry.max_total_size {
        body.insert("maxTotalSizeBytes".into(), json!(n));
    }
    if let Some(r) = &record.referral {
        body.insert("referral".into(), referral_json(r, true));
    }
    if record.exempt {
        body.insert("exempt".into(), json!(true));
    }
    Value::Object(body)
}

/// `account/register/0.1`.
pub(crate) async fn register(
    cx: &Cx<'_>,
    p: register::v0_1::Payload,
) -> Result<register::v0_1::Response, TaskError> {
    use register::v0_1::error_codes;

    let Some(acct) = cx.self_registered else {
        // Unreachable through the gate, which admits this type only as a
        // self-registration.
        return Err(TaskError::Standard(
            StandardCode::PermissionDenied,
            "a registration must be admitted as a self-registration".into(),
        ));
    };
    if p.path.as_str() != acct.path || p.domain.as_str() != acct.domain {
        return Err(AppError::Internal(
            "a registration reached its row with a payload the gate did not admit".into(),
        )
        .into());
    }
    let state = cx.state;
    let terms = &acct.policy;
    let refused = |reason: &str, message: &str| {
        TaskError::Declared(error_codes::ADMISSION_REFUSED, message.to_string())
            .with_details(json!({ "reason": reason }))
    };

    // One registration per domain at a time, from the capacity count to the
    // grant, so `max_registrations` holds under concurrency (per process).
    let canonical = normalize_domain_name(&acct.domain).unwrap_or_else(|_| acct.domain.clone());
    let _domain_guard = state
        .acl_locks
        .guard(&format!("self-register:{canonical}"))
        .await;
    if account::count_on_domain(&state.acl_ks, &canonical).await?
        >= terms.max_registrations as usize
    {
        warn!(target: "audit", event = "account.register_refused", subject = %acct.subject,
              domain = %acct.domain, "self-registration refused: the domain is at capacity");
        return Err(TaskError::Declared(
            error_codes::CAPACITY_REACHED,
            format!(
                "domain `{}` holds the most self-registered accounts it admits",
                acct.domain
            ),
        ));
    }

    // The evidence, again, held until it is consumed.
    let _invite_guard = match &acct.admitted {
        Admitted::Invite { invite_id } => {
            let guard = invite::lock(invite_id).await;
            match invite::by_id(&state.acl_ks, invite_id)
                .await?
                .map(|i| i.state(now_epoch()))
            {
                Some(InviteState::Pending) => {}
                Some(InviteState::Redeemed) => {
                    return Err(refused("inviteRedeemed", "the invite has been used"));
                }
                Some(InviteState::Revoked) => {
                    return Err(refused("inviteRevoked", "the invite was withdrawn"));
                }
                Some(InviteState::Expired) => {
                    return Err(refused("inviteExpired", "the invite has lapsed"));
                }
                None => return Err(refused("unknownInvite", "no such invite")),
            }
            Some(guard)
        }
        Admitted::Voucher { issuer, id, .. } => {
            if voucher::is_used(&state.acl_ks, issuer, id).await? {
                return Err(refused("voucherUsed", "the voucher has already been used"));
            }
            None
        }
    };

    // A path held by anyone else is not this registrant's to take.
    if let Some(existing) = state.dids_ks.get::<DidRecord>(did_key(&acct.path)).await?
        && existing.owner != acct.subject
    {
        return Err(TaskError::Declared(
            error_codes::PATH_TAKEN,
            format!("path `{}` is already held", acct.path),
        ));
    }
    if let Some(max) = terms.max_total_size
        && p.did_data.as_str().len() as u64 > max
    {
        return Err(AppError::quota(
            QuotaKind::Size,
            format!("the log is larger than this domain's accounts may hold ({max} bytes)"),
        )
        .into());
    }
    // A self-registered account holds no agent names: a document that claims
    // one is refused, never published with the claim left unserved. (Later
    // publications are held to the same rule by `register_did_atomic`.)
    if !did_hosting_common::did_ops::extract_agent_names(p.did_data.as_str(), &canonical).is_empty()
    {
        return Err(TaskError::Standard(
            StandardCode::PermissionDenied,
            "a self-registered account may not hold agent names: remove this domain's names \
             from alsoKnownAs"
                .into(),
        ));
    }

    let auth = AuthClaims {
        did: acct.subject.clone(),
        role: Role::Owner,
        session_id: String::new(),
        session_pubkey_b58btc: None,
        amr: vec![AMR.to_string()],
        acr: "aal1".to_string(),
    };
    let record = crate::did_ops::register_did_atomic(
        &auth,
        state,
        &acct.path,
        p.did_data.as_str(),
        false,
        Some(&acct.domain),
    )
    .await?;

    // After the slot, never before it: a grant or a spent invite for a
    // registration that then failed would leave a stranger standing, or an
    // invitee locked out, with no slot to show for it. A crash between the
    // two leaves an owned slot, an unspent invite and no entry; a retry (the
    // same DID, the same slot) takes this path again and finishes.
    match &acct.admitted {
        Admitted::Invite { invite_id } => {
            if !invite::redeem_locked(&state.acl_ks, invite_id, &acct.subject).await? {
                warn!(invite_id = %invite_id, subject = %acct.subject,
                      "self-registration committed, but its invite lapsed before it was spent");
            }
        }
        Admitted::Voucher {
            issuer,
            id,
            valid_until,
        } => voucher::record_used(&state.acl_ks, issuer, id, *valid_until).await?,
    }
    let now = now_epoch();
    // The account record before the entry: a crash between them leaves a
    // record with no entry, which the lifecycle removes, never an owner with
    // no terms.
    let record_acct = match account::get(&state.acl_ks, &acct.subject).await? {
        Some(existing) => existing,
        None => {
            let created = AccountRecord {
                subject: acct.subject.clone(),
                domain: canonical.clone(),
                admission: acct.admitted.kind(),
                admitted_by: acct.admitted.reference(),
                registered_at: now,
                last_active_at: now,
                state: AccountState::Active,
                disabled_at: None,
                expiry_disabled: Vec::new(),
                notices_sent: Vec::new(),
                referral: acct.referral.clone(),
                exempt: false,
            };
            account::save(&state.acl_ks, &created).await?;
            created
        }
    };
    let entry = grant_owner_entry(state, &acct.subject, &canonical, terms).await?;
    info!(
        target: "audit",
        event = "account.registered",
        subject = %acct.subject,
        path = %record.mnemonic,
        domain = %record.domain,
        admission = acct.admitted.kind().as_str(),
        admitted_by = %acct.admitted.reference(),
        referral_via = acct.referral.as_ref().and_then(|r| r.via.as_deref()).unwrap_or(""),
        referral_verified = acct.referral.as_ref().is_some_and(|r| r.verified),
        source = %acct.source,
        "account self-registered, authenticated by its own did:webvh log"
    );

    typed(
        json!({
            "account": account_json(&record_acct, &entry, Some(terms)),
            "record": spec_record::<register::v0_1::DidRecord>(state, &record)?,
        }),
        "account/register response",
    )
}

/// Give `subject` an owner's entry, scoped to `domain` and the terms' quotas
/// (the service's ordinary limits where they state none). Left alone when it
/// has an entry already (an earlier attempt's, or an administrator's).
/// Serialised with every other ACL write.
async fn grant_owner_entry(
    state: &AppState,
    subject: &str,
    domain: &str,
    terms: &SelfRegistrationPolicy,
) -> Result<AclEntry, AppError> {
    let _guard = state
        .acl_locks
        .guard(did_hosting_common::server::trust_tasks::ACL_WRITE_LOCK_KEY)
        .await;
    if let Some(existing) = acl::get_acl_entry(&state.acl_ks, subject).await? {
        return Ok(existing);
    }
    let entry = AclEntry {
        did: subject.to_string(),
        role: Role::Owner,
        label: Some(SELF_REGISTERED_LABEL.into()),
        created_at: now_epoch(),
        max_total_size: terms.max_total_size,
        max_did_count: terms.max_did_count,
        domains: DomainScope::Allowed {
            domains: vec![domain.to_string()],
        },
    };
    acl::store_acl_entry(&state.acl_ks, &entry).await?;
    Ok(entry)
}

/// The caller's account: its ACL entry and record. `noAccount` (by its local
/// part, which renew and status both declare) when there is no entry.
async fn own_account(
    cx: &Cx<'_>,
    no_account: trust_tasks_rs::DeclaredErrorCode,
) -> Result<(AclEntry, AccountRecord), TaskError> {
    let caller = cx.caller()?.to_string();
    let missing = || {
        TaskError::Declared(
            no_account,
            "the issuer holds no account here; register one with did-management/account/register"
                .into(),
        )
    };
    let entry = acl::get_acl_entry(&cx.state.acl_ks, &caller)
        .await?
        .ok_or_else(missing)?;
    if entry.role == Role::MetricsReader {
        return Err(missing());
    }
    let record = match account::get(&cx.state.acl_ks, &caller).await? {
        Some(r) => r,
        // An account an administrator created has no record: it does not
        // expire, and status answers for it from its entry alone.
        None => AccountRecord {
            subject: caller.clone(),
            domain: match &entry.domains {
                DomainScope::Allowed { domains } => domains.first().cloned().unwrap_or_default(),
                _ => String::new(),
            },
            admission: GuestAdmission::Invite,
            admitted_by: String::new(),
            registered_at: entry.created_at,
            last_active_at: entry.created_at,
            state: AccountState::Active,
            disabled_at: None,
            expiry_disabled: Vec::new(),
            notices_sent: Vec::new(),
            referral: None,
            exempt: false,
        },
    };
    Ok((entry, record))
}

/// The terms an account is held to: its domain's, for a self-registered one.
async fn terms_for(
    state: &AppState,
    record: &AccountRecord,
) -> Result<Option<SelfRegistrationPolicy>, AppError> {
    if record.admitted_by.is_empty() {
        return Ok(None);
    }
    policy_of(state, &record.domain).await
}

/// `account/renew/0.1`: restart the caller's inactivity period, and restore
/// an account disabled for it.
pub(crate) async fn renew(
    cx: &Cx<'_>,
    _p: renew::v0_1::Payload,
) -> Result<renew::v0_1::Response, TaskError> {
    let (entry, mut record) = own_account(cx, renew::v0_1::error_codes::NO_ACCOUNT).await?;
    let state = cx.state;
    let changed = record.state != AccountState::Active;
    if record.state == AccountState::Disabled {
        crate::account_lifecycle::restore(state, &record).await?;
    }
    record.state = AccountState::Active;
    record.disabled_at = None;
    record.expiry_disabled.clear();
    record.notices_sent.clear();
    record.last_active_at = now_epoch();
    if account::is_self_registered(&state.acl_ks, &record.subject).await? {
        account::save(&state.acl_ks, &record).await?;
    }
    if changed {
        info!(target: "audit", event = "account.renewed", subject = %record.subject,
              "self-registered account restored to active by its holder");
    }
    let terms = terms_for(state, &record).await?;
    typed(
        json!({ "account": account_json(&record, &entry, terms.as_ref()), "changed": changed }),
        "account/renew response",
    )
}

/// `account/status/0.1`: the caller's account. Not a liveness signal.
pub(crate) async fn status(
    cx: &Cx<'_>,
    _p: status::v0_1::Payload,
) -> Result<status::v0_1::Response, TaskError> {
    let (entry, record) = own_account(cx, status::v0_1::error_codes::NO_ACCOUNT).await?;
    let terms = terms_for(cx.state, &record).await?;
    typed(
        json!({ "account": account_json(&record, &entry, terms.as_ref()) }),
        "account/status response",
    )
}

/// An `AccountInvite` summary — never a secret.
fn invite_json(invite: &invite::AccountInvite, now: u64) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("inviteId".into(), json!(invite.invite_id));
    body.insert("domain".into(), json!(invite.domain));
    if let Some(p) = &invite.path_prefix {
        body.insert("pathPrefix".into(), json!(p));
    }
    if let Some(l) = &invite.label {
        body.insert("label".into(), json!(l));
    }
    if let Some(r) = &invite.referral {
        body.insert("referral".into(), referral_json(r, false));
    }
    body.insert("state".into(), json!(invite.state(now).as_str()));
    body.insert("createdAt".into(), json!(at(invite.created_at)));
    if let Some(did) = invite.issued_by.administrator_did() {
        body.insert("createdBy".into(), json!(did));
    }
    body.insert("expiresAt".into(), json!(at(invite.expires_at)));
    if invite.state(now) == InviteState::Redeemed {
        if let Some(by) = &invite.redeemed_by {
            body.insert("redeemedBy".into(), json!(by));
        }
        if let Some(t) = invite.redeemed_at {
            body.insert("redeemedAt".into(), json!(at(t)));
        }
    }
    Value::Object(body)
}

/// A request's `referral`, read from its typed payload by its wire names.
fn stated_referral(value: Value) -> Option<Referral> {
    let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_string);
    let (via, label) = (text("via"), text("label"));
    (via.is_some() || label.is_some()).then_some(Referral {
        via,
        label,
        verified: false,
    })
}

/// `account/invite/issue/0.1`. Admin.
pub(crate) async fn invite_issue(
    cx: &Cx<'_>,
    p: issue::v0_1::Payload,
) -> Result<issue::v0_1::Response, TaskError> {
    use issue::v0_1::error_codes;

    let auth = cx.admin().await?;
    let state = cx.state;
    let domain = p.domain.as_str().to_string();
    if did_hosting_common::server::domain::get_domain(&state.store, &domain)
        .await?
        .is_none()
    {
        return Err(TaskError::Declared(
            error_codes::UNKNOWN_DOMAIN,
            format!("`{domain}` is not a hosting domain here"),
        ));
    }
    let Some(terms) = policy_of(state, &domain)
        .await?
        .filter(|t| t.admits(GuestAdmission::Invite))
    else {
        return Err(TaskError::Declared(
            error_codes::INVITES_NOT_ACCEPTED,
            format!("domain `{domain}` does not admit self-registration by invite"),
        ));
    };
    if invite::count_pending(&state.acl_ks, &domain, now_epoch()).await?
        >= terms.max_pending_invites as usize
    {
        return Err(TaskError::Declared(
            error_codes::TOO_MANY_PENDING,
            format!(
                "domain `{domain}` already holds {} pending invites",
                terms.max_pending_invites
            ),
        ));
    }
    let referral = p
        .referral
        .as_ref()
        .and_then(|r| stated_referral(serde_json::to_value(r).unwrap_or_default()));
    let issued = invite::issue(
        &state.acl_ks,
        invite::IssueRequest {
            domain,
            path_prefix: p.path_prefix.as_ref().map(|s| s.as_str().to_string()),
            label: p.label.as_ref().map(|s| s.as_str().to_string()),
            referral,
            issued_by: Issuer::administrator(auth.did)?,
            ttl_secs: serde_json::to_value(&p)?
                .get("ttlSeconds")
                .and_then(Value::as_u64)
                .unwrap_or(invite::MAX_TTL_SECS),
        },
        state.config.auth.claim_code_hash_wait(),
    )
    .await?;
    typed(
        json!({
            "invite": invite_json(&issued.invite, now_epoch()),
            "token": issued.token,
            "claimCode": issued.claim_code,
        }),
        "account/invite/issue response",
    )
}

/// The most invites one page returns.
const MAX_PAGE: usize = 100;

/// `account/invite/list/0.1`. Admin.
pub(crate) async fn invite_list(
    cx: &Cx<'_>,
    p: invite_list::v0_1::Payload,
) -> Result<invite_list::v0_1::Response, TaskError> {
    cx.admin().await?;
    let now = now_epoch();
    let filter = serde_json::to_value(&p)?;
    let text = |name: &str| filter.get(name).and_then(Value::as_str).map(str::to_string);
    let want_domain = text("domain").map(|d| normalize_domain_name(&d).unwrap_or(d));
    let want_state = text("state");
    let want_via = text("referralVia");
    let matching: Vec<_> = invite::list(&cx.state.acl_ks)
        .await?
        .into_iter()
        .filter(|i| {
            want_domain.as_deref().is_none_or(|d| {
                normalize_domain_name(&i.domain).unwrap_or_else(|_| i.domain.clone()) == d
            })
        })
        .filter(|i| {
            want_state
                .as_deref()
                .is_none_or(|s| s == i.state(now).as_str())
        })
        .filter(|i| {
            want_via.as_deref().is_none_or(|v| {
                i.referral
                    .as_ref()
                    .and_then(|r| r.via.as_deref())
                    .is_some_and(|via| did_hosting_common::scid::same_reference(via, v))
            })
        })
        .collect();
    // The cursor is the id of the last invite of the previous page; one this
    // service never issued names no invite and is refused.
    let start = match text("cursor") {
        None => 0,
        Some(c) => {
            matching
                .iter()
                .position(|i| i.invite_id == c)
                .ok_or_else(|| {
                    TaskError::Standard(StandardCode::MalformedRequest, "unknown cursor".into())
                })?
                + 1
        }
    };
    let limit = filter
        .get("limit")
        .and_then(Value::as_u64)
        .map(|l| (l as usize).min(MAX_PAGE))
        .unwrap_or(MAX_PAGE);
    let page: Vec<_> = matching.iter().skip(start).take(limit).collect();
    let mut body = serde_json::Map::new();
    body.insert(
        "invites".into(),
        Value::Array(page.iter().map(|i| invite_json(i, now)).collect()),
    );
    if start + page.len() < matching.len()
        && let Some(last) = page.last()
    {
        body.insert("nextCursor".into(), json!(last.invite_id));
    }
    typed(Value::Object(body), "account/invite/list response")
}

/// `account/invite/revoke/0.1`. Admin.
pub(crate) async fn invite_revoke(
    cx: &Cx<'_>,
    p: revoke::v0_1::Payload,
) -> Result<revoke::v0_1::Response, TaskError> {
    use revoke::v0_1::error_codes;

    let auth = cx.admin().await?;
    let now = now_epoch();
    let (invite, changed) =
        match invite::revoke(&cx.state.acl_ks, p.invite_id.as_str(), &auth.did).await? {
            Revocation::Revoked(i) => (i, true),
            Revocation::AlreadyRevoked(i) => (i, false),
            Revocation::NotPending(_, state) => {
                return Err(TaskError::Declared(
                    error_codes::NOT_PENDING,
                    format!(
                        "the invite is {}; there is nothing to revoke",
                        state.as_str()
                    ),
                )
                .with_details(json!({ "state": state.as_str() })));
            }
            Revocation::NotFound => {
                return Err(TaskError::Declared(
                    error_codes::UNKNOWN_INVITE,
                    "no such invite".into(),
                ));
            }
        };
    typed(
        json!({ "invite": invite_json(&invite, now), "changed": changed }),
        "account/invite/revoke response",
    )
}

/// A `SelfRegistrationPolicy`, as `account/policy/*` carry it — labels and
/// all, for administrators. `server/info` publishes its own subset.
pub(crate) fn policy_json(terms: &SelfRegistrationPolicy) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("domain".into(), json!(terms.domain));
    body.insert("enabled".into(), json!(terms.enabled));
    body.insert(
        "admissions".into(),
        json!(
            terms
                .admissions
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
        ),
    );
    body.insert(
        "trustedIssuers".into(),
        Value::Array(
            terms
                .trusted_issuers
                .iter()
                .map(|t| {
                    let mut i = serde_json::Map::new();
                    i.insert("did".into(), json!(t.did));
                    if let Some(l) = &t.label {
                        i.insert("label".into(), json!(l));
                    }
                    Value::Object(i)
                })
                .collect(),
        ),
    );
    body.insert("pathPrefixes".into(), json!(terms.path_prefixes));
    body.insert("maxRegistrations".into(), json!(terms.max_registrations));
    if let Some(n) = terms.max_did_count {
        body.insert("maxDidCount".into(), json!(n));
    }
    if let Some(n) = terms.max_total_size {
        body.insert("maxTotalSizeBytes".into(), json!(n));
    }
    body.insert("inactivityDays".into(), json!(terms.inactivity_days));
    body.insert("graceDays".into(), json!(terms.grace_days));
    body.insert("maxPendingInvites".into(), json!(terms.max_pending_invites));
    body.insert("updatedAt".into(), json!(at(terms.updated_at)));
    body.insert("updatedBy".into(), json!(terms.updated_by));
    Value::Object(body)
}

/// `account/policy/list/0.1`. Admin.
pub(crate) async fn policy_list_task(
    cx: &Cx<'_>,
    p: policy_list::v0_1::Payload,
) -> Result<policy_list::v0_1::Response, TaskError> {
    cx.admin().await?;
    let state = cx.state;
    let want = p.domain.as_ref().map(|d| d.as_str().to_string());
    if let Some(d) = &want
        && did_hosting_common::server::domain::get_domain(&state.store, d)
            .await?
            .is_none()
    {
        return Err(TaskError::Declared(
            policy_list::v0_1::error_codes::UNKNOWN_DOMAIN,
            format!("`{d}` is not a hosting domain here"),
        ));
    }
    let policies: Vec<Value> = policy::list(&state.acl_ks)
        .await?
        .iter()
        .filter(|t| {
            want.as_deref().is_none_or(|d| {
                normalize_domain_name(d).unwrap_or_else(|_| d.to_string()) == t.domain
            })
        })
        .map(policy_json)
        .collect();
    typed(
        json!({ "policies": policies }),
        "account/policy/list response",
    )
}

/// `account/policy/set/0.1`. Admin. Replaces the domain's terms, at once.
pub(crate) async fn policy_set_task(
    cx: &Cx<'_>,
    p: policy_set::v0_1::Payload,
) -> Result<policy_set::v0_1::Response, TaskError> {
    use policy_set::v0_1::error_codes;

    let auth = cx.admin().await?;
    let state = cx.state;
    let wire = serde_json::to_value(&p.policy)?;
    let invalid = |reason: String| {
        TaskError::Declared(error_codes::INVALID_POLICY, reason.clone())
            .with_details(json!({ "reason": reason }))
    };
    let text = |name: &str| wire.get(name).and_then(Value::as_str).map(str::to_string);
    let number = |name: &str| wire.get(name).and_then(Value::as_u64);
    let domain = text("domain").unwrap_or_default();
    let canonical = normalize_domain_name(&domain).map_err(|e| invalid(e.user_message()))?;
    if did_hosting_common::server::domain::get_domain(&state.store, &canonical)
        .await?
        .is_none()
    {
        return Err(TaskError::Declared(
            error_codes::UNKNOWN_DOMAIN,
            format!("`{domain}` is not a hosting domain here"),
        ));
    }
    let admissions = wire
        .get("admissions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| serde_json::from_value::<GuestAdmission>(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    let trusted_issuers = wire
        .get("trustedIssuers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    Some(TrustedIssuer {
                        did: did_hosting_common::scid::identity(t.get("did")?.as_str()?),
                        label: t.get("label").and_then(Value::as_str).map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let path_prefixes = wire
        .get("pathPrefixes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim_matches('/').to_string())
                .collect()
        })
        .unwrap_or_default();
    let u32_of = |name: &str| {
        number(name)
            .map(|n| n.min(u64::from(u32::MAX)) as u32)
            .unwrap_or(0)
    };
    let mut terms = SelfRegistrationPolicy {
        domain: canonical.clone(),
        enabled: wire
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        admissions,
        trusted_issuers,
        path_prefixes,
        max_registrations: u32_of("maxRegistrations"),
        max_did_count: number("maxDidCount"),
        max_total_size: number("maxTotalSizeBytes"),
        inactivity_days: u32_of("inactivityDays"),
        grace_days: u32_of("graceDays"),
        max_pending_invites: u32_of("maxPendingInvites"),
        updated_at: 0,
        updated_by: String::new(),
    };
    terms.validate().map_err(invalid)?;

    // Serialised per domain with registrations, so a registration admitted
    // under the old terms completes under them, and none starts half-way
    // through the change.
    let _guard = state
        .acl_locks
        .guard(&format!("self-register:{canonical}"))
        .await;
    let current = policy::get(&state.acl_ks, &canonical).await?;
    let changed = current.as_ref().is_none_or(|c| {
        let mut same = c.clone();
        same.updated_at = 0;
        same.updated_by = String::new();
        same != terms
    });
    if changed {
        terms.updated_at = now_epoch();
        terms.updated_by = auth.did.clone();
        policy::set(&state.acl_ks, &terms).await?;
        info!(
            target: "audit",
            event = "account.policy_set",
            domain = %canonical,
            enabled = terms.enabled,
            trusted_issuers = terms.trusted_issuers.len(),
            by = %auth.did,
            "self-registration terms changed"
        );
    } else if let Some(c) = current {
        terms = c;
    }
    typed(
        json!({ "policy": policy_json(&terms), "changed": changed }),
        "account/policy/set response",
    )
}

/// `account/exempt/0.1`. Admin. Lifts a self-registered account's terms, or
/// holds it to them again.
pub(crate) async fn exempt_task(
    cx: &Cx<'_>,
    p: exempt::v0_1::Payload,
) -> Result<exempt::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let state = cx.state;
    let subject = did_hosting_common::scid::identity(p.subject.as_str());
    let no_account = || {
        TaskError::Declared(
            exempt::v0_1::error_codes::NO_ACCOUNT,
            format!("`{subject}` holds no self-registered account here"),
        )
    };
    let entry = acl::get_acl_entry(&state.acl_ks, &subject)
        .await?
        .ok_or_else(no_account)?;
    let mut record = account::get(&state.acl_ks, &subject)
        .await?
        .ok_or_else(no_account)?;
    let changed = record.exempt != p.exempt;
    if changed {
        if p.exempt {
            if record.state == AccountState::Disabled {
                crate::account_lifecycle::restore(state, &record).await?;
            }
        } else {
            // Never disabled for the time it spent exempt.
            record.last_active_at = now_epoch();
        }
        record.state = AccountState::Active;
        record.disabled_at = None;
        record.expiry_disabled.clear();
        record.notices_sent.clear();
        record.exempt = p.exempt;
        account::save(&state.acl_ks, &record).await?;
        info!(target: "audit", event = "account.exempt", subject = %subject,
              exempt = p.exempt, by = %auth.did,
              "self-registered account's exemption from its terms changed");
    }
    let terms = terms_for(state, &record).await?;
    typed(
        json!({ "account": account_json(&record, &entry, terms.as_ref()), "changed": changed }),
        "account/exempt response",
    )
}

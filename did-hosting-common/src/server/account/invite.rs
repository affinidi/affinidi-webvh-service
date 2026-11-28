//! Guest-account invites (`did-management/account/invite/*`), stored hashed.
//!
//! An invite admits one party with no account to register one
//! (`did-management/account/register/0.1`) on one domain. Like a passkey
//! enrolment invite ([`crate::server::passkey::invite`], whose token and
//! claim-code hashing this reuses) it has two secrets, delivered over two
//! channels:
//!
//! - the **token** (256 bits), kept only as its SHA-256, which also indexes
//!   the invite (`acct_invite_tok:{hash}`) — a fast hash is right for a value
//!   with that much entropy;
//! - the **claim code** (60 bits, short enough to type), kept only as a
//!   salted Argon2id digest and compared in constant time.
//!
//! Unlike an enrolment invite, an account invite names no subject: the
//! invitee may not have minted its DID yet. Its authority is the domain (and
//! optional path prefix) it admits on.
//!
//! An invite is kept after it is used, so the domain keeps a record of who
//! admitted which account (`did-management/account/invite/list`); what makes
//! it usable — the token index and the claim digest — is deleted the moment
//! it is redeemed or revoked. Wrong claim codes are counted per invite,
//! atomically in the store; the [`MAX_WRONG_CODES`]th revokes it.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::server::auth::session::now_epoch;
use crate::server::error::AppError;
use crate::server::passkey::invite::{
    ClaimHash, DECOY, HASH_PERMITS, ISSUE_HASH_PERMITS, Issuer, blocking, generate_claim_code,
    generate_token, hash_claim_code, hash_token, verify_claim_code,
};
use crate::server::path_locks::{PathGuard, PathLocks};
use crate::server::store::KeyspaceHandle;

pub use crate::server::passkey::invite::MAX_WRONG_CODES;

/// The longest an invite may stay redeemable (30 days), as the
/// `account/invite/issue` schema bounds `ttlSeconds`.
pub const MAX_TTL_SECS: u64 = 30 * 24 * 3600;

/// The prefix every stored invite is under.
pub const INVITE_PREFIX: &str = "acct_invite:";

fn invite_key(invite_id: &str) -> String {
    format!("{INVITE_PREFIX}{invite_id}")
}

fn token_index_key(token_hash: &str) -> String {
    format!("acct_invite_tok:{token_hash}")
}

fn wrong_codes_key(invite_id: &str) -> String {
    format!("acct_invite_wrong:{invite_id}")
}

/// Serialises everything that reads and then changes one invite — a wrong
/// code's lockout, a redemption, a revocation — in this process. Keyed by
/// invite id. The wrong-code count itself is atomic in the store.
static LOCKS: LazyLock<PathLocks> = LazyLock::new(PathLocks::new);

/// Hold invite `invite_id` for a read-check-write that must not interleave
/// with a redemption or a revocation of it — the register row holds it from
/// its last check of the invite through the commit that redeems it.
pub async fn lock(invite_id: &str) -> PathGuard {
    LOCKS.guard(invite_id).await
}

/// What has become of an invite, before expiry is taken into account.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum InviteStatus {
    Pending,
    Redeemed,
    Revoked,
}

/// An invite as the domain's admission record reports it
/// (`AccountInvite.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteState {
    Pending,
    Redeemed,
    Revoked,
    Expired,
}

impl InviteState {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            InviteState::Pending => "pending",
            InviteState::Redeemed => "redeemed",
            InviteState::Revoked => "revoked",
            InviteState::Expired => "expired",
        }
    }
}

/// A stored invite. Holds no secret: only hashes, and only while usable.
#[derive(Clone, Serialize, Deserialize)]
pub struct AccountInvite {
    /// The administrator-facing handle; carries no authority.
    pub invite_id: String,
    /// Hex SHA-256 of the token, while the invite is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_hash: Option<String>,
    /// The claim code's digest, while the invite is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claim: Option<ClaimHash>,
    /// The hosting domain it admits on, as issued.
    pub domain: String,
    /// When set, the account's DIDs must sit under this `/`-separated prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// The issuer's note on who it is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The source the administrator recorded for it; an account it admits
    /// carries it as verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referral: Option<super::Referral>,
    /// Who issued it, and so whose authority it carries.
    pub issued_by: Issuer,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: InviteStatus,
    /// The account subject that redeemed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeemed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeemed_at: Option<u64>,
    /// Who withdrew it: an administrator's DID, or `lockout` after too many
    /// wrong claim codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
}

impl std::fmt::Debug for AccountInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountInvite")
            .field("invite_id", &self.invite_id)
            .field("domain", &self.domain)
            .field("path_prefix", &self.path_prefix)
            .field("issued_by", &self.issued_by)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("status", &self.status)
            .field("redeemed_by", &self.redeemed_by)
            .finish_non_exhaustive()
    }
}

impl AccountInvite {
    /// Where it stands at `now`.
    pub fn state(&self, now: u64) -> InviteState {
        match self.status {
            InviteStatus::Redeemed => InviteState::Redeemed,
            InviteStatus::Revoked => InviteState::Revoked,
            InviteStatus::Pending if now >= self.expires_at => InviteState::Expired,
            InviteStatus::Pending => InviteState::Pending,
        }
    }

    /// Whether a slot at `path` satisfies the invite's own prefix (the
    /// domain's rules apply as well, separately). Whole segments.
    pub fn admits_path(&self, path: &str) -> bool {
        match self.path_prefix.as_deref().map(|p| p.trim_matches('/')) {
            None | Some("") => true,
            Some(prefix) => path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1),
        }
    }

    /// Drop what makes the invite usable, leaving its record.
    fn retire(&mut self) -> Option<String> {
        self.claim = None;
        self.token_hash.take()
    }
}

/// A freshly issued invite with its two secrets — returned exactly once.
pub struct IssuedInvite {
    pub invite: AccountInvite,
    pub token: String,
    pub claim_code: String,
}

impl std::fmt::Debug for IssuedInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedInvite")
            .field("invite", &self.invite)
            .field("token", &"<redacted>")
            .field("claim_code", &"<redacted>")
            .finish()
    }
}

/// What to issue.
#[derive(Debug, Clone)]
pub struct IssueRequest {
    pub domain: String,
    pub path_prefix: Option<String>,
    pub label: Option<String>,
    pub referral: Option<super::Referral>,
    pub issued_by: Issuer,
    pub ttl_secs: u64,
}

/// Issue and store an invite. The returned token and code are the only copy.
pub async fn issue(
    ks: &KeyspaceHandle,
    req: IssueRequest,
    hash_wait: std::time::Duration,
) -> Result<IssuedInvite, AppError> {
    let token = generate_token();
    let claim_code = generate_claim_code();
    let code = claim_code.clone();
    let claim = blocking(&ISSUE_HASH_PERMITS, hash_wait, move || {
        hash_claim_code(&code)
    })
    .await??;
    let now = now_epoch();
    let token_hash = hash_token(&token);
    let invite = AccountInvite {
        invite_id: format!("inv-{}", uuid::Uuid::new_v4()),
        token_hash: Some(token_hash.clone()),
        claim: Some(claim),
        domain: req.domain,
        path_prefix: req.path_prefix,
        label: req.label,
        referral: req.referral.map(|r| super::Referral {
            verified: true,
            ..r
        }),
        issued_by: req.issued_by,
        created_at: now,
        expires_at: now.saturating_add(req.ttl_secs.clamp(1, MAX_TTL_SECS)),
        status: InviteStatus::Pending,
        redeemed_by: None,
        redeemed_at: None,
        revoked_by: None,
    };
    let mut batch = ks.batch();
    batch.insert(ks, invite_key(&invite.invite_id), &invite)?;
    batch.insert_raw(
        ks,
        token_index_key(&token_hash),
        invite.invite_id.as_bytes().to_vec(),
    );
    batch.commit().await?;
    info!(
        target: "audit",
        event = "account.invite.issued",
        invite_id = %invite.invite_id,
        issued_by = %invite.issued_by,
        domain = %invite.domain,
        expires_at = invite.expires_at,
        "guest account invite issued"
    );
    Ok(IssuedInvite {
        invite,
        token,
        claim_code,
    })
}

/// The invite with id `invite_id`.
pub async fn by_id(
    ks: &KeyspaceHandle,
    invite_id: &str,
) -> Result<Option<AccountInvite>, AppError> {
    ks.get(invite_key(invite_id)).await
}

/// Every stored invite, newest first.
pub async fn list(ks: &KeyspaceHandle) -> Result<Vec<AccountInvite>, AppError> {
    let mut out: Vec<AccountInvite> = ks
        .prefix_iter_raw(INVITE_PREFIX)
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    out.sort_by_key(|i: &AccountInvite| std::cmp::Reverse(i.created_at));
    Ok(out)
}

/// How many invites for `domain` are pending at `now`.
pub async fn count_pending(ks: &KeyspaceHandle, domain: &str, now: u64) -> Result<usize, AppError> {
    use crate::server::domain::normalize_domain_name;
    let canonical = normalize_domain_name(domain).unwrap_or_else(|_| domain.to_string());
    Ok(list(ks)
        .await?
        .into_iter()
        .filter(|i| i.state(now) == InviteState::Pending)
        .filter(|i| {
            normalize_domain_name(&i.domain).unwrap_or_else(|_| i.domain.clone()) == canonical
        })
        .count())
}

/// Why a presented invite admits nobody. Each names a refusal reason of
/// `account/register`'s `admissionRefused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteRefusal {
    /// No usable invite has this token, or the claim code is wrong.
    /// Deliberately one answer, after the same hashing work.
    Unknown,
    /// Both halves match, but the invite lapsed.
    Expired,
}

impl InviteRefusal {
    /// The `admissionRefused` reason.
    pub fn reason(self) -> &'static str {
        match self {
            InviteRefusal::Unknown => "unknownInvite",
            InviteRefusal::Expired => "inviteExpired",
        }
    }
}

/// Present `token` and `claim_code`, without consuming anything.
///
/// `Ok(Ok(invite))`: both halves match a pending, unexpired invite. Every
/// other answer comes after the same Argon2 work, so it is no oracle for
/// which half was wrong. A wrong code counts against the invite; the
/// [`MAX_WRONG_CODES`]th revokes it. Waiting longer than `hash_wait` for a
/// hashing permit is refused as [`AppError::RateLimited`] and counts against
/// nothing.
pub async fn check(
    ks: &KeyspaceHandle,
    token: &str,
    claim_code: &str,
    hash_wait: std::time::Duration,
) -> Result<Result<AccountInvite, InviteRefusal>, AppError> {
    let now = now_epoch();
    let code = claim_code.to_string();
    let found = match ks.get_raw(token_index_key(&hash_token(token))).await? {
        Some(id) => {
            let id = String::from_utf8(id)
                .map_err(|e| AppError::Internal(format!("invite index: {e}")))?;
            by_id(ks, &id).await?
        }
        None => None,
    };
    let Some(invite) = found.filter(|i| i.claim.is_some()) else {
        blocking(&HASH_PERMITS, hash_wait, move || {
            verify_claim_code(&DECOY, &code)
        })
        .await?;
        return Ok(Err(InviteRefusal::Unknown));
    };
    let claim = invite.claim.clone().expect("filtered on a claim above");
    if blocking(&HASH_PERMITS, hash_wait, move || {
        verify_claim_code(&claim, &code)
    })
    .await?
    {
        return Ok(match invite.state(now) {
            InviteState::Pending => Ok(invite),
            InviteState::Expired => Err(InviteRefusal::Expired),
            // A redeemed or revoked invite has no claim digest to match.
            InviteState::Redeemed | InviteState::Revoked => Err(InviteRefusal::Unknown),
        });
    }
    let wrong = ks.incr_raw(wrong_codes_key(&invite.invite_id)).await?;
    if wrong >= u64::from(MAX_WRONG_CODES) {
        let _guard = lock(&invite.invite_id).await;
        if let Some(mut current) = by_id(ks, &invite.invite_id).await?
            && current.status == InviteStatus::Pending
        {
            current.status = InviteStatus::Revoked;
            current.revoked_by = Some("lockout".into());
            write_retired(ks, &mut current).await?;
            info!(
                target: "audit",
                event = "account.invite.locked",
                invite_id = %current.invite_id,
                wrong_codes = wrong,
                "guest account invite revoked after too many wrong claim codes"
            );
        }
    }
    Ok(Err(InviteRefusal::Unknown))
}

/// Rewrite `invite` with what made it usable removed, in one batch with the
/// removal of its token index and wrong-code counter.
async fn write_retired(ks: &KeyspaceHandle, invite: &mut AccountInvite) -> Result<(), AppError> {
    let token_hash = invite.retire();
    let mut batch = ks.batch();
    batch.insert(ks, invite_key(&invite.invite_id), &*invite)?;
    if let Some(hash) = token_hash {
        batch.remove(ks, token_index_key(&hash));
    }
    batch.remove(ks, wrong_codes_key(&invite.invite_id));
    batch.commit().await
}

/// Mark invite `invite_id` redeemed by `subject`. The caller holds
/// [`lock`]`(invite_id)` and has just checked it is pending; `false` (and
/// nothing written) when it no longer is.
pub async fn redeem_locked(
    ks: &KeyspaceHandle,
    invite_id: &str,
    subject: &str,
) -> Result<bool, AppError> {
    let now = now_epoch();
    let Some(mut invite) = by_id(ks, invite_id).await? else {
        return Ok(false);
    };
    if invite.state(now) != InviteState::Pending {
        return Ok(false);
    }
    invite.status = InviteStatus::Redeemed;
    invite.redeemed_by = Some(crate::scid::identity(subject));
    invite.redeemed_at = Some(now);
    write_retired(ks, &mut invite).await?;
    info!(
        target: "audit",
        event = "account.invite.redeemed",
        invite_id = %invite_id,
        redeemed_by = %subject,
        "guest account invite redeemed"
    );
    Ok(true)
}

/// The outcome of revoking an invite.
#[derive(Debug)]
pub enum Revocation {
    /// It was pending, and is now revoked.
    Revoked(AccountInvite),
    /// It was already revoked.
    AlreadyRevoked(AccountInvite),
    /// It was redeemed or has expired: nothing to revoke.
    NotPending(AccountInvite, InviteState),
    /// No invite has this id.
    NotFound,
}

/// Withdraw invite `invite_id`, effective before this returns.
pub async fn revoke(
    ks: &KeyspaceHandle,
    invite_id: &str,
    by: &str,
) -> Result<Revocation, AppError> {
    let _guard = lock(invite_id).await;
    let Some(mut invite) = by_id(ks, invite_id).await? else {
        return Ok(Revocation::NotFound);
    };
    match invite.state(now_epoch()) {
        InviteState::Revoked => Ok(Revocation::AlreadyRevoked(invite)),
        state @ (InviteState::Redeemed | InviteState::Expired) => {
            Ok(Revocation::NotPending(invite, state))
        }
        InviteState::Pending => {
            invite.status = InviteStatus::Revoked;
            invite.revoked_by = Some(by.to_string());
            write_retired(ks, &mut invite).await?;
            info!(
                target: "audit",
                event = "account.invite.revoked",
                invite_id = %invite_id,
                revoked_by = %by,
                "guest account invite revoked"
            );
            Ok(Revocation::Revoked(invite))
        }
    }
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::account::test_ks;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(30);

    fn request(ttl_secs: u64) -> IssueRequest {
        IssueRequest {
            domain: "did.example.com".into(),
            path_prefix: Some("g".into()),
            label: Some("pilot".into()),
            referral: None,
            issued_by: Issuer::administrator("did:example:admin").unwrap(),
            ttl_secs,
        }
    }

    #[tokio::test]
    async fn both_halves_admit_and_redemption_retires_the_secrets() {
        let (ks, _dir) = test_ks().await;
        let issued = issue(&ks, request(3600), WAIT).await.unwrap();
        let invite = check(&ks, &issued.token, &issued.claim_code, WAIT)
            .await
            .unwrap()
            .expect("admits");
        assert_eq!(invite.invite_id, issued.invite.invite_id);

        let _guard = lock(&invite.invite_id).await;
        assert!(
            redeem_locked(&ks, &invite.invite_id, "did:scid:vh:1:Qm?src=x")
                .await
                .unwrap()
        );
        let stored = by_id(&ks, &invite.invite_id).await.unwrap().unwrap();
        assert_eq!(stored.state(now_epoch()), InviteState::Redeemed);
        assert_eq!(stored.redeemed_by.as_deref(), Some("did:scid:vh:1:Qm"));
        assert!(stored.token_hash.is_none() && stored.claim.is_none());
        // Spent: a second presentation is refused, and a second redemption
        // writes nothing.
        assert_eq!(
            check(&ks, &issued.token, &issued.claim_code, WAIT)
                .await
                .unwrap()
                .unwrap_err(),
            InviteRefusal::Unknown
        );
        assert!(
            !redeem_locked(&ks, &invite.invite_id, "did:example:other")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_wrong_code_is_unknown_and_enough_of_them_revoke() {
        let (ks, _dir) = test_ks().await;
        let issued = issue(&ks, request(3600), WAIT).await.unwrap();
        for _ in 0..MAX_WRONG_CODES {
            assert_eq!(
                check(&ks, &issued.token, "0000-0000-0000", WAIT)
                    .await
                    .unwrap()
                    .unwrap_err(),
                InviteRefusal::Unknown
            );
        }
        let stored = by_id(&ks, &issued.invite.invite_id).await.unwrap().unwrap();
        assert_eq!(stored.state(now_epoch()), InviteState::Revoked);
        assert_eq!(stored.revoked_by.as_deref(), Some("lockout"));
        // The right code no longer helps.
        assert!(
            check(&ks, &issued.token, &issued.claim_code, WAIT)
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn revocation_is_a_setting_and_spares_a_redeemed_invite() {
        let (ks, _dir) = test_ks().await;
        let issued = issue(&ks, request(3600), WAIT).await.unwrap();
        let id = issued.invite.invite_id.clone();
        assert!(matches!(
            revoke(&ks, &id, "did:example:admin").await.unwrap(),
            Revocation::Revoked(_)
        ));
        assert!(matches!(
            revoke(&ks, &id, "did:example:admin").await.unwrap(),
            Revocation::AlreadyRevoked(_)
        ));
        assert!(matches!(
            revoke(&ks, "inv-none", "did:example:admin").await.unwrap(),
            Revocation::NotFound
        ));

        let other = issue(&ks, request(3600), WAIT).await.unwrap();
        {
            let _guard = lock(&other.invite.invite_id).await;
            redeem_locked(&ks, &other.invite.invite_id, "did:example:guest")
                .await
                .unwrap();
        }
        assert!(matches!(
            revoke(&ks, &other.invite.invite_id, "did:example:admin")
                .await
                .unwrap(),
            Revocation::NotPending(_, InviteState::Redeemed)
        ));
    }

    #[tokio::test]
    async fn path_prefix_matches_whole_segments() {
        let (ks, _dir) = test_ks().await;
        let invite = issue(&ks, request(3600), WAIT).await.unwrap().invite;
        assert!(invite.admits_path("g/agent-1"));
        assert!(!invite.admits_path("gx/agent-1"));
        assert!(!invite.admits_path("g"));
        assert_eq!(
            count_pending(&ks, "did.example.com", now_epoch())
                .await
                .unwrap(),
            1
        );
    }
}

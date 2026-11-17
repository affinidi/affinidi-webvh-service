//! Passkey enrolment invites (`auth/passkey/enroll/invite/0.3`), stored hashed.
//!
//! An invite is two secrets delivered over two channels: a **token**, carried
//! in the invite URL, and a short **claim code** the invitee types. Neither is
//! ever stored:
//!
//! - the token (256 bits) is kept only as its SHA-256, which is also the key
//!   the invite is looked up by — a fast hash is right for a value with that
//!   much entropy, and the lookup then compares nothing secret;
//! - the claim code (60 bits, short enough to type) is kept only as a salted
//!   Argon2id digest, and compared in constant time.
//!
//! Wrong claim codes are counted per invite, atomically in the store (so the
//! count is correct even when replicas share it — see `ATTEMPT_LOCKS`).
//! At [`MAX_WRONG_CODES`] the invite is deleted, so a stolen URL gives an
//! attacker a handful of guesses at a 60-bit code and no more. An invite
//! expires, and is consumed exactly once: [`take`] is the atomic step that
//! lets exactly one redemption bind a credential.
//!
//! Every read and change an administrator makes addresses an invite by its
//! `invite_id`, which carries no authority.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::info;

use crate::server::auth::session::now_epoch;
use crate::server::error::AppError;
use crate::server::path_locks::PathLocks;
use crate::server::store::KeyspaceHandle;

/// Entropy of the invite token, in bytes (256 bits; the spec requires ≥128
/// and recommends 192).
pub const TOKEN_BYTES: usize = 32;

/// Characters in a claim code, before grouping: 12 Crockford base32 symbols,
/// 60 bits (the spec requires ≥40).
pub const CLAIM_CODE_LEN: usize = 12;

/// Wrong claim codes an invite survives. The next one deletes it.
pub const MAX_WRONG_CODES: u32 = 5;

/// The invite TTL when the request names none (`payload.ttl` default: 1 h).
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// Argon2id cost for the claim code: the OWASP baseline (19 MiB, 2 passes).
const ARGON2_M_KIB: u32 = 19 * 1024;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;
const SALT_BYTES: usize = 16;

/// Crockford base32, which has no `I`, `L`, `O` or `U` to misread.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// What a redeemed credential may authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Purpose {
    /// Signs its subject in (a login credential).
    Session,
    /// Only the user-verification evidence of a step-up bound to one
    /// operation. Never opens or elevates a session, and is held in a store
    /// the login ceremony does not read.
    StepUp,
}

impl Purpose {
    /// The wire name (`session` / `stepUp`).
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Session => "session",
            Purpose::StepUp => "stepUp",
        }
    }
}

/// A salted Argon2id digest of a claim code.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClaimHash {
    /// Hex salt.
    salt: String,
    m_kib: u32,
    t: u32,
    p: u32,
    /// Hex digest (32 bytes).
    digest: String,
}

/// How an operator-issued invite's issuer is stored. Not a DID, so no
/// administrator's issuer can be read back as it (see [`Issuer`]).
const OPERATOR_CLI_ISSUER: &str = "operator (CLI)";

/// Who issued an invite, and so whose authority it carries.
///
/// Either the operator, through the `invite` subcommand (whose authority is
/// store access, which no ACL change takes away), or an administrator, named
/// by DID (whose authority is their ACL entry, so the invite is honoured only
/// while they still hold administrator standing). The two cannot be confused:
/// an administrator is always a DID, and the operator's stored form is not
/// one, so the only way to make an operator issuer is [`Issuer::operator`].
///
/// Stored as a string — the administrator's DID, or `operator (CLI)` — the
/// form every invite already on disk has.
#[derive(Clone, PartialEq, Eq)]
pub struct Issuer(IssuerKind);

#[derive(Clone, PartialEq, Eq)]
enum IssuerKind {
    Operator,
    Administrator(String),
}

impl Issuer {
    /// The operator, issuing from the command line with store access.
    pub fn operator() -> Self {
        Self(IssuerKind::Operator)
    }

    /// An administrator, by DID. Anything that is not a DID is refused, so
    /// no caller-supplied string can stand for the operator.
    pub fn administrator(did: impl Into<String>) -> Result<Self, AppError> {
        let did = did.into();
        if !did.starts_with("did:") {
            return Err(AppError::invalid(format!(
                "an invite's administrator issuer must be a DID, not `{did}`"
            )));
        }
        Ok(Self(IssuerKind::Administrator(did)))
    }

    /// Whether this is the operator.
    pub fn is_operator(&self) -> bool {
        matches!(self.0, IssuerKind::Operator)
    }

    /// The administrator's DID; `None` for the operator.
    pub fn administrator_did(&self) -> Option<&str> {
        match &self.0 {
            IssuerKind::Operator => None,
            IssuerKind::Administrator(did) => Some(did),
        }
    }

    /// The stored and logged form.
    pub fn as_str(&self) -> &str {
        self.administrator_did().unwrap_or(OPERATOR_CLI_ISSUER)
    }
}

impl std::fmt::Display for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Issuer {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Issuer {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == OPERATOR_CLI_ISSUER {
            return Ok(Self::operator());
        }
        Self::administrator(s).map_err(serde::de::Error::custom)
    }
}

/// A stored invite. Holds no secret: only hashes of the token and the code.
#[derive(Clone, Serialize, Deserialize)]
pub struct Invite {
    /// The administrator-facing handle (list, update, revoke).
    pub invite_id: String,
    /// Hex SHA-256 of the token; the storage key.
    pub token_hash: String,
    claim: ClaimHash,
    /// The VID the credential will be bound to.
    pub subject: String,
    pub purpose: Purpose,
    /// For `session`: the role an ACL entry is created with, when the subject
    /// has none yet. Always `None` for `stepUp`.
    pub role: Option<String>,
    /// The inviter's suggested credential label.
    pub device_label: Option<String>,
    /// Who issued it.
    pub issued_by: Issuer,
    /// The administrators who changed its role or expiry since it was issued
    /// (`auth/passkey/enroll/invite/update`), each once. The invite carries
    /// their authority too: it is honoured only while every one of them is
    /// still an administrator, and withdrawn with any one's ACL entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amended_by: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    /// Wrong claim codes presented so far.
    pub wrong_codes: u32,
    /// The redemption ceremony currently open against this invite. A newer
    /// `redeem/start` supersedes an older one, so an invite has at most one.
    pub ceremony: Option<String>,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("invite_id", &self.invite_id)
            .field("subject", &self.subject)
            .field("purpose", &self.purpose)
            .field("role", &self.role)
            .field("issued_by", &self.issued_by)
            .field("amended_by", &self.amended_by)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("wrong_codes", &self.wrong_codes)
            .finish_non_exhaustive()
    }
}

impl Invite {
    /// Whether the invite can no longer be redeemed.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// The administrators whose standing the invite rests on: its issuer,
    /// when that is an administrator, and every administrator who amended it.
    /// An operator-issued invite nobody amended rests on none.
    pub fn administrators(&self) -> impl Iterator<Item = &str> {
        self.issued_by
            .administrator_did()
            .into_iter()
            .chain(self.amended_by.iter().map(String::as_str))
    }

    /// Record that administrator `did` changed the invite.
    pub fn record_amendment(&mut self, did: &str) {
        if !self
            .administrators()
            .any(|a| crate::scid::same_reference(a, did))
        {
            self.amended_by.push(did.to_string());
        }
    }
}

/// A freshly issued invite with its two secrets — returned exactly once.
pub struct IssuedInvite {
    pub invite: Invite,
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
pub struct InviteRequest {
    pub subject: String,
    pub purpose: Purpose,
    pub role: Option<String>,
    pub device_label: Option<String>,
    pub issued_by: Issuer,
    pub ttl_secs: u64,
}

/// The outcome of presenting a token and claim code.
#[derive(Debug)]
pub enum Redemption {
    /// Both halves match an unexpired invite.
    Valid(Box<Invite>),
    /// No redeemable invite, or the wrong code. Deliberately one answer.
    Invalid,
    /// This wrong code was the last one allowed; the invite is gone.
    TooManyAttempts,
}

fn invite_key(token_hash: &str) -> String {
    format!("pk_invite:{token_hash}")
}

fn invite_id_key(invite_id: &str) -> String {
    format!("pk_invite_id:{invite_id}")
}

/// The wrong-claim-code counter for one invite, kept apart from the `Invite`
/// JSON blob so it can be incremented atomically (`KeyspaceHandle::incr_raw`)
/// without a read-modify-write race between replicas sharing this store. See
/// [`redeem`].
fn wrong_codes_key(token_hash: &str) -> String {
    format!("pk_wrong:{token_hash}")
}

/// The prefix every stored invite is under. The session cleanup task sweeps
/// expired ones (`auth::session::cleanup_expired_sessions`).
pub const INVITE_PREFIX: &str = "pk_invite:";

/// Hex SHA-256 of a token.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A new token: `inv_` and 256 bits, base64url.
pub fn generate_token() -> String {
    use base64::Engine;
    let bytes: [u8; TOKEN_BYTES] = rand::random();
    format!(
        "inv_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// A new claim code: 12 Crockford base32 symbols, grouped `XXXX-XXXX-XXXX`.
pub fn generate_claim_code() -> String {
    let mut out = String::with_capacity(CLAIM_CODE_LEN + 2);
    for i in 0..CLAIM_CODE_LEN {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        // 32 divides 256, so a byte masked to 5 bits is uniform.
        let b = rand::random::<u8>() & 0x1f;
        out.push(CROCKFORD[b as usize] as char);
    }
    out
}

/// The canonical form of a typed claim code: grouping and case dropped, and
/// the letters Crockford reads as digits mapped to them.
pub fn normalise_claim_code(code: &str) -> String {
    code.chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

fn argon2(m_kib: u32, t: u32, p: u32) -> Result<argon2::Argon2<'static>, AppError> {
    let params = argon2::Params::new(m_kib, t, p, Some(32))
        .map_err(|e| AppError::Internal(format!("argon2 parameters: {e}")))?;
    Ok(argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    ))
}

fn digest(code: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<[u8; 32], AppError> {
    let mut out = [0u8; 32];
    argon2(m_kib, t, p)?
        .hash_password_into(normalise_claim_code(code).as_bytes(), salt, &mut out)
        .map_err(|e| AppError::Internal(format!("argon2: {e}")))?;
    Ok(out)
}

/// Hash `code` under a fresh salt. Blocking: call from `spawn_blocking`.
pub fn hash_claim_code(code: &str) -> Result<ClaimHash, AppError> {
    let salt: [u8; SALT_BYTES] = rand::random();
    let out = digest(code, &salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P)?;
    Ok(ClaimHash {
        salt: hex::encode(salt),
        m_kib: ARGON2_M_KIB,
        t: ARGON2_T,
        p: ARGON2_P,
        digest: hex::encode(out),
    })
}

/// Whether `code` matches `hash`, compared in constant time. Blocking.
pub fn verify_claim_code(hash: &ClaimHash, code: &str) -> bool {
    let (Ok(salt), Ok(expected)) = (hex::decode(&hash.salt), hex::decode(&hash.digest)) else {
        return false;
    };
    match digest(code, &salt, hash.m_kib, hash.t, hash.p) {
        Ok(got) => bool::from(got.as_slice().ct_eq(expected.as_slice())),
        Err(_) => false,
    }
}

/// A claim hash for a code nobody holds, so a refusal for an unknown token
/// costs what a refusal for a wrong code does.
static DECOY: LazyLock<ClaimHash> = LazyLock::new(|| ClaimHash {
    salt: hex::encode([0u8; SALT_BYTES]),
    m_kib: ARGON2_M_KIB,
    t: ARGON2_T,
    p: ARGON2_P,
    digest: hex::encode([0u8; 32]),
});

/// Serialises one invite's existence check, ceremony bookkeeping and
/// consume-on-lockout against concurrent callers **in this process**.
///
/// The wrong-code count itself no longer depends on this lock for
/// correctness: [`redeem`] increments it with
/// [`KeyspaceHandle::incr_raw`](crate::server::store::KeyspaceHandle::incr_raw),
/// which is atomic in the store and therefore correct across replicas too.
/// This lock still avoids duplicate work within one process — two racing
/// wrong codes on the same invite in this process take the invite exactly
/// once past the threshold rather than both attempting it — but a
/// deployment with more than one replica relies on the store's atomicity,
/// not on this lock, for the lockout to hold.
static ATTEMPT_LOCKS: LazyLock<PathLocks> = LazyLock::new(PathLocks::new);

/// Claim-code checks for redemptions that run at once in this process
/// ([`HASH_PERMITS`]); invite issuance has its own [`MAX_CONCURRENT_ISSUE_HASHES`]
/// on top, so at most the sum of the two hashes run at once. Each takes
/// [`ARGON2_M_KIB`] of memory, and a stranger can ask for one per redemption
/// attempt — from as many sources as they can mint VIDs — so the per-source
/// rate limit alone does not bound the memory and CPU they can make the
/// service spend. Past this many, attempts wait for a permit, for at most the
/// configured `auth.claim_code_hash_wait_ms`.
const MAX_CONCURRENT_HASHES: usize = 8;

static HASH_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_HASHES);

/// Claim-code hashes for [`issue`], kept apart from [`HASH_PERMITS`] so that
/// a queue of redemption attempts cannot hold up an administrator issuing an
/// invite.
const MAX_CONCURRENT_ISSUE_HASHES: usize = 2;

static ISSUE_HASH_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_ISSUE_HASHES);

/// [`AppError::RateLimited::limiter`] for a claim-code hash that found no
/// free permit within its wait.
pub const LIMITER_CLAIM_CODE_HASHING: &str = "claim-code-hashing";

/// The retry hint for [`LIMITER_CLAIM_CODE_HASHING`]. A hash takes well under
/// a second, so permits free up quickly once the burst passes.
const HASH_BUSY_RETRY_AFTER_SECS: u64 = 1;

/// The refusal for a claim-code check that could not start within its wait.
fn hashing_busy() -> AppError {
    AppError::RateLimited {
        limiter: LIMITER_CLAIM_CODE_HASHING,
        message: "too many claim codes are being checked; retry shortly".into(),
        retry_after_secs: HASH_BUSY_RETRY_AFTER_SECS,
    }
}

/// Run one claim-code hash on the blocking pool, within `permits`.
///
/// Waits at most `wait` for a permit, then answers
/// [`AppError::RateLimited`] (`unavailable` with a retry time on the Trust
/// Task surface) rather than queueing without bound behind other attempts.
///
/// The permit moves into the blocking task, so it is held for as long as the
/// hash runs, even if the caller stops waiting (a client that goes away, a
/// dropped handler): a hash that keeps running keeps counting.
async fn blocking<T: Send + 'static>(
    permits: &'static tokio::sync::Semaphore,
    wait: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AppError> {
    let permit = tokio::time::timeout(wait, permits.acquire())
        .await
        .map_err(|_| hashing_busy())?
        .map_err(|e| AppError::Internal(format!("hashing permits closed: {e}")))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|e| AppError::Internal(format!("hashing task failed: {e}")))
}

/// Issue and store an invite. The returned token and code are the only copy.
///
/// `hash_wait` bounds the wait for a free hashing permit
/// (`auth.claim_code_hash_wait_ms`).
pub async fn issue(
    ks: &KeyspaceHandle,
    req: InviteRequest,
    hash_wait: std::time::Duration,
) -> Result<IssuedInvite, AppError> {
    if req.purpose == Purpose::StepUp && req.role.is_some() {
        return Err(AppError::invalid("a step-up invite confers no role"));
    }
    let token = generate_token();
    let claim_code = generate_claim_code();
    let code = claim_code.clone();
    let claim = blocking(&ISSUE_HASH_PERMITS, hash_wait, move || {
        hash_claim_code(&code)
    })
    .await??;
    let now = now_epoch();
    let invite = Invite {
        invite_id: uuid::Uuid::new_v4().to_string(),
        token_hash: hash_token(&token),
        claim,
        subject: req.subject,
        purpose: req.purpose,
        role: req.role,
        device_label: req.device_label,
        issued_by: req.issued_by,
        amended_by: Vec::new(),
        created_at: now,
        expires_at: now.saturating_add(req.ttl_secs.max(1)),
        wrong_codes: 0,
        ceremony: None,
    };
    save(ks, &invite).await?;
    // The audit record: who let whom enrol what, until when. Never a secret.
    info!(
        target: "audit",
        event = "passkey.invite.issued",
        invite_id = %invite.invite_id,
        issued_by = %invite.issued_by,
        subject = %invite.subject,
        purpose = invite.purpose.as_str(),
        expires_at = invite.expires_at,
        "passkey enrolment invite issued"
    );
    Ok(IssuedInvite {
        invite,
        token,
        claim_code,
    })
}

/// Store (or rewrite) an invite and its id index, unlocked: for a new invite,
/// or under the invite's `ATTEMPT_LOCKS` guard. A rewrite of an existing
/// invite goes through [`update`], so it cannot bring back one that was taken
/// meanwhile.
pub async fn save(ks: &KeyspaceHandle, invite: &Invite) -> Result<(), AppError> {
    // The invite and its id index in one write: neither is ever stored
    // without the other.
    let mut batch = ks.batch();
    batch.insert(ks, invite_key(&invite.token_hash), invite)?;
    batch.insert_raw(
        ks,
        invite_id_key(&invite.invite_id),
        invite.token_hash.as_bytes().to_vec(),
    );
    batch.commit().await
}

/// The invite stored under `token_hash`.
pub async fn by_token_hash(
    ks: &KeyspaceHandle,
    token_hash: &str,
) -> Result<Option<Invite>, AppError> {
    ks.get(invite_key(token_hash)).await
}

/// The invite an administrator addresses by `invite_id`.
pub async fn by_id(ks: &KeyspaceHandle, invite_id: &str) -> Result<Option<Invite>, AppError> {
    let Some(bytes) = ks.get_raw(invite_id_key(invite_id)).await? else {
        return Ok(None);
    };
    let token_hash =
        String::from_utf8(bytes).map_err(|e| AppError::Internal(format!("invite index: {e}")))?;
    by_token_hash(ks, &token_hash).await
}

/// Every stored invite, newest first.
pub async fn list(ks: &KeyspaceHandle) -> Result<Vec<Invite>, AppError> {
    let mut out: Vec<Invite> = ks
        .prefix_iter_raw(INVITE_PREFIX)
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    out.sort_by_key(|i: &Invite| std::cmp::Reverse(i.created_at));
    Ok(out)
}

/// Consume the invite under `token_hash`, atomically: exactly one caller gets
/// it. Its id index goes with it.
///
/// Taken under the invite's `ATTEMPT_LOCKS` guard, so a wrong-code count,
/// a ceremony or an administrator's update in flight cannot write the invite
/// back after it is gone — a consumed or revoked invite stays consumed.
pub async fn take(ks: &KeyspaceHandle, token_hash: &str) -> Result<Option<Invite>, AppError> {
    let _guard = ATTEMPT_LOCKS.guard(token_hash).await;
    take_locked(ks, token_hash).await
}

/// [`take`], for a caller already holding the invite's guard.
async fn take_locked(ks: &KeyspaceHandle, token_hash: &str) -> Result<Option<Invite>, AppError> {
    let taken: Option<Invite> = ks.take(invite_key(token_hash)).await?;
    if let Some(ref invite) = taken {
        // The claim must stay the store's atomic take; what hangs off the
        // invite follows in one batch, not one remove each.
        let mut batch = ks.batch();
        batch.remove(ks, invite_id_key(&invite.invite_id));
        batch.remove(ks, wrong_codes_key(token_hash));
        batch.commit().await?;
    }
    Ok(taken)
}

/// Change the invite an administrator addresses by `invite_id`: `change` sees
/// the stored invite, read under its guard, and the result is written back
/// only if `change` succeeds. `None` when there is no such invite — including
/// one taken while the change waited for the guard.
pub async fn update<E: From<AppError>>(
    ks: &KeyspaceHandle,
    invite_id: &str,
    change: impl FnOnce(&mut Invite) -> Result<(), E>,
) -> Result<Option<Invite>, E> {
    let Some(found) = by_id(ks, invite_id).await? else {
        return Ok(None);
    };
    let _guard = ATTEMPT_LOCKS.guard(&found.token_hash).await;
    let Some(mut invite) = by_token_hash(ks, &found.token_hash).await? else {
        return Ok(None);
    };
    change(&mut invite)?;
    save(ks, &invite).await?;
    Ok(Some(invite))
}

/// Withdraw an invite by `invite_id`. `false` when there was none.
pub async fn revoke(ks: &KeyspaceHandle, invite_id: &str, by: &str) -> Result<bool, AppError> {
    let Some(invite) = by_id(ks, invite_id).await? else {
        return Ok(false);
    };
    let revoked = take(ks, &invite.token_hash).await?.is_some();
    if revoked {
        info!(
            target: "audit",
            event = "passkey.invite.revoked",
            invite_id = %invite_id,
            revoked_by = %by,
            subject = %invite.subject,
            "passkey enrolment invite revoked"
        );
    }
    Ok(revoked)
}

/// Present `token` and `claim_code`.
///
/// Every way of being wrong — no such token, expired, wrong code — answers
/// [`Redemption::Invalid`] after the same Argon2 work, so the answer is no
/// oracle for which half was wrong. A wrong code counts against the invite;
/// the [`MAX_WRONG_CODES`]th deletes it and answers
/// [`Redemption::TooManyAttempts`]. A right code leaves the count alone and
/// the invite unconsumed.
///
/// When the invite's attempt lock or every hashing permit stays busy for
/// `hash_wait`
/// (`auth.claim_code_hash_wait_ms`) the attempt is refused with
/// [`AppError::RateLimited`] and counts against nothing.
pub async fn redeem(
    ks: &KeyspaceHandle,
    token: &str,
    claim_code: &str,
    hash_wait: std::time::Duration,
) -> Result<Redemption, AppError> {
    let token_hash = hash_token(token);
    let now = now_epoch();
    let code = claim_code.to_string();
    // Locked only once the token names a stored invite, so the lock registry
    // holds real invites' hashes and never grows with guessed ones.
    let exists = by_token_hash(ks, &token_hash)
        .await?
        .is_some_and(|i| !i.is_expired(now));
    // The invite's attempt lock is waited for within the same bound as a
    // hashing permit: the holder ahead may itself be waiting for one.
    let _guard = match exists {
        true => Some(
            tokio::time::timeout(hash_wait, ATTEMPT_LOCKS.guard(&token_hash))
                .await
                .map_err(|_| hashing_busy())?,
        ),
        false => None,
    };
    let invite = match exists {
        true => by_token_hash(ks, &token_hash).await?,
        false => None,
    };
    let Some(mut invite) = invite.filter(|i| !i.is_expired(now)) else {
        blocking(&HASH_PERMITS, hash_wait, move || {
            verify_claim_code(&DECOY, &code)
        })
        .await?;
        return Ok(Redemption::Invalid);
    };
    let claim = invite.claim.clone();
    if blocking(&HASH_PERMITS, hash_wait, move || {
        verify_claim_code(&claim, &code)
    })
    .await?
    {
        return Ok(Redemption::Valid(Box::new(invite)));
    }
    // The lockout decision is made from the atomic counter, not from
    // `invite.wrong_codes` — the field mirrors it for observability (an
    // administrator reading the invite by id) but a replica racing this
    // call cannot lose an increment the way a plain get-then-save could.
    let wrong_codes = ks.incr_raw(wrong_codes_key(&token_hash)).await?;
    invite.wrong_codes = wrong_codes.min(u64::from(u32::MAX)) as u32;
    if wrong_codes >= u64::from(MAX_WRONG_CODES) {
        take_locked(ks, &token_hash).await?;
        info!(
            target: "audit",
            event = "passkey.invite.locked",
            invite_id = %invite.invite_id,
            subject = %invite.subject,
            wrong_codes,
            "passkey enrolment invite invalidated after too many wrong claim codes"
        );
        return Ok(Redemption::TooManyAttempts);
    }
    save(ks, &invite).await?;
    Ok(Redemption::Invalid)
}

/// Record `ceremony` as the one redemption ceremony open against the invite,
/// superseding any earlier one.
pub async fn open_ceremony(
    ks: &KeyspaceHandle,
    token_hash: &str,
    ceremony: &str,
) -> Result<(), AppError> {
    let _guard = ATTEMPT_LOCKS.guard(token_hash).await;
    let Some(mut invite) = by_token_hash(ks, token_hash).await? else {
        return Err(AppError::NotFound("invite not found".into()));
    };
    invite.ceremony = Some(ceremony.to_string());
    save(ks, &invite).await
}

#[cfg(test)]
#[path = "invite_tests.rs"]
mod tests;

//! Passkey enrolment invites (`auth/passkey/enroll/invite/0.2`), stored hashed.
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
//! Wrong claim codes are counted per invite. At [`MAX_WRONG_CODES`] the invite
//! is deleted, so a stolen URL gives an attacker a handful of guesses at a
//! 60-bit code and no more. An invite expires, and is consumed exactly once:
//! [`take`] is the atomic step that lets exactly one redemption bind a
//! credential.
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
    /// Who issued it: the administrator's VID, or `operator (CLI)`.
    pub issued_by: String,
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
    pub issued_by: String,
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

/// Serialises the read–verify–write of one invite's attempt counter, so
/// concurrent wrong codes are each counted.
static ATTEMPT_LOCKS: LazyLock<PathLocks> = LazyLock::new(PathLocks::new);

/// Claim-code hashes run at once, service-wide. Each takes
/// [`ARGON2_M_KIB`] of memory, and a stranger can ask for one per redemption
/// attempt — from as many sources as they can mint VIDs — so the per-source
/// rate limit alone does not bound the memory and CPU they can make the
/// service spend. Past this many, attempts queue.
const MAX_CONCURRENT_HASHES: usize = 8;

static HASH_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_HASHES);

/// Run one claim-code hash on the blocking pool, within [`HASH_PERMITS`].
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, AppError> {
    let _permit = HASH_PERMITS
        .acquire()
        .await
        .map_err(|e| AppError::Internal(format!("hashing permits closed: {e}")))?;
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AppError::Internal(format!("hashing task failed: {e}")))
}

/// Issue and store an invite. The returned token and code are the only copy.
pub async fn issue(ks: &KeyspaceHandle, req: InviteRequest) -> Result<IssuedInvite, AppError> {
    if req.purpose == Purpose::StepUp && req.role.is_some() {
        return Err(AppError::Validation(
            "a step-up invite confers no role".into(),
        ));
    }
    let token = generate_token();
    let claim_code = generate_claim_code();
    let code = claim_code.clone();
    let claim = blocking(move || hash_claim_code(&code)).await??;
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
/// or under the invite's [`ATTEMPT_LOCKS`] guard. A rewrite of an existing
/// invite goes through [`update`], so it cannot bring back one that was taken
/// meanwhile.
pub async fn save(ks: &KeyspaceHandle, invite: &Invite) -> Result<(), AppError> {
    ks.insert(invite_key(&invite.token_hash), invite).await?;
    ks.insert_raw(
        invite_id_key(&invite.invite_id),
        invite.token_hash.as_bytes().to_vec(),
    )
    .await
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
/// Taken under the invite's [`ATTEMPT_LOCKS`] guard, so a wrong-code count,
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
        ks.remove(invite_id_key(&invite.invite_id)).await?;
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
pub async fn redeem(
    ks: &KeyspaceHandle,
    token: &str,
    claim_code: &str,
) -> Result<Redemption, AppError> {
    let token_hash = hash_token(token);
    let now = now_epoch();
    let code = claim_code.to_string();
    // Locked only once the token names a stored invite, so the lock registry
    // holds real invites' hashes and never grows with guessed ones.
    let exists = by_token_hash(ks, &token_hash)
        .await?
        .is_some_and(|i| !i.is_expired(now));
    let _guard = match exists {
        true => Some(ATTEMPT_LOCKS.guard(&token_hash).await),
        false => None,
    };
    let invite = match exists {
        true => by_token_hash(ks, &token_hash).await?,
        false => None,
    };
    let Some(mut invite) = invite.filter(|i| !i.is_expired(now)) else {
        blocking(move || verify_claim_code(&DECOY, &code)).await?;
        return Ok(Redemption::Invalid);
    };
    let claim = invite.claim.clone();
    if blocking(move || verify_claim_code(&claim, &code)).await? {
        return Ok(Redemption::Valid(Box::new(invite)));
    }
    invite.wrong_codes += 1;
    if invite.wrong_codes >= MAX_WRONG_CODES {
        take_locked(ks, &token_hash).await?;
        info!(
            target: "audit",
            event = "passkey.invite.locked",
            invite_id = %invite.invite_id,
            subject = %invite.subject,
            wrong_codes = invite.wrong_codes,
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
mod tests {
    use super::*;
    use crate::server::config::StoreConfig;
    use crate::server::store::{KS_SESSIONS, Store};

    async fn ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .unwrap();
        (store.keyspace(KS_SESSIONS).unwrap(), dir)
    }

    fn request(purpose: Purpose) -> InviteRequest {
        InviteRequest {
            subject: "did:example:carol".into(),
            purpose,
            role: (purpose == Purpose::Session).then(|| "owner".into()),
            device_label: None,
            issued_by: "did:example:admin".into(),
            ttl_secs: 3600,
        }
    }

    #[test]
    fn secrets_have_the_entropy_the_spec_asks_for() {
        let token = generate_token();
        assert!(token.len() >= 16 + 4);
        let code = generate_claim_code();
        assert_eq!(normalise_claim_code(&code).len(), CLAIM_CODE_LEN);
        // 12 symbols of 5 bits each.
        const { assert!(CLAIM_CODE_LEN * 5 >= 40) };
        assert_ne!(generate_claim_code(), generate_claim_code());
    }

    #[test]
    fn a_claim_code_is_read_forgivingly() {
        assert_eq!(normalise_claim_code("7kq4-mx2p 9tda"), "7KQ4MX2P9TDA");
        assert_eq!(normalise_claim_code("OIL"), "011");
    }

    /// Neither the token nor the claim code is anywhere in what is stored —
    /// only a SHA-256 of the one and a salted Argon2id digest of the other.
    #[tokio::test]
    async fn an_invite_is_stored_hashed() {
        let (ks, _dir) = ks().await;
        let issued = issue(&ks, request(Purpose::Session)).await.unwrap();
        let rows = ks.iter_all().await.unwrap();
        assert!(!rows.is_empty());
        let code = normalise_claim_code(&issued.claim_code);
        for (k, v) in &rows {
            for haystack in [String::from_utf8_lossy(k), String::from_utf8_lossy(v)] {
                assert!(
                    !haystack.contains(&issued.token),
                    "token stored: {haystack}"
                );
                assert!(
                    !haystack.contains(&issued.claim_code),
                    "code stored: {haystack}"
                );
                assert!(!haystack.contains(&code), "code stored: {haystack}");
            }
        }
        let stored = by_id(&ks, &issued.invite.invite_id).await.unwrap().unwrap();
        assert_eq!(stored.token_hash, hash_token(&issued.token));
        assert!(verify_claim_code(&stored.claim, &issued.claim_code));
        // Salted: the same code hashes differently twice.
        let again = hash_claim_code(&issued.claim_code).unwrap();
        assert_ne!(again.digest, stored.claim.digest);
    }

    #[tokio::test]
    async fn both_halves_redeem_and_the_invite_stays_until_taken() {
        let (ks, _dir) = ks().await;
        let issued = issue(&ks, request(Purpose::Session)).await.unwrap();
        for _ in 0..2 {
            assert!(matches!(
                redeem(&ks, &issued.token, &issued.claim_code.to_lowercase())
                    .await
                    .unwrap(),
                Redemption::Valid(_)
            ));
        }
        // Single use.
        assert!(
            take(&ks, &issued.invite.token_hash)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            take(&ks, &issued.invite.token_hash)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            redeem(&ks, &issued.token, &issued.claim_code)
                .await
                .unwrap(),
            Redemption::Invalid
        ));
        assert!(
            by_id(&ks, &issued.invite.invite_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn wrong_codes_lock_the_invite_out() {
        let (ks, _dir) = ks().await;
        let issued = issue(&ks, request(Purpose::StepUp)).await.unwrap();
        for n in 1..MAX_WRONG_CODES {
            assert!(
                matches!(
                    redeem(&ks, &issued.token, "0000-0000-0000").await.unwrap(),
                    Redemption::Invalid
                ),
                "wrong code {n}"
            );
            let stored = by_id(&ks, &issued.invite.invite_id).await.unwrap().unwrap();
            assert_eq!(stored.wrong_codes, n);
        }
        assert!(matches!(
            redeem(&ks, &issued.token, "0000-0000-0000").await.unwrap(),
            Redemption::TooManyAttempts
        ));
        // Gone: the right code no longer redeems it.
        assert!(matches!(
            redeem(&ks, &issued.token, &issued.claim_code)
                .await
                .unwrap(),
            Redemption::Invalid
        ));
        assert!(
            by_id(&ks, &issued.invite.invite_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_wrong_codes_are_each_counted() {
        let (ks, _dir) = ks().await;
        let issued = issue(&ks, request(Purpose::Session)).await.unwrap();
        let tries = (0..MAX_WRONG_CODES).map(|_| {
            let ks = ks.clone();
            let token = issued.token.clone();
            tokio::spawn(async move { redeem(&ks, &token, "WRONGWRONG12").await.unwrap() })
        });
        let outcomes = futures_join(tries).await;
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, Redemption::TooManyAttempts))
                .count(),
            1
        );
        assert!(
            by_id(&ks, &issued.invite.invite_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A wrong code in flight while the invite is consumed must not write the
    /// invite back: once taken, it stays gone.
    #[tokio::test]
    async fn a_taken_invite_is_not_brought_back_by_a_racing_wrong_code() {
        let (ks, _dir) = ks().await;
        for _ in 0..8 {
            let issued = issue(&ks, request(Purpose::Session)).await.unwrap();
            let wrong = {
                let ks = ks.clone();
                let token = issued.token.clone();
                tokio::spawn(async move { redeem(&ks, &token, "WRONGWRONG12").await.unwrap() })
            };
            let taken = {
                let ks = ks.clone();
                let hash = issued.invite.token_hash.clone();
                tokio::spawn(async move { take(&ks, &hash).await.unwrap() })
            };
            wrong.await.unwrap();
            assert!(taken.await.unwrap().is_some());
            assert!(
                by_token_hash(&ks, &issued.invite.token_hash)
                    .await
                    .unwrap()
                    .is_none(),
                "a consumed invite was written back"
            );
        }
    }

    /// An administrator's update of an invite that has since been consumed
    /// finds nothing, and writes nothing.
    #[tokio::test]
    async fn an_update_does_not_bring_back_a_taken_invite() {
        let (ks, _dir) = ks().await;
        let issued = issue(&ks, request(Purpose::Session)).await.unwrap();
        assert!(
            take(&ks, &issued.invite.token_hash)
                .await
                .unwrap()
                .is_some()
        );
        let updated = update::<AppError>(&ks, &issued.invite.invite_id, |i| {
            i.expires_at += 60;
            Ok(())
        })
        .await
        .unwrap();
        assert!(updated.is_none());
        assert!(
            by_token_hash(&ks, &issued.invite.token_hash)
                .await
                .unwrap()
                .is_none()
        );
    }

    async fn futures_join<T>(handles: impl Iterator<Item = tokio::task::JoinHandle<T>>) -> Vec<T> {
        let mut out = Vec::new();
        for h in handles {
            out.push(h.await.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn an_expired_invite_redeems_nothing_and_is_swept() {
        let (ks, _dir) = ks().await;
        let issued = issue(&ks, request(Purpose::Session)).await.unwrap();
        let mut invite = by_id(&ks, &issued.invite.invite_id).await.unwrap().unwrap();
        invite.expires_at = now_epoch() - 1;
        save(&ks, &invite).await.unwrap();
        assert!(matches!(
            redeem(&ks, &issued.token, &issued.claim_code)
                .await
                .unwrap(),
            Redemption::Invalid
        ));
        // An expired invite's wrong codes are not counted: it is not redeemable.
        assert_eq!(
            by_id(&ks, &issued.invite.invite_id)
                .await
                .unwrap()
                .unwrap()
                .wrong_codes,
            0
        );
        crate::server::auth::session::cleanup_expired_sessions(&ks, 300)
            .await
            .unwrap();
        assert!(
            by_id(&ks, &issued.invite.invite_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_step_up_invite_confers_no_role() {
        let (ks, _dir) = ks().await;
        let mut req = request(Purpose::StepUp);
        req.role = Some("admin".into());
        assert!(issue(&ks, req).await.is_err());
    }
}

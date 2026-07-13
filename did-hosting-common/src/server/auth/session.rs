use uuid::Uuid;

use crate::server::acl::Role;
use crate::server::auth::jwt::JwtKeys;
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

// Canonical Session + SessionState now live in vti-common
// (`vti_common::auth::session`). Re-exported here so existing
// `use crate::server::auth::session::Session` paths keep
// compiling unchanged after the cross-repo unification.
//
// The storage helpers below (store_session, get_session, …)
// keep operating on did-hosting's own `KeyspaceHandle` +
// `AppError`; only the wire/storage shape is shared.
pub use ::vti_common::auth::session::{Session, SessionState};

fn session_key(session_id: &str) -> String {
    format!("session:{session_id}")
}

fn refresh_key(token: &str) -> String {
    format!("refresh:{token}")
}

/// Store a new session in the `sessions` keyspace.
pub async fn store_session(sessions: &KeyspaceHandle, session: &Session) -> Result<(), AppError> {
    sessions
        .insert(session_key(&session.session_id), session)
        .await?;
    debug!(session_id = %session.session_id, did = %session.did, "session stored");
    Ok(())
}

/// Load a session by session_id.
pub async fn get_session(
    sessions: &KeyspaceHandle,
    session_id: &str,
) -> Result<Option<Session>, AppError> {
    sessions.get(session_key(session_id)).await
}

/// Store a reverse index from refresh token to session_id.
pub async fn store_refresh_index(
    sessions: &KeyspaceHandle,
    token: &str,
    session_id: &str,
) -> Result<(), AppError> {
    sessions
        .insert_raw(refresh_key(token), session_id.as_bytes().to_vec())
        .await
}

/// Look up a session_id by refresh token.
pub async fn get_session_by_refresh(
    sessions: &KeyspaceHandle,
    token: &str,
) -> Result<Option<String>, AppError> {
    match sessions.get_raw(refresh_key(token)).await? {
        Some(bytes) => {
            let session_id = String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid session_id bytes: {e}")))?;
            Ok(Some(session_id))
        }
        None => Ok(None),
    }
}

/// Atomically look up *and consume* the refresh-token → session_id index.
///
/// Backed by `KeyspaceHandle::take_raw` (`Redis GETDEL` / DynamoDB
/// `DeleteItem`+`ReturnValues=ALL_OLD` / fjall mutex). Exactly one
/// concurrent caller observes `Some` for any given refresh token, even
/// across replicas backed by Redis or DynamoDB.
///
/// This is the cross-replica equivalent of the in-process `RefreshClaim`
/// added in an earlier round, and replaces it on the rotation path: the
/// caller that wins the take is the only one that proceeds to delete the
/// session and create a new one. Losers see `Ok(None)` and reject the
/// refresh as already consumed.
pub async fn take_session_id_by_refresh(
    sessions: &KeyspaceHandle,
    token: &str,
) -> Result<Option<String>, AppError> {
    match sessions.take_raw(refresh_key(token)).await? {
        Some(bytes) => {
            let session_id = String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid session_id bytes: {e}")))?;
            Ok(Some(session_id))
        }
        None => Ok(None),
    }
}

/// Returns the current UNIX epoch timestamp in seconds.
///
/// Uses `unwrap_or_default()` so a system clock set before 1970 yields
/// 0 rather than panicking — every caller (JWT issue, session create,
/// log ingest) would otherwise propagate the panic and fail the
/// request with a 500 instead of a sensible error.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Delete a single session and its refresh index.
pub async fn delete_session(sessions: &KeyspaceHandle, session_id: &str) -> Result<(), AppError> {
    let session: Option<Session> = sessions.get(session_key(session_id)).await?;
    if let Some(session) = session {
        if let Some(ref token) = session.refresh_token {
            sessions.remove(refresh_key(token)).await?;
        }
        sessions.remove(session_key(session_id)).await?;
        debug!(session_id, "session deleted");
    }
    Ok(())
}

/// Remove expired sessions from the store.
///
/// - `ChallengeSent` sessions expire after `challenge_ttl` seconds from `created_at`.
/// - `Authenticated` sessions expire when `refresh_expires_at` has passed.
pub async fn cleanup_expired_sessions(
    sessions: &KeyspaceHandle,
    challenge_ttl: u64,
) -> Result<(), AppError> {
    let entries = sessions.prefix_iter_raw("session:").await?;
    let now = now_epoch();
    let mut removed = 0u64;

    for (key, value) in entries {
        let session: Session = match serde_json::from_slice(&value) {
            Ok(s) => s,
            Err(e) => {
                warn!("skipping malformed session record: {e}");
                continue;
            }
        };

        let expired = match session.state {
            SessionState::ChallengeSent => now.saturating_sub(session.created_at) > challenge_ttl,
            SessionState::Authenticated => session
                .refresh_expires_at
                .is_none_or(|expires| now > expires),
        };

        if expired {
            sessions.remove(key).await?;
            if let Some(ref token) = session.refresh_token {
                sessions.remove(refresh_key(token)).await?;
            }
            removed += 1;
        }
    }

    // Clean up expired enrollment tokens (have an `expires_at` field).
    let enrollments = sessions.prefix_iter_raw("enroll:").await?;
    for (key, value) in enrollments {
        #[derive(serde::Deserialize)]
        struct EnrollmentExpiry {
            expires_at: u64,
        }
        if let Ok(e) = serde_json::from_slice::<EnrollmentExpiry>(&value)
            && now > e.expires_at
        {
            sessions.remove(key).await?;
            removed += 1;
        }
    }

    debug!(removed, "session cleanup complete");

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared authenticated-session creation (used by DIDComm + passkey flows)
// ---------------------------------------------------------------------------

/// Response payload returned to clients after successful authentication.
/// Carries the absolute access/refresh expiries + the JWT's AAL claims
/// so the route handler can synthesise the canonical
/// `AuthenticateResponse { session, tokens }` shape without
/// re-deriving them.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub session_id: String,
    pub subject: String,
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
    /// Issuance moment (Unix seconds). The canonical wire encodes
    /// this as `session.issuedAt`; `expiresIn` = `access_expires_at -
    /// issued_at`.
    pub issued_at: u64,
    /// Authentication methods references — `["did"]` for the
    /// challenge-response path, augmented by step-up handlers.
    pub amr: Vec<String>,
    /// Authentication context class — `"aal1"` for single-factor,
    /// `"aal2"` after step-up.
    pub acr: String,
}

impl TokenResponse {
    /// Convert to the canonical `AuthenticateResponse { session, tokens }`
    /// wire shape. The route handler calls this once and returns
    /// `Json(token_resp.into_canonical())`.
    pub fn into_canonical(self) -> crate::AuthenticateResponse {
        let session_expires_at_epoch = self.refresh_expires_at.max(self.access_expires_at);
        crate::AuthenticateResponse {
            session: crate::Session {
                id: self.session_id,
                subject: self.subject,
                issued_at: crate::epoch_to_rfc3339(self.issued_at),
                expires_at: crate::epoch_to_rfc3339(session_expires_at_epoch),
                amr: self.amr,
                acr: self.acr,
            },
            tokens: crate::TokenBundle {
                access_token: self.access_token,
                refresh_token: Some(self.refresh_token),
                token_type: "Bearer".to_string(),
                expires_in: self.access_expires_at.saturating_sub(self.issued_at),
                refresh_expires_in: Some(self.refresh_expires_at.saturating_sub(self.issued_at)),
                scope: Vec::new(),
            },
        }
    }
}

/// Generate access + refresh tokens for an authenticated session.
///
/// `amr_acr_override` lets refresh paths preserve an elevated session's
/// AAL — pass `Some((["did","passkey"], "aal2"))` to mint a token at
/// the post-step-up level. `None` falls back to the Claims-struct
/// defaults (`["did"]`/`"aal1"`), correct for first-time authenticate.
fn generate_tokens(
    jwt_keys: &JwtKeys,
    did: &str,
    session_id: &str,
    role: &Role,
    access_expiry: u64,
    refresh_expiry: u64,
    amr_acr_override: Option<(Vec<String>, String)>,
) -> Result<(String, u64, String, u64, String), AppError> {
    let mut claims = JwtKeys::new_claims(
        did.to_string(),
        session_id.to_string(),
        role.to_string(),
        access_expiry,
    );
    if let Some((amr, acr)) = amr_acr_override {
        claims.amr = amr;
        claims.acr = acr;
    }
    let access_expires_at = claims.exp;
    let token_id = claims.jti.clone();
    let access_token = jwt_keys.encode(&claims)?;
    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = now_epoch() + refresh_expiry;
    Ok((
        access_token,
        access_expires_at,
        refresh_token,
        refresh_expires_at,
        token_id,
    ))
}

/// Upgrade an existing `ChallengeSent` session to `Authenticated`, generating
/// tokens and storing the refresh index. Used by DIDComm auth which preserves
/// the original session_id from the challenge phase.
pub async fn finalize_challenge_session(
    sessions: &KeyspaceHandle,
    jwt_keys: &JwtKeys,
    session: &mut Session,
    role: &Role,
    access_expiry: u64,
    refresh_expiry: u64,
) -> Result<TokenResponse, AppError> {
    let (access_token, access_expires_at, refresh_token, refresh_expires_at, token_id) =
        generate_tokens(
            jwt_keys,
            &session.did,
            &session.session_id,
            role,
            access_expiry,
            refresh_expiry,
            None,
        )?;

    // Persist AAL on the session row so refresh re-mints at the same
    // level (challenge-response is aal1; passkey / VTA step-up
    // elevates via `elevate_session` which records the higher value).
    session.state = SessionState::Authenticated;
    session.refresh_token = Some(refresh_token.clone());
    session.refresh_expires_at = Some(refresh_expires_at);
    session.token_id = Some(token_id);
    session.amr = vec!["did".to_string()];
    session.acr = "aal1".to_string();
    store_session(sessions, session).await?;

    store_refresh_index(sessions, &refresh_token, &session.session_id).await?;

    Ok(TokenResponse {
        session_id: session.session_id.clone(),
        subject: session.did.clone(),
        access_token,
        access_expires_at,
        refresh_token,
        refresh_expires_at,
        issued_at: now_epoch(),
        // DIDComm challenge-response: single DID-key factor.
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
    })
}

/// Create a new authenticated session, returning access + refresh tokens.
///
/// Reusable across DIDComm and passkey authentication flows.
///
/// `session_pubkey_b58btc` is the optional client-supplied ephemeral
/// Ed25519 multikey (base58btc, `z6Mk…`) used for Data Integrity
/// proofs on REQUIRED-spec trust-task requests. `None` for backend
/// callers that sign with their own DID's verification methods, or
/// when the Web UI hasn't enabled in-band signing yet.
///
/// `amr_acr_override` lets the refresh handler preserve an elevated
/// session's AAL across the rotation. Initial authenticate paths
/// pass `None` and get the defaults (`["did"]`/`"aal1"`); refresh
/// reads the pre-rotation session's amr/acr and passes
/// `Some((..., ...))` so the new session row + JWT carry the same
/// values.
// Eight cohesive parameters shared by the DIDComm and passkey auth
// flows; grouping them into a struct would add churn at every call
// site for no clarity gain. (clippy::too_many_arguments is default-deny
// as of clippy 1.96.)
#[allow(clippy::too_many_arguments)]
pub async fn create_authenticated_session(
    sessions: &KeyspaceHandle,
    jwt_keys: &JwtKeys,
    did: &str,
    role: &Role,
    access_expiry: u64,
    refresh_expiry: u64,
    session_pubkey_b58btc: Option<String>,
    amr_acr_override: Option<(Vec<String>, String)>,
) -> Result<TokenResponse, AppError> {
    let session_id = Uuid::new_v4().to_string();

    let (access_token, access_expires_at, refresh_token, refresh_expires_at, token_id) =
        generate_tokens(
            jwt_keys,
            did,
            &session_id,
            role,
            access_expiry,
            refresh_expiry,
            amr_acr_override.clone(),
        )?;

    let (amr, acr) =
        amr_acr_override.unwrap_or_else(|| (vec!["did".to_string()], "aal1".to_string()));
    let session = Session {
        session_id: session_id.clone(),
        did: did.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        last_seen: now_epoch(),
        refresh_token: Some(refresh_token.clone()),
        refresh_expires_at: Some(refresh_expires_at),
        tee_attested: false,
        token_id: Some(token_id),
        session_pubkey_b58btc,
        amr: amr.clone(),
        acr: acr.clone(),
        // An elevated `acr` arriving via `amr_acr_override` carries no lapse
        // deadline: our step-up is bounded by the access token's TTL, not by
        // vti-common's read-time downgrade in `resolve_did_session`.
        acr_expires_at: None,
    };

    store_session(sessions, &session).await?;
    store_refresh_index(sessions, &refresh_token, &session_id).await?;

    Ok(TokenResponse {
        session_id,
        subject: did.to_string(),
        access_token,
        access_expires_at,
        refresh_token,
        refresh_expires_at,
        issued_at: now_epoch(),
        amr,
        acr,
    })
}

/// Elevate an existing authenticated session to a higher assurance level,
/// minting a fresh token with the given `amr`/`acr` and rotating the
/// session's `token_id` so the prior (lower-`acr`) access token is
/// invalidated. The `session_id` is preserved — this upgrades the session
/// in place rather than creating a new one. Used by step-up.
#[allow(clippy::too_many_arguments)]
pub async fn elevate_session(
    sessions: &KeyspaceHandle,
    jwt_keys: &JwtKeys,
    session_id: &str,
    role: &Role,
    amr: Vec<String>,
    acr: &str,
    access_expiry: u64,
    refresh_expiry: u64,
) -> Result<TokenResponse, AppError> {
    let mut session = get_session(sessions, session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;
    if session.state != SessionState::Authenticated {
        return Err(AppError::Authentication("session not authenticated".into()));
    }

    let mut claims = JwtKeys::new_claims(
        session.did.clone(),
        session_id.to_string(),
        role.to_string(),
        access_expiry,
    );
    claims.amr = amr.clone();
    claims.acr = acr.to_string();
    let access_expires_at = claims.exp;
    let token_id = claims.jti.clone();
    let access_token = jwt_keys.encode(&claims)?;

    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = now_epoch() + refresh_expiry;

    // Persist the elevated AAL on the session row so subsequent
    // refreshes preserve aal2 (instead of silently dropping back to
    // the pre-step-up aal1).
    session.token_id = Some(token_id);
    session.refresh_token = Some(refresh_token.clone());
    session.refresh_expires_at = Some(refresh_expires_at);
    session.amr = amr.clone();
    session.acr = acr.to_string();
    store_session(sessions, &session).await?;
    store_refresh_index(sessions, &refresh_token, session_id).await?;

    Ok(TokenResponse {
        session_id: session_id.to_string(),
        subject: session.did.clone(),
        access_token,
        access_expires_at,
        refresh_token,
        refresh_expires_at,
        issued_at: now_epoch(),
        amr,
        acr: acr.to_string(),
    })
}

/// Guards the invariant that [`cleanup_expired_sessions`] silently depends on:
/// **every session did-hosting creates carries a refresh token.**
///
/// The sweeper bounds an `Authenticated` session by `refresh_expires_at`, and
/// treats `None` as *already expired* — so a refresh-less session is deleted on
/// the very next pass, seconds after it is written.
///
/// That is harmless today because nothing here creates one. But vti-common has
/// a second session shape — DID-keyed (`session_id == did`), no refresh token,
/// reaped on an idle TTL via `Session::last_seen` — minted by its
/// `resolve_did_session`. did-hosting does not use it: our DIDComm/TSP callers
/// hold no session at all (trust-task handlers authorise per-message off the
/// envelope's sender DID via the ACL), and the one DIDComm path that *does*
/// authenticate hands back a normal token pair.
///
/// If someone later adopts `resolve_did_session` — say to give TSP callers
/// step-up/AAL state — those sessions will be eaten by the sweeper the moment
/// they are written, which is a baffling bug to debug from the symptom. These
/// tests fail first, and point here.
#[cfg(all(test, feature = "store-fjall"))]
mod refresh_token_invariant {
    use super::*;
    use crate::server::config::StoreConfig;
    use crate::server::store::{KS_SESSIONS, Store};
    use std::path::PathBuf;

    async fn make_ks() -> (KeyspaceHandle, JwtKeys, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        })
        .await
        .unwrap();
        let ks = store.keyspace(KS_SESSIONS).unwrap();
        let keys = JwtKeys::from_ed25519_bytes(&[11u8; 32]).unwrap();
        (ks, keys, dir)
    }

    /// Both production creators must leave a refresh token on the row.
    #[tokio::test]
    async fn sessions_we_create_carry_a_refresh_token() {
        let (ks, keys, _dir) = make_ks().await;

        let created = create_authenticated_session(
            &ks,
            &keys,
            "did:example:alice",
            &Role::Owner,
            60,
            900,
            None,
            None,
        )
        .await
        .expect("create session");

        let stored = get_session(&ks, &created.session_id)
            .await
            .expect("load")
            .expect("session exists");
        assert!(
            stored.refresh_token.is_some() && stored.refresh_expires_at.is_some(),
            "create_authenticated_session must leave a refresh token: cleanup_expired_sessions \
             reaps refresh-less Authenticated sessions on the next pass"
        );

        // Step-up rotates the tokens; it must not drop the refresh token either.
        elevate_session(
            &ks,
            &keys,
            &created.session_id,
            &Role::Owner,
            vec!["did".to_string(), "passkey".to_string()],
            "aal2",
            60,
            900,
        )
        .await
        .expect("elevate");

        let elevated = get_session(&ks, &created.session_id)
            .await
            .expect("load")
            .expect("session exists");
        assert!(
            elevated.refresh_token.is_some() && elevated.refresh_expires_at.is_some(),
            "elevate_session must leave a refresh token on the row"
        );
    }

    /// Pins *why* the invariant matters: this is the fate of a refresh-less
    /// session under our sweeper. If you are here because you adopted
    /// vti-common's intrinsic (DID-keyed, refresh-less) sessions, this branch
    /// of `cleanup_expired_sessions` is what you must teach about
    /// `Session::last_seen` and an idle TTL first.
    #[tokio::test]
    async fn sweeper_reaps_a_refreshless_authenticated_session_immediately() {
        let (ks, _keys, _dir) = make_ks().await;

        let intrinsic = Session {
            session_id: "did:example:tsp-caller".to_string(),
            did: "did:example:tsp-caller".to_string(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            token_id: None,
            session_pubkey_b58btc: None,
            amr: vec!["did".to_string()],
            acr: "aal1".to_string(),
            acr_expires_at: None,
        };
        store_session(&ks, &intrinsic).await.expect("store");

        cleanup_expired_sessions(&ks, 300).await.expect("sweep");

        assert!(
            get_session(&ks, &intrinsic.session_id)
                .await
                .expect("load")
                .is_none(),
            "a refresh-less Authenticated session is reaped on the next sweep, however recently \
             it was seen — teach cleanup_expired_sessions about last_seen before creating one"
        );
    }
}

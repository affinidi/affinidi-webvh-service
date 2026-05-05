use uuid::Uuid;

use crate::server::acl::Role;
use crate::server::auth::jwt::JwtKeys;
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Refresh-rotation in-process lock
// ---------------------------------------------------------------------------
//
// Closes a TOCTOU between `get_session_by_refresh` and `delete_session`.
// Without this guard, two concurrent requests with the same leaked refresh
// token both pass the lookup before either deletes — both would rotate the
// session and mint two parallel valid token streams from a single refresh
// token.
//
// Backend-level atomic remove-and-return primitives (Redis GETDEL,
// DynamoDB DeleteItem with ReturnValues=ALL_OLD, etc.) would be the
// principled fix for distributed deployments. For the default single-
// process daemon this in-process lock is sufficient and adds no
// cross-node coordination cost.

fn refresh_rotation_locks() -> &'static Mutex<HashSet<String>> {
    static LOCKS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Exclusive lease on a single refresh token's rotation. Released on drop.
#[derive(Debug)]
pub struct RefreshClaim {
    token: String,
}

/// Attempt to claim exclusive use of `refresh_token` for the duration of
/// a rotation. Returns `Err(AppError::Conflict)` if another worker is
/// already rotating the same token in this process — the caller should
/// treat that as "race lost; refresh already consumed by a parallel
/// request" and reject without rotating again.
pub fn try_claim_refresh_rotation(refresh_token: &str) -> Result<RefreshClaim, AppError> {
    let mut locks = refresh_rotation_locks()
        .lock()
        .map_err(|e| AppError::Internal(format!("refresh lock poisoned: {e}")))?;
    if !locks.insert(refresh_token.to_string()) {
        return Err(AppError::Conflict(
            "refresh token rotation already in progress".into(),
        ));
    }
    Ok(RefreshClaim {
        token: refresh_token.to_string(),
    })
}

impl Drop for RefreshClaim {
    fn drop(&mut self) {
        if let Ok(mut locks) = refresh_rotation_locks().lock() {
            locks.remove(&self.token);
        }
    }
}

#[cfg(test)]
mod refresh_claim_tests {
    use super::*;

    #[test]
    fn second_concurrent_claim_for_same_token_is_rejected() {
        let token = "test-refresh-token-A";
        let claim = try_claim_refresh_rotation(token).expect("first claim succeeds");

        let err = try_claim_refresh_rotation(token).unwrap_err();
        assert!(
            matches!(err, AppError::Conflict(_)),
            "expected Conflict for second concurrent claim, got {err:?}"
        );

        // Drop the first claim and the token becomes claimable again.
        drop(claim);
        let _again = try_claim_refresh_rotation(token).expect("released claim is reusable");
    }

    #[test]
    fn distinct_tokens_can_be_claimed_independently() {
        let _a = try_claim_refresh_rotation("token-A").unwrap();
        let _b = try_claim_refresh_rotation("token-B").unwrap();
        // Both succeeded — distinct tokens don't contend.
    }
}

/// Session lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    ChallengeSent,
    Authenticated,
}

/// A session record stored under `session:{session_id}`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub did: String,
    pub challenge: String,
    pub state: SessionState,
    pub created_at: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<u64>,
    /// Current token ID — JWT `jti` must match this to be valid. Rotated on
    /// each token issue/refresh so old tokens are immediately invalidated.
    #[serde(default)]
    pub token_id: Option<String>,
}

// Manual `Debug` redacts the secret fields (challenge, refresh_token, token_id)
// so a casual `tracing::debug!(?session, …)` does not leak material a leak-
// detector would flag. Non-secret fields (session_id, did, state, timestamps)
// stay visible for diagnostics.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("did", &self.did)
            .field("challenge", &"<redacted>")
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("token_id", &self.token_id.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

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

/// Returns the current UNIX epoch timestamp in seconds.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
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
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub session_id: String,
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

/// Generate access + refresh tokens for an authenticated session.
fn generate_tokens(
    jwt_keys: &JwtKeys,
    did: &str,
    session_id: &str,
    role: &Role,
    access_expiry: u64,
    refresh_expiry: u64,
) -> Result<(String, u64, String, u64, String), AppError> {
    let claims = JwtKeys::new_claims(
        did.to_string(),
        session_id.to_string(),
        role.to_string(),
        access_expiry,
    );
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
        )?;

    session.state = SessionState::Authenticated;
    session.refresh_token = Some(refresh_token.clone());
    session.refresh_expires_at = Some(refresh_expires_at);
    session.token_id = Some(token_id);
    store_session(sessions, session).await?;

    store_refresh_index(sessions, &refresh_token, &session.session_id).await?;

    Ok(TokenResponse {
        session_id: session.session_id.clone(),
        access_token,
        access_expires_at,
        refresh_token,
        refresh_expires_at,
    })
}

/// Create a new authenticated session, returning access + refresh tokens.
///
/// Reusable across DIDComm and passkey authentication flows.
pub async fn create_authenticated_session(
    sessions: &KeyspaceHandle,
    jwt_keys: &JwtKeys,
    did: &str,
    role: &Role,
    access_expiry: u64,
    refresh_expiry: u64,
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
        )?;

    let session = Session {
        session_id: session_id.clone(),
        did: did.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: Some(refresh_token.clone()),
        refresh_expires_at: Some(refresh_expires_at),
        token_id: Some(token_id),
    };

    store_session(sessions, &session).await?;
    store_refresh_index(sessions, &refresh_token, &session_id).await?;

    Ok(TokenResponse {
        session_id,
        access_token,
        access_expires_at,
        refresh_token,
        refresh_expires_at,
    })
}

use uuid::Uuid;

use crate::acl::Role;
use crate::auth::jwt::JwtKeys;
use crate::error::AppError;
use crate::store::KeyspaceHandle;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Session lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    ChallengeSent,
    Authenticated,
}

/// A session record stored in fjall under `session:{session_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub did: String,
    pub challenge: String,
    pub state: SessionState,
    pub created_at: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<u64>,
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
#[allow(dead_code)]
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
            Err(_) => continue,
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
) -> Result<(String, u64, String, u64), AppError> {
    let claims = JwtKeys::new_claims(
        did.to_string(),
        session_id.to_string(),
        role.to_string(),
        access_expiry,
    );
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;
    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = now_epoch() + refresh_expiry;
    Ok((access_token, access_expires_at, refresh_token, refresh_expires_at))
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
    let (access_token, access_expires_at, refresh_token, refresh_expires_at) =
        generate_tokens(jwt_keys, &session.did, &session.session_id, role, access_expiry, refresh_expiry)?;

    session.state = SessionState::Authenticated;
    session.refresh_token = Some(refresh_token.clone());
    session.refresh_expires_at = Some(refresh_expires_at);
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

    let (access_token, access_expires_at, refresh_token, refresh_expires_at) =
        generate_tokens(jwt_keys, did, &session_id, role, access_expiry, refresh_expiry)?;

    let session = Session {
        session_id: session_id.clone(),
        did: did.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: Some(refresh_token.clone()),
        refresh_expires_at: Some(refresh_expires_at),
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

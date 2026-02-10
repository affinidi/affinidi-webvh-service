use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::UnpackOptions;
use affinidi_webvh_common::{
    AuthenticateData, AuthenticateResponse, ChallengeData, ChallengeResponse, RefreshData,
    RefreshResponse,
};

use crate::acl::check_acl;
use crate::auth::jwt::JwtKeys;
use crate::auth::session::{
    Session, SessionState, finalize_challenge_session, get_session, get_session_by_refresh,
    now_epoch, store_session,
};
use crate::error::AppError;
use crate::server::AppState;
use tracing::{info, warn};

// ---------- POST /auth/challenge ----------

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub did: String,
}

pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    // ACL enforcement: DID must be in the ACL to request a challenge
    let acl = state.acl_ks.clone();
    check_acl(&acl, &req.did).await?;

    let session_id = uuid::Uuid::new_v4().to_string();

    // Generate 32-byte random challenge as hex
    let mut challenge_bytes = [0u8; 32];
    rand::fill(&mut challenge_bytes);
    let challenge = hex::encode(challenge_bytes);

    let session = Session {
        session_id: session_id.clone(),
        did: req.did,
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
    };

    let sessions = state.sessions_ks.clone();
    store_session(&sessions, &session).await?;

    info!(did = %session.did, session_id = %session.session_id, "auth challenge issued");

    Ok(Json(ChallengeResponse {
        session_id,
        data: ChallengeData { challenge },
    }))
}

// ---------- POST /auth/ ----------

pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Authentication("DID resolver not configured".into()))?;
    let secrets_resolver = state
        .secrets_resolver
        .as_ref()
        .ok_or_else(|| AppError::Authentication("secrets resolver not configured".into()))?;
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    // Unpack the DIDComm message
    let (msg, _metadata) = Message::unpack_string(
        &body,
        did_resolver,
        secrets_resolver.as_ref(),
        &UnpackOptions::default(),
    )
    .await
    .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Validate message type
    if msg.type_ != "https://affinidi.com/webvh/1.0/authenticate" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.type_
        )));
    }

    // Extract challenge and session_id from body
    let challenge = msg.body["challenge"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?;
    let session_id = msg.body["session_id"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?;

    // Validate sender DID
    let sender_did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("message has no sender (from)".into()))?;

    // Look up session and validate
    let sessions = state.sessions_ks.clone();
    let mut session = get_session(&sessions, session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::ChallengeSent {
        warn!(session_id, "authentication rejected: session replay");
        return Err(AppError::Authentication(
            "session already authenticated (replay)".into(),
        ));
    }
    if session.challenge != challenge {
        warn!(session_id, "authentication rejected: challenge mismatch");
        return Err(AppError::Authentication("challenge mismatch".into()));
    }
    // Match the DID (compare base DID, ignoring any fragment)
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);
    if session.did != sender_base {
        warn!(session_id, sender = %sender_base, expected = %session.did, "authentication rejected: DID mismatch");
        return Err(AppError::Authentication("DID mismatch".into()));
    }

    // Check challenge TTL
    if now_epoch().saturating_sub(session.created_at) > state.config.auth.challenge_ttl {
        warn!(session_id, "authentication rejected: challenge expired");
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // Look up ACL entry to get role for the token
    let acl = state.acl_ks.clone();
    let role = check_acl(&acl, &session.did).await?;

    // Generate tokens and finalize session
    let token_resp = finalize_challenge_session(
        &sessions,
        jwt_keys,
        &mut session,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
    )
    .await?;

    info!(did = %session.did, session_id = %session.session_id, "authentication successful");

    Ok(Json(AuthenticateResponse {
        session_id: token_resp.session_id,
        data: AuthenticateData {
            access_token: token_resp.access_token,
            access_expires_at: token_resp.access_expires_at,
            refresh_token: token_resp.refresh_token,
            refresh_expires_at: token_resp.refresh_expires_at,
        },
    }))
}

// ---------- POST /auth/refresh ----------

pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<RefreshResponse>, AppError> {
    let did_resolver = state
        .did_resolver
        .as_ref()
        .ok_or_else(|| AppError::Authentication("DID resolver not configured".into()))?;
    let secrets_resolver = state
        .secrets_resolver
        .as_ref()
        .ok_or_else(|| AppError::Authentication("secrets resolver not configured".into()))?;
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    // Unpack the DIDComm message
    let (msg, _metadata) = Message::unpack_string(
        &body,
        did_resolver,
        secrets_resolver.as_ref(),
        &UnpackOptions::default(),
    )
    .await
    .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    // Validate message type
    if msg.type_ != "https://affinidi.com/webvh/1.0/authenticate/refresh" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.type_
        )));
    }

    // Extract refresh_token from body
    let refresh_token = msg.body["refresh_token"]
        .as_str()
        .ok_or_else(|| AppError::Authentication("missing refresh_token in message body".into()))?;

    // Look up session by refresh token
    let sessions = state.sessions_ks.clone();
    let session_id = get_session_by_refresh(&sessions, refresh_token)
        .await?
        .ok_or_else(|| AppError::Authentication("refresh token not found".into()))?;

    let session = get_session(&sessions, &session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::Authenticated {
        return Err(AppError::Authentication("session not authenticated".into()));
    }

    // Verify refresh token hasn't expired
    if let Some(expires_at) = session.refresh_expires_at
        && now_epoch() > expires_at
    {
        return Err(AppError::Authentication("refresh token expired".into()));
    }

    // Look up current ACL role (propagates changes at refresh time)
    let acl = state.acl_ks.clone();
    let role = check_acl(&acl, &session.did).await?;

    // Generate new access token
    let claims = JwtKeys::new_claims(
        session.did.clone(),
        session.session_id.clone(),
        role.to_string(),
        state.config.auth.access_token_expiry,
    );
    let access_expires_at = claims.exp;
    let access_token = jwt_keys.encode(&claims)?;

    info!(did = %session.did, session_id = %session.session_id, "token refreshed");

    Ok(Json(RefreshResponse {
        session_id: session.session_id,
        data: RefreshData {
            access_token,
            access_expires_at,
        },
    }))
}

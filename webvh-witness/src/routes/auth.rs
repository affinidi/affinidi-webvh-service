use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::acl::check_acl;
use crate::auth::session::{
    Session, SessionState, create_authenticated_session, finalize_challenge_session, get_session,
    get_session_by_refresh, now_epoch, store_session,
};
use crate::error::AppError;
use crate::server::AppState;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub did: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub session_id: String,
    pub data: ChallengeData,
}

#[derive(Serialize)]
pub struct ChallengeData {
    pub challenge: String,
}

#[derive(Serialize)]
pub struct AuthenticateResponse {
    pub session_id: String,
    pub data: AuthenticateData,
}

#[derive(Serialize)]
pub struct AuthenticateData {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    // Verify DID is in ACL
    let _role = check_acl(&state.acl_ks, &req.did).await?;

    // Generate challenge
    let challenge = hex::encode(rand::random::<[u8; 32]>());
    let session_id = uuid::Uuid::new_v4().to_string();
    let now = now_epoch();

    let session = Session {
        session_id: session_id.clone(),
        did: req.did.clone(),
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now,
        refresh_token: None,
        refresh_expires_at: None,
    };

    store_session(&state.sessions_ks, &session).await?;

    Ok(Json(ChallengeResponse {
        session_id,
        data: ChallengeData { challenge },
    }))
}

pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    use affinidi_tdk::didcomm::Message;

    let (did_resolver, secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    let (msg, _metadata) = Message::unpack_string(
        &body,
        did_resolver,
        secrets_resolver,
        &affinidi_tdk::didcomm::UnpackOptions::default(),
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

    // Extract fields
    let challenge = msg
        .body
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?;

    let session_id = msg
        .body
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?;

    // Load session
    let mut session = get_session(&state.sessions_ks, session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    // Validate session state
    if session.state != SessionState::ChallengeSent {
        return Err(AppError::Authentication("invalid session state".into()));
    }

    // Validate challenge
    if session.challenge != challenge {
        return Err(AppError::Authentication("challenge mismatch".into()));
    }

    // Validate DID matches (compare base DID without fragment)
    let sender_did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("missing sender DID".into()))?;
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);

    if sender_base != session.did {
        return Err(AppError::Authentication("DID mismatch".into()));
    }

    // Check challenge TTL
    let now = now_epoch();
    if now - session.created_at > state.config.auth.challenge_ttl {
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // Re-check ACL for current role
    let role = check_acl(&state.acl_ks, &session.did).await?;

    // Finalize session
    let token_response = finalize_challenge_session(
        &state.sessions_ks,
        jwt_keys,
        &mut session,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
    )
    .await?;

    Ok(Json(AuthenticateResponse {
        session_id: token_response.session_id,
        data: AuthenticateData {
            access_token: token_response.access_token,
            access_expires_at: token_response.access_expires_at,
            refresh_token: token_response.refresh_token,
            refresh_expires_at: token_response.refresh_expires_at,
        },
    }))
}

pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<serde_json::Value>, AppError> {
    use affinidi_tdk::didcomm::Message;

    let (did_resolver, secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    let (msg, _metadata) = Message::unpack_string(
        &body,
        did_resolver,
        secrets_resolver,
        &affinidi_tdk::didcomm::UnpackOptions::default(),
    )
    .await
    .map_err(|e| AppError::Authentication(format!("failed to unpack refresh message: {e}")))?;

    if msg.type_ != "https://affinidi.com/webvh/1.0/authenticate/refresh" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.type_
        )));
    }

    let refresh_token = msg
        .body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing refresh_token".into()))?;

    // get_session_by_refresh returns Option<String> (session_id)
    let session_id = get_session_by_refresh(&state.sessions_ks, refresh_token)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    let session = get_session(&state.sessions_ks, &session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::Authenticated {
        return Err(AppError::Authentication("invalid session state".into()));
    }

    let now = now_epoch();
    if let Some(expires) = session.refresh_expires_at {
        if now > expires {
            return Err(AppError::Authentication("refresh token expired".into()));
        }
    }

    // Re-check ACL
    let role = check_acl(&state.acl_ks, &session.did).await?;

    let token_response = create_authenticated_session(
        &state.sessions_ks,
        jwt_keys,
        &session.did,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "session_id": token_response.session_id,
        "data": {
            "access_token": token_response.access_token,
            "access_expires_at": token_response.access_expires_at,
        }
    })))
}

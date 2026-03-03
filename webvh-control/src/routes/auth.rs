//! DIDComm challenge-response authentication routes.

use axum::Json;
use axum::extract::State;
use tracing::{info, warn};

use affinidi_webvh_common::{ChallengeRequest, ChallengeResponse, ChallengeData};

use crate::auth::session::{self, SessionState, Session, now_epoch};
use crate::error::AppError;
use crate::server::AppState;

/// POST /api/auth/challenge — request a challenge nonce.
pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let challenge = uuid::Uuid::new_v4().to_string();
    let session_id = uuid::Uuid::new_v4().to_string();

    let session = Session {
        session_id: session_id.clone(),
        did: req.did.clone(),
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
    };

    session::store_session(&state.sessions_ks, &session).await?;

    info!(did = %req.did, session_id = %session_id, "challenge issued");

    Ok(Json(ChallengeResponse {
        session_id,
        data: ChallengeData { challenge },
    }))
}

/// POST /api/auth/ — authenticate with a signed DIDComm message.
pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<affinidi_webvh_common::AuthenticateResponse>, AppError> {
    use affinidi_tdk::didcomm::Message;

    let (did_resolver, secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    // Unpack the signed DIDComm message
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

    // Extract session_id and challenge from the message body
    let session_id = msg
        .body
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?;

    let challenge = msg
        .body
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?;

    // Look up the session
    let mut session = session::get_session(&state.sessions_ks, session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    if session.state != SessionState::ChallengeSent {
        return Err(AppError::Authentication("session already authenticated".into()));
    }
    if session.challenge != challenge {
        return Err(AppError::Authentication("challenge mismatch".into()));
    }

    // Check TTL
    let now = now_epoch();
    if now.saturating_sub(session.created_at) > state.config.auth.challenge_ttl {
        session::delete_session(&state.sessions_ks, session_id).await?;
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // Verify sender DID matches session DID (compare base DID without fragment)
    let sender_did = msg
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("missing sender DID".into()))?;
    let sender_base = sender_did.split('#').next().unwrap_or(sender_did);

    if sender_base != session.did {
        warn!(
            expected = %session.did,
            actual = %sender_base,
            "DID mismatch in authentication"
        );
        return Err(AppError::Authentication("DID mismatch".into()));
    }

    // Determine role from ACL
    let role = crate::acl::check_acl(&state.acl_ks, &session.did).await?;

    // Finalize session and issue tokens
    let token_response = session::finalize_challenge_session(
        &state.sessions_ks,
        jwt_keys,
        &mut session,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
    )
    .await?;

    info!(did = %session.did, role = %role, "authenticated via DIDComm");

    Ok(Json(affinidi_webvh_common::AuthenticateResponse {
        session_id: token_response.session_id,
        data: affinidi_webvh_common::AuthenticateData {
            access_token: token_response.access_token,
            access_expires_at: token_response.access_expires_at,
            refresh_token: token_response.refresh_token,
            refresh_expires_at: token_response.refresh_expires_at,
        },
    }))
}

/// POST /api/auth/refresh — refresh an access token.
pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<affinidi_webvh_common::RefreshResponse>, AppError> {
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;

    let refresh_token = body.trim().trim_matches('"');

    let session_id =
        session::get_session_by_refresh(&state.sessions_ks, refresh_token)
            .await?
            .ok_or_else(|| AppError::Authentication("invalid refresh token".into()))?;

    let session = session::get_session(&state.sessions_ks, &session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    // Check refresh token hasn't expired
    if let Some(expires_at) = session.refresh_expires_at {
        if now_epoch() > expires_at {
            session::delete_session(&state.sessions_ks, &session_id).await?;
            return Err(AppError::Authentication("refresh token expired".into()));
        }
    }

    let role = crate::acl::check_acl(&state.acl_ks, &session.did).await?;

    let claims = crate::auth::jwt::JwtKeys::new_claims(
        session.did.clone(),
        session_id.clone(),
        role.to_string(),
        state.config.auth.access_token_expiry,
    );
    let access_token = jwt_keys.encode(&claims)?;

    info!(did = %session.did, "token refreshed");

    Ok(Json(affinidi_webvh_common::RefreshResponse {
        session_id,
        data: affinidi_webvh_common::RefreshData {
            access_token,
            access_expires_at: claims.exp,
        },
    }))
}

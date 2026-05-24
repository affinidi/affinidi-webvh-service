use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use did_hosting_common::server::auth::constant_time_eq;
use tracing::warn;

use crate::acl::check_acl;
use crate::auth::session::{
    Session, SessionState, create_authenticated_session, delete_session,
    finalize_challenge_session, get_session, now_epoch, store_session,
};
use crate::error::AppError;
use crate::server::AppState;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub did: String,
}

// Wire types reuse did-hosting-common's canonical shapes
// (spec/auth/challenge/0.1#response, spec/auth/authenticate/0.1#response)
// so the witness exposes the same wire contract as the main
// did-hosting daemon.
pub use did_hosting_common::{AuthenticateResponse, ChallengeResponse};

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
        tee_attested: false,
        token_id: None,
        session_pubkey_b58btc: None,
        amr: Vec::new(),
        acr: String::new(),
    };

    store_session(&state.sessions_ks, &session).await?;

    // Canonical wire: { challenge, sessionId, expiresAt }.
    let expires_at_epoch = session
        .created_at
        .saturating_add(state.config.auth.challenge_ttl);
    Ok(Json(ChallengeResponse {
        challenge,
        session_id,
        expires_at: did_hosting_common::epoch_to_rfc3339(expires_at_epoch),
    }))
}

pub async fn authenticate(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<AuthenticateResponse>, AppError> {
    let (did_resolver, _secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    // sender_base is the JWS-verified DID (unpack_signed enforced from == signer).
    let (msg, sender_base) =
        did_hosting_common::server::didcomm_unpack::unpack_signed(&body, did_resolver).await?;

    // Validate message type
    if msg.typ != "https://affinidi.com/webvh/1.0/authenticate" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
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

    // Validate challenge (constant-time to prevent timing side-channels)
    if !constant_time_eq(session.challenge.as_bytes(), challenge.as_bytes()) {
        warn!(session_id, "authentication rejected: challenge mismatch");
        return Err(AppError::Authentication("challenge mismatch".into()));
    }

    // sender_base is JWS-verified by unpack_signed.
    if sender_base != session.did {
        warn!(session_id, sender = %sender_base, expected = %session.did, "authentication rejected: DID mismatch");
        return Err(AppError::Authentication("DID mismatch".into()));
    }

    // Check challenge TTL (saturating_sub to prevent underflow on clock skew)
    let now = now_epoch();
    let challenge_ttl = state.config.auth.challenge_ttl;
    if now.saturating_sub(session.created_at) > challenge_ttl {
        warn!(session_id, "authentication rejected: challenge expired");
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // Validate DIDComm message created_time to prevent replay attacks
    let created_time = msg
        .created_time
        .ok_or_else(|| AppError::Authentication("message missing created_time".into()))?;
    if created_time < session.created_at {
        warn!(
            session_id,
            created_time,
            session_created = session.created_at,
            "authentication rejected: message created_time before challenge"
        );
        return Err(AppError::Authentication(
            "message created_time is before the challenge was issued".into(),
        ));
    }
    if now.saturating_sub(created_time) > challenge_ttl {
        warn!(
            session_id,
            created_time,
            now,
            challenge_ttl,
            "authentication rejected: message created_time outside challenge TTL"
        );
        return Err(AppError::Authentication(
            "message created_time is outside the challenge TTL window".into(),
        ));
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

    Ok(Json(token_response.into_canonical()))
}

pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<serde_json::Value>, AppError> {
    let (did_resolver, _secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    // sender_base is JWS-verified; refresh requires the holder's signed envelope.
    let (msg, sender_base) =
        did_hosting_common::server::didcomm_unpack::unpack_signed(&body, did_resolver).await?;

    if msg.typ != "https://affinidi.com/webvh/1.0/authenticate/refresh" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
        )));
    }

    let refresh_token = msg
        .body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing refresh_token".into()))?;

    // Atomically claim and consume the refresh-token → session_id index.
    // Cross-replica safe via Redis GETDEL / DynamoDB DeleteItem
    // ReturnValues=ALL_OLD / fjall mutex. Closes the rotation TOCTOU.
    let session_id = did_hosting_common::server::auth::session::take_session_id_by_refresh(
        &state.sessions_ks,
        refresh_token,
    )
    .await?
    .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    let session = get_session(&state.sessions_ks, &session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    // Bind the JWS signer to the session DID. Without this check, a leaked
    // refresh token plus any attacker-controlled DID is enough to rotate the
    // victim's tokens — the signed envelope alone proves possession of *some*
    // signing key, not the right one.
    if sender_base != session.did {
        warn!(
            session_id = %session.session_id,
            session_did = %session.did,
            sender = %sender_base,
            "refresh rejected: signer DID does not match session DID",
        );
        return Err(AppError::Authentication(
            "signer DID does not match session DID".into(),
        ));
    }

    if session.state != SessionState::Authenticated {
        return Err(AppError::Authentication("invalid session state".into()));
    }

    let now = now_epoch();
    if let Some(expires) = session.refresh_expires_at
        && now > expires
    {
        return Err(AppError::Authentication("refresh token expired".into()));
    }

    // Re-check ACL
    let role = check_acl(&state.acl_ks, &session.did).await?;

    // Preserve the pre-rotation AAL so a step-upped session stays at
    // its existing level across refresh. Empty amr on legacy rows
    // falls back to ["did"]/"aal1".
    let preserved_amr_acr = if session.amr.is_empty() {
        None
    } else {
        Some((session.amr.clone(), session.acr.clone()))
    };

    // Invalidate the old session to prevent refresh token reuse
    delete_session(&state.sessions_ks, &session.session_id).await?;

    let token_response = create_authenticated_session(
        &state.sessions_ks,
        jwt_keys,
        &session.did,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
        None,
        preserved_amr_acr,
    )
    .await?;

    // Canonical { session, tokens } shape via the helper on TokenResponse.
    Ok(Json(serde_json::to_value(token_response.into_canonical())?))
}

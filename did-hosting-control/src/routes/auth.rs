//! DIDComm challenge-response authentication routes.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use tracing::{info, warn};

use did_hosting_common::server::auth::constant_time_eq;
use did_hosting_common::{ChallengeData, ChallengeRequest, ChallengeResponse};

use crate::auth::session::{self, Session, SessionState, now_epoch};
use crate::error::AppError;
use crate::rate_limit::resolve_client_ip;
use crate::server::AppState;

/// Maximum concurrent pending challenges per DID. Combined with the
/// global cap on the `pending_challenges` tracker on `AppState`, this
/// bounds the unauthenticated challenge-endpoint surface against both
/// per-DID floods and DID-sweep attacks.
const MAX_PENDING_CHALLENGES_PER_DID: u64 = 10;

/// POST /api/auth/challenge — request a challenge nonce.
///
/// Two layers of rate-limit defence:
/// 1. Per-IP fixed-window counter (`IpRateLimiter`) — caps requests
///    from any single IP regardless of which DID they're issuing
///    challenges for. Trusted-proxy XFF resolution per
///    `server.trusted_proxies` config.
/// 2. Per-DID + global pending-challenge cap (`PendingChallengeTracker`)
///    — caps the active session population.
///
/// Replaced an earlier O(N) `prefix_iter_raw("session:")` scan with
/// the O(1) in-memory tracker (review SM3).
pub async fn challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    // Input validation
    if req.did.len() > 512 {
        return Err(AppError::Validation("DID exceeds maximum length".into()));
    }

    // IP rate limit (defence in depth before any session-storage I/O).
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let client_ip = resolve_client_ip(addr.ip(), xff, &state.config.server.trusted_proxies);
    state
        .ip_rate_limiter
        .try_consume(client_ip, now_epoch())
        .inspect_err(|e| {
            warn!(ip = %client_ip, error = %e, "challenge IP rate limited");
        })?;

    // Reserve a pending-challenge slot. Rejects on per-DID cap or
    // global cap; the global cap is the defence against an attacker
    // sweeping millions of distinct DIDs.
    state
        .pending_challenges
        .try_issue(&req.did, MAX_PENDING_CHALLENGES_PER_DID)
        .await
        .inspect_err(|e| {
            warn!(did = %req.did, error = %e, "challenge rate limited");
        })?;

    let challenge_bytes = rand::random::<[u8; 32]>();
    let challenge = challenge_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let session_id = uuid::Uuid::new_v4().to_string();

    let session = Session {
        session_id: session_id.clone(),
        did: req.did.clone(),
        challenge: challenge.clone(),
        state: SessionState::ChallengeSent,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
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
) -> Result<Json<did_hosting_common::AuthenticateResponse>, AppError> {
    use did_hosting_common::server::didcomm_unpack;

    let (did_resolver, _secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    // Unpack the signed DIDComm message; sender_base is the JWS-verified DID.
    let (msg, sender_base) = didcomm_unpack::unpack_signed(&body, did_resolver).await?;

    // Validate message type
    if msg.typ != "https://affinidi.com/webvh/1.0/authenticate" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
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
        return Err(AppError::Authentication(
            "session already authenticated".into(),
        ));
    }
    if !constant_time_eq(session.challenge.as_bytes(), challenge.as_bytes()) {
        warn!(session_id, "authentication rejected: challenge mismatch");
        return Err(AppError::Authentication("challenge mismatch".into()));
    }

    // Check TTL
    let now = now_epoch();
    if now.saturating_sub(session.created_at) > state.config.auth.challenge_ttl {
        session::delete_session(&state.sessions_ks, session_id).await?;
        // Free the pending-challenge slot so the legitimate caller
        // can re-issue. Without this, an expired challenge would
        // hold the slot until the per-DID cap caused subsequent
        // challenges to fail with the wrong error.
        state.pending_challenges.release(&session.did).await;
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // sender_base is the JWS-verified DID (unpack_signed enforced from == signer).
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

    // Optional: pick up the client's ephemeral session pubkey
    // (Ed25519 multikey, base58btc-encoded with the `z` prefix).
    // Stored on the session so `dispatch_trust_task` can verify
    // Data Integrity proofs on REQUIRED-spec trust-task requests
    // came from the same browser session that authenticated.
    //
    // We validate the prefix shape minimally — only ed25519
    // multikey is supported today (`z6Mk` is the base58btc-encoded
    // multicodec 0xed01 prefix). Anything else is rejected so the
    // server doesn't accept a key shape it can't later resolve via
    // `did:key`.
    if let Some(pk) = msg
        .body
        .get("session_pubkey_b58btc")
        .and_then(|v| v.as_str())
    {
        if !pk.starts_with("z6Mk") {
            warn!(prefix = %&pk[..pk.len().min(8)], "rejected unsupported session-key shape");
            return Err(AppError::Authentication(
                "session_pubkey_b58btc must be an Ed25519 multikey (z6Mk… prefix)".into(),
            ));
        }
        session.session_pubkey_b58btc = Some(pk.to_string());
    }

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

    // Free the pending-challenge slot now that the session has
    // transitioned to Authenticated.
    state.pending_challenges.release(&session.did).await;

    info!(did = %session.did, role = %role, "authenticated via DIDComm");

    Ok(Json(did_hosting_common::AuthenticateResponse {
        session_id: token_response.session_id,
        data: did_hosting_common::AuthenticateData {
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
) -> Result<Json<did_hosting_common::RefreshResponse>, AppError> {
    use did_hosting_common::server::didcomm_unpack;

    let (did_resolver, _secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    // Parity with server/witness: refresh requires a JWS-signed DIDComm
    // envelope addressed by the holder of the session DID. Proves
    // possession of the signing key, not just the bearer refresh token,
    // so a leaked refresh token alone cannot rotate a victim's tokens.
    let (msg, sender_base) = didcomm_unpack::unpack_signed(&body, did_resolver).await?;

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
        .ok_or_else(|| AppError::Authentication("missing refresh_token in message body".into()))?;

    // Atomically claim and consume the refresh-token → session_id index in
    // a single backend operation (Redis GETDEL / DynamoDB DeleteItem with
    // ReturnValues=ALL_OLD / fjall mutex). Exactly one concurrent request
    // with the same token sees `Some` here, even across replicas. Losers
    // see `None` and reject as if the token were invalid — which it now
    // is, having been consumed by the winner.
    let session_id = session::take_session_id_by_refresh(&state.sessions_ks, refresh_token)
        .await?
        .ok_or_else(|| AppError::Authentication("invalid refresh token".into()))?;

    let session = session::get_session(&state.sessions_ks, &session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    // Bind the JWS signer to the session DID. Same invariant as server/witness:
    // signing proves possession of the right key for *this* session, not just
    // some key for some DID.
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

    // Verify session is in Authenticated state
    if session.state != SessionState::Authenticated {
        warn!(session_id = %session.session_id, "refresh rejected: session not authenticated");
        return Err(AppError::Authentication("session not authenticated".into()));
    }

    // Check refresh token hasn't expired
    if let Some(expires_at) = session.refresh_expires_at
        && now_epoch() > expires_at
    {
        session::delete_session(&state.sessions_ks, &session_id).await?;
        return Err(AppError::Authentication("refresh token expired".into()));
    }

    // Refresh rotates everything: a brand-new session id, access token, and
    // refresh token. The old session is deleted atomically so a leaked
    // refresh token cannot be reused.
    session::delete_session(&state.sessions_ks, &session.session_id).await?;

    let role = crate::acl::check_acl(&state.acl_ks, &session.did).await?;

    let token_response = session::create_authenticated_session(
        &state.sessions_ks,
        jwt_keys,
        &session.did,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
        None,
    )
    .await?;

    info!(did = %session.did, "token refreshed");

    Ok(Json(did_hosting_common::RefreshResponse {
        session_id: token_response.session_id,
        data: did_hosting_common::RefreshData {
            access_token: token_response.access_token,
            access_expires_at: token_response.access_expires_at,
            refresh_token: token_response.refresh_token,
            refresh_expires_at: token_response.refresh_expires_at,
        },
    }))
}

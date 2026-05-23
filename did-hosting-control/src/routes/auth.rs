//! DIDComm challenge-response authentication routes.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use tracing::{info, warn};

use did_hosting_common::server::auth::constant_time_eq;
use did_hosting_common::{ChallengeRequest, ChallengeResponse, epoch_to_rfc3339};

use crate::auth::AuthClaims;
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

    // Canonical wire: { challenge, sessionId, expiresAt }.
    let expires_at_epoch = session
        .created_at
        .saturating_add(state.config.auth.challenge_ttl);
    Ok(Json(ChallengeResponse {
        challenge,
        session_id,
        expires_at: epoch_to_rfc3339(expires_at_epoch),
    }))
}

/// POST /api/auth/ — authenticate with a SIOPv2 self-issued `id_token`.
///
/// The request body is a Trust-Task-shaped envelope whose `type` is the
/// flat, exact-match-routed `did-hosting/auth/authenticate/1.0` URL and
/// whose `payload` carries an [`AuthenticatePayload`] (`id_token`,
/// `session_id`, optional `session_pubkey_b58btc`). Because that flat URL
/// is not a framework `/spec/<slug>/<ver>` `TypeUri`, the envelope is
/// parsed by hand rather than as a `trust_tasks_rs::TrustTask<Value>`.
///
/// The `id_token` is a compact EdDSA JWS the wallet self-issues, signed
/// by its `did:key`. We verify it by resolving the issuer DID and
/// checking the signature, then bind the JWT to the resolved DID.
///
/// Body is accepted as raw bytes (mirroring `routes/trust_tasks.rs`) so
/// a malformed envelope surfaces a `trust-task-error/0.1` document with
/// `code: malformed_request` rather than axum's text/plain default.
pub async fn authenticate(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    use did_hosting_common::AuthenticatePayload;
    use did_hosting_common::server::didcomm_unpack;
    use did_hosting_common::v1_aliases;

    let (did_resolver, _secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    // ─── 1. Parse the authenticate envelope.
    //
    // The did-hosting task identifiers (`https://trusttasks.org/did-hosting/
    // …`) are exact-match routed strings, *not* framework `/spec/<slug>/
    // <ver>` `TypeUri`s. So the body cannot be deserialized as
    // `trust_tasks_rs::TrustTask<Value>`: that type's `type_uri: TypeUri`
    // field runs the strict `/spec/` parser and rejects our flat URI. We
    // parse a minimal envelope by hand and match the `type` string the same
    // way the DIDComm dispatcher matches `msg.typ` — via `v1_aliases`. A
    // parse failure emits a routed `trust-task-error/0.1` document with
    // `code: malformed_request` (same pattern as the /trust-tasks endpoint).
    #[derive(serde::Deserialize)]
    struct AuthEnvelope {
        #[serde(rename = "type")]
        type_uri: String,
        payload: serde_json::Value,
    }

    let envelope: AuthEnvelope = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            return Ok(trust_task_malformed(&format!(
                "body did not parse as an authenticate envelope: {e}"
            )));
        }
    };

    // Envelope `type` must canonicalise to the authenticate task. Accepts
    // both the canonical `did-hosting/auth/authenticate/1.0` URL and its
    // legacy `affinidi.com/webvh/1.0/authenticate` alias.
    let expected_type = did_hosting_common::did_hosting_tasks::TASK_AUTH_AUTHENTICATE_0_1.as_str();
    if v1_aliases::canonicalize(&envelope.type_uri) != Some(expected_type) {
        return Ok(trust_task_malformed(&format!(
            "unexpected Trust-Task type: expected {expected_type}, got {}",
            envelope.type_uri
        )));
    }

    let payload: AuthenticatePayload = match serde_json::from_value(envelope.payload) {
        Ok(p) => p,
        Err(e) => {
            return Ok(trust_task_malformed(&format!(
                "authenticate payload malformed: {e}"
            )));
        }
    };

    // ─── 2–4. Verify the SIOPv2 id_token: signature over
    //          `header.payload` against the `iss` did:key's resolved
    //          Ed25519 authentication key, with `iss == sub`.
    let verified = didcomm_unpack::verify_siop_id_token(&payload.id_token, did_resolver).await?;

    // ─── 6. Look up the session named by the payload's `session_id`.
    let mut session = session::get_session(&state.sessions_ks, &payload.session_id)
        .await?
        .ok_or_else(|| AppError::Authentication("session not found".into()))?;

    // ─── 7. Session must be awaiting a challenge response.
    if session.state != SessionState::ChallengeSent {
        return Err(AppError::Authentication(
            "session already authenticated".into(),
        ));
    }

    // ─── 6 (cont). nonce must equal the issued challenge (constant-time).
    if !constant_time_eq(session.challenge.as_bytes(), verified.nonce.as_bytes()) {
        warn!(session_id = %payload.session_id, "authentication rejected: nonce mismatch");
        return Err(AppError::Authentication("nonce mismatch".into()));
    }

    // ─── 7 (cont). Same challenge-TTL check as the legacy flow.
    let now = now_epoch();
    if now.saturating_sub(session.created_at) > state.config.auth.challenge_ttl {
        session::delete_session(&state.sessions_ks, &payload.session_id).await?;
        // Free the pending-challenge slot so the legitimate caller
        // can re-issue. Without this, an expired challenge would
        // hold the slot until the per-DID cap caused subsequent
        // challenges to fail with the wrong error.
        state.pending_challenges.release(&session.did).await;
        return Err(AppError::Authentication("challenge expired".into()));
    }

    // ─── 5. `aud` must equal this service's RP identifier (its own
    //        DID, configured as `server_did`). Without a configured
    //        server DID there is no RP identity to bind the token to,
    //        so refuse rather than accept an unbound token.
    let rp_id = state.config.server_did.as_deref().ok_or_else(|| {
        AppError::Config("server_did not configured; cannot verify id_token `aud`".into())
    })?;
    if verified.audience != rp_id {
        warn!(
            expected = %rp_id,
            actual = %verified.audience,
            "authentication rejected: id_token `aud` does not match this service",
        );
        return Err(AppError::Authentication(
            "id_token `aud` does not match this service".into(),
        ));
    }

    // ─── 8. The authenticated DID is `iss`; it must match the DID the
    //        challenge was issued to (replaces the legacy
    //        `sender_base != session.did` check).
    if verified.issuer != session.did {
        warn!(
            expected = %session.did,
            actual = %verified.issuer,
            "DID mismatch in authentication",
        );
        return Err(AppError::Authentication("DID mismatch".into()));
    }

    // ─── 9. Token freshness: `exp` in the future, `iat` not in the
    //        future (small skew tolerance) and not after `exp`.
    const CLOCK_SKEW_SECS: u64 = 60;
    if verified.expires_at <= now {
        return Err(AppError::Authentication("id_token has expired".into()));
    }
    if verified.issued_at > now + CLOCK_SKEW_SECS {
        return Err(AppError::Authentication(
            "id_token `iat` is in the future".into(),
        ));
    }
    if verified.issued_at > verified.expires_at {
        return Err(AppError::Authentication(
            "id_token `iat` is after `exp`".into(),
        ));
    }

    // Determine role from ACL.
    let role = crate::acl::check_acl(&state.acl_ks, &session.did).await?;

    // ─── 10. Optional: pick up the client's ephemeral session pubkey
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
    if let Some(pk) = payload.session_pubkey_b58btc.as_deref() {
        if !pk.starts_with("z6Mk") {
            warn!(prefix = %&pk[..pk.len().min(8)], "rejected unsupported session-key shape");
            return Err(AppError::Authentication(
                "session_pubkey_b58btc must be an Ed25519 multikey (z6Mk… prefix)".into(),
            ));
        }
        session.session_pubkey_b58btc = Some(pk.to_string());
    }

    // Finalize session and issue tokens — same primitive as the legacy
    // flow, so the JWT shape and lifetimes are unchanged.
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

    info!(did = %session.did, role = %role, "authenticated via SIOPv2 id_token");

    let resp = token_response.into_canonical();
    Ok(Json(resp).into_response())
}

/// Build a `trust-task-error/0.1` HTTP response for a malformed
/// authenticate envelope. Mirrors `routes/trust_tasks.rs::body_parse_error`
/// — unrouted (no source issuer/recipient to draw from), `code:
/// malformed_request`, mapped to its spec status via `status_for_code`.
fn trust_task_malformed(reason: &str) -> Response {
    use trust_tasks_https::status_for_code;
    use trust_tasks_rs::{ErrorPayload, RejectReason};
    use uuid::Uuid;

    let reject = RejectReason::MalformedRequest {
        reason: reason.to_string(),
    };
    let payload: ErrorPayload = reject.into();
    let status_u16 = status_for_code(&payload.code);
    let status =
        axum::http::StatusCode::from_u16(status_u16).unwrap_or(axum::http::StatusCode::BAD_REQUEST);
    let err_doc = trust_tasks_rs::ErrorResponse {
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        thread_id: None,
        type_uri: "https://trusttasks.org/spec/trust-task-error/0.1"
            .parse()
            .expect("framework error Type URI parses"),
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    };
    let body = serde_json::to_vec(&err_doc).expect("error document serialises");
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// POST /api/auth/step-up/vta/start — issue a step-up nonce bound to the
/// caller's session. The wallet relays it to the VTA, which signs an
/// approval committing to it.
pub async fn step_up_vta_start(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let nonce = rand::random::<[u8; 32]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    state
        .sessions_ks
        .insert_raw(
            format!("stepup-nonce:{}", auth.session_id),
            nonce.as_bytes().to_vec(),
        )
        .await?;
    Ok(Json(serde_json::json!({ "nonce": nonce })))
}

#[derive(serde::Deserialize)]
pub struct StepUpVtaFinishRequest {
    /// VTA-signed approval token (compact EdDSA JWS).
    pub approval_token: String,
}

/// POST /api/auth/step-up/vta/finish — verify a VTA-signed approval and
/// elevate the caller's session to `aal2` (`amr: [did, vta]`).
pub async fn step_up_vta_finish(
    State(state): State<AppState>,
    auth: AuthClaims,
    Json(req): Json<StepUpVtaFinishRequest>,
) -> Result<Json<did_hosting_common::server::auth::session::TokenResponse>, AppError> {
    use did_hosting_common::server::didcomm_unpack;

    let (did_resolver, _secrets_resolver, jwt_keys) = state.require_didcomm_auth()?;

    let trusted_vta = state
        .config
        .step_up_trusted_vta_did
        .as_deref()
        .ok_or_else(|| {
            AppError::Config("step_up_trusted_vta_did not configured; VTA step-up disabled".into())
        })?;
    let rp_id = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| AppError::Config("server_did not configured".into()))?;

    let verified =
        didcomm_unpack::verify_vta_approval_token(&req.approval_token, did_resolver).await?;

    // ─── Bindings. ───
    if verified.issuer != trusted_vta {
        warn!(expected = %trusted_vta, actual = %verified.issuer, "step-up rejected: approval not from the trusted VTA");
        return Err(AppError::Forbidden(
            "approval was not issued by the trusted VTA".into(),
        ));
    }
    if verified.subject != auth.did {
        warn!(authed = %auth.did, subject = %verified.subject, "step-up rejected: approval subject mismatch");
        return Err(AppError::Authentication(
            "approval subject does not match the authenticated DID".into(),
        ));
    }
    if verified.audience != rp_id {
        return Err(AppError::Authentication(
            "approval audience does not match this service".into(),
        ));
    }

    // Consume the session-bound nonce (single use).
    let stored = state
        .sessions_ks
        .take_raw(format!("stepup-nonce:{}", auth.session_id))
        .await?
        .ok_or_else(|| {
            AppError::Authentication("no step-up challenge issued for this session".into())
        })?;
    let stored = String::from_utf8(stored)
        .map_err(|e| AppError::Internal(format!("stored nonce not utf8: {e}")))?;
    if !constant_time_eq(stored.as_bytes(), verified.nonce.as_bytes()) {
        warn!(session_id = %auth.session_id, "step-up rejected: nonce mismatch");
        return Err(AppError::Authentication("step-up nonce mismatch".into()));
    }

    // Freshness.
    const CLOCK_SKEW_SECS: u64 = 60;
    let now = now_epoch();
    if verified.expires_at <= now {
        return Err(AppError::Authentication("approval has expired".into()));
    }
    if verified.issued_at > now + CLOCK_SKEW_SECS {
        return Err(AppError::Authentication(
            "approval `iat` is in the future".into(),
        ));
    }

    let role = crate::acl::check_acl(&state.acl_ks, &auth.did).await?;
    let token_resp = session::elevate_session(
        &state.sessions_ks,
        jwt_keys,
        &auth.session_id,
        &role,
        vec!["did".to_string(), "vta".to_string()],
        "aal2",
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
    )
    .await?;

    info!(did = %auth.did, "step-up complete via VTA approval: session elevated to aal2");
    Ok(Json(token_resp))
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

    // RefreshResponse is an alias for AuthenticateResponse — same
    // canonical { session, tokens } shape.
    Ok(Json(token_response.into_canonical()))
}

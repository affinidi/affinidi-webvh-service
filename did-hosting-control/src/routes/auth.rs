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
    // Input validation (route-layer concern).
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

    // Reserve a pending-challenge slot via the O(1) tracker. Per-DID
    // cap + global cap (against DID-sweep attacks). The canonical
    // handler's per-DID limit is disabled in this backend; the
    // tracker is the single source of truth.
    state
        .pending_challenges
        .try_issue(&req.did, MAX_PENDING_CHALLENGES_PER_DID)
        .await
        .inspect_err(|e| {
            warn!(did = %req.did, error = %e, "challenge rate limited");
        })?;

    let backend = crate::auth::DidHostingControlAuthBackend::from_state(&state)?;
    let canonical = vti_common::auth::handlers::handle_challenge(
        &backend,
        vti_common::auth::ChallengeInput {
            did: req.did,
            session_pubkey_b58btc: None,
        },
    )
    .await?;
    // did-hosting's ChallengeResponse drops the canonical
    // `teeAttestation` field — did-hosting doesn't run in a TEE.
    Ok(Json(ChallengeResponse {
        challenge: canonical.challenge,
        session_id: canonical.session_id,
        expires_at: canonical.expires_at,
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

    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    // ─── 1. Parse the Trust-Task envelope.
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

    // ─── 2. SIOPv2 id_token verification (transport layer).
    //
    // Verifies signature against the iss did:key, checks
    // iss == sub, returns the bound claims. Everything else —
    // session lookup, challenge match, signer-DID-binds-to-
    // session-DID, challenge TTL — flows through the canonical
    // handler.
    let verified = didcomm_unpack::verify_siop_id_token(&payload.id_token, did_resolver).await?;

    // ─── 3. id_token-layer checks the canonical handler doesn't
    //        know about: audience binding to this service's
    //        `server_did`, plus the JWT's own iat/exp window.
    //        These are properties of the SIOPv2 token, not the
    //        challenge-response session.
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

    let now = now_epoch();
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

    // ─── 4. Session pubkey validation (route-layer concern —
    //        the canonical handler treats it opaquely).
    let session_pubkey_b58btc = if let Some(pk) = payload.session_pubkey_b58btc.as_deref() {
        if !pk.starts_with("z6Mk") {
            warn!(prefix = %&pk[..pk.len().min(8)], "rejected unsupported session-key shape");
            return Err(AppError::Authentication(
                "session_pubkey_b58btc must be an Ed25519 multikey (z6Mk… prefix)".into(),
            ));
        }
        Some(pk.to_string())
    } else {
        None
    };

    // ─── 5. Capture the DID up-front so we can release the
    //        pending-challenge slot regardless of canonical-handler
    //        outcome.
    let signer_did = verified.issuer.clone();

    let backend = crate::auth::DidHostingControlAuthBackend::from_state(&state)?;
    let result = vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id: payload.session_id.clone(),
            challenge: verified.nonce.clone(),
            signer_did: signer_did.clone(),
            // SIOPv2 / REST — no DIDComm created_time to thread.
            created_time: None,
            session_pubkey_b58btc,
        },
    )
    .await;

    // Always release the pending-challenge slot on success.
    // On failure the slot remains until either the legitimate
    // caller retries (re-issue replaces) or the session TTL
    // sweeper reaps it — same behaviour as the pre-migration
    // flow.
    match result {
        Ok(resp) => {
            state.pending_challenges.release(&signer_did).await;
            info!(did = %signer_did, "authenticated via SIOPv2 id_token");
            Ok(Json(canonical_to_local_auth_response(resp)).into_response())
        }
        Err(e) => Err(e),
    }
}

/// Translate the canonical
/// `vti_common::auth::handlers::handle_*` response (shape from
/// vti-common's internal vta-sdk pin) into did-hosting's
/// workspace-vta-sdk-pinned wire type. Both shapes are
/// byte-identical on the wire (same JSON via serde) so the
/// translation is pure field-copy — but Rust treats the two
/// versions of vta-sdk as distinct types, so we copy fields
/// explicitly.
///
/// When vta-sdk consolidates onto a single published version
/// (next vti-common publish to crates.io) this helper goes away
/// in favour of a direct `From` impl.
fn canonical_to_local_auth_response(
    a: vta_sdk::protocols::auth::AuthenticateResponse,
) -> did_hosting_common::AuthenticateResponse {
    did_hosting_common::AuthenticateResponse {
        session: did_hosting_common::Session {
            id: a.session.id,
            subject: a.session.subject,
            issued_at: a.session.issued_at,
            expires_at: a.session.expires_at,
            amr: a.session.amr,
            acr: a.session.acr,
        },
        tokens: did_hosting_common::TokenBundle {
            access_token: a.tokens.access_token,
            refresh_token: a.tokens.refresh_token,
            token_type: a.tokens.token_type,
            expires_in: a.tokens.expires_in,
            refresh_expires_in: a.tokens.refresh_expires_in,
            scope: a.tokens.scope,
        },
    }
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
///
/// Thin dispatcher: parse the JWS-signed DIDComm refresh
/// envelope (proves the holder has the signing key, not just the
/// bearer refresh token), then call the canonical refresh
/// handler. The canonical handler atomically claims the
/// refresh-token reverse-index, preserves the pre-rotation AAL,
/// re-looks-up the ACL role, and mints a new session +
/// access/refresh pair.
pub async fn refresh(
    State(state): State<AppState>,
    body: String,
) -> Result<Json<did_hosting_common::RefreshResponse>, AppError> {
    use did_hosting_common::server::didcomm_unpack;

    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

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
        .ok_or_else(|| AppError::Authentication("missing refresh_token in message body".into()))?
        .to_string();

    let backend = crate::auth::DidHostingControlAuthBackend::from_state(&state)?;
    let resp = vti_common::auth::handlers::handle_refresh(
        &backend,
        vti_common::auth::RefreshInput {
            refresh_token,
            signer_did: Some(sender_base),
        },
    )
    .await?;
    Ok(Json(canonical_to_local_auth_response(resp)))
}

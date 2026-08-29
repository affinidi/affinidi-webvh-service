//! DIDComm challenge-response authentication routes.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tracing::{info, warn};
use trust_tasks_rs::{ProofVerifier, TrustTask};

use did_hosting_common::server::auth::constant_time_eq;
use did_hosting_common::{ChallengeRequest, ChallengeResponse};

use crate::auth::AuthClaims;
use crate::auth::session::{self, now_epoch};
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
/// a malformed envelope surfaces a `trust-task-error` document with
/// `code: malformed_request` rather than axum's text/plain default.
pub async fn authenticate(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    use did_hosting_common::AuthenticatePayload;
    use did_hosting_common::server::didcomm_unpack;

    let (did_resolver, _secrets_resolver, _jwt_keys) = state.require_didcomm_auth()?;

    // ─── 0. Content-negotiate the request-body shape.
    //
    // Two authenticate dialects share this endpoint (additive — the
    // SIOPv2 path below is the default and unchanged):
    //
    // - SIOPv2 id_token Trust-Task envelope `{type, payload}` — the
    //   wallet/control contract handled inline below.
    // - DIDComm-v2 JWS envelope — a general-JSON JWS carrying a
    //   `signatures` array (no Trust-Task `type` field). This is what
    //   `did-hosting-server` accepts and what a provisioning VTA sends
    //   (`build_authenticate_message`: type
    //   `https://trusttasks.org/spec/auth/authenticate/0.1`, body
    //   `{session_id, challenge}`, `pack_signed` by the VTA DID). Because
    //   the unified daemon mounts *this* control route (not the server's
    //   `/auth/`), a VTA publish would otherwise fail with `400 missing
    //   field type`. We detect the JWS by its top-level `signatures`
    //   array and dispatch to the DIDComm path.
    //
    // A JWS envelope has no Trust-Task `type` field, and the SIOPv2
    // envelope has no `signatures` array, so the shapes are unambiguous
    // and neither dialect can be misrouted.
    if is_didcomm_jws_envelope(&body) {
        return authenticate_didcomm_jws(&state, &body, did_resolver).await;
    }

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
    if envelope.type_uri != expected_type {
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

/// Cheap structural check: does `body` look like a DIDComm-v2 general-JSON
/// JWS envelope (a top-level `signatures` array)?
///
/// The SIOPv2 Trust-Task envelope this route otherwise expects is
/// `{type, payload}` with no `signatures` array, so a `true` here
/// unambiguously means "route to the DIDComm-JWS path". A body that is
/// neither shape (e.g. junk) returns `false` and falls through to the
/// SIOPv2 parser, which emits the existing `trust-task-error` document —
/// so the malformed-request behaviour for non-JWS bodies is unchanged.
fn is_didcomm_jws_envelope(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value
        .get("signatures")
        .and_then(|s| s.as_array())
        .is_some_and(|arr| !arr.is_empty())
}

/// Authenticate via a DIDComm-v2 JWS envelope (the `did-hosting-server`
/// contract) — the second dialect this endpoint accepts, in addition to
/// the default SIOPv2 id_token path.
///
/// This mirrors `did-hosting-server`'s `routes/auth.rs::authenticate`:
/// `unpack_signed` verifies the JWS signature and binds the *verified*
/// signer base DID (an attacker cannot forge `from`), the message `type`
/// must be the authenticate task URI, and the `{session_id, challenge}`
/// body is threaded into the same canonical `handle_authenticate` the
/// SIOPv2 path uses. The canonical handler re-looks-up the signer's ACL
/// role, so a signer that is not in the ACL is still rejected — this
/// path adds an accepted *envelope shape*, not a trust relaxation. The
/// provisioning VTA is authorised only because setup seeded its ACL
/// entry (see `acl::seed_provisioning_vta_acl`).
async fn authenticate_didcomm_jws(
    state: &AppState,
    body: &[u8],
    did_resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> Result<Response, AppError> {
    use did_hosting_common::server::didcomm_unpack;

    let body_str = std::str::from_utf8(body)
        .map_err(|e| AppError::Authentication(format!("JWS body is not valid UTF-8: {e}")))?;

    let (msg, signer_did) = didcomm_unpack::unpack_signed(body_str, did_resolver).await?;

    // The canonical authenticate Type URI — the same one did-hosting-server
    // accepts, so the VTA's envelope routes here verbatim. The legacy
    // `affinidi.com/webvh/1.0/authenticate` arm that sat beside it is gone:
    // it was the last thing keeping a retired vendor URI alive on this
    // route, and a second accepted spelling is a second thing to keep true.
    if msg.typ.as_str() != "https://trusttasks.org/spec/auth/authenticate/0.1" {
        return Err(AppError::Authentication(format!(
            "unexpected message type: {}",
            msg.typ
        )));
    }

    let challenge = msg
        .body
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing challenge in message body".into()))?
        .to_string();
    let session_id = msg
        .body
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Authentication("missing session_id in message body".into()))?
        .to_string();

    let backend = crate::auth::DidHostingControlAuthBackend::from_state(state)?;
    let result = vti_common::auth::handlers::handle_authenticate(
        &backend,
        vti_common::auth::AuthenticateInput {
            session_id,
            challenge,
            signer_did: signer_did.clone(),
            created_time: msg.created_time,
            session_pubkey_b58btc: None,
        },
    )
    .await;

    match result {
        Ok(resp) => {
            // Release the pending-challenge slot on success, mirroring
            // the SIOPv2 path's bookkeeping.
            state.pending_challenges.release(&signer_did).await;
            info!(did = %signer_did, "authenticated via DIDComm-JWS envelope");
            Ok(Json(canonical_to_local_auth_response(resp)).into_response())
        }
        Err(e) => Err(e),
    }
}

/// Translate the canonical `vta_sdk::protocols::auth::AuthenticateResponse`
/// returned by `vti_common::auth::handlers::handle_*` into did-hosting's own
/// [`did_hosting_common::AuthenticateResponse`].
///
/// These are two genuinely different types, not two copies of one type: the
/// SDK owns the canonical SIOPv2 / RFC-6749 shape, while `did-hosting-common`
/// declares its own in `types.rs` so the client crates have a wire type that
/// does not drag the SDK in. Both serialise identically, so the translation is
/// a pure field-copy — but it is a permanent boundary, not a workaround for a
/// duplicated dependency. (An earlier version of this comment claimed the
/// latter and predicted the helper would disappear once vta-sdk consolidated
/// onto one published version; that consolidation happened at vta-sdk 0.20 /
/// vti-common 0.11.30 and the helper is still required.)
///
/// A `From` impl would be the natural home for this, but neither type is local
/// to this crate, so the orphan rule rules it out here.
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

/// Build a `trust-task-error` HTTP response for a malformed
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
        // Unrouted: the envelope never parsed, so there is no request to read
        // an enclosing exchange from (SPEC §4.9.2) — nor a ceremony to stay
        // inside (§7.1).
        parent_thread_id: None,
        ceremony: None,
        type_uri: did_hosting_common::server::trust_tasks::framework_error_type_uri(),
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

/// Build the signed `auth/step-up/approve-request/0.2` document.
///
/// A full Trust Task document per the spec: `issuer` = the control DID
/// (the relying party), `recipient` = the subject DID (self-approve
/// path — the wallet holding the subject key is the approver), and the
/// spec's REQUIRED Data Integrity proof (`eddsa-jcs-2022`,
/// `proofPurpose: assertionMethod`) signed with the control DID's
/// assertion key, so the wallet can verify the `reason` it renders is
/// this RP's before surfacing it. The payload carries exactly the
/// schema's REQUIRED members (`subject`, `sessionId`, `challenge`,
/// `reason`); the schema is closed (`additionalProperties: false`) and
/// has no `expiresAt` — expiry is the RP's server-side nonce policy.
async fn build_signed_step_up_approve_request(
    control_did: &str,
    signing_secret: &affinidi_tdk::secrets_resolver::secrets::Secret,
    subject: &str,
    session_id: &str,
    challenge: &str,
    reason: &str,
) -> Result<Value, AppError> {
    use did_hosting_common::did_hosting_tasks::TASK_AUTH_STEP_UP_VTA_START_0_2;

    let unsigned = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": TASK_AUTH_STEP_UP_VTA_START_0_2.as_str(),
        "issuer": control_did,
        "recipient": subject,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {
            "subject": subject,
            "sessionId": session_id,
            "challenge": challenge,
            "reason": reason,
        },
    });
    crate::signing::sign_trust_task_document(unsigned, signing_secret).await
}

/// POST /api/auth/step-up/vta/start — issue a step-up nonce bound to the
/// caller's session, minted as a signed
/// `auth/step-up/approve-request/0.2` Trust Task document. The wallet
/// verifies the document's proof, shows the `reason`, and signs an
/// approve-response committing to the `challenge`.
///
/// Response shape (coordinated-rollout superset):
/// - `document` — the signed `auth/step-up/approve-request/0.2` Trust
///   Task document. New consumers MUST use this.
/// - `subject`, `sessionId`, `challenge`, `reason` — **deprecated**
///   legacy top-level copies of the document's payload fields, kept
///   verbatim for existing consumers that parse the bare shape. They
///   will be removed once the wallet side reads `document`.
pub async fn step_up_vta_start(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    // The control DID signs the request; both are required to finish the
    // flow anyway (`step_up_vta_finish` needs `server_did` + verifier).
    let control_did = state.config.server_did.as_deref().ok_or_else(|| {
        AppError::Config("server_did not configured; cannot sign the step-up request".into())
    })?;
    let signing_secret = crate::signing::control_assertion_secret(&state, control_did)?;

    let challenge = rand::random::<[u8; 32]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    // Spec `auth/step-up/approve-request/0.2` payload fields. The subject is
    // the session's authenticated DID; the wallet signs an approve-response
    // that echoes `subject`/`sessionId`/`challenge` and proves control of the
    // subject key (holder-self-signs — the VTA is no longer in the loop).
    let reason = "Elevate this session to aal2";
    let document = build_signed_step_up_approve_request(
        control_did,
        &signing_secret,
        &auth.did,
        &auth.session_id,
        &challenge,
        reason,
    )
    .await?;

    // Persist the nonce only after the document signed, so a signing
    // failure leaves no orphaned challenge bound to the session.
    state
        .sessions_ks
        .insert_raw(
            format!("stepup-nonce:{}", auth.session_id),
            challenge.as_bytes().to_vec(),
        )
        .await?;

    Ok(Json(serde_json::json!({
        // Deprecated legacy fields — kept for wire compatibility during
        // the coordinated rollout; consumers should move to `document`.
        "subject": auth.did,
        "sessionId": auth.session_id,
        "challenge": challenge,
        "reason": reason,
        "document": document,
    })))
}

/// POST /api/auth/step-up/vta/finish — verify the wallet's signed
/// `auth/step-up/approve-response/0.2` document and elevate the caller's
/// session to `aal2`.
///
/// Converged to the holder-self-signs model (trusttasks-tf
/// `auth/step-up/approve-response/0.2`): the wallet — not the VTA — signs the
/// approval with a W3C Data Integrity proof (`eddsa-jcs-2022`) over the
/// session-subject key, and the RP verifies that proof. The proof binds the
/// user's fresh possession of the subject DID to the step-up `challenge`; the
/// VTA is no longer a trusted third party for step-up.
// The `_0_1` task const is deprecated in favour of `_0_2`, but we still
// accept the 0.1 type URI on inbound for backwards compatibility.
#[allow(deprecated)]
pub async fn step_up_vta_finish(
    State(state): State<AppState>,
    auth: AuthClaims,
    Json(doc): Json<TrustTask<Value>>,
) -> Result<Json<did_hosting_common::server::auth::session::TokenResponse>, AppError> {
    use did_hosting_common::did_hosting_tasks::{
        TASK_AUTH_STEP_UP_VTA_FINISH_0_1, TASK_AUTH_STEP_UP_VTA_FINISH_0_2,
    };

    let rp_id = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| AppError::Config("server_did not configured".into()))?;
    let jwt_keys = state
        .jwt_keys
        .as_deref()
        .ok_or_else(|| AppError::Config("auth not configured".into()))?;

    // ─── 1. Task type: approve-response/0.2 (0.1 accepted as legacy alias).
    let type_uri = doc.type_uri.to_string();
    if type_uri != TASK_AUTH_STEP_UP_VTA_FINISH_0_2.as_str()
        && type_uri != TASK_AUTH_STEP_UP_VTA_FINISH_0_1.as_str()
    {
        return Err(AppError::Authentication(format!(
            "unexpected step-up document type: {type_uri}"
        )));
    }

    // ─── 2. Typed payload fields.
    let payload = &doc.payload;
    let field = |k: &str| payload.get(k).and_then(Value::as_str);
    let subject = field("subject")
        .ok_or_else(|| AppError::Authentication("approve-response missing subject".into()))?;
    let session_id = field("sessionId")
        .ok_or_else(|| AppError::Authentication("approve-response missing sessionId".into()))?;
    let challenge = field("challenge")
        .ok_or_else(|| AppError::Authentication("approve-response missing challenge".into()))?;
    let decision = field("decision")
        .ok_or_else(|| AppError::Authentication("approve-response missing decision".into()))?;

    // ─── 3. A signed refusal is valid but elevates nothing.
    if decision != "approved" {
        return Err(AppError::Forbidden(format!(
            "step-up not approved (decision: {decision})"
        )));
    }

    // ─── 4. The proof is mandatory in the converged flow.
    let proof = doc
        .proof
        .as_ref()
        .ok_or_else(|| AppError::Authentication("approve-response carries no proof".into()))?;

    // ─── 5. Proof-verificationMethod ↔ session binding (SECURITY), mirroring
    //        `dispatch_trust_task`. Without this, the framework verifier would
    //        accept a proof from ANY resolvable DID and let a holder elevate a
    //        session belonging to a different subject.
    match auth.session_pubkey_b58btc.as_deref() {
        Some(pk) => {
            let expected_vm = format!("did:key:{pk}#{pk}");
            if proof.verification_method != expected_vm {
                warn!(actual_vm = %proof.verification_method, %expected_vm,
                    "step-up rejected: proof verificationMethod not bound to this session");
                return Err(AppError::Authentication(
                    "proof verificationMethod is not bound to this session".into(),
                ));
            }
        }
        None => {
            let proof_did = proof
                .verification_method
                .split_once('#')
                .map(|(d, _)| d)
                .unwrap_or("");
            if proof_did != auth.did {
                warn!(%proof_did, authed = %auth.did,
                    "step-up rejected: proof verificationMethod DID does not match the authenticated caller");
                return Err(AppError::Authentication(
                    "proof verificationMethod DID does not match the authenticated caller".into(),
                ));
            }
        }
    }

    // ─── 6. Verify the eddsa-jcs-2022 signature against the resolved key.
    let verifier = state
        .trust_tasks_verifier
        .as_deref()
        .ok_or_else(|| AppError::Config("trust-tasks proof verifier not configured".into()))?;
    verifier.verify(&doc).await.map_err(|e| {
        warn!(error = %e, "step-up rejected: approve-response proof failed verification");
        AppError::Authentication("approve-response proof failed verification".into())
    })?;

    // ─── 7. Framework bindings.
    if subject != auth.did {
        warn!(authed = %auth.did, %subject, "step-up rejected: approval subject mismatch");
        return Err(AppError::Authentication(
            "approval subject does not match the authenticated DID".into(),
        ));
    }
    if session_id != auth.session_id {
        return Err(AppError::Authentication(
            "approval sessionId does not match the authenticated session".into(),
        ));
    }
    if let Some(issuer) = doc.issuer.as_deref()
        && issuer != subject
    {
        return Err(AppError::Authentication(
            "approval issuer does not match subject".into(),
        ));
    }
    // Audience binding (SPEC §4.8.2): the signed `recipient` binds the proof to
    // this RP, so an approval captured elsewhere can't be replayed here.
    match doc.recipient.as_deref() {
        Some(r) if r == rp_id => {}
        _ => {
            return Err(AppError::Authentication(
                "approval recipient does not bind this service".into(),
            ));
        }
    }

    // ─── 8. Consume the session-bound challenge (single use).
    let stored = state
        .sessions_ks
        .take_raw(format!("stepup-nonce:{}", auth.session_id))
        .await?
        .ok_or_else(|| {
            AppError::Authentication("no step-up challenge issued for this session".into())
        })?;
    let stored = String::from_utf8(stored)
        .map_err(|e| AppError::Internal(format!("stored challenge not utf8: {e}")))?;
    if !constant_time_eq(stored.as_bytes(), challenge.as_bytes()) {
        warn!(session_id = %auth.session_id, "step-up rejected: challenge mismatch");
        return Err(AppError::Authentication(
            "step-up challenge mismatch".into(),
        ));
    }

    // ─── 9. Freshness: the proof `created` must be neither in the future nor
    //        older than the step-up window (defence in depth on top of the
    //        single-use challenge).
    const CLOCK_SKEW_SECS: i64 = 60;
    const MAX_PROOF_AGE_SECS: i64 = 300;
    let now = now_epoch() as i64;
    let created = proof.created.timestamp();
    if created > now + CLOCK_SKEW_SECS {
        return Err(AppError::Authentication(
            "approval proof `created` is in the future".into(),
        ));
    }
    if created < now - MAX_PROOF_AGE_SECS {
        return Err(AppError::Authentication("approval proof is too old".into()));
    }

    // ─── 10. Elevate. The holder self-signed, so `amr` reflects `did` only
    //         (the VTA is no longer part of the step-up assurance).
    let role = crate::acl::check_acl(&state.acl_ks, &auth.did).await?;
    let token_resp = session::elevate_session(
        &state.sessions_ks,
        jwt_keys,
        &auth.session_id,
        &role,
        vec!["did".to_string()],
        "aal2",
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
    )
    .await?;

    info!(did = %auth.did, "step-up complete via wallet-signed approval: session elevated to aal2");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use affinidi_data_integrity::DidKeyResolver;
    use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
    use serde_json::json;

    /// The step-up approve-request document's proof verifies with the
    /// same machinery the finish leg uses (`TransportBoundVerifier`),
    /// and the issuer binding holds: `issuer` == control DID == the DID
    /// of `proof.verificationMethod`.
    #[tokio::test]
    async fn signed_step_up_request_verifies_and_binds_issuer() {
        use did_hosting_common::did_hosting_tasks::TASK_AUTH_STEP_UP_VTA_START_0_2;

        let (control_did, signer) = crate::signing::test_util::did_key_signer(&[13u8; 32]);

        let subject = "did:web:alice.example";
        let session_id = "sess-1234";
        let challenge = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let document = build_signed_step_up_approve_request(
            &control_did,
            &signer,
            subject,
            session_id,
            challenge,
            "Elevate this session to aal2",
        )
        .await
        .expect("build + sign");

        // Envelope shape per the spec: RP as issuer, approver (the
        // subject wallet, self-approve path) as recipient.
        assert_eq!(document["type"], TASK_AUTH_STEP_UP_VTA_START_0_2.as_str());
        assert_eq!(document["issuer"], control_did);
        assert_eq!(document["recipient"], subject);
        assert_eq!(document["payload"]["subject"], subject);
        assert_eq!(document["payload"]["sessionId"], session_id);
        assert_eq!(document["payload"]["challenge"], challenge);

        // Proof binding: assertion key of the issuer DID, eddsa-jcs-2022.
        let vm = document["proof"]["verificationMethod"]
            .as_str()
            .expect("proof carries a verificationMethod");
        assert_eq!(vm.split('#').next().unwrap(), control_did);
        assert_eq!(document["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(document["proof"]["proofPurpose"], "assertionMethod");

        // Verifies under the shared verifier (issuer ↔ vm binding included).
        let doc: TrustTask<Value> =
            serde_json::from_value(document.clone()).expect("signed doc parses as a TrustTask");
        TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver))
            .verify(&doc)
            .await
            .expect("approve-request proof verifies");

        // The signature covers the rendered reason: tampering breaks it.
        let mut tampered = doc;
        tampered.payload["reason"] = json!("Hand over the keys");
        TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver))
            .verify(&tampered)
            .await
            .expect_err("tampered reason must fail verification");
    }
}

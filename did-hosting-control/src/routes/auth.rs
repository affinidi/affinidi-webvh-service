//! The one browser sign-in route that has no Trust Task form: the
//! challenge nonce (`auth/challenge/0.1` has a Trust Task form too, served
//! identically from `trust_tasks_auth`, but the console always reaches it
//! over plain REST before it holds any credential to sign a Trust Task
//! envelope with). See `routes/mod.rs` for why it alone stays plain HTTP —
//! authenticate and refresh both moved onto `auth/authenticate/0.3` and
//! `auth/refresh/0.2` over `/api/trust-tasks` (`trust_tasks_auth`).

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use tracing::warn;

use did_hosting_common::{ChallengeRequest, ChallengeResponse};

use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::rate_limit::resolve_client_ip;
use crate::server::AppState;

/// Default maximum concurrent pending challenges per DID. Combined with the
/// global cap on the `pending_challenges` tracker on `AppState`, this
/// bounds the unauthenticated challenge-endpoint surface against both
/// per-DID floods and DID-sweep attacks. Shared with the
/// `auth/challenge/0.1` Trust Task handler, which applies the same caps.
///
/// This is the compiled-in default; the effective value is
/// `AuthConfig::max_pending_challenges_per_did`, which defaults to this and is
/// read per call by [`issue_challenge`]. The default and the config default
/// are pinned equal by `pending_challenges::tests::config_defaults_match_constants`.
pub(crate) const MAX_PENDING_CHALLENGES_PER_DID: usize = 10;

// Keep the constant referenced in non-test builds (it is otherwise used only
// from the config-default pin test and the TSP suite) and pin its value, so a
// change is deliberate and travels with the config default above.
const _: () = assert!(MAX_PENDING_CHALLENGES_PER_DID == 10);

/// POST /api/auth/challenge — request a challenge nonce.
///
/// Two layers of rate-limit defence:
/// 1. Per-IP fixed-window counter (`IpRateLimiter`) — caps requests
///    from any single IP regardless of which DID they're issuing
///    challenges for. Trusted-proxy XFF resolution per
///    `server.trusted_proxies` config.
/// 2. Per-DID + global cap on live challenges (`PendingChallengeTracker`).
///    A slot frees when its challenge authenticates or its
///    `challenge_ttl` runs out, and a refusal's `Retry-After` is the
///    moment the oldest counted challenge expires.
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

    let canonical = issue_challenge(&state, req.did).await?;
    // did-hosting's ChallengeResponse drops the canonical
    // `teeAttestation` field — did-hosting doesn't run in a TEE.
    Ok(Json(ChallengeResponse {
        challenge: canonical.challenge,
        session_id: canonical.session_id,
        expires_at: canonical.expires_at,
    }))
}

/// Reserve a pending-challenge slot for `did`, run the canonical challenge
/// handler, and bind the slot to the session it minted — the one issuance path
/// for every binding (REST here, DIDComm/TSP/HTTPS-trust-task in
/// `trust_tasks_auth`).
///
/// The canonical handler's own per-DID limit is disabled in this backend; the
/// tracker is the single source of truth. The slot is taken whether or not the
/// DID holds an ACL entry: the canonical handler answers an unenrolled subject
/// without persisting anything, and counting only enrolled subjects would turn
/// the cap into an enumeration oracle (VTI-SES-007).
///
/// The per-DID cap is `AuthConfig::max_pending_challenges_per_did`
/// (default [`MAX_PENDING_CHALLENGES_PER_DID`]); the global cap is baked into
/// the tracker at construction from `max_global_pending_challenges`.
pub(crate) async fn issue_challenge(
    state: &AppState,
    did: String,
) -> Result<vta_sdk::protocols::auth::ChallengeResponse, AppError> {
    let per_did_cap = state.config.auth.max_pending_challenges_per_did;
    let reservation = state
        .pending_challenges
        .try_issue(&did, per_did_cap)
        .inspect_err(|e| {
            warn!(did = %did, error = %e, "challenge rate limited");
        })?;

    let result = match crate::auth::DidHostingControlAuthBackend::from_state(state) {
        Ok(backend) => {
            vti_common::auth::handlers::handle_challenge(
                &backend,
                vti_common::auth::ChallengeInput {
                    did,
                    session_pubkey_b58btc: None,
                },
            )
            .await
        }
        Err(e) => Err(e),
    };

    match result {
        Ok(resp) => {
            state.pending_challenges.bind(reservation, &resp.session_id);
            Ok(resp)
        }
        Err(e) => {
            state.pending_challenges.cancel(reservation);
            Err(e)
        }
    }
}

/// Refuse a renewal for a session that has gone quiet longer than
/// `auth.admin_idle_timeout`. Shared by `trust_tasks_auth`'s
/// `auth/refresh/0.2` arm — the only surviving refresh path since the REST
/// `/api/auth/refresh` route was retired.
///
/// Checked separately from — and before — the shared `handle_refresh`, so
/// the policy is ours and needs no vti-common release to change, and so an
/// idled-out session is refused before anything is spent: the handler's
/// first act is to claim-and-delete the refresh-token index, and refusing
/// afterwards would burn the caller's token on the way to telling them no.
///
/// A session whose `last_seen` predates the field (`0`) falls back to
/// `created_at`, so rows written before idle tracking existed are judged
/// from when they began rather than being refused outright.
pub(crate) fn refuse_if_idle_session(
    session: &did_hosting_common::server::auth::session::Session,
    idle_ttl: u64,
) -> Result<(), AppError> {
    use did_hosting_common::server::auth::session::now_epoch;

    let last_activity = if session.last_seen == 0 {
        session.created_at
    } else {
        session.last_seen
    };
    let idle_for = now_epoch().saturating_sub(last_activity);
    if idle_for > idle_ttl {
        warn!(
            session_id = %session.session_id,
            did = %session.did,
            idle_for,
            idle_ttl,
            "refresh rejected: session idle past the timeout",
        );
        return Err(AppError::Authentication(
            "session signed out after the configured period of inactivity".into(),
        ));
    }
    Ok(())
}

/// Bind a refresh to the device that logged in.
///
/// A refresh token proves nothing about the party presenting it beyond
/// possession, so without a check here a stolen token alone would authorise
/// a rotation from anywhere.
///
/// The binding reuses what the console already has: the login flow
/// generates an ephemeral Ed25519 keypair, sends its public multikey as
/// `session_pubkey_b58btc`, and the server stores it on the session row.
/// Requiring a Data Integrity proof from that key (SPEC `auth/refresh/0.2`
/// item 3: "the located session carries a bound `sessionKey`... MUST
/// require that `proof` be present and its `verificationMethod` resolve to
/// exactly that `sessionKey`") means a stolen refresh token is not enough on
/// its own — the attacker also needs a key that never left the browser that
/// logged in.
///
/// **Sessions with no bound key are unchanged.** Wallet and
/// machine-to-machine sessions sign with their own DID's verification
/// methods and never supplied a session pubkey; demanding a proof from them
/// would break a path this change does not otherwise touch. That arm is not
/// a downgrade an attacker can choose: whether a session has a bound key is
/// a property of the stored row, not of the request.
///
/// Mirrors the case (a) / case (b) split in
/// `routes::trust_tasks::dispatch_trust_task`, where the same binding is
/// enforced for every other document the console signs.
pub(crate) async fn verify_session_bound_proof(
    doc: &trust_tasks_rs::TrustTask<serde_json::Value>,
    session: &did_hosting_common::server::auth::session::Session,
) -> Result<(), AppError> {
    use affinidi_data_integrity::DidKeyResolver;
    use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
    use trust_tasks_rs::ProofVerifier;

    let Some(pk) = session.session_pubkey_b58btc.as_deref() else {
        return Ok(());
    };

    let Some(proof) = doc.proof.as_ref() else {
        return Err(AppError::Authentication(
            "refresh document must carry a proof from this session's key".into(),
        ));
    };

    // Check the binding before verifying the signature, so a proof signed by
    // some other resolvable key is refused for the reason that actually
    // applies rather than verifying cleanly and being wrong.
    let expected_vm = format!("did:key:{pk}#{pk}");
    if proof.verification_method != expected_vm {
        warn!(
            session_id = %session.session_id,
            actual_vm = %proof.verification_method,
            "refresh proof verificationMethod is not this session's key",
        );
        return Err(AppError::Authentication(
            "refresh proof is not bound to this session".into(),
        ));
    }

    // `did:key` resolves locally, so this needs no DID cache and no DIDComm
    // configuration — which matters, because the point of this dialect is to
    // serve a client that has neither.
    TransportBoundVerifier::with_resolver(std::sync::Arc::new(DidKeyResolver))
        .verify(doc)
        .await
        .map_err(|e| {
            warn!(
                session_id = %session.session_id,
                error = %e,
                "refresh proof failed verification",
            );
            AppError::Authentication("refresh proof failed verification".into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    use did_hosting_common::server::auth::session::{Session, SessionState};

    /// A stored session, optionally carrying a bound session key.
    fn session_with(pubkey: Option<&str>, last_seen: u64) -> Session {
        Session {
            session_id: "sess-refresh".into(),
            did: "did:example:alice".into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: last_seen,
            last_seen,
            refresh_token: Some("tok".into()),
            refresh_expires_at: Some(u64::MAX),
            tee_attested: false,
            amr: vec!["passkey".into()],
            acr: "aal1".into(),
            acr_expires_at: None,
            token_id: Some("jti".into()),
            session_pubkey_b58btc: pubkey.map(str::to_string),
        }
    }

    fn refresh_doc(
        proof: Option<serde_json::Value>,
    ) -> trust_tasks_rs::TrustTask<serde_json::Value> {
        let mut v = json!({
            "type": "https://trusttasks.org/spec/auth/refresh/0.2",
            "id": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "payload": { "refreshToken": "tok" },
        });
        if let Some(p) = proof {
            v.as_object_mut().unwrap().insert("proof".into(), p);
        }
        serde_json::from_value(v).expect("refresh document parses")
    }

    /// A session that registered a key must prove possession of it. Without
    /// this, a stolen refresh token alone would rotate the session.
    #[tokio::test]
    async fn a_bound_session_refresh_without_a_proof_is_refused() {
        let session = session_with(Some("z6MkExampleKeyMaterialNotReal"), 0);
        let err = verify_session_bound_proof(&refresh_doc(None), &session)
            .await
            .expect_err("a bound session must demand a proof");
        assert!(format!("{err}").contains("proof"), "{err}");
    }

    /// …and it must be *that* key, not merely a resolvable one.
    #[tokio::test]
    async fn a_proof_from_another_key_is_refused() {
        let (other_did, signer) = crate::signing::test_util::did_key_signer(&[7u8; 32]);
        let _ = signer;
        let session = session_with(Some("z6MkTheSessionsOwnKeyNotThatOne"), 0);
        let proof = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{other_did}#irrelevant"),
            "created": "2026-01-01T00:00:00Z",
            "proofPurpose": "assertionMethod",
            "proofValue": "z2fake",
        });
        let err = verify_session_bound_proof(&refresh_doc(Some(proof)), &session)
            .await
            .expect_err("a proof from a foreign key must be refused");
        assert!(
            format!("{err}").contains("not bound to this session"),
            "the refusal should name the binding, got: {err}"
        );
    }

    /// Wallet and machine-to-machine sessions never supplied a session key.
    /// They are unchanged — and this is not a downgrade an attacker can
    /// pick, because it is a property of the stored row, not of the request.
    #[tokio::test]
    async fn a_session_with_no_bound_key_needs_no_proof() {
        let session = session_with(None, 0);
        verify_session_bound_proof(&refresh_doc(None), &session)
            .await
            .expect("an unbound session keeps its previous behaviour");
    }

    #[test]
    fn an_idle_session_is_refused_and_a_busy_one_is_not() {
        let now = did_hosting_common::server::auth::session::now_epoch();
        let fresh = session_with(None, now - 60);
        refuse_if_idle_session(&fresh, 900).expect("60s idle is inside a 900s window");

        let stale = session_with(None, now - 1_200);
        let err =
            refuse_if_idle_session(&stale, 900).expect_err("1200s idle is outside a 900s window");
        assert!(format!("{err}").contains("inactivity"), "{err}");
    }
}

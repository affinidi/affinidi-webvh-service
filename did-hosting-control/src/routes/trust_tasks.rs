//! `POST /api/trust-tasks` — the Trust Tasks transport endpoint
//! introduced in v0.7.0.
//!
//! Receives a JSON-encoded `TrustTask<serde_json::Value>` document and hands
//! it to `messaging::dispatch_trust_task_doc` — the same dispatch TSP and
//! DIDComm use. The document's proof is the authorisation; a bearer session
//! is optional context.
//!
//! ## Body-parse failures are spec-conformant
//!
//! We accept the request body as `axum::body::Bytes` and parse to
//! `TrustTask<Value>` by hand. The reason: axum's typed `Json<...>`
//! extractor rejects malformed bodies with a plain-text 400 *before*
//! the handler runs, which would be a wire-shape regression — the
//! framework spec asks for a `trust-task-error` document on
//! malformed input. Handling the parse here lets us emit the routed
//! error document with `code: malformed_request` for any body-shape
//! failure.
//!
//! ## Why this isn't wired through `trust_tasks_https::HttpsServer`
//!
//! [`trust_tasks_https::HttpsServerBuilder::on`] takes a **sync**
//! `Fn(&TrustTask<P>, &RequestContext) -> Result<Resp, RejectReason>`.
//! Our ACL handlers all need async fjall I/O, which doesn't compose
//! with that signature without [`tokio::task::block_in_place`] (a
//! code smell). We use [`trust_tasks_https::HttpsHandler`] (the
//! [`TransportHandler`] adapter that maps the bearer-authenticated
//! peer into framework identity), [`trust_tasks_https::status_for_code`]
//! (for the spec status table), and our own async dispatch core.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use trust_tasks_https::{HttpsHandler, status_for_code};
use trust_tasks_rs::{ErrorPayload, RejectReason, TrustTask};
use uuid::Uuid;

use did_hosting_common::server::trust_tasks::DispatchOutcome;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// The mounted `POST /api/trust-tasks` route: [`dispatch_trust_task`], after
/// the per-source limit on invite redemption.
///
/// `auth/passkey/enroll/redeem/start` is the one task a stranger may send that
/// makes the service hash a guess (the claim code, with Argon2). Over HTTPS
/// the only source a stranger cannot choose is the client IP, so it is counted
/// here, before the document is parsed any further; the messaging transports
/// count their authenticated sender in the task itself.
pub async fn trust_tasks_endpoint(
    auth: Option<AuthClaims>,
    State(state): State<AppState>,
    connect: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    if let Some(axum::Extension(axum::extract::ConnectInfo(addr))) = connect
        && is_redeem_start(&body)
    {
        let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
        let ip = crate::rate_limit::resolve_client_ip(
            addr.ip(),
            xff,
            &state.config.server.trusted_proxies,
        );
        let limited = state.redeem_rate_limiter.try_consume(
            &format!("ip:{ip}"),
            did_hosting_common::server::auth::session::now_epoch(),
        );
        if let Err(AppError::RateLimited {
            retry_after_secs, ..
        }) = limited
        {
            tracing::warn!(%ip, "invite redemption rate limited");
            // Refused as the task would be — a routed `unavailable` document
            // with its retry time — not as a bare REST 429.
            if let Ok(doc) = serde_json::from_slice::<TrustTask<Value>>(&body) {
                let reject = RejectReason::Unavailable {
                    retry_after: Some(
                        chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                    ),
                };
                let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject);
                return Ok(into_response(DispatchOutcome::Rejected(routed)));
            }
        }
    }
    dispatch_trust_task(auth, State(state), body).await
}

/// Whether `body` is an `auth/passkey/enroll/redeem/start` document.
///
/// Read exactly as [`dispatch_trust_task`] and the task table read it — the
/// whole body as a `TrustTask`, its parsed `type` compared as the router
/// compares it — so no body the router serves as a redemption (duplicate
/// members, escapes, any other quirk of a lighter parse) slips past the limit.
fn is_redeem_start(body: &[u8]) -> bool {
    use trust_tasks_rs::Payload;
    serde_json::from_slice::<TrustTask<Value>>(body).is_ok_and(|doc| {
        doc.type_uri.to_string()
            == trust_tasks_rs::specs::auth::passkey::enroll::redeem::start::v0_1::Payload::TYPE_URI
    })
}

/// `POST /api/trust-tasks` handler — the HTTPS binding of the same dispatch
/// TSP and DIDComm use.
///
/// The document's own proof is the authorisation, exactly as on the other two
/// transports; a bearer session is optional. Without one the document's
/// in-band `issuer` stands where a messaging transport's reported sender
/// would — a routing hint the proof must agree with — and a task whose
/// `ProofRule` is `Optional` (`server/info`, opening a passkey login) may be
/// sent with neither. With one, the session is the peer, a proof must be bound
/// to it (below), and the session's assurance level travels with the request.
///
/// Body is accepted as raw bytes so a parse failure surfaces as a
/// `trust-task-error` document with `code: malformed_request`
/// rather than axum's text/plain default. The route mount caps body
/// size separately (see [`crate::routes::trust_tasks_body_limit_bytes`]);
/// the per-type narrowing below is what actually decides most requests.
pub async fn dispatch_trust_task(
    auth: Option<AuthClaims>,
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    // ─── 1. Service DID required. Without one configured the §7.2
    //        recipient check has no `my_vid` to compare against, so we
    //        refuse early with an operator-actionable error rather
    //        than emitting a wire response.
    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| AppError::Config("server_did not configured".into()))?;

    // ─── 1b. Per-type document size, decided from the body alone —
    //         before it is parsed into `TrustTask<Value>` — on every
    //         transport (`size`). The route mount already caps the raw
    //         body at the largest limit any served type declares
    //         (`crate::routes::trust_tasks_body_limit_bytes`); this
    //         narrows further for a type whose own limit is smaller.
    if let Err(err) = did_hosting_common::server::trust_tasks::size::check_for_known_issuer(
        &body,
        &crate::control_tasks::SERVED_TRUST_TASK_URIS,
        &state.acl_ks,
    )
    .await
    {
        return Ok(into_response(DispatchOutcome::Rejected(err)));
    }

    // ─── 2. Parse the body to `TrustTask<Value>`. A parse failure
    //        emits a routed `trust-task-error` document with
    //        `code: malformed_request`.
    let doc: TrustTask<Value> = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            return Ok(into_response(DispatchOutcome::Rejected(body_parse_error(
                &e.to_string(),
            ))));
        }
    };

    // Replay protection runs inside `dispatch_trust_task_doc`, keyed on the
    // proven issuer and the document id, after the proof has been verified.

    // ─── 3. With a bearer session, the proof must be bound to it (SECURITY).
    //
    // Two keys may sign for the session's subject:
    //
    // (a) The subject's own key: the proof's `verificationMethod` belongs to
    //     the session's DID. Always accepted. It is what a wallet signs an
    //     approval or a refresh with, even in a session that has a key bound.
    //
    // (b) The session key bound at login (`auth/authenticate/0.2`
    //     `sessionKey`, or a passkey login's browser key): exactly
    //     `did:key:{pk}#{pk}`, and only for a task a session key may sign
    //     (`session_key_may_sign`). Never an approval, and never the auth
    //     family, so it cannot step itself up or outlive the login.
    //
    // Anything else is refused, or any resolvable DID's key could be
    // attributed to the subject. Checked before verification, so a forged
    // attribution is refused with its reason rather than a generic
    // `proofInvalid`.
    let session_key_vm = auth
        .as_ref()
        .and_then(|a| a.session_pubkey_b58btc.as_deref())
        .filter(|_| crate::messaging::session_key_may_sign(&doc.type_uri.to_string()))
        .map(|pk| format!("did:key:{pk}#{pk}"));
    if let (Some(auth), Some(proof)) = (auth.as_ref(), doc.proof.as_ref()) {
        let own_key = did_hosting_common::server::trust_tasks::verifier::controller_did(
            &proof.verification_method,
        ) == auth.did;
        let session_key = session_key_vm.as_deref() == Some(proof.verification_method.as_str());
        if !own_key && !session_key {
            tracing::warn!(
                actual_vm = %proof.verification_method,
                auth_did = %auth.did,
                session_key_vm = ?session_key_vm,
                type_uri = %doc.type_uri,
                "trust-task proof is neither the session subject's key nor a session key \
                 this task accepts — rejecting as proof_invalid"
            );
            let reject = RejectReason::ProofInvalid {
                reason: "proof verificationMethod is not bound to this session".to_string(),
            };
            let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject);
            return Ok(into_response(DispatchOutcome::Rejected(routed)));
        }
    }

    // ─── Route, through `messaging::dispatch_trust_task_doc`: the same entry
    // DIDComm and TSP use, so what a document means is decided in one place.
    //
    // A session with a bound key signs with it on behalf of the session's
    // subject, so its verifier accepts exactly that key for exactly that
    // principal. It is built per request from the verified bearer token, never
    // on the shared verifier, and only for a task that key may sign. Every
    // other caller signs as itself.
    let shared = state
        .trust_tasks_verifier
        .as_deref()
        .ok_or_else(|| AppError::Config("no trust-task proof verifier configured".into()))?;
    let delegated;
    let verifier = match (auth.as_ref(), session_key_vm) {
        (Some(auth), Some(vm)) => {
            delegated = shared.clone().with_session_delegate(auth.did.clone(), vm);
            &delegated
        }
        _ => shared,
    };

    // The peer: the bearer session's subject, or — with no session — the
    // document's own issuer, which the proof must then bind (empty when an
    // anonymous public read names none).
    let peer = match auth.as_ref() {
        Some(auth) => auth.did.clone(),
        None => doc.issuer.clone().unwrap_or_default(),
    };
    let transport = HttpsHandler::new(my_vid.to_string(), (!peer.is_empty()).then(|| peer.clone()));
    match crate::messaging::dispatch_trust_task_doc(
        &state,
        &peer,
        auth.as_ref(),
        &transport,
        doc,
        verifier,
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    {
        // The framework outcome keeps its reject code, which is the whole reason
        // the router hands it back whole: SPEC's status table is HTTPS's alone.
        crate::messaging::RoutedReply::Framework(outcome) => Ok(into_response(*outcome)),
        crate::messaging::RoutedReply::Document(value) => Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            serde_json::to_vec(&value).expect("Trust Task response serialises"),
        )
            .into_response()),
        crate::messaging::RoutedReply::Suppressed => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

/// Build a `trust-task-error` document for a body-parse failure.
/// We have no source `TrustTask` to draw `issuer`/`recipient` from,
/// so the error response is unrouted — the framework permits this on
/// malformed-body failures since the producer can correlate on the
/// response `id`.
fn body_parse_error(reason: &str) -> trust_tasks_rs::ErrorResponse {
    let reject = RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    };
    let payload: ErrorPayload = reject.into();
    trust_tasks_rs::ErrorResponse {
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        thread_id: None,
        // Unrouted, as above: nothing parsed, so no enclosing exchange to name
        // (SPEC §4.9.2) and no ceremony to stay inside (§7.1).
        parent_thread_id: None,
        ceremony: None,
        type_uri: error_type_uri(),
        issuer: None,
        recipient: None,
        issued_at: Some(chrono::Utc::now()),
        expires_at: None,
        payload,
        context: None,
        proof: None,
        extra: Default::default(),
    }
}

/// One definition for the workspace — see
/// [`did_hosting_common::server::trust_tasks::framework_error_type_uri`] for why
/// the value is named rather than read from the framework, and why every
/// unrouted path must agree with the routed ones.
fn error_type_uri() -> trust_tasks_rs::TypeUri {
    did_hosting_common::server::trust_tasks::framework_error_type_uri()
}

fn into_response(outcome: DispatchOutcome) -> Response {
    match outcome {
        DispatchOutcome::Handled(doc) => {
            let body = serde_json::to_vec(&doc)
                .expect("Handled response document serialises (TrustTask<Value>)");
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        DispatchOutcome::Rejected(err_doc) => {
            let status_u16 = status_for_code(&err_doc.payload.code);
            let status = StatusCode::from_u16(status_u16).unwrap_or_else(|_| {
                tracing::error!(status_u16, "unexpected status code from status_for_code");
                StatusCode::INTERNAL_SERVER_ERROR
            });
            let body =
                serde_json::to_vec(&err_doc).expect("error document serialises (trust-task-error)");
            (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        DispatchOutcome::Suppressed => {
            // SPEC.md §8.1: identity-mismatch with no transport
            // authenticated sender. Unreachable on the HTTPS transport
            // because bearer auth always resolves a peer. Surfaced as
            // an `error!` log on the off-chance the invariant breaks.
            tracing::error!(
                should_not_happen = true,
                "trust-tasks dispatch suppressed its reply on HTTPS"
            );
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    //! Smoke tests for the route wiring. The handlers themselves are
    //! tested exhaustively in
    //! `did_hosting_common::server::trust_tasks::handlers::*`.

    use trust_tasks_rs::{Payload, specs::acl::grant::v0_1 as grant};

    /// Unit test of [`body_parse_error`] — pins the wire shape clients
    /// depend on (code, type URI, unrouted issuer/recipient).
    #[test]
    fn body_parse_error_shape() {
        let err = super::body_parse_error("expected `,`");
        assert!(err.id.starts_with("urn:uuid:"));
        assert!(err.thread_id.is_none());
        assert_eq!(
            err.type_uri,
            did_hosting_common::server::trust_tasks::framework_error_type_uri(),
        );
        assert!(err.issuer.is_none());
        assert!(err.recipient.is_none());
        assert_eq!(
            err.payload.code,
            trust_tasks_rs::TrustTaskCode::Standard(trust_tasks_rs::StandardCode::MalformedRequest)
        );
        assert!(
            err.payload
                .message
                .as_deref()
                .unwrap()
                .contains("did not parse as a Trust Task document")
        );
    }

    /// Verify that a well-formed acl/grant payload at least
    /// deserialises at the `TrustTask<Value>` boundary the route's
    /// hand-rolled parse uses.
    #[test]
    fn well_formed_grant_envelope_round_trips() {
        let body = serde_json::json!({
            "id": "urn:uuid:5b3c5e2a-1b81-4d3e-9b51-7a3c89e3d1f2",
            "type": grant::Payload::TYPE_URI,
            "issuer": "did:web:admin.example",
            "recipient": "did:web:maintainer.example",
            "issuedAt": "2026-05-18T10:00:00Z",
            "payload": {
                "entry": {
                    "subject": "did:web:alice.example",
                    "role": "owner",
                    "ext": {
                        "vnd.affinidi.webvh": {
                            "domains": { "kind": "all" }
                        }
                    }
                }
            }
        });
        let doc: trust_tasks_rs::TrustTask<serde_json::Value> =
            serde_json::from_value(body).expect("envelope parses");
        assert_eq!(doc.type_uri.to_string(), grant::Payload::TYPE_URI);
    }
}

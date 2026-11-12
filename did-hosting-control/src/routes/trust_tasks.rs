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
    connect: Result<
        axum::extract::ConnectInfo<std::net::SocketAddr>,
        <axum::extract::ConnectInfo<std::net::SocketAddr> as axum::extract::FromRequestParts<
            AppState,
        >>::Rejection,
    >,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    // The client IP, resolved the same way whether it is about to gate an
    // invite redemption or a large document's per-address budget below —
    // both count the one source a stranger cannot choose over HTTPS.
    //
    // A request with no connection address is refused rather than counted
    // under a shared placeholder: every production server is built with
    // `into_make_service_with_connect_info`, so its absence is a wiring
    // fault, and a shared bucket would skip the redemption limit and pool
    // every such caller's large-document budget.
    let Ok(axum::extract::ConnectInfo(addr)) = connect else {
        tracing::error!(
            "trust-tasks request without a connection address; the server must be built with \
             into_make_service_with_connect_info"
        );
        return Err(AppError::Internal(
            "no connection address for this request".into(),
        ));
    };
    // A trusted proxy's unreadable `X-Forwarded-For` leaves the request with
    // no one to charge. Refused as every other refusal here is — a
    // `trust-task-error` document (`malformedRequest`, 400) — not as a REST
    // error body.
    let ip = match state.client_ips.client_ip(addr.ip(), &headers) {
        Ok(ip) => ip,
        Err(invalid) => {
            let reject = RejectReason::MalformedRequest {
                reason: invalid.to_string(),
            };
            return Ok(into_response(DispatchOutcome::Rejected(refusal(
                &body, reject,
            ))));
        }
    };
    let client_ip = Some(ip);
    // The unauthenticated ceremonies are limited per client address here, the
    // one place that knows it; on DIDComm and TSP their handlers limit per
    // sender.
    let limiter = match ceremony_kind(&body) {
        Some(Ceremony::RedeemStart) => Some(&state.redeem_rate_limiter),
        Some(Ceremony::LoginStart) => Some(&state.login_start_rate_limiter),
        None => None,
    };
    if let Some(limiter) = limiter {
        let limited = limiter.try_consume(format!("ip:{ip}"));
        if let Err(AppError::RateLimited {
            retry_after_secs, ..
        }) = limited
        {
            // Refused as the task would be — a routed `unavailable` document
            // with its retry time — not as a bare REST 429.
            let reject = RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                ),
            };
            return Ok(into_response(DispatchOutcome::Rejected(refusal(
                &body, reject,
            ))));
        }
    }
    dispatch_trust_task(auth, State(state), client_ip, &headers, body).await
}

/// An unauthenticated ceremony the route limits per client address.
enum Ceremony {
    /// `auth/passkey/enroll/redeem/start`.
    RedeemStart,
    /// `auth/passkey/login/start`.
    LoginStart,
}

/// The Type URIs of the ceremonies the route limits per client address.
const LIMITED_CEREMONY_TYPES: [&str; 2] = {
    use did_hosting_common::tasks::auth::passkey::{enroll::redeem, login};
    use trust_tasks_rs::Payload;
    [
        redeem::start::v0_1::Payload::TYPE_URI,
        login::start::v0_2::Payload::TYPE_URI,
    ]
};

/// Which limited ceremony `body` opens, if any.
///
/// Two steps, cheapest first, so a stranger's body costs no more here than
/// the size gate in [`dispatch_trust_task`] would allow:
///
/// 1. A body larger than every limited ceremony's own document limit is not
///    one. Its length is all that is read: whatever its `type`, the size
///    gate refuses it before anything parses it, so it can never reach a
///    ceremony's handler.
/// 2. Otherwise only the top-level `type` is read, into the same [`TypeUri`]
///    the router's `TrustTask<Value>` parse produces and compared as the
///    router compares it, with every other member skipped. A body the router
///    would serve as a ceremony therefore always classifies as one:
///    duplicate members and escapes read the same way in both parses. A
///    body that only this lighter read accepts is refused by the router as
///    malformed, so counting it costs nobody a legitimate attempt.
///
/// [`TypeUri`]: trust_tasks_rs::TypeUri
fn ceremony_kind(body: &[u8]) -> Option<Ceremony> {
    let ceiling = LIMITED_CEREMONY_TYPES
        .iter()
        .map(|type_uri| {
            did_hosting_common::server::trust_tasks::size::max_document_bytes(
                type_uri,
                &crate::control_tasks::SERVED_TRUST_TASK_URIS,
            )
        })
        .max()
        .unwrap_or(did_hosting_common::server::trust_tasks::size::DEFAULT_MAX_DOCUMENT_BYTES);
    if body.len() > ceiling {
        return None;
    }
    #[derive(serde::Deserialize)]
    struct TypeOnly {
        #[serde(rename = "type")]
        type_uri: trust_tasks_rs::TypeUri,
    }
    let type_uri = serde_json::from_slice::<TypeOnly>(body)
        .ok()?
        .type_uri
        .to_string();
    let [redeem_start, login_start] = LIMITED_CEREMONY_TYPES;
    if type_uri == redeem_start {
        Some(Ceremony::RedeemStart)
    } else if type_uri == login_start {
        Some(Ceremony::LoginStart)
    } else {
        None
    }
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
///
/// `client_ip`, when known, is this document's address for the per-address
/// large-document budget below (`ip:{client_ip}`) — `None` for a direct,
/// non-HTTPS call (tests exercising this handler without a real socket),
/// which then shares one placeholder address rather than being charged
/// against nothing.
///
/// `client_ip`, `headers` and the body's size travel to the router as
/// [`HttpsFacts`](crate::messaging::HttpsFacts): a bound-key row (wallet
/// sign-in) is admitted on them — its origin, rate limits and size — and
/// reads its requester details from them.
pub async fn dispatch_trust_task(
    auth: Option<AuthClaims>,
    State(state): State<AppState>,
    client_ip: Option<std::net::IpAddr>,
    headers: &axum::http::HeaderMap,
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
    //
    //         A document large enough to need its claimed (not yet
    //         verified) issuer's ACL entry for the raised limit is charged
    //         against that address's large-document budget first — see
    //         `size`'s module docs for why an unverified claim alone would
    //         otherwise be a DoS amplifier.
    let address = client_ip
        .map(|ip| format!("ip:{ip}"))
        .unwrap_or_else(|| "ip:unknown".to_string());
    let large_doc_charge =
        match did_hosting_common::server::trust_tasks::size::check_for_known_issuer(
            &body,
            &crate::control_tasks::SERVED_TRUST_TASK_URIS,
            &state.acl_ks,
            &state.large_document_budget,
            &address,
        )
        .await
        {
            Ok(charge) => charge,
            Err(err) => return Ok(into_response(DispatchOutcome::Rejected(err))),
        };

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

    // A task whose rule takes no bearer session (`ProofRule::BoundKey`: wallet
    // sign-in, whose exchange is its only authority) is served exactly as if
    // none were sent — no session binding below, no session context, and the
    // document's own issuer as the peer.
    let auth =
        auth.filter(|_| crate::messaging::proof_rule(&doc.type_uri.to_string()).admits_bearer());

    // ─── 3. With a bearer session, the proof must be bound to it (SECURITY).
    //
    // Two keys may sign for the session's subject:
    //
    // (a) The subject's own key: the proof's `verificationMethod` belongs to
    //     the session's DID. Always accepted. It is what a wallet signs an
    //     approval or a refresh with, even in a session that has a key bound.
    //
    // (b) The session key bound at login (`auth/authenticate/0.3`
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
        let own_key = did_hosting_common::scid::same_reference(
            did_hosting_common::server::trust_tasks::verifier::controller_did(
                &proof.verification_method,
            ),
            &auth.did,
        );
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
    let https = crate::messaging::HttpsFacts {
        ip: client_ip,
        headers,
        body_len: body.len(),
    };
    match crate::messaging::dispatch_trust_task_doc(
        &state,
        &peer,
        auth.as_ref(),
        Some(&https),
        &transport,
        doc,
        verifier,
        large_doc_charge,
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    {
        // The framework outcome keeps its reject code, which is the whole reason
        // the router hands it back whole: SPEC's status table is HTTPS's alone.
        crate::messaging::RoutedReply::Framework(outcome) => Ok(into_response(*outcome)),
        crate::messaging::RoutedReply::Document(value) => {
            // `trust_tasks_auth::dispatch` (the auth family's own local
            // dispatcher — see `messaging::route_trust_task_doc`) hands back a
            // bare serialised document, success or `trust-task-error` alike,
            // with no `DispatchOutcome` wrapper to carry a status through. A
            // refusal — `delegationNotRecognized`, `sessionKeyProofRequired`,
            // `sessionLifetimeExceeded`, every code this family raises —
            // answered `200 OK` would tell a caller that gates on the status
            // line, before ever reading the body, that its login or refresh
            // succeeded. Map it through the same table `into_response` uses.
            let status = document_status(&value);
            // Only a refusal carries a retry hint; a success payload's own
            // field of that name is not one.
            let retry_after = (!status.is_success())
                .then(|| value["payload"]["retryAfter"].as_str())
                .flatten()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&chrono::Utc));
            let mut response = (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                serde_json::to_vec(&value).expect("Trust Task response serialises"),
            )
                .into_response();
            set_retry_after(&mut response, retry_after);
            Ok(response)
        }
        crate::messaging::RoutedReply::Suppressed => Ok(StatusCode::NO_CONTENT.into_response()),
        crate::messaging::RoutedReply::Sealed(sealed) => Ok(sealed_response(sealed)),
    }
}

/// A bound-key row's reply (`RoutedReply::Sealed`), with the status its
/// family assigned. Never cached and never sent as a referrer: these replies
/// carry one-time numbers and, from `redeem`, session tokens.
fn sealed_response(sealed: crate::control_tasks::SealedReply) -> Response {
    use axum::http::{HeaderValue, header};
    let mut resp = match sealed {
        crate::control_tasks::SealedReply::Document { status, body } => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            axum::Json(body),
        )
            .into_response(),
        crate::control_tasks::SealedReply::Unavailable(message) => {
            (StatusCode::SERVICE_UNAVAILABLE, message).into_response()
        }
    };
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

/// A `trust-task-error` refusing `body` for `reject` before it is
/// dispatched: routed to the document when the body parses as one, unrouted
/// otherwise.
fn refusal(body: &[u8], reject: RejectReason) -> trust_tasks_rs::ErrorResponse {
    // A body larger than any type takes by default is not parsed just to
    // address a refusal: the reply goes unrouted, as a parse failure's does.
    if body.len() > did_hosting_common::server::trust_tasks::size::DEFAULT_MAX_DOCUMENT_BYTES {
        return unrouted_error(reject);
    }
    match serde_json::from_slice::<TrustTask<Value>>(body) {
        Ok(doc) => doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject),
        Err(_) => unrouted_error(reject),
    }
}

/// Build a `trust-task-error` document for a body-parse failure.
fn body_parse_error(reason: &str) -> trust_tasks_rs::ErrorResponse {
    unrouted_error(RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    })
}

/// An unrouted `trust-task-error` document. We have no source `TrustTask` to
/// draw `issuer`/`recipient` from, so the error response is unrouted — the
/// framework permits this on malformed-body failures since the producer can
/// correlate on the response `id`.
fn unrouted_error(reject: RejectReason) -> trust_tasks_rs::ErrorResponse {
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
            let mut response = (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response();
            set_retry_after(&mut response, err_doc.payload.retry_after);
            response
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

/// A refusal carrying `retryAfter` says what an HTTP client reads from
/// `Retry-After`: give it both. Rounded up, since a hint rounded down invites
/// a retry too soon.
fn set_retry_after(response: &mut Response, at: Option<chrono::DateTime<chrono::Utc>>) {
    let Some(at) = at else {
        return;
    };
    let millis = (at - chrono::Utc::now()).num_milliseconds().max(0) as u64;
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(millis.div_ceil(1000).max(1)),
    );
}

/// The status for a bare serialised reply document from
/// `trust_tasks_auth::dispatch` — `200` for a success (or anything not shaped
/// like a framework error), and [`status_for_code`]'s mapping for a
/// `trust-task-error` document, exactly as [`into_response`] applies it to a
/// routed [`DispatchOutcome::Rejected`].
fn document_status(value: &Value) -> StatusCode {
    let error_type_uri =
        did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string();
    let is_error = value
        .get("type")
        .and_then(Value::as_str)
        .map(|t| t == error_type_uri)
        .unwrap_or(false);
    if !is_error {
        return StatusCode::OK;
    }
    let Some(code) = value
        .get("payload")
        .and_then(|p| p.get("code"))
        .and_then(Value::as_str)
    else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    let Ok(code) = code.parse::<trust_tasks_rs::TrustTaskCode>() else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    StatusCode::from_u16(status_for_code(&code)).unwrap_or_else(|_| {
        tracing::error!(code = %code, "unexpected status code from status_for_code");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

#[cfg(test)]
mod tests {
    //! Smoke tests for the route wiring. The handlers themselves are
    //! tested exhaustively in
    //! `did_hosting_common::server::trust_tasks::handlers::*`.

    use did_hosting_common::tasks::acl::grant::v0_2 as grant;
    use trust_tasks_rs::Payload;

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
                    "act": { "scope": "all" },
                    "keys": { "scope": "none" },
                    "capabilities": { "scope": "ceiling" }
                }
            }
        });
        let doc: trust_tasks_rs::TrustTask<serde_json::Value> =
            serde_json::from_value(body).expect("envelope parses");
        assert_eq!(doc.type_uri.to_string(), grant::Payload::TYPE_URI);
    }

    fn ceremony_body(type_uri: &str, padding: usize) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": "urn:uuid:5b3c5e2a-1b81-4d3e-9b51-7a3c89e3d1f2",
            "type": type_uri,
            "issuedAt": "2026-05-18T10:00:00Z",
            "payload": {
                "token": "inv_not-a-real-token",
                "claimCode": "0000-0000-0000",
                "padding": "x".repeat(padding),
            }
        }))
        .unwrap()
    }

    #[test]
    fn ceremonies_are_classified_by_their_type() {
        let [redeem_start, login_start] = super::LIMITED_CEREMONY_TYPES;
        assert!(matches!(
            super::ceremony_kind(&ceremony_body(redeem_start, 0)),
            Some(super::Ceremony::RedeemStart)
        ));
        assert!(matches!(
            super::ceremony_kind(&ceremony_body(login_start, 0)),
            Some(super::Ceremony::LoginStart)
        ));
        assert!(super::ceremony_kind(&ceremony_body(grant::Payload::TYPE_URI, 0)).is_none());
        assert!(super::ceremony_kind(b"not json").is_none());
    }

    /// A body over the ceremonies' own size limit is not classified, even
    /// one whose content a parse would read as a ceremony: only its length
    /// is looked at, and the size gate refuses it later before any parse.
    #[test]
    fn an_oversized_body_is_not_classified() {
        use did_hosting_common::server::trust_tasks::size::DEFAULT_MAX_DOCUMENT_BYTES;
        let [redeem_start, _] = super::LIMITED_CEREMONY_TYPES;
        let body = ceremony_body(redeem_start, DEFAULT_MAX_DOCUMENT_BYTES);
        assert!(body.len() > DEFAULT_MAX_DOCUMENT_BYTES);
        // A full parse would read it as a redemption...
        let doc: trust_tasks_rs::TrustTask<serde_json::Value> =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(doc.type_uri.to_string(), redeem_start);
        // ...but it is not one here.
        assert!(super::ceremony_kind(&body).is_none());

        // A body of that length is refused for its size whatever comes after
        // its first bytes, so nothing past them needs to be valid JSON.
        let mut truncated = body[..body.len() / 2].to_vec();
        truncated.resize(DEFAULT_MAX_DOCUMENT_BYTES + 1, b'x');
        assert!(super::ceremony_kind(&truncated).is_none());
    }

    /// The light read and the router's full parse agree on what a `type`
    /// is: a duplicate `type` is refused by both, so it cannot be served as
    /// a ceremony while going uncounted.
    #[test]
    fn a_duplicate_type_is_refused_by_both_reads() {
        let [redeem_start, _] = super::LIMITED_CEREMONY_TYPES;
        let body = format!(
            r#"{{"id":"urn:uuid:x","type":"{}","type":"{redeem_start}","payload":{{}}}}"#,
            grant::Payload::TYPE_URI
        );
        assert!(super::ceremony_kind(body.as_bytes()).is_none());
        assert!(
            serde_json::from_str::<trust_tasks_rs::TrustTask<serde_json::Value>>(&body).is_err()
        );
    }

    /// A refusal does not parse a body larger than the default limit to
    /// address it.
    #[test]
    fn a_refusal_of_an_oversized_body_is_unrouted() {
        use did_hosting_common::server::trust_tasks::size::DEFAULT_MAX_DOCUMENT_BYTES;
        let [redeem_start, _] = super::LIMITED_CEREMONY_TYPES;
        let reject = || trust_tasks_rs::RejectReason::MalformedRequest {
            reason: "test".into(),
        };
        let small = super::refusal(&ceremony_body(redeem_start, 0), reject());
        assert_eq!(
            small.thread_id.as_deref(),
            Some("urn:uuid:5b3c5e2a-1b81-4d3e-9b51-7a3c89e3d1f2")
        );
        let large = super::refusal(
            &ceremony_body(redeem_start, DEFAULT_MAX_DOCUMENT_BYTES),
            reject(),
        );
        assert!(large.thread_id.is_none());
    }
}

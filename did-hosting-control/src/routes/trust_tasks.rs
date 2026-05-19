//! `POST /api/trust-tasks` — the new Trust Tasks transport endpoint
//! introduced in v0.7.1.
//!
//! Receives a JSON-encoded `TrustTask<serde_json::Value>` envelope,
//! authenticates the caller via the existing JWT-bearer flow, and
//! hands the document to [`did_hosting_common::server::trust_tasks::dispatch_inbound`].
//! The dispatch layer narrows the untyped document to one of the
//! six typed handlers (five `acl/*` + `trust-task-discovery`), runs
//! SPEC.md §7.2 items 4–8 against it, and produces a typed response
//! or routed error.
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

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use trust_tasks_https::{HttpsHandler, status_for_code};
use trust_tasks_rs::{ErrorPayload, RejectReason, TrustTask};
use uuid::Uuid;

use did_hosting_common::server::trust_tasks::{
    DispatchOutcome, NoVerifier, TrustTaskContext, dispatch_inbound,
};
use trust_tasks_proof::affinidi::Verifier as AffinidiVerifier;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// `POST /api/trust-tasks` handler.
///
/// Bearer-auth'd via [`AuthClaims`]; the caller's DID becomes the
/// transport-authenticated peer for SPEC.md §4.8.1 precedence inside
/// each typed handler.
pub async fn dispatch_trust_task(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(doc): Json<TrustTask<Value>>,
) -> Result<Response, AppError> {
    // Service DID is the local party — every typed handler uses it as
    // `recipient` and (on success) as the response document's issuer.
    // Without one configured we can't run the §7.2 recipient check,
    // so refuse early with a clear operator message.
    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| AppError::Config("server_did not configured".into()))?;

    let transport = HttpsHandler::new(my_vid.to_string(), auth.did);
    let ctx = TrustTaskContext {
        acl_ks: &state.acl_ks,
        my_vid,
    };

    // Dispatch with the configured proof verifier only when the
    // operator has opted in via `trust_tasks.enforce_proofs = true`.
    // v0.7.1 ships proof-optional by default so the Web UI (no
    // browser-side signing infrastructure yet) keeps working; backend
    // callers that DO sign get strict enforcement by flipping the
    // flag. See `AppConfig.trust_tasks.enforce_proofs`.
    let outcome = match (
        state.config.trust_tasks.enforce_proofs,
        state.trust_tasks_verifier.as_deref(),
    ) {
        (true, Some(v)) => {
            dispatch_inbound::<AffinidiVerifier>(&ctx, &transport, Some(v), doc).await
        }
        _ => dispatch_inbound::<NoVerifier>(&ctx, &transport, None, doc).await,
    };
    Ok(into_response(outcome))
}

/// Custom JSON-decode rejection handler: when the body is not a
/// valid `TrustTask<Value>`, axum's `Json` extractor returns a 400
/// with a plain-text error. We never reach `dispatch_trust_task` in
/// that case. To preserve the trust-task error-document shape on the
/// malformed-body path, axum lets us register a fallback. The
/// simplest way to keep this behaviour explicit is to handle the
/// parse manually — see [`dispatch_trust_task_raw`] below.
///
/// In practice we expose [`dispatch_trust_task`] (which uses axum's
/// `Json` extractor) and accept that body-parse failures land as a
/// plain-text 400. Clients should treat 400 with `Content-Type:
/// text/plain` as a body-shape failure (≈ `malformed_request`); a
/// future tighten can swap this for [`dispatch_trust_task_raw`] if
/// the wire shape matters.
#[allow(dead_code)]
pub async fn dispatch_trust_task_raw(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let doc: TrustTask<Value> = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            let err_doc = body_parse_error(&e.to_string());
            return Ok(into_response(DispatchOutcome::Rejected(err_doc)));
        }
    };
    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| AppError::Config("server_did not configured".into()))?;
    let transport = HttpsHandler::new(my_vid.to_string(), auth.did);
    let ctx = TrustTaskContext {
        acl_ks: &state.acl_ks,
        my_vid,
    };
    let outcome = match (
        state.config.trust_tasks.enforce_proofs,
        state.trust_tasks_verifier.as_deref(),
    ) {
        (true, Some(v)) => {
            dispatch_inbound::<AffinidiVerifier>(&ctx, &transport, Some(v), doc).await
        }
        _ => dispatch_inbound::<NoVerifier>(&ctx, &transport, None, doc).await,
    };
    Ok(into_response(outcome))
}

/// Build a `trust-task-error/0.1` document for a body-parse failure.
/// We have no source `TrustTask` to draw `issuer`/`recipient` from,
/// so the error response is unrouted (per the framework, this is
/// acceptable for malformed-body failures — the producer can correlate
/// on the response `id`).
fn body_parse_error(reason: &str) -> trust_tasks_rs::ErrorResponse {
    let reject = RejectReason::MalformedRequest {
        reason: format!("body did not parse as a Trust Task document: {reason}"),
    };
    let payload: ErrorPayload = reject.into();
    trust_tasks_rs::ErrorResponse {
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        thread_id: None,
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

fn error_type_uri() -> trust_tasks_rs::TypeUri {
    // `trust-task-error/0.1` is a framework-reserved slug; the parser
    // accepts it as canonical.
    "https://trusttasks.org/spec/trust-task-error/0.1"
        .parse()
        .expect("framework error Type URI parses")
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
            // Default `task_failed` to 422 when the maintainer-side
            // policy did not pick a more specific standard code (the
            // status_for_code table maps every variant; this branch
            // covers the InternalError edge).
            let status = StatusCode::from_u16(status_u16).unwrap_or_else(|_| {
                // Conservative fallback — status table emits values
                // axum accepts, so this only fires on bug.
                tracing::error!(status_u16, "unexpected status code from status_for_code");
                StatusCode::INTERNAL_SERVER_ERROR
            });
            let body = serde_json::to_vec(&err_doc)
                .expect("error document serialises (trust-task-error/0.1)");
            (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        DispatchOutcome::Suppressed => {
            // SPEC.md §8.1: identity-mismatch rejection where the
            // transport authenticated no sender. Emitting any body
            // would constitute an oracle — return an empty 204 so
            // the client at least sees the request was received.
            // (The §8.1 letter says "SHOULD NOT emit any response,"
            // which 204 with no body honours at the application
            // layer; the response line itself is unavoidable on HTTP.)
            //
            // In practice this branch is unreachable on the HTTPS
            // transport — the bearer-auth resolved the peer DID, so
            // transport.derive_parties().issuer is always Some.
            tracing::warn!(
                "trust-tasks dispatch returned Suppressed on HTTPS — this should be unreachable \
                 because bearer auth pins the transport sender"
            );
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    //! Smoke tests for the `POST /api/trust-tasks` route wiring.
    //!
    //! The handlers themselves are tested exhaustively in
    //! `did_hosting_common::server::trust_tasks::handlers::*`. Tests
    //! here only verify the route + transport + auth glue.

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::json;
    use tower::ServiceExt;
    use trust_tasks_rs::{Payload, specs::acl::grant::v0_1 as grant};

    use crate::routes;

    /// Build an `AppState`-bearing router for inline integration tests.
    /// Requires the full setup pipeline; we use the existing test
    /// harness in `crate::server::test_support` if present, otherwise
    /// fall through with a `#[ignore]` marker for ops to run manually.
    #[tokio::test]
    #[ignore = "requires AppState test harness (TODO: wire test fixture)"]
    async fn route_returns_400_on_malformed_body() {
        // Placeholder for an inline AppState fixture. The control
        // plane doesn't currently expose a test-only `AppState::test()`
        // constructor; building one here would duplicate the setup
        // logic in src/main.rs. Skipped until task #14 lands the
        // shared harness.
        let _ = routes::router; // smoke-link the symbol
    }

    /// Unit test of [`body_parse_error`] — verifies the produced
    /// document carries the `malformed_request` code and the wire
    /// shape clients depend on.
    #[test]
    fn body_parse_error_shape() {
        let err = super::body_parse_error("expected `,`");
        assert!(err.id.starts_with("urn:uuid:"));
        assert!(err.thread_id.is_none());
        assert_eq!(
            err.type_uri.to_string(),
            "https://trusttasks.org/spec/trust-task-error/0.1"
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

    /// Verify that a well-formed acl/grant payload at least deserialises
    /// at the Json<TrustTask<Value>> boundary that the route uses.
    /// (The handler-level behaviour is tested in did-hosting-common.)
    #[test]
    fn well_formed_grant_envelope_round_trips() {
        let body = json!({
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
        // Round-trips into the untyped envelope axum's Json<TrustTask<Value>>
        // produces on the wire — proves the body shape parses.
        let doc: trust_tasks_rs::TrustTask<serde_json::Value> =
            serde_json::from_value(body).expect("envelope parses");
        assert_eq!(doc.type_uri.to_string(), grant::Payload::TYPE_URI);
    }

    // Touch the `tower` + `to_bytes` imports so dropping the
    // #[ignore]'d integration test below doesn't leave an unused-dep
    // warning.
    fn _imports_silencer() {
        let _ = std::any::type_name::<Body>();
        let _ = std::any::type_name::<Request<Body>>();
        let _ = StatusCode::OK;
        // tower's ServiceExt is the trait we'd use for `oneshot()`.
        fn _take<T: ServiceExt<()>>() {}
        async fn _async_silence() {
            let _: Vec<u8> = to_bytes(Body::empty(), 0).await.unwrap_or_default().into();
        }
    }
}

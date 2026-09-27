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
/// size separately (see [`crate::routes::TRUST_TASKS_BODY_LIMIT`]).
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
    // (a) The session carries an ephemeral session key (passkey Web UI flow):
    //     the proof's `verificationMethod` MUST be that `did:key:{pk}#{pk}`.
    //     Otherwise a key the server never bound to this session could sign as
    //     its subject.
    //
    // (b) It carries none (wallet or machine sessions): the proof's
    //     `verificationMethod` MUST belong to the session's subject, or any
    //     resolvable DID's key could be attributed to it.
    //
    // Enforced before verification, so a forged attribution is refused with
    // its reason rather than a generic `proofInvalid`.
    if let (Some(auth), Some(proof)) = (auth.as_ref(), doc.proof.as_ref()) {
        if let Some(pk) = auth.session_pubkey_b58btc.as_deref() {
            let expected_vm = format!("did:key:{pk}#{pk}");
            if proof.verification_method != expected_vm {
                tracing::warn!(
                    actual_vm = %proof.verification_method,
                    expected_vm,
                    "trust-task proof verificationMethod does not match the JWT-bound \
                     session pubkey — rejecting as proof_invalid"
                );
                let reject = RejectReason::ProofInvalid {
                    reason: "proof verificationMethod is not bound to this session".to_string(),
                };
                let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject);
                return Ok(into_response(DispatchOutcome::Rejected(routed)));
            }
        } else {
            let proof_did = proof
                .verification_method
                .split_once('#')
                .map(|(d, _)| d)
                .unwrap_or("");
            if proof_did != auth.did {
                tracing::warn!(
                    proof_did = %proof_did,
                    auth_did = %auth.did,
                    "trust-task proof verificationMethod DID does not match the \
                     authenticated caller — rejecting as proof_invalid"
                );
                let reject = RejectReason::ProofInvalid {
                    reason: "proof verificationMethod DID does not match the authenticated caller"
                        .to_string(),
                };
                let routed = doc.reject_with(format!("urn:uuid:{}", Uuid::new_v4()), reject);
                return Ok(into_response(DispatchOutcome::Rejected(routed)));
            }
        }
    }

    // ─── Route, through `messaging::dispatch_trust_task_doc`: the same entry
    // DIDComm and TSP use, so what a document means is decided in one place.
    //
    // A passkey session signs with its session key on behalf of the session's
    // subject, so its verifier accepts exactly that key for exactly that
    // principal — built per request from the verified bearer token, never on
    // the shared verifier. Every other caller signs as itself.
    let shared = state
        .trust_tasks_verifier
        .as_deref()
        .ok_or_else(|| AppError::Config("no trust-task proof verifier configured".into()))?;
    let delegated;
    let verifier = match auth
        .as_ref()
        .and_then(|a| a.session_pubkey_b58btc.as_deref().map(|pk| (a, pk)))
    {
        Some((auth, pk)) => {
            delegated = shared
                .clone()
                .with_session_delegate(auth.did.clone(), format!("did:key:{pk}#{pk}"));
            &delegated
        }
        None => shared,
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

//! `POST /api/trust-tasks` — the Trust Tasks transport endpoint
//! introduced in v0.7.0.
//!
//! Receives a JSON-encoded `TrustTask<serde_json::Value>` envelope,
//! authenticates the caller via the existing JWT-bearer flow, and
//! hands the document to [`did_hosting_common::server::trust_tasks::dispatch_inbound`].
//! The dispatch layer narrows the untyped document to one of the six
//! typed handlers (five `acl/*` + `trust-task-discovery`), runs
//! SPEC.md §7.2 items 4–8 against it, and produces a typed response
//! or routed error.
//!
//! ## Body-parse failures are spec-conformant
//!
//! We accept the request body as `axum::body::Bytes` and parse to
//! `TrustTask<Value>` by hand. The reason: axum's typed `Json<...>`
//! extractor rejects malformed bodies with a plain-text 400 *before*
//! the handler runs, which would be a wire-shape regression — the
//! framework spec asks for a `trust-task-error/0.1` document on
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
use trust_tasks_rs::{ErrorPayload, ProofPolicy, RejectReason, TrustTask};
use uuid::Uuid;

use did_hosting_common::server::trust_tasks::{
    DispatchOutcome, TrustTaskContext, dispatch_inbound,
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
///
/// Body is accepted as raw bytes so a parse failure surfaces as a
/// `trust-task-error/0.1` document with `code: malformed_request`
/// rather than axum's text/plain default. The route mount caps body
/// size separately (see [`crate::routes::TRUST_TASKS_BODY_LIMIT`]).
pub async fn dispatch_trust_task(
    auth: AuthClaims,
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
    //        emits a routed `trust-task-error/0.1` document with
    //        `code: malformed_request`.
    let doc: TrustTask<Value> = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            return Ok(into_response(DispatchOutcome::Rejected(body_parse_error(
                &e.to_string(),
            ))));
        }
    };

    // ─── 3. Proof-verificationMethod binding pre-check (SECURITY).
    //
    // Two cases, depending on how the JWT was issued:
    //
    // (a) JWT carries an ephemeral session pubkey (passkey Web UI flow).
    //     The proof's `verificationMethod` MUST be the matching
    //     `did:key:{pk}#{pk}` URL. Otherwise the proof was signed by a key
    //     the server hasn't bound to this JWT — even if the signature
    //     verifies, accepting it would let any key holder forge requests
    //     as the JWT subject.
    //
    // (b) JWT carries no session pubkey (wallet SIOPv2 flow, machine-to-
    //     machine auth). The proof's `verificationMethod` MUST resolve to
    //     a DID that matches `auth.did` (the JWT `sub`). Without this
    //     check, the framework's verifier would happily accept a proof
    //     from ANY resolvable DID — letting a wallet user with one
    //     authenticated session sign trust-tasks attributed to a totally
    //     different DID, as long as that other DID's key can be resolved.
    //
    // The framework's verifier handles signature verification + DID
    // resolution; this pre-check enforces caller binding *before*
    // verification so a forged-attribution attempt is rejected with the
    // explicit reason rather than a generic "proof_invalid".
    if let Some(proof) = doc.proof.as_ref() {
        if let Some(pk) = auth.session_pubkey_b58btc.as_deref() {
            // Case (a): session-key flow.
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
            // Case (b): no session-key bound; verify the proof's DID matches
            // the authenticated caller (JWT.sub).
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

    // ─── 4. Build the transport adapter + context.
    let transport = HttpsHandler::new(my_vid.to_string(), auth.did);
    let ctx = TrustTaskContext {
        acl_ks: &state.acl_ks,
        acl_locks: &state.acl_locks,
        my_vid,
    };

    // ─── 5. Dispatch.
    //
    // Map the operator's `enforce_proofs` toggle to a framework
    // [`ProofPolicy`]:
    //
    //   * `true` + verifier configured → `Verify(&verifier)` — proof-
    //     bearing documents are verified, proofless REQUIRED-spec
    //     documents are rejected `proof_required`.
    //   * `false` (default) → `RejectIfPresent` — proof-bearing
    //     documents are rejected `malformed_request` with the
    //     framework-shared sanitised wire message (see
    //     `trust_tasks_rs::PROOF_NOT_ACCEPTED_BY_POLICY`). The
    //     operator-actionable diagnostic moves to a `tracing::warn!`
    //     in `dispatch_inbound`. Silently dropping a proof would
    //     mislead the producer about the integrity guarantees of
    //     the exchange.
    let policy: ProofPolicy<'_, AffinidiVerifier> = match (
        state.config.trust_tasks.enforce_proofs,
        state.trust_tasks_verifier.as_deref(),
    ) {
        (true, Some(v)) => ProofPolicy::Verify(v),
        _ => ProofPolicy::RejectIfPresent,
    };
    let outcome = dispatch_inbound::<AffinidiVerifier>(&ctx, &transport, policy, doc).await;
    Ok(into_response(outcome))
}

/// Build a `trust-task-error/0.1` document for a body-parse failure.
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
            let status = StatusCode::from_u16(status_u16).unwrap_or_else(|_| {
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
            // SPEC.md §8.1: identity-mismatch with no transport
            // authenticated sender. Unreachable on the HTTPS transport
            // because bearer auth always resolves a peer. Surfaced as
            // an `error!` log on the off-chance the invariant breaks.
            tracing::error!(
                should_not_happen = true,
                "trust-tasks dispatch returned Suppressed on HTTPS — bearer auth always resolves a peer"
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

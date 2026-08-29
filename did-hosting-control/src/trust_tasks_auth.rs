//! Control-plane auth trust tasks: `auth/{challenge,authenticate,refresh}/0.1`.
//!
//! Authentication to this control plane existed in two mutually exclusive
//! shapes, and neither was reachable from the third transport:
//!
//! | binding | how a peer authenticated |
//! |---|---|
//! | HTTPS | canonical challenge → authenticate, with a signed document |
//! | DIDComm | bespoke `MSG_AUTHENTICATE`: the authcrypt sender *is* the auth, body ignored |
//! | TSP | nothing at all |
//!
//! So a wallet connected over TSP could not log in, and a wallet over DIDComm
//! logged in by a different rule than one over HTTPS. This module gives the
//! family one identity on every wire, exactly as [`crate::trust_tasks_infra`]
//! did for server registration and health — see its module doc for the same
//! argument made about a different family.
//!
//! ## Why not `did_hosting_common::server::trust_tasks::build_dispatcher`
//!
//! That dispatcher's [`TrustTaskContext`] carries `acl_ks`, `acl_locks` and
//! `my_vid` — it is the ACL family's context. Auth needs session storage,
//! challenge tracking and token minting, which live on the control plane's
//! `AppState`. Widening the shared context to carry control-plane state would
//! push this service's concerns into the crate both services share. A local
//! `owns` + `dispatch` pair is the pattern this codebase already uses twice for
//! exactly that reason.
//!
//! ## The authentication rule, and why it is the strict one
//!
//! `AuthenticateInput::signer_did` is documented as: *"Verified signer DID. The
//! transport layer must produce this from a cryptographic check — never echo it
//! from the request body unchecked."*
//!
//! Two things could satisfy that here. The transport-authenticated sender
//! (authcrypt / TSP prove it) is what the bespoke DIDComm handler used. The
//! **document proof** is what the canonical spec means: `auth/authenticate/0.1`
//! exists so that possession of a challenge plus a signature over it proves
//! control of a VID, independent of how the bytes travelled.
//!
//! This takes the document proof. `ResolvedParties::issuer` is that value, and
//! it is cryptographically established either way by
//! [`TransportBoundVerifier`](did_hosting_common::server::trust_tasks::TransportBoundVerifier):
//! when the document asserts an `issuer`, the proof's `verificationMethod` DID
//! must equal it; when it does not, the framework fills `issuer` from the
//! transport-authenticated sender and a transport that authenticated nobody
//! leaves it `None`, which is refused below. There is no path here where an
//! unverified body value becomes a session.
//!
//! The stricter reading is the right one for a family whose entire purpose is
//! proving identity: accepting the transport's word would make `challenge`
//! decorative on two of three bindings, and a decorative challenge is one that
//! stops being checked.

use serde_json::Value;
use tracing::warn;
use trust_tasks_rs::{
    Dispatcher, ErrorPayload, ErrorResponse, ProofPolicy, ProofVerifier, ResolvedParties,
    StandardCode, TransportHandler, TrustTask,
    specs::auth::{
        authenticate::v0_1 as authenticate, challenge::v0_1 as challenge, refresh::v0_1 as refresh,
    },
};

use did_hosting_common::server::trust_tasks::{DispatchOutcome, run_pipeline};
use vti_common::auth::backend::{AuthenticateInput, ChallengeInput, RefreshInput};
use vti_common::auth::handlers::{handle_authenticate, handle_challenge, handle_refresh};

use crate::server::AppState;

/// The three request documents this module narrows an untyped inbound into.
enum TypedAuth {
    Challenge(Box<TrustTask<challenge::Payload>>),
    Authenticate(Box<TrustTask<authenticate::Payload>>),
    Refresh(Box<TrustTask<refresh::Payload>>),
}

/// Narrowing dispatcher — SPEC §7.2 items 1–3 (framework schema, payload-type
/// narrowing, unknown-type rejection). Items 4–8 run per-arm in
/// [`run_pipeline`].
fn build_auth_dispatcher() -> Dispatcher<TypedAuth> {
    Dispatcher::new()
        .on::<challenge::Payload, _>(|d| TypedAuth::Challenge(Box::new(d)))
        .on::<authenticate::Payload, _>(|d| TypedAuth::Authenticate(Box::new(d)))
        .on::<refresh::Payload, _>(|d| TypedAuth::Refresh(Box::new(d)))
}

/// Does this Type URI belong to the auth family handled here?
///
/// Asked of the dispatcher rather than matched against literals, so the set
/// this claims and the set it can actually narrow cannot drift apart — the
/// failure mode being a URI `owns` accepts and `dispatch` then warns about as
/// unowned, which is a silent 500 dressed as a routing bug.
pub fn owns(type_uri: &str) -> bool {
    build_auth_dispatcher()
        .registered_uris()
        .contains(&type_uri)
}

/// Handle an auth trust task. Returns the serialised response document.
pub async fn dispatch<V>(
    state: &AppState,
    transport: &(impl TransportHandler + Sync),
    policy: ProofPolicy<'_, V>,
    doc: TrustTask<Value>,
) -> Option<Value>
where
    V: ProofVerifier + ?Sized,
{
    let error_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let typed = match build_auth_dispatcher().dispatch_or_reject(doc, error_id) {
        Ok(t) => t,
        Err(err) => return Some(serialise(&err)),
    };

    let outcome = match typed {
        TypedAuth::Challenge(d) => {
            run_pipeline(
                transport,
                policy,
                *d,
                my_vid(state)?,
                |doc, parties| async move { challenge_arm(state, doc, &parties).await },
            )
            .await
        }
        TypedAuth::Authenticate(d) => {
            run_pipeline(
                transport,
                policy,
                *d,
                my_vid(state)?,
                |doc, parties| async move { authenticate_arm(state, doc, &parties).await },
            )
            .await
        }
        TypedAuth::Refresh(d) => {
            run_pipeline(
                transport,
                policy,
                *d,
                my_vid(state)?,
                |doc, parties| async move { refresh_arm(state, doc, &parties).await },
            )
            .await
        }
    };

    match outcome {
        DispatchOutcome::Handled(resp) => Some(serialise(&resp)),
        DispatchOutcome::Rejected(err) => Some(serialise(&err)),
        // SPEC §8.1: an identity mismatch with no transport-authenticated
        // sender has nobody safe to address a rejection to.
        DispatchOutcome::Suppressed => None,
    }
}

fn my_vid(state: &AppState) -> Option<&str> {
    match state.config.server_did.as_deref() {
        Some(v) => Some(v),
        None => {
            warn!("trust_tasks_auth: server_did not configured; cannot answer an auth task");
            None
        }
    }
}

fn serialise<T: serde::Serialize>(doc: &T) -> Value {
    serde_json::to_value(doc).expect("response document serialises")
}

/// The caller, as established by the framework — never a body value.
// `ErrorResponse` is the upstream `TrustTask<ErrorPayload>`, which
// `result_large_err` flags — here and on each of the three arms below, all of
// which return it. Same reasoning as the allows in `trust_tasks_did` and
// `did-hosting-common`'s handlers: the type is upstream, and boxing it at this
// boundary would churn every caller to save one move on a path that is about to
// serialise the error onto the wire anyway.
#[allow(clippy::result_large_err)]
fn caller<P>(doc: &TrustTask<P>, parties: &ResolvedParties) -> Result<String, ErrorResponse> {
    parties.issuer.clone().ok_or_else(|| {
        doc.reject_with(
            format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            ErrorPayload::new(StandardCode::PermissionDenied).with_message(
                "inbound document has no in-band or transport-derived issuer, so there is \
                 no verified identity to authenticate",
            ),
        )
    })
}

/// Map a backend auth failure onto a framework rejection.
///
/// Deliberately opaque: `AuthError` distinguishes an unknown session from an
/// expired challenge from a signer that does not match the session, and telling
/// an unauthenticated caller which of those it hit is an oracle. The operator
/// gets the detail in the log; the wire gets `permissionDenied`.
fn denied<P>(doc: &TrustTask<P>, what: &str, err: impl std::fmt::Display) -> ErrorResponse {
    warn!(error = %err, op = what, "auth trust task refused");
    doc.reject_with(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        ErrorPayload::new(StandardCode::PermissionDenied).with_message("authentication refused"),
    )
}

#[allow(clippy::result_large_err)]
async fn challenge_arm(
    state: &AppState,
    doc: TrustTask<challenge::Payload>,
    parties: &ResolvedParties,
) -> Result<TrustTask<vta_sdk::protocols::auth::ChallengeResponse>, ErrorResponse> {
    let did = caller(&doc, parties)?;
    let backend = crate::auth::DidHostingControlAuthBackend::from_state(state)
        .map_err(|e| denied(&doc, "challenge/backend", e))?;

    // `subject` in the payload is the VID the producer *intends* to
    // authenticate as. It is not taken as the caller: the challenge is bound to
    // the identity the framework verified, so a document asking for a challenge
    // on someone else's behalf gets one bound to itself and fails at
    // authenticate. Honouring it would make the challenge a request for a
    // credential naming an arbitrary subject.
    let resp = handle_challenge(
        &backend,
        ChallengeInput {
            did,
            session_pubkey_b58btc: None,
        },
    )
    .await
    .map_err(|e| denied(&doc, "challenge", e))?;

    Ok(doc.respond_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), resp))
}

#[allow(clippy::result_large_err)]
async fn authenticate_arm(
    state: &AppState,
    doc: TrustTask<authenticate::Payload>,
    parties: &ResolvedParties,
) -> Result<TrustTask<vta_sdk::protocols::auth::AuthenticateResponse>, ErrorResponse> {
    let signer_did = caller(&doc, parties)?;
    let backend = crate::auth::DidHostingControlAuthBackend::from_state(state)
        .map_err(|e| denied(&doc, "authenticate/backend", e))?;

    let resp = handle_authenticate(
        &backend,
        AuthenticateInput {
            session_id: doc.payload.session_id.to_string(),
            challenge: doc.payload.challenge.to_string(),
            // The verified signer. See the module doc: this is the document's
            // proof identity, bound to the asserted `issuer` when there is one
            // and filled from the authenticated transport when there is not.
            signer_did,
            // Freshness is the framework's job here — `validate_freshness` has
            // already bounded `issuedAt` against the acceptance window by the
            // time this runs, so there is no separate DIDComm `created_time`
            // for the handler to re-check.
            created_time: None,
            // A session pubkey is the HTTPS/passkey delegation path's concern;
            // a trust-task producer signs with its own key.
            session_pubkey_b58btc: None,
        },
    )
    .await
    .map_err(|e| denied(&doc, "authenticate", e))?;

    Ok(doc.respond_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), resp))
}

#[allow(clippy::result_large_err)]
async fn refresh_arm(
    state: &AppState,
    doc: TrustTask<refresh::Payload>,
    parties: &ResolvedParties,
) -> Result<TrustTask<vta_sdk::protocols::auth::AuthenticateResponse>, ErrorResponse> {
    let signer_did = caller(&doc, parties)?;
    let backend = crate::auth::DidHostingControlAuthBackend::from_state(state)
        .map_err(|e| denied(&doc, "refresh/backend", e))?;

    let resp = handle_refresh(
        &backend,
        RefreshInput {
            refresh_token: doc.payload.refresh_token.to_string(),
            // Always `Some` on this path. `RefreshInput` documents `None` as
            // "skip the signer-matches-session check", which is only safe where
            // the transport offers no signer assertion — plain REST, where the
            // token is the sole credential. A trust task always carries a
            // verified identity, so declining to pass it would discard a check
            // we are in a position to make.
            signer_did: Some(signer_did),
        },
    )
    .await
    .map_err(|e| denied(&doc, "refresh", e))?;

    Ok(doc.respond_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests read the spec constants; importing it at module scope
    // would be dead weight in a non-test build.
    use trust_tasks_rs::Payload as PayloadSpec;

    /// `owns` must claim exactly the three request URIs — and in particular not
    /// the `#response` forms, which are documents *we* emit and must never
    /// route back into ourselves.
    #[test]
    fn owns_the_three_request_uris_and_not_their_responses() {
        for uri in [
            <challenge::Payload as PayloadSpec>::TYPE_URI,
            <authenticate::Payload as PayloadSpec>::TYPE_URI,
            <refresh::Payload as PayloadSpec>::TYPE_URI,
        ] {
            assert!(owns(uri), "{uri} must be owned");
            assert!(
                !owns(&format!("{uri}#response")),
                "{uri}#response must NOT be owned",
            );
        }
    }

    #[test]
    fn owns_nothing_outside_the_family() {
        assert!(!owns("https://trusttasks.org/spec/acl/list/0.1"));
        assert!(!owns("https://trusttasks.org/spec/auth/whoami/0.1"));
        assert!(!owns("not a uri"));
    }
}

//! Control-plane auth trust tasks: `auth/challenge/0.1`, `auth/authenticate`
//! (`0.2` and `0.3`) and `auth/refresh` (`0.1` and `0.2`).
//!
//! Two versions of `authenticate` and of `refresh` are served side by side.
//! This is not a compatibility shim for anything this service used to do
//! itself — every in-repo caller (the did-hosting UI's wallet login and the
//! VTA-proxied SIOP login, both below) moved onto `0.3`/`0.2`. It is because
//! the VTI Wallet browser extension — a separate, externally-versioned
//! client this change cannot reach — still emits `auth/authenticate/0.2` for
//! its own login and `auth/refresh/0.1` for its step-up renewal
//! (`stepUpVta`). `0.3` is a backwards-compatible `MINOR` increment over
//! `0.2` by the spec's own design ("every `0.2` document... is processed
//! identically"), and `0.2` says the same of `0.1` for refresh, so keeping
//! both arms is exactly what the specs anticipate for a mixed-version fleet,
//! not a hand-rolled compatibility layer this service invented.
//!
//! Authentication to this control plane existed in two mutually exclusive
//! shapes, and neither was reachable from the third transport:
//!
//! | binding | how a peer authenticated |
//! |---|---|
//! | HTTPS | canonical challenge → authenticate, with a signed document |
//! | DIDComm | bespoke `MSG_AUTHENTICATE`: the reported sender *is* the auth, body ignored (route since removed) |
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
//! Two things were candidates here. The transport's reported sender is what
//! the bespoke DIDComm handler used — but a report is not a cryptographic check
//! this service performs. The
//! **document proof** is what the canonical spec means: `auth/authenticate/0.1`
//! exists so that possession of a challenge plus a signature over it proves
//! control of a VID, independent of how the bytes travelled.
//!
//! This takes the document proof. `ResolvedParties::issuer` is that value:
//! [`TransportBoundVerifier`](did_hosting_common::server::trust_tasks::TransportBoundVerifier)
//! requires an in-band `issuer` and binds the proof's `verificationMethod` to
//! it, and `dispatch_trust_task_doc`'s gate has already refused any
//! `auth/authenticate` document that is unsigned or whose issuer disagrees with
//! the transport's sender. There is no path here where an unverified body value,
//! or a transport's report of the sender, becomes a session. (`auth/challenge`
//! is the one member of the family routed without a proof: it only mints the
//! nonce the authenticate document must then sign.)
//!
//! The stricter reading is the right one for a family whose entire purpose is
//! proving identity: accepting the transport's word would make `challenge`
//! decorative on two of three bindings, and a decorative challenge is one that
//! stops being checked.
//!
//! ## Session keys (`auth/authenticate/0.2`)
//!
//! An authenticate document may name a `sessionKey`, a `did:key` the producer
//! holds. It sits inside the payload, so the subject's own proof is what
//! authorises the binding. [`authenticate_arm`] stores its Ed25519 multikey on
//! the new session row, exactly as a passkey login stores its browser key. From
//! then on the HTTPS binding accepts that key's `authentication` proofs as the
//! subject:
//!
//! - **for that session only.** The key is honoured only alongside the
//!   session's own bearer token, and only for that token's subject;
//! - **within the session's bounds.** The bearer extractor reads the session
//!   row on every request, so expiry, `auth/revoke-session` and logout end the
//!   key with the session. The session's `acr` is carried unchanged, so
//!   anything that needs a step-up still does;
//! - **never where an `assertionMethod` attestation is required.** A step-up
//!   approval must be signed by the subject's own key, on the Trust Task and
//!   REST paths alike, and the verifier refuses a delegated approval outright;
//! - **never to mint or extend a session.** `auth/authenticate` and
//!   `auth/refresh` refuse a session-key proof (`session_key_may_sign`). A
//!   refresh is authorised by the refresh token, not by the key. The console's
//!   REST refresh (`routes::auth::refresh`) does ask for the key's proof, but
//!   only on top of the refresh token, as proof that the browser presenting
//!   the token is the one that logged in: the key alone refreshes nothing.
//!
//! A key type this service cannot verify is refused with
//! `auth/authenticate:sessionKeyUnsupported`, before the challenge is spent. It
//! never falls back to a login without the binding the producer asked for.

use serde_json::Value;
use tracing::warn;
use trust_tasks_rs::{
    Dispatcher, ErrorPayload, ErrorResponse, ProofPolicy, ProofVerifier, ResolvedParties,
    StandardCode, TransportHandler, TrustTask,
    specs::auth::{
        authenticate::v0_2 as authenticate_v2, authenticate::v0_3 as authenticate,
        challenge::v0_1 as challenge, refresh::v0_1 as refresh_v1, refresh::v0_2 as refresh,
    },
};

use did_hosting_common::epoch_to_rfc3339;
use did_hosting_common::server::auth::session::{get_session, get_session_by_refresh, now_epoch};
use did_hosting_common::server::trust_tasks::{DispatchOutcome, run_pipeline};
use vti_common::auth::backend::{AuthenticateInput, RefreshInput};
use vti_common::auth::handlers::{handle_authenticate, handle_refresh};

use crate::server::AppState;

/// The five request documents this module narrows an untyped inbound into.
enum TypedAuth {
    Challenge(Box<TrustTask<challenge::Payload>>),
    AuthenticateV2(Box<TrustTask<authenticate_v2::Payload>>),
    AuthenticateV3(Box<TrustTask<authenticate::Payload>>),
    RefreshV1(Box<TrustTask<refresh_v1::Payload>>),
    RefreshV2(Box<TrustTask<refresh::Payload>>),
}

/// Narrowing dispatcher — SPEC §7.2 items 1–3 (framework schema, payload-type
/// narrowing, unknown-type rejection). Items 4–8 run per-arm in
/// [`run_pipeline`].
fn build_auth_dispatcher() -> Dispatcher<TypedAuth> {
    Dispatcher::new()
        .on::<challenge::Payload, _>(|d| TypedAuth::Challenge(Box::new(d)))
        .on::<authenticate_v2::Payload, _>(|d| TypedAuth::AuthenticateV2(Box::new(d)))
        .on::<authenticate::Payload, _>(|d| TypedAuth::AuthenticateV3(Box::new(d)))
        .on::<refresh_v1::Payload, _>(|d| TypedAuth::RefreshV1(Box::new(d)))
        .on::<refresh::Payload, _>(|d| TypedAuth::RefreshV2(Box::new(d)))
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
        TypedAuth::AuthenticateV2(d) => {
            run_pipeline(
                transport,
                policy,
                *d,
                my_vid(state)?,
                |doc, parties| async move { authenticate_v2_arm(state, doc, &parties).await },
            )
            .await
        }
        TypedAuth::AuthenticateV3(d) => {
            run_pipeline(
                transport,
                policy,
                *d,
                my_vid(state)?,
                |doc, parties| async move { authenticate_v3_arm(state, doc, &parties).await },
            )
            .await
        }
        TypedAuth::RefreshV1(d) => {
            run_pipeline(
                transport,
                policy,
                *d,
                my_vid(state)?,
                |doc, parties| async move { refresh_v1_arm(state, doc, &parties).await },
            )
            .await
        }
        TypedAuth::RefreshV2(d) => {
            run_pipeline(
                transport,
                policy,
                *d,
                my_vid(state)?,
                |doc, parties| async move { refresh_v2_arm(state, doc, &parties).await },
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
// which return it. Same reasoning as the allows in `did-hosting-common`'s
// handlers: the type is upstream, and boxing it at this
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

    // `subject` in the payload is the VID the producer *intends* to
    // authenticate as. It is not taken as the caller: the challenge is bound to
    // the identity the framework verified, so a document asking for a challenge
    // on someone else's behalf gets one bound to itself and fails at
    // authenticate. Honouring it would make the challenge a request for a
    // credential naming an arbitrary subject.
    //
    // Issued through the same path as `POST /api/auth/challenge`, so the
    // per-DID and global pending-challenge caps hold on every binding — before,
    // this arm called the canonical handler directly with its per-DID limit
    // disabled, and challenges over DIDComm/TSP were unbounded. (The per-IP
    // limiter has no meaning here: there is no client IP on a messaging
    // binding.) The Trust Task specification defines no rate-limit code, so a
    // refusal takes this arm's existing mapping for every challenge failure —
    // `permissionDenied`, with the limiter and retry hint in the operator log
    // only.
    let resp = crate::routes::auth::issue_challenge(state, did)
        .await
        .map_err(|e| denied(&doc, "challenge", e))?;

    Ok(doc.respond_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), resp))
}

/// The Ed25519 multikey (`z6Mk…`) inside a `sessionKey` `did:key`, or `None`
/// when it encodes anything this service cannot verify a proof from.
///
/// The session-key verifier resolves `did:key:{pk}#{pk}` and signs with
/// `eddsa-jcs-2022`, so only an Ed25519 key is usable. Accepting another curve
/// would bind a key whose every later proof is refused. The schema has already
/// held the value to `did:key:z…` in base58btc; this checks what it decodes to.
fn ed25519_session_key(session_key: &str) -> Option<String> {
    let multikey = session_key.strip_prefix("did:key:")?;
    did_hosting_common::server::auth::session::is_ed25519_multikey(multikey)
        .then(|| multikey.to_string())
}

#[allow(clippy::result_large_err)]
async fn authenticate_v2_arm(
    state: &AppState,
    doc: TrustTask<authenticate_v2::Payload>,
    parties: &ResolvedParties,
) -> Result<TrustTask<authenticate_v2::Response>, ErrorResponse> {
    let signer_did = caller(&doc, parties)?;

    // Refused before the challenge is touched, so the producer can retry the
    // same challenge without the key. It is never quietly dropped: a login the
    // producer believes bound a key, and which did not, would have every
    // later call the key signs refused.
    let requested_key = doc.payload.session_key.as_ref().map(|k| k.to_string());
    let session_pubkey_b58btc = match requested_key.as_deref() {
        None => None,
        Some(key) => Some(ed25519_session_key(key).ok_or_else(|| {
            warn!(session_key = %key, "authenticate refused: unsupported session key type");
            doc.reject_with(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                ErrorPayload::from(authenticate_v2::error_codes::SESSION_KEY_UNSUPPORTED)
                    .with_message("this service binds Ed25519 did:key session keys only")
                    .with_details(serde_json::json!({ "requested": key })),
            )
        })?),
    };

    let backend = crate::auth::DidHostingControlAuthBackend::from_state(state)
        .map_err(|e| denied(&doc, "authenticate/backend", e))?;

    let session_id = doc.payload.session_id.to_string();
    let resp = handle_authenticate(
        &backend,
        AuthenticateInput {
            session_id: session_id.clone(),
            challenge: doc.payload.challenge.to_string(),
            // The verified signer. See the module doc: this is the document's
            // in-band `issuer`, which the proof is bound to.
            signer_did,
            // Freshness is the framework's job here — `validate_freshness` has
            // already bounded `issuedAt` against the acceptance window by the
            // time this runs, so there is no separate DIDComm `created_time`
            // for the handler to re-check.
            created_time: None,
            // The session key the subject's proof covers, bound to the session
            // row this creates. See the module doc for what it may then sign.
            session_pubkey_b58btc,
            // The document's `recipient` is covered by its proof and has been
            // checked against `my_vid` twice already — by the proof gate in
            // `dispatch_trust_task_doc` and by `run_pipeline`.
            audience: vti_common::auth::AudienceBinding::Transport,
        },
    )
    .await
    .map_err(|e| denied(&doc, "authenticate", e))?;

    // The challenge is spent: free its slot, whichever binding issued it.
    state.pending_challenges.release_session(&session_id);

    // The absolute session lifetime is this deployment's own backstop
    // (`AuthConfig::absolute_session_lifetime`) against a refresh token (and,
    // where bound, a session key) that stays quietly compromised — and its
    // own doc comment states the ceiling in terms of "authenticated
    // (`auth/authenticate/0.2` or `/0.3`)", not just 0.3. `refresh_v2_arm`
    // enforces it by reading this same meta row; a 0.2 login that never wrote
    // one would refresh forever with no ceiling at all, exactly the
    // unbounded-compromise case this config exists to close. So every login
    // through this arm gets one too, with no `actor` — 0.2 has no proxied
    // form.
    //
    // Keyed by `resp.session.id` (the DID-keyed session `handle_authenticate`
    // just minted) — never the local `session_id` above, which is
    // `payload.sessionId`, the just-released *challenge* row. See
    // `authenticate_v3_arm`'s identical note.
    store_auth_proxy_meta(
        state,
        &resp.session.id,
        None,
        now_epoch() + state.config.auth.absolute_session_lifetime,
    )
    .await
    .map_err(|e| denied(&doc, "authenticate/meta", e))?;

    // The response echoes the bound key (`Session.sessionKey`), so the
    // producer can confirm the binding it asked for is the one it got.
    let mut value =
        serde_json::to_value(&resp).map_err(|e| denied(&doc, "authenticate/response", e))?;
    if let Some(key) = requested_key {
        value["session"]["sessionKey"] = Value::String(key);
    }
    let payload: authenticate_v2::Response =
        serde_json::from_value(value).map_err(|e| denied(&doc, "authenticate/response", e))?;

    Ok(doc.respond_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload))
}

// ---------------------------------------------------------------------------
// auth/authenticate/0.3 — the proxied form
// ---------------------------------------------------------------------------

/// The one `delegationEvidence.kind` this deployment recognizes: a mandate
/// the principal signed themselves, naming the delegate and this service.
///
/// A `reference` alone, or any other `kind`, is refused
/// (`delegationNotRecognized`) — this service keeps no out-of-band
/// delegation registry to resolve a bare reference against, and the
/// Authorization section is explicit that an unrecognized `kind` is refused,
/// never treated as an unenforced pass.
const MANDATE_EVIDENCE_KIND: &str = "mandateCredential";

/// The `type` this deployment requires on an inline `mandateCredential`, so a
/// document minted for some *other* purpose — signed by the same principal,
/// addressed to the same service, naming the same delegate by coincidence of
/// field names — cannot be replayed here as a mandate it never was.
///
/// `local/…`, not `_local/…`: a Trust Task *Type URI* slug segment must start
/// with an ASCII lowercase letter (SPEC.md §6.1's grammar; `TypeUri::from_str`
/// enforces it), so a leading underscore fails to parse at all — every
/// mandate a producer could ever present would be refused as "not a Trust
/// Task document" before its own contents were ever checked, which is a
/// silent, total outage of this evidence kind rather than the deliberate
/// unenforced-kind refusal `delegationNotRecognized` is for.
const MANDATE_EVIDENCE_TYPE_URI: &str =
    "https://trusttasks.org/spec/local/did-hosting-auth-mandate/0.1";

/// `payload.delegate` on a `mandateCredential`: the delegate the principal is
/// entitling, which MUST equal the authenticate document's own signer.
#[derive(serde::Deserialize)]
struct MandatePayload {
    delegate: String,
}

/// The second recognized `delegationEvidence.kind`: the compact SIOPv2
/// `id_token` the VTA-proxied SIOP login already produces (`vault/proxy-login`
/// custodial signing — the *principal's own* key, held at the VTA, signs the
/// token; the browser never touches it). Session-specific rather than a
/// standing grant: it is freshly signed over *this* login's own challenge, so
/// unlike `mandateCredential` it carries no separate expiry of its own — its
/// freshness is the challenge's.
const SIOP_ID_TOKEN_EVIDENCE_KIND: &str = "siopIdToken";

/// `delegationEvidence.credential` under `kind: "siopIdToken"`.
#[derive(serde::Deserialize)]
struct SiopIdTokenCredential {
    #[serde(rename = "idToken")]
    id_token: String,
}

/// Verify that `evidence` establishes `delegate` (the authenticate
/// document's own signer — verified via its framework `proof`, never a body
/// claim) is entitled to authenticate as `principal`, for the challenge this
/// authenticate document itself carries.
///
/// Independent verification, exactly as Authorization requires: `evidence`
/// is never taken at its word. Two shapes are recognized; any other `kind`
/// (and a `reference` alone, under either) is refused —
/// `delegationNotRecognized` — this service keeps no out-of-band delegation
/// registry to resolve a bare reference against:
///
/// - **`mandateCredential`** — `credential`, inline, shaped as a Trust Task
///   document whose `issuer` is the principal, `recipient` is this service's
///   own VID (so a mandate minted for one auth service cannot be replayed at
///   another), `payload.delegate` names the delegate, and a `proof` with
///   `proofPurpose: assertionMethod` — an attestation, over the principal's
///   *own* key, never a session-key delegation — that
///   [`AppState::trust_tasks_verifier`] resolves through the principal's own
///   DID document and verifies. A standing grant: usable for any login until
///   the mandate's own `expiresAt`.
/// - **`siopIdToken`** — `credential.idToken`, the compact SIOPv2 `id_token`
///   `vault/proxy-login`'s custodial signing already produces: `iss`/`sub`
///   MUST be the principal, `aud` MUST be this service, and — the freshness
///   that ties it to *this* login rather than any other the principal's VTA
///   ever signed — its `nonce` MUST equal `challenge`, the same value this
///   authenticate document itself echoes from `auth/challenge`. Verified via
///   [`didcomm_unpack::verify_siop_id_token`], which resolves `iss`'s DID
///   document independently; a party that cannot produce the principal's own
///   signature cannot satisfy this, whatever `issuer`/`proof` the outer
///   authenticate document carries.
///
/// On success this is exactly the property
/// `auth/authenticate:delegationNotRecognized`'s absence promises: the
/// principal themselves said, in a signature only they could produce, that
/// this delegate may act for them at this service.
///
/// Returns the refusal reason (operator-log detail only; the wire refusal is
/// the same opaque `delegationNotRecognized` for every cause) on failure.
async fn verify_delegation_evidence(
    state: &AppState,
    principal: &str,
    delegate: &str,
    challenge: &str,
    evidence: &authenticate::PayloadDelegationEvidence,
) -> Result<(), String> {
    match evidence.kind.as_str() {
        MANDATE_EVIDENCE_KIND => {
            if evidence.credential.is_empty() {
                return Err("mandateCredential requires an inline credential".into());
            }
            let mandate: TrustTask<Value> = serde_json::from_value(Value::Object(
                evidence.credential.clone(),
            ))
            .map_err(|e| format!("credential does not parse as a Trust Task document: {e}"))?;

            if mandate.type_uri.to_string() != MANDATE_EVIDENCE_TYPE_URI {
                return Err("credential is not a did-hosting-auth-mandate document".into());
            }
            if mandate.issuer.as_deref() != Some(principal) {
                return Err("credential.issuer does not name the principal".into());
            }
            if mandate.recipient.as_deref() != state.config.server_did.as_deref() {
                return Err("credential.recipient does not name this service".into());
            }
            if let Some(expires_at) = mandate.expires_at
                && expires_at < chrono::Utc::now()
            {
                return Err("credential has expired".into());
            }
            let mandate_payload: MandatePayload =
                serde_json::from_value(mandate.payload.clone())
                    .map_err(|e| format!("credential.payload does not name a delegate: {e}"))?;
            if mandate_payload.delegate != delegate {
                return Err("credential does not name this delegate".into());
            }
            if mandate.proof.as_ref().map(|p| p.proof_purpose.as_str()) != Some("assertionMethod") {
                return Err("credential proof must be an assertionMethod attestation".into());
            }
            let verifier = state
                .trust_tasks_verifier
                .as_ref()
                .ok_or_else(|| "no proof verifier configured".to_string())?;
            verifier
                .verify(&mandate)
                .await
                .map_err(|e| format!("credential proof failed verification: {e}"))?;
            Ok(())
        }
        SIOP_ID_TOKEN_EVIDENCE_KIND => {
            if evidence.credential.is_empty() {
                return Err("siopIdToken requires an inline credential".into());
            }
            let cred: SiopIdTokenCredential =
                serde_json::from_value(Value::Object(evidence.credential.clone()))
                    .map_err(|e| format!("credential is not a siopIdToken payload: {e}"))?;
            let did_resolver = state
                .did_resolver
                .as_ref()
                .ok_or_else(|| "no DID resolver configured".to_string())?;
            let verified = did_hosting_common::server::didcomm_unpack::verify_siop_id_token(
                &cred.id_token,
                did_resolver,
            )
            .await
            .map_err(|e| format!("id_token failed verification: {e}"))?;
            if verified.issuer != principal {
                return Err("id_token iss/sub does not name the principal".into());
            }
            let own_vid = state
                .config
                .server_did
                .as_deref()
                .ok_or_else(|| "server_did not configured".to_string())?;
            if verified.audience != own_vid {
                return Err("id_token aud does not name this service".into());
            }
            if verified.nonce != challenge {
                return Err("id_token nonce does not match this authenticate's challenge".into());
            }
            let now = now_epoch();
            const CLOCK_SKEW_SECS: u64 = 60;
            if verified.expires_at <= now {
                return Err("id_token has expired".into());
            }
            if verified.issued_at > now + CLOCK_SKEW_SECS {
                return Err("id_token iat is in the future".into());
            }
            if verified.issued_at > verified.expires_at {
                return Err("id_token iat is after exp".into());
            }
            Ok(())
        }
        other => Err(format!("unrecognized delegationEvidence.kind {other:?}")),
    }
}

/// Side state this module keeps *outside* the `vti_common::auth::session`
/// row, keyed by `session_id` (which, for an authenticated session, is
/// stable for the session's whole life — vti-common mints it once, at
/// `auth/authenticate`, and every `auth/refresh` preserves it unchanged).
/// Two members neither vti-common's `Session` nor its canonical handlers
/// carry: the proxied login's delegate (`actor`) and the absolute session
/// lifetime this deployment enforces. Overwritten, never accumulated: a
/// fresh login for the same principal writes the same key.
#[derive(serde::Serialize, serde::Deserialize)]
struct AuthProxyMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    absolute_expires_at: u64,
}

fn auth_proxy_meta_key(session_id: &str) -> String {
    format!("auth-proxy-meta:{session_id}")
}

async fn store_auth_proxy_meta(
    state: &AppState,
    session_id: &str,
    actor: Option<String>,
    absolute_expires_at: u64,
) -> Result<(), crate::error::AppError> {
    state
        .sessions_ks
        .insert(
            auth_proxy_meta_key(session_id),
            &AuthProxyMeta {
                actor,
                absolute_expires_at,
            },
        )
        .await?;
    Ok(())
}

async fn get_auth_proxy_meta(
    state: &AppState,
    session_id: &str,
) -> Result<Option<AuthProxyMeta>, crate::error::AppError> {
    state.sessions_ks.get(auth_proxy_meta_key(session_id)).await
}

/// Remove `session_id`'s auth-proxy meta row, if any.
///
/// Called from `auth/revoke-session` (the console's logout) and from any
/// other path that ends a session outright, so a proxied login's `actor`
/// and absolute-lifetime cap never outlive the session they were minted
/// for. Sessions never proxied (a direct `auth/authenticate/0.2` login)
/// have no row here — deleting a key that was never written is a no-op,
/// not an error.
pub(crate) async fn delete_auth_proxy_meta(
    state: &AppState,
    session_id: &str,
) -> Result<(), crate::error::AppError> {
    state
        .sessions_ks
        .remove(auth_proxy_meta_key(session_id))
        .await
}

#[allow(clippy::result_large_err)]
async fn authenticate_v3_arm(
    state: &AppState,
    doc: TrustTask<authenticate::Payload>,
    parties: &ResolvedParties,
) -> Result<TrustTask<authenticate::Response>, ErrorResponse> {
    let signer_did = caller(&doc, parties)?;

    // Refused before the challenge is touched, so the producer can retry the
    // same challenge without the key. It is never quietly dropped: a login the
    // producer believes bound a key, and which did not, would have every
    // later call the key signs refused.
    let requested_key = doc.payload.session_key.as_ref().map(|k| k.to_string());
    let session_pubkey_b58btc = match requested_key.as_deref() {
        None => None,
        Some(key) => Some(ed25519_session_key(key).ok_or_else(|| {
            warn!(session_key = %key, "authenticate refused: unsupported session key type");
            doc.reject_with(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                ErrorPayload::from(authenticate::error_codes::SESSION_KEY_UNSUPPORTED)
                    .with_message("this service binds Ed25519 did:key session keys only")
                    .with_details(serde_json::json!({ "requested": key })),
            )
        })?),
    };

    // The acting party: `principal` when present and unequal to `issuer` (a
    // proxied authenticate), otherwise `issuer` itself — SPEC conformance
    // item 5. Passed to `handle_authenticate` as the session's own subject,
    // so the challenge-binding check it already runs
    // (`subjectMismatch`/`SignerMismatch`) compares against the *acting
    // party*, exactly as item 5 requires, without this module re-deriving
    // vti-common's session lookup to do it separately.
    let principal = doc.payload.principal.as_ref().map(|p| p.to_string());
    let proxied = principal.as_deref().is_some_and(|p| p != signer_did);
    let acting_party = if proxied {
        principal.clone().expect("proxied implies principal")
    } else {
        signer_did.clone()
    };

    if proxied {
        let Some(evidence) = doc.payload.delegation_evidence.as_ref() else {
            return Err(doc.reject_with(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                ErrorPayload::from(authenticate::error_codes::DELEGATION_EVIDENCE_REQUIRED)
                    .with_message("a proxied authenticate must carry delegationEvidence"),
            ));
        };
        if let Err(reason) = verify_delegation_evidence(
            state,
            &acting_party,
            &signer_did,
            doc.payload.challenge.as_str(),
            evidence,
        )
        .await
        {
            warn!(
                principal = %acting_party,
                delegate = %signer_did,
                reason = %reason,
                "proxied authenticate refused: delegation not recognized",
            );
            return Err(doc.reject_with(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                ErrorPayload::from(authenticate::error_codes::DELEGATION_NOT_RECOGNIZED)
                    .with_message("delegation evidence did not establish the entitlement"),
            ));
        }
    }

    let backend = crate::auth::DidHostingControlAuthBackend::from_state(state)
        .map_err(|e| denied(&doc, "authenticate/backend", e))?;

    let session_id = doc.payload.session_id.to_string();
    let resp = handle_authenticate(
        &backend,
        AuthenticateInput {
            session_id: session_id.clone(),
            challenge: doc.payload.challenge.to_string(),
            // The acting party — `principal` for a proxied login, else the
            // verified signer. Never the raw, unproxied `issuer` on a
            // proxied request: that would bind the session, and the
            // challenge's own subject check, to the delegate instead of the
            // principal it is authenticating.
            signer_did: acting_party.clone(),
            created_time: None,
            session_pubkey_b58btc,
            audience: vti_common::auth::AudienceBinding::Transport,
        },
    )
    .await
    .map_err(|e| denied(&doc, "authenticate", e))?;

    state.pending_challenges.release_session(&session_id);

    // Keyed by `resp.session.id` — the canonical, DID-keyed session id
    // `handle_authenticate` just minted — never `session_id` above, which is
    // `payload.sessionId`, the now-consumed *challenge*'s row. The two are
    // different identifiers throughout the session's whole life (a fresh
    // login mints a new challenge id every time; the authenticated session id
    // is the subject's own DID and outlives it), and `refresh_v2_arm` reads
    // this row back keyed by the former, not the latter. Keying the write by
    // the challenge id silently orphaned every meta row the instant the
    // challenge it was written under was released a line above — no refresh
    // could ever find it again, so neither the absolute lifetime cap nor
    // `actor` ever actually reached a refresh.
    let absolute_expires_at = now_epoch() + state.config.auth.absolute_session_lifetime;
    let actor = proxied.then(|| signer_did.clone());
    store_auth_proxy_meta(state, &resp.session.id, actor.clone(), absolute_expires_at)
        .await
        .map_err(|e| denied(&doc, "authenticate/meta", e))?;

    let mut value =
        serde_json::to_value(&resp).map_err(|e| denied(&doc, "authenticate/response", e))?;
    if let Some(key) = requested_key {
        value["session"]["sessionKey"] = Value::String(key);
    }
    if let Some(actor) = actor {
        value["session"]["actor"] = Value::String(actor);
    }
    value["session"]["absoluteExpiresAt"] = Value::String(epoch_to_rfc3339(absolute_expires_at));
    let payload: authenticate::Response =
        serde_json::from_value(value).map_err(|e| denied(&doc, "authenticate/response", e))?;

    Ok(doc.respond_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload))
}

#[allow(clippy::result_large_err)]
async fn refresh_v1_arm(
    state: &AppState,
    doc: TrustTask<refresh_v1::Payload>,
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

/// Re-type `doc` as the framework's untyped `TrustTask<Value>`, for
/// [`crate::routes::auth::verify_session_bound_proof`], whose signature
/// predates the typed `refresh::Payload`.
///
/// MUST carry every member exactly as received — `issuer`, `recipient`,
/// `issuedAt` and the real `payload` alongside `id`/`type`/`proof` — not a
/// reconstruction with the payload nulled out. A Data Integrity proof signs
/// the whole document (canonicalised, minus `proof` itself); verifying it
/// against anything else, however "unused" that field looks, recomputes a
/// different hash than the one the signature covers and can never succeed.
/// An earlier version of this helper built a stripped `{id, type, proof}`
/// probe on exactly that mistaken premise — a session that bound a key could
/// then never pass its own binding check, on this refresh version alone.
fn proof_probe<P: serde::Serialize>(doc: &TrustTask<P>) -> TrustTask<Value> {
    let value = serde_json::to_value(doc).expect("TrustTask serialises");
    serde_json::from_value(value).expect("TrustTask<Value> re-parses from its own serialisation")
}

#[allow(clippy::result_large_err)]
async fn refresh_v2_arm(
    state: &AppState,
    doc: TrustTask<refresh::Payload>,
    parties: &ResolvedParties,
) -> Result<TrustTask<refresh::Response>, ErrorResponse> {
    // Unlike `authenticate` (proof REQUIRED) and unlike `refresh_v1_arm`
    // (which always demands one via `caller`), this arm does not require a
    // verified issuer at all — SPEC declares `proofRequirement: OPTIONAL`,
    // and a session with no bound key legitimately omits `proof` entirely
    // (Conformance item 3, "exactly as in 0.1"). The refresh token itself is
    // the authority (Authorization); a bound session key, checked below
    // against the *session's own record* rather than against this value, is
    // the only additional binding this version adds.
    let signer_did = parties.issuer.clone();
    let refresh_token = doc.payload.refresh_token.to_string();

    // Pre-checks against the *presented* token's session, non-consuming
    // (`get_session_by_refresh` peeks the index; `handle_refresh`'s own
    // atomic claim is what actually spends the token). Both refusals below
    // MUST NOT burn the token on the way to refusing it — SPEC conformance
    // item 3 for the session-key check, and the same principle for the
    // absolute-lifetime check: a producer that retries with the right proof,
    // or that was refused only because it is out of time, must still get the
    // canonical answer, not "token already spent".
    //
    // A session that carries a bound key is required to prove it right here
    // — never by `handle_refresh`'s own signer-matches-session check, which
    // compares against the session's long-term *subject*, not the ephemeral
    // `did:key` a session key proof is signed by (and, for the auth family,
    // never delegated at the transport level — `session_key_may_sign`
    // excludes it). So a session with a bound key passes `None` below: this
    // check is what stands in for it.
    let mut bound_key_verified = false;
    if let Some(session_id) = get_session_by_refresh(&state.sessions_ks, &refresh_token)
        .await
        .map_err(|e| denied(&doc, "refresh/peek", e))?
        && let Some(session) = get_session(&state.sessions_ks, &session_id)
            .await
            .map_err(|e| denied(&doc, "refresh/peek", e))?
    {
        // Carried over from the retired REST `/api/auth/refresh` route,
        // which was the only refresh path to enforce it: this deployment's
        // idle-timeout policy, not vti-common's (its `AuthBackend::idle_timeout`
        // stays `None`, the default). Checked before anything is spent, same
        // reasoning as the session-key-proof check below.
        crate::routes::auth::refuse_if_idle_session(&session, state.config.auth.admin_idle_timeout)
            .map_err(|e| denied(&doc, "refresh/idle", e))?;

        crate::routes::auth::verify_session_bound_proof(&proof_probe(&doc), &session)
            .await
            .map_err(|e| {
                warn!(session_id = %session_id, error = %e, "refresh refused: session-key proof required");
                doc.reject_with(
                    format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                    ErrorPayload::from(refresh::error_codes::SESSION_KEY_PROOF_REQUIRED)
                        .with_message(
                            "a session that bound a key must refresh with that key's proof",
                        ),
                )
            })?;
        bound_key_verified = session.session_pubkey_b58btc.is_some();

        if let Some(meta) = get_auth_proxy_meta(state, &session_id)
            .await
            .map_err(|e| denied(&doc, "refresh/meta", e))?
            && session
                .refresh_expires_at
                .is_some_and(|expires| expires >= meta.absolute_expires_at)
        {
            warn!(session_id = %session_id, "refresh refused: absolute session lifetime reached");
            return Err(doc.reject_with(
                format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                ErrorPayload::from(refresh::error_codes::SESSION_LIFETIME_EXCEEDED).with_message(
                    "the session has reached its absolute lifetime; re-authenticate via \
                         auth/authenticate",
                ),
            ));
        }
    }

    let backend = crate::auth::DidHostingControlAuthBackend::from_state(state)
        .map_err(|e| denied(&doc, "refresh/backend", e))?;

    let resp = handle_refresh(
        &backend,
        RefreshInput {
            refresh_token,
            signer_did: if bound_key_verified { None } else { signer_did },
        },
    )
    .await
    .map_err(|e| denied(&doc, "refresh", e))?;

    // `resp.session.id` is the same session_id throughout the session's
    // life (vti-common preserves it across rotation), so the meta row
    // written at login is still the right one to read and needs no
    // migration here.
    let new_session_id = resp.session.id.clone();
    let mut value = serde_json::to_value(&resp).map_err(|e| denied(&doc, "refresh/response", e))?;
    if let Some(meta) = get_auth_proxy_meta(state, &new_session_id)
        .await
        .map_err(|e| denied(&doc, "refresh/meta", e))?
    {
        // Cap the rotated session's own refresh deadline at the ceiling —
        // conformance item 4 ("MUST NOT set the resulting Session.expiresAt
        // later than Session.absoluteExpiresAt"). The pre-check above has
        // already refused outright once the *current* deadline reached the
        // ceiling, so what remains here is only ever a downward clamp, never
        // a silent zero-or-negative window.
        if let Some(mut session) = get_session(&state.sessions_ks, &new_session_id)
            .await
            .map_err(|e| denied(&doc, "refresh/meta", e))?
            && let Some(refresh_expires_at) = session.refresh_expires_at
            && refresh_expires_at > meta.absolute_expires_at
        {
            session.refresh_expires_at = Some(meta.absolute_expires_at);
            did_hosting_common::server::auth::session::store_session(&state.sessions_ks, &session)
                .await
                .map_err(|e| denied(&doc, "refresh/meta", e))?;
            let now = now_epoch();
            value["tokens"]["refreshExpiresIn"] =
                serde_json::json!(meta.absolute_expires_at.saturating_sub(now));
        }
        value["session"]["absoluteExpiresAt"] =
            Value::String(epoch_to_rfc3339(meta.absolute_expires_at));
        // Preserved unchanged across the refresh — conformance item 6.
        if let Some(actor) = meta.actor {
            value["session"]["actor"] = Value::String(actor);
        }
    }

    let payload: refresh::Response =
        serde_json::from_value(value).map_err(|e| denied(&doc, "refresh/response", e))?;

    Ok(doc.respond_with(format!("urn:uuid:{}", uuid::Uuid::new_v4()), payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests read the spec constants; importing it at module scope
    // would be dead weight in a non-test build.
    use trust_tasks_rs::Payload as PayloadSpec;

    /// `owns` must claim exactly the five request URIs — and in particular not
    /// the `#response` forms, which are documents *we* emit and must never
    /// route back into ourselves.
    #[test]
    fn owns_the_five_request_uris_and_not_their_responses() {
        for uri in [
            <challenge::Payload as PayloadSpec>::TYPE_URI,
            <authenticate_v2::Payload as PayloadSpec>::TYPE_URI,
            <authenticate::Payload as PayloadSpec>::TYPE_URI,
            <refresh_v1::Payload as PayloadSpec>::TYPE_URI,
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

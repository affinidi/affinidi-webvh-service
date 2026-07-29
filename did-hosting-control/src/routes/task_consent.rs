//! RP-initiated wallet consent over DIDComm — the `task-consent` family.
//!
//! The control plane (Relying Party / executor) asks a wallet to consent
//! to a sensitive admin action: it generates a random `challenge`, sends
//! a `task-consent/request/0.1` Trust Task document over DIDComm to the
//! holder DID (authcrypt + forward via the holder's mediator), and parks
//! the REST request on a `oneshot` channel until the wallet authcrypts a
//! signed `task-consent/decision/0.1` back. Correlation is by
//! `challenge`; the inbound decision handler (see
//! [`crate::messaging::handle_consent_decision`]) resolves the wait.
//!
//! This replaced the retired `confirm/{request,response}/0.1` pair
//! (registry supersededBy: `task-consent/*`): a confirm is a
//! task-consent with empty `effects`, `minApprovals: 1`, and the
//! requester's display text carried in the explicitly-untrusted `note`
//! field.
//!
//! ## Wire contract (must match the wallet implementation)
//!
//! - **Request** (RP → wallet): DIDComm message
//!   `type = "https://trusttasks.org/spec/task-consent/request/0.1"`,
//!   `to = [holder_did]`, body = a full Trust Task document whose
//!   payload carries `challenge`, `taskType`, `payloadDigest`,
//!   `effects: []`, `note` (the admin's action text, verbatim),
//!   `minApprovals: 1` and `expiresAt`.
//! - **Decision** (wallet → RP): inbound DIDComm message
//!   `type = "https://trusttasks.org/spec/task-consent/decision/0.1"`,
//!   authcrypt-sender = the holder DID, body = a Trust Task document
//!   with a **required Data Integrity proof** whose payload echoes
//!   `challenge` + `payloadDigest` verbatim and sets
//!   `decision: "approve" | "deny"`.
//!
//! Auth model: the wallet's *decision* carries a mandatory
//! `eddsa-jcs-2022` proof over the holder's key — the proof, not the
//! transport session, is the authorization (per the task-consent spec).
//! The authcrypt envelope additionally binds the sender: a decision is
//! only honoured if its authcrypt sender equals the holder DID the
//! request was sent to AND the proof verifies against that same DID.
//! The *request* leg carries the spec's REQUIRED Data Integrity proof,
//! signed by the control plane's own DID key (`eddsa-jcs-2022`,
//! `proofPurpose: assertionMethod`, `issuer` == the DID of
//! `proof.verificationMethod` == the control DID) — see
//! [`crate::signing`]. The wallet verifies that proof before rendering
//! `note`/`effects`; the authcrypt envelope additionally binds the
//! transport sender to the same DID.

use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::auth::AdminAuth;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::server::{AppState, PendingConfirm};

/// DIDComm listener id the control plane registers (see
/// `server::start_didcomm_service`). Outbound `send_message` calls are
/// scoped to this listener.
const CONTROL_LISTENER_ID: &str = "control";

/// How long the REST request waits for the wallet's decision. Also the
/// window advertised to the wallet as the request's `expiresAt`.
const CONSENT_TIMEOUT: Duration = Duration::from_secs(60);

/// `note` is capped at 500 characters by the `task-consent/request/0.1`
/// payload schema. The executor MAY truncate, but a truncated consent
/// prompt is worse than a rejected request — we validate instead.
const MAX_ACTION_CHARS: usize = 500;

/// Domain-separation tag for [`wire_digest`]: keeps these digests from
/// colliding with any other SHA-256 over a canonical payload elsewhere.
const DIGEST_DOMAIN: &[u8] = b"did-hosting/task-consent/v1\0";

#[derive(Debug, Deserialize)]
pub struct ConsentRequest {
    /// The wallet holder DID to prompt.
    pub holder_did: String,
    /// Human-readable description of the action being consented to.
    /// Carried verbatim in the request's `note` field (explicitly
    /// untrusted requester display text, per the spec).
    pub action: String,
}

#[derive(Debug, Serialize)]
pub struct ConsentResult {
    /// `true` if the user approved, `false` if denied.
    pub approved: bool,
}

/// The salted wire digest the wallet echoes back (`payloadDigest`).
///
/// Per `task-consent/request/0.1`: a digest over the canonical
/// (RFC 8785 JCS) pending-task payload, the task type, and the
/// `challenge` as salt. Type and payload are length-prefixed so the
/// boundary can't be shifted; salted so an unsalted digest over a
/// low-entropy payload isn't a confirmation oracle for anyone who
/// observes it in transit.
pub(crate) fn wire_digest(
    task_type: &str,
    payload: &Value,
    challenge: &str,
) -> Result<String, AppError> {
    let canonical = serde_json_canonicalizer::to_string(payload)
        .map_err(|e| AppError::Internal(format!("payload JCS canonicalization failed: {e}")))?;
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update((task_type.len() as u64).to_be_bytes());
    h.update(task_type.as_bytes());
    h.update((canonical.len() as u64).to_be_bytes());
    h.update(canonical.as_bytes());
    h.update(challenge.as_bytes());
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Build the signed `task-consent/request/0.1` document.
///
/// A full Trust Task document, matching the shape the spec's consumers
/// render. `effects` is empty (no dry-run exists for a prose-described
/// action) and `consequences` says so; the admin's `action` rides
/// verbatim in the explicitly-untrusted `note`. The document carries the
/// spec's REQUIRED Data Integrity proof: `eddsa-jcs-2022`,
/// `proofPurpose: assertionMethod`, signed by `signing_secret` (the
/// control DID's assertion key, so `issuer` equals the DID of
/// `proof.verificationMethod`).
///
/// `pub(crate)` (with [`wire_digest`]) so the round-trip tests in
/// `crate::messaging` mint the request leg through the exact production
/// builder rather than a lookalike.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_signed_request_document(
    control_did: &str,
    signing_secret: &affinidi_tdk::secrets_resolver::secrets::Secret,
    holder_did: &str,
    requester_did: &str,
    action: &str,
    task_type: &str,
    challenge: &str,
    digest: &str,
    issued_at: &str,
    expires_at: &str,
) -> Result<Value, AppError> {
    let request_type = did_hosting_common::did_hosting_tasks::TASK_CONSENT_REQUEST_0_1.as_str();
    let unsigned = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": request_type,
        "issuer": control_did,
        "recipient": holder_did,
        "issuedAt": issued_at,
        "payload": {
            "challenge": challenge,
            "taskType": task_type,
            "payloadDigest": digest,
            // The gated actions are state-changing admin operations; the
            // service has no compiled handler to derive a finer class from.
            "sideEffects": "mutating",
            "exposure": { "discloses": "none", "actsAsSubject": false },
            // No dry-run exists for a prose-described admin action, so
            // effects MUST stay empty and the static fallback text below
            // carries what is knowable per-task rather than per-request.
            "effects": [],
            "consequences": [
                "Approving authorizes the control-plane administrator to proceed \
                 with the one admin action described in the requester's note. The \
                 service cannot compute the action's concrete effects.",
            ],
            "requester": requester_did,
            "note": action,
            "approverSet": "holder",
            "minApprovals": 1,
            "excludeRequester": false,
            "expiresAt": expires_at,
        },
    });
    crate::signing::sign_trust_task_document(unsigned, signing_secret).await
}

/// POST /api/task-consent/request — admin-only.
///
/// Generates a random hex `challenge`, sends a signed
/// `task-consent/request/0.1` document to `holder_did`, then waits (up
/// to 60s) for the wallet's signed `task-consent/decision/0.1`. Returns
/// `{ "approved": bool }`.
pub async fn request(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<ConsentRequest>,
) -> Result<Json<ConsentResult>, AppError> {
    if req.holder_did.is_empty() {
        return Err(AppError::Validation("holder_did must not be empty".into()));
    }
    if req.holder_did.len() > 512 {
        return Err(AppError::Validation(
            "holder_did exceeds maximum length".into(),
        ));
    }
    if req.action.is_empty() {
        return Err(AppError::Validation("action must not be empty".into()));
    }
    if req.action.chars().count() > MAX_ACTION_CHARS {
        return Err(AppError::Validation(format!(
            "action exceeds the {MAX_ACTION_CHARS}-character note limit"
        )));
    }

    // The control DID is the authcrypt sender of the outbound request.
    let control_did = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| {
            AppError::Config("server_did not configured; cannot send consent request".into())
        })?
        .to_string();

    // The DIDComm service must be up to send + receive the round-trip.
    let svc = state
        .didcomm_service
        .get()
        .ok_or_else(|| AppError::Internal("DIDComm service not started".into()))?;

    // The control DID's assertion key — resolved before anything is
    // registered, so a missing key fails the request cleanly.
    let signing_secret = crate::signing::control_assertion_secret(&state, &control_did)?;

    // Fresh 16-byte (128-bit) challenge, hex-encoded — the spec's
    // entropy floor, and the digest salt.
    let challenge = rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    // The pending "task" is the prose-described admin action itself —
    // this service cannot dry-run it, so the payload is the action text
    // and the type is the service-local admin-action identifier. The
    // digest still binds the wallet's decision to exactly this
    // (type, payload, challenge) triple.
    let task_type = did_hosting_common::did_hosting_tasks::TASK_ADMIN_ACTION_1_0.as_str();
    let pending_payload = json!({ "action": req.action });
    let digest = wire_digest(task_type, &pending_payload, &challenge)?;

    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::from_std(CONSENT_TIMEOUT).expect("static"))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let request_type = did_hosting_common::did_hosting_tasks::TASK_CONSENT_REQUEST_0_1.as_str();

    // Build + sign the document before registering the pending entry, so
    // a signing failure leaves nothing behind to clean up.
    let document = build_signed_request_document(
        &control_did,
        &signing_secret,
        &req.holder_did,
        &auth.0.did,
        &req.action,
        task_type,
        &challenge,
        &digest,
        &now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        &expires_at,
    )
    .await?;

    // Register the pending entry *before* sending so a fast wallet
    // decision can never arrive before the correlation slot exists.
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
    {
        let mut pending = state.pending_confirms.lock().await;
        pending.insert(
            challenge.clone(),
            PendingConfirm {
                holder_did: req.holder_did.clone(),
                expected_digest: digest.clone(),
                tx,
            },
        );
    }

    let message = Message::build(
        uuid::Uuid::new_v4().to_string(),
        request_type.to_string(),
        document,
    )
    .from(control_did)
    .to(req.holder_did.clone())
    .created_time(now_epoch())
    .finalize();

    info!(
        holder_did = %req.holder_did,
        challenge = %challenge,
        "sending task-consent request"
    );

    if let Err(e) = svc
        .send_message(CONTROL_LISTENER_ID, message, &req.holder_did)
        .await
    {
        // Drop the pending entry — no decision will ever resolve it.
        state.pending_confirms.lock().await.remove(&challenge);
        return Err(AppError::Internal(format!(
            "failed to send task-consent request: {e}"
        )));
    }

    match tokio::time::timeout(CONSENT_TIMEOUT, rx).await {
        Ok(Ok(approved)) => {
            info!(holder_did = %req.holder_did, approved, "task-consent decision resolved");
            Ok(Json(ConsentResult { approved }))
        }
        Ok(Err(_recv_err)) => {
            // Sender dropped without sending — the pending entry was
            // already removed by the decision handler. Treat as internal.
            state.pending_confirms.lock().await.remove(&challenge);
            Err(AppError::Internal(
                "consent channel closed before a decision arrived".into(),
            ))
        }
        Err(_timed_out) => {
            // Remove the abandoned pending entry on timeout.
            state.pending_confirms.lock().await.remove(&challenge);
            warn!(holder_did = %req.holder_did, "task-consent request timed out");
            Err(AppError::Internal(
                "wallet did not respond within the consent window".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_binds_type_payload_and_challenge() {
        let payload = json!({ "action": "Rotate the registry signing key" });
        let base = wire_digest("https://a.example/t/1.0", &payload, "c1").unwrap();

        // Different task type, payload, or challenge each change the digest.
        assert_ne!(
            base,
            wire_digest("https://a.example/other/1.0", &payload, "c1").unwrap()
        );
        assert_ne!(
            base,
            wire_digest(
                "https://a.example/t/1.0",
                &json!({ "action": "something else" }),
                "c1"
            )
            .unwrap()
        );
        assert_ne!(
            base,
            wire_digest("https://a.example/t/1.0", &payload, "c2").unwrap()
        );

        // Deterministic for identical inputs.
        assert_eq!(
            base,
            wire_digest("https://a.example/t/1.0", &payload, "c1").unwrap()
        );
    }

    /// The outbound request document's proof verifies with the same
    /// machinery the repo uses for inbound decisions
    /// (`TransportBoundVerifier`), and the issuer binding holds:
    /// `issuer` == control DID == the DID of `proof.verificationMethod`.
    #[tokio::test]
    async fn signed_request_document_verifies_and_binds_issuer() {
        use std::sync::Arc;

        use affinidi_data_integrity::DidKeyResolver;
        use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
        use trust_tasks_rs::{ProofVerifier, TrustTask};

        let (control_did, signer) = crate::signing::test_util::did_key_signer(&[11u8; 32]);

        let task_type = did_hosting_common::did_hosting_tasks::TASK_ADMIN_ACTION_1_0.as_str();
        let action = "Rotate the registry signing key";
        let challenge = "00112233445566778899aabbccddeeff";
        let digest = wire_digest(task_type, &json!({ "action": action }), challenge).unwrap();

        let document = build_signed_request_document(
            &control_did,
            &signer,
            "did:web:holder.example",
            "did:web:admin.example",
            action,
            task_type,
            challenge,
            &digest,
            "2026-07-29T00:00:00Z",
            "2026-07-29T00:01:00Z",
        )
        .await
        .expect("build + sign");

        // The proof names the assertion key of the issuer DID.
        assert_eq!(document["issuer"], control_did);
        let vm = document["proof"]["verificationMethod"]
            .as_str()
            .expect("proof carries a verificationMethod");
        assert_eq!(vm.split('#').next().unwrap(), control_did);
        assert_eq!(document["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(document["proof"]["proofPurpose"], "assertionMethod");

        // The proof verifies under the shared verifier (which also
        // enforces the issuer ↔ verificationMethod binding).
        let doc: TrustTask<Value> =
            serde_json::from_value(document.clone()).expect("signed doc parses as a TrustTask");
        TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver))
            .verify(&doc)
            .await
            .expect("request proof verifies");

        // And the signature actually covers the payload: tampering with
        // the rendered note breaks it.
        let mut tampered = doc;
        tampered.payload["note"] = json!("Approve something else entirely");
        TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver))
            .verify(&tampered)
            .await
            .expect_err("tampered note must fail verification");
    }

    #[test]
    fn digest_is_canonical_over_key_order() {
        // JCS canonicalization makes key order irrelevant.
        let a = json!({ "action": "x", "extra": 1 });
        let b = serde_json::from_str::<Value>(r#"{"extra":1,"action":"x"}"#).unwrap();
        assert_eq!(
            wire_digest("https://a.example/t/1.0", &a, "c").unwrap(),
            wire_digest("https://a.example/t/1.0", &b, "c").unwrap()
        );
    }
}

//! [`TransportBoundVerifier`] — a [`ProofVerifier`] that enforces the
//! in-band issuer↔`verificationMethod` binding **only when the document
//! actually asserts an `issuer`**, and otherwise verifies the signature
//! alone.
//!
//! ## Why this exists (read before "simplifying" it)
//!
//! `trust-tasks-proof`'s stock `affinidi::Verifier` (≥ 0.2) hard-rejects
//! any proof-bearing document that has no in-band `issuer`:
//!
//! > "document carries a proof but no in-band issuer to bind it to"
//!
//! That rule assumes the proof signer and the responsible party are the
//! same entity (`issuer == verificationMethod` DID). It is correct for a
//! *self-signed* producer (our wallet path: the holder/principal DID signs
//! with its own key, so `issuer == vm`), but it breaks the **passkey
//! delegation** model:
//!
//! * A passkey can't produce an `eddsa-jcs-2022` Data Integrity proof, so
//!   the browser generates an **ephemeral session keypair** at login and
//!   signs trust-tasks with it. The proof's `verificationMethod` is the
//!   session `did:key`, which is *deliberately not* the user's DID.
//! * The responsible party (the user's real DID, the ACL identity) is
//!   carried by the **transport** — the bearer JWT's `sub`. The HTTPS
//!   route's pre-check (`routes::trust_tasks::dispatch_trust_task`)
//!   cryptographically binds the session key to that JWT
//!   (`proof.verificationMethod == JWT-bound session pubkey`).
//!
//! So for passkey the wire document leaves `issuer` absent: SPEC §4.8.1
//! transport-fill resolves it to the JWT subject, and authorization keys on
//! that. There is **no single `issuer` value** that satisfies the stock
//! verifier (wants the session `did:key`), the framework's
//! `resolve_parties` identity cross-check (wants the JWT subject), and ACL
//! authorization (wants the JWT subject) at once — the session key is a
//! *delegate*, an axis the stock verifier doesn't model.
//!
//! ## The policy: bind when present, signature-only when absent
//!
//! * **`issuer` present** → enforce `vm_DID == issuer` exactly, identical
//!   to the stock verifier. A producer that asserts an identity cannot
//!   spoof it (covers e.g. an authenticated DIDComm sender claiming a
//!   different `issuer` than the key it signed with).
//! * **`issuer` absent** → verify the signature only. The responsible
//!   party is established by the *transport*, not by the proof:
//!     - On HTTPS the bearer pre-check has already pinned the signing key
//!       to the authenticated caller before dispatch.
//!     - On any transport, `resolve_parties` fills `issuer` from the
//!       transport-authenticated sender; if the transport authenticated
//!       *nobody* (e.g. anoncrypt DIDComm), `parties.issuer` is `None` and
//!       every handler rejects with `permission_denied` before acting — so
//!       a free-floating signature can never authorize as anyone.
//!
//! This is exactly the pre-0.2 (`trust-tasks-proof` 0.1.x) behaviour for
//! the issuer-absent case, restored locally and *scoped to absence* so the
//! anti-spoofing guarantee is retained whenever an identity is asserted.
//!
//! **Invariant under test:** an `issuer`-present-but-`vm`-mismatched
//! document MUST still be rejected. See `tests::issuer_present_mismatch_*`.
//! Do not collapse this into an unconditional "skip binding" — that would
//! reopen the spoofing hole on transports with no authenticated sender.

use std::sync::Arc;

use affinidi_data_integrity::{
    DataIntegrityError, SignatureFailure, VerificationMethodResolver, VerifyOptions,
};
use async_trait::async_trait;
use serde::Serialize;
use trust_tasks_rs::{ProofVerifier, TrustTask, VerificationError};

/// A [`ProofVerifier`] that binds the proof to the in-band `issuer` when
/// one is present and verifies the signature alone when it is absent. See
/// the module docs for the security rationale.
pub struct TransportBoundVerifier {
    resolver: Arc<dyn VerificationMethodResolver>,
    options: VerifyOptions,
}

impl TransportBoundVerifier {
    /// Construct a verifier over `resolver`. Pass the same
    /// `CachedDidResolver` the stock `affinidi::Verifier` would have used so
    /// `did:web` / `did:webvh` `verificationMethod` lookups hit the shared
    /// DID cache.
    pub fn with_resolver(resolver: Arc<dyn VerificationMethodResolver>) -> Self {
        Self {
            resolver,
            options: VerifyOptions::default(),
        }
    }

    /// Override the [`VerifyOptions`] (expected proof purpose, domain /
    /// challenge, …). Defaults match `VerifyOptions::default()`.
    pub fn with_options(mut self, options: VerifyOptions) -> Self {
        self.options = options;
        self
    }
}

#[async_trait]
impl ProofVerifier for TransportBoundVerifier {
    async fn verify<P>(&self, doc: &TrustTask<P>) -> Result<(), VerificationError>
    where
        P: Serialize + Send + Sync,
    {
        // ─── 1. Extract the proof.
        let Some(proof) = &doc.proof else {
            return Err(VerificationError::MalformedProof(
                "document carries no proof member".to_string(),
            ));
        };

        // ─── 2. Parse our typed Proof into the Affinidi DataIntegrityProof
        //        via the crate's public helper (members-equivalent, just
        //        different serde casing).
        let proof_value = serde_json::to_value(proof)
            .map_err(|e| VerificationError::MalformedProof(format!("serialise proof: {e}")))?;
        let parsed_proof = trust_tasks_proof::affinidi::parse_data_integrity_proof(&proof_value)?;

        // ─── 3. Serialise the document minus the proof member (W3C Data
        //        Integrity canonicalises over the doc + proof config, not
        //        the embedded proof object).
        let mut doc_value = serde_json::to_value(doc).map_err(|e| {
            VerificationError::Other(format!("serialise TrustTask for verification: {e}"))
        })?;
        if let Some(obj) = doc_value.as_object_mut() {
            obj.remove("proof");
        }

        // ─── 3b. CONDITIONAL issuer↔verificationMethod binding.
        //
        // Enforce the binding ONLY when the document asserts an in-band
        // `issuer`. When absent, the responsible party is established by the
        // transport (see module docs) and the proof is a possession check;
        // skipping the binding here is what the pre-0.2 verifier did. Do not
        // make this unconditional — keep the `Some` arm exactly as strict as
        // the stock verifier.
        if let Some(issuer) = doc_value.get("issuer").and_then(|v| v.as_str()) {
            let vm_did = proof
                .verification_method
                .split('#')
                .next()
                .unwrap_or(&proof.verification_method);
            if vm_did != issuer {
                return Err(VerificationError::IssuerMismatch(format!(
                    "verificationMethod is controlled by {vm_did}, not the document issuer {issuer}"
                )));
            }
        }

        // ─── 4. Verify the signature against the resolved key.
        parsed_proof
            .verify(&doc_value, &*self.resolver, self.options.clone())
            .await
            .map_err(map_error)?;
        Ok(())
    }
}

/// Map [`DataIntegrityError`] into the framework's [`VerificationError`]
/// taxonomy. Mirrors `trust_tasks_proof::affinidi`'s private `map_error`
/// (kept in sync with the pinned crate version) so wire `proof_invalid`
/// diagnostics match the stock verifier's.
fn map_error(err: DataIntegrityError) -> VerificationError {
    match err {
        DataIntegrityError::UnsupportedCryptoSuite { name } => {
            VerificationError::UnsupportedCryptosuite(name)
        }
        DataIntegrityError::KeyTypeMismatch {
            expected,
            actual,
            suite,
        } => VerificationError::IssuerMismatch(format!(
            "key type {actual:?} does not match cryptosuite {suite:?} (expected {expected:?})"
        )),
        DataIntegrityError::InvalidSignature { reason, .. } => match reason {
            SignatureFailure::Malformed | SignatureFailure::Invalid => {
                VerificationError::SignatureInvalid
            }
            _ => VerificationError::SignatureInvalid,
        },
        DataIntegrityError::InvalidPublicKey { reason, .. } => {
            VerificationError::MalformedProof(format!("public key: {reason}"))
        }
        DataIntegrityError::Canonicalization(reason) => {
            VerificationError::Other(format!("canonicalisation: {reason}"))
        }
        DataIntegrityError::MalformedProof(reason) => VerificationError::MalformedProof(reason),
        other => VerificationError::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use affinidi_data_integrity::{DataIntegrityProof, DidKeyResolver, SignOptions};
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::{Value, json};
    use trust_tasks_rs::TrustTask;

    /// A verifier over the local `did:key` resolver (no I/O).
    fn verifier() -> TransportBoundVerifier {
        TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver))
    }

    /// The base envelope body (no `issuer`, no `proof`). Callers add an
    /// `issuer` when exercising the bind-when-present path.
    fn base_body() -> Value {
        json!({
            "id": "urn:uuid:24f1b27f-36d9-49af-9a20-751def9000aa",
            "type": "https://trusttasks.org/spec/acl/grant/0.1",
            "recipient": "did:web:server.example",
            "issuedAt": "2026-06-09T08:51:03Z",
            "payload": { "entry": { "subject": "did:web:alice.example", "role": "owner" } },
        })
    }

    /// Sign `body` (an object with no `proof` member) with a fresh ed25519
    /// `did:key`, returning the proof-bearing `TrustTask<Value>` plus the
    /// signer's bare `did:key` (no fragment). The signing input is the
    /// document's canonical `TrustTask` serialisation minus `proof` —
    /// exactly what [`TransportBoundVerifier::verify`] reconstructs.
    async fn sign(body: Value) -> (TrustTask<Value>, String) {
        // Deterministic seed → reproducible key; any 32 bytes work.
        let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
        let pk_mb = secret.get_public_keymultibase().expect("multibase pubkey");
        let did_key = format!("did:key:{pk_mb}");
        let mut signer = secret.clone();
        signer.id = format!("{did_key}#{pk_mb}");

        // Canonical no-proof form (skip_serializing_if drops absent fields).
        let doc_noproof: TrustTask<Value> =
            serde_json::from_value(body).expect("body parses as TrustTask");
        let signing_value = serde_json::to_value(&doc_noproof).expect("serialise doc");

        let di_proof = DataIntegrityProof::sign(&signing_value, &signer, SignOptions::new())
            .await
            .expect("sign");

        let mut full = signing_value;
        full.as_object_mut().unwrap().insert(
            "proof".to_string(),
            serde_json::to_value(&di_proof).unwrap(),
        );
        let doc: TrustTask<Value> = serde_json::from_value(full).expect("proofed doc parses");
        (doc, did_key)
    }

    /// Passkey path: `issuer` absent → signature-only verification passes.
    /// This is the case the stock `affinidi::Verifier` rejects with
    /// "no in-band issuer to bind it to".
    #[tokio::test]
    async fn issuer_absent_verifies_signature_only() {
        let (doc, _did) = sign(base_body()).await;
        assert!(doc.issuer.is_none(), "test fixture must omit issuer");
        verifier()
            .verify(&doc)
            .await
            .expect("issuer-absent proof verifies");
    }

    /// Wallet path: `issuer` present and equal to the signer's DID → the
    /// binding is enforced and passes.
    #[tokio::test]
    async fn issuer_present_matching_verifies() {
        // We can't know the did:key before generating it, so sign first,
        // then re-sign with the matching issuer in-band.
        let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let did_key = format!("did:key:{pk_mb}");
        let mut body = base_body();
        body.as_object_mut()
            .unwrap()
            .insert("issuer".to_string(), json!(did_key));
        let (doc, signer_did) = sign(body).await;
        assert_eq!(doc.issuer.as_deref(), Some(signer_did.as_str()));
        verifier()
            .verify(&doc)
            .await
            .expect("issuer-matched proof verifies");
    }

    /// GUARD: `issuer` present but NOT the signer's DID → rejected with
    /// `IssuerMismatch`, *before* the signature is even checked. This is the
    /// anti-spoofing invariant that must never regress into an
    /// unconditional skip.
    #[tokio::test]
    async fn issuer_present_mismatch_rejected() {
        let mut body = base_body();
        body.as_object_mut()
            .unwrap()
            .insert("issuer".to_string(), json!("did:web:evil.example"));
        let (doc, signer_did) = sign(body).await;
        assert_ne!(signer_did, "did:web:evil.example");
        let err = verifier().verify(&doc).await.expect_err("must reject");
        assert!(
            matches!(err, VerificationError::IssuerMismatch(_)),
            "expected IssuerMismatch, got {err:?}"
        );
    }

    /// The signature-only path still actually verifies the signature: a
    /// tampered payload (after signing) is rejected, not waved through.
    #[tokio::test]
    async fn issuer_absent_tampered_payload_rejected() {
        let (mut doc, _did) = sign(base_body()).await;
        // Mutate a signed field; the proof no longer covers the document.
        doc.payload = json!({ "entry": { "subject": "did:web:mallory.example", "role": "admin" } });
        let err = verifier()
            .verify(&doc)
            .await
            .expect_err("must reject tampered doc");
        assert!(
            matches!(err, VerificationError::SignatureInvalid),
            "expected SignatureInvalid, got {err:?}"
        );
    }

    /// A document with no `proof` member is malformed for a verifier.
    #[tokio::test]
    async fn missing_proof_rejected() {
        let doc: TrustTask<Value> = serde_json::from_value(base_body()).expect("body parses");
        let err = verifier().verify(&doc).await.expect_err("must reject");
        assert!(
            matches!(err, VerificationError::MalformedProof(_)),
            "expected MalformedProof, got {err:?}"
        );
    }
}

//! [`TransportBoundVerifier`] — a [`ProofVerifier`] that binds every proof to
//! the document's in-band `issuer`.
//!
//! ## The rule
//!
//! A proof-bearing document is accepted only when:
//!
//! 1. it carries an in-band `issuer` — **always**; a document that names no
//!    issuer is refused, whatever transport carried it; and
//! 2. the proof's `verificationMethod` is controlled by that issuer
//!    (`vm_DID == issuer`, exact string match per SPEC.md §4.8), **or** the
//!    verifier was built for one bearer session with
//!    [`TransportBoundVerifier::with_session_delegate`] and the proof is signed
//!    by exactly that session's key on behalf of exactly that session's
//!    principal; and
//! 3. the signature verifies over the document.
//!
//! The issuer is therefore always something the proof establishes, never
//! something the transport asserted. Callers authorise on
//! `ResolvedParties::issuer`, and with this verifier in front of them that value
//! is the proven signer on every binding.
//!
//! ## Why the issuer is required, not merely checked when present
//!
//! An issuer-less document verifies as a bare possession check: *someone* holds
//! the key named by `verificationMethod`. The framework then fills the issuer
//! from the transport's reported sender (SPEC §4.8.1) and every handler
//! authorises on that. So the only thing binding the signer to the identity the
//! handler acts for is the transport's report of who sent the message — and a
//! transport's report is not a proof. Any signer could pair its own valid proof
//! with somebody else's name on the envelope. Requiring the issuer in-band, and
//! binding it to the key, makes the document itself say who it is from.
//!
//! ## The passkey session delegate
//!
//! A passkey can't produce an `eddsa-jcs-2022` proof, so the Web UI signs with
//! an ephemeral session key generated at login. That key's `did:key` is
//! deliberately not the user's DID; the bearer JWT's `sub` is, and the login
//! flow binds the session public key into the JWT. For that one case the HTTPS
//! route builds a per-request verifier with
//! [`TransportBoundVerifier::with_session_delegate`]`(jwt.sub, session_vm)`, and
//! a document is then accepted when its `issuer` is the JWT subject and its
//! proof is signed by exactly the JWT-bound session key. The delegate is never
//! configured on a shared verifier, so no other transport can use it.
//!
//! **Invariants under test:** an issuer-less document is rejected; an
//! issuer-present-but-`vm`-mismatched document is rejected; a delegate accepts
//! only its own key for only its own principal. See `tests`.

use std::sync::Arc;

use affinidi_data_integrity::{
    DataIntegrityError, SignatureFailure, VerificationMethodResolver, VerifyOptions,
};
use async_trait::async_trait;
use serde::Serialize;
use trust_tasks_rs::{ProofVerifier, TrustTask, VerificationError};

/// One bearer session's signing delegate: the only key, and the only
/// principal, a delegated proof may name.
#[derive(Clone, Debug)]
struct SessionDelegate {
    principal: String,
    verification_method: String,
}

/// A [`ProofVerifier`] that requires an in-band `issuer` and binds the proof's
/// `verificationMethod` to it. See the module docs for the security rationale.
#[derive(Clone)]
pub struct TransportBoundVerifier {
    resolver: Arc<dyn VerificationMethodResolver>,
    options: VerifyOptions,
    delegate: Option<SessionDelegate>,
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
            delegate: None,
        }
    }

    /// Construct a verifier over a configured DID cache client.
    pub fn with_did_cache(client: affinidi_did_resolver_cache_sdk::DIDCacheClient) -> Self {
        Self::with_resolver(Arc::new(
            trust_tasks_proof::affinidi::CachedDidResolver::new(Arc::new(client)),
        ))
    }

    /// Override the [`VerifyOptions`] (expected proof purpose, domain /
    /// challenge, …). Defaults match `VerifyOptions::default()`.
    pub fn with_options(mut self, options: VerifyOptions) -> Self {
        self.options = options;
        self
    }

    /// Additionally accept documents whose `issuer` is `principal` and whose
    /// proof is signed by exactly `verification_method` — a bearer session's
    /// JWT-bound signing key acting for the JWT subject.
    ///
    /// Build this per request, from an already-verified bearer token, and never
    /// on a verifier shared across callers.
    pub fn with_session_delegate(
        mut self,
        principal: impl Into<String>,
        verification_method: impl Into<String>,
    ) -> Self {
        self.delegate = Some(SessionDelegate {
            principal: principal.into(),
            verification_method: verification_method.into(),
        });
        self
    }
}

/// The DID that controls a verification method URL (the part before `#`).
pub fn controller_did(verification_method: &str) -> &str {
    verification_method
        .split('#')
        .next()
        .unwrap_or(verification_method)
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

        // ─── 3b. issuer↔verificationMethod binding — unconditional.
        let Some(issuer) = doc_value.get("issuer").and_then(|v| v.as_str()) else {
            return Err(VerificationError::IssuerMismatch(
                "document carries a proof but no in-band issuer to bind it to".to_string(),
            ));
        };
        let vm = proof.verification_method.as_str();
        let self_signed = controller_did(vm) == issuer;
        let delegated = self
            .delegate
            .as_ref()
            .is_some_and(|d| d.verification_method == vm && d.principal == issuer);
        if !self_signed && !delegated {
            return Err(VerificationError::IssuerMismatch(format!(
                "verificationMethod is controlled by {}, not the document issuer {issuer}",
                controller_did(vm)
            )));
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

    /// GUARD: `issuer` absent → rejected, even though the signature itself is
    /// valid. A proof that names no issuer must never verify as a bare
    /// possession check.
    #[tokio::test]
    async fn issuer_absent_rejected() {
        let (doc, _did) = sign(base_body()).await;
        assert!(doc.issuer.is_none(), "test fixture must omit issuer");
        let err = verifier().verify(&doc).await.expect_err("must reject");
        assert!(
            matches!(err, VerificationError::IssuerMismatch(_)),
            "expected IssuerMismatch, got {err:?}"
        );
    }

    /// Passkey session delegate: `issuer` is the principal, the proof is signed
    /// by the delegate key → accepted.
    #[tokio::test]
    async fn session_delegate_accepts_its_key_for_its_principal() {
        let mut body = base_body();
        body.as_object_mut()
            .unwrap()
            .insert("issuer".to_string(), json!("did:web:alice.example"));
        let (doc, signer_did) = sign(body).await;
        let vm = doc.proof.as_ref().unwrap().verification_method.clone();
        assert!(vm.starts_with(&signer_did));
        verifier()
            .with_session_delegate("did:web:alice.example", vm)
            .verify(&doc)
            .await
            .expect("delegated proof verifies");
    }

    /// GUARD: a delegate is scoped to one principal — the same key acting for a
    /// different issuer is refused.
    #[tokio::test]
    async fn session_delegate_rejects_other_principal() {
        let mut body = base_body();
        body.as_object_mut()
            .unwrap()
            .insert("issuer".to_string(), json!("did:web:admin.example"));
        let (doc, _) = sign(body).await;
        let vm = doc.proof.as_ref().unwrap().verification_method.clone();
        let err = verifier()
            .with_session_delegate("did:web:alice.example", vm)
            .verify(&doc)
            .await
            .expect_err("must reject");
        assert!(matches!(err, VerificationError::IssuerMismatch(_)));
    }

    /// GUARD: a delegate is scoped to one key — a different key acting for the
    /// principal is refused.
    #[tokio::test]
    async fn session_delegate_rejects_other_key() {
        let mut body = base_body();
        body.as_object_mut()
            .unwrap()
            .insert("issuer".to_string(), json!("did:web:alice.example"));
        let (doc, _) = sign(body).await;
        let err = verifier()
            .with_session_delegate("did:web:alice.example", "did:key:z6MkOther#z6MkOther")
            .verify(&doc)
            .await
            .expect_err("must reject");
        assert!(matches!(err, VerificationError::IssuerMismatch(_)));
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

    /// The signature is actually verified: a tampered payload (after signing)
    /// is rejected, not waved through.
    #[tokio::test]
    async fn tampered_payload_rejected() {
        let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let mut body = base_body();
        body.as_object_mut()
            .unwrap()
            .insert("issuer".to_string(), json!(format!("did:key:{pk_mb}")));
        let (mut doc, _did) = sign(body).await;
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

    // ─── Cross-language interop with the JS wallet ───
    //
    // `stepup-approval-fixture.json` is generated by the browser plugin's
    // actual signer (`@openvtc/pnm-core` `buildStepUpApproval`, eddsa-jcs-2022)
    // — see the PR that converged step-up to holder-self-signs. These tests are
    // the load-bearing guarantee that the JS wallet and this Rust verifier
    // canonicalize + hash byte-identically: if they ever diverge,
    // holder-self-signed step-up silently stops verifying. Regenerate the
    // fixture from the plugin if the wire shape changes.
    const STEP_UP_FIXTURE: &str = include_str!("testdata/stepup-approval-fixture.json");

    /// A wallet-signed `auth/step-up/approve-response/0.2` (both the approved
    /// and denied variants) verifies against `TransportBoundVerifier` — the
    /// same verifier the `/auth/step-up/vta/finish` handler uses.
    #[tokio::test]
    async fn wallet_signed_step_up_approval_verifies() {
        let fixture: Value = serde_json::from_str(STEP_UP_FIXTURE).expect("fixture parses");

        let approved: TrustTask<Value> =
            serde_json::from_value(fixture["approved"].clone()).expect("approved doc parses");
        verifier()
            .verify(&approved)
            .await
            .expect("wallet-signed approved response verifies");

        let denied: TrustTask<Value> =
            serde_json::from_value(fixture["denied"].clone()).expect("denied doc parses");
        verifier()
            .verify(&denied)
            .await
            .expect("wallet-signed denied response verifies");
    }

    /// Flipping the wallet-signed `decision` after signing breaks the proof —
    /// the fixture proves the signature actually covers the payload, not just
    /// that the shapes line up.
    #[tokio::test]
    async fn wallet_signed_step_up_tampered_decision_rejected() {
        let fixture: Value = serde_json::from_str(STEP_UP_FIXTURE).expect("fixture parses");
        let mut doc: TrustTask<Value> =
            serde_json::from_value(fixture["approved"].clone()).expect("approved doc parses");
        doc.payload
            .as_object_mut()
            .expect("payload is an object")
            .insert("decision".to_string(), json!("denied"));

        let err = verifier()
            .verify(&doc)
            .await
            .expect_err("tampered decision must be rejected");
        // The issuer is untouched, so this is a signature failure, not an
        // issuer-binding rejection.
        assert!(
            !matches!(err, VerificationError::IssuerMismatch(_)),
            "expected a signature failure, got {err:?}"
        );
    }
}

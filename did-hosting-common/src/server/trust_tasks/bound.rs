//! Sender-bound Trust Task documents: the one rule every privileged inbound
//! document is held to, and the signing half that produces documents meeting
//! it.
//!
//! ## The rule
//!
//! A privileged document — anything that changes state or discloses more than
//! public data — is acted on only when **the document itself** proves who sent
//! it. [`verify_sender_bound`] requires, in this order:
//!
//! 1. a `proof` member;
//! 2. an in-band `issuer`, and, when the caller knows who the peer must be,
//!    `issuer == expected` exactly;
//! 3. when the transport reported a sender, that it names the same DID as the
//!    issuer (a mismatch is refused rather than resolved in either's favour);
//! 4. an in-band `recipient` equal to this service's DID, so a document signed
//!    for another service cannot be replayed here;
//! 5. an `issuedAt` inside the freshness window, and no passed `expiresAt`;
//! 6. a proof with `proofPurpose: authentication`, whose `verificationMethod`
//!    is controlled by the issuer and listed under its `authentication`
//!    relationship, and whose signature verifies
//!    ([`TransportBoundVerifier::verify_operational`]). These are a service's
//!    own operational messages, not attestations; `assertionMethod` is
//!    reserved for credentials and is refused.
//!
//! The returned DID is the **proven** signer. Callers authorise on it and key
//! their replay cache on `(it, doc.id)` — never on the transport's report of
//! who sent the message, which is at most a routing hint.
//!
//! ## Why the transport's sender is not enough
//!
//! A messaging transport reports a sender, and the service used to authorise on
//! that report alone. But a report is only as strong as the unpacking code that
//! produced it, and that code lives in another crate with its own release
//! cycle. A signature over the document does not depend on any of it: it is
//! checked here, against keys resolved from the issuer's own DID document.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask, VerificationError};

use super::verifier::{TransportBoundVerifier, controller_did};
use crate::server::didcomm_unpack::{FRESHNESS_WINDOW_SECS, FUTURE_SKEW_SECS};

/// Why a document failed [`verify_sender_bound`].
#[derive(Debug, thiserror::Error)]
pub enum BoundError {
    #[error("document carries no proof; a signed document is required")]
    MissingProof,
    #[error("document carries no in-band issuer")]
    MissingIssuer,
    #[error("document issuer {issuer} is not the expected peer {expected}")]
    UnexpectedIssuer { issuer: String, expected: String },
    #[error("document issuer {issuer} does not match the transport sender {sender}")]
    SenderMismatch { issuer: String, sender: String },
    #[error("document carries no in-band recipient")]
    MissingRecipient,
    #[error("document is addressed to {recipient}, not {expected}")]
    WrongRecipient { recipient: String, expected: String },
    #[error("document carries no issuedAt")]
    MissingIssuedAt,
    #[error("document issuedAt is outside the freshness window")]
    Stale,
    #[error("document expired at {0}")]
    Expired(DateTime<Utc>),
    #[error("proof verification failed: {0}")]
    Proof(#[from] VerificationError),
}

impl BoundError {
    /// Whether the failure may clear on its own — the signer's DID could not be
    /// resolved, or its status read — so the same document is worth re-sending.
    pub fn is_transient(&self) -> bool {
        matches!(self, BoundError::Proof(e) if super::verifier::is_unreachable(e))
    }

    /// The framework rejection this failure is reported as on the wire. A
    /// transient failure ([`Self::is_transient`]) is `unavailable` (retryable);
    /// every other one is final.
    pub fn reject_reason(&self) -> RejectReason {
        if self.is_transient() {
            return RejectReason::Unavailable { retry_after: None };
        }
        match self {
            BoundError::MissingProof => RejectReason::ProofRequired,
            BoundError::MissingIssuer
            | BoundError::MissingRecipient
            | BoundError::MissingIssuedAt => RejectReason::MalformedRequest {
                reason: self.to_string(),
            },
            BoundError::WrongRecipient {
                recipient,
                expected,
            } => RejectReason::WrongRecipient {
                in_band: recipient.clone(),
                expected: expected.clone(),
            },
            BoundError::Expired(at) => RejectReason::Expired { expires_at: *at },
            BoundError::Stale => RejectReason::MalformedRequest {
                reason: self.to_string(),
            },
            BoundError::UnexpectedIssuer { .. } | BoundError::SenderMismatch { .. } => {
                RejectReason::PermissionDenied {
                    reason: self.to_string(),
                }
            }
            BoundError::Proof(e) => RejectReason::ProofInvalid {
                reason: e.to_string(),
            },
        }
    }
}

/// Verify that `doc` is signed by its issuer, addressed to `my_vid`, fresh, and
/// — when `expected_issuer` is given — issued by exactly that DID. Returns the
/// proven issuer. See the module docs for the full rule.
///
/// `transport_sender` is whatever the carrying transport reported (DIDComm
/// sender, TSP sender VID, bearer-token subject). It is never trusted on its
/// own; it is only required to agree with the proof.
pub async fn verify_sender_bound<P>(
    doc: &TrustTask<P>,
    expected_issuer: Option<&str>,
    transport_sender: Option<&str>,
    my_vid: &str,
    verifier: &TransportBoundVerifier,
) -> Result<String, BoundError>
where
    P: Serialize + Send + Sync,
{
    verify_sender_bound_at(
        doc,
        expected_issuer,
        transport_sender,
        my_vid,
        verifier,
        Utc::now(),
    )
    .await
}

/// [`verify_sender_bound`] against an explicit clock, for tests.
pub async fn verify_sender_bound_at<P>(
    doc: &TrustTask<P>,
    expected_issuer: Option<&str>,
    transport_sender: Option<&str>,
    my_vid: &str,
    verifier: &TransportBoundVerifier,
    now: DateTime<Utc>,
) -> Result<String, BoundError>
where
    P: Serialize + Send + Sync,
{
    if doc.proof.is_none() {
        return Err(BoundError::MissingProof);
    }
    let issuer = doc.issuer.as_deref().ok_or(BoundError::MissingIssuer)?;
    if let Some(expected) = expected_issuer
        && issuer != expected
    {
        return Err(BoundError::UnexpectedIssuer {
            issuer: issuer.to_string(),
            expected: expected.to_string(),
        });
    }
    if let Some(sender) = transport_sender
        && controller_did(sender) != issuer
    {
        return Err(BoundError::SenderMismatch {
            issuer: issuer.to_string(),
            sender: sender.to_string(),
        });
    }
    let recipient = doc
        .recipient
        .as_deref()
        .ok_or(BoundError::MissingRecipient)?;
    if recipient != my_vid {
        return Err(BoundError::WrongRecipient {
            recipient: recipient.to_string(),
            expected: my_vid.to_string(),
        });
    }
    let issued_at = doc.issued_at.ok_or(BoundError::MissingIssuedAt)?;
    if issued_at < now - Duration::seconds(FRESHNESS_WINDOW_SECS as i64)
        || issued_at > now + Duration::seconds(FUTURE_SKEW_SECS as i64)
    {
        return Err(BoundError::Stale);
    }
    if let Some(expires_at) = doc.expires_at
        && expires_at <= now
    {
        return Err(BoundError::Expired(expires_at));
    }
    verifier.verify_operational(doc).await?;
    Ok(issuer.to_string())
}

/// Sign an unsigned document (no `proof`) with `signer`, returning it with the
/// proof attached. `eddsa-jcs-2022`, `proofPurpose: authentication` — the
/// operational purpose [`verify_sender_bound`] requires. `signer` must be one
/// of the issuer's `authentication` keys.
///
/// The document's `issuer` must be the DID of `signer`'s verification method;
/// the signing call refuses otherwise, so a document that could never verify
/// is never produced.
pub async fn sign_document(
    doc: &TrustTask<Value>,
    signer: &affinidi_tdk::secrets_resolver::secrets::Secret,
) -> Result<TrustTask<Value>, SignError> {
    use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};

    let unsigned = serde_json::to_value(doc).map_err(|e| SignError(e.to_string()))?;
    let signed = sign_trust_task(
        &unsigned,
        signer,
        SignOptions::new()
            .with_proof_purpose(super::verifier::OPERATIONAL_PROOF_PURPOSE)
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| SignError(e.to_string()))?;
    serde_json::from_value(signed).map_err(|e| SignError(e.to_string()))
}

/// A document could not be signed.
#[derive(Debug, thiserror::Error)]
#[error("sign trust task document: {0}")]
pub struct SignError(pub String);

/// This service's current operational (`authentication`) key as a signing secret, named by the kid
/// its published DID document lists.
///
/// `expected_did` is the configured service DID; a current identity
/// generation for a different DID means config and identity store disagree,
/// and a proof signed with either would fail the issuer binding at the peer.
pub fn identity_signing_secret(
    identity: &crate::server::identity::ServiceIdentity,
    expected_did: &str,
) -> Result<affinidi_tdk::secrets_resolver::secrets::Secret, SignError> {
    let generation = identity.current();
    if generation.did != expected_did {
        return Err(SignError(format!(
            "current identity generation DID {} does not match the configured service DID \
             {expected_did}",
            generation.did
        )));
    }
    identity
        .secrets()
        .into_iter()
        .find(|s| s.id == generation.signing_kid)
        .ok_or_else(|| {
            SignError(format!(
                "no signing secret loaded for {}",
                generation.signing_kid
            ))
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use affinidi_data_integrity::DidKeyResolver;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use serde_json::json;

    use super::*;
    use crate::server::trust_tasks::send::build_request;

    const TYPE: &str = "https://trusttasks.org/spec/webvh/sync/delete/0.1";
    const ME: &str = "did:example:edge";

    fn signer(seed: u8) -> (String, Secret) {
        let secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
        let pk = secret.get_public_keymultibase().unwrap();
        let did = format!("did:key:{pk}");
        let mut s = secret;
        s.id = format!("{did}#{pk}");
        (did, s)
    }

    fn verifier() -> TransportBoundVerifier {
        TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver))
    }

    async fn signed_by(seed: u8, to: &str) -> (String, TrustTask<Value>) {
        let (did, secret) = signer(seed);
        let doc = build_request(TYPE, &did, to, json!({ "mnemonic": "alice" })).unwrap();
        (did.clone(), sign_document(&doc, &secret).await.unwrap())
    }

    #[tokio::test]
    async fn a_signed_fresh_addressed_document_verifies_to_its_issuer() {
        let (did, doc) = signed_by(1, ME).await;
        let proven = verify_sender_bound(&doc, Some(&did), Some(&did), ME, &verifier())
            .await
            .expect("verifies");
        assert_eq!(proven, did);
    }

    #[tokio::test]
    async fn an_unsigned_document_is_refused() {
        let (did, _) = signer(1);
        let doc = build_request(TYPE, &did, ME, json!({})).unwrap();
        let err = verify_sender_bound(&doc, None, Some(&did), ME, &verifier())
            .await
            .unwrap_err();
        assert!(matches!(err, BoundError::MissingProof));
    }

    /// The case sender-only authorisation could not catch: the transport says
    /// the message came from the expected peer, and the document is validly
    /// signed — by somebody else.
    #[tokio::test]
    async fn a_valid_proof_from_another_signer_is_refused_whatever_the_transport_says() {
        let (control, _) = signer(9);
        let (_attacker, doc) = signed_by(2, ME).await;
        let err = verify_sender_bound(&doc, Some(&control), Some(&control), ME, &verifier())
            .await
            .unwrap_err();
        assert!(
            matches!(err, BoundError::UnexpectedIssuer { .. }),
            "{err:?}"
        );
    }

    /// The same attack without an expected peer (DID ops, where the ACL decides
    /// afterwards): the proof's issuer and the transport's sender disagree.
    #[tokio::test]
    async fn an_issuer_that_disagrees_with_the_transport_sender_is_refused() {
        let (admin, _) = signer(9);
        let (_attacker, doc) = signed_by(2, ME).await;
        let err = verify_sender_bound(&doc, None, Some(&admin), ME, &verifier())
            .await
            .unwrap_err();
        assert!(matches!(err, BoundError::SenderMismatch { .. }), "{err:?}");
    }

    /// Claiming the victim's DID as `issuer` while signing with one's own key.
    #[tokio::test]
    async fn an_issuer_the_proof_does_not_bind_to_is_refused() {
        let (victim, _) = signer(9);
        let (_attacker, secret) = signer(2);
        let mut doc = build_request(TYPE, &victim, ME, json!({})).unwrap();
        // `sign_trust_task` refuses to sign a mismatched issuer, so sign under
        // the attacker's DID and swap the issuer afterwards.
        doc.issuer = Some(secret.id.split('#').next().unwrap().to_string());
        let mut signed = sign_document(&doc, &secret).await.unwrap();
        signed.issuer = Some(victim.clone());
        let err = verify_sender_bound(&signed, Some(&victim), Some(&victim), ME, &verifier())
            .await
            .unwrap_err();
        assert!(
            matches!(err, BoundError::Proof(VerificationError::IssuerMismatch(_))),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_document_for_another_recipient_is_refused() {
        let (did, doc) = signed_by(1, "did:example:other-edge").await;
        let err = verify_sender_bound(&doc, Some(&did), None, ME, &verifier())
            .await
            .unwrap_err();
        assert!(matches!(err, BoundError::WrongRecipient { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn a_stale_or_future_document_is_refused() {
        let (did, doc) = signed_by(1, ME).await;
        let issued = doc.issued_at.unwrap();
        for now in [
            issued + Duration::seconds(FRESHNESS_WINDOW_SECS as i64 + 1),
            issued - Duration::seconds(FUTURE_SKEW_SECS as i64 + 1),
        ] {
            let err = verify_sender_bound_at(&doc, Some(&did), None, ME, &verifier(), now)
                .await
                .unwrap_err();
            assert!(matches!(err, BoundError::Stale), "{err:?}");
        }
    }

    #[tokio::test]
    async fn a_tampered_payload_is_refused() {
        let (did, mut doc) = signed_by(1, ME).await;
        doc.payload = json!({ "mnemonic": "bob" });
        let err = verify_sender_bound(&doc, Some(&did), None, ME, &verifier())
            .await
            .unwrap_err();
        assert!(matches!(err, BoundError::Proof(_)), "{err:?}");
    }

    /// An attestation-purpose proof is not an operational one: refused even
    /// though it is validly signed by the right DID.
    #[tokio::test]
    async fn an_assertion_method_proof_is_refused() {
        use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
        let (did, secret) = signer(1);
        let doc = build_request(TYPE, &did, ME, json!({})).unwrap();
        let signed = sign_trust_task(
            &serde_json::to_value(&doc).unwrap(),
            &secret,
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .unwrap();
        let doc: TrustTask<Value> = serde_json::from_value(signed).unwrap();
        let err = verify_sender_bound(&doc, Some(&did), Some(&did), ME, &verifier())
            .await
            .unwrap_err();
        assert!(
            matches!(err, BoundError::Proof(VerificationError::MalformedProof(ref m)) if m.contains("authentication")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn documents_are_signed_for_authentication() {
        let (_, doc) = signed_by(1, ME).await;
        assert_eq!(doc.proof.unwrap().proof_purpose, "authentication");
    }

    /// A signer that cannot be resolved is a retryable condition, not a bad
    /// proof: a DID with no reachable log fails with an error that says so.
    #[tokio::test]
    async fn an_unresolvable_signer_is_reported_as_retryable() {
        use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
        // `.invalid` never resolves (RFC 6761), and the default host policy
        // refuses it before any request is made.
        let did = "did:web:control.invalid";
        let (_, secret) = signer(3);
        let mut doc = build_request(TYPE, did, ME, json!({})).unwrap();
        doc.issuer = Some(secret.id.split('#').next().unwrap().to_string());
        let mut signed = sign_document(&doc, &secret).await.unwrap();
        signed.issuer = Some(did.to_string());
        let mut proof = signed.proof.take().unwrap();
        proof.verification_method = format!("{did}#key-1");
        signed.proof = Some(proof);
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let err = verify_sender_bound(
            &signed,
            Some(did),
            None,
            ME,
            &TransportBoundVerifier::with_did_cache(client),
        )
        .await
        .unwrap_err();
        assert!(err.is_transient(), "{err:?}");
        assert!(err.to_string().contains("control.invalid"), "{err}");
        assert!(matches!(
            err.reject_reason(),
            RejectReason::Unavailable { .. }
        ));
    }

    #[test]
    fn missing_proof_is_reported_as_proof_required() {
        assert_eq!(
            BoundError::MissingProof.reject_reason(),
            RejectReason::ProofRequired
        );
    }
}

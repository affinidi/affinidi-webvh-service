//! Tests for [`super`].

use super::*;

use affinidi_data_integrity::{
    DataIntegrityProof, DidKeyResolver, SignOptions, VerificationMethodResolver,
};
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
        "type": "https://trusttasks.org/spec/acl/grant/0.2",
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
    sign_with(body, SignOptions::new()).await
}

/// [`sign`] with explicit options (for a proof purpose).
async fn sign_with(body: Value, options: SignOptions) -> (TrustTask<Value>, String) {
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

    let di_proof = DataIntegrityProof::sign(&signing_value, &signer, options)
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
    // A session key signs ordinary requests, so `authentication`.
    let (doc, signer_did) = sign_with(
        body,
        SignOptions::new().with_proof_purpose(OPERATIONAL_PROOF_PURPOSE),
    )
    .await;
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

/// GUARD (`auth/authenticate/0.3` Conformance item 13): a session key never
/// signs an approval, even for its own principal.
///
/// The first assertion shows why the refusal has to be explicit. A
/// `did:key` document lists its key under `assertionMethod`, so the same
/// key signing as *itself* is a valid approval. Only the delegation is
/// refused: acting for the principal, it is not the principal's own
/// `assertionMethod` key.
#[tokio::test]
async fn session_delegate_never_signs_an_approval() {
    let approval = SignOptions::new().with_proof_purpose(APPROVAL_PROOF_PURPOSE);

    let (as_itself, signer_did) = sign_with(base_body(), approval.clone()).await;
    let mut as_itself_body = serde_json::to_value(&as_itself).unwrap();
    as_itself_body["issuer"] = json!(signer_did);
    as_itself_body.as_object_mut().unwrap().remove("proof");
    let (as_itself, _) = sign_with(as_itself_body, approval.clone()).await;
    verifier()
        .verify_approval(&as_itself)
        .await
        .expect("a did:key's own assertionMethod proof verifies");

    let mut body = base_body();
    body["issuer"] = json!("did:web:alice.example");
    let (doc, _) = sign_with(body, approval).await;
    let vm = doc.proof.as_ref().unwrap().verification_method.clone();
    let delegated = verifier().with_session_delegate("did:web:alice.example", vm);

    let err = delegated
        .verify_approval(&doc)
        .await
        .expect_err("a delegate must not approve");
    assert!(
        matches!(err, VerificationError::IssuerMismatch(_)),
        "{err:?}"
    );
    let err = delegated
        .verify(&doc)
        .await
        .expect_err("nor pass an assertionMethod proof through the generic check");
    assert!(
        matches!(err, VerificationError::IssuerMismatch(_)),
        "{err:?}"
    );
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

// ─── Stale cached DID document ───

/// A resolver that reports the key missing until the refresher has
/// "re-resolved" — a peer that rotated keys since its document was cached.
struct RotatedResolver {
    refreshed: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl ProofPurposeResolver for RotatedResolver {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        if self.refreshed.load(std::sync::atomic::Ordering::SeqCst) {
            DidKeyResolver.resolve_vm_for_purpose(vm, purpose).await
        } else {
            Err(DataIntegrityError::Resolver(format!(
                "{vm} not in cached document"
            )))
        }
    }
}

struct FlagRefresher {
    refreshed: Arc<std::sync::atomic::AtomicBool>,
    calls: std::sync::atomic::AtomicUsize,
    allow: bool,
}

#[async_trait]
impl StaleKeyRefresh for FlagRefresher {
    async fn refresh(&self, _did: &str) -> bool {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.allow {
            self.refreshed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.allow
    }
}

fn rotated_verifier(allow: bool) -> (TransportBoundVerifier, Arc<FlagRefresher>) {
    let refreshed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let refresher = Arc::new(FlagRefresher {
        refreshed: refreshed.clone(),
        calls: Default::default(),
        allow,
    });
    let mut v = TransportBoundVerifier::with_resolver(Arc::new(RotatedResolver { refreshed }));
    v.refresher = Some(refresher.clone());
    (v, refresher)
}

async fn self_issued_doc() -> TrustTask<Value> {
    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let mut body = base_body();
    body.as_object_mut()
        .unwrap()
        .insert("issuer".to_string(), json!(format!("did:key:{pk_mb}")));
    sign(body).await.0
}

/// A proof that fails against the cached document verifies after one fresh
/// resolution — a rotation does not open a rejection window.
#[tokio::test]
async fn a_stale_cached_document_is_re_resolved_once_before_refusing() {
    let (v, refresher) = rotated_verifier(true);
    v.verify(&self_issued_doc().await)
        .await
        .expect("verifies after refresh");
    assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// When a refresh is not allowed (rate limit), the failure stands.
#[tokio::test]
async fn without_a_refresh_the_stale_failure_stands() {
    let (v, refresher) = rotated_verifier(false);
    assert!(v.verify(&self_issued_doc().await).await.is_err());
    assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A reply to this service's own send has a forced-refresh allowance of
/// its own: with the inbound allowance spent, a reply from a peer that
/// has just rotated still gets its one re-resolution, and the inbound
/// path still gets none.
#[tokio::test]
async fn replies_have_their_own_forced_refresh_allowance() {
    let refreshed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let inbound = Arc::new(FlagRefresher {
        refreshed: refreshed.clone(),
        calls: Default::default(),
        allow: false,
    });
    let reply = Arc::new(FlagRefresher {
        refreshed: refreshed.clone(),
        calls: Default::default(),
        allow: true,
    });
    let mut v = TransportBoundVerifier::with_resolver(Arc::new(RotatedResolver { refreshed }));
    v.refresher = Some(inbound.clone());
    v.reply_refresher = Some(reply.clone());

    assert!(v.verify(&self_issued_doc().await).await.is_err());
    v.for_replies()
        .verify(&self_issued_doc().await)
        .await
        .expect("the reply gets its own refresh");
    assert_eq!(inbound.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(reply.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A failure a fresh document cannot cure (issuer binding) triggers no
/// resolution at all.
#[tokio::test]
async fn a_binding_failure_does_not_trigger_a_refresh() {
    let (v, refresher) = rotated_verifier(true);
    let mut body = base_body();
    body.as_object_mut()
        .unwrap()
        .insert("issuer".to_string(), json!("did:web:evil.example"));
    let (doc, _) = sign(body).await;
    assert!(matches!(
        v.verify(&doc).await,
        Err(VerificationError::IssuerMismatch(_))
    ));
    assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn forced_refreshes_are_rate_limited_per_did() {
    let limiter = RefreshLimiter::default();
    let t0 = Instant::now();
    assert!(limiter.allow("did:example:a", t0));
    assert!(!limiter.allow("did:example:a", t0 + Duration::from_secs(1)));
    assert!(limiter.allow("did:example:b", t0 + Duration::from_secs(1)));
    assert!(limiter.allow("did:example:a", t0 + FORCED_REFRESH_INTERVAL));
}

/// The `src` variants of one did:scid share one allowance.
#[test]
fn forced_refreshes_are_limited_per_scid_identity() {
    let limiter = RefreshLimiter::default();
    let t0 = Instant::now();
    assert!(limiter.allow("did:scid:vh:1:abc?src=one.example", t0));
    assert!(!limiter.allow("did:scid:vh:1:abc?src=two.example", t0));
    assert!(!limiter.allow("did:scid:vh:1:abc", t0));
}

/// Every spelling of one DID shares one allowance: a `src` with further
/// parameters (which the `src` helpers leave alone), any other query, a
/// path or a fragment.
#[test]
fn forced_refreshes_are_limited_per_canonical_did() {
    let limiter = RefreshLimiter::default();
    let t0 = Instant::now();
    assert!(limiter.allow("did:scid:vh:1:abc?src=one.example", t0));
    for variant in [
        "did:scid:vh:1:abc?src=two.example&n=1",
        "did:scid:vh:1:abc?src=three.example&src=four.example",
        "did:scid:vh:1:abc?versionId=2",
        "did:scid:vh:1:abc/some/path",
        "did:scid:vh:1:abc#key-1",
    ] {
        assert!(!limiter.allow(variant, t0), "{variant}");
    }
    assert!(limiter.allow("did:webvh:Qm:host.example?versionId=1", t0));
    assert!(!limiter.allow("did:webvh:Qm:host.example?versionId=2", t0));
    assert!(limiter.allow("did:scid:vh:1:other?src=one.example", t0));
}

#[test]
fn canonical_did_drops_path_query_and_fragment() {
    assert_eq!(
        canonical_did("did:scid:vh:1:Qm?src=a.example&x=1#key-1"),
        "did:scid:vh:1:Qm"
    );
    assert_eq!(
        canonical_did("did:webvh:Qm:host.example?versionId=2"),
        "did:webvh:Qm:host.example"
    );
    assert_eq!(canonical_did("did:key:z6Mk#z6Mk"), "did:key:z6Mk");
    assert_eq!(
        canonical_did("did:web:host.example/x"),
        "did:web:host.example"
    );
    assert_eq!(
        canonical_did("did:web:host.example"),
        "did:web:host.example"
    );
}

/// The limiter holds a bounded number of DIDs and refuses (rather than
/// forgets) past it, until entries age out; an oversized DID is refused.
#[test]
fn the_forced_refresh_limiter_is_bounded() {
    let limiter = RefreshLimiter::default();
    let t0 = Instant::now();
    for i in 0..FORCED_REFRESH_CAPACITY {
        assert!(limiter.allow(&format!("did:example:{i}"), t0));
    }
    assert!(!limiter.allow("did:example:one-more", t0));
    assert!(limiter.allow("did:example:one-more", t0 + FORCED_REFRESH_INTERVAL));
    let long = format!("did:example:{}", "a".repeat(FORCED_REFRESH_MAX_DID_LEN));
    assert!(!limiter.allow(&long, t0 + FORCED_REFRESH_INTERVAL));
}

/// A signer resolver that fails every resolution with `kind` and a
/// message of the caller's choosing.
struct Failing {
    kind: VerifyFailureKind,
    message: String,
}

#[async_trait]
impl SignerResolve for Failing {
    async fn resolve_signer(
        &self,
        _vm: &str,
        _purpose: ProofPurpose,
    ) -> Result<ResolvedKey, ResolveFailure> {
        Err(ResolveFailure::new(
            self.kind,
            DataIntegrityError::Resolver(self.message.clone()),
        ))
    }
}

fn failing_verifier(
    kind: VerifyFailureKind,
    message: &str,
) -> (TransportBoundVerifier, Arc<FlagRefresher>) {
    let refresher = Arc::new(FlagRefresher {
        refreshed: Default::default(),
        calls: Default::default(),
        allow: true,
    });
    let mut v = TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver));
    v.signer_resolver = Arc::new(Failing {
        kind,
        message: message.to_string(),
    });
    v.refresher = Some(refresher.clone());
    (v, refresher)
}

/// A signer whose DID could not be resolved at all is not resolved a
/// second time: the failure is reported as unreachable straight away.
#[tokio::test]
async fn an_unresolvable_signer_is_not_resolved_twice() {
    let (v, refresher) = failing_verifier(VerifyFailureKind::Unreachable, "cannot resolve");
    let err = v
        .check_approval(&self_issued_doc().await)
        .await
        .unwrap_err();
    assert!(err.is_unreachable(), "{err:?}");
    assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// The kind decides, not the text: a failure whose message reads like an
/// unreachable or deactivated signer (a DID can be made to say anything)
/// is still the kind its resolver reported, and an unreachable signer
/// stays unreachable whatever its message says.
#[tokio::test]
async fn failure_kinds_do_not_depend_on_message_text() {
    let doc = self_issued_doc().await;

    let lookalike = format!("did:example:x {UNREACHABLE} {DEACTIVATED} not in document");
    let (v, refresher) = failing_verifier(VerifyFailureKind::Invalid, &lookalike);
    let err = v.check_approval(&doc).await.unwrap_err();
    assert_eq!(err.kind, VerifyFailureKind::Invalid, "{err:?}");
    assert_eq!(
        refresher.calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a key-not-found failure is retried once, whatever its text"
    );

    let (v, refresher) = failing_verifier(VerifyFailureKind::Unreachable, "plain words");
    let err = v.check_approval(&doc).await.unwrap_err();
    assert!(err.is_unreachable(), "{err:?}");
    assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    let (v, refresher) = failing_verifier(VerifyFailureKind::Deactivated, UNREACHABLE);
    let err = v.check_approval(&doc).await.unwrap_err();
    assert_eq!(err.kind, VerifyFailureKind::Deactivated, "{err:?}");
    assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// A caller-supplied resolver cannot classify its failures: they are bad
/// proofs, whatever they say.
#[tokio::test]
async fn a_caller_supplied_resolver_reports_invalid() {
    struct SaysUnreachable;
    #[async_trait]
    impl ProofPurposeResolver for SaysUnreachable {
        async fn resolve_vm_for_purpose(
            &self,
            vm: &str,
            _purpose: ProofPurpose,
        ) -> Result<ResolvedKey, DataIntegrityError> {
            Err(DataIntegrityError::Resolver(format!(
                "{UNREACHABLE}: cannot resolve {vm}"
            )))
        }
    }
    let v = TransportBoundVerifier::with_resolver(Arc::new(SaysUnreachable));
    let err = v
        .check_approval(&self_issued_doc().await)
        .await
        .unwrap_err();
    assert_eq!(err.kind, VerifyFailureKind::Invalid, "{err:?}");
}

/// `without_forced_refresh` refuses a proof that fails against the cached
/// document as it stands.
#[tokio::test]
async fn without_forced_refresh_does_not_re_resolve() {
    let (v, refresher) = rotated_verifier(true);
    assert!(
        v.without_forced_refresh()
            .verify(&self_issued_doc().await)
            .await
            .is_err()
    );
    assert_eq!(refresher.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// Operational proofs must be `authentication`-purpose.
#[tokio::test]
async fn operational_verification_requires_authentication_purpose() {
    let doc = self_issued_doc().await;
    assert_eq!(doc.proof.as_ref().unwrap().proof_purpose, "assertionMethod");
    let err = verifier().verify_operational(&doc).await.unwrap_err();
    assert!(
        matches!(err, VerificationError::MalformedProof(_)),
        "{err:?}"
    );
}

/// Against a real DID document, an operational key must be listed under
/// `authentication`; one listed only under `assertionMethod` is refused.
#[tokio::test]
async fn operational_keys_must_be_authentication_keys() {
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;

    let secret = Secret::generate_ed25519(None, Some(&[5u8; 32]));
    let pk = secret.get_public_keymultibase().unwrap();
    let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    for (did, rel) in [
        ("did:web:auth.example", "authentication"),
        ("did:web:assert.example", "assertionMethod"),
    ] {
        let doc: affinidi_tdk::did_common::Document = serde_json::from_value(json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": pk,
            }],
            rel: [format!("{did}#key-1")],
        }))
        .unwrap();
        client.add_did_document(did, doc).await;
    }
    let signers = SignerKeyResolver {
        client: client.clone(),
        decode: CachedDidResolver::new(Arc::new(client)),
        deactivation: None,
    };
    let recording = Recording::new(&signers);
    let resolver = PurposeBound::new(&recording, ProofPurpose::Authentication);
    resolver
        .resolve_vm("did:web:auth.example#key-1")
        .await
        .expect("authentication key resolves");
    let err = resolver
        .resolve_vm("did:web:assert.example#key-1")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not listed under authentication"),
        "{err}"
    );

    // An approver's decision is the mirror image: its key must be listed
    // under `assertionMethod`, and an authentication-only key is refused.
    let approvals = PurposeBound::new(&recording, ProofPurpose::AssertionMethod);
    approvals
        .resolve_vm("did:web:assert.example#key-1")
        .await
        .expect("assertionMethod key resolves for an approval");
    let err = approvals
        .resolve_vm("did:web:auth.example#key-1")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not listed under assertionMethod"),
        "{err}"
    );
}

/// An approver's decision must carry `proofPurpose: assertionMethod`; an
/// operational (`authentication`) proof is not a decision.
#[tokio::test]
async fn approval_verification_requires_assertion_method_purpose() {
    let doc = self_issued_doc().await;
    verifier()
        .verify_approval(&doc)
        .await
        .expect("an assertionMethod-purpose decision verifies");

    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let did = format!("did:key:{pk_mb}");
    let mut signer = secret;
    signer.id = format!("{did}#{pk_mb}");
    let mut body = base_body();
    body.as_object_mut()
        .unwrap()
        .insert("issuer".to_string(), json!(did));
    let unsigned: TrustTask<Value> = serde_json::from_value(body).unwrap();
    let signed = super::super::bound::sign_document(&unsigned, &signer)
        .await
        .unwrap();
    assert_eq!(
        signed.proof.as_ref().unwrap().proof_purpose,
        "authentication"
    );
    let err = verifier().verify_approval(&signed).await.unwrap_err();
    assert!(
        matches!(err, VerificationError::MalformedProof(ref m) if m.contains("assertionMethod")),
        "{err:?}"
    );
}

/// A failure carries its kind and the framework error alongside; an
/// unclassified framework error is a bad proof.
#[test]
fn unreachable_signers_are_distinguished_from_bad_proofs() {
    let unreachable = classified(
        DataIntegrityError::Resolver(format!(
            "{UNREACHABLE}: cannot resolve did:webvh:QmX:gone.example"
        )),
        Some(VerifyFailureKind::Unreachable),
    );
    assert!(unreachable.is_unreachable(), "{unreachable:?}");
    assert!(unreachable.to_string().contains("gone.example"));
    let not_listed = classified(
        DataIntegrityError::Resolver(format!("{UNREACHABLE}: not listed under authentication")),
        None,
    );
    assert!(!not_listed.is_unreachable());
    assert!(!VerifyFailure::from(VerificationError::SignatureInvalid).is_unreachable());
}

/// The deactivation verdict follows the DID cache: reused while the cache
/// serves the same document, re-read when the cache resolved afresh.
#[test]
fn a_deactivation_verdict_is_reused_only_for_a_cached_document() {
    let cache = DeactivationCache::default();
    cache.remember("did:webvh:QmA:a.example", false);
    assert_eq!(cache.cached("did:webvh:QmA:a.example", true), Some(false));
    assert_eq!(cache.cached("did:webvh:QmA:a.example", false), None);
    assert_eq!(cache.cached("did:webvh:QmB:b.example", true), None);
}

/// The verdict map is bounded.
#[test]
fn the_deactivation_cache_is_bounded() {
    let cache = DeactivationCache::default();
    for i in 0..DEACTIVATION_CACHE_CAPACITY + 10 {
        cache.remember(&format!("did:webvh:Qm{i}:x.example"), false);
    }
    let len = cache.verdicts.lock().unwrap().len();
    assert!(len <= DEACTIVATION_CACHE_CAPACITY, "{len}");
    // The newest verdict survives eviction.
    let newest = format!("did:webvh:Qm{}:x.example", DEACTIVATION_CACHE_CAPACITY + 9);
    assert_eq!(cache.cached(&newest, true), Some(false));
}

/// A deactivated `did:webvh` signer is refused even though its last
/// document still lists the key.
#[tokio::test]
async fn a_deactivated_webvh_signer_is_refused() {
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;

    let secret = Secret::generate_ed25519(None, Some(&[6u8; 32]));
    let pk = secret.get_public_keymultibase().unwrap();
    let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    let live = "did:webvh:QmLive:live.example";
    let dead = "did:webvh:QmDead:dead.example";
    for did in [live, dead] {
        let doc: affinidi_tdk::did_common::Document = serde_json::from_value(json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": pk,
            }],
            "authentication": [format!("{did}#key-1")],
        }))
        .unwrap();
        client.add_did_document(did, doc).await;
    }
    let deactivation = Arc::new(DeactivationCache::default());
    {
        let mut v = deactivation.verdicts.lock().unwrap();
        v.insert(live.into(), (Instant::now(), false));
        v.insert(dead.into(), (Instant::now(), true));
    }
    let signers = SignerKeyResolver {
        client: client.clone(),
        decode: CachedDidResolver::new(Arc::new(client)),
        deactivation: Some(deactivation),
    };
    let recording = Recording::new(&signers);
    let resolver = PurposeBound::new(&recording, ProofPurpose::Authentication);
    resolver
        .resolve_vm(&format!("{live}#key-1"))
        .await
        .expect("a live signer resolves");
    let err = resolver
        .resolve_vm(&format!("{dead}#key-1"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("deactivated"), "{err}");
    assert_eq!(
        recording.failure_kind(),
        Some(VerifyFailureKind::Deactivated)
    );
}

/// A signed did:webvh log for `localhost:{port}` with `secret` as its
/// `authentication` key, ending in a deactivation when `deactivate`:
/// the DID and its `did.jsonl`.
async fn webvh_log(port: u16, secret: &Secret, deactivate: bool) -> (String, String) {
    use didwebvh_rs::{
        DIDWebVHState, Multibase, log_entry::LogEntryMethods, parameters::Parameters,
    };

    let mut update_key = Secret::generate_ed25519(None, None);
    let update_pk = update_key.get_public_keymultibase().unwrap();
    update_key.id = format!("did:key:{update_pk}#{update_pk}");
    let pk = secret.get_public_keymultibase().unwrap();
    let template = format!("did:webvh:{{SCID}}:localhost%3A{port}");
    let doc = json!({
        "id": template,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{template}#key-1"),
            "type": "Multikey",
            "controller": template,
            "publicKeyMultibase": pk,
        }],
        "authentication": [format!("{template}#key-1")],
    });
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(update_pk)])),
        portable: Some(false),
        ..Default::default()
    };
    // Backdated so a deactivation entry's versionTime is strictly later.
    let genesis = (chrono::Utc::now() - chrono::Duration::seconds(100)).fixed_offset();
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(Some(genesis), &doc, &params, &update_key)
        .await
        .unwrap();
    if deactivate {
        state.deactivate(&update_key).await.unwrap();
    }
    let did = state
        .log_entries()
        .last()
        .unwrap()
        .log_entry
        .get_did_document()
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let jsonl = state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    (did, jsonl)
}

/// Serve `body` to every request on `listener`.
fn serve(listener: tokio::net::TcpListener, body: String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ = socket.read(&mut request).await;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/jsonl\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            });
        }
    });
}

/// A deactivated `did:webvh` signer the DID cache has never seen is refused
/// as **deactivated** — final — and not as unreachable. Since
/// `affinidi-did-resolver-cache-sdk` 0.8.39 the cache refuses to resolve a
/// deactivated did:webvh at all; that refusal used to be reported as an
/// unreachable signer, so the proof was retried (a cache eviction and a
/// re-resolution each time) and the caller told to try again. A live DID
/// served beside it shows the harness serves logs that resolve.
#[tokio::test]
async fn an_uncached_deactivated_webvh_signer_is_refused_as_final() {
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy as CacheHostPolicy;

    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let live_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (live, live_log) =
        webvh_log(live_listener.local_addr().unwrap().port(), &secret, false).await;
    let (dead, dead_log) =
        webvh_log(dead_listener.local_addr().unwrap().port(), &secret, true).await;
    serve(live_listener, live_log);
    serve(dead_listener, dead_log);

    let client = DIDCacheClient::new(
        DIDCacheConfigBuilder::default()
            .with_host_policy(CacheHostPolicy::AllowPrivate)
            .build(),
    )
    .await
    .unwrap();
    let signers = SignerKeyResolver {
        client: client.clone(),
        // Built as `with_did_cache_and_host_policy` builds it for
        // `AllowPrivate`: the decode step screens hosts on its own.
        decode: CachedDidResolver::new(Arc::new(client)).allow_private_hosts(true),
        deactivation: Some(Arc::new(DeactivationCache {
            host_policy: HostPolicy::AllowPrivate,
            ..DeactivationCache::default()
        })),
    };
    signers
        .resolve_signer(&format!("{live}#key-1"), ProofPurpose::Authentication)
        .await
        .map_err(|f| f.error)
        .expect("a live signer resolves");
    let Err(failure) = signers
        .resolve_signer(&format!("{dead}#key-1"), ProofPurpose::Authentication)
        .await
    else {
        panic!("a deactivated signer is refused");
    };
    assert_eq!(
        failure.kind,
        VerifyFailureKind::Deactivated,
        "a deactivated signer is final: {}",
        failure.error
    );
    assert!(failure.error.to_string().contains(DEACTIVATED));
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
    // …and passes the approval check `/auth/step-up/vta/finish` applies
    // (`assertionMethod` purpose and relationship).
    verifier()
        .verify_approval(&approved)
        .await
        .expect("wallet-signed approval passes the approval check");

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

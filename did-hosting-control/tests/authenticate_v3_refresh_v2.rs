//! `auth/authenticate/0.3` (the proxied form) and `auth/refresh/0.2` (the
//! session-key-bound, absolute-lifetime-capped form), end to end over
//! `POST /api/trust-tasks`.
//!
//! Covers what `trust_tasks_auth::authenticate_v3_arm` and `refresh_v2_arm`
//! add over `0.2`/`0.1`:
//!
//! - a proxied login succeeds only with delegation evidence the control plane
//!   verifies independently — both recognized `delegationEvidence.kind`s
//!   (`mandateCredential`, `siopIdToken`);
//! - forged or mismatched evidence, on both kinds, is refused;
//! - evidence that is otherwise valid but names a different principal than
//!   the request claims is refused (the confused-deputy case
//!   `auth/authenticate/0.3`'s Security & Privacy names directly);
//! - a challenge cannot be redeemed twice;
//! - a refresh on a session-key-bound session must carry that key's own
//!   proof, not any other key the subject controls;
//! - a refresh cannot advance a session past its `absoluteExpiresAt`.

use std::sync::Arc;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use did_hosting_common::server::acl::Role;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use did_hosting_control::test_support::TestServer;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const CONTROL: &str = "did:webvh:test:control.example.com";
const TT: &str = "https://trusttasks.org/spec/";

struct Key {
    did: String,
    secret: Secret,
    /// The same key material as `secret`, for the raw Ed25519 JWS signing a
    /// SIOPv2 `id_token` needs — a bare compact JWS, not a Data Integrity
    /// document, so `DataIntegrityProof::sign` does not apply to it.
    signing_key: ed25519_dalek::SigningKey,
}

fn key(seed: u8) -> Key {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let pk = secret.get_public_keymultibase().expect("multibase");
    let did = format!("did:key:{pk}");
    let mut secret = secret;
    secret.id = format!("{did}#{pk}");
    Key {
        did,
        secret,
        signing_key,
    }
}

/// A harness whose trust-task verifier and DID resolver both work over
/// `did:key` with no network — everything a `siopIdToken`'s independent
/// `iss` resolution, and a `mandateCredential`'s `assertionMethod`
/// verification, need.
async fn harness() -> TestServer {
    let mut h = TestServer::start().await;
    h.state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
        DidKeyResolver,
    ))));
    h.state.did_resolver = Some(
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("did:key resolver"),
    );
    h
}

fn doc(type_uri: &str, issuer: &str, payload: Value) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": format!("{TT}{type_uri}"),
        "issuer": issuer,
        "recipient": CONTROL,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    })
}

/// Sign `doc` with `key` exactly as given, whatever its `issuer` says: the
/// documents a session key, a delegate, or an attacker, would send.
async fn sign(doc: Value, key: &Key, purpose: &str) -> Value {
    let typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(doc).unwrap();
    let canonical = serde_json::to_value(&typed).unwrap();
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &canonical,
        &key.secret,
        affinidi_data_integrity::SignOptions::new().with_proof_purpose(purpose),
    )
    .await
    .expect("sign");
    let mut out = canonical;
    out["proof"] = serde_json::to_value(&proof).unwrap();
    out
}

async fn post(h: &TestServer, doc: &Value) -> (StatusCode, Value) {
    let resp = h
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/trust-tasks")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(doc).unwrap()))
                .unwrap(),
        )
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn code(body: &Value) -> &str {
    body["payload"]["code"].as_str().unwrap_or("")
}

/// `auth/challenge/0.1` signed by `subject` itself — the challenge is bound
/// to `subject`, which for a proxied login must be the *principal*, not the
/// delegate (`trust_tasks_auth::challenge_arm` binds strictly to whoever the
/// framework verified as the request's signer).
async fn challenge(h: &TestServer, subject: &Key) -> (String, String) {
    let d = sign(
        doc("auth/challenge/0.1", &subject.did, json!({})),
        subject,
        "authentication",
    )
    .await;
    let (status, body) = post(h, &d).await;
    assert_eq!(status, StatusCode::OK, "challenge: {body}");
    (
        body["payload"]["challenge"].as_str().unwrap().to_string(),
        body["payload"]["sessionId"].as_str().unwrap().to_string(),
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A SIOPv2 self-issued `id_token`, a bare compact JWS (not a Data Integrity
/// document — signed directly with `id`'s Ed25519 key): `iss == sub == id`.
fn siop_id_token(id: &Key, aud: &str, nonce: &str, now: u64) -> String {
    use ed25519_dalek::Signer;
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": id.secret.id });
    let payload = json!({
        "iss": id.did, "sub": id.did, "aud": aud, "nonce": nonce,
        "iat": now, "exp": now + 300,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = id.signing_key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

/// A `mandateCredential` document: `principal` entitles `delegate`, signed by
/// `signer` (the principal itself, for a genuine mandate — or an impostor,
/// for the forged-evidence cases).
async fn mandate_credential(principal: &str, delegate: &str, signer: &Key) -> Value {
    let mandate = doc(
        "local/did-hosting-auth-mandate/0.1",
        principal,
        json!({ "delegate": delegate }),
    );
    sign(mandate, signer, "assertionMethod").await
}

fn delegation_evidence(kind: &str, credential: Value) -> Value {
    json!({ "kind": kind, "credential": credential })
}

/// Build a proxied `auth/authenticate/0.3` document: `delegate` signs it as
/// `issuer`, naming `principal`, carrying `evidence`.
async fn proxied_authenticate(
    delegate: &Key,
    principal_did: &str,
    challenge: &str,
    session_id: &str,
    evidence: Value,
    session_key: Option<&str>,
) -> Value {
    let mut payload = json!({
        "challenge": challenge,
        "sessionId": session_id,
        "principal": principal_did,
        "delegationEvidence": evidence,
    });
    if let Some(k) = session_key {
        payload["sessionKey"] = json!(k);
    }
    let d = doc("auth/authenticate/0.3", &delegate.did, payload);
    sign(d, delegate, "authentication").await
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

/// A proxied login backed by a `mandateCredential` — a standing grant the
/// principal signed in advance, with no live participation at login time —
/// succeeds: `session.subject` is the principal, `session.actor` the
/// delegate.
#[tokio::test]
async fn mandate_credential_proxied_login_succeeds() {
    let h = harness().await;
    let (principal, delegate) = (key(1), key(2));
    h.add_acl(&principal.did, Role::Owner).await;

    let (challenge, session_id) = challenge(&h, &principal).await;
    let mandate = mandate_credential(&principal.did, &delegate.did, &principal).await;
    let d = proxied_authenticate(
        &delegate,
        &principal.did,
        &challenge,
        &session_id,
        delegation_evidence("mandateCredential", mandate),
        None,
    )
    .await;

    let (status, body) = post(&h, &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["type"], format!("{TT}auth/authenticate/0.3#response"));
    assert_eq!(body["payload"]["session"]["subject"], principal.did);
    assert_eq!(body["payload"]["session"]["actor"], delegate.did);
    assert!(
        body["payload"]["session"]["absoluteExpiresAt"].is_string(),
        "{body}"
    );
}

/// A proxied login backed by a `siopIdToken` — the principal's own key,
/// custodially held at the delegate, signing a self-issued token over this
/// same challenge — succeeds identically.
#[tokio::test]
async fn siop_id_token_proxied_login_succeeds() {
    let h = harness().await;
    let (principal, delegate) = (key(3), key(4));
    h.add_acl(&principal.did, Role::Owner).await;

    let (challenge, session_id) = challenge(&h, &principal).await;
    let id_token = siop_id_token(&principal, CONTROL, &challenge, now_secs());
    let d = proxied_authenticate(
        &delegate,
        &principal.did,
        &challenge,
        &session_id,
        delegation_evidence("siopIdToken", json!({ "idToken": id_token })),
        None,
    )
    .await;

    let (status, body) = post(&h, &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["session"]["subject"], principal.did);
    assert_eq!(body["payload"]["session"]["actor"], delegate.did);
}

// ---------------------------------------------------------------------------
// Forged / mismatched delegationEvidence
// ---------------------------------------------------------------------------

/// A `mandateCredential` naming a *different* delegate than the one that
/// actually signed the authenticate document is refused: the entitlement is
/// for someone else.
#[tokio::test]
async fn mandate_credential_naming_the_wrong_delegate_is_refused() {
    let h = harness().await;
    let (principal, delegate, someone_else) = (key(5), key(6), key(7));
    h.add_acl(&principal.did, Role::Owner).await;

    let (challenge, session_id) = challenge(&h, &principal).await;
    // The mandate entitles `someone_else`, not `delegate`.
    let mandate = mandate_credential(&principal.did, &someone_else.did, &principal).await;
    let d = proxied_authenticate(
        &delegate,
        &principal.did,
        &challenge,
        &session_id,
        delegation_evidence("mandateCredential", mandate),
        None,
    )
    .await;

    let (status, body) = post(&h, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        code(&body),
        "auth/authenticate:delegationNotRecognized",
        "{body}"
    );
}

/// A `mandateCredential` whose `proof` does not resolve to the principal's
/// own key — forged, or signed by the delegate itself — is refused, even
/// though every field it claims is correct: a claim of entitlement is not
/// itself evidence of one (`auth/authenticate/0.3` Authorization).
#[tokio::test]
async fn a_forged_mandate_credential_is_refused() {
    let h = harness().await;
    let (principal, delegate) = (key(8), key(9));
    h.add_acl(&principal.did, Role::Owner).await;

    let (challenge, session_id) = challenge(&h, &principal).await;
    // Correct shape, but signed by the delegate itself, not the principal —
    // the delegate cannot mint its own entitlement.
    let mandate = mandate_credential(&principal.did, &delegate.did, &delegate).await;
    let d = proxied_authenticate(
        &delegate,
        &principal.did,
        &challenge,
        &session_id,
        delegation_evidence("mandateCredential", mandate),
        None,
    )
    .await;

    let (status, body) = post(&h, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        code(&body),
        "auth/authenticate:delegationNotRecognized",
        "{body}"
    );
}

/// A `siopIdToken` whose `nonce` does not match this authenticate's own
/// challenge — a token genuinely signed by the principal, but for a
/// different login — is refused as not replayable across challenges.
#[tokio::test]
async fn a_siop_id_token_for_a_different_challenge_is_refused() {
    let h = harness().await;
    let (principal, delegate) = (key(10), key(11));
    h.add_acl(&principal.did, Role::Owner).await;

    let (challenge, session_id) = challenge(&h, &principal).await;
    // Signed over a nonce that is not this challenge.
    let id_token = siop_id_token(&principal, CONTROL, "some-other-challenge", now_secs());
    let d = proxied_authenticate(
        &delegate,
        &principal.did,
        &challenge,
        &session_id,
        delegation_evidence("siopIdToken", json!({ "idToken": id_token })),
        None,
    )
    .await;

    let (status, body) = post(&h, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        code(&body),
        "auth/authenticate:delegationNotRecognized",
        "{body}"
    );
}

/// A `siopIdToken` forged — claiming `iss`/`sub` is the principal, but
/// actually signed by a different key — fails the token's own signature
/// verification and is refused.
#[tokio::test]
async fn a_forged_siop_id_token_is_refused() {
    let h = harness().await;
    let (principal, delegate, impostor) = (key(12), key(13), key(14));
    h.add_acl(&principal.did, Role::Owner).await;

    let (challenge, session_id) = challenge(&h, &principal).await;
    // `iss`/`sub` claim the principal, but the signature is the impostor's.
    use ed25519_dalek::Signer;
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": impostor.secret.id });
    let payload = json!({
        "iss": principal.did, "sub": principal.did, "aud": CONTROL, "nonce": challenge,
        "iat": now_secs(), "exp": now_secs() + 300,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = impostor.signing_key.sign(signing_input.as_bytes());
    let id_token = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );

    let d = proxied_authenticate(
        &delegate,
        &principal.did,
        &challenge,
        &session_id,
        delegation_evidence("siopIdToken", json!({ "idToken": id_token })),
        None,
    )
    .await;

    let (status, body) = post(&h, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        code(&body),
        "auth/authenticate:delegationNotRecognized",
        "{body}"
    );
}

// ---------------------------------------------------------------------------
// Wrong principal — evidence is genuine, but for someone else
// ---------------------------------------------------------------------------

/// Evidence that genuinely entitles the delegate for `carol` does not
/// entitle it for `alice` — the confused-deputy case
/// `auth/authenticate/0.3`'s Security & Privacy names directly: the
/// delegate's key is well-formed and its evidence independently verifies, it
/// simply does not establish the entitlement *this* request claims.
#[tokio::test]
async fn evidence_for_one_principal_does_not_authenticate_a_different_one() {
    let h = harness().await;
    let (alice, carol, delegate) = (key(15), key(16), key(17));
    h.add_acl(&alice.did, Role::Owner).await;
    h.add_acl(&carol.did, Role::Owner).await;

    // The challenge must still be bound to the principal the request claims
    // (`alice`) for the request to reach the delegation check at all.
    let (challenge, session_id) = challenge(&h, &alice).await;
    // Genuine evidence — but for carol, not alice.
    let id_token = siop_id_token(&carol, CONTROL, &challenge, now_secs());
    let d = proxied_authenticate(
        &delegate,
        &alice.did,
        &challenge,
        &session_id,
        delegation_evidence("siopIdToken", json!({ "idToken": id_token })),
        None,
    )
    .await;

    let (status, body) = post(&h, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        code(&body),
        "auth/authenticate:delegationNotRecognized",
        "{body}"
    );
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// The same `(sessionId, challenge)` cannot be redeemed twice, even by an
/// identical, validly-signed proxied authenticate document.
#[tokio::test]
async fn a_redeemed_challenge_cannot_be_replayed() {
    let h = harness().await;
    let (principal, delegate) = (key(18), key(19));
    h.add_acl(&principal.did, Role::Owner).await;

    let (challenge, session_id) = challenge(&h, &principal).await;
    let mandate = mandate_credential(&principal.did, &delegate.did, &principal).await;
    let d = proxied_authenticate(
        &delegate,
        &principal.did,
        &challenge,
        &session_id,
        delegation_evidence("mandateCredential", mandate),
        None,
    )
    .await;

    let (status, _) = post(&h, &d).await;
    assert_eq!(status, StatusCode::OK);

    // Bit-for-bit the same document, replayed.
    let (status, body) = post(&h, &d).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a replayed challenge must not mint a second session: {body}"
    );
}

// ---------------------------------------------------------------------------
// auth/refresh/0.2
// ---------------------------------------------------------------------------

/// Log `principal` in via a proxied `mandateCredential` login, binding
/// `session_key`. Returns the refresh token, the response body and the
/// session id.
async fn proxied_login_binding_session_key(
    h: &TestServer,
    principal: &Key,
    delegate: &Key,
    session_key: &Key,
) -> (String, Value, String) {
    h.add_acl(&principal.did, Role::Owner).await;
    let (challenge, session_id) = challenge(h, principal).await;
    let mandate = mandate_credential(&principal.did, &delegate.did, principal).await;
    let d = proxied_authenticate(
        delegate,
        &principal.did,
        &challenge,
        &session_id,
        delegation_evidence("mandateCredential", mandate),
        Some(&session_key.did),
    )
    .await;
    let (status, body) = post(h, &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refresh_token = body["payload"]["tokens"]["refreshToken"]
        .as_str()
        .unwrap()
        .to_string();
    let session_id = body["payload"]["session"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    (refresh_token, body, session_id)
}

fn refresh_doc(refresh_token: &str, issuer: &str) -> Value {
    doc(
        "auth/refresh/0.2",
        issuer,
        json!({ "refreshToken": refresh_token }),
    )
}

/// A session that bound a key must refresh with *that* key's proof — the
/// principal's own long-term key (which signed the login's delegation
/// evidence) does not substitute, and neither does an unrelated key.
#[tokio::test]
async fn refresh_with_the_wrong_key_is_refused() {
    let h = harness().await;
    let (principal, delegate, session_key, wrong_key) = (key(20), key(21), key(22), key(23));

    let (refresh_token, _, _) =
        proxied_login_binding_session_key(&h, &principal, &delegate, &session_key).await;

    // Signed by a key that is not the bound session key.
    let d = sign(
        refresh_doc(&refresh_token, &wrong_key.did),
        &wrong_key,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        code(&body),
        "auth/refresh:sessionKeyProofRequired",
        "{body}"
    );

    // Nor does the principal's own key, which the spec calls out by name.
    let d = sign(
        refresh_doc(&refresh_token, &principal.did),
        &principal,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        code(&body),
        "auth/refresh:sessionKeyProofRequired",
        "{body}"
    );

    // The bound key itself still works, and the token was not burned by the
    // refusals above.
    let d = sign(
        refresh_doc(&refresh_token, &session_key.did),
        &session_key,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A session that has already reached its `absoluteExpiresAt` refuses
/// refresh outright, however valid the token and key — the producer must
/// re-authenticate.
#[tokio::test]
async fn refresh_past_the_absolute_lifetime_is_refused() {
    let h = harness().await;
    let (principal, delegate, session_key) = (key(24), key(25), key(26));

    let (refresh_token, body, session_id) =
        proxied_login_binding_session_key(&h, &principal, &delegate, &session_key).await;
    let absolute_expires_at = chrono::DateTime::parse_from_rfc3339(
        body["payload"]["session"]["absoluteExpiresAt"]
            .as_str()
            .expect("absoluteExpiresAt"),
    )
    .expect("valid rfc3339")
    .timestamp() as u64;

    // Push the session's own refresh deadline out to the absolute ceiling —
    // simulating a session that has been refreshed right up against it —
    // without needing to wait out the real 30-day default.
    let mut session =
        did_hosting_common::server::auth::session::get_session(&h.state.sessions_ks, &session_id)
            .await
            .expect("read session")
            .expect("session exists");
    session.refresh_expires_at = Some(absolute_expires_at);
    did_hosting_common::server::auth::session::store_session(&h.state.sessions_ks, &session)
        .await
        .expect("store session");

    let d = sign(
        refresh_doc(&refresh_token, &session_key.did),
        &session_key,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(
        code(&body),
        "auth/refresh:sessionLifetimeExceeded",
        "{body}"
    );
}

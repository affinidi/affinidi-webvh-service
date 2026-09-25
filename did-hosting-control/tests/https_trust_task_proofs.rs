//! `POST /api/trust-tasks`: every privileged document must carry a proof bound
//! to the bearer token's subject.
//!
//! Two signing shapes are accepted, and nothing else:
//!
//! - **self-signed** — `issuer` is the JWT subject and the proof is one of the
//!   subject's own keys (wallet / machine callers);
//! - **passkey session delegate** — `issuer` is the JWT subject and the proof
//!   is signed by exactly the session key the login flow bound into the JWT.
//!
//! In both, `issuer` is required in-band.

use std::sync::Arc;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::server::acl::Role;
use did_hosting_common::server::auth::session::create_authenticated_session;
use did_hosting_common::server::config::AuthConfig;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use did_hosting_control::test_support::TestServer;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const CONTROL: &str = "did:webvh:test:control.example.com";
const LIST: &str = "https://trusttasks.org/spec/acl/list/0.1";

fn did_key_signer(seed: u8) -> (String, String, Secret) {
    let secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let pk = secret.get_public_keymultibase().expect("multibase");
    let did = format!("did:key:{pk}");
    let mut s = secret;
    s.id = format!("{did}#{pk}");
    (did, pk, s)
}

async fn harness() -> TestServer {
    let mut h = TestServer::start().await;
    h.state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
        DidKeyResolver,
    ))));
    h
}

/// A bearer token for `did`, optionally bound to a passkey session key.
async fn token(h: &TestServer, did: &str, session_pk: Option<String>) -> String {
    let auth = AuthConfig::default();
    create_authenticated_session(
        &h.state.sessions_ks,
        h.state.jwt_keys.as_ref().expect("jwt keys"),
        did,
        &Role::Admin,
        auth.access_token_expiry,
        auth.refresh_token_expiry,
        session_pk,
        None,
    )
    .await
    .expect("session")
    .access_token
}

fn list_doc(issuer: Option<&str>) -> Value {
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": LIST,
        "recipient": CONTROL,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {},
    });
    if let Some(issuer) = issuer {
        doc["issuer"] = json!(issuer);
    }
    doc
}

/// Sign `doc` with `key` exactly as given, whatever its `issuer` says (or its
/// absence) — the documents a session delegate, or an attacker, would send.
/// Uses the Data Integrity primitive directly because the Trust Task signer
/// refuses an issuer that is not the key's own DID.
async fn sign_as(doc: Value, key: &Secret) -> Value {
    let typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(doc).unwrap();
    let canonical = serde_json::to_value(&typed).unwrap();
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &canonical,
        key,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .expect("sign");
    let mut out = canonical;
    out["proof"] = serde_json::to_value(&proof).unwrap();
    out
}

async fn post(h: &TestServer, token: &str, doc: &Value) -> (StatusCode, Value) {
    let resp = h
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/trust-tasks")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
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

#[tokio::test]
async fn self_signed_document_is_accepted() {
    let h = harness().await;
    let (admin, _, key) = did_key_signer(1);
    h.add_acl(&admin, Role::Admin).await;
    let tok = token(&h, &admin, None).await;

    let doc = sign_as(list_doc(Some(&admin)), &key).await;
    let (status, body) = post(&h, &tok, &doc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["type"], format!("{LIST}#response"));
}

#[tokio::test]
async fn passkey_session_key_signing_for_its_subject_is_accepted() {
    let h = harness().await;
    let admin = "did:web:alice.example";
    h.add_acl(admin, Role::Admin).await;
    let (_session_did, session_pk, session_key) = did_key_signer(2);
    let tok = token(&h, admin, Some(session_pk)).await;

    let doc = sign_as(list_doc(Some(admin)), &session_key).await;
    let (status, body) = post(&h, &tok, &doc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["type"], format!("{LIST}#response"));
}

/// The passkey shape the Web UI used to send — no `issuer` — is refused: the
/// document must say who it is from.
#[tokio::test]
async fn passkey_document_without_issuer_is_refused() {
    let h = harness().await;
    let admin = "did:web:alice.example";
    h.add_acl(admin, Role::Admin).await;
    let (_session_did, session_pk, session_key) = did_key_signer(2);
    let tok = token(&h, admin, Some(session_pk)).await;

    let doc = sign_as(list_doc(None), &session_key).await;
    let (status, body) = post(&h, &tok, &doc).await;
    assert_ne!(status, StatusCode::OK, "{body}");
}

/// A session key can only ever act for its own session's subject.
#[tokio::test]
async fn passkey_session_key_cannot_act_for_another_issuer() {
    let h = harness().await;
    let alice = "did:web:alice.example";
    let admin = "did:web:admin.example";
    h.add_acl(alice, Role::Owner).await;
    h.add_acl(admin, Role::Admin).await;
    let (_session_did, session_pk, session_key) = did_key_signer(2);
    let tok = token(&h, alice, Some(session_pk)).await;

    let doc = sign_as(list_doc(Some(admin)), &session_key).await;
    let (status, body) = post(&h, &tok, &doc).await;
    assert_ne!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn unsigned_privileged_document_is_refused() {
    let h = harness().await;
    let admin = "did:web:admin.example";
    h.add_acl(admin, Role::Admin).await;
    let tok = token(&h, admin, None).await;

    let (status, body) = post(&h, &tok, &list_doc(Some(admin))).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["code"], "proofRequired", "{body}");
}

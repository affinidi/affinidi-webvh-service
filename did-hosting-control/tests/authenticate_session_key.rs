//! `auth/authenticate/0.2` session keys, end to end over `POST /api/trust-tasks`.
//!
//! A subject logs in with `auth/challenge/0.1` then `auth/authenticate/0.2`,
//! naming a `sessionKey`. The control plane binds it to the new session and
//! then accepts that key's `authentication` proofs as the subject:
//!
//! - for that session only;
//! - until the session expires, is revoked or is logged out;
//! - never for an approval (`auth/step-up/approve-response`);
//! - never to mint or refresh a session.
//!
//! A key type it cannot verify is refused with `sessionKeyUnsupported`, before
//! the challenge is spent.

use std::sync::Arc;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
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
}

fn key(seed: u8) -> Key {
    let secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let pk = secret.get_public_keymultibase().expect("multibase");
    let did = format!("did:key:{pk}");
    let mut secret = secret;
    secret.id = format!("{did}#{pk}");
    Key { did, secret }
}

async fn harness() -> TestServer {
    let mut h = TestServer::start().await;
    h.state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
        DidKeyResolver,
    ))));
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
/// documents a session key, or an attacker, would send.
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

async fn post(h: &TestServer, bearer: Option<&str>, doc: &Value) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = h
        .router()
        .oneshot(
            req.body(Body::from(serde_json::to_vec(doc).unwrap()))
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

/// `auth/challenge/0.1` for `subject`, returning `(challenge, sessionId)`.
async fn challenge(h: &TestServer, subject: &Key) -> (String, String) {
    let d = sign(
        doc("auth/challenge/0.1", &subject.did, json!({})),
        subject,
        "authentication",
    )
    .await;
    let (status, body) = post(h, None, &d).await;
    assert_eq!(status, StatusCode::OK, "challenge: {body}");
    (
        body["payload"]["challenge"].as_str().unwrap().to_string(),
        body["payload"]["sessionId"].as_str().unwrap().to_string(),
    )
}

/// `auth/authenticate/0.2` for a challenge, optionally binding `session_key`.
async fn authenticate(
    h: &TestServer,
    subject: &Key,
    (challenge, session_id): &(String, String),
    session_key: Option<&str>,
) -> (StatusCode, Value) {
    let mut payload = json!({ "challenge": challenge, "sessionId": session_id });
    if let Some(k) = session_key {
        payload["sessionKey"] = json!(k);
    }
    let d = sign(
        doc("auth/authenticate/0.2", &subject.did, payload),
        subject,
        "authentication",
    )
    .await;
    post(h, None, &d).await
}

/// Log `subject` in, binding `session_key`. Returns the access token and the
/// full response document.
async fn login(h: &TestServer, subject: &Key, session_key: Option<&Key>) -> (String, Value) {
    let ch = challenge(h, subject).await;
    let (status, body) = authenticate(h, subject, &ch, session_key.map(|k| k.did.as_str())).await;
    assert_eq!(status, StatusCode::OK, "authenticate: {body}");
    let token = body["payload"]["tokens"]["accessToken"]
        .as_str()
        .unwrap()
        .to_string();
    (token, body)
}

/// An ordinary operational request (`acl/list`) as `subject`, signed by `by`.
async fn list_as(h: &TestServer, bearer: &str, subject: &Key, by: &Key) -> (StatusCode, Value) {
    let d = sign(
        doc("acl/list/0.1", &subject.did, json!({})),
        by,
        "authentication",
    )
    .await;
    post(h, Some(bearer), &d).await
}

/// Another live session for `subject`, created directly in the store,
/// optionally bound to `session_key`.
async fn session_for(h: &TestServer, subject: &Key, session_key: Option<&Key>) -> String {
    let auth = did_hosting_common::server::config::AuthConfig::default();
    did_hosting_common::server::auth::session::create_authenticated_session(
        &h.state.sessions_ks,
        h.state.jwt_keys.as_ref().expect("jwt keys"),
        &subject.did,
        &Role::Admin,
        auth.access_token_expiry,
        auth.refresh_token_expiry,
        session_key.map(|k| k.did.trim_start_matches("did:key:").to_string()),
        None,
    )
    .await
    .expect("session")
    .access_token
}

fn code(body: &Value) -> &str {
    body["payload"]["code"].as_str().unwrap_or("")
}

#[tokio::test]
async fn login_binds_the_session_key_and_it_signs_for_its_session() {
    let h = harness().await;
    let (alice, browser) = (key(1), key(2));
    h.add_acl(&alice.did, Role::Admin).await;

    let (token, body) = login(&h, &alice, Some(&browser)).await;
    assert_eq!(body["type"], format!("{TT}auth/authenticate/0.2#response"));
    assert_eq!(
        body["payload"]["session"]["sessionKey"], browser.did,
        "the binding is echoed"
    );

    let (status, body) = list_as(&h, &token, &alice, &browser).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The subject's own key still works in the same session.
    let (status, body) = list_as(&h, &token, &alice, &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_login_without_a_session_key_binds_none() {
    let h = harness().await;
    let (alice, stranger) = (key(3), key(4));
    h.add_acl(&alice.did, Role::Admin).await;

    let (token, body) = login(&h, &alice, None).await;
    assert!(
        body["payload"]["session"].get("sessionKey").is_none(),
        "{body}"
    );
    let (status, body) = list_as(&h, &token, &alice, &stranger).await;
    assert_ne!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn the_session_key_is_accepted_only_for_its_own_session() {
    let h = harness().await;
    let (alice, browser, other_browser) = (key(5), key(6), key(7));
    h.add_acl(&alice.did, Role::Admin).await;

    let (_first, _) = login(&h, &alice, Some(&browser)).await;
    // Two more live sessions for the same subject: one bound to a different
    // browser key, one bound to none.
    let second = session_for(&h, &alice, Some(&other_browser)).await;
    let third = session_for(&h, &alice, None).await;

    // The same subject's other sessions do not honour it. Each bearer is
    // live (the subject's own key is accepted with it), so the refusal is
    // about the key, not the session.
    for bearer in [&second, &third] {
        let (status, body) = list_as(&h, bearer, &alice, &alice).await;
        assert_eq!(status, StatusCode::OK, "bearer is live: {body}");
        let (status, body) = list_as(&h, bearer, &alice, &browser).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert_eq!(code(&body), "proofInvalid", "{body}");
    }
    // Nor does a request with no session at all.
    let d = sign(
        doc("acl/list/0.1", &alice.did, json!({})),
        &browser,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, None, &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn the_session_key_cannot_act_for_another_subject() {
    let h = harness().await;
    let (alice, bob, browser) = (key(8), key(9), key(10));
    h.add_acl(&alice.did, Role::Admin).await;
    h.add_acl(&bob.did, Role::Admin).await;

    let (token, _) = login(&h, &alice, Some(&browser)).await;
    let (status, body) = list_as(&h, &token, &bob, &browser).await;
    assert_ne!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn the_session_key_ends_when_the_session_is_revoked() {
    let h = harness().await;
    let (alice, browser) = (key(11), key(12));
    h.add_acl(&alice.did, Role::Admin).await;
    let (token, body) = login(&h, &alice, Some(&browser)).await;
    let session_id = body["payload"]["session"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Logout: the session key itself may revoke its session.
    let d = sign(
        doc(
            "auth/revoke-session/0.2",
            &alice.did,
            json!({ "sessionId": session_id, "reason": "logout" }),
        ),
        &browser,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, Some(&token), &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 1);

    let (status, body) = list_as(&h, &token, &alice, &browser).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn a_session_cannot_be_revoked_by_another_subject() {
    let h = harness().await;
    let (alice, bob) = (key(13), key(14));
    h.add_acl(&alice.did, Role::Admin).await;
    h.add_acl(&bob.did, Role::Admin).await;
    let (alice_token, body) = login(&h, &alice, None).await;
    let alice_session = body["payload"]["session"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (bob_token, _) = login(&h, &bob, None).await;

    let d = sign(
        doc(
            "auth/revoke-session/0.2",
            &bob.did,
            json!({ "sessionId": alice_session }),
        ),
        &bob,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, Some(&bob_token), &d).await;
    // Answered exactly as a session that does not exist: nothing revoked.
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 0, "{body}");
    let (status, body) = list_as(&h, &alice_token, &alice, &alice).await;
    assert_eq!(status, StatusCode::OK, "alice's session survives: {body}");
}

#[tokio::test]
async fn the_session_key_revokes_only_its_own_session_and_a_retry_succeeds() {
    let h = harness().await;
    let (alice, browser) = (key(22), key(23));
    h.add_acl(&alice.did, Role::Admin).await;
    let (token, body) = login(&h, &alice, Some(&browser)).await;
    let own = body["payload"]["session"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let other_token = session_for(&h, &alice, None).await;
    let other = h
        .state
        .jwt_keys
        .as_ref()
        .expect("jwt keys")
        .decode(&other_token)
        .expect("decode")
        .session_id;

    let revoke = |session_id: &str| {
        doc(
            "auth/revoke-session/0.2",
            &alice.did,
            json!({ "sessionId": session_id }),
        )
    };

    // The session key cannot end the subject's other session.
    let d = sign(revoke(&other), &browser, "authentication").await;
    let (status, body) = post(&h, Some(&token), &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 0, "{body}");
    assert!(
        did_hosting_common::server::auth::session::get_session(&h.state.sessions_ks, &other)
            .await
            .unwrap()
            .is_some(),
        "the other session survives"
    );

    // It can end its own, and a retried logout still succeeds.
    let d = sign(revoke(&own), &browser, "authentication").await;
    let (status, body) = post(&h, Some(&token), &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 1, "{body}");
    let d = sign(revoke(&own), &alice, "authentication").await;
    let (status, body) = post(&h, None, &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"]["revokedCount"], 0, "{body}");
}

#[tokio::test]
async fn the_session_key_ends_when_the_session_expires() {
    let h = harness().await;
    let (alice, browser) = (key(15), key(16));
    h.add_acl(&alice.did, Role::Admin).await;
    let (token, _) = login(&h, &alice, Some(&browser)).await;

    // The same session's token, expired well past the validation leeway.
    let jwt = h.state.jwt_keys.as_ref().expect("jwt keys");
    let mut claims = jwt.decode(&token).expect("decode");
    claims.exp = chrono::Utc::now().timestamp() as u64 - 3600;
    let expired = jwt.encode(&claims).expect("encode");

    let (status, body) = list_as(&h, &expired, &alice, &browser).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn the_session_key_cannot_approve_a_step_up() {
    let h = harness().await;
    let (alice, browser) = (key(17), key(18));
    h.add_acl(&alice.did, Role::Admin).await;
    let (token, body) = login(&h, &alice, Some(&browser)).await;
    let session_id = body["payload"]["session"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let approve = || {
        doc(
            "auth/step-up/approve-response/0.5",
            &alice.did,
            json!({
                "subject": alice.did,
                "sessionId": session_id,
                "challenge": "c".repeat(64),
                "decision": "approved",
                "grantedAcr": "aal2",
            }),
        )
    };

    // Signed by the session key, with the attestation purpose: refused at
    // the proof gate, before anything reads the approval.
    let d = sign(approve(), &browser, "assertionMethod").await;
    let (status, body) = post(&h, Some(&token), &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(code(&body), "proofInvalid", "{body}");

    // Signed by the subject's own key in the same session: the proof is
    // accepted, and the approval is judged on its merits (there is no
    // pending step-up, so it names an unknown challenge).
    let d = sign(approve(), &alice, "assertionMethod").await;
    let (_, body) = post(&h, Some(&token), &d).await;
    assert_eq!(
        code(&body),
        "auth/step-up/approve-response:challengeUnknown",
        "{body}"
    );
}

#[tokio::test]
async fn the_session_key_cannot_mint_or_refresh_a_session() {
    let h = harness().await;
    let (alice, browser) = (key(19), key(20));
    h.add_acl(&alice.did, Role::Admin).await;
    let (token, body) = login(&h, &alice, Some(&browser)).await;
    let refresh_token = body["payload"]["tokens"]["refreshToken"]
        .as_str()
        .unwrap()
        .to_string();

    // A refresh signed by the session key is refused, even with the refresh
    // token: any proof on a refresh must be the subject's own.
    let refresh = doc(
        "auth/refresh/0.1",
        &alice.did,
        json!({ "refreshToken": refresh_token }),
    );
    let d = sign(refresh.clone(), &browser, "authentication").await;
    let (status, body) = post(&h, Some(&token), &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(code(&body), "proofInvalid", "{body}");

    // A new login signed by the session key is refused the same way.
    let (ch, sid) = challenge(&h, &alice).await;
    let d = sign(
        doc(
            "auth/authenticate/0.2",
            &alice.did,
            json!({ "challenge": ch, "sessionId": sid }),
        ),
        &browser,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, Some(&token), &d).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(code(&body), "proofInvalid", "{body}");

    // The refresh token with the subject's own proof still works.
    let d = sign(
        doc(
            "auth/refresh/0.1",
            &alice.did,
            json!({ "refreshToken": refresh_token }),
        ),
        &alice,
        "authentication",
    )
    .await;
    let (status, body) = post(&h, Some(&token), &d).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_unsupported_session_key_is_refused_and_the_challenge_survives() {
    let h = harness().await;
    let alice = key(21);
    h.add_acl(&alice.did, Role::Admin).await;
    let ch = challenge(&h, &alice).await;

    // A secp256k1 did:key (multicodec 0xe7): valid per the schema, and a key
    // type this service cannot verify a session proof from.
    let mut secp = vec![0xe7, 0x01, 0x02];
    secp.extend_from_slice(&[7u8; 32]);
    let secp_key = format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, secp)
    );

    let (_, body) = authenticate(&h, &alice, &ch, Some(&secp_key)).await;
    assert!(
        body["type"]
            .as_str()
            .unwrap_or("")
            .starts_with(&format!("{TT}trust-task-error/")),
        "{body}"
    );
    assert_eq!(
        code(&body),
        "auth/authenticate:sessionKeyUnsupported",
        "{body}"
    );
    assert_eq!(body["payload"]["details"]["requested"], secp_key);

    // Refused before the challenge was spent: the same challenge still logs in.
    let (status, body) = authenticate(&h, &alice, &ch, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

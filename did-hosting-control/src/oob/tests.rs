//! The `auth/oob/*` state machine and its checks, driven with real Ed25519
//! `did:key` signatures (starter, approver, member and service) through the
//! repo's own `TransportBoundVerifier`, and a fake clock.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use async_trait::async_trait;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use serde_json::{Value, json};
use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};

use super::service::*;
use super::store::OobStore;
use super::types::*;
use crate::signing::test_util::did_key_signer;

const ORIGIN: &str = "https://control.example.com";

struct Key {
    did: String,
    secret: Secret,
}

fn key(seed: u8) -> Key {
    let (did, secret) = did_key_signer(&[seed; 32]);
    Key { did, secret }
}

struct TestEnv {
    now: AtomicU64,
    verifier: TransportBoundVerifier,
    allowed: Mutex<HashSet<String>>,
    service: Key,
    /// How often the member verifier was reached (DID resolution).
    verifier_calls: AtomicUsize,
}

#[async_trait]
impl OobEnv for TestEnv {
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    fn member_verifier(&self) -> Option<&TransportBoundVerifier> {
        self.verifier_calls.fetch_add(1, Ordering::SeqCst);
        Some(&self.verifier)
    }
    async fn is_allowed(&self, did: &str) -> bool {
        self.allowed.lock().unwrap().contains(did)
    }
    async fn display_name(&self, _did: &str) -> Option<String> {
        Some("Alice".into())
    }
    async fn sign(&self, unsigned: Value, purpose: &str) -> Result<Value, String> {
        sign(unsigned, &self.service.secret, purpose)
            .await
            .ok_or("sign".into())
    }
}

async fn sign(unsigned: Value, secret: &Secret, purpose: &str) -> Option<Value> {
    sign_trust_task(
        &unsigned,
        secret,
        SignOptions::new()
            .with_proof_purpose(purpose)
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .ok()
}

struct World {
    env: TestEnv,
    svc: OobService,
    starter: Key,
    approver: Key,
    member: Key,
}

fn real_now() -> u64 {
    did_hosting_common::server::auth::session::now_epoch()
}

fn world() -> World {
    let service = key(1);
    let member = key(4);
    let env = TestEnv {
        now: AtomicU64::new(real_now()),
        verifier: TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver)),
        allowed: Mutex::new(HashSet::from([member.did.clone()])),
        verifier_calls: AtomicUsize::new(0),
        service,
    };
    let mut config = OobConfig::new(
        env.service.did.clone(),
        "control.example.com".into(),
        ORIGIN.into(),
    );
    config.redeem_hold = Duration::from_millis(50);
    World {
        svc: OobService::new(config),
        env,
        starter: key(2),
        approver: key(3),
        member,
    }
}

impl World {
    fn service_did(&self) -> String {
        self.env.service.did.clone()
    }

    async fn doc(&self, signer: &Key, type_uri: &str, payload: Value, purpose: &str) -> Value {
        let unsigned = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuer": signer.did,
            "recipient": self.service_did(),
            "issuedAt": rfc3339(self.env.now()),
            "payload": payload,
        });
        sign(unsigned, &signer.secret, purpose).await.unwrap()
    }

    async fn send(&self, doc: Value) -> (u16, Value) {
        self.send_from(doc, "203.0.113.7").await
    }

    async fn send_from(&self, doc: Value, ip: &str) -> (u16, Value) {
        let conn = Connection {
            ip: Some(ip.into()),
            location: None,
            browser: Some("Firefox".into()),
            os: Some("macOS".into()),
        };
        match self.svc.handle(&self.env, doc, &conn).await {
            OobReply::Document { status, body } => (status, body),
            OobReply::Approved { session, .. } => (
                200,
                json!({ "approved": session.subject, "sessionKey": session.session_key,
                        "notAfter": session.not_after, "displayName": session.display_name }),
            ),
        }
    }

    async fn request(&self) -> String {
        let d = self
            .doc(
                &self.starter,
                TYPE_REQUEST,
                json!({"purpose": "login", "mode": "scan"}),
                "assertionMethod",
            )
            .await;
        let (status, body) = self.send(d).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body["payload"]["claimDeadline"].is_u64(),
            "C9: epoch seconds"
        );
        body["payload"]["requestId"].as_str().unwrap().to_string()
    }

    async fn claim_doc(&self, request_id: &str, parent: Option<&str>) -> Value {
        let mut unsigned = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": TYPE_CLAIM,
            "issuer": self.approver.did,
            "recipient": self.service_did(),
            "issuedAt": rfc3339(self.env.now()),
            "payload": {"requestId": request_id},
        });
        if let Some(p) = parent {
            unsigned["parentThreadId"] = json!(p);
        }
        sign(unsigned, &self.approver.secret, "authentication")
            .await
            .unwrap()
    }

    async fn claim(&self, request_id: &str) -> Value {
        let d = self.claim_doc(request_id, Some(request_id)).await;
        let (status, body) = self.send(d).await;
        assert_eq!(status, 200, "{body}");
        body
    }

    /// The number, as the starter learns it from a pending redeem.
    async fn number(&self, request_id: &str) -> String {
        let d = self
            .doc(
                &self.starter,
                TYPE_REDEEM,
                json!({"requestId": request_id}),
                "assertionMethod",
            )
            .await;
        let (status, body) = self.send(d).await;
        assert_eq!(code(&body), "pending", "{status} {body}");
        body["payload"]["details"]["matchNumber"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn identify(&self, signer: &Key, request_id: &str, number: &str, purpose: &str) -> Value {
        self.doc(
            signer,
            TYPE_IDENTIFY,
            json!({"requestId": request_id, "approverKey": self.approver.did, "enteredNumber": number}),
            purpose,
        )
        .await
    }

    async fn prove_with(&self, identify: Value) -> (u16, Value) {
        let d = self
            .doc(
                &self.approver,
                TYPE_PROVE,
                json!({"identify": identify}),
                "authentication",
            )
            .await;
        self.send(d).await
    }

    async fn prove(&self, request_id: &str) -> Value {
        let n = self.number(request_id).await;
        let id = self
            .identify(&self.member, request_id, &n, "authentication")
            .await;
        let (status, body) = self.prove_with(id).await;
        assert_eq!(status, 200, "{body}");
        body
    }

    async fn grant(&self, request_id: &str, step2: &Value, decision: &str, purpose: &str) -> Value {
        self.doc(
            &self.member,
            TYPE_GRANT,
            json!({
                "requestId": request_id,
                "decision": decision,
                "sessionKey": self.starter.did,
                "approverKey": self.approver.did,
                "origin": ORIGIN,
                "contextDigest": context_digest(step2),
                "notAfter": self.env.now() + 3600,
            }),
            purpose,
        )
        .await
    }

    async fn respond_with(&self, grant: Value) -> (u16, Value) {
        let d = self
            .doc(
                &self.approver,
                TYPE_RESPOND,
                json!({"grant": grant}),
                "authentication",
            )
            .await;
        self.send(d).await
    }

    async fn redeem(&self, request_id: &str) -> (u16, Value) {
        let d = self
            .doc(
                &self.starter,
                TYPE_REDEEM,
                json!({"requestId": request_id}),
                "assertionMethod",
            )
            .await;
        self.send(d).await
    }

    fn state(&self, request_id: &str) -> OobState {
        self.svc.store().get(request_id).unwrap().state
    }

    fn advance(&self, secs: u64) {
        self.env.now.fetch_add(secs, Ordering::SeqCst);
    }
}

/// The code's last segment: `auth/oob/redeem:pending` → `pending`. The full
/// wire codes are pinned in `error_codes_follow_the_schemas`.
fn code(body: &Value) -> &str {
    let c = body["payload"]["code"].as_str().unwrap_or("");
    c.rsplit(':').next().unwrap_or(c)
}

/// Verify a service response the way a wallet would: `did:key` issuer,
/// expected proof purpose.
async fn assert_signed(body: &Value, purpose: &str) {
    assert_eq!(body["proof"]["proofPurpose"], purpose, "{body}");
    let doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(body.clone()).unwrap();
    let v = TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver));
    trust_tasks_rs::ProofVerifier::verify(&v, &doc)
        .await
        .expect("service signature verifies");
}

// ---- the whole flow --------------------------------------------------------

#[tokio::test]
async fn sign_in_end_to_end() {
    let w = world();
    let rid = w.request().await;
    assert_eq!(rid.len(), 22, "16 bytes, unpadded base64url");
    assert_eq!(w.state(&rid), OobState::Pending);

    let step1 = w.claim(&rid).await;
    assert_signed(&step1, "assertionMethod").await;
    let p1 = &step1["payload"];
    assert_eq!(p1["requestId"], rid);
    assert_eq!(p1["service"]["did"], w.service_did());
    assert_eq!(p1["origin"], ORIGIN);
    assert_eq!(p1["purpose"], "login");
    assert!(p1["decisionDeadline"].is_u64(), "C9: epoch seconds");
    assert!(
        p1.get("sessionKey").is_none(),
        "step 1 says nothing about the starter"
    );
    assert_eq!(w.state(&rid), OobState::Claimed);

    let step2 = w.prove(&rid).await;
    assert_signed(&step2, "assertionMethod").await;
    let p2 = &step2["payload"];
    assert_eq!(p2["sessionKey"], w.starter.did);
    assert_eq!(p2["identifiedAs"], w.member.did);
    assert_eq!(p2["requester"]["sameNetwork"], true);
    assert_eq!(p2["requester"]["location"], "unknown");
    assert_eq!(w.state(&rid), OobState::Identified);
    assert_eq!(
        w.svc.store().get(&rid).unwrap().step2_digest.unwrap(),
        context_digest(&step2),
        "the stored digest is of the signed step 2 response"
    );

    let grant = w.grant(&rid, &step2, "approve", "assertionMethod").await;
    let (status, ok) = w.respond_with(grant).await;
    assert_eq!(status, 200, "{ok}");
    assert_eq!(ok["payload"], json!({"status": "approved"}));
    assert!(
        ok["payload"].get("tokens").is_none(),
        "no session material to the approver"
    );
    assert_eq!(w.state(&rid), OobState::Approved);

    let (status, session) = w.redeem(&rid).await;
    assert_eq!(status, 200, "{session}");
    assert_eq!(session["approved"], w.member.did);
    assert_eq!(session["sessionKey"], w.starter.did);
    assert!(session["notAfter"].as_u64().unwrap() <= w.env.now() + 3600);
    assert_eq!(w.state(&rid), OobState::Consumed);

    // One redemption.
    let (_, again) = w.redeem(&rid).await;
    assert_eq!(code(&again), "requestExpired");
}

#[tokio::test]
async fn redeem_long_poll_wakes_on_approval() {
    let mut w = world();
    w.svc.config.redeem_hold = Duration::from_secs(10);
    let w = Arc::new(w);
    let rid = w.request().await;
    w.claim(&rid).await;
    // Read from the store: a pending redeem would hold for the full 10 s.
    let n = w.svc.store().get(&rid).unwrap().match_number.unwrap();
    let id = w.identify(&w.member, &rid, &n, "authentication").await;
    let (_, step2) = w.prove_with(id).await;

    let poller = {
        let w = w.clone();
        let rid = rid.clone();
        tokio::spawn(async move { w.redeem(&rid).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = std::time::Instant::now();
    let grant = w.grant(&rid, &step2, "approve", "assertionMethod").await;
    w.respond_with(grant).await;
    let (status, body) = poller.await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "woken, not timed out"
    );
}

// ---- request ----------------------------------------------------------------

#[tokio::test]
async fn request_refuses_other_purposes_modes_and_keys() {
    let w = world();
    let d = w
        .doc(
            &w.starter,
            TYPE_REQUEST,
            json!({"purpose": "step-up", "mode": "scan"}),
            "assertionMethod",
        )
        .await;
    assert_eq!(code(&w.send(d).await.1), "purposeUnsupported");
    let d = w
        .doc(
            &w.starter,
            TYPE_REQUEST,
            json!({"purpose": "login", "mode": "push"}),
            "assertionMethod",
        )
        .await;
    assert_eq!(code(&w.send(d).await.1), "modeUnsupported");

    // Not a did:key.
    let mut d = w
        .doc(
            &w.starter,
            TYPE_REQUEST,
            json!({"purpose": "login", "mode": "scan"}),
            "assertionMethod",
        )
        .await;
    d["issuer"] = json!("did:webvh:abc:example.com");
    assert_eq!(code(&w.send(d).await.1), "keyUnsupported");

    // Addressed elsewhere.
    let unsigned = json!({
        "id": "urn:uuid:1", "type": TYPE_REQUEST, "issuer": w.starter.did,
        "recipient": "did:example:other", "issuedAt": rfc3339(w.env.now()),
        "payload": {"purpose": "login", "mode": "scan"},
    });
    let d = sign(unsigned, &w.starter.secret, "assertionMethod")
        .await
        .unwrap();
    assert_eq!(code(&w.send(d).await.1), "notAuthorized");
}

#[tokio::test]
async fn a_tampered_or_replayed_document_is_refused() {
    let w = world();
    let mut d = w
        .doc(
            &w.starter,
            TYPE_REQUEST,
            json!({"purpose": "login", "mode": "scan"}),
            "assertionMethod",
        )
        .await;
    let replay = d.clone();
    assert_eq!(w.send(d.clone()).await.0, 200);
    assert_eq!(
        code(&w.send(replay).await.1),
        "notAuthorized",
        "replayed id"
    );

    d["id"] = json!("urn:uuid:tampered");
    assert_eq!(
        code(&w.send(d).await.1),
        "notAuthorized",
        "signature no longer covers it"
    );

    // Stale.
    let d = w
        .doc(
            &w.starter,
            TYPE_REQUEST,
            json!({"purpose": "login", "mode": "scan"}),
            "assertionMethod",
        )
        .await;
    w.advance(MAX_DOCUMENT_AGE_SECS + 1);
    assert_eq!(code(&w.send(d).await.1), "notAuthorized");
}

// ---- claim ------------------------------------------------------------------

#[tokio::test]
async fn claim_needs_parent_thread_id_equal_to_request_id() {
    let w = world();
    let rid = w.request().await;
    let d = w.claim_doc(&rid, None).await;
    assert_eq!(code(&w.send(d).await.1), "malformedRequest");
    let d = w.claim_doc(&rid, Some("AAAAAAAAAAAAAAAAAAAAAA")).await;
    assert_eq!(code(&w.send(d).await.1), "malformedRequest");
    assert_eq!(
        w.state(&rid),
        OobState::Pending,
        "a failed claim changes nothing"
    );
    w.claim(&rid).await;
}

#[tokio::test]
async fn only_the_first_claim_succeeds() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let other = key(9);
    let unsigned = json!({
        "id": "urn:uuid:second", "type": TYPE_CLAIM, "issuer": other.did,
        "recipient": w.service_did(), "issuedAt": rfc3339(w.env.now()),
        "parentThreadId": rid, "payload": {"requestId": rid},
    });
    let d = sign(unsigned, &other.secret, "authentication")
        .await
        .unwrap();
    let (status, body) = w.send(d).await;
    assert_eq!(status, 409);
    assert_eq!(code(&body), "alreadyClaimed");
    assert!(body["payload"].get("details").is_none(), "no details");
    assert_eq!(
        w.svc.store().get(&rid).unwrap().approver_key.unwrap(),
        w.approver.did,
        "the lock is unchanged"
    );
}

#[tokio::test]
async fn claim_window_closes() {
    let w = world();
    let rid = w.request().await;
    w.advance(121);
    let d = w.claim_doc(&rid, Some(&rid)).await;
    assert_eq!(code(&w.send(d).await.1), "requestExpired");
    assert_eq!(w.state(&rid), OobState::Expired);
}

#[tokio::test]
async fn an_unknown_request_is_not_found() {
    let w = world();
    let rid = "AAAAAAAAAAAAAAAAAAAAAA";
    let d = w.claim_doc(rid, Some(rid)).await;
    let (status, body) = w.send(d).await;
    assert_eq!((status, code(&body)), (404, "requestNotFound"));
}

// ---- prove ------------------------------------------------------------------

#[tokio::test]
async fn prove_from_someone_other_than_the_claimant_changes_nothing() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    let id = w.identify(&w.member, &rid, &n, "authentication").await;
    let intruder = key(8);
    let d = w
        .doc(
            &intruder,
            TYPE_PROVE,
            json!({"identify": id}),
            "authentication",
        )
        .await;
    assert_eq!(code(&w.send(d).await.1), "notClaimant");
    assert_eq!(w.state(&rid), OobState::Claimed);
}

#[tokio::test]
async fn a_non_member_is_refused_before_any_did_resolution() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    let stranger = key(7);
    let id = w.identify(&stranger, &rid, &n, "authentication").await;
    let (status, body) = w.prove_with(id).await;
    assert_eq!((status, code(&body)), (403, "notAuthorized"));
    assert_eq!(
        w.env.verifier_calls.load(Ordering::SeqCst),
        0,
        "no DID resolution"
    );
    assert_eq!(w.state(&rid), OobState::Declined, "one attempt");
}

#[tokio::test]
async fn identify_must_be_signed_for_authentication() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    let id = w.identify(&w.member, &rid, &n, "assertionMethod").await;
    let (_, body) = w.prove_with(id).await;
    assert_eq!(code(&body), "notAuthorized");
    assert_eq!(w.state(&rid), OobState::Declined);
}

#[tokio::test]
async fn identify_must_name_the_lock() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    let id = w
        .doc(
            &w.member,
            TYPE_IDENTIFY,
            json!({"requestId": rid, "approverKey": key(8).did, "enteredNumber": n}),
            "authentication",
        )
        .await;
    assert_eq!(code(&w.prove_with(id).await.1), "notAuthorized");
    assert_eq!(w.state(&rid), OobState::Declined);
}

#[tokio::test]
async fn a_wrong_number_declines_the_request() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    let wrong = format!("{:02}", (n.parse::<u8>().unwrap() + 1) % 100);
    let id = w.identify(&w.member, &rid, &wrong, "authentication").await;
    assert_eq!(code(&w.prove_with(id).await.1), "numberMismatch");
    assert_eq!(w.state(&rid), OobState::Declined);
    // No second try.
    let id = w.identify(&w.member, &rid, &n, "authentication").await;
    assert_eq!(code(&w.prove_with(id).await.1), "requestExpired");
    let (_, body) = w.redeem(&rid).await;
    assert_eq!(code(&body), "declined");
    assert_eq!(body["payload"]["details"]["state"], "declined");
}

#[tokio::test]
async fn identify_payload_has_no_extra_members() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    let id = w
        .doc(
            &w.member,
            TYPE_IDENTIFY,
            json!({"requestId": rid, "approverKey": w.approver.did, "enteredNumber": n, "ext": {}}),
            "authentication",
        )
        .await;
    assert_eq!(code(&w.prove_with(id).await.1), "notAuthorized");
}

#[tokio::test]
async fn the_decision_window_closes() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    w.advance(121);
    let id = w.identify(&w.member, &rid, &n, "authentication").await;
    assert_eq!(code(&w.prove_with(id).await.1), "requestExpired");
    assert_eq!(w.state(&rid), OobState::Expired);
    assert!(
        w.svc.store().get(&rid).unwrap().start_network.is_none(),
        "IP dropped"
    );
}

// ---- respond ----------------------------------------------------------------

#[tokio::test]
async fn grant_must_be_signed_for_assertion_method() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let step2 = w.prove(&rid).await;
    let grant = w.grant(&rid, &step2, "approve", "authentication").await;
    assert_eq!(code(&w.respond_with(grant).await.1), "notAuthorized");
    assert_eq!(w.state(&rid), OobState::Declined);
}

#[tokio::test]
async fn grant_must_match_the_step_2_context() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let step2 = w.prove(&rid).await;
    let mut other = step2.clone();
    other["payload"]["requester"]["browser"] = json!("Chrome");
    let grant = w.grant(&rid, &other, "approve", "assertionMethod").await;
    assert_eq!(code(&w.respond_with(grant).await.1), "contextMismatch");
    assert_eq!(w.state(&rid), OobState::Declined);
}

#[tokio::test]
async fn grant_must_name_the_starter_key() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let step2 = w.prove(&rid).await;
    let grant = w
        .doc(
            &w.member,
            TYPE_GRANT,
            json!({
                "requestId": rid, "decision": "approve", "sessionKey": key(8).did,
                "approverKey": w.approver.did, "origin": ORIGIN,
                "contextDigest": context_digest(&step2), "notAfter": w.env.now() + 60,
            }),
            "assertionMethod",
        )
        .await;
    assert_eq!(code(&w.respond_with(grant).await.1), "contextMismatch");
}

#[tokio::test]
async fn grant_from_another_did_is_refused() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let step2 = w.prove(&rid).await;
    let other = key(6);
    w.env.allowed.lock().unwrap().insert(other.did.clone());
    let grant = w
        .doc(
            &other,
            TYPE_GRANT,
            json!({
                "requestId": rid, "decision": "approve", "sessionKey": w.starter.did,
                "approverKey": w.approver.did, "origin": ORIGIN,
                "contextDigest": context_digest(&step2), "notAfter": w.env.now() + 60,
            }),
            "assertionMethod",
        )
        .await;
    assert_eq!(code(&w.respond_with(grant).await.1), "notAuthorized");
}

#[tokio::test]
async fn a_member_removed_before_respond_is_refused() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let step2 = w.prove(&rid).await;
    w.env.allowed.lock().unwrap().clear();
    let grant = w.grant(&rid, &step2, "approve", "assertionMethod").await;
    assert_eq!(code(&w.respond_with(grant).await.1), "notAuthorized");
}

#[tokio::test]
async fn a_declining_grant_ends_the_request() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let step2 = w.prove(&rid).await;
    let grant = w.grant(&rid, &step2, "decline", "assertionMethod").await;
    let (status, body) = w.respond_with(grant).await;
    assert_eq!(status, 200);
    assert_eq!(body["payload"], json!({"status": "declined"}));
    assert_eq!(w.state(&rid), OobState::Declined);
    let (_, body) = w.redeem(&rid).await;
    assert_eq!(code(&body), "declined");
}

/// C9: integer epoch seconds only.
#[tokio::test]
async fn grant_refuses_an_rfc3339_not_after() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let step2 = w.prove(&rid).await;
    let grant = w
        .doc(
            &w.member,
            TYPE_GRANT,
            json!({
                "requestId": rid, "decision": "approve", "sessionKey": w.starter.did,
                "approverKey": w.approver.did, "origin": ORIGIN,
                "contextDigest": context_digest(&step2), "notAfter": rfc3339(w.env.now() + 600),
            }),
            "assertionMethod",
        )
        .await;
    assert_eq!(code(&w.respond_with(grant).await.1), "notAuthorized");
    assert_eq!(w.state(&rid), OobState::Declined);
}

// ---- redeem and cancel --------------------------------------------------------

#[tokio::test]
async fn only_the_starter_can_redeem() {
    let w = world();
    let rid = w.request().await;
    let d = w
        .doc(
            &key(8),
            TYPE_REDEEM,
            json!({"requestId": rid}),
            "assertionMethod",
        )
        .await;
    assert_eq!(code(&w.send(d).await.1), "notStarter");
}

#[tokio::test]
async fn pending_redeem_reports_state_and_number_only_once_claimed() {
    let w = world();
    let rid = w.request().await;
    let (_, body) = w.redeem(&rid).await;
    assert_eq!(code(&body), "pending");
    assert_eq!(body["payload"]["details"], json!({"state": "pending"}));
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    assert_eq!(n.len(), 2);
}

#[tokio::test]
async fn one_open_poll_per_request() {
    let mut w = world();
    w.svc.config.redeem_hold = Duration::from_secs(2);
    let w = Arc::new(w);
    let rid = w.request().await;
    let first = {
        let (w, rid) = (w.clone(), rid.clone());
        tokio::spawn(async move { w.redeem(&rid).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, body) = w.redeem(&rid).await;
    assert_eq!((status, code(&body)), (429, "rateLimited"));
    first.abort();
    let _ = first.await;
    // The guard is released when the poll goes away.
    let mut w = Arc::try_unwrap(w).ok().unwrap();
    w.svc.config.redeem_hold = Duration::from_millis(10);
    assert_eq!(code(&w.redeem(&rid).await.1), "pending");
}

#[tokio::test]
async fn cancel_by_the_starter_is_seen_by_redeem() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let d = w
        .doc(
            &w.starter,
            TYPE_CANCEL,
            json!({"requestId": rid}),
            "assertionMethod",
        )
        .await;
    let (status, body) = w.send(d).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(w.state(&rid), OobState::Cancelled);
    let (_, body) = w.redeem(&rid).await;
    assert_eq!(code(&body), "declined");
    assert_eq!(body["payload"]["details"]["state"], "cancelled", "C9");
}

#[tokio::test]
async fn cancel_by_the_lock_holder_and_not_by_others() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let d = w
        .doc(
            &key(8),
            TYPE_CANCEL,
            json!({"requestId": rid}),
            "authentication",
        )
        .await;
    assert_eq!(code(&w.send(d).await.1), "notAuthorized");
    let d = w
        .doc(
            &w.approver,
            TYPE_CANCEL,
            json!({"requestId": rid}),
            "authentication",
        )
        .await;
    assert_eq!(w.send(d).await.0, 200);
    assert_eq!(w.state(&rid), OobState::Cancelled);
}

// ---- units --------------------------------------------------------------------

#[test]
fn compare_and_set_refuses_a_stale_version() {
    let store = OobStore::new();
    let now = 1_000;
    let rec = super::store::OobRecord {
        request_id: "r".into(),
        state: OobState::Pending,
        version: 0,
        purpose: "login".into(),
        origin: ORIGIN.into(),
        start_key: "k".into(),
        start_network: Some("ip".into()),
        location: "unknown".into(),
        browser: "unknown".into(),
        os: "unknown".into(),
        created_at: now,
        approver_key: None,
        match_number: None,
        identified_did: None,
        step2_digest: None,
        claim_deadline: now + 120,
        decision_deadline: None,
        grant: None,
        grant_not_after: None,
        finished_at: None,
    };
    store.create(rec.clone(), now).unwrap();
    assert!(store.compare_and_set(0, rec.next(OobState::Claimed, now)));
    assert!(
        !store.compare_and_set(0, rec.next(OobState::Claimed, now)),
        "lost race"
    );
    let cancelled = store.get("r").unwrap().next(OobState::Cancelled, now);
    assert!(
        cancelled.start_network.is_none(),
        "a final state drops the IP"
    );
    assert!(store.compare_and_set(1, cancelled));
    assert_eq!(store.record_count(), 1);
    // Swept once well past its end.
    let other = super::store::OobRecord {
        request_id: "s".into(),
        ..rec
    };
    store
        .create(other, now + super::store::FINISHED_RETENTION_SECS + 1)
        .unwrap();
    assert!(store.get("r").is_none());
}

#[test]
fn context_digest_encodings_compare_by_bytes() {
    let v = json!({"b": 1, "a": [true, null]});
    let z = context_digest(&v);
    assert!(z.starts_with("zQm"), "{z}");
    let (_, bytes) = multibase::decode(&z).unwrap();
    let u = multibase::encode(multibase::Base::Base64Url, &bytes);
    let hex: String = bytes[2..].iter().map(|b| format!("{b:02x}")).collect();
    assert!(context_digests_equal(&z, &u));
    assert!(!context_digests_equal(&z, &hex), "C9: z or u only");
    assert!(!context_digests_equal(
        &z,
        &context_digest(&json!({"b": 2}))
    ));
    assert!(!context_digests_equal(&z, "nonsense"));
    // Key order does not matter: JCS.
    assert_eq!(z, context_digest(&json!({"a": [true, null], "b": 1})));
}

#[test]
fn user_agents_parse_coarsely() {
    use super::http::parse_user_agent;
    let mac_ff =
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:131.0) Gecko/20100101 Firefox/131.0";
    assert_eq!(parse_user_agent(mac_ff), ("Firefox", "macOS"));
    let win_edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 Edg/129.0";
    assert_eq!(parse_user_agent(win_edge), ("Edge", "Windows"));
    let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
    assert_eq!(parse_user_agent(iphone), ("Safari", "iOS"));
    assert_eq!(parse_user_agent(""), ("unknown", "unknown"));
}

#[test]
fn portal_endpoint_is_the_login_page_on_the_public_origin() {
    use super::http::sign_in_portal_endpoint;
    assert_eq!(
        sign_in_portal_endpoint("https://dids.example.org/some/path").unwrap(),
        "https://dids.example.org/login"
    );
    assert_eq!(
        sign_in_portal_endpoint("http://localhost:8530").unwrap(),
        "http://localhost:8530/login"
    );
}

#[test]
fn request_ids_are_22_url_safe_characters() {
    for _ in 0..50 {
        let id = new_request_id();
        assert_eq!(id.len(), 22);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }
}

// ---- the HTTPS binding ----------------------------------------------------------

mod https {
    use super::*;
    use crate::control_tasks::harness;
    use axum::http::{HeaderMap, HeaderValue, header};
    use did_hosting_common::server::acl::Role;
    use did_hosting_common::server::auth::session::{
        get_session, get_session_by_refresh, now_epoch,
    };
    use http_body_util::BodyExt;

    const PORTAL: &str = "http://control.test";

    async fn post(
        state: &crate::server::AppState,
        doc: &Value,
        origin: Option<&str>,
    ) -> (u16, HeaderMap, Value) {
        let mut headers = HeaderMap::new();
        if let Some(o) = origin {
            headers.insert(header::ORIGIN, HeaderValue::from_str(o).unwrap());
        }
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"),
        );
        let body = serde_json::to_vec(doc).unwrap();
        let resp =
            crate::oob::http::maybe_handle(state, "198.51.100.4".parse().unwrap(), &headers, &body)
                .await
                .expect("an auth/oob document is handled here");
        let status = resp.status().as_u16();
        let h = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, h, serde_json::from_slice(&bytes).unwrap())
    }

    async fn doc(signer: &Key, type_uri: &str, payload: Value, purpose: &str) -> Value {
        doc_with(signer, type_uri, payload, purpose, None).await
    }

    async fn doc_with(
        signer: &Key,
        type_uri: &str,
        payload: Value,
        purpose: &str,
        parent: Option<&str>,
    ) -> Value {
        let mut unsigned = json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuer": signer.did,
            "recipient": harness::CONTROL,
            "issuedAt": rfc3339(now_epoch()),
            "payload": payload,
        });
        if let Some(p) = parent {
            unsigned["parentThreadId"] = json!(p);
        }
        sign(unsigned, &signer.secret, purpose).await.unwrap()
    }

    #[tokio::test]
    async fn other_documents_pass_through() {
        let (state, _dir) = harness::state().await;
        let body =
            serde_json::to_vec(&json!({"type": "https://trusttasks.org/spec/server/info/0.1"}))
                .unwrap();
        assert!(
            crate::oob::http::maybe_handle(
                &state,
                "198.51.100.4".parse().unwrap(),
                &HeaderMap::new(),
                &body
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn request_only_from_the_portal_and_never_cached() {
        let (state, _dir) = harness::state().await;
        let starter = key(2);
        let req = doc(
            &starter,
            TYPE_REQUEST,
            json!({"purpose": "login", "mode": "scan"}),
            "assertionMethod",
        )
        .await;
        let (status, h, body) = post(&state, &req, None).await;
        assert_eq!((status, code(&body)), (403, "notAuthorized"));
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");

        let req = doc(
            &starter,
            TYPE_REQUEST,
            json!({"purpose": "login", "mode": "scan"}),
            "assertionMethod",
        )
        .await;
        let (status, _, body) = post(&state, &req, Some("https://evil.example")).await;
        assert_eq!((status, code(&body)), (403, "notAuthorized"));

        let req = doc(
            &starter,
            TYPE_REQUEST,
            json!({"purpose": "login", "mode": "scan"}),
            "assertionMethod",
        )
        .await;
        let (status, h, body) = post(&state, &req, Some(PORTAL)).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        assert!(body["proof"].is_object(), "replies are signed");
    }

    #[tokio::test]
    async fn redeem_creates_a_console_session_bound_to_the_starter_key() {
        let (state, _dir) = harness::state().await;
        let m = harness::member(&state, 40, Role::Admin).await;
        let member = Key {
            did: m.did.clone(),
            secret: m.key,
        };
        let starter = key(2);
        let approver = key(3);

        let req = doc(
            &starter,
            TYPE_REQUEST,
            json!({"purpose": "login", "mode": "scan"}),
            "assertionMethod",
        )
        .await;
        let (_, _, r) = post(&state, &req, Some(PORTAL)).await;
        let rid = r["payload"]["requestId"].as_str().unwrap().to_string();

        let claim = doc_with(
            &approver,
            TYPE_CLAIM,
            json!({"requestId": rid}),
            "authentication",
            Some(&rid),
        )
        .await;
        let (status, _, step1) = post(&state, &claim, None).await;
        assert_eq!(status, 200, "{step1}");
        assert_eq!(step1["proof"]["proofPurpose"], "assertionMethod", "C5");
        assert_eq!(step1["payload"]["origin"], PORTAL);

        let n = state
            .oob
            .service_for_tests(&state)
            .store()
            .get(&rid)
            .unwrap()
            .match_number
            .unwrap();
        let identify = doc(
            &member,
            TYPE_IDENTIFY,
            json!({"requestId": rid, "approverKey": approver.did, "enteredNumber": n}),
            "authentication",
        )
        .await;
        let prove = doc(
            &approver,
            TYPE_PROVE,
            json!({"identify": identify}),
            "authentication",
        )
        .await;
        let (status, _, step2) = post(&state, &prove, None).await;
        assert_eq!(status, 200, "{step2}");
        assert_eq!(step2["payload"]["requester"]["browser"], "Firefox");
        assert_eq!(step2["payload"]["requester"]["os"], "Linux");
        assert!(
            !step2.to_string().contains("198.51.100.4"),
            "the IP is never in a response"
        );

        let grant = doc(
            &member,
            TYPE_GRANT,
            json!({
                "requestId": rid, "decision": "approve", "sessionKey": starter.did,
                "approverKey": approver.did, "origin": PORTAL,
                "contextDigest": context_digest(&step2), "notAfter": now_epoch() + 1800,
            }),
            "assertionMethod",
        )
        .await;
        let respond = doc(
            &approver,
            TYPE_RESPOND,
            json!({"grant": grant}),
            "authentication",
        )
        .await;
        let (status, _, ok) = post(&state, &respond, None).await;
        assert_eq!(status, 200, "{ok}");

        let redeem = doc(
            &starter,
            TYPE_REDEEM,
            json!({"requestId": rid}),
            "assertionMethod",
        )
        .await;
        let (status, h, body) = post(&state, &redeem, None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        let p = &body["payload"];
        assert_eq!(p["subject"], member.did);
        assert_eq!(p["amr"], json!(["did", "oob", "uv"]));
        assert!(
            p["notAfter"].as_u64().unwrap() <= now_epoch() + 1800,
            "C9: epoch seconds, bounded by the grant"
        );

        // The service's own session, with K_b as its session key.
        assert_eq!(p["displayName"], member.did, "no ACL label: the DID");
        assert!(p.get("tokens").is_none());
        let refresh = p["ext"][crate::oob::http::SESSION_EXT_NAMESPACE]["tokens"]["refreshToken"]
            .as_str()
            .expect("bearer tokens under ext (C9 conflict)");
        let sid = get_session_by_refresh(&state.sessions_ks, refresh)
            .await
            .unwrap()
            .unwrap();
        let session = get_session(&state.sessions_ks, &sid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.did, member.did);
        assert_eq!(
            session.session_pubkey_b58btc.as_deref(),
            starter.did.strip_prefix("did:key:")
        );
        assert_eq!(session.amr, vec!["did", "oob", "uv"]);
        assert!(
            session.refresh_expires_at.unwrap() <= now_epoch() + 1800,
            "never past notAfter"
        );
    }
}

#[test]
fn error_codes_follow_the_schemas() {
    use OobErrorCode::*;
    let table = [
        (PurposeUnsupported, "auth/oob/request:purposeUnsupported"),
        (ModeUnsupported, "auth/oob/request:modeUnsupported"),
        (KeyUnsupported, "auth/oob:keyUnsupported"),
        (RateLimited, "auth/oob:rateLimited"),
        (RequestNotFound, "auth/oob:requestNotFound"),
        (RequestExpired, "auth/oob:requestExpired"),
        (AlreadyClaimed, "auth/oob/claim:alreadyClaimed"),
        (NotClaimant, "auth/oob:notClaimant"),
        (NumberMismatch, "auth/oob/prove:numberMismatch"),
        (NotAuthorized, "auth/oob:notAuthorized"),
        (AlreadyDecided, "auth/oob:alreadyDecided"),
        (ContextMismatch, "auth/oob/respond:contextMismatch"),
        (Pending, "auth/oob/redeem:pending"),
        (Declined, "auth/oob/redeem:declined"),
        (NotStarter, "auth/oob:notStarter"),
        (MalformedRequest, "malformedRequest"),
    ];
    for (c, wire) in table {
        assert_eq!(c.as_str(), wire);
    }
}

#[tokio::test]
async fn prove_with_a_different_parent_thread_is_malformed() {
    let w = world();
    let rid = w.request().await;
    w.claim(&rid).await;
    let n = w.number(&rid).await;
    let id = w.identify(&w.member, &rid, &n, "authentication").await;
    let unsigned = json!({
        "id": "urn:uuid:p", "type": TYPE_PROVE, "issuer": w.approver.did,
        "recipient": w.service_did(), "issuedAt": rfc3339(w.env.now()),
        "parentThreadId": "BBBBBBBBBBBBBBBBBBBBBB", "payload": {"identify": id},
    });
    let d = sign(unsigned, &w.approver.secret, "authentication")
        .await
        .unwrap();
    let (_, body) = w.send(d).await;
    assert_eq!(body["payload"]["code"], "malformedRequest");
    assert_eq!(
        w.state(&rid),
        OobState::Claimed,
        "refused before the attempt counts"
    );
}

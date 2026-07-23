//! An ACL subject may be typed as an agent name.
//!
//! `webvh.storm.ws/@alice` is far easier to type correctly than
//! `did:webvh:QmV2DUD2u665BTFRvACvR4wDN1wBXEY5fS23Yq32cRvdSu:…`, and a mistyped
//! ACL subject fails silently — the entry simply never matches anyone.
//!
//! The property these tests exist to pin is not the convenience, though. It is
//! that resolution happens **once, at write time**, and the value stored is
//! always the DID. Names are re-claimable, so anything resolving them at
//! authorization time would hand a new holder the old holder's role with no
//! write to the ACL and nothing in an audit log.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::did_ops::{AgentNameEntry, DidRecord, agent_name_key, did_key};
use did_hosting_common::server::acl::Role;
use did_hosting_control::test_support::{TestServer, TestServerOptions};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const DOMAIN: &str = "control.example.com";
const ALICE_DID: &str = "did:webvh:abc:control.example.com:alice";

async fn harness() -> TestServer {
    TestServer::start_with(TestServerOptions::default().agent_names(true)).await
}

/// Bind `name` to a hosted DID, registry entry and index alike.
async fn bind_name(h: &TestServer, mnemonic: &str, did_id: &str, name: &str, enabled: bool) {
    let record = DidRecord {
        owner: "did:example:operator".into(),
        mnemonic: mnemonic.into(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: Some(did_id.into()),
        content_size: 0,
        disabled: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: DOMAIN.into(),
        services: None,
        agent_names: vec![AgentNameEntry {
            name: name.into(),
            enabled,
            created_at: 0,
        }],
    };
    h.state
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .expect("put record");
    h.state
        .dids_ks
        .insert_raw(agent_name_key(DOMAIN, name), mnemonic.as_bytes().to_vec())
        .await
        .expect("put index");
}

async fn create_acl(h: &TestServer, token: &str, subject: &str) -> (StatusCode, Value) {
    let resp = h
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/acl")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&json!({ "did": subject, "role": "owner" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

async fn admin(h: &TestServer) -> String {
    h.mint_token("did:example:admin", Role::Admin).await
}

/// **The load-bearing test.** The entry is keyed on the DID, not the name.
///
/// If this ever stores the name, a later re-claim of that name silently
/// transfers the role to whoever claimed it.
#[tokio::test]
async fn an_agent_name_subject_is_stored_as_its_did() {
    let h = harness().await;
    let token = admin(&h).await;
    bind_name(&h, "alice", ALICE_DID, "alice", true).await;

    let (status, body) = create_acl(&h, &token, "control.example.com/@alice").await;
    assert_eq!(status, StatusCode::CREATED, "got {body}");

    assert!(
        did_hosting_common::server::acl::get_acl_entry(&h.state.acl_ks, ALICE_DID)
            .await
            .unwrap()
            .is_some(),
        "the entry must be keyed on the DID the name resolved to"
    );
    assert!(
        did_hosting_common::server::acl::get_acl_entry(
            &h.state.acl_ks,
            "control.example.com/@alice"
        )
        .await
        .unwrap()
        .is_none(),
        "the name itself must never be stored as a key — it could never match \
         an authenticated principal, and it is re-claimable"
    );
}

/// Re-pointing the name afterwards must not move the authorization. This is
/// the attack that late resolution would enable, written out.
#[tokio::test]
async fn re_claiming_the_name_does_not_transfer_the_acl_entry() {
    let h = harness().await;
    let token = admin(&h).await;
    bind_name(&h, "alice", ALICE_DID, "alice", true).await;
    create_acl(&h, &token, "control.example.com/@alice").await;

    // Alice releases the name; Mallory claims it.
    const MALLORY_DID: &str = "did:webvh:abc:control.example.com:mallory";
    bind_name(&h, "mallory", MALLORY_DID, "alice", true).await;

    let acl = &h.state.acl_ks;
    assert!(
        did_hosting_common::server::acl::get_acl_entry(acl, ALICE_DID)
            .await
            .unwrap()
            .is_some(),
        "the original holder keeps the role that was granted to them"
    );
    assert!(
        did_hosting_common::server::acl::get_acl_entry(acl, MALLORY_DID)
            .await
            .unwrap()
            .is_none(),
        "claiming the name must not confer the role — authorization is bound to \
         the DID resolved at write time"
    );
}

/// A plain DID subject still works exactly as before.
#[tokio::test]
async fn a_plain_did_subject_is_unchanged() {
    let h = harness().await;
    let token = admin(&h).await;

    let (status, body) = create_acl(&h, &token, "did:web:example.com").await;
    assert_eq!(status, StatusCode::CREATED, "got {body}");
    assert!(
        did_hosting_common::server::acl::get_acl_entry(&h.state.acl_ks, "did:web:example.com")
            .await
            .unwrap()
            .is_some()
    );
}

/// A name nobody has bound is a validation error naming the name — never a
/// silently-created entry keyed on something that cannot authenticate.
#[tokio::test]
async fn an_unbound_name_is_refused() {
    let h = harness().await;
    let token = admin(&h).await;

    let (status, _) = create_acl(&h, &token, "control.example.com/@nobody").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        did_hosting_common::server::acl::list_acl_entries(&h.state.acl_ks)
            .await
            .unwrap()
            .iter()
            .all(|e| e.did != "control.example.com/@nobody"),
        "a refused subject must not be stored"
    );
}

/// A parked name does not resolve publicly, so it must not resolve here
/// either — the same gate the `/@name` redirect applies.
#[tokio::test]
async fn a_parked_name_is_refused() {
    let h = harness().await;
    let token = admin(&h).await;
    bind_name(&h, "alice", ALICE_DID, "alice", false).await;

    let (status, _) = create_acl(&h, &token, "control.example.com/@alice").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A name on somebody else's domain is not ours to resolve.
#[tokio::test]
async fn a_name_on_a_foreign_domain_is_refused() {
    let h = harness().await;
    let token = admin(&h).await;
    bind_name(&h, "alice", ALICE_DID, "alice", true).await;

    let (status, _) = create_acl(&h, &token, "elsewhere.example/@alice").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Spellings that canonicalise to the same name all resolve, because the
/// shared `agent-names` parser does the splitting.
#[tokio::test]
async fn scheme_and_case_variants_resolve_identically() {
    for spelling in [
        "https://control.example.com/@alice",
        "https://CONTROL.EXAMPLE.COM/@alice",
        "  control.example.com/@alice  ",
    ] {
        let h = harness().await;
        let token = admin(&h).await;
        bind_name(&h, "alice", ALICE_DID, "alice", true).await;

        let (status, body) = create_acl(&h, &token, spelling).await;
        assert_eq!(status, StatusCode::CREATED, "{spelling} → {body}");
        assert!(
            did_hosting_common::server::acl::get_acl_entry(&h.state.acl_ks, ALICE_DID)
                .await
                .unwrap()
                .is_some(),
            "{spelling} should resolve to the same DID"
        );
    }
}

/// With agent names off, a name is not a subject at all — it falls through to
/// DID validation and is rejected as malformed rather than resolved.
#[tokio::test]
async fn a_name_is_refused_when_the_feature_is_off() {
    let h = TestServer::start_with(TestServerOptions::default().agent_names(false)).await;
    let token = admin(&h).await;
    bind_name(&h, "alice", ALICE_DID, "alice", true).await;

    let (status, _) = create_acl(&h, &token, "control.example.com/@alice").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

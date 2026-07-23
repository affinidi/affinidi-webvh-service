//! HTTP-shape coverage for the agent-name REST surface
//! (`POST /api/agent-names/{set,remove,enable,disable,check}`).
//!
//! Drives the full Axum router in-process via `tower::ServiceExt::oneshot`.
//! The point of these tests is the wiring the `did_ops` unit tests can't
//! reach: that the routes are actually registered, that the JWT-Bearer gate
//! runs, and that the destructive verbs (`remove`/`disable`) reach `did_ops`
//! on a plain **aal1** session. That last one is a regression pin, not an
//! oversight: these verbs were briefly aal2 step-up-gated, but the gate was
//! uncallable — the VTA's did-hosting session is aal1 by construction — so
//! #108 moved the elevation to the agent's consent layer. The signed-log happy
//! paths stay covered by the `did_ops` unit tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::did_ops::AgentNameEntry;
use did_hosting_common::server::acl::Role;
use did_hosting_control::test_support::{TestServer, TestServerOptions};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test harness — the shared `TestServer` fixture (see
// `did_hosting_control::test_support`). Before it existed, every file here
// hand-assembled a ~25-field `AppState`; these two functions are all that is
// left of that.
// ---------------------------------------------------------------------------

async fn make_harness() -> TestServer {
    TestServer::start().await
}

async fn make_harness_with_agent_names(agent_names: bool) -> TestServer {
    TestServer::start_with(TestServerOptions::default().agent_names(agent_names)).await
}

fn post(path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn read_json(body: Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("response is valid JSON")
}

fn app(h: &TestServer) -> axum::Router {
    h.router()
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// `remove` is owner-or-admin, NOT HTTP step-up-gated: its real caller is the
/// aal1 VTA, and the destructive elevation lives at the VTA's consent layer.
/// An aal1 owner reaches `did_ops` — a malformed `didLog` is rejected there
/// with 400 (not a 403 `step_up_required`), proving the gate is gone and the
/// handler delegates.
#[tokio::test]
async fn remove_reaches_did_ops_without_step_up() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    h.add_acl(owner, Role::Owner).await;
    h.seed_did(owner, "aliceslot").await;
    let token = h.mint_token(owner, Role::Owner).await;

    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/remove",
            Some(&token),
            json!({ "mnemonic": "aliceslot", "name": "alice", "didLog": "not-a-valid-log" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// `disable` is likewise owner-or-admin, not step-up-gated.
#[tokio::test]
async fn disable_reaches_did_ops_without_step_up() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    h.add_acl(owner, Role::Owner).await;
    h.seed_did(owner, "aliceslot").await;
    let token = h.mint_token(owner, Role::Owner).await;

    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/disable",
            Some(&token),
            json!({ "mnemonic": "aliceslot", "name": "alice", "didLog": "not-a-valid-log" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// No Authorization header → 401, pinning the auth gate on a destructive verb.
#[tokio::test]
async fn remove_without_auth_is_401() {
    let h = make_harness().await;
    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/remove",
            None,
            json!({ "mnemonic": "slot", "name": "alice", "didLog": "x" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// `set` is NOT step-up-gated (an aal1 owner may bind). The route is wired and
/// delegates to `did_ops`: a malformed `didLog` is rejected there with 400
/// (not 404), proving both registration and delegation.
#[tokio::test]
async fn set_route_is_wired_and_delegates() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    h.add_acl(owner, Role::Owner).await;
    h.seed_did(owner, "aliceslot").await;
    let token = h.mint_token(owner, Role::Owner).await;

    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/set",
            Some(&token),
            json!({ "mnemonic": "aliceslot", "name": "alice", "didLog": "not-a-valid-log" }),
        ))
        .await
        .expect("router responds");
    // Reached the handler + did_ops (400), not an unrouted 404.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// `check` reports availability for a free name (aal1 is fine — it's a read).
#[tokio::test]
async fn check_reports_availability() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    h.add_acl(owner, Role::Owner).await;
    let token = h.mint_token(owner, Role::Owner).await;

    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/check",
            Some(&token),
            json!({ "name": "alice", "domain": "control.test" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(false));

    // A reserved name is unavailable but flagged, not an error.
    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/check",
            Some(&token),
            json!({ "name": "admin", "domain": "control.test" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(true));
}

/// A client must be able to learn whether this deployment serves agent names
/// *before* it has a session — it cannot probe for it, because with the feature
/// off `GET /@name` 404s exactly as an unknown name does.
#[tokio::test]
async fn server_info_advertises_agent_names_unauthenticated() {
    let h = make_harness_with_agent_names(true).await;
    let resp = app(&h)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/server-info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "server-info must stay unauthenticated"
    );
    let body = read_json(resp.into_body()).await;
    assert_eq!(
        body.get("agent_names").and_then(|v| v.as_bool()),
        Some(true)
    );
}

/// …and the answer has to track the flag, not merely be present.
#[tokio::test]
async fn server_info_reports_agent_names_off() {
    let h = make_harness_with_agent_names(false).await;
    let resp = app(&h)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/server-info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    let body = read_json(resp.into_body()).await;
    assert_eq!(
        body.get("agent_names").and_then(|v| v.as_bool()),
        Some(false)
    );
}

/// The registry reaches `GET /api/dids` as `agentNames`, so the DID list can
/// render a handle without fetching every DID.
///
/// Parked entries ride along — the list view filters them client-side, but the
/// payload is the registry, not a pre-filtered view of it, so a caller
/// auditing reservations isn't silently short-changed. Slots with no names
/// omit the key entirely, which is what puts the UI's optional field on
/// `undefined` rather than `[]`.
#[tokio::test]
async fn dids_list_exposes_the_agent_name_registry() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    h.add_acl(owner, Role::Owner).await;
    let token = h.mint_token(owner, Role::Owner).await;

    let mut named = h.seed_did(owner, "named").await;
    named.domain = "control.test".into();
    named.agent_names = vec![
        AgentNameEntry {
            name: "alice".into(),
            enabled: true,
            created_at: 7,
        },
        AgentNameEntry {
            name: "parked".into(),
            enabled: false,
            created_at: 9,
        },
    ];
    h.put_did(&named).await;
    h.seed_did(owner, "unnamed").await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/dids")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app(&h).oneshot(req).await.expect("router response");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;

    let entries = body.as_array().expect("array of DIDs");
    let named = entries
        .iter()
        .find(|e| e["mnemonic"] == "named")
        .expect("named DID present");
    assert_eq!(
        named["agentNames"],
        json!([
            { "name": "alice", "enabled": true, "createdAt": 7 },
            { "name": "parked", "enabled": false, "createdAt": 9 },
        ]),
        "camelCase registry entries, parked included"
    );

    let unnamed = entries
        .iter()
        .find(|e| e["mnemonic"] == "unnamed")
        .expect("unnamed DID present");
    assert!(
        unnamed.get("agentNames").is_none(),
        "a DID with no names must omit the key, not send []; got {unnamed}"
    );
}

// ---------------------------------------------------------------------------
// `server_names` — the server's own agent names on `GET /api/server-info`
//
// The login page shows the server's DID so an operator can grant it wallet
// access. A DID is unreadable, so the friendly handle rides along on the same
// unauthenticated request. It is resolved from the store rather than config, so
// it cannot claim a name the edge would not actually serve.
// ---------------------------------------------------------------------------

/// The default test node's `server_did` is pathless, so its slot is the root
/// one — and the name it carries is the community name, an empty local part.
async fn seed_server_own_names(h: &TestServer, did_id: &str, names: &[(&str, bool)]) {
    let record = did_hosting_common::did_ops::DidRecord {
        owner: "did:example:operator".into(),
        mnemonic: ".well-known".into(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: Some(did_id.into()),
        content_size: 0,
        disabled: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: "control.example.com".into(),
        services: None,
        agent_names: names
            .iter()
            .map(|(n, enabled)| AgentNameEntry {
                name: (*n).into(),
                enabled: *enabled,
                created_at: 0,
            })
            .collect(),
    };
    h.put_did(&record).await;
}

async fn server_names_of(h: &TestServer) -> Vec<String> {
    let resp = app(h)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/server-info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    body.get("server_names")
        .and_then(|v| v.as_array())
        .expect("server_names must always be present")
        .iter()
        .map(|v| v.as_str().expect("name is a string").to_string())
        .collect()
}

/// The community name reaches the client as an empty local part — which is
/// what it is. The client joins it with the authority to render
/// `control.example.com/@`.
#[tokio::test]
async fn server_info_reports_the_servers_own_community_name() {
    let h = make_harness().await;
    seed_server_own_names(&h, "did:webvh:test:control.example.com", &[("", true)]).await;

    assert_eq!(server_names_of(&h).await, vec![""]);
}

/// A server with no names of its own reports an empty list, not an absent
/// field — so a client never has to distinguish "none" from "too old to say".
#[tokio::test]
async fn server_info_reports_no_names_when_the_server_has_none() {
    let h = make_harness().await;
    assert!(server_names_of(&h).await.is_empty());
}

/// The load-bearing guard. `mnemonic_from_did` maps any pathless DID to the
/// single global `.well-known` slot, so without checking that the slot holds
/// *this* DID, a node whose `server_did` was minted elsewhere would advertise
/// whichever root DID happens to be hosted here.
#[tokio::test]
async fn server_info_ignores_a_root_slot_holding_a_different_did() {
    let h = make_harness().await;
    seed_server_own_names(&h, "did:webvh:other:someone-else.example", &[("", true)]).await;

    assert!(
        server_names_of(&h).await.is_empty(),
        "a root slot holding someone else's DID must not be reported as ours"
    );
}

/// A parked name does not resolve, so advertising it would hand out a handle
/// that 404s.
#[tokio::test]
async fn server_info_omits_a_parked_name() {
    let h = make_harness().await;
    seed_server_own_names(
        &h,
        "did:webvh:test:control.example.com",
        &[("", false), ("live", true)],
    )
    .await;

    assert_eq!(server_names_of(&h).await, vec!["live"]);
}

/// With agent names off nothing is served, so nothing is advertised.
#[tokio::test]
async fn server_info_reports_no_names_when_the_feature_is_off() {
    let h = make_harness_with_agent_names(false).await;
    seed_server_own_names(&h, "did:webvh:test:control.example.com", &[("", true)]).await;

    assert!(server_names_of(&h).await.is_empty());
}

// ---------------------------------------------------------------------------
// `POST /api/agent-names/resolve` — DID -> names, the reverse of `/@name`
//
// Display surfaces hold a DID and want to show its handle. There is no
// did_id -> record index and none is needed: for `did:webvh` the mnemonic is
// derivable from the identifier, so each entry is a direct read.
// ---------------------------------------------------------------------------

/// Seed a hosted DID at `mnemonic` whose identifier is `did_id`.
async fn seed_named_did(h: &TestServer, mnemonic: &str, did_id: &str, names: &[(&str, bool)]) {
    let record = did_hosting_common::did_ops::DidRecord {
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
        domain: "control.example.com".into(),
        services: None,
        agent_names: names
            .iter()
            .map(|(n, enabled)| AgentNameEntry {
                name: (*n).into(),
                enabled: *enabled,
                created_at: 0,
            })
            .collect(),
    };
    h.put_did(&record).await;
}

async fn resolve_names(h: &TestServer, token: &str, dids: &[&str]) -> (StatusCode, Value) {
    let resp = app(h)
        .oneshot(post(
            "/api/agent-names/resolve",
            Some(token),
            json!({ "dids": dids }),
        ))
        .await
        .expect("router responds");
    let status = resp.status();
    (status, read_json(resp.into_body()).await)
}

#[tokio::test]
async fn resolve_maps_dids_to_their_served_names() {
    let h = make_harness().await;
    let token = h.mint_token("did:example:owner", Role::Owner).await;
    seed_named_did(
        &h,
        "alice",
        "did:webvh:abc:control.example.com:alice",
        &[("alice", true)],
    )
    .await;

    let (status, body) =
        resolve_names(&h, &token, &["did:webvh:abc:control.example.com:alice"]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["names"]["did:webvh:abc:control.example.com:alice"],
        json!(["alice"])
    );
}

/// The root DID's community name comes back as an empty local part, which is
/// what a client joins with the authority to render `{domain}/@`.
#[tokio::test]
async fn resolve_returns_the_community_name_for_a_root_did() {
    let h = make_harness().await;
    let token = h.mint_token("did:example:owner", Role::Owner).await;
    seed_named_did(
        &h,
        ".well-known",
        "did:webvh:abc:control.example.com",
        &[("", true)],
    )
    .await;

    let (_, body) = resolve_names(&h, &token, &["did:webvh:abc:control.example.com"]).await;
    assert_eq!(
        body["names"]["did:webvh:abc:control.example.com"],
        json!([""])
    );
}

/// The guard that matters. Every pathless DID maps to the *same* `.well-known`
/// slot, so without checking `did_id` a question about a foreign root DID would
/// be answered with the local root DID's names.
#[tokio::test]
async fn resolve_does_not_answer_for_a_foreign_root_did() {
    let h = make_harness().await;
    let token = h.mint_token("did:example:owner", Role::Owner).await;
    seed_named_did(
        &h,
        ".well-known",
        "did:webvh:abc:control.example.com",
        &[("", true)],
    )
    .await;

    let (_, body) = resolve_names(&h, &token, &["did:webvh:zzz:someone-else.example"]).await;
    assert_eq!(
        body["names"],
        json!({}),
        "a foreign root DID must not inherit the local root DID's names"
    );
}

/// Parked names are registry-private: they resolve to nothing, so returning
/// one would advertise a handle that 404s.
#[tokio::test]
async fn resolve_omits_parked_names() {
    let h = make_harness().await;
    let token = h.mint_token("did:example:owner", Role::Owner).await;
    seed_named_did(
        &h,
        "bob",
        "did:webvh:abc:control.example.com:bob",
        &[("parked", false), ("live", true)],
    )
    .await;

    let (_, body) = resolve_names(&h, &token, &["did:webvh:abc:control.example.com:bob"]).await;
    assert_eq!(
        body["names"]["did:webvh:abc:control.example.com:bob"],
        json!(["live"])
    );
}

/// A DID this service does not host is reported as having no names rather than
/// resolved over the network — the service can only vouch for names it serves.
#[tokio::test]
async fn resolve_omits_unknown_and_unnamed_dids() {
    let h = make_harness().await;
    let token = h.mint_token("did:example:owner", Role::Owner).await;
    seed_named_did(&h, "quiet", "did:webvh:abc:control.example.com:quiet", &[]).await;

    let (_, body) = resolve_names(
        &h,
        &token,
        &[
            "did:webvh:abc:control.example.com:quiet",
            "did:web:elsewhere.example",
            "not-even-a-did",
        ],
    )
    .await;
    assert_eq!(body["names"], json!({}));
}

/// Unauthenticated batch lookup would be an enumeration surface even though
/// each individual answer is public.
#[tokio::test]
async fn resolve_requires_authentication() {
    let h = make_harness().await;
    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/resolve",
            None,
            json!({ "dids": ["did:webvh:abc:control.example.com:alice"] }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Each entry is a store read, so the batch is capped rather than unbounded.
#[tokio::test]
async fn resolve_rejects_an_oversized_batch() {
    let h = make_harness().await;
    let token = h.mint_token("did:example:owner", Role::Owner).await;
    let many: Vec<String> = (0..(did_hosting_control::did_ops::MAX_RESOLVE_DIDS + 1))
        .map(|i| format!("did:webvh:abc:control.example.com:slot{i}"))
        .collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();

    let (status, _) = resolve_names(&h, &token, &refs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// An unknown field is refused rather than dropped — a scope or filter a
/// caller thought it sent must not go missing silently (R3.2).
#[tokio::test]
async fn resolve_rejects_unknown_fields() {
    let h = make_harness().await;
    let token = h.mint_token("did:example:owner", Role::Owner).await;
    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/resolve",
            Some(&token),
            json!({ "dids": [], "includeParked": true }),
        ))
        .await
        .expect("router responds");
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "an unknown field must not be silently ignored"
    );
}

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

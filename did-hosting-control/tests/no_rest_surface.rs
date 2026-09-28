//! The control plane has no REST management surface.
//!
//! Every management operation is a Trust Task on `POST /api/trust-tasks` (and
//! on TSP and DIDComm). Beside it the router keeps only the liveness probe and
//! the browser sign-in routes that have no Trust Task form. Every route the
//! REST tier used to serve answers `404` — on the fallback-free router the
//! daemon merges, and on the standalone router whose SPA fallback must not
//! answer an API path with the console's HTML.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use did_hosting_control::test_support::TestServer;
use tower::ServiceExt;

/// Every route the REST management tier served, by method.
const REMOVED: &[(&str, &str)] = &[
    // Registry, domain directives, server registration and stats sync.
    ("GET", "/api/control/registry"),
    ("POST", "/api/control/registry"),
    ("GET", "/api/control/registry/srv-1"),
    ("DELETE", "/api/control/registry/srv-1"),
    ("POST", "/api/control/registry/srv-1/health"),
    (
        "POST",
        "/api/control/registry/srv-1/domains/example.com/assign",
    ),
    (
        "POST",
        "/api/control/registry/srv-1/domains/example.com/unassign",
    ),
    (
        "POST",
        "/api/control/registry/srv-1/domains/example.com/purge",
    ),
    ("POST", "/api/control/register-service"),
    ("POST", "/api/control/stats"),
    // DID slots.
    ("POST", "/api/dids/check"),
    ("POST", "/api/dids"),
    ("GET", "/api/dids"),
    ("POST", "/api/dids/register"),
    ("GET", "/api/dids/alice"),
    ("PUT", "/api/dids/alice"),
    ("DELETE", "/api/dids/alice"),
    ("PUT", "/api/witness/alice"),
    ("GET", "/api/log/alice"),
    ("GET", "/api/raw/alice"),
    ("PUT", "/api/owner/alice"),
    ("PUT", "/api/disable/alice"),
    ("PUT", "/api/enable/alice"),
    ("POST", "/api/rollback/alice"),
    // Agent names.
    ("POST", "/api/agent-names/check"),
    ("POST", "/api/agent-names/resolve"),
    ("POST", "/api/agent-names/update"),
    ("POST", "/api/agent-names/remove"),
    // Hosting domains.
    ("GET", "/api/domains"),
    ("POST", "/api/domains"),
    ("PUT", "/api/domains/example.com"),
    ("DELETE", "/api/domains/example.com"),
    ("POST", "/api/domains/example.com/disable"),
    ("POST", "/api/domains/example.com/enable"),
    ("POST", "/api/domains/example.com/set-default"),
    ("GET", "/api/me/domains"),
    // ACL.
    ("GET", "/api/acl"),
    ("POST", "/api/acl"),
    ("PUT", "/api/acl/did:example:alice"),
    ("DELETE", "/api/acl/did:example:alice"),
    // Stats, time series, overview, config, server info.
    ("GET", "/api/stats"),
    ("GET", "/api/stats/alice"),
    ("GET", "/api/timeseries"),
    ("GET", "/api/timeseries/alice"),
    ("GET", "/api/services/overview"),
    ("GET", "/api/config"),
    ("GET", "/api/server-info"),
    // The service's identity generations.
    ("GET", "/api/identity/generations"),
    ("POST", "/api/identity/generations/gen-1/retire"),
    // Step-up, wallet consent and the pass-through proxy.
    ("POST", "/api/auth/step-up/vta/start"),
    ("POST", "/api/auth/step-up/vta/finish"),
    ("GET", "/api/auth/step-up/check"),
    ("POST", "/api/task-consent/request"),
    ("GET", "/api/proxy/server/srv-1/api/health"),
    ("POST", "/api/proxy/witness/wit-1/api/trust-tasks"),
];

async fn status(app: axum::Router, method: &str, path: &str) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method(Method::from_bytes(method.as_bytes()).unwrap())
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await
    .expect("router responds")
    .status()
}

#[tokio::test]
async fn every_removed_route_is_not_found() {
    let h = TestServer::start().await;
    for (method, path) in REMOVED {
        assert_eq!(
            status(h.router(), method, path).await,
            StatusCode::NOT_FOUND,
            "{method} {path} must be gone"
        );
    }
    // The Prometheus scrape endpoint is gone too: operational metrics are the
    // admin-only `did-management/server/metrics/0.1` Trust Task.
    assert_eq!(
        status(h.router(), "GET", "/metrics").await,
        StatusCode::NOT_FOUND
    );
}

/// The standalone router's SPA fallback serves the console for client-side
/// routes, but never for an API path.
#[tokio::test]
async fn the_console_fallback_does_not_answer_api_paths() {
    let h = TestServer::start().await;
    let app = || did_hosting_control::routes::router().with_state(h.state.clone());
    for (method, path) in REMOVED {
        assert_eq!(
            status(app(), method, path).await,
            StatusCode::NOT_FOUND,
            "{method} {path} must be gone"
        );
    }
}

/// What stays: the Trust Task binding, the liveness probe, and the browser
/// sign-in routes. Each is answered by its handler (a malformed body is a
/// client error there), never a `404`.
#[tokio::test]
async fn the_trust_task_binding_and_sign_in_routes_are_served() {
    let h = TestServer::start().await;
    for (method, path) in [
        ("POST", "/api/trust-tasks"),
        ("GET", "/api/health"),
        ("POST", "/api/auth/challenge"),
        ("POST", "/api/auth/"),
        ("POST", "/api/auth/refresh"),
    ] {
        let got = status(h.router(), method, path).await;
        assert_ne!(got, StatusCode::NOT_FOUND, "{method} {path} must be served");
        assert_ne!(
            got,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} must be served"
        );
    }
}

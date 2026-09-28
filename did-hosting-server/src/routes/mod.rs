pub mod did_public;
pub(crate) mod health;
pub mod resolve_agent_name;
mod resolve_shared;
#[cfg(feature = "method-web")]
pub mod resolve_web;
// No `.well-known` route: a did:webs identifier always carries its AID
// as the final path segment, so the method has no root form. Everything
// it serves goes through the fallback dispatcher.
#[cfg(feature = "method-webs")]
pub mod resolve_webs;
#[cfg(feature = "method-webvh")]
pub mod resolve_webvh;
pub mod trust_tasks;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use crate::server::AppState;

/// Agent-name redirect routes (`/@`, `/@{name}` and `/@{name}/{*context}`).
///
/// Registered on both the full and public-only routers because a redirect is a
/// public read, like `.well-known`. The routes are always present; the handler
/// gates on `features.agent_names` at request time and 404s when the feature is
/// off, so a disabled deployment is indistinguishable from one with no names.
/// This keeps the runtime flag out of router *construction*, which is otherwise
/// compile-time.
///
/// `/@` — the community name — needs its own route: the router will not bind
/// an empty path parameter in the final segment, so `/@{name}` does not cover
/// it and the request would otherwise fall through to the DID-serving fallback
/// and be read as a mnemonic.
///
/// It is deliberately *not* paired with a `/@/{*context}` route — the
/// community name takes no path. Note that omitting the route is not by itself
/// enough: the router *will* bind an empty parameter when a wildcard follows
/// it, so `/@/context` still reaches `serve` with `name = ""`. `serve` rejects
/// an empty name for exactly that reason; see the note there.
fn agent_name_routes() -> Router<AppState> {
    Router::new()
        .route("/@", get(resolve_agent_name::serve_community))
        .route("/@{name}", get(resolve_agent_name::serve))
        .route("/@{name}/{*context}", get(resolve_agent_name::serve))
}

/// The largest Trust Task document the edge's HTTPS binding reads. A
/// `sync/batch` carries up to 512 KiB of logs (the control plane's cap), and a
/// single `sync/update` a whole log; this leaves room for the envelope.
pub const TRUST_TASKS_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// The HTTPS binding of the Trust Task listener, `POST /trust-tasks` (mounted
/// under `/api`). Never smaller than [`TRUST_TASKS_BODY_LIMIT_BYTES`], so the
/// control plane's largest batch always fits.
fn trust_task_routes(body_limit: usize) -> Router<AppState> {
    Router::new().route(
        "/trust-tasks",
        post(trust_tasks::receive).layer(DefaultBodyLimit::max(
            body_limit.max(TRUST_TASKS_BODY_LIMIT_BYTES),
        )),
    )
}

/// `POST /api/trust-tasks` on its own, for a server that serves resolution
/// and its Trust Task listener only.
pub fn trust_task_listener(body_limit: usize) -> Router<AppState> {
    Router::new().nest("/api", trust_task_routes(body_limit))
}

/// The edge's router without the DID-serving fallback: public resolution
/// (`/.well-known/*`, the agent-name redirects) and the HTTPS binding of the
/// Trust Task listener.
///
/// There is no management surface. Every write reaches an edge as a Trust
/// Task signed by its control plane, over TSP, DIDComm or `POST
/// /api/trust-tasks` alike; the edge holds no sessions and no ACL of its own.
pub fn router_without_fallback(body_limit: usize) -> Router<AppState> {
    #[allow(unused_mut)]
    let mut router = router_public_only().merge(trust_task_listener(body_limit));

    // Prometheus metrics endpoint (only when metrics feature is enabled)
    #[cfg(feature = "metrics")]
    {
        router = router.route("/metrics", get(metrics_handler));
    }
    router
}

/// Public DID-serving routes only (`.well-known` and the agent-name
/// redirects), without the Trust Task listener.
///
/// The daemon mounts this: its control plane runs the one listener, on the
/// authoritative store the embedded server reads.
pub fn router_public_only() -> Router<AppState> {
    #[allow(unused_mut)]
    let mut router = Router::new();
    #[cfg(feature = "method-webvh")]
    {
        router = router
            .route(
                "/.well-known/did.jsonl",
                get(resolve_webvh::serve_root_did_log),
            )
            .route(
                "/.well-known/did-witness.json",
                get(resolve_webvh::serve_root_witness),
            );
    }
    #[cfg(feature = "method-web")]
    {
        router = router.route(
            "/.well-known/did.json",
            get(resolve_web::serve_root_did_web),
        );
    }
    router.merge(agent_name_routes())
}

/// The edge's full router, with the DID-serving fallback.
pub fn router(body_limit: usize) -> Router<AppState> {
    router_without_fallback(body_limit).fallback(did_public::serve_public)
}

#[cfg(feature = "metrics")]
async fn metrics_handler() -> (
    axum::http::StatusCode,
    [(&'static str, &'static str); 1],
    String,
) {
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        did_hosting_common::server::metrics::render(),
    )
}

mod did_public;
pub mod health;
pub mod trust_tasks;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use crate::server::AppState;

/// The largest Trust Task document the watcher reads. A `sync/batch` carries
/// up to 512 KiB of logs (the control plane's cap), a `sync/update` a whole
/// log; this leaves room for the envelope.
pub const TRUST_TASKS_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Public DID serving only: the mirrored logs and witness proofs.
pub fn router_public_only() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/did.jsonl",
            get(did_public::serve_root_did_log),
        )
        .route(
            "/.well-known/did-witness.json",
            get(did_public::serve_root_witness),
        )
        .fallback(did_public::serve_public)
}

/// The watcher's HTTP surface: public resolution, and the HTTPS binding of
/// its Trust Task listener, `POST /api/trust-tasks`. There is no sync REST
/// API — a source pushes signed `webvh/sync/*` documents, the same on every
/// transport.
pub fn router() -> Router<AppState> {
    router_public_only()
        .route(
            "/api/trust-tasks",
            post(trust_tasks::receive).layer(DefaultBodyLimit::max(TRUST_TASKS_BODY_LIMIT_BYTES)),
        )
        // `receive`'s rate limiter reads `ConnectInfo<SocketAddr>`, supplied
        // per real connection in production by
        // `into_make_service_with_connect_info`. There is deliberately no
        // `MockConnectInfo` layer here: production must never silently fall
        // back to a shared address, so a router driven directly (`.oneshot()`
        // in tests) with no real connection behind it has to supply its own
        // mock, or `receive`'s extractor fails the request closed with a 500.
        // This layer only logs that case; it never masks it.
        .layer(axum::middleware::from_fn(
            trust_tasks::log_missing_connect_info,
        ))
}

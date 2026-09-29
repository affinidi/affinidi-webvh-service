pub mod health;
pub mod trust_tasks;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::post;

use crate::server::AppState;

/// The largest Trust Task document the witness reads. A `witness/sign`
/// carries a whole `did.jsonl`; this leaves room for the envelope.
pub const TRUST_TASKS_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// The witness's HTTP surface: the HTTPS binding of its Trust Task listener,
/// `POST /api/trust-tasks`. There is no REST management API — every operation
/// is a Trust Task, the same on every transport. (`/api/health` is added by
/// the caller, outside the security-header layer.)
pub fn router() -> Router<AppState> {
    Router::new()
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

pub mod health;
pub mod trust_tasks;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::extract::connect_info::MockConnectInfo;
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
        // `into_make_service_with_connect_info`. This is the fallback
        // `ConnectInfo`'s extractor uses when a router is driven directly
        // (`.oneshot()` in tests) with no real connection behind it; it never
        // affects a genuine request.
        .layer(MockConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            0,
        ))))
}

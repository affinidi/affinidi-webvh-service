//! The control plane's HTTP surface.
//!
//! Every management operation is a Trust Task. `POST /api/trust-tasks` is
//! its HTTPS binding, the same dispatch TSP and DIDComm reach
//! (`messaging::dispatch_trust_task_doc`), so there is no REST management
//! surface beside it. What else stays plain HTTP:
//!
//! - `GET /api/health`, the unauthenticated liveness probe;
//! - the browser sign-in ceremony that has no Trust Task form:
//!   `POST /api/auth/challenge` then `POST /api/auth/` with a SIOPv2
//!   `id_token` minted by the holder's VTA (`auth/authenticate/0.2` carries no
//!   `id_token`), and `POST /api/auth/refresh`, which renews a console session
//!   on its refresh token and the browser's bound session key (the Trust Task
//!   `auth/refresh` must be signed by the subject, whose key a browser session
//!   does not hold);
//! - the admin console's static assets, as the fallback (standalone mode).

pub(crate) mod auth;
pub mod health;
pub(crate) mod trust_tasks;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use crate::server::AppState;

/// Maximum body size accepted on `POST /api/trust-tasks` (in bytes).
/// Sized for the largest legitimate envelope a client produces
/// (`acl/list` response with a full page) plus headroom; an
/// authenticated-Owner attacker can no longer drive multi-MB JSON
/// allocations before the handler-level Admin check rejects.
pub const TRUST_TASKS_BODY_LIMIT_BYTES: usize = 64 * 1024;

/// Maximum body size accepted on the **unauthenticated** auth surface
/// (`/auth/challenge`, `/auth/`, `/auth/refresh`) in bytes.
///
/// These routes take no credential before parsing: a refresh document is a
/// type URI, a uuid and an opaque token, and the largest legitimate body here
/// is a SIOPv2 `id_token` envelope. 32 KB is generous for both.
pub const AUTH_BODY_LIMIT_BYTES: usize = 32 * 1024;

/// Build the control plane router without the UI fallback (daemon mode).
pub fn router_without_fallback() -> Router<AppState> {
    Router::new()
        .route(
            "/api/trust-tasks",
            post(trust_tasks::trust_tasks_endpoint)
                .layer(DefaultBodyLimit::max(TRUST_TASKS_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/auth/challenge",
            post(auth::challenge).layer(DefaultBodyLimit::max(AUTH_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/auth/",
            post(auth::authenticate).layer(DefaultBodyLimit::max(AUTH_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/auth/refresh",
            post(auth::refresh).layer(DefaultBodyLimit::max(AUTH_BODY_LIMIT_BYTES)),
        )
        .route("/api/health", get(health::health))
}

/// Build the full control plane router with UI fallback (standalone mode).
pub fn router() -> Router<AppState> {
    #[allow(unused_mut)]
    let mut r = router_without_fallback();

    #[cfg(feature = "ui")]
    {
        r = r.fallback(crate::frontend::static_handler);
    }

    r
}

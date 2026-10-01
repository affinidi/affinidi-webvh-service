//! The control plane's HTTP surface.
//!
//! Every management operation is a Trust Task. `POST /api/trust-tasks` is
//! its HTTPS binding, the same dispatch TSP and DIDComm reach
//! (`messaging::dispatch_trust_task_doc`), so there is no REST management
//! surface beside it. What else stays plain HTTP:
//!
//! - `GET /api/health`, the unauthenticated liveness probe;
//! - `POST /api/auth/challenge`, which mints the challenge every sign-in
//!   completes over the Trust Task surface (`auth/authenticate/0.2` for the
//!   VTI Wallet extension, which this deployment cannot re-version; `0.3` for
//!   the did-hosting UI's own wallet login and its VTA-proxied SIOP login —
//!   see `trust_tasks_auth`). The console's session refresh went the same
//!   way: `auth/refresh/0.2` over `/api/trust-tasks`, not a REST route;
//! - the admin console's static assets, as the fallback (standalone mode).

pub(crate) mod auth;
pub mod health;
pub(crate) mod trust_tasks;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use crate::server::AppState;

/// Maximum body size accepted on `POST /api/trust-tasks` (in bytes) — the
/// largest limit any type this control plane serves declares
/// (`did_hosting_common::server::trust_tasks::size`). Every type not
/// individually raised there still takes
/// `size::DEFAULT_MAX_DOCUMENT_BYTES` (64 KiB); an authenticated-Owner
/// attacker can no longer drive multi-MB JSON allocations before the
/// handler-level Admin check rejects. `dispatch_trust_task` narrows
/// further per the document's own `type` once it is read, so a request for
/// a type with a smaller limit than this route's blanket cap is still
/// refused at its own, tighter ceiling.
pub fn trust_tasks_body_limit_bytes() -> usize {
    did_hosting_common::server::trust_tasks::size::largest_max_document_bytes(
        &crate::control_tasks::SERVED_TRUST_TASK_URIS,
    )
}

/// Maximum body size accepted on the **unauthenticated** `/auth/challenge`
/// route, in bytes. It takes no credential before parsing: the body is a
/// DID and nothing else. 32 KB is generous.
pub const AUTH_BODY_LIMIT_BYTES: usize = 32 * 1024;

/// Build the control plane router without the UI fallback (daemon mode).
pub fn router_without_fallback() -> Router<AppState> {
    Router::new()
        .route(
            "/api/trust-tasks",
            post(trust_tasks::trust_tasks_endpoint)
                .layer(DefaultBodyLimit::max(trust_tasks_body_limit_bytes())),
        )
        .route(
            "/api/auth/challenge",
            post(auth::challenge).layer(DefaultBodyLimit::max(AUTH_BODY_LIMIT_BYTES)),
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

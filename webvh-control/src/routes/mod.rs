mod acl;
mod auth;
pub mod health;
mod passkey;
mod proxy;
mod registry;

use axum::Router;
use axum::routing::{any, get, post, put};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    let control = Router::new()
        .route("/registry", get(registry::list).post(registry::register))
        .route(
            "/registry/{instance_id}",
            get(registry::get).delete(registry::deregister),
        )
        .route(
            "/registry/{instance_id}/health",
            post(registry::health_check),
        );

    let api = Router::new()
        // Auth (DIDComm challenge-response)
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/", post(auth::authenticate))
        .route("/auth/refresh", post(auth::refresh))
        // Passkey (WebAuthn)
        .route("/auth/passkey/enroll/start", post(passkey::enroll_start::<AppState>))
        .route("/auth/passkey/enroll/finish", post(passkey::enroll_finish::<AppState>))
        .route("/auth/passkey/login/start", post(passkey::login_start::<AppState>))
        .route("/auth/passkey/login/finish", post(passkey::login_finish::<AppState>))
        .route("/auth/passkey/invite", post(passkey::create_invite::<AppState>))
        // ACL
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route(
            "/acl/{did}",
            put(acl::update_acl).delete(acl::delete_acl),
        )
        // Control plane
        .nest("/control", control)
        // Proxy to backend services
        .route(
            "/server/{instance_id}/{*path}",
            any(proxy::proxy_to_service),
        )
        .route(
            "/witness/{instance_id}/{*path}",
            any(proxy::proxy_to_service),
        )
        // Health
        .route("/health", get(health::health));

    let router = Router::new().nest("/api", api);

    // SPA fallback when UI feature is enabled
    #[cfg(feature = "ui")]
    let router = router.fallback(crate::frontend::static_handler);

    router
}

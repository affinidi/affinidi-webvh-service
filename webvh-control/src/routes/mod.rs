mod acl;
mod auth;
mod did_manage;
pub mod health;
mod passkey;
mod proxy;
mod registry;

use axum::Router;
use axum::extract::DefaultBodyLimit;
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
        )
        .route(
            "/register-service",
            post(registry::register_service),
        );

    // Upload routes with a custom body-size limit (DID log + witness)
    let upload_routes = Router::new()
        .route("/dids/{*mnemonic}", put(did_manage::upload_did))
        .route("/witness/{*mnemonic}", put(did_manage::upload_witness))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)); // 10 MB

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
        // DID management (authenticated)
        .route("/dids/check", post(did_manage::check_name))
        .route("/dids", post(did_manage::request_uri).get(did_manage::list_dids))
        .route(
            "/dids/{*mnemonic}",
            get(did_manage::get_did).delete(did_manage::delete_did),
        )
        .route("/log/{*mnemonic}", get(did_manage::get_did_log))
        .route("/disable/{*mnemonic}", put(did_manage::disable_did))
        .route("/enable/{*mnemonic}", put(did_manage::enable_did))
        .route("/rollback/{*mnemonic}", post(did_manage::rollback_did))
        .route("/raw/{*mnemonic}", get(did_manage::get_raw_log))
        // Stats (DID count from control plane)
        .route("/stats", get(did_manage::get_server_stats))
        // Control plane
        .nest("/control", control)
        // Proxy to backend services (moved to /proxy/ prefix to avoid
        // ambiguity with DID management witness routes)
        .route(
            "/proxy/server/{instance_id}/{*path}",
            any(proxy::proxy_to_service),
        )
        .route(
            "/proxy/witness/{instance_id}/{*path}",
            any(proxy::proxy_to_service),
        )
        // Merge upload routes (body-limited) into the API router
        .merge(upload_routes);

    let router = Router::new().nest("/api", api);

    // SPA fallback when UI feature is enabled
    #[cfg(feature = "ui")]
    let router = router.fallback(crate::frontend::static_handler);

    router
}

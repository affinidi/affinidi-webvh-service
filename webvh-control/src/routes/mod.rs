mod acl;
mod auth;
mod did_manage;
pub mod health;
mod passkey;
mod proxy;
mod registry;
mod stats_sync;

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
        .route("/register-service", post(registry::register_service));

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
        .route(
            "/auth/passkey/enroll/start",
            post(passkey::enroll_start::<AppState>),
        )
        .route(
            "/auth/passkey/enroll/finish",
            post(passkey::enroll_finish::<AppState>),
        )
        .route(
            "/auth/passkey/login/start",
            post(passkey::login_start::<AppState>),
        )
        .route(
            "/auth/passkey/login/finish",
            post(passkey::login_finish::<AppState>),
        )
        .route(
            "/auth/passkey/invite",
            post(passkey::create_invite::<AppState>),
        )
        // ACL
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route("/acl/{did}", put(acl::update_acl).delete(acl::delete_acl))
        // DID management (authenticated)
        .route("/dids/check", post(did_manage::check_name))
        .route(
            "/dids",
            post(did_manage::request_uri).get(did_manage::list_dids),
        )
        .route(
            "/dids/{*mnemonic}",
            get(did_manage::get_did).delete(did_manage::delete_did),
        )
        .route("/log/{*mnemonic}", get(did_manage::get_did_log))
        .route("/disable/{*mnemonic}", put(did_manage::disable_did))
        .route("/enable/{*mnemonic}", put(did_manage::enable_did))
        .route("/rollback/{*mnemonic}", post(did_manage::rollback_did))
        .route("/raw/{*mnemonic}", get(did_manage::get_raw_log))
        // Stats & time-series
        .route("/stats", get(did_manage::get_server_stats))
        .route("/stats/{*mnemonic}", get(did_manage::get_did_stats))
        .route("/timeseries", get(did_manage::get_server_timeseries))
        .route(
            "/timeseries/{*mnemonic}",
            get(did_manage::get_did_timeseries),
        )
        // Service overview (topology + health + stats)
        .route("/services/overview", get(did_manage::get_services_overview))
        // Config
        .route("/config", get(did_manage::get_config))
        // Stats sync (server → control plane, no auth — servers self-identify by DID)
        .route("/control/stats", post(stats_sync::receive_stats))
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

    #[allow(unused_mut)]
    let mut router = Router::new().nest("/api", api);

    // Prometheus metrics endpoint (only when metrics feature is enabled)
    #[cfg(feature = "metrics")]
    {
        router = router.route("/metrics", get(metrics_handler));
    }

    // SPA fallback when UI feature is enabled
    #[cfg(feature = "ui")]
    let router = router.fallback(crate::frontend::static_handler);

    router
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
        affinidi_webvh_common::server::metrics::render(),
    )
}

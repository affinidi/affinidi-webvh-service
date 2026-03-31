mod acl;
mod auth;
mod config;
mod didcomm;
pub(crate) mod did_manage;
mod did_public;
pub(crate) mod health;
mod stats;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};

use crate::server::AppState;

pub fn router(upload_body_limit: usize) -> Router<AppState> {
    // Upload routes with a custom body-size limit
    let upload_routes = Router::new()
        .route("/dids/{*mnemonic}", put(did_manage::upload_did))
        .route("/witness/{*mnemonic}", put(did_manage::upload_witness))
        .layer(DefaultBodyLimit::max(upload_body_limit));

    // API routes live under /api/ so they never collide with DID serving paths.
    let api = Router::new()
        // Auth routes
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/", post(auth::authenticate))
        .route("/auth/refresh", post(auth::refresh))
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
        // Rollback + raw log (authenticated)
        .route("/rollback/{*mnemonic}", post(did_manage::rollback_did))
        .route("/recover/{*mnemonic}", post(did_manage::recover_did))
        .route("/raw/{*mnemonic}", get(did_manage::get_raw_log))
        // Services (authenticated, any role)
        .route("/services", get(config::get_services))
        // Stats (authenticated — in-memory only, authoritative stats on control plane)
        .route("/stats", get(stats::get_server_stats))
        .route("/stats/{*mnemonic}", get(stats::get_did_stats))
        // DIDComm protocol endpoint
        .route("/didcomm", post(didcomm::handle))
        // Server config (admin only)
        .route("/config", get(config::get_config))
        // ACL management (admin only)
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route(
            "/acl/{did}",
            put(acl::update_acl).delete(acl::delete_acl),
        )
        // Merge upload routes (body-limited) into the API router
        .merge(upload_routes);

    Router::new()
        .nest("/api", api)
        // .well-known routes (specific routes take priority over fallback)
        .route(
            "/.well-known/did.jsonl",
            get(did_public::serve_root_did_log),
        )
        .route(
            "/.well-known/did.json",
            get(did_public::serve_root_did_web),
        )
        .route(
            "/.well-known/did-witness.json",
            get(did_public::serve_root_witness),
        )
        // Combined fallback: DID serving (no SPA - UI moved to webvh-control)
        .fallback(did_public::serve_public)
}

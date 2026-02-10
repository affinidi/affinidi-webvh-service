mod acl;
mod auth;
pub(crate) mod did_manage;
mod did_public;
mod health;
mod passkey;
mod stats;

use axum::Router;
use axum::routing::{delete, get, post, put};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    // API routes live under /api/ so they never collide with SPA client routes.
    let api = Router::new()
        // Health
        .route("/health", get(health::health))
        // Auth routes
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/", post(auth::authenticate))
        .route("/auth/refresh", post(auth::refresh))
        // DID management (authenticated)
        .route("/dids/check", post(did_manage::check_name))
        .route("/dids", post(did_manage::request_uri).get(did_manage::list_dids))
        .route(
            "/dids/{*mnemonic}",
            get(did_manage::get_did)
                .put(did_manage::upload_did)
                .delete(did_manage::delete_did),
        )
        // Witness upload (separate prefix so the catch-all doesn't eat /witness)
        .route("/witness/{*mnemonic}", put(did_manage::upload_witness))
        // Stats (authenticated)
        .route("/stats", get(stats::get_server_stats))
        .route("/stats/{*mnemonic}", get(stats::get_did_stats))
        // Passkey auth routes
        .route("/auth/passkey/enroll/start", post(passkey::enroll_start))
        .route("/auth/passkey/enroll/finish", post(passkey::enroll_finish))
        .route("/auth/passkey/login/start", post(passkey::login_start))
        .route("/auth/passkey/login/finish", post(passkey::login_finish))
        // ACL management (admin only)
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route("/acl/{did}", delete(acl::delete_acl));

    Router::new()
        .nest("/api", api)
        // .well-known routes (specific routes take priority over fallback)
        .route(
            "/.well-known/did.jsonl",
            get(did_public::serve_root_did_log),
        )
        .route(
            "/.well-known/did-witness.json",
            get(did_public::serve_root_witness),
        )
        // Combined fallback: DID serving + SPA
        .fallback(did_public::serve_public)
}

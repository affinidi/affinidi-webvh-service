mod acl;
mod auth;
mod did_manage;
mod did_public;
mod health;
mod stats;

use axum::Router;
use axum::routing::{delete, get, post, put};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        // Health
        .route("/health", get(health::health))
        // Auth routes
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/", post(auth::authenticate))
        .route("/auth/refresh", post(auth::refresh))
        // DID management (authenticated)
        .route("/dids", post(did_manage::request_uri).get(did_manage::list_dids))
        .route(
            "/dids/{mnemonic}",
            put(did_manage::upload_did).delete(did_manage::delete_did),
        )
        .route("/dids/{mnemonic}/witness", put(did_manage::upload_witness))
        // Public DID serving
        .route("/{mnemonic}/did.jsonl", get(did_public::serve_did_log))
        .route(
            "/{mnemonic}/did-witness.json",
            get(did_public::serve_witness),
        )
        .route(
            "/.well-known/did.jsonl",
            get(did_public::serve_root_did_log),
        )
        .route(
            "/.well-known/did-witness.json",
            get(did_public::serve_root_witness),
        )
        // Stats (authenticated)
        .route("/stats/{mnemonic}", get(stats::get_did_stats))
        // ACL management (admin only)
        .route("/acl", get(acl::list_acl).post(acl::create_acl))
        .route("/acl/{did}", delete(acl::delete_acl))
}

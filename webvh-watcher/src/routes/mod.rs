mod did_public;
pub mod health;
mod sync;

use axum::Router;
use axum::routing::{get, post};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    let sync_routes = Router::new()
        .route("/did", post(sync::receive_did))
        .route("/delete", post(sync::receive_delete));

    let api = Router::new()
        .nest("/sync", sync_routes)
        .route("/health", get(health::health));

    Router::new()
        .nest("/api", api)
        // Public DID serving
        .route(
            "/.well-known/did.jsonl",
            get(did_public::serve_root_did_log),
        )
        .route(
            "/.well-known/did-witness.json",
            get(did_public::serve_root_witness),
        )
        .fallback(did_public::serve_public)
}

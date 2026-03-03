pub mod acl;
pub mod auth;
pub mod didcomm;
pub mod health;
pub mod witness;

use axum::Router;
use axum::routing::{delete, get, post, put};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    let api = Router::new()
        // Auth
        .route("/auth/challenge", post(auth::challenge))
        .route("/auth/", post(auth::authenticate))
        .route("/auth/refresh", post(auth::refresh))
        // Witnesses (admin)
        .route("/witnesses", post(witness::create_witness))
        .route("/witnesses", get(witness::list_witnesses))
        .route("/witnesses/{witness_id}", get(witness::get_witness))
        .route("/witnesses/{witness_id}", delete(witness::delete_witness))
        // Proof signing (any authenticated user)
        .route("/proof/{witness_id}", post(witness::sign_proof))
        // ACL (admin)
        .route("/acl", get(acl::list_acl))
        .route("/acl", post(acl::create_acl))
        .route("/acl/{did}", put(acl::update_acl))
        .route("/acl/{did}", delete(acl::delete_acl))
        // DIDComm
        .route("/didcomm", post(didcomm::handle));

    Router::new().nest("/api", api)
}

//! `GET /api/server-info` — public-facing identity + capability surface.
//!
//! Exposes the server's DID so clients (the web UI, SDK consumers) can bind
//! signed trust-task envelopes to this specific verifier per
//! [`trust_tasks_rs`] SPEC §4.8.2 audience binding. Without this, the UI has
//! no way to set `recipient` on its outgoing envelopes and the framework
//! rejects them with `malformed_request`.
//!
//! Unauthenticated by design — the server DID is published in its did.jsonl
//! anyway and clients need it BEFORE they can sign anything.
//!
//! Returns `server_did = null` when the operator hasn't configured one. A
//! client that gets `null` should refuse to send any signed trust task (the
//! server would reject it at dispatch time anyway).

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::server::AppState;

#[derive(Serialize)]
pub struct ServerInfoResponse {
    /// The server's DID (did:webvh:…), used as the `recipient` /
    /// audience-binding value on signed trust-task envelopes.
    pub server_did: Option<String>,
}

pub async fn server_info(State(state): State<AppState>) -> Json<ServerInfoResponse> {
    Json(ServerInfoResponse {
        server_did: state.config.server_did.clone(),
    })
}

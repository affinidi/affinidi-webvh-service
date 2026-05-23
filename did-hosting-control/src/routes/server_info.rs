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
use did_hosting_common::server::pending_purge::parse_grace_string;
use serde::Serialize;

use crate::server::AppState;

#[derive(Serialize)]
pub struct ServerInfoResponse {
    /// The server's DID (did:webvh:…), used as the `recipient` /
    /// audience-binding value on signed trust-task envelopes.
    pub server_did: Option<String>,
    /// Soft-delete grace, in seconds, applied when a domain is
    /// disabled. The UI uses this to render the deletion countdown
    /// in the disable confirm dialog (before the request lands and
    /// `purgeAt` is known). `null` if config is missing or
    /// unparseable — in that case the UI falls back to a generic
    /// message without a specific duration.
    pub disable_purge_grace_seconds: Option<u64>,
}

pub async fn server_info(State(state): State<AppState>) -> Json<ServerInfoResponse> {
    let disable_purge_grace_seconds =
        parse_grace_string(&state.config.hosting.disable_purge_grace).ok();
    Json(ServerInfoResponse {
        server_did: state.config.server_did.clone(),
        disable_purge_grace_seconds,
    })
}

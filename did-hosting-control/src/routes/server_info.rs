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
use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::identity::mnemonic_from_did;
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
    /// Whether this deployment serves agent names (`/@alice` -> 302).
    ///
    /// Advertised here, on the unauthenticated endpoint, because a client
    /// needs it *before* it has a session in order to decide whether to offer
    /// the feature at all — and because it cannot be detected behaviourally:
    /// with the feature off `GET /@name` returns 404, deliberately
    /// indistinguishable from "no such name".
    pub agent_names: bool,

    /// The agent names this server's *own* DID currently serves, as bare local
    /// parts. Empty for the overwhelmingly common case of a server with none.
    ///
    /// A **community name** (`{domain}/@`, the shape a service that owns its
    /// domain has) appears here as an empty string — which is what it is, and
    /// what `AgentName` reports for the form. Clients render it by joining
    /// authority and local part, so the empty case needs no special handling.
    ///
    /// Sending this unauthenticated adds no disclosure. Every name here is
    /// already published in the server's own `alsoKnownAs` and already served
    /// as a public redirect by the edge — and `server_did`, the thing a name
    /// would point at, is in this very response. It says nothing about *hosted*
    /// DIDs, which is the association that must not leak.
    pub server_names: Vec<String>,
}

/// The served agent names of the server's own DID, best-effort.
///
/// Resolved rather than configured, so it cannot drift from what the edge
/// actually serves. Every failure — feature off, no configured DID, an
/// unparseable identifier, no such record, a store error — yields an empty
/// list: this endpoint is informational, and a login page that renders one
/// fewer chip is a better failure than one that will not load.
///
/// The `did_id` equality check is the load-bearing line. `mnemonic_from_did`
/// maps an identifier to the slot it *would* occupy, which for a root DID is
/// the single global `.well-known` slot — so without confirming the slot holds
/// this exact DID, a deployment whose configured `server_did` was minted
/// elsewhere would advertise whichever root DID happens to be hosted here.
async fn server_agent_names(state: &AppState) -> Vec<String> {
    if !state.config.features.agent_names {
        return Vec::new();
    }
    let Some(did) = state.config.server_did.as_deref() else {
        return Vec::new();
    };
    let Some(mnemonic) = mnemonic_from_did(did) else {
        return Vec::new();
    };
    let Ok(Some(record)) = state.dids_ks.get::<DidRecord>(did_key(&mnemonic)).await else {
        return Vec::new();
    };
    if record.did_id.as_deref() != Some(did) || record.disabled || record.deleted_at.is_some() {
        return Vec::new();
    }
    record
        .agent_names
        .iter()
        .filter(|e| e.enabled)
        .map(|e| e.name.clone())
        .collect()
}

pub async fn server_info(State(state): State<AppState>) -> Json<ServerInfoResponse> {
    let disable_purge_grace_seconds =
        parse_grace_string(&state.config.hosting.disable_purge_grace).ok();
    let server_names = server_agent_names(&state).await;
    Json(ServerInfoResponse {
        server_did: state.config.server_did.clone(),
        disable_purge_grace_seconds,
        agent_names: state.config.features.agent_names,
        server_names,
    })
}

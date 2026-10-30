//! Shared helpers for per-method resolve handlers (T25).
//!
//! Shared between methods: the trusted-CIDR-gated request-host extractor
//! (T19), and the gate every method checks before serving (the DID's
//! record and the domain). The cached-content reader (`serve_content`)
//! is webvh-only — did:web has its own custom did.json extraction —
//! so it lives in `resolve_webvh` directly. Adding a method that
//! reuses the cached jsonl/witness shape (e.g. did:webs) would lift
//! `serve_content` back up here.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::request::Parts;
use did_hosting_common::server::domain::{
    HostHeaders, assert_resolution_allowed, resolve_request_host,
};

use crate::did_ops::{self, DidRecord};
use crate::error::AppError;
use crate::server::AppState;
use crate::store::KeyspaceHandle;

/// `mnemonic`'s record, which decides whether it may be served: from the
/// gate cache when this process keeps one, else the store.
pub(super) async fn gate_record(
    state: &AppState,
    mnemonic: &str,
) -> Result<Option<Arc<DidRecord>>, AppError> {
    match &state.gate_cache {
        Some(gate) => gate.record(mnemonic).await,
        None => Ok(state
            .dids_ks
            .get::<DidRecord>(did_ops::did_key(mnemonic))
            .await?
            .map(Arc::new)),
    }
}

/// The handle to read content through on a content-cache miss: the gate
/// cache's strongly consistent one when this process keeps a gate cache
/// (nothing else would ever correct a stale miss there), else the ordinary
/// one.
pub(super) fn content_ks(state: &AppState) -> &KeyspaceHandle {
    match &state.gate_cache {
        Some(gate) => gate.dids_ks(),
        None => &state.dids_ks,
    }
}

/// [`assert_resolution_allowed`], against the gate cache's domains when
/// this process keeps one.
pub(super) async fn assert_gate_allows(
    state: &AppState,
    request_host: Option<&str>,
    did_id: &str,
) -> Result<(), AppError> {
    match &state.gate_cache {
        Some(gate) => gate.domains().await?.assert_allowed(request_host, did_id),
        None => assert_resolution_allowed(&state.store, request_host, did_id).await,
    }
}

/// Extract the intended request host using the trusted-CIDR-gated
/// resolver. Reads everything off [`Parts`] so the helper works for
/// both production (axum serving with `ConnectInfo` layer) and tests
/// (`oneshot`, where there is no connect info — peer IP is then
/// `None` and the resolver falls back to the literal `Host` header).
///
/// Returns an owned `String` so callers don't have to thread the
/// `Parts` lifetime through subsequent helpers; the cost is one short
/// copy per request, which is negligible against the KV reads that
/// follow.
pub(super) fn extract_request_host(
    parts: &Parts,
    trusted_cidrs: &[ipnetwork::IpNetwork],
) -> Option<String> {
    let headers = &parts.headers;
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    let forwarded = headers.get("forwarded").and_then(|v| v.to_str().ok());
    let xfh = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok());
    let h = HostHeaders {
        host,
        forwarded,
        x_forwarded_host: xfh,
    };
    let peer_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    resolve_request_host(&h, peer_ip, trusted_cidrs).map(|s| s.to_string())
}

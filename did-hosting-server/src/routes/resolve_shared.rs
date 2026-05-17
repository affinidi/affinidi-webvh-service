//! Shared helpers for per-method resolve handlers (T25).
//!
//! Today only the trusted-CIDR-gated request-host extractor (T19) is
//! shared between methods. The cached-content reader (`serve_content`)
//! is webvh-only — did:web has its own custom did.json extraction —
//! so it lives in `resolve_webvh` directly. Adding a method that
//! reuses the cached jsonl/witness shape (e.g. did:webs) would lift
//! `serve_content` back up here.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::request::Parts;
use did_hosting_common::server::domain::{HostHeaders, resolve_request_host};

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

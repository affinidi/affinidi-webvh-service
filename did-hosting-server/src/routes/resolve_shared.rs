//! Shared helpers for per-method resolve handlers (T25).
//!
//! Shared by every method (did:webvh, did:webs, did:web and the agent-name
//! route): the trusted-CIDR-gated request-host extractor (T19), the gate
//! every method checks before serving (the DID's record and the domain),
//! the per-request [`Lookup`] (host, `If-None-Match` and the slot's record,
//! read once however many dispatchers look at it), and [`content_response`]
//! (`ETag` / `304` and `Cache-Control` for resolved content). Each method
//! reads its own content: webvh's cached-log reader (`serve_content`) lives
//! in `resolve_webvh`, and `resolve_webs` derives did:webs' `did.json`
//! from the stored `keri.cesr` (memoised in memory, never stored).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use did_hosting_common::server::domain::{
    HostHeaders, assert_resolution_allowed, resolve_request_host,
};

use crate::cache::{CachedContent, if_none_match_hits};
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

/// One resolve request, read once: its host and `If-None-Match`, and the
/// record of the slot it names, fetched at most once however many method
/// dispatchers look at it (`did.json` is tried as did:webs, then did:web).
pub struct Lookup<'a> {
    pub(super) state: &'a AppState,
    host: Option<String>,
    if_none_match: Option<String>,
    record: tokio::sync::OnceCell<(String, Option<Arc<DidRecord>>)>,
}

impl<'a> Lookup<'a> {
    pub fn new(state: &'a AppState, parts: &Parts) -> Self {
        Self {
            state,
            host: extract_request_host(parts, &state.trusted_proxy_cidrs),
            if_none_match: parts
                .headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            record: tokio::sync::OnceCell::new(),
        }
    }

    pub(super) fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// `mnemonic`'s gate record ([`gate_record`]), read once per request.
    pub(super) async fn record(&self, mnemonic: &str) -> Result<Option<Arc<DidRecord>>, AppError> {
        if let Some((held, record)) = self.record.get() {
            if held == mnemonic {
                return Ok(record.clone());
            }
            return gate_record(self.state, mnemonic).await;
        }
        let (held, record) = self
            .record
            .get_or_try_init(|| async {
                Ok::<_, AppError>((
                    mnemonic.to_string(),
                    gate_record(self.state, mnemonic).await?,
                ))
            })
            .await?;
        if held == mnemonic {
            Ok(record.clone())
        } else {
            gate_record(self.state, mnemonic).await
        }
    }
}

/// The response for resolved content: `304 Not Modified` when the request's
/// `If-None-Match` names its tag, else the bytes. Both carry the strong
/// `ETag` and the `[server.resolve_cache]` `Cache-Control` — explicit, so the
/// global `no-store` middleware leaves it, letting CDNs and browsers
/// revalidate hot DIDs instead of refetching them.
pub(super) fn content_response(
    lookup: &Lookup<'_>,
    content_type: &str,
    content: &CachedContent,
) -> Response {
    let cache_control = lookup.state.config.server.resolve_cache.header_value();
    let not_modified = lookup
        .if_none_match
        .as_deref()
        .is_some_and(|h| if_none_match_hits(h, &content.etag));
    if not_modified {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, content.etag.to_string()),
                (header::CACHE_CONTROL, cache_control),
            ],
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (header::ETAG, content.etag.to_string()),
            (header::CACHE_CONTROL, cache_control),
        ],
        content.bytes.clone(),
    )
        .into_response()
}

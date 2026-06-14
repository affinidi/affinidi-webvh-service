//! did:webvh resolution routes (T25, gated by `method-webvh`).
//!
//! Handles the webvh artifacts published at each hosted DID's HTTPS
//! origin:
//!
//! - `GET /{*mnemonic}/did.jsonl` — the canonical did:webvh log.
//! - `GET /{*mnemonic}/did-witness.json` — the witness file (optional).
//! - `GET /.well-known/did.jsonl` / `/.well-known/did-witness.json` —
//!   the root-DID variants (mnemonic = `.well-known`).
//!
//! ## Why this module exists separately from did:web (`resolve_web`)
//!
//! The two methods are wire-incompatible: webvh delivers an append-
//! only jsonl log + a sidecar witness, did:web delivers a single
//! `did.json` document. They share storage (T12's `DidRecord` carries
//! the method tag) but they don't share HTTP paths. Putting them in
//! separate modules makes the feature gating ergonomic — a
//! `method-web`-only build never compiles the jsonl handler, and the
//! corresponding route is never registered.

use axum::extract::{Request, State};
use axum::http::{StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use did_hosting_common::server::domain::assert_resolution_allowed;
use tracing::debug;

use super::resolve_shared::extract_request_host;
use crate::did_ops::{self, DidRecord};
use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;

/// Serve stored content for a mnemonic, optionally incrementing
/// resolve stats. Runs the disabled/deleted check and the T21
/// resolve-side safety check before returning bytes.
async fn serve_content(
    state: &AppState,
    mnemonic: &str,
    key: &str,
    content_type: &str,
    track_stats: bool,
    request_host: Option<&str>,
) -> Result<Response, AppError> {
    if let Some(record) = state
        .dids_ks
        .get::<DidRecord>(did_ops::did_key(mnemonic))
        .await?
    {
        if record.disabled || record.deleted_at.is_some() {
            return Err(AppError::NotFound(format!("content not found: {mnemonic}")));
        }
        if let Some(host) = request_host
            && let Some(ref did_id) = record.did_id
        {
            assert_resolution_allowed(&state.store, host, did_id).await?;
        }
    }

    let content = if let Some(cached) = state.did_cache.get(key) {
        #[cfg(feature = "metrics")]
        did_hosting_common::server::metrics::inc_cache_hit();
        cached
    } else {
        #[cfg(feature = "metrics")]
        did_hosting_common::server::metrics::inc_cache_miss();
        let data = state
            .dids_ks
            .get_raw(key)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("content not found: {mnemonic}")))?;
        state.did_cache.insert(key.to_string(), data.clone());
        std::sync::Arc::new(data)
    };

    if track_stats && let Some(ref collector) = state.stats_collector {
        collector.record_resolve(mnemonic);
        #[cfg(feature = "metrics")]
        did_hosting_common::server::metrics::inc_resolve();
    }

    debug!(mnemonic = %mnemonic, size = content.len(), content_type, "content resolved");

    // DID logs are content-addressed (the SCID prevents content drift) and
    // safe to cache aggressively. Setting an explicit `Cache-Control` here
    // overrides the global `no-store` security middleware so CDNs and
    // browsers can serve hot DIDs without round-tripping the origin.
    Ok((
        StatusCode::OK,
        [
            ("content-type", content_type),
            ("cache-control", "public, max-age=300"),
        ],
        (*content).clone(),
    )
        .into_response())
}

/// `GET /.well-known/did.jsonl` — root-DID webvh log.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/.well-known/did.jsonl",
    tag = "resolve",
    responses(
        (status = 200, description = "Root DID's did:webvh log (JSONL)", content_type = "application/jsonl+json"),
        (status = 404, description = "No root DID hosted on this domain"),
    ),
))]
pub async fn serve_root_did_log(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _) = request.into_parts();
    let host = extract_request_host(&parts, &state.trusted_proxy_cidrs);
    serve_content(
        &state,
        ".well-known",
        "content:.well-known:log",
        "application/jsonl+json",
        true,
        host.as_deref(),
    )
    .await
}

/// `GET /.well-known/did-witness.json` — root-DID witness.
pub async fn serve_root_witness(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _) = request.into_parts();
    let host = extract_request_host(&parts, &state.trusted_proxy_cidrs);
    serve_content(
        &state,
        ".well-known",
        "content:.well-known:witness",
        "application/json",
        false,
        host.as_deref(),
    )
    .await
}

/// Catch-all dispatcher for webvh artifacts.
///
/// Returns:
/// - `Some(response)` when the URL is a webvh artifact path. This is
///   terminal — the caller serves whatever's in the response (200 with
///   bytes, 404 for unknown mnemonic, 503 for disabled-domain, etc.).
/// - `None` when the URL has no webvh suffix. The caller should try
///   the next method's dispatcher (e.g. [`super::resolve_web::dispatch`]).
pub async fn dispatch(state: &AppState, parts: &Parts) -> Option<Response> {
    let path = parts.uri.path().trim_start_matches('/');
    let host = extract_request_host(parts, &state.trusted_proxy_cidrs);
    let host = host.as_deref();

    if let Some(mnemonic) = path.strip_suffix("/did.jsonl")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return Some(e.into_response());
        }
        let key = format!("content:{mnemonic}:log");
        return Some(
            serve_content(state, mnemonic, &key, "application/jsonl+json", true, host)
                .await
                .unwrap_or_else(|e| e.into_response()),
        );
    }

    if let Some(mnemonic) = path.strip_suffix("/did-witness.json")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return Some(e.into_response());
        }
        let key = format!("content:{mnemonic}:witness");
        return Some(
            serve_content(state, mnemonic, &key, "application/json", false, host)
                .await
                .unwrap_or_else(|e| e.into_response()),
        );
    }

    None
}

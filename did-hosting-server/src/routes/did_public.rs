use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use did_hosting_common::did::build_did_web_id;
use did_hosting_common::server::domain::{
    HostHeaders, assert_resolution_allowed, resolve_request_host,
};

use tracing::debug;

use crate::did_ops::{self, DidRecord};
use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;

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
fn extract_request_host(parts: &Parts, trusted_cidrs: &[ipnetwork::IpNetwork]) -> Option<String> {
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

/// Serve stored content for a mnemonic, optionally incrementing resolve stats.
async fn serve_content(
    state: &AppState,
    mnemonic: &str,
    key: &str,
    content_type: &str,
    track_stats: bool,
    request_host: Option<&str>,
) -> Result<Response, AppError> {
    // Check if the DID is disabled — return 404 to avoid leaking state.
    if let Some(record) = state
        .dids_ks
        .get::<DidRecord>(did_ops::did_key(mnemonic))
        .await?
    {
        if record.disabled || record.deleted_at.is_some() {
            return Err(AppError::NotFound(format!("content not found: {mnemonic}")));
        }
        // Resolve-side safety check (T21): the request must arrive on
        // the same domain the DID was issued on, and that domain must
        // still be active. Skipped when no KS_DOMAINS entries exist
        // (legacy / fresh-install state) — see
        // `assert_resolution_allowed` for the permissive-on-empty
        // contract.
        if let Some(host) = request_host
            && let Some(ref did_id) = record.did_id
        {
            assert_resolution_allowed(&state.store, host, did_id).await?;
        }
    }

    // Check cache first (hot path — read lock only, no I/O, Arc clone only)
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

/// Serve a did:web document (`did.json`) for the given mnemonic.
///
/// Loads the JSONL log, constructs the expected `did:web` identifier,
/// checks `alsoKnownAs`, and returns the rewritten DID document with
/// `application/did+json` content type.
///
/// ## T23 audit — relationship to `crate::method::web::Web`
///
/// This handler predates the multi-method work (T10/T24) and is a
/// **did:webvh → did:web bridge**: the underlying storage is the
/// same `content_log_key(mnemonic)` jsonl that `serve_public` reads
/// for did:webvh, and `extract_did_web_document` finds a did:web-
/// shaped snapshot inside the log entries (matched against the
/// document's `alsoKnownAs` field).
///
/// `crate::method::web::Web` (T24) is a **separate** path: a
/// standalone did:web method with its own apply_update (overwrite
/// semantics), no log, independent of any webvh storage. Both paths
/// must coexist:
///
/// - **Tenant has did:webvh AND wants a did:web view** (e.g. cross-
///   compat with older resolvers) → existing bridge here.
/// - **Tenant only wants did:web** (no log, simpler storage) →
///   T24's `methods/web.rs` via the trait-routed path that lands
///   with T25.
///
/// The dispatch decision at request time will be made by T25's
/// per-method route registration based on the stored `DidRecord`'s
/// method tag (T12). Until T25 ships, this handler keeps serving
/// `*/did.json` requests; the trait-routed path is a separate write
/// surface (`Web::apply_update`) with its own future read path.
///
/// Decision: **wrap, don't remove.** The semantics are different
/// enough that a single handler would either lose the dual-view
/// behaviour or grow a method-discriminator branch. Two handlers
/// with clear names is cleaner.
async fn serve_did_web(
    state: &AppState,
    mnemonic: &str,
    request_host: Option<&str>,
) -> Result<Response, AppError> {
    // Check if the DID is disabled and run resolve-side safety check.
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

    let content_bytes = state
        .dids_ks
        .get_raw(did_ops::content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("content not found: {mnemonic}")))?;

    let jsonl = String::from_utf8(content_bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))?;

    let server_url = state.config.public_base_url();
    let expected_did_web = build_did_web_id(&server_url, mnemonic)
        .map_err(|e| AppError::Internal(format!("failed to build did:web id: {e}")))?;

    let doc_bytes = did_ops::extract_did_web_document(&jsonl, &expected_did_web)
        .ok_or_else(|| AppError::NotFound(format!("no did:web document for: {mnemonic}")))?;

    // Track stats (same counters as did:webvh resolves)
    if let Some(ref collector) = state.stats_collector {
        collector.record_resolve(mnemonic);
    }

    debug!(mnemonic = %mnemonic, size = doc_bytes.len(), "did:web document resolved");

    Ok((
        StatusCode::OK,
        [("content-type", "application/did+json")],
        doc_bytes,
    )
        .into_response())
}

/// GET /.well-known/did.json — serve the root did:web document (mnemonic = ".well-known")
pub async fn serve_root_did_web(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _) = request.into_parts();
    let host = extract_request_host(&parts, &state.trusted_proxy_cidrs);
    serve_did_web(&state, ".well-known", host.as_deref()).await
}

/// GET /.well-known/did.jsonl — serve the root DID log (mnemonic = ".well-known")
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

/// GET /.well-known/did-witness.json — serve the root witness
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

/// Combined fallback handler: serves DID documents for any path ending
/// in `/did.jsonl` or `/did-witness.json`, and falls through to the SPA
/// static handler (when the `ui` feature is enabled) for everything else.
pub async fn serve_public(State(state): State<AppState>, request: Request) -> Response {
    let (parts, _) = request.into_parts();
    let path = parts.uri.path().trim_start_matches('/').to_string();
    let host = extract_request_host(&parts, &state.trusted_proxy_cidrs);
    let host = host.as_deref();

    // Check for DID log: <mnemonic>/did.jsonl
    if let Some(mnemonic) = path.strip_suffix("/did.jsonl")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return e.into_response();
        }
        let key = format!("content:{mnemonic}:log");
        return match serve_content(&state, mnemonic, &key, "application/jsonl+json", true, host)
            .await
        {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };
    }

    // Check for witness: <mnemonic>/did-witness.json
    if let Some(mnemonic) = path.strip_suffix("/did-witness.json")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return e.into_response();
        }
        let key = format!("content:{mnemonic}:witness");
        return match serve_content(&state, mnemonic, &key, "application/json", false, host).await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };
    }

    // Check for did:web document: <mnemonic>/did.json
    if let Some(mnemonic) = path.strip_suffix("/did.json")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return e.into_response();
        }
        return match serve_did_web(&state, mnemonic, host).await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };
    }

    // No matching DID path — return 404
    StatusCode::NOT_FOUND.into_response()
}

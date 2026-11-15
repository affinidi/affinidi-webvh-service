use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use did_hosting_common::server::mnemonic::validate_mnemonic;
use tracing::debug;

use crate::error::AppError;
use crate::server::AppState;
use crate::watcher_ops::{self, WatcherRecord};

/// A strong entity tag for `content`: its SHA-256, quoted.
fn entity_tag(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(content);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("\"{hex}\"")
}

/// Whether an `If-None-Match` header names `etag` (or is `*`). Weak
/// validators match by their opaque tag, as RFC 9110 §13.1.2's weak
/// comparison allows for `If-None-Match`.
fn none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|tag| tag == "*" || tag.trim_start_matches("W/") == etag)
}

/// Serve stored content for a mnemonic, from one store read when the
/// disabled slots are tracked in memory.
async fn serve_content(
    state: &AppState,
    headers: &HeaderMap,
    mnemonic: &str,
    key: &str,
    content_type: &str,
) -> Result<Response, AppError> {
    let not_found = || AppError::NotFound(format!("content not found: {mnemonic}"));
    // A disabled DID answers 404, so its state does not leak.
    let disabled = match state.disabled.is_disabled(mnemonic) {
        Some(disabled) => disabled,
        None => state
            .dids_ks
            .get::<WatcherRecord>(watcher_ops::did_key(mnemonic))
            .await?
            .is_some_and(|r| r.disabled),
    };
    if disabled {
        return Err(not_found());
    }

    let content = state.dids_ks.get_raw(key).await?.ok_or_else(not_found)?;

    debug!(mnemonic = %mnemonic, size = content.len(), content_type, "content resolved");

    // Public DID resolution is cacheable (content-addressed via the SCID).
    // Setting Cache-Control here overrides the global `no-store` security
    // middleware so CDNs / browsers can serve mirrored DIDs without
    // hitting the watcher origin every time. The policy is
    // `[server.resolve_cache]`.
    let cache_control = state.config.server.resolve_cache.header_value();
    let etag = entity_tag(&content);
    if none_match(headers, &etag) {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag.as_str()),
                (header::CACHE_CONTROL, cache_control.as_str()),
            ],
        )
            .into_response());
    }
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, cache_control.as_str()),
            (header::ETAG, etag.as_str()),
        ],
        content,
    )
        .into_response())
}

/// GET /.well-known/did.jsonl — serve the root DID log
pub async fn serve_root_did_log(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    serve_content(
        &state,
        &headers,
        ".well-known",
        "content:.well-known:log",
        "application/jsonl+json",
    )
    .await
}

/// GET /.well-known/did-witness.json — serve the root witness
pub async fn serve_root_witness(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    serve_content(
        &state,
        &headers,
        ".well-known",
        "content:.well-known:witness",
        "application/json",
    )
    .await
}

/// Combined fallback handler: serves DID documents for any path ending
/// in `/did.jsonl` or `/did-witness.json`.
pub async fn serve_public(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    // Resolution is read-only: anything but GET or HEAD is refused before a
    // lookup, so it neither returns the content nor counts as a resolve.
    if method != Method::GET && method != Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, HeaderValue::from_static("GET, HEAD"))],
        )
            .into_response();
    }
    let path = uri.path().trim_start_matches('/');

    // Check for DID log: <mnemonic>/did.jsonl
    if let Some(mnemonic) = path.strip_suffix("/did.jsonl")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return e.into_response();
        }
        let key = format!("content:{mnemonic}:log");
        return match serve_content(&state, &headers, mnemonic, &key, "application/jsonl+json").await
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
        return match serve_content(&state, &headers, mnemonic, &key, "application/json").await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };
    }

    // No matching DID path — return 404
    StatusCode::NOT_FOUND.into_response()
}

use affinidi_webvh_common::did::build_did_web_id;
use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use tracing::debug;

use crate::did_ops::{self, DidRecord};
use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;

/// Serve stored content for a mnemonic, optionally incrementing resolve stats.
async fn serve_content(
    state: &AppState,
    mnemonic: &str,
    key: &str,
    content_type: &str,
    track_stats: bool,
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
    }

    // Check cache first (hot path — read lock only, no I/O, Arc clone only)
    let content = if let Some(cached) = state.did_cache.get(key) {
        #[cfg(feature = "metrics")]
        affinidi_webvh_common::server::metrics::inc_cache_hit();
        cached
    } else {
        #[cfg(feature = "metrics")]
        affinidi_webvh_common::server::metrics::inc_cache_miss();
        let data = state
            .dids_ks
            .get_raw(key)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("content not found: {mnemonic}")))?;
        state.did_cache.insert(key.to_string(), data.clone());
        std::sync::Arc::new(data)
    };

    if track_stats {
        if let Some(ref collector) = state.stats_collector {
            collector.record_resolve(mnemonic);
        }
        #[cfg(feature = "metrics")]
        affinidi_webvh_common::server::metrics::inc_resolve();
    }

    debug!(mnemonic = %mnemonic, size = content.len(), content_type, "content resolved");

    Ok((
        StatusCode::OK,
        [("content-type", content_type)],
        (*content).clone(),
    )
        .into_response())
}

/// Serve a did:web document (`did.json`) for the given mnemonic.
///
/// Loads the JSONL log, constructs the expected `did:web` identifier,
/// checks `alsoKnownAs`, and returns the rewritten DID document with
/// `application/did+json` content type.
async fn serve_did_web(state: &AppState, mnemonic: &str) -> Result<Response, AppError> {
    // Check if the DID is disabled
    if let Some(record) = state
        .dids_ks
        .get::<DidRecord>(did_ops::did_key(mnemonic))
        .await?
    {
        if record.disabled || record.deleted_at.is_some() {
            return Err(AppError::NotFound(format!("content not found: {mnemonic}")));
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
pub async fn serve_root_did_web(State(state): State<AppState>) -> Result<Response, AppError> {
    serve_did_web(&state, ".well-known").await
}

/// GET /.well-known/did.jsonl — serve the root DID log (mnemonic = ".well-known")
pub async fn serve_root_did_log(State(state): State<AppState>) -> Result<Response, AppError> {
    serve_content(
        &state,
        ".well-known",
        "content:.well-known:log",
        "application/jsonl+json",
        true,
    )
    .await
}

/// GET /.well-known/did-witness.json — serve the root witness
pub async fn serve_root_witness(State(state): State<AppState>) -> Result<Response, AppError> {
    serve_content(
        &state,
        ".well-known",
        "content:.well-known:witness",
        "application/json",
        false,
    )
    .await
}

/// Combined fallback handler: serves DID documents for any path ending
/// in `/did.jsonl` or `/did-witness.json`, and falls through to the SPA
/// static handler (when the `ui` feature is enabled) for everything else.
pub async fn serve_public(State(state): State<AppState>, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Check for DID log: <mnemonic>/did.jsonl
    if let Some(mnemonic) = path.strip_suffix("/did.jsonl")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return e.into_response();
        }
        let key = format!("content:{mnemonic}:log");
        return match serve_content(&state, mnemonic, &key, "application/jsonl+json", true).await {
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
        return match serve_content(&state, mnemonic, &key, "application/json", false).await {
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
        return match serve_did_web(&state, mnemonic).await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };
    }

    // No matching DID path — return 404
    StatusCode::NOT_FOUND.into_response()
}

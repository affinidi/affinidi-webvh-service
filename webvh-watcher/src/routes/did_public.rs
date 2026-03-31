use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use affinidi_webvh_common::server::mnemonic::validate_mnemonic;
use tracing::debug;

use crate::error::AppError;
use crate::server::AppState;
use crate::watcher_ops::{self, WatcherRecord};

/// Serve stored content for a mnemonic.
async fn serve_content(
    state: &AppState,
    mnemonic: &str,
    key: &str,
    content_type: &str,
) -> Result<Response, AppError> {
    // Check if the DID is disabled — return 404 to avoid leaking state.
    if let Some(record) = state
        .dids_ks
        .get::<WatcherRecord>(watcher_ops::did_key(mnemonic))
        .await?
    {
        if record.disabled {
            return Err(AppError::NotFound(format!("content not found: {mnemonic}")));
        }
    }

    let content = state
        .dids_ks
        .get_raw(key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("content not found: {mnemonic}")))?;

    debug!(mnemonic = %mnemonic, size = content.len(), content_type, "content resolved");

    Ok((StatusCode::OK, [("content-type", content_type)], content).into_response())
}

/// GET /.well-known/did.jsonl — serve the root DID log
pub async fn serve_root_did_log(State(state): State<AppState>) -> Result<Response, AppError> {
    serve_content(
        &state,
        ".well-known",
        "content:.well-known:log",
        "application/jsonl+json",
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
    )
    .await
}

/// Combined fallback handler: serves DID documents for any path ending
/// in `/did.jsonl` or `/did-witness.json`.
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
        return match serve_content(&state, mnemonic, &key, "application/jsonl+json").await {
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
        return match serve_content(&state, mnemonic, &key, "application/json").await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };
    }

    // No matching DID path — return 404
    StatusCode::NOT_FOUND.into_response()
}

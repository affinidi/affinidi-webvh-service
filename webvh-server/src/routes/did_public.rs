use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use tracing::debug;

use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;
use crate::stats;

/// Inner helper: serve the DID log for a given mnemonic.
async fn serve_did_log_inner(state: &AppState, mnemonic: &str) -> Result<Response, AppError> {
    let key = format!("content:{mnemonic}:log");
    let content = state
        .dids_ks
        .get_raw(key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID log not found: {mnemonic}")))?;

    // Increment resolve stats (best-effort, don't fail the request)
    let _ = stats::increment_resolves(&state.stats_ks, mnemonic).await;

    debug!(mnemonic = %mnemonic, size = content.len(), "DID log resolved");

    Ok((
        StatusCode::OK,
        [("content-type", "application/jsonl+json")],
        content,
    )
        .into_response())
}

/// Inner helper: serve the witness for a given mnemonic.
async fn serve_witness_inner(state: &AppState, mnemonic: &str) -> Result<Response, AppError> {
    let key = format!("content:{mnemonic}:witness");
    let content = state
        .dids_ks
        .get_raw(key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("witness not found: {mnemonic}")))?;

    debug!(mnemonic = %mnemonic, size = content.len(), "DID witness resolved");

    Ok((
        StatusCode::OK,
        [("content-type", "application/json")],
        content,
    )
        .into_response())
}

/// GET /.well-known/did.jsonl — serve the root DID log (mnemonic = ".well-known")
pub async fn serve_root_did_log(State(state): State<AppState>) -> Result<Response, AppError> {
    serve_did_log_inner(&state, ".well-known").await
}

/// GET /.well-known/did-witness.json — serve the root witness
pub async fn serve_root_witness(State(state): State<AppState>) -> Result<Response, AppError> {
    serve_witness_inner(&state, ".well-known").await
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
        return match serve_did_log_inner(&state, mnemonic).await {
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
        return match serve_witness_inner(&state, mnemonic).await {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };
    }

    // Fall through to SPA static handler or 404
    #[cfg(feature = "ui")]
    {
        crate::frontend::static_handler(uri).await
    }

    #[cfg(not(feature = "ui"))]
    {
        StatusCode::NOT_FOUND.into_response()
    }
}

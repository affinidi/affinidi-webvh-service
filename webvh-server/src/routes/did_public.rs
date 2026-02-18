use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use tracing::debug;

use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;
use crate::stats;

/// Serve stored content for a mnemonic, optionally incrementing resolve stats.
async fn serve_content(
    state: &AppState,
    mnemonic: &str,
    key: &str,
    content_type: &str,
    track_stats: bool,
) -> Result<Response, AppError> {
    let content = state
        .dids_ks
        .get_raw(key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("content not found: {mnemonic}")))?;

    if track_stats {
        let _ = stats::increment_resolves(&state.stats_ks, mnemonic).await;
        let _ = stats::record_timeseries_resolve(&state.stats_ks, mnemonic).await;
    }

    debug!(mnemonic = %mnemonic, size = content.len(), content_type, "content resolved");

    Ok((StatusCode::OK, [("content-type", content_type)], content).into_response())
}

/// GET /.well-known/did.jsonl — serve the root DID log (mnemonic = ".well-known")
pub async fn serve_root_did_log(State(state): State<AppState>) -> Result<Response, AppError> {
    serve_content(&state, ".well-known", "content:.well-known:log", "application/jsonl+json", true).await
}

/// GET /.well-known/did-witness.json — serve the root witness
pub async fn serve_root_witness(State(state): State<AppState>) -> Result<Response, AppError> {
    serve_content(&state, ".well-known", "content:.well-known:witness", "application/json", false).await
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

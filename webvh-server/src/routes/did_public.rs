use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;
use crate::server::AppState;
use crate::stats;

/// GET /{mnemonic}/did.jsonl
pub async fn serve_did_log(
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Response, AppError> {
    let key = format!("content:{mnemonic}:log");
    let content = state
        .dids_ks
        .get_raw(key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID log not found: {mnemonic}")))?;

    // Increment resolve stats (best-effort, don't fail the request)
    let _ = stats::increment_resolves(&state.stats_ks, &mnemonic).await;

    Ok((
        StatusCode::OK,
        [("content-type", "application/jsonl+json")],
        content,
    )
        .into_response())
}

/// GET /{mnemonic}/did-witness.json
pub async fn serve_witness(
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Response, AppError> {
    let key = format!("content:{mnemonic}:witness");
    let content = state
        .dids_ks
        .get_raw(key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("witness not found: {mnemonic}")))?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/json")],
        content,
    )
        .into_response())
}

/// GET /.well-known/did.jsonl — serve the root DID log (mnemonic = ".well-known")
pub async fn serve_root_did_log(State(state): State<AppState>) -> Result<Response, AppError> {
    let key = "content:.well-known:log";
    let content = state
        .dids_ks
        .get_raw(key)
        .await?
        .ok_or_else(|| AppError::NotFound("root DID log not found".into()))?;

    let _ = stats::increment_resolves(&state.stats_ks, ".well-known").await;

    Ok((
        StatusCode::OK,
        [("content-type", "application/jsonl+json")],
        content,
    )
        .into_response())
}

/// GET /.well-known/did-witness.json — serve the root witness
pub async fn serve_root_witness(State(state): State<AppState>) -> Result<Response, AppError> {
    let key = "content:.well-known:witness";
    let content = state
        .dids_ks
        .get_raw(key)
        .await?
        .ok_or_else(|| AppError::NotFound("root witness not found".into()))?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/json")],
        content,
    )
        .into_response())
}

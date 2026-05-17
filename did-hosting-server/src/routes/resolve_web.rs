//! did:web resolution routes (T25, gated by `method-web`).
//!
//! Handles the canonical did:web surface — a single `did.json`
//! document per mnemonic, served from the same HTTPS origin:
//!
//! - `GET /{*mnemonic}/did.json` — per-mnemonic.
//! - `GET /.well-known/did.json` — root-DID (mnemonic = `.well-known`).
//!
//! ## Storage shape
//!
//! Today this handler is a did:webvh → did:web **bridge**: the stored
//! bytes are still the webvh jsonl log, and
//! [`did_hosting_common::did_ops::extract_did_web_document`] finds a
//! did:web-shaped snapshot inside the log via `alsoKnownAs`. T24's
//! standalone [`did_hosting_common::method::web::Web`] is a separate
//! write path with overwrite semantics; once T26 generalises the
//! request body and routes pure-did:web writes here, this handler
//! grows a branch on the loaded [`crate::did_ops::DidRecord`]'s
//! `method` tag to pick between "extract from jsonl" and "serve
//! `data` directly".

use axum::extract::{Request, State};
use axum::http::{StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use did_hosting_common::did::build_did_web_id;
use did_hosting_common::server::domain::assert_resolution_allowed;
use tracing::debug;

use super::resolve_shared::extract_request_host;
use crate::did_ops::{self, DidRecord};
use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;

/// Serve the `did.json` view for `mnemonic`. Used by both the catch-
/// all dispatcher and the `.well-known` root handler.
async fn serve_did_web(
    state: &AppState,
    mnemonic: &str,
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

/// `GET /.well-known/did.json` — root-DID did:web document.
pub async fn serve_root_did_web(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _) = request.into_parts();
    let host = extract_request_host(&parts, &state.trusted_proxy_cidrs);
    serve_did_web(&state, ".well-known", host.as_deref()).await
}

/// Catch-all dispatcher for did:web artifacts.
///
/// Returns:
/// - `Some(response)` when the URL ends in `/did.json`. Terminal.
/// - `None` when the URL has no did.json suffix.
pub async fn dispatch(state: &AppState, parts: &Parts) -> Option<Response> {
    let path = parts.uri.path().trim_start_matches('/');
    let host = extract_request_host(parts, &state.trusted_proxy_cidrs);
    let host = host.as_deref();

    if let Some(mnemonic) = path.strip_suffix("/did.json")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return Some(e.into_response());
        }
        return Some(
            serve_did_web(state, mnemonic, host)
                .await
                .unwrap_or_else(|e| e.into_response()),
        );
    }

    None
}

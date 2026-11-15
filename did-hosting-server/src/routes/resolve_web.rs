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
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use did_hosting_common::did::build_did_web_id;
use tracing::debug;

use super::resolve_shared::{Lookup, assert_gate_allows, content_ks, content_response};
use crate::cache::{CachedContent, ContentCache};
use crate::did_ops;
use crate::error::AppError;
use crate::mnemonic::validate_mnemonic;
use crate::server::AppState;

/// Serve the `did.json` view for `mnemonic`. Used by both the catch-
/// all dispatcher and the `.well-known` root handler.
async fn serve_did_web(lookup: &Lookup<'_>, mnemonic: &str) -> Result<Response, AppError> {
    let state = lookup.state;
    let record = lookup.record(mnemonic).await?;
    if let Some(record) = &record {
        if record.disabled || record.deleted_at.is_some() {
            return Err(AppError::NotFound(format!("content not found: {mnemonic}")));
        }
        if let Some(ref did_id) = record.did_id {
            assert_gate_allows(state, lookup.host(), did_id).await?;
        }
    }

    // The extracted document is cached only behind a gate cache (an edge, or
    // a daemon running its control plane), where every change to the DID
    // clears it in-process, and only for a DID with a record: without one
    // there is no gate to refuse a deleted DID before the cache would
    // answer. Anywhere else, read the store as before, so a change made
    // elsewhere shows on the next resolve.
    let cacheable = state.gate_cache.is_some() && record.is_some();
    let key = ContentCache::did_web_document_key(mnemonic);
    let cached = cacheable.then(|| state.did_cache.get(&key)).flatten();
    let doc = if let Some(cached) = cached {
        #[cfg(feature = "metrics")]
        did_hosting_common::server::metrics::inc_cache_hit();
        cached
    } else {
        #[cfg(feature = "metrics")]
        did_hosting_common::server::metrics::inc_cache_miss();
        let generation = state.did_cache.generation();
        let content_bytes = content_ks(state)
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
        if cacheable {
            state.did_cache.insert(generation, key, doc_bytes)
        } else {
            CachedContent::new(doc_bytes)
        }
    };

    if let Some(ref collector) = state.stats_collector {
        collector.record_resolve(mnemonic);
    }

    debug!(mnemonic = %mnemonic, size = doc.bytes.len(), "did:web document resolved");

    Ok(content_response(lookup, "application/did+json", &doc))
}

/// `GET /.well-known/did.json` — root-DID did:web document.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/.well-known/did.json",
    tag = "resolve",
    responses(
        (status = 200, description = "Root DID's did:web document (for a did:webvh root, its did:web form)", content_type = "application/did+json"),
        (status = 404, description = "No root DID hosted on this domain"),
        (status = 429, description = "This address's resolution rate exceeds `[server.resolve_rate_limit]`; see `Retry-After`", content_type = "application/json"),
    ),
))]
pub async fn serve_root_did_web(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, _) = request.into_parts();
    let lookup = Lookup::new(&state, &parts);
    serve_did_web(&lookup, ".well-known").await
}

/// Catch-all dispatcher for did:web artifacts.
///
/// Returns:
/// - `Some(response)` when the URL ends in `/did.json`. Terminal.
/// - `None` when the URL has no did.json suffix.
pub async fn dispatch(lookup: &Lookup<'_>, parts: &Parts) -> Option<Response> {
    let path = parts.uri.path().trim_start_matches('/');

    if let Some(mnemonic) = path.strip_suffix("/did.json")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_mnemonic(mnemonic) {
            return Some(e.into_response());
        }
        return Some(
            serve_did_web(lookup, mnemonic)
                .await
                .unwrap_or_else(|e| e.into_response()),
        );
    }

    None
}

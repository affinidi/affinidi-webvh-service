//! `did:webs` resolution routes (gated by `method-webs`).
//!
//! A `did:webs` identifier publishes two artifacts at the same path:
//!
//! ```text
//! GET /{*mnemonic}/keri.cesr   the key event log — the authority
//! GET /{*mnemonic}/did.json    the document it implies — a cache
//! ```
//!
//! There is deliberately **no `.well-known` handler here**. The AID is
//! always the final path segment of a `did:webs` identifier, so unlike
//! `did:web` and `did:webvh` this method has no root form to serve.
//!
//! ## Why `did.json` is derived, not stored
//!
//! Only `keri.cesr` carries authority; `did.json` is a cache of what the
//! verified key state implies, and a conforming resolver derives its own
//! copy and treats a disagreement as an error. So this service stores
//! one blob — the CESR stream, under the same `content:{mnemonic}:log`
//! key webvh uses for its jsonl — and derives the document per request.
//!
//! Deriving costs a full key-event-log verification per `did.json` hit,
//! and that is a deliberate trade. The alternative is a second cache
//! entry, which would have to be invalidated at all five sites that
//! currently invalidate `content_log_key` — and a single missed one
//! serves a document from *before* a key rotation, which is precisely
//! the attack pre-rotation exists to defeat. The CESR bytes themselves
//! still come from the existing content cache, so the cost is CPU on
//! already-resident bytes. If it ever shows up in a profile, the safe
//! fix is a memo keyed by a hash of those bytes, which cannot go stale.
//!
//! ## Sharing `/{*mnemonic}/did.json` with did:web
//!
//! Both methods serve that suffix, so this dispatcher runs **before**
//! [`super::resolve_web`] and claims the URL only when the stored
//! record is actually a `did:webs` record. Anything else falls through
//! with `None`, leaving the did:web bridge exactly as it was.

use axum::http::{StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use did_hosting_common::method::webs::{CESR_CONTENT_TYPE, Webs};
use did_hosting_common::server::domain::assert_resolution_allowed;
use did_hosting_common::server::mnemonic::validate_webs_mnemonic;
use tracing::{debug, error};

use super::resolve_shared::extract_request_host;
use crate::did_ops::{self, DidRecord};
use crate::error::AppError;
use crate::server::AppState;

/// The stored record for `mnemonic`, if it is a servable `did:webs` one.
///
/// `Ok(None)` means "not this method's problem" — no record, or a
/// record belonging to another method — and the caller falls through to
/// the next dispatcher. Errors are terminal: a disabled or deleted slot
/// must 404 rather than quietly hand the URL to did:web, which would
/// serve content this record says is withdrawn.
async fn webs_record(
    state: &AppState,
    mnemonic: &str,
    request_host: Option<&str>,
) -> Result<Option<DidRecord>, AppError> {
    let Some(record) = state
        .dids_ks
        .get::<DidRecord>(did_ops::did_key(mnemonic))
        .await?
    else {
        return Ok(None);
    };
    if record.method != "webs" {
        return Ok(None);
    }
    if record.disabled || record.deleted_at.is_some() {
        return Err(AppError::NotFound(format!("content not found: {mnemonic}")));
    }
    if let Some(host) = request_host
        && let Some(ref did_id) = record.did_id
    {
        assert_resolution_allowed(&state.store, host, did_id).await?;
    }
    Ok(Some(record))
}

/// Read the stored CESR stream for `mnemonic`, via the content cache.
async fn load_keri_cesr(state: &AppState, mnemonic: &str) -> Result<Vec<u8>, AppError> {
    let key = did_ops::content_log_key(mnemonic);
    if let Some(cached) = state.did_cache.get(&key) {
        #[cfg(feature = "metrics")]
        did_hosting_common::server::metrics::inc_cache_hit();
        return Ok((*cached).clone());
    }
    #[cfg(feature = "metrics")]
    did_hosting_common::server::metrics::inc_cache_miss();
    let data = state
        .dids_ks
        .get_raw(key.as_str())
        .await?
        .ok_or_else(|| AppError::NotFound(format!("content not found: {mnemonic}")))?;
    state.did_cache.insert(key, data.clone());
    Ok(data)
}

/// Serve `keri.cesr` — the key event log, verbatim.
///
/// Served as stored rather than re-serialized: the stream's signatures
/// cover exact bytes, and a resolver that re-derives the document from
/// a re-encoded copy could reach a different answer than the publisher.
async fn serve_keri_cesr(
    state: &AppState,
    mnemonic: &str,
    request_host: Option<&str>,
) -> Result<Response, AppError> {
    // Unlike `did.json`, this suffix belongs to no other method, so a
    // missing or wrong-method record is a 404 rather than a fall-through.
    if webs_record(state, mnemonic, request_host).await?.is_none() {
        return Err(AppError::NotFound(format!("content not found: {mnemonic}")));
    }
    let content = load_keri_cesr(state, mnemonic).await?;

    if let Some(ref collector) = state.stats_collector {
        collector.record_resolve(mnemonic);
        #[cfg(feature = "metrics")]
        did_hosting_common::server::metrics::inc_resolve();
    }

    debug!(mnemonic = %mnemonic, size = content.len(), "keri.cesr resolved");

    Ok((
        StatusCode::OK,
        [
            ("content-type", CESR_CONTENT_TYPE),
            // Same reasoning as the webvh log: a key event log is
            // append-only and self-verifying, so a stale-but-signed
            // copy cannot be forged into something else. Cache it.
            ("cache-control", "public, max-age=300"),
        ],
        content,
    )
        .into_response())
}

/// Serve `did.json` — derived from the verified key event log.
async fn serve_did_json(state: &AppState, record: &DidRecord) -> Result<Response, AppError> {
    let mnemonic = &record.mnemonic;
    let content = load_keri_cesr(state, mnemonic).await?;

    // The DID this slot hosts, as recorded at registration. Without it
    // there is no way to know which AID the stream should establish, and
    // deriving against the wrong one would either fail or — worse —
    // succeed for a co-hosted identifier in the same stream.
    let did_id = record.did_id.as_deref().ok_or_else(|| {
        AppError::Internal(format!(
            "did:webs record {mnemonic} has no did_id; cannot derive did.json"
        ))
    })?;

    let doc = Webs::derive_document(did_id, &content).map_err(|e| {
        // Reaching here means bytes that passed `verify_artifacts` on
        // the way in no longer verify — the store is corrupt, or was
        // written by something that bypassed the write path. Serving an
        // underived document would be worse than serving none.
        error!(
            mnemonic = %mnemonic,
            did = %did_id,
            error = %e,
            "stored keri.cesr no longer verifies; refusing to serve a did.json for it"
        );
        AppError::Internal(format!(
            "stored key event log for {mnemonic} does not verify"
        ))
    })?;

    if let Some(ref collector) = state.stats_collector {
        collector.record_resolve(mnemonic);
        #[cfg(feature = "metrics")]
        did_hosting_common::server::metrics::inc_resolve();
    }

    debug!(mnemonic = %mnemonic, size = doc.len(), "did:webs document derived");

    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/did+json"),
            ("cache-control", "public, max-age=300"),
        ],
        doc,
    )
        .into_response())
}

/// Catch-all dispatcher for `did:webs` artifacts.
///
/// Returns:
/// - `Some(response)` when the URL is a `did:webs` artifact path. Terminal.
/// - `None` when the URL is not this method's — no matching suffix, or a
///   `did.json` whose slot belongs to another method. The caller tries
///   the next dispatcher.
pub async fn dispatch(state: &AppState, parts: &Parts) -> Option<Response> {
    let path = parts.uri.path().trim_start_matches('/');
    let host = extract_request_host(parts, &state.trusted_proxy_cidrs);
    let host = host.as_deref();

    if let Some(mnemonic) = path.strip_suffix("/keri.cesr")
        && !mnemonic.is_empty()
    {
        if let Err(e) = validate_webs_mnemonic(mnemonic) {
            return Some(e.into_response());
        }
        return Some(
            serve_keri_cesr(state, mnemonic, host)
                .await
                .unwrap_or_else(|e| e.into_response()),
        );
    }

    if let Some(mnemonic) = path.strip_suffix("/did.json")
        && !mnemonic.is_empty()
    {
        // A malformed-for-webs mnemonic is not an error here — did:web
        // owns this suffix too, and its paths are the ones this
        // validator rejects. Fall through and let it answer.
        if validate_webs_mnemonic(mnemonic).is_err() {
            return None;
        }
        return match webs_record(state, mnemonic, host).await {
            // Not a did:webs slot — did:web's bridge handles it.
            Ok(None) => None,
            Ok(Some(record)) => Some(
                serve_did_json(state, &record)
                    .await
                    .unwrap_or_else(|e| e.into_response()),
            ),
            Err(e) => Some(e.into_response()),
        };
    }

    None
}

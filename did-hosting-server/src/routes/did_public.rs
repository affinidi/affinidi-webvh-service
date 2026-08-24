//! Combined public-DID fallback that walks each compiled-in method's
//! resolver in priority order (T25).
//!
//! At compile time the daemon may have `method-webvh`, `method-web`,
//! both, or (in the future) neither. Each enabled method's
//! `dispatch(state, parts)` is called in turn; the first method that
//! recognises the URL returns its response, and we stop there. If no
//! method matches, the fallback returns 404 (or, in the daemon's
//! combined router, hands off to the SPA static handler).
//!
//! ## Priority
//!
//! 1. **did:webvh** (when `method-webvh` is on). Webvh's URLs end in
//!    `/did.jsonl` or `/did-witness.json`; both are method-exclusive,
//!    so registering webvh first doesn't shadow other methods.
//! 2. **did:webs** (when `method-webs` is on). `/keri.cesr` is
//!    method-exclusive, but `/did.json` is **not** — did:web serves it
//!    too. So webs must come before web, and it claims a `did.json`
//!    only when the stored record is actually a did:webs record,
//!    returning `None` otherwise. Ordering them the other way round
//!    would let did:web's bridge answer for a did:webs slot: it would
//!    look for a webvh log where a CESR stream is stored, and 404 a
//!    DID that is hosted perfectly well.
//! 3. **did:web** (when `method-web` is on). Web's URL ends in
//!    `/did.json`. Last, so it acts as the fall-through for that
//!    suffix — which is what its did:webvh bridge has always been.
//!
//! ## Why a fallback rather than `Router::route("/{*x}/did.jsonl", ...)`
//!
//! Axum's nested catch-alls (`/{*path}`) don't compose with sibling
//! catch-alls at the same level — you get a "match" conflict at
//! router-build time. The fallback path is the only way to do
//! suffix-based dispatch in a single router. Each method's
//! `dispatch` does its own suffix check and returns `None` when the
//! URL isn't its problem, which is structurally equivalent to "this
//! route didn't match, try the next one".

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[cfg(feature = "method-web")]
use super::resolve_web;
#[cfg(feature = "method-webs")]
use super::resolve_webs;
#[cfg(feature = "method-webvh")]
use super::resolve_webvh;
use crate::server::AppState;

/// Combined fallback handler: walks each enabled method's dispatcher
/// in priority order, returning the first match.
///
/// 404 when no method recognises the URL. Callers expecting an SPA
/// (daemon mode) check for 404 and then call the static handler.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/{mnemonic}/did.jsonl",
    tag = "resolve",
    params(("mnemonic" = String, Path, description = "Slot path; the published did:webvh resolves at <base>/{mnemonic}/did.jsonl")),
    responses(
        (status = 200, description = "did:webvh log (JSONL) or did:web document for the slot", content_type = "application/jsonl+json"),
        (status = 404, description = "No DID hosted at this path"),
    ),
))]
pub async fn serve_public(State(state): State<AppState>, request: Request) -> Response {
    let (parts, _) = request.into_parts();

    // Order matters when methods share suffixes; today they don't, but
    // the iteration is encoded explicitly anyway so the priority is
    // visible at the call site rather than buried in router config.

    #[cfg(feature = "method-webvh")]
    {
        if let Some(response) = resolve_webvh::dispatch(&state, &parts).await {
            return response;
        }
    }

    // Before did:web — both serve `/did.json`, and only this one can
    // tell whether the slot behind it is a did:webs record.
    #[cfg(feature = "method-webs")]
    {
        if let Some(response) = resolve_webs::dispatch(&state, &parts).await {
            return response;
        }
    }

    #[cfg(feature = "method-web")]
    {
        if let Some(response) = resolve_web::dispatch(&state, &parts).await {
            return response;
        }
    }

    // Silence the unused-binding warning when no method features are
    // on. The build with both features off is rejected at the crate
    // level by `compile_error!` in `lib.rs` (added below).
    let _ = state;
    let _ = parts;

    StatusCode::NOT_FOUND.into_response()
}

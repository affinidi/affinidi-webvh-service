//! Agent name resolution — `GET /@{name}` (T-agent-names).
//!
//! An agent name is a human-memorable shortcut (`example.com/@alice`) that
//! **redirects** to a DID. This is the hosting side of the two-stage resolution
//! the agent-name specification describes: the name resolves to a DID here, and
//! a DID resolver turns that DID into a document.
//!
//! ## Why a route, not the 404 fallback
//!
//! Per-DID artifacts (`/{mnemonic}/did.jsonl`) are matched in the fallback
//! because axum's sibling catch-alls conflict at build time. Agent names are a
//! *prefix* match (`/@…`), which is a plain route with no such conflict — and
//! `@` is not a legal mnemonic character (`[a-z0-9-]` only), so `/@name` can
//! never shadow a hosted DID path.
//!
//! ## The redirect contract
//!
//! `302 Found` with `Location: <the DID>`. The agent-name FAQ leaves the status
//! code and target form unspecified; the companion `agent-names` resolver
//! accepts any 3xx carrying a bare `did:…` in `Location`, so this is the
//! concrete contract those two ends agree on.
//!
//! ## Trust
//!
//! A name only appears in the index if the signed DID document claimed it via
//! `alsoKnownAs` (see `control_register::apply_single_update`). This handler
//! therefore serves a redirect the document has already authorised; the
//! resolver still re-verifies `alsoKnownAs` itself, because this service is a
//! cache of that authorisation, not the authority for it.

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use did_hosting_common::did_ops::{self, DidRecord, agent_name_key};
use did_hosting_common::server::mnemonic::validate_agent_name;
use tracing::debug;

use super::resolve_shared::extract_request_host;
use crate::error::AppError;
use crate::server::AppState;

/// `GET /@{name}` and `GET /@{name}/{*context}`.
///
/// The optional `context` tail (`/@alice/h2hsummit`) is accepted and ignored
/// for the redirect target — it is the FAQ's context-path affordance, carried
/// through for the caller's benefit, not part of the name's identity.
pub async fn serve(
    State(state): State<AppState>,
    Path(params): Path<AgentNamePath>,
    parts: Parts,
) -> Response {
    match resolve(&state, &params.name, &parts).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

/// Captured path segments. `context` is present only on the two-segment route.
#[derive(Debug, serde::Deserialize)]
pub struct AgentNamePath {
    pub name: String,
    #[serde(default)]
    pub context: Option<String>,
}

async fn resolve(state: &AppState, raw_name: &str, parts: &Parts) -> Result<Response, AppError> {
    // Feature off -> the /@ namespace is not served here at all. 404, not 403:
    // a caller cannot tell an unconfigured server from one with no such name,
    // and there is nothing to authenticate against to justify saying more.
    if !state.config.features.agent_names {
        return Err(AppError::NotFound(format!(
            "no such agent name: @{raw_name}"
        )));
    }

    // Reject a malformed or reserved name up front. This is validation, not a
    // lookup, so it returns 400 rather than 404 — the request is ill-formed,
    // not merely unmatched.
    validate_agent_name(raw_name).map_err(|_| {
        // Do not leak *why* (reserved vs malformed) to an unauthenticated
        // caller; a plain not-found is the honest public answer.
        AppError::NotFound(format!("no such agent name: @{raw_name}"))
    })?;
    let name = raw_name.strip_prefix('@').unwrap_or(raw_name);

    // The domain is the request host — the same authority the DID identifier
    // encodes and the same value the index was keyed on.
    let host = extract_request_host(parts, &state.trusted_proxy_cidrs);
    let Some(host) = host.as_deref() else {
        return Err(AppError::NotFound(format!("no such agent name: @{name}")));
    };

    // name -> mnemonic
    let Some(mnemonic) = state
        .dids_ks
        .get_raw(agent_name_key(host, name).into_bytes())
        .await?
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return Err(AppError::NotFound(format!("no such agent name: @{name}")));
    };

    // Load the DID record and apply the same gates the content path applies:
    // a disabled or deleted DID serves nothing, and the name's own `enabled`
    // flag must be set. All three failures are a 404 — a parked or suspended
    // name is indistinguishable from a missing one to the public.
    let Some(record) = state
        .dids_ks
        .get::<DidRecord>(did_ops::did_key(&mnemonic))
        .await?
    else {
        // Index pointed at a mnemonic with no record — a torn write. Retire
        // the dangling entry opportunistically rather than serving a 500.
        debug!(%name, %mnemonic, "agent name index entry with no DID record; ignoring");
        return Err(AppError::NotFound(format!("no such agent name: @{name}")));
    };

    if record.disabled || record.deleted_at.is_some() {
        return Err(AppError::NotFound(format!("no such agent name: @{name}")));
    }
    let enabled = record
        .agent_names
        .iter()
        .any(|entry| entry.name == name && entry.enabled);
    if !enabled {
        return Err(AppError::NotFound(format!("no such agent name: @{name}")));
    }

    let Some(did) = record.did_id else {
        // A reserved slot with no published document yet — nothing to redirect
        // to.
        return Err(AppError::NotFound(format!("no such agent name: @{name}")));
    };

    debug!(%name, %did, "agent name resolved");

    // Content-negotiate the redirect target on `Accept`.
    //
    // The default — for resolvers, the `agent-names` `HttpRedirectResolver`,
    // and `curl` — is the DID itself. That is the contract: the caller resolves
    // the DID and checks its document claims the name back (Layer-1). A browser,
    // though, can't follow a `did:` scheme, so an `Accept: text/html` caller
    // gets a same-origin redirect to the DID's resolvable `did.jsonl` instead —
    // it lands on real, loadable content rather than an unnavigable scheme. The
    // machine contract is unchanged; only the human's browser is redirected
    // somewhere it can render.
    //
    // A *relative* target (`/{mnemonic}/did.jsonl`) so the browser resolves it
    // against this exact origin — no scheme/host reconstruction, correct behind
    // a TLS-terminating proxy. `mnemonic` is `.well-known` for a root DID, which
    // is exactly the log's path there too, so one form covers every case.
    let wants_html = parts
        .headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"));
    let target = if wants_html {
        format!("/{mnemonic}/did.jsonl")
    } else {
        did
    };

    let location = HeaderValue::from_str(&target)
        .map_err(|_| AppError::NotFound(format!("no such agent name: @{name}")))?;
    Ok((
        StatusCode::FOUND,
        [
            (header::LOCATION, location),
            // The response body depends on `Accept`, so a shared cache must key
            // on it — otherwise it could hand a browser's `did.jsonl` redirect
            // to a resolver, or vice versa.
            (header::VARY, HeaderValue::from_static("accept")),
        ],
        // A short public cache: a name mapping changes rarely, but it CAN
        // change (rename, disable), so it is not immutable.
        [(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        )],
    )
        .into_response())
}

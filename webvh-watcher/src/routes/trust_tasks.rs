//! `POST /api/trust-tasks` — the HTTPS binding of the watcher's Trust Task
//! listener.
//!
//! The same documents arrive over TSP and DIDComm on the mediator connection;
//! all three land in [`crate::trust_tasks::dispatch_inbound_document`]. The
//! document's own proof is the only authorisation: there is no session or
//! bearer on this surface.
//!
//! ## Rate limiting
//!
//! Verifying a document's proof means resolving its claimed issuer's DID — an
//! outbound fetch. `dispatch_inbound_document`'s cheap pre-check refuses a
//! claimed issuer outside the source allowlist before that resolution is
//! attempted, but a configured source still triggers one (to check whether
//! the proof genuinely is theirs). A per-address limiter sits in front of
//! both, so one address cannot force unbounded resolver work by posting
//! documents quickly, whatever they claim.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tracing::{error, warn};
use trust_tasks_rs::{RejectReason, TrustTask};

use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::rate_limit::resolve_client_ip;

use crate::server::AppState;
use crate::trust_tasks::{Via, dispatch_inbound_document};

/// Logs, but does not itself refuse, a request reaching this route with no
/// `ConnectInfo<SocketAddr>` extension. Production always serves this router
/// through `into_make_service_with_connect_info`, which sets it on every real
/// connection; if it is ever missing (a serve path regresses, a test drives
/// the router directly), `receive`'s own `ConnectInfo` extractor already
/// fails the request closed with a 500 rather than sharing a fallback
/// address — this only makes that otherwise-silent rejection visible.
pub async fn log_missing_connect_info(req: Request, next: Next) -> Response {
    if req.extensions().get::<ConnectInfo<SocketAddr>>().is_none() {
        error!("trust-tasks request has no ConnectInfo<SocketAddr>; it will be refused with a 500");
    }
    next.run(req).await
}

/// Hand the posted document to the watcher's one inbound dispatch and answer
/// with its signed reply.
///
/// A document that does not verify gets no signed answer: it is answered `403`
/// with an unsigned, detail-free error document, which settles nothing.
pub async fn receive(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Per-address rate limit, ahead of parsing and any DID resolution the
    // document's verification would trigger.
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let client_ip = resolve_client_ip(addr.ip(), xff, &state.config.server.trusted_proxies);
    if let Err(e) = state
        .trust_tasks_rate_limiter
        .try_consume(client_ip, now_epoch())
    {
        warn!(ip = %client_ip, error = %e, "trust-tasks request rate limited");
        return e.into_response();
    }

    let doc: TrustTask<Value> = match serde_json::from_slice(&body) {
        Ok(doc) => doc,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "malformed_request",
                    "message": format!("the body is not a Trust Task document: {e}"),
                })),
            )
                .into_response();
        }
    };
    let refusal = doc.reject_with(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        RejectReason::PermissionDenied {
            reason: "the document was not accepted".into(),
        },
    );
    match dispatch_inbound_document(&state, Via::Https, None, doc).await {
        Some(reply) => (StatusCode::OK, Json(reply)).into_response(),
        None => (StatusCode::FORBIDDEN, Json(refusal)).into_response(),
    }
}

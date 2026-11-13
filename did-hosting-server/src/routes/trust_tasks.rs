//! `POST /api/trust-tasks` — the HTTPS binding of the edge's Trust Task
//! listener.
//!
//! The same documents arrive over TSP and DIDComm on the mediator connection;
//! all three land in [`crate::messaging::dispatch_inbound_document`], so a
//! directive is verified and applied identically whichever transport carried
//! it. The document's own proof is the only authorisation: there is no session
//! or bearer on this surface.
//!
//! A service's DID document advertises `TrustTaskHTTPS` at `{origin}/api`
//! (the Trust Task base, per HTTPS binding 0.2 §6), so this is the route a
//! peer that resolved the edge's DID reaches.
//!
//! ## Rate limiting
//!
//! Verifying a document's proof means resolving its claimed issuer's DID — an
//! outbound fetch. `verify_control_plane`'s cheap pre-check refuses a
//! claimed issuer that isn't `control_did` before that resolution is
//! attempted, but a claimed issuer that *is* `control_did` still triggers one
//! (to check whether the proof genuinely is theirs). A per-address limiter
//! sits in front of both, so one address cannot force unbounded resolver work
//! by posting documents quickly, whatever they claim.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use did_hosting_common::server::listener::{BODY_READ_TIMEOUT, read_body};
use serde_json::Value;
use tracing::error;
use trust_tasks_rs::TrustTask;

use crate::messaging::Inbound;
use crate::server::AppState;

/// Logs, but does not itself refuse, a request reaching this route with no
/// `ConnectInfo<SocketAddr>` extension. Production always serves this router
/// through `into_make_service_with_connect_info`, which sets it on every real
/// connection; if it is ever missing (a serve path regresses, a test drives
/// the router directly), `receive`'s own `ConnectInfo` extractor already
/// fails the request closed with a 500 rather than sharing a fallback
/// address — this only makes that otherwise-silent rejection visible.
/// Largest request body `receive` reads, set where the route is mounted.
#[derive(Debug, Clone, Copy)]
pub struct BodyLimit(pub usize);

pub async fn log_missing_connect_info(req: Request, next: Next) -> Response {
    if req.extensions().get::<ConnectInfo<SocketAddr>>().is_none() {
        error!("trust-tasks request has no ConnectInfo<SocketAddr>; it will be refused with a 500");
    }
    next.run(req).await
}

/// Hand the posted document to the edge's one inbound dispatch and answer with
/// its signed reply.
///
/// A document that fails `verify_control_plane` gets no answer, signed or
/// unsigned: a signed refusal would settle a directive the control plane never
/// sent, and an error document is an answer too. It is refused with a bare
/// `403` and an empty body, as is a document that takes no reply. One that
/// could not be checked just now (its signer's DID could not be resolved, the
/// replay cache is full) is answered `503` with `Retry-After` and an empty
/// body, so the sender keeps it and sends it again.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/trust-tasks",
    tag = "trust-tasks",
    request_body(content = String, description = "A signed Trust Task document", content_type = "application/json"),
    responses(
        (status = 200, description = "The edge's signed reply document", content_type = "application/json"),
        (status = 400, description = "The body is not a Trust Task document", content_type = "application/json"),
        (status = 403, description = "The document was not accepted, or takes no reply; empty body"),
        (status = 408, description = "The body did not arrive in time"),
        (status = 413, description = "The body is larger than the listener accepts"),
        (status = 429, description = "This address's request rate exceeds the limit", content_type = "application/json"),
        (status = 503, description = "The document could not be checked just now; send it again after `Retry-After`. Empty body"),
    ),
))]
pub async fn receive(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(BodyLimit(limit)): Extension<BodyLimit>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Per-address rate limit, ahead of reading the body, parsing it, and any
    // DID resolution the document's verification would trigger: a refused
    // address never has its body read.
    if let Err(refusal) =
        state
            .trust_tasks_rate_limiter
            .admit(&state.client_ips, addr.ip(), &headers)
    {
        return refusal.into_response();
    }
    let body = match read_body(body, limit, BODY_READ_TIMEOUT).await {
        Ok(body) => body,
        Err(refusal) => return refusal.into_response(),
    };

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
    match crate::messaging::dispatch_inbound_document(&state, None, doc).await {
        Inbound::Reply(reply) => (StatusCode::OK, Json(reply)).into_response(),
        Inbound::NoReply => StatusCode::FORBIDDEN.into_response(),
        Inbound::Deferred(deferred) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, deferred.retry_after_secs.max(1))],
        )
            .into_response(),
    }
}

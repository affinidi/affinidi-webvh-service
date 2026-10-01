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

/// Hand the posted document to the edge's one inbound dispatch and answer with
/// its signed reply.
///
/// A document that does not verify gets no signed answer — a signed refusal
/// would settle a directive the control plane never sent — so it is answered
/// `403` with an unsigned, detail-free error document, which settles nothing.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/api/trust-tasks",
    tag = "trust-tasks",
    request_body(content = String, description = "A signed Trust Task document", content_type = "application/json"),
    responses(
        (status = 200, description = "The edge's signed reply document", content_type = "application/json"),
        (status = 400, description = "The body is not a Trust Task document", content_type = "application/json"),
        (status = 403, description = "The document was not accepted; an unsigned refusal", content_type = "application/json"),
        (status = 429, description = "This address's request rate exceeds the limit", content_type = "application/json"),
    ),
))]
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
    match crate::messaging::dispatch_inbound_document(&state, None, doc).await {
        Some(reply) => (StatusCode::OK, Json(reply)).into_response(),
        None => (StatusCode::FORBIDDEN, Json(refusal)).into_response(),
    }
}

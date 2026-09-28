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

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};

use crate::server::AppState;

/// Hand the posted document to the edge's one inbound dispatch and answer with
/// its signed reply.
///
/// A document that does not verify gets no signed answer — a signed refusal
/// would settle a directive the control plane never sent — so it is answered
/// `403` with an unsigned, detail-free error document, which settles nothing.
pub async fn receive(State(state): State<AppState>, body: axum::body::Bytes) -> Response {
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

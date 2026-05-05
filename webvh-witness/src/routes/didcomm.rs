use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// DIDComm REST endpoint — receives signed DIDComm messages over HTTP.
///
/// Phase 4 / not-yet-implemented. Returns 501 Not Implemented so callers can
/// distinguish "feature is roadmapped but absent" from "internal server error
/// during request handling". The mediator-driven inbound DIDComm path
/// (configured via `mediator_did` in the witness config) is unaffected — it
/// is the supported transport for v0.6.x. See `tasks/plan.md` for the
/// roadmap entry that revives this endpoint.
pub async fn handle(
    _auth: AuthClaims,
    State(_state): State<AppState>,
    _body: String,
) -> Result<Response, AppError> {
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "witness DIDComm REST endpoint is not yet implemented; \
         use the mediator-driven DIDComm path instead",
    )
        .into_response())
}

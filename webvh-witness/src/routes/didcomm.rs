use axum::extract::State;
use axum::response::Response;

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;

/// DIDComm REST endpoint — receives signed DIDComm messages over HTTP.
pub async fn handle(
    _auth: AuthClaims,
    State(_state): State<AppState>,
    _body: String,
) -> Result<Response, AppError> {
    // TODO: Phase 4 — implement DIDComm protocol dispatch
    Err(AppError::Internal(
        "DIDComm REST endpoint not yet implemented".into(),
    ))
}

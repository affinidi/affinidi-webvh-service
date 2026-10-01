//! The one REST route left in the passkey module: a demo operation gated on a
//! stepped-up session.
//!
//! Passkey enrolment, login and session step-up are Trust Tasks
//! (`auth/passkey/enroll/*`, `auth/passkey/login/*`), served on every
//! transport by the control plane's table; WebAuthn's own ceremony data rides
//! inside their payloads.

use axum::Json;
use serde::Serialize;

use crate::server::auth::extractor::StepUpAuth;

#[derive(Debug, Serialize)]
pub struct StepUpCheckResponse {
    pub ok: bool,
    pub did: String,
    pub acr: String,
    pub amr: Vec<String>,
}

/// GET /auth/step-up/check — a demo "sensitive operation" gated by
/// [`StepUpAuth`]. A base (`aal1`) session is rejected with
/// `step_up_required` (403); an elevated (`aal2`) session gets `200` with
/// its assurance echoed back. Exists so the demo has something to gate.
pub async fn step_up_check(StepUpAuth(claims): StepUpAuth) -> Json<StepUpCheckResponse> {
    Json(StepUpCheckResponse {
        ok: true,
        did: claims.did,
        acr: claims.acr,
        amr: claims.amr,
    })
}

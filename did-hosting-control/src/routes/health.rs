use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;

use crate::server::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}

/// Unauthenticated liveness + one local-resolution check. Deliberately
/// generic — no configuration or DID detail — but it must not claim
/// healthy while the service's own DID isn't being served locally (Keyring
/// VTI-17): see [`did_hosting_common::server::health::own_did_served_locally`].
pub async fn health(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let ok = did_hosting_common::server::health::own_did_served_locally(
        &state.dids_ks,
        state.config.server_did.as_deref(),
    )
    .await;

    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(HealthResponse {
            status: if ok { "ok" } else { "degraded" },
            service: "did-hosting-control",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

//! `GET /api/health`: liveness and version.

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

/// The control plane's `/readyz` check: its store, and nothing else. Its
/// `/api/health` own-DID check is about whether DID resolution serves the
/// right identity, and a standalone control plane serves no resolution, so
/// it is not a reason to stop sending it management traffic.
pub fn readiness_probe(state: &AppState) -> did_hosting_common::server::probes::ReadinessProbe {
    did_hosting_common::server::probes::ReadinessProbe::new(state.dids_ks.clone())
}

/// `GET /livez` and `GET /readyz` (see [`did_hosting_common::server::probes`]),
/// merged after the router's layers so they sit outside request tracing.
pub fn probe_routes(state: &AppState) -> axum::Router {
    did_hosting_common::server::probes::router(readiness_probe(state))
}

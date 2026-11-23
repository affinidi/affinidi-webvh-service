//! `GET /api/health`: the unauthenticated liveness probe.

use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "webvh-watcher",
    })
}

/// `GET /livez` and `GET /readyz` (see [`did_hosting_common::server::probes`]):
/// readiness is the watcher's store, read through the keyspace it resolves
/// from. Merged beside `/api/health`, after the router's layers.
pub fn probe_routes(state: &crate::server::AppState) -> axum::Router {
    did_hosting_common::server::probes::router(
        did_hosting_common::server::probes::ReadinessProbe::new(state.dids_ks.clone()),
    )
}

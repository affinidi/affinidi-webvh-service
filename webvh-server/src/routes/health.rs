use axum::Json;
use serde::Serialize;
use tracing::debug;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    debug!("health check");
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

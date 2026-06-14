use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/api/health",
    tag = "system",
    responses((status = 200, description = "Service is up; returns status + version", content_type = "application/json")),
))]
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

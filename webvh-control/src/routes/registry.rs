//! Service registry API routes.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use tracing::info;

use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::registry::{self, ServiceInstance, ServiceType};
use crate::server::AppState;

// ---------- GET /api/control/registry ----------

pub async fn list(
    _auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<Vec<ServiceInstance>>, AppError> {
    let instances = registry::list_instances(&state.registry_ks).await?;
    Ok(Json(instances))
}

// ---------- POST /api/control/registry ----------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub service_type: ServiceType,
    pub label: Option<String>,
    pub url: String,
}

pub async fn register(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<ServiceInstance>), AppError> {
    let instance = ServiceInstance {
        instance_id: uuid::Uuid::new_v4().to_string(),
        service_type: req.service_type,
        label: req.label,
        url: req.url,
        status: registry::ServiceStatus::Active,
        last_health_check: None,
        registered_at: crate::auth::session::now_epoch(),
        metadata: serde_json::Value::Null,
    };

    registry::register_instance(&state.registry_ks, &instance).await?;
    info!(
        instance_id = %instance.instance_id,
        url = %instance.url,
        service_type = %instance.service_type,
        "instance registered"
    );

    Ok((StatusCode::CREATED, Json(instance)))
}

// ---------- GET /api/control/registry/{instance_id} ----------

pub async fn get(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
) -> Result<Json<ServiceInstance>, AppError> {
    let instance = registry::get_instance(&state.registry_ks, &instance_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("instance {instance_id}")))?;
    Ok(Json(instance))
}

// ---------- DELETE /api/control/registry/{instance_id} ----------

pub async fn deregister(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
) -> Result<StatusCode, AppError> {
    registry::deregister_instance(&state.registry_ks, &instance_id).await?;
    info!(instance_id = %instance_id, "instance deregistered");
    Ok(StatusCode::NO_CONTENT)
}

// ---------- POST /api/control/registry/{instance_id}/health ----------

pub async fn health_check(
    _auth: AdminAuth,
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
) -> Result<Json<ServiceInstance>, AppError> {
    let instance = registry::get_instance(&state.registry_ks, &instance_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("instance {instance_id}")))?;

    let status = registry::health_check(&state.http_client, &instance).await;
    let now = crate::auth::session::now_epoch();
    registry::update_instance_status(&state.registry_ks, &instance_id, status, now).await?;

    let updated = registry::get_instance(&state.registry_ks, &instance_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("instance {instance_id}")))?;

    Ok(Json(updated))
}

//! Service registry — tracks registered backend service instances.

use crate::error::AppError;
use crate::store::KeyspaceHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    Server,
    Witness,
    Watcher,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server => write!(f, "server"),
            Self::Witness => write!(f, "witness"),
            Self::Watcher => write!(f, "watcher"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Active,
    Degraded,
    Unreachable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInstance {
    pub instance_id: String,
    pub service_type: ServiceType,
    pub label: Option<String>,
    pub url: String,
    pub status: ServiceStatus,
    pub last_health_check: Option<u64>,
    pub registered_at: u64,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

fn instance_key(instance_id: &str) -> String {
    format!("instance:{instance_id}")
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

pub async fn register_instance(
    registry_ks: &KeyspaceHandle,
    instance: &ServiceInstance,
) -> Result<(), AppError> {
    registry_ks
        .insert(instance_key(&instance.instance_id), instance)
        .await
}

pub async fn deregister_instance(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
) -> Result<(), AppError> {
    registry_ks.remove(instance_key(instance_id)).await
}

pub async fn get_instance(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
) -> Result<Option<ServiceInstance>, AppError> {
    registry_ks.get(instance_key(instance_id)).await
}

pub async fn list_instances(
    registry_ks: &KeyspaceHandle,
) -> Result<Vec<ServiceInstance>, AppError> {
    let raw = registry_ks.prefix_iter_raw("instance:").await?;
    let mut instances = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        if let Ok(instance) = serde_json::from_slice::<ServiceInstance>(&value) {
            instances.push(instance);
        }
    }
    Ok(instances)
}

pub async fn list_instances_by_type(
    registry_ks: &KeyspaceHandle,
    service_type: &ServiceType,
) -> Result<Vec<ServiceInstance>, AppError> {
    let all = list_instances(registry_ks).await?;
    Ok(all
        .into_iter()
        .filter(|i| &i.service_type == service_type)
        .collect())
}

/// Update the status and health check timestamp of an instance.
pub async fn update_instance_status(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
    status: ServiceStatus,
    timestamp: u64,
) -> Result<(), AppError> {
    if let Some(mut instance) = get_instance(registry_ks, instance_id).await? {
        instance.status = status;
        instance.last_health_check = Some(timestamp);
        register_instance(registry_ks, &instance).await?;
    }
    Ok(())
}

/// Perform a health check against an instance.
pub async fn health_check(
    http: &reqwest::Client,
    instance: &ServiceInstance,
) -> ServiceStatus {
    let url = format!("{}/api/health", instance.url.trim_end_matches('/'));
    match http.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
        Ok(resp) if resp.status().is_success() => ServiceStatus::Active,
        Ok(_) => ServiceStatus::Degraded,
        Err(_) => ServiceStatus::Unreachable,
    }
}

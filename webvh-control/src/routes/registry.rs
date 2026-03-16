//! Service registry API routes.

use affinidi_webvh_common::{DidSyncEntry, DidSyncUpdate, RegisterServiceResponse};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use tracing::info;

use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::registry::{self, ServiceInstance, ServiceStatus, ServiceType};
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

// ---------- POST /api/control/register-service ----------

/// Request body for `POST /api/control/register-service`.
/// Extends `RegisterRequest` with DID sync data.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterServiceWithSyncRequest {
    pub service_type: ServiceType,
    pub label: Option<String>,
    pub url: String,
    #[serde(default)]
    pub preloaded_dids: Vec<DidSyncEntry>,
}

/// DIDComm-authenticated service self-registration endpoint.
///
/// Backend services (webvh-server, webvh-witness, etc.) call this on startup
/// to announce themselves to the control plane. Authentication uses DIDComm
/// challenge-response (the calling service must have an ACL entry).
///
/// Idempotent: if an instance with the same URL and service type already
/// exists, its status is set to Active and the existing record is returned.
pub async fn register_service(
    auth: AdminAuth,
    State(state): State<AppState>,
    Json(req): Json<RegisterServiceWithSyncRequest>,
) -> Result<(StatusCode, Json<RegisterServiceResponse>), AppError> {
    // Dedup check: look for existing instance with same URL + service_type
    let existing = registry::list_instances(&state.registry_ks).await?;
    if let Some(instance) = existing
        .into_iter()
        .find(|i| i.url == req.url && i.service_type == req.service_type)
    {
        // Re-activate existing instance
        let now = crate::auth::session::now_epoch();
        registry::update_instance_status(
            &state.registry_ks,
            &instance.instance_id,
            ServiceStatus::Active,
            now,
        )
        .await?;

        info!(
            instance_id = %instance.instance_id,
            url = %instance.url,
            did = %auth.0.did,
            "service re-registered (existing instance reactivated)"
        );

        let did_updates = compute_did_sync_updates(&state, &req.preloaded_dids).await;

        return Ok((
            StatusCode::OK,
            Json(RegisterServiceResponse {
                instance_id: instance.instance_id,
                did_updates,
                did_hosting_url: state.config.did_hosting_url.clone(),
            }),
        ));
    }

    // Create new instance — store registering DID in metadata
    let metadata = serde_json::json!({ "did": auth.0.did });
    let instance = ServiceInstance {
        instance_id: uuid::Uuid::new_v4().to_string(),
        service_type: req.service_type,
        label: req.label,
        url: req.url,
        status: ServiceStatus::Active,
        last_health_check: None,
        registered_at: crate::auth::session::now_epoch(),
        metadata,
    };

    registry::register_instance(&state.registry_ks, &instance).await?;
    info!(
        instance_id = %instance.instance_id,
        url = %instance.url,
        service_type = %instance.service_type,
        did = %auth.0.did,
        "service registered via DIDComm auth"
    );

    let did_updates = compute_did_sync_updates(&state, &req.preloaded_dids).await;

    Ok((
        StatusCode::CREATED,
        Json(RegisterServiceResponse {
            instance_id: instance.instance_id,
            did_updates,
            did_hosting_url: state.config.did_hosting_url.clone(),
        }),
    ))
}

/// Compute DID sync updates for the registering service.
///
/// Compares the control plane's DID store against the server's reported DIDs
/// and returns updates for any DIDs the server is missing or has outdated.
async fn compute_did_sync_updates(
    state: &AppState,
    reported_dids: &[DidSyncEntry],
) -> Vec<DidSyncUpdate> {
    use affinidi_webvh_common::did_ops::{self, DidRecord};
    use std::collections::HashMap;

    // Build a lookup of reported DIDs by mnemonic
    let reported: HashMap<&str, &DidSyncEntry> = reported_dids
        .iter()
        .map(|e| (e.mnemonic.as_str(), e))
        .collect();

    // Iterate all DIDs on the control plane
    let raw = match state.dids_ks.prefix_iter_raw("did:").await {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(error = %e, "compute_did_sync_updates: failed to iterate DIDs");
            return Vec::new();
        }
    };

    let mut updates = Vec::new();

    for (_key, value) in raw {
        let record: DidRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Skip empty (unpublished) DID slots
        if record.version_count == 0 {
            continue;
        }

        let needs_update = match reported.get(record.mnemonic.as_str()) {
            // Server doesn't have this DID → send it
            None => true,
            // Server has it but with fewer versions → send update
            Some(entry) => entry.version_count < record.version_count,
        };

        if !needs_update {
            continue;
        }

        // Read the log content
        let log_content = match state
            .dids_ks
            .get_raw(did_ops::content_log_key(&record.mnemonic))
            .await
        {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => continue,
            },
            _ => continue,
        };

        // Read witness content (optional)
        let witness_content = match state
            .dids_ks
            .get_raw(did_ops::content_witness_key(&record.mnemonic))
            .await
        {
            Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
            _ => None,
        };

        let did_id = record.did_id.unwrap_or_default();

        updates.push(DidSyncUpdate {
            mnemonic: record.mnemonic,
            did_id,
            log_content,
            witness_content,
            version_count: record.version_count,
        });
    }

    // Log any DIDs the server has that the control plane doesn't
    for entry in reported_dids {
        let key = did_ops::did_key(&entry.mnemonic);
        match state.dids_ks.get::<DidRecord>(key).await {
            Ok(None) => {
                tracing::warn!(
                    mnemonic = %entry.mnemonic,
                    "server has DID unknown to control plane — manual import may be needed"
                );
            }
            _ => {}
        }
    }

    if !updates.is_empty() {
        info!(
            count = updates.len(),
            "computed DID sync updates for registering server"
        );
    }

    updates
}

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use tracing::info;

use crate::auth::AdminAuth;
use crate::error::AppError;
use crate::server::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfigResponse {
    pub server_did: Option<String>,
    pub public_url: Option<String>,
    pub features: FeaturesResponse,
    pub server: ServerResponse,
    pub log: LogResponse,
    pub store: StoreResponse,
    pub auth: AuthResponse,
    pub limits: LimitsResponse,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeaturesResponse {
    pub didcomm: bool,
    pub rest_api: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerResponse {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogResponse {
    pub level: String,
    pub format: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreResponse {
    pub data_dir: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub access_token_expiry: u64,
    pub refresh_token_expiry: u64,
    pub challenge_ttl: u64,
    pub session_cleanup_interval: u64,
    pub passkey_enrollment_ttl: u64,
    pub cleanup_ttl_minutes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitsResponse {
    pub upload_body_limit: usize,
    pub default_max_total_size: u64,
    pub default_max_did_count: u64,
}

/// GET /config — return safe server configuration (admin only)
pub async fn get_config(
    auth: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<ServerConfigResponse>, AppError> {
    let cfg = &state.config;

    let format = match cfg.log.format {
        crate::config::LogFormat::Text => "text",
        crate::config::LogFormat::Json => "json",
    };

    info!(caller = %auth.0.did, "server config retrieved");

    Ok(Json(ServerConfigResponse {
        server_did: cfg.server_did.clone(),
        public_url: cfg.public_url.clone(),
        features: FeaturesResponse {
            didcomm: cfg.features.didcomm,
            rest_api: cfg.features.rest_api,
        },
        server: ServerResponse {
            host: cfg.server.host.clone(),
            port: cfg.server.port,
        },
        log: LogResponse {
            level: cfg.log.level.clone(),
            format: format.to_string(),
        },
        store: StoreResponse {
            data_dir: cfg.store.data_dir.display().to_string(),
        },
        auth: AuthResponse {
            access_token_expiry: cfg.auth.access_token_expiry,
            refresh_token_expiry: cfg.auth.refresh_token_expiry,
            challenge_ttl: cfg.auth.challenge_ttl,
            session_cleanup_interval: cfg.auth.session_cleanup_interval,
            passkey_enrollment_ttl: cfg.auth.passkey_enrollment_ttl,
            cleanup_ttl_minutes: cfg.auth.cleanup_ttl_minutes,
        },
        limits: LimitsResponse {
            upload_body_limit: cfg.limits.upload_body_limit,
            default_max_total_size: cfg.limits.default_max_total_size,
            default_max_did_count: cfg.limits.default_max_did_count,
        },
    }))
}

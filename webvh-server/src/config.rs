use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types so existing code can still use `crate::config::*`
pub use affinidi_webvh_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, LogFormat, SecretsConfig, ServerConfig, StoreConfig,
    VtaConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub features: FeaturesConfig,
    pub server_did: Option<String>,
    pub mediator_did: Option<String>,
    pub public_url: Option<String>,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub watchers: Vec<WatcherEndpoint>,
    /// URL of the control plane for service registration.
    pub control_url: Option<String>,
    /// DID of the control plane service (for DIDComm authentication).
    pub control_did: Option<String>,
    #[serde(default)]
    pub vta: VtaConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WatcherEndpoint {
    pub url: String,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    /// Maximum body size (bytes) for did.jsonl / witness uploads. Default: 100KB.
    #[serde(default = "default_upload_body_limit")]
    pub upload_body_limit: usize,
    /// Default per-account total DID document size (bytes). Default: 1MB.
    #[serde(default = "default_max_total_size")]
    pub default_max_total_size: u64,
    /// Default per-account maximum number of DIDs. Default: 20.
    #[serde(default = "default_max_did_count")]
    pub default_max_did_count: u64,
}

fn default_upload_body_limit() -> usize {
    102_400
}

fn default_max_total_size() -> u64 {
    1_048_576
}

fn default_max_did_count() -> u64 {
    20
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            upload_body_limit: default_upload_body_limit(),
            default_max_total_size: default_max_total_size(),
            default_max_did_count: default_max_did_count(),
        }
    }
}

impl AppConfig {
    /// Return the public-facing base URL for this server.
    pub fn public_base_url(&self) -> String {
        self.public_url.clone().unwrap_or_else(|| {
            format!("http://{}:{}", self.server.host, self.server.port)
        })
    }

    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("WEBVH_CONFIG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("config.toml"));

        if !path.exists() {
            return Err(AppError::Config(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }

        let contents = std::fs::read_to_string(&path).map_err(AppError::Io)?;
        let mut config = toml::from_str::<AppConfig>(&contents)
            .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;

        config.config_path = path.clone();

        // Apply shared env overrides for common config fields
        affinidi_webvh_common::server::config::apply_env_overrides(
            "WEBVH",
            &mut config.features,
            &mut config.server,
            &mut config.log,
            &mut config.store,
            &mut config.auth,
            &mut config.secrets,
        )?;

        // Server identity (webvh-server specific env vars)
        macro_rules! env_opt { ($var:expr, $field:expr) => { if let Ok(v) = std::env::var($var) { $field = Some(v); } }; }
        macro_rules! env_parse { ($var:expr, $field:expr) => {
            if let Ok(v) = std::env::var($var) {
                $field = v.parse().map_err(|e| AppError::Config(format!("invalid {}: {e}", $var)))?;
            }
        }; }

        env_opt!("WEBVH_SERVER_DID", config.server_did);
        env_opt!("WEBVH_MEDIATOR_DID", config.mediator_did);
        env_opt!("WEBVH_PUBLIC_URL", config.public_url);
        env_opt!("WEBVH_CONTROL_URL", config.control_url);
        env_opt!("WEBVH_CONTROL_DID", config.control_did);

        // VTA config
        env_opt!("WEBVH_VTA_URL", config.vta.url);
        env_opt!("WEBVH_VTA_DID", config.vta.did);
        env_opt!("WEBVH_VTA_CONTEXT_ID", config.vta.context_id);

        // Limits
        env_parse!("WEBVH_LIMITS_UPLOAD_BODY_LIMIT", config.limits.upload_body_limit);
        env_parse!("WEBVH_LIMITS_DEFAULT_MAX_TOTAL_SIZE", config.limits.default_max_total_size);
        env_parse!("WEBVH_LIMITS_DEFAULT_MAX_DID_COUNT", config.limits.default_max_did_count);

        // Normalize: strip trailing slashes from URLs
        if let Some(ref mut url) = config.public_url {
            let trimmed = url.trim_end_matches('/').to_string();
            *url = trimmed;
        }
        if let Some(ref mut url) = config.control_url {
            let trimmed = url.trim_end_matches('/').to_string();
            *url = trimmed;
        }

        Ok(config)
    }
}

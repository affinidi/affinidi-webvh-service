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
    pub did_hosting_url: Option<String>,
    #[serde(default = "default_server")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store")]
    pub store: StoreConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub vta: VtaConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

fn default_server() -> ServerConfig {
    ServerConfig {
        host: "0.0.0.0".to_string(),
        port: 8532,
    }
}

fn default_store() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/webvh-control"),
        ..StoreConfig::default()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistryConfig {
    #[serde(default)]
    pub instances: Vec<InstanceConfig>,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval: u64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            instances: Vec::new(),
            health_check_interval: default_health_check_interval(),
        }
    }
}

fn default_health_check_interval() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstanceConfig {
    pub label: Option<String>,
    pub service_type: String,
    pub url: String,
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("CONTROL_CONFIG_PATH").ok().map(PathBuf::from))
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

        config.config_path = path;

        // Apply shared env overrides for common config fields
        affinidi_webvh_common::server::config::apply_env_overrides(
            "CONTROL",
            &mut config.features,
            &mut config.server,
            &mut config.log,
            &mut config.store,
            &mut config.auth,
            &mut config.secrets,
        )?;

        // Control-specific env vars
        macro_rules! env_opt {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    $field = Some(v);
                }
            };
        }
        macro_rules! env_parse {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    $field = v
                        .parse()
                        .map_err(|e| AppError::Config(format!("invalid {}: {e}", $var)))?;
                }
            };
        }

        env_opt!("CONTROL_SERVER_DID", config.server_did);
        env_opt!("CONTROL_MEDIATOR_DID", config.mediator_did);
        env_opt!("CONTROL_PUBLIC_URL", config.public_url);
        env_opt!("CONTROL_DID_HOSTING_URL", config.did_hosting_url);

        // VTA config
        env_opt!("CONTROL_VTA_URL", config.vta.url);
        env_opt!("CONTROL_VTA_DID", config.vta.did);
        env_opt!("CONTROL_VTA_CONTEXT_ID", config.vta.context_id);
        env_parse!(
            "CONTROL_REGISTRY_HEALTH_CHECK_INTERVAL",
            config.registry.health_check_interval
        );

        // Normalize: strip trailing slashes from public_url and did_hosting_url
        if let Some(ref mut url) = config.public_url {
            let trimmed = url.trim_end_matches('/').to_string();
            *url = trimmed;
        }
        if let Some(ref mut url) = config.did_hosting_url {
            let trimmed = url.trim_end_matches('/').to_string();
            *url = trimmed;
        }

        Ok(config)
    }
}

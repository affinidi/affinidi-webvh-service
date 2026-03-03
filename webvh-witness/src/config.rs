use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types so existing code can still use `crate::config::*`
pub use affinidi_webvh_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, LogFormat, SecretsConfig, ServerConfig, StoreConfig,
};

// Re-export PlaintextSecrets for setup.rs
#[allow(unused_imports)]
pub use affinidi_webvh_common::server::config::PlaintextSecrets;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub features: FeaturesConfig,
    pub server_did: Option<String>,
    pub mediator_did: Option<String>,
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
    pub vta: VtaConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct VtaConfig {
    /// VTA REST URL for remote key management
    pub url: Option<String>,
    /// VTA DID for DIDComm communication
    pub did: Option<String>,
    /// VTA context ID for witness keys
    pub context_id: Option<String>,
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("WITNESS_CONFIG_PATH").ok().map(PathBuf::from))
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
            "WITNESS",
            &mut config.features,
            &mut config.server,
            &mut config.log,
            &mut config.store,
            &mut config.auth,
            &mut config.secrets,
        )?;

        // Witness-specific env vars
        macro_rules! env_opt { ($var:expr, $field:expr) => { if let Ok(v) = std::env::var($var) { $field = Some(v); } }; }

        env_opt!("WITNESS_SERVER_DID", config.server_did);
        env_opt!("WITNESS_MEDIATOR_DID", config.mediator_did);

        // VTA config
        env_opt!("WITNESS_VTA_URL", config.vta.url);
        env_opt!("WITNESS_VTA_DID", config.vta.did);
        env_opt!("WITNESS_VTA_CONTEXT_ID", config.vta.context_id);

        Ok(config)
    }
}

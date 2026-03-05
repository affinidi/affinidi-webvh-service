use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use affinidi_webvh_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig,
};
use affinidi_webvh_common::server::error::AppError;

/// Daemon-level configuration combining all services.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    /// Shared listener config (single port for all services).
    #[serde(default = "default_server")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,

    // Shared identity
    pub server_did: Option<String>,
    pub mediator_did: Option<String>,
    pub public_url: Option<String>,
    pub did_hosting_url: Option<String>,

    // Per-service store locations (separate to avoid keyspace collisions)
    #[serde(default = "default_server_store")]
    pub server_store: StoreConfig,
    #[serde(default = "default_witness_store")]
    pub witness_store: StoreConfig,
    #[serde(default = "default_watcher_store")]
    pub watcher_store: StoreConfig,
    #[serde(default = "default_control_store")]
    pub control_store: StoreConfig,

    // Server-specific
    #[serde(default)]
    pub limits: affinidi_webvh_server::config::LimitsConfig,
    #[serde(default)]
    pub watchers: Vec<affinidi_webvh_server::config::WatcherEndpoint>,

    // Witness-specific
    #[serde(default)]
    pub vta: affinidi_webvh_witness::config::VtaConfig,

    // Watcher-specific
    #[serde(default)]
    pub watcher_sync: affinidi_webvh_watcher::config::SyncConfig,

    // Control-specific
    #[serde(default)]
    pub registry: affinidi_webvh_control::config::RegistryConfig,

    /// Which services to enable
    #[serde(default)]
    pub enable: EnableConfig,

    #[serde(skip)]
    pub config_path: PathBuf,
}

fn default_server() -> ServerConfig {
    ServerConfig {
        host: "0.0.0.0".to_string(),
        port: 8534,
    }
}

fn default_server_store() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/daemon/server"),
        ..StoreConfig::default()
    }
}

fn default_witness_store() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/daemon/witness"),
        ..StoreConfig::default()
    }
}

fn default_watcher_store() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/daemon/watcher"),
        ..StoreConfig::default()
    }
}

fn default_control_store() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/daemon/control"),
        ..StoreConfig::default()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnableConfig {
    #[serde(default = "default_true")]
    pub server: bool,
    #[serde(default = "default_true")]
    pub witness: bool,
    #[serde(default)]
    pub watcher: bool,
    #[serde(default = "default_true")]
    pub control: bool,
}

fn default_true() -> bool {
    true
}

impl Default for EnableConfig {
    fn default() -> Self {
        Self {
            server: true,
            witness: true,
            watcher: false,
            control: true,
        }
    }
}

impl DaemonConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("DAEMON_CONFIG_PATH").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("config.toml"));

        if !path.exists() {
            return Err(AppError::Config(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }

        let contents = std::fs::read_to_string(&path).map_err(AppError::Io)?;
        let mut config = toml::from_str::<DaemonConfig>(&contents)
            .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?;

        config.config_path = path;

        // Apply env overrides
        macro_rules! env_opt {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    $field = Some(v);
                }
            };
        }

        env_opt!("DAEMON_SERVER_DID", config.server_did);
        env_opt!("DAEMON_MEDIATOR_DID", config.mediator_did);
        env_opt!("DAEMON_PUBLIC_URL", config.public_url);
        env_opt!("DAEMON_DID_HOSTING_URL", config.did_hosting_url);

        if let Ok(v) = std::env::var("DAEMON_SERVER_HOST") {
            config.server.host = v;
        }
        if let Ok(v) = std::env::var("DAEMON_SERVER_PORT") {
            config.server.port = v
                .parse()
                .map_err(|e| AppError::Config(format!("invalid DAEMON_SERVER_PORT: {e}")))?;
        }
        if let Ok(v) = std::env::var("DAEMON_LOG_LEVEL") {
            config.log.level = v;
        }

        // Normalize
        if let Some(ref mut url) = config.public_url {
            *url = url.trim_end_matches('/').to_string();
        }
        if let Some(ref mut url) = config.did_hosting_url {
            *url = url.trim_end_matches('/').to_string();
        }

        Ok(config)
    }

    /// Build a webvh-server AppConfig from the daemon config.
    pub fn server_config(&self) -> affinidi_webvh_server::config::AppConfig {
        affinidi_webvh_server::config::AppConfig {
            features: self.features_config(),
            server_did: self.server_did.clone(),
            mediator_did: self.mediator_did.clone(),
            public_url: self.public_url.clone(),
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.server_store.clone(),
            auth: self.auth.clone(),
            secrets: self.secrets.clone(),
            limits: self.limits.clone(),
            watchers: self.watchers.clone(),
            control_url: None,
            control_did: None,
            config_path: self.config_path.clone(),
        }
    }

    /// Build a webvh-witness AppConfig from the daemon config.
    pub fn witness_config(&self) -> affinidi_webvh_witness::config::AppConfig {
        affinidi_webvh_witness::config::AppConfig {
            features: self.features_config(),
            server_did: self.server_did.clone(),
            mediator_did: self.mediator_did.clone(),
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.witness_store.clone(),
            auth: self.auth.clone(),
            secrets: self.secrets.clone(),
            vta: self.vta.clone(),
            config_path: self.config_path.clone(),
        }
    }

    /// Build a webvh-watcher AppConfig from the daemon config.
    pub fn watcher_config(&self) -> affinidi_webvh_watcher::config::AppConfig {
        affinidi_webvh_watcher::config::AppConfig {
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.watcher_store.clone(),
            sync: self.watcher_sync.clone(),
            config_path: self.config_path.clone(),
        }
    }

    /// Build a webvh-control AppConfig from the daemon config.
    pub fn control_config(&self) -> affinidi_webvh_control::config::AppConfig {
        affinidi_webvh_control::config::AppConfig {
            features: self.features_config(),
            server_did: self.server_did.clone(),
            mediator_did: self.mediator_did.clone(),
            public_url: self.public_url.clone(),
            did_hosting_url: self.did_hosting_url.clone(),
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.control_store.clone(),
            auth: self.auth.clone(),
            secrets: self.secrets.clone(),
            registry: self.registry.clone(),
            config_path: self.config_path.clone(),
        }
    }

    fn features_config(&self) -> FeaturesConfig {
        FeaturesConfig {
            didcomm: false,
            rest_api: true,
        }
    }
}

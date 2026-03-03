use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use affinidi_webvh_common::server::config::{
    LogConfig, LogFormat, ServerConfig, StoreConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct SyncConfig {
    /// Shared secret tokens that source servers must present when pushing.
    #[serde(default)]
    pub push_tokens: Vec<String>,
    /// Source servers to pull from on startup (reconciliation).
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    /// Reconciliation interval in seconds (0 = disabled).
    #[serde(default)]
    pub reconcile_interval: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceConfig {
    pub url: String,
    pub token: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".into(),
                port: 8533,
            },
            log: LogConfig::default(),
            store: StoreConfig {
                data_dir: PathBuf::from("data/webvh-watcher"),
                ..StoreConfig::default()
            },
            sync: SyncConfig::default(),
            config_path: PathBuf::new(),
        }
    }
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("WATCHER_CONFIG_PATH").ok().map(PathBuf::from))
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

        // Watcher-specific env var overrides
        if let Ok(v) = std::env::var("WATCHER_SERVER_HOST") {
            config.server.host = v;
        }
        if let Ok(v) = std::env::var("WATCHER_SERVER_PORT") {
            config.server.port = v
                .parse()
                .map_err(|e| AppError::Config(format!("invalid WATCHER_SERVER_PORT: {e}")))?;
        }
        if let Ok(v) = std::env::var("WATCHER_LOG_LEVEL") {
            config.log.level = v;
        }

        Ok(config)
    }
}

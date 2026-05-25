use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use did_hosting_common::server::config::{LogConfig, LogFormat, ServerConfig, StoreConfig};

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

#[derive(Default, Clone, Deserialize, Serialize)]
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

// `push_tokens` are the shared bearer secrets that gate the /sync push
// endpoint (checked by SyncAuth via constant_time_eq). Manual Debug avoids
// leaking the live credentials via tracing or error formatting.
impl std::fmt::Debug for SyncConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncConfig")
            .field(
                "push_tokens",
                &format_args!("[<{} redacted>]", self.push_tokens.len()),
            )
            .field("sources", &self.sources)
            .field("reconcile_interval", &self.reconcile_interval)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SourceConfig {
    pub url: String,
    pub token: Option<String>,
}

// `token` is the bearer credential this watcher presents when pulling from a
// source server — same redaction class as SyncConfig.push_tokens above.
impl std::fmt::Debug for SourceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceConfig")
            .field("url", &self.url)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".into(),
                port: 8533,
                trusted_proxies: Vec::new(),
                trusted_proxy_cidrs: Vec::new(),
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

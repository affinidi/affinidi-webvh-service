use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct AppConfig {
    pub server_did: Option<String>,
    pub public_url: Option<String>,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    /// Base64url-no-pad encoded 32-byte Ed25519 private key for server DID signing.
    pub signing_key: Option<String>,
    /// Base64url-no-pad encoded 32-byte X25519 private key for server DID key agreement.
    pub key_agreement_key: Option<String>,
    #[serde(skip)]
    pub config_path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StoreConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry: u64,
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry: u64,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl: u64,
    #[serde(default = "default_session_cleanup_interval")]
    pub session_cleanup_interval: u64,
    /// Base64url-no-pad encoded 32-byte Ed25519 private key for JWT signing.
    pub jwt_signing_key: Option<String>,
}

fn default_access_token_expiry() -> u64 {
    900
}

fn default_refresh_token_expiry() -> u64 {
    86400
}

fn default_challenge_ttl() -> u64 {
    300
}

fn default_session_cleanup_interval() -> u64 {
    600
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: default_access_token_expiry(),
            refresh_token_expiry: default_refresh_token_expiry(),
            challenge_ttl: default_challenge_ttl(),
            session_cleanup_interval: default_session_cleanup_interval(),
            jwt_signing_key: None,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    3000
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data/webvh-server")
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
        }
    }
}

impl AppConfig {
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

        // Apply env var overrides
        if let Ok(did) = std::env::var("WEBVH_SERVER_DID") {
            config.server_did = Some(did);
        }
        if let Ok(url) = std::env::var("WEBVH_PUBLIC_URL") {
            config.public_url = Some(url);
        }
        if let Ok(host) = std::env::var("WEBVH_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("WEBVH_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| AppError::Config(format!("invalid WEBVH_SERVER_PORT: {e}")))?;
        }
        if let Ok(level) = std::env::var("WEBVH_LOG_LEVEL") {
            config.log.level = level;
        }
        if let Ok(format) = std::env::var("WEBVH_LOG_FORMAT") {
            config.log.format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "text" => LogFormat::Text,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid WEBVH_LOG_FORMAT '{other}', expected 'text' or 'json'"
                    )));
                }
            };
        }
        if let Ok(data_dir) = std::env::var("WEBVH_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }

        // Auth env var overrides
        if let Ok(expiry) = std::env::var("WEBVH_AUTH_ACCESS_EXPIRY") {
            config.auth.access_token_expiry = expiry
                .parse()
                .map_err(|e| AppError::Config(format!("invalid WEBVH_AUTH_ACCESS_EXPIRY: {e}")))?;
        }
        if let Ok(expiry) = std::env::var("WEBVH_AUTH_REFRESH_EXPIRY") {
            config.auth.refresh_token_expiry = expiry.parse().map_err(|e| {
                AppError::Config(format!("invalid WEBVH_AUTH_REFRESH_EXPIRY: {e}"))
            })?;
        }
        if let Ok(ttl) = std::env::var("WEBVH_AUTH_CHALLENGE_TTL") {
            config.auth.challenge_ttl = ttl
                .parse()
                .map_err(|e| AppError::Config(format!("invalid WEBVH_AUTH_CHALLENGE_TTL: {e}")))?;
        }
        if let Ok(interval) = std::env::var("WEBVH_AUTH_SESSION_CLEANUP_INTERVAL") {
            config.auth.session_cleanup_interval = interval.parse().map_err(|e| {
                AppError::Config(format!(
                    "invalid WEBVH_AUTH_SESSION_CLEANUP_INTERVAL: {e}"
                ))
            })?;
        }
        if let Ok(key) = std::env::var("WEBVH_AUTH_JWT_SIGNING_KEY") {
            config.auth.jwt_signing_key = Some(key);
        }
        if let Ok(key) = std::env::var("WEBVH_SIGNING_KEY") {
            config.signing_key = Some(key);
        }
        if let Ok(key) = std::env::var("WEBVH_KEY_AGREEMENT_KEY") {
            config.key_agreement_key = Some(key);
        }

        Ok(config)
    }
}

use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    /// Base64url-no-pad encoded 32-byte Ed25519 private key for server DID signing.
    pub signing_key: Option<String>,
    /// Base64url-no-pad encoded 32-byte X25519 private key for server DID key agreement.
    pub key_agreement_key: Option<String>,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct FeaturesConfig {
    #[serde(default)]
    pub didcomm: bool,
    #[serde(default)]
    pub rest_api: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    #[serde(default = "default_passkey_enrollment_ttl")]
    pub passkey_enrollment_ttl: u64,
    /// How long (in minutes) to keep empty DID records before auto-cleanup.
    #[serde(default = "default_cleanup_ttl_minutes")]
    pub cleanup_ttl_minutes: u64,
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
    30
}

fn default_session_cleanup_interval() -> u64 {
    600
}

fn default_passkey_enrollment_ttl() -> u64 {
    86400
}

fn default_cleanup_ttl_minutes() -> u64 {
    60
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: default_access_token_expiry(),
            refresh_token_expiry: default_refresh_token_expiry(),
            challenge_ttl: default_challenge_ttl(),
            session_cleanup_interval: default_session_cleanup_interval(),
            passkey_enrollment_ttl: default_passkey_enrollment_ttl(),
            cleanup_ttl_minutes: default_cleanup_ttl_minutes(),
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
    8101
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

        // Env var override macros
        macro_rules! env_str { ($var:expr, $field:expr) => { if let Ok(v) = std::env::var($var) { $field = v; } }; }
        macro_rules! env_opt { ($var:expr, $field:expr) => { if let Ok(v) = std::env::var($var) { $field = Some(v); } }; }
        macro_rules! env_parse { ($var:expr, $field:expr) => {
            if let Ok(v) = std::env::var($var) {
                $field = v.parse().map_err(|e| AppError::Config(format!("invalid {}: {e}", $var)))?;
            }
        }; }
        macro_rules! env_bool { ($var:expr, $field:expr) => {
            if let Ok(v) = std::env::var($var) { $field = v == "1" || v.eq_ignore_ascii_case("true"); }
        }; }

        // Features
        env_bool!("WEBVH_FEATURES_DIDCOMM", config.features.didcomm);
        env_bool!("WEBVH_FEATURES_REST_API", config.features.rest_api);

        // Server identity
        env_opt!("WEBVH_SERVER_DID", config.server_did);
        env_opt!("WEBVH_MEDIATOR_DID", config.mediator_did);
        env_opt!("WEBVH_PUBLIC_URL", config.public_url);

        // Server
        env_str!("WEBVH_SERVER_HOST", config.server.host);
        env_parse!("WEBVH_SERVER_PORT", config.server.port);

        // Logging
        env_str!("WEBVH_LOG_LEVEL", config.log.level);
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

        // Store
        if let Ok(data_dir) = std::env::var("WEBVH_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }

        // Auth
        env_parse!("WEBVH_AUTH_ACCESS_EXPIRY", config.auth.access_token_expiry);
        env_parse!("WEBVH_AUTH_REFRESH_EXPIRY", config.auth.refresh_token_expiry);
        env_parse!("WEBVH_AUTH_CHALLENGE_TTL", config.auth.challenge_ttl);
        env_parse!("WEBVH_AUTH_SESSION_CLEANUP_INTERVAL", config.auth.session_cleanup_interval);
        env_parse!("WEBVH_AUTH_PASSKEY_ENROLLMENT_TTL", config.auth.passkey_enrollment_ttl);
        env_parse!("WEBVH_CLEANUP_TTL_MINUTES", config.auth.cleanup_ttl_minutes);
        env_opt!("WEBVH_AUTH_JWT_SIGNING_KEY", config.auth.jwt_signing_key);

        // Keys
        env_opt!("WEBVH_SIGNING_KEY", config.signing_key);
        env_opt!("WEBVH_KEY_AGREEMENT_KEY", config.key_agreement_key);

        // Limits
        env_parse!("WEBVH_LIMITS_UPLOAD_BODY_LIMIT", config.limits.upload_body_limit);
        env_parse!("WEBVH_LIMITS_DEFAULT_MAX_TOTAL_SIZE", config.limits.default_max_total_size);
        env_parse!("WEBVH_LIMITS_DEFAULT_MAX_DID_COUNT", config.limits.default_max_did_count);

        Ok(config)
    }
}

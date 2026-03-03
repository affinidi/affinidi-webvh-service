use super::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    /// Redis connection URL (e.g. `redis://localhost:6379`). Used by `store-redis` backend.
    pub redis_url: Option<String>,
    /// DynamoDB table name prefix (default: `"webvh"`). Used by `store-dynamodb` backend.
    pub dynamodb_table_prefix: Option<String>,
    /// AWS region for DynamoDB. Used by `store-dynamodb` backend.
    pub dynamodb_region: Option<String>,
    /// GCP project ID for Firestore. Used by `store-firestore` backend.
    pub firestore_project: Option<String>,
    /// Firestore database name (default: `"(default)"`). Used by `store-firestore` backend.
    pub firestore_database: Option<String>,
    /// Azure Cosmos DB connection string. Used by `store-cosmosdb` backend.
    pub cosmosdb_connection_string: Option<String>,
    /// Cosmos DB database name (default: `"webvh"`). Used by `store-cosmosdb` backend.
    pub cosmosdb_database: Option<String>,
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
    8530
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
            redis_url: None,
            dynamodb_table_prefix: None,
            dynamodb_region: None,
            firestore_project: None,
            firestore_database: None,
            cosmosdb_connection_string: None,
            cosmosdb_database: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    pub aws_secret_name: Option<String>,
    pub aws_region: Option<String>,
    pub gcp_project: Option<String>,
    pub gcp_secret_name: Option<String>,
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
    /// Plaintext secrets stored directly in the config file.
    /// Only used when no secure backend (keyring, AWS, GCP) is compiled in.
    pub plaintext: Option<PlaintextSecrets>,
}

/// Plaintext secret key material stored directly in the configuration file.
///
/// **WARNING**: This is insecure and should only be used for testing/development.
/// For production deployments, compile with a secure backend feature:
/// `keyring`, `aws-secrets`, or `gcp-secrets`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PlaintextSecrets {
    pub signing_key: String,
    pub key_agreement_key: String,
    pub jwt_signing_key: String,
}

fn default_keyring_service() -> String {
    "webvh".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            keyring_service: default_keyring_service(),
            plaintext: None,
        }
    }
}

/// Apply environment variable overrides to shared config fields.
///
/// Call this from your application's `AppConfig::load()` after deserializing the
/// TOML file. The `prefix` argument controls the env var namespace
/// (e.g. `"WEBVH"` for webvh-server, `"WITNESS"` for webvh-witness).
pub fn apply_env_overrides(
    prefix: &str,
    features: &mut FeaturesConfig,
    server: &mut ServerConfig,
    log: &mut LogConfig,
    store: &mut StoreConfig,
    auth: &mut AuthConfig,
    secrets: &mut SecretsConfig,
) -> Result<(), AppError> {
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
    env_bool!(&format!("{prefix}_FEATURES_DIDCOMM"), features.didcomm);
    env_bool!(&format!("{prefix}_FEATURES_REST_API"), features.rest_api);

    // Server
    env_str!(&format!("{prefix}_SERVER_HOST"), server.host);
    env_parse!(&format!("{prefix}_SERVER_PORT"), server.port);

    // Logging
    env_str!(&format!("{prefix}_LOG_LEVEL"), log.level);
    let log_format_var = format!("{prefix}_LOG_FORMAT");
    if let Ok(format) = std::env::var(&log_format_var) {
        log.format = match format.to_lowercase().as_str() {
            "json" => LogFormat::Json,
            "text" => LogFormat::Text,
            other => {
                return Err(AppError::Config(format!(
                    "invalid {log_format_var} '{other}', expected 'text' or 'json'"
                )));
            }
        };
    }

    // Store
    let store_data_dir_var = format!("{prefix}_STORE_DATA_DIR");
    if let Ok(data_dir) = std::env::var(&store_data_dir_var) {
        store.data_dir = PathBuf::from(data_dir);
    }
    env_opt!(&format!("{prefix}_STORE_REDIS_URL"), store.redis_url);
    env_opt!(&format!("{prefix}_STORE_DYNAMODB_TABLE_PREFIX"), store.dynamodb_table_prefix);
    env_opt!(&format!("{prefix}_STORE_DYNAMODB_REGION"), store.dynamodb_region);
    env_opt!(&format!("{prefix}_STORE_FIRESTORE_PROJECT"), store.firestore_project);
    env_opt!(&format!("{prefix}_STORE_FIRESTORE_DATABASE"), store.firestore_database);
    env_opt!(&format!("{prefix}_STORE_COSMOSDB_CONNECTION_STRING"), store.cosmosdb_connection_string);
    env_opt!(&format!("{prefix}_STORE_COSMOSDB_DATABASE"), store.cosmosdb_database);

    // Auth
    env_parse!(&format!("{prefix}_AUTH_ACCESS_EXPIRY"), auth.access_token_expiry);
    env_parse!(&format!("{prefix}_AUTH_REFRESH_EXPIRY"), auth.refresh_token_expiry);
    env_parse!(&format!("{prefix}_AUTH_CHALLENGE_TTL"), auth.challenge_ttl);
    env_parse!(&format!("{prefix}_AUTH_SESSION_CLEANUP_INTERVAL"), auth.session_cleanup_interval);
    env_parse!(&format!("{prefix}_AUTH_PASSKEY_ENROLLMENT_TTL"), auth.passkey_enrollment_ttl);
    env_parse!(&format!("{prefix}_CLEANUP_TTL_MINUTES"), auth.cleanup_ttl_minutes);

    // Secrets
    env_opt!(&format!("{prefix}_SECRETS_AWS_SECRET_NAME"), secrets.aws_secret_name);
    env_opt!(&format!("{prefix}_SECRETS_AWS_REGION"), secrets.aws_region);
    env_opt!(&format!("{prefix}_SECRETS_GCP_PROJECT"), secrets.gcp_project);
    env_opt!(&format!("{prefix}_SECRETS_GCP_SECRET_NAME"), secrets.gcp_secret_name);
    env_str!(&format!("{prefix}_SECRETS_KEYRING_SERVICE"), secrets.keyring_service);

    Ok(())
}

/// Initialize the tracing subscriber based on config.
pub fn init_tracing(log: &LogConfig) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log.level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    match log.format {
        LogFormat::Json => subscriber.json().init(),
        LogFormat::Text => subscriber.init(),
    }
}

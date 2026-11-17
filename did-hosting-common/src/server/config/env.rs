//! Environment-variable overrides applied over the shared config sections.

use crate::server::error::AppError;

use super::{
    AuthConfig, FeaturesConfig, LogConfig, LogFormat, SecretsConfig, ServerConfig, StoreConfig,
    apply_store_env_overrides,
};

/// A boolean environment variable: `1`/`true`/`yes`/`on` or
/// `0`/`false`/`no`/`off` (any case, surrounding whitespace ignored).
/// Anything else is refused with an error naming `var`, rather than read as
/// `false`.
pub fn parse_env_bool(var: &str, value: &str) -> Result<bool, AppError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(AppError::Config(format!(
            "invalid {var}: `{value}` is not a boolean (use 1/true/yes/on or 0/false/no/off)"
        ))),
    }
}

/// Apply environment variable overrides to shared config fields.
///
/// Call this from your application's `AppConfig::load()` after deserializing the
/// TOML file. The `prefix` argument controls the env var namespace
/// (e.g. `"WEBVH"` for did-hosting-server, `"WITNESS"` for webvh-witness).
pub fn apply_env_overrides(
    prefix: &str,
    features: &mut FeaturesConfig,
    server: &mut ServerConfig,
    log: &mut LogConfig,
    store: &mut StoreConfig,
    auth: &mut AuthConfig,
    secrets: &mut SecretsConfig,
) -> Result<(), AppError> {
    macro_rules! env_str {
        ($var:expr, $field:expr) => {
            if let Ok(v) = std::env::var($var) {
                $field = v;
            }
        };
    }
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
    macro_rules! env_bool {
        ($var:expr, $field:expr) => {
            let var: &str = $var;
            if let Ok(v) = std::env::var(var) {
                $field = parse_env_bool(var, &v)?;
            }
        };
    }

    // Features
    env_bool!(&format!("{prefix}_FEATURES_DIDCOMM"), features.didcomm);
    env_bool!(&format!("{prefix}_FEATURES_TSP"), features.tsp);
    // `_REST_API` is the flag's former name, read first so the current name
    // wins when both are set.
    env_bool!(
        &format!("{prefix}_FEATURES_REST_API"),
        features.http_listener
    );
    env_bool!(
        &format!("{prefix}_FEATURES_HTTP_LISTENER"),
        features.http_listener
    );
    env_bool!(
        &format!("{prefix}_FEATURES_AGENT_NAMES"),
        features.agent_names
    );

    // Server
    env_str!(&format!("{prefix}_SERVER_HOST"), server.host);
    env_parse!(&format!("{prefix}_SERVER_PORT"), server.port);
    server.apply_trusted_proxies_env_override(prefix)?;

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
    apply_store_env_overrides(&format!("{prefix}_STORE"), store)?;

    // Auth
    env_parse!(
        &format!("{prefix}_AUTH_ACCESS_EXPIRY"),
        auth.access_token_expiry
    );
    env_parse!(
        &format!("{prefix}_AUTH_REFRESH_EXPIRY"),
        auth.refresh_token_expiry
    );
    env_parse!(&format!("{prefix}_AUTH_CHALLENGE_TTL"), auth.challenge_ttl);
    env_parse!(
        &format!("{prefix}_AUTH_SESSION_CLEANUP_INTERVAL"),
        auth.session_cleanup_interval
    );
    env_parse!(
        &format!("{prefix}_AUTH_ADMIN_IDLE_TIMEOUT"),
        auth.admin_idle_timeout
    );
    env_parse!(
        &format!("{prefix}_AUTH_PASSKEY_ENROLLMENT_TTL"),
        auth.passkey_enrollment_ttl
    );
    env_parse!(
        &format!("{prefix}_AUTH_CLAIM_CODE_HASH_WAIT_MS"),
        auth.claim_code_hash_wait_ms
    );
    env_parse!(
        &format!("{prefix}_CLEANUP_TTL_MINUTES"),
        auth.cleanup_ttl_minutes
    );
    env_parse!(
        &format!("{prefix}_AUTH_MAX_GLOBAL_PENDING_CHALLENGES"),
        auth.max_global_pending_challenges
    );
    env_parse!(
        &format!("{prefix}_AUTH_MAX_PENDING_CHALLENGES_PER_DID"),
        auth.max_pending_challenges_per_did
    );

    // Secrets
    env_opt!(
        &format!("{prefix}_SECRETS_AWS_SECRET_NAME"),
        secrets.aws_secret_name
    );
    env_opt!(&format!("{prefix}_SECRETS_AWS_REGION"), secrets.aws_region);
    env_opt!(
        &format!("{prefix}_SECRETS_GCP_PROJECT"),
        secrets.gcp_project
    );
    env_opt!(
        &format!("{prefix}_SECRETS_GCP_SECRET_NAME"),
        secrets.gcp_secret_name
    );
    env_opt!(
        &format!("{prefix}_SECRETS_AZURE_VAULT_URL"),
        secrets.azure_vault_url
    );
    env_opt!(
        &format!("{prefix}_SECRETS_AZURE_SECRET_NAME"),
        secrets.azure_secret_name
    );
    env_str!(
        &format!("{prefix}_SECRETS_KEYRING_SERVICE"),
        secrets.keyring_service
    );

    // Secrets — HashiCorp Vault (vault-secrets)
    env_opt!(&format!("{prefix}_SECRETS_VAULT_ADDR"), secrets.vault_addr);
    env_str!(
        &format!("{prefix}_SECRETS_VAULT_KV_MOUNT"),
        secrets.vault_kv_mount
    );
    env_opt!(
        &format!("{prefix}_SECRETS_VAULT_SECRET_PATH"),
        secrets.vault_secret_path
    );
    env_str!(
        &format!("{prefix}_SECRETS_VAULT_SECRET_KEY"),
        secrets.vault_secret_key
    );
    env_opt!(
        &format!("{prefix}_SECRETS_VAULT_NAMESPACE"),
        secrets.vault_namespace
    );
    env_str!(
        &format!("{prefix}_SECRETS_VAULT_AUTH_METHOD"),
        secrets.vault_auth_method
    );
    env_opt!(
        &format!("{prefix}_SECRETS_VAULT_K8S_ROLE"),
        secrets.vault_k8s_role
    );
    env_str!(
        &format!("{prefix}_SECRETS_VAULT_K8S_MOUNT"),
        secrets.vault_k8s_mount
    );
    env_str!(
        &format!("{prefix}_SECRETS_VAULT_K8S_JWT_PATH"),
        secrets.vault_k8s_jwt_path
    );
    env_opt!(
        &format!("{prefix}_SECRETS_VAULT_TOKEN"),
        secrets.vault_token
    );
    env_opt!(
        &format!("{prefix}_SECRETS_VAULT_APPROLE_ROLE_ID"),
        secrets.vault_approle_role_id
    );
    env_opt!(
        &format!("{prefix}_SECRETS_VAULT_APPROLE_SECRET_ID"),
        secrets.vault_approle_secret_id
    );
    env_str!(
        &format!("{prefix}_SECRETS_VAULT_APPROLE_MOUNT"),
        secrets.vault_approle_mount
    );
    env_bool!(
        &format!("{prefix}_SECRETS_VAULT_SKIP_VERIFY"),
        secrets.vault_skip_verify
    );

    // Secrets — native Kubernetes Secret (k8s-secrets)
    env_opt!(
        &format!("{prefix}_SECRETS_K8S_SECRET_NAME"),
        secrets.k8s_secret_name
    );
    env_opt!(
        &format!("{prefix}_SECRETS_K8S_NAMESPACE"),
        secrets.k8s_namespace
    );
    env_str!(
        &format!("{prefix}_SECRETS_K8S_SECRET_KEY"),
        secrets.k8s_secret_key
    );

    Ok(())
}

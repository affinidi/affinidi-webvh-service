//! The witness's `config.toml` ([`AppConfig`]), loaded from file with
//! environment overrides.

use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types so existing code can still use `crate::config::*`
pub use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, FjallTuning, LogConfig, LogFormat, SecretsConfig, ServerConfig,
    StoreConfig, VtaConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub features: FeaturesConfig,
    pub server_did: Option<String>,
    pub mediator_did: Option<String>,
    #[serde(default = "default_server")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store")]
    pub store: StoreConfig,
    /// Optional Fjall memory tuning (`[fjall]`) — the block cache, write
    /// buffer and journal-size caps that keep the store's memory use
    /// inside a pod's Kubernetes limit. Every field defaults to `None`
    /// (fjall's own defaults, unchanged). See
    /// [`did_hosting_common::server::config::FjallTuning`].
    #[serde(default)]
    pub fjall: FjallTuning,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub vta: VtaConfig,
    /// How the service's own identity is produced, and how long a superseded
    /// generation keeps being honoured after a rotation.
    #[serde(default)]
    pub identity: did_hosting_common::server::config::IdentityConfig,
    /// Bounds of the anti-replay cache for signed Trust Tasks (`[replay]`;
    /// env `WITNESS_REPLAY_*`).
    #[serde(
        default,
        skip_serializing_if = "did_hosting_common::server::config::ReplayConfig::is_default"
    )]
    pub replay: did_hosting_common::server::config::ReplayConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

fn default_server() -> ServerConfig {
    ServerConfig {
        host: "0.0.0.0".to_string(),
        port: 8531,
        trusted_proxies: Vec::new(),
        client_ipv6_prefix: did_hosting_common::server::config::default_client_ipv6_prefix(),
        trusted_proxy_cidrs: Vec::new(),
        resolve_cache: Default::default(),
        resolve_rate_limit: Default::default(),
    }
}

fn default_store() -> StoreConfig {
    StoreConfig {
        data_dir: std::path::PathBuf::from("data/webvh-witness"),
        ..StoreConfig::default()
    }
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
        did_hosting_common::server::config::apply_env_overrides(
            "WITNESS",
            &mut config.features,
            &mut config.server,
            &mut config.log,
            &mut config.store,
            // The witness holds no sessions: nothing reads the auth settings.
            &mut AuthConfig::default(),
            &mut config.secrets,
        )?;
        // Fjall memory settings (STORAGE_FJALL_BLOCK_CACHE / _WRITE_BUFFER /
        // _MAX_JOURNAL) — shared, unprefixed names; see
        // `did_hosting_common::server::config::apply_fjall_env_overrides`.
        did_hosting_common::server::config::apply_fjall_env_overrides(&mut config.fjall)?;
        // WITNESS_REPLAY_* — anti-replay cache bounds. Also validates `[replay]`.
        config.replay.apply_env_overrides("WITNESS")?;

        // Witness-specific env vars
        macro_rules! env_opt {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var) {
                    $field = Some(v);
                }
            };
        }

        env_opt!("WITNESS_SERVER_DID", config.server_did);
        env_opt!("WITNESS_MEDIATOR_DID", config.mediator_did);

        // VTA config
        env_opt!("WITNESS_VTA_URL", config.vta.url);
        env_opt!("WITNESS_VTA_DID", config.vta.did);
        env_opt!("WITNESS_VTA_CONTEXT_ID", config.vta.context_id);

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the setup wizard and recipe write (a serialised `AppConfig`)
    /// loads back under the strict parser, with the default port 8531;
    /// misspelt keys are refused and the former `rest_api` name still loads.
    #[test]
    fn a_written_config_loads_and_typos_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config: AppConfig = toml::from_str("").unwrap();
        assert_eq!(config.server.port, 8531);
        config.server_did = Some("did:webvh:abc:witness.example.com".into());
        config.features.http_listener = true;
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();
        let loaded = AppConfig::load(Some(path.clone())).expect("written config loads");
        assert!(loaded.features.http_listener);

        std::fs::write(&path, "[features]\nrest_api = true\n").unwrap();
        assert!(
            AppConfig::load(Some(path.clone()))
                .unwrap()
                .features
                .http_listener
        );

        for bad in [
            "sever_did = \"did:example:x\"\n",
            "[store]\ndatadir = \"x\"\n",
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(AppConfig::load(Some(path.clone())).is_err(), "{bad}");
        }
    }
}

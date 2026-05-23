use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, HostingConfig, IdentityConfig, IdentityMode, LogConfig,
    SecretsConfig, ServerConfig, StoreConfig,
};
use did_hosting_common::server::error::AppError;

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

    // Store locations
    #[serde(default = "default_store")]
    pub store: StoreConfig,
    #[serde(default = "default_witness_store")]
    pub witness_store: StoreConfig,

    // Server-specific
    #[serde(default)]
    pub limits: did_hosting_server::config::LimitsConfig,
    #[serde(default)]
    pub watchers: Vec<did_hosting_server::config::WatcherEndpoint>,

    // Witness-specific
    #[serde(default)]
    pub vta: did_hosting_common::server::config::VtaConfig,

    // Watcher-specific
    #[serde(default)]
    pub watcher_sync: webvh_watcher::config::SyncConfig,

    // Control-specific
    #[serde(default)]
    pub registry: did_hosting_control::config::RegistryConfig,

    /// Feature flags (didcomm, rest_api).
    #[serde(default)]
    pub features: FeaturesConfig,

    /// How the daemon obtains its own identity (VTA-provisioned or self-managed).
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Multi-domain hosting settings (T18). `bootstrap_domains` seeds
    /// the `domains` keyspace on first boot when no entries exist;
    /// `unassigned_purge_grace` controls the retain-then-purge window
    /// for domains the control plane has unassigned from this server.
    #[serde(default)]
    pub hosting: HostingConfig,

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
        trusted_proxies: Vec::new(),
        trusted_proxy_cidrs: Vec::new(),
    }
}

fn default_store() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/daemon/store"),
        ..StoreConfig::default()
    }
}

fn default_witness_store() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/daemon/witness"),
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

        if let Ok(v) = std::env::var("DID_HOSTING_IDENTITY_MODE") {
            config.identity.mode = match v.to_ascii_lowercase().as_str() {
                "vta" => IdentityMode::Vta,
                "self-managed" | "selfmanaged" => IdentityMode::SelfManaged,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid DID_HOSTING_IDENTITY_MODE '{other}' (expected 'vta' or 'self-managed')"
                    )));
                }
            };
        }

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

    /// Build a did-hosting-server AppConfig from the daemon config.
    pub fn server_config(&self) -> did_hosting_server::config::AppConfig {
        did_hosting_server::config::AppConfig {
            features: self.features_config(),
            server_did: self.server_did.clone(),
            mediator_did: self.mediator_did.clone(),
            public_url: self.public_url.clone(),
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.store.clone(),
            auth: self.auth.clone(),
            hosting: self.hosting.clone(),
            secrets: self.secrets.clone(),
            limits: self.limits.clone(),
            watchers: self.watchers.clone(),
            control_url: None,
            control_did: None,
            vta: self.vta.clone(),
            stats: did_hosting_server::config::StatsConfig::default(),
            config_path: self.config_path.clone(),
        }
    }

    /// Build a webvh-witness AppConfig from the daemon config.
    pub fn witness_config(&self) -> webvh_witness::config::AppConfig {
        webvh_witness::config::AppConfig {
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
    pub fn watcher_config(&self) -> webvh_watcher::config::AppConfig {
        webvh_watcher::config::AppConfig {
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.store.clone(),
            sync: self.watcher_sync.clone(),
            config_path: self.config_path.clone(),
        }
    }

    /// Build a did-hosting-control AppConfig from the daemon config.
    pub fn control_config(&self) -> did_hosting_control::config::AppConfig {
        did_hosting_control::config::AppConfig {
            features: self.features_config(),
            server_did: self.server_did.clone(),
            mediator_did: self.mediator_did.clone(),
            step_up_trusted_vta_did: None,
            public_url: self.public_url.clone(),
            did_hosting_url: self.did_hosting_url.clone(),
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.store.clone(),
            auth: self.auth.clone(),
            secrets: self.secrets.clone(),
            vta: self.vta.clone(),
            registry: self.registry.clone(),
            trust_tasks: did_hosting_control::config::TrustTasksConfig::default(),
            hosting: self.hosting.clone(),
            config_path: self.config_path.clone(),
        }
    }

    fn features_config(&self) -> FeaturesConfig {
        FeaturesConfig {
            didcomm: self.features.didcomm,
            rest_api: self.features.rest_api,
            deployment_mode: "daemon".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Minimal self-managed config: `[identity] mode = "self-managed"`,
    /// no `[vta]` block at all (back-compat with existing parsers).
    const SELF_MANAGED_TOML: &str = r#"
public_url = "https://daemon.example.com"
did_hosting_url = "https://daemon.example.com"

[identity]
mode = "self-managed"

[server]
host = "0.0.0.0"
port = 8534

[log]
level = "info"
format = "text"

[store]
data_dir = "data/daemon/store"

[witness_store]
data_dir = "data/daemon/witness"

[auth]

[secrets]
plaintext = { signing_key = "z3uABC", key_agreement_key = "z3uDEF", jwt_signing_key = "z3uGHI" }
"#;

    /// Minimal VTA-mode config (the back-compat case — no `[identity]`
    /// block at all, so the loader must default `identity.mode` to `Vta`).
    const VTA_DEFAULT_TOML: &str = r#"
public_url = "https://daemon.example.com"
did_hosting_url = "https://daemon.example.com"

[server]
host = "0.0.0.0"
port = 8534

[log]
level = "info"
format = "text"

[store]
data_dir = "data/daemon/store"

[witness_store]
data_dir = "data/daemon/witness"

[auth]

[secrets]
plaintext = { signing_key = "z3uABC", key_agreement_key = "z3uDEF", jwt_signing_key = "z3uGHI" }

[vta]
url = "https://vta.example.com"
did = "did:webvh:vta.example.com"
context_id = "webvh"
"#;

    fn write_temp_config(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&path).expect("create config");
        f.write_all(contents.as_bytes()).expect("write config");
        (dir, path)
    }

    #[test]
    fn loads_self_managed_config_with_empty_vta() {
        let (_dir, path) = write_temp_config(SELF_MANAGED_TOML);

        let cfg = DaemonConfig::load(Some(path)).expect("load self-managed config");

        assert_eq!(cfg.identity.mode, IdentityMode::SelfManaged);
        assert!(cfg.vta.url.is_none(), "vta.url should be None");
        assert!(cfg.vta.did.is_none(), "vta.did should be None");
        assert!(
            cfg.vta.context_id.is_none(),
            "vta.context_id should be None"
        );
        assert_eq!(
            cfg.public_url.as_deref(),
            Some("https://daemon.example.com")
        );
    }

    #[test]
    fn loads_vta_config_without_identity_block_defaults_to_vta() {
        // Back-compat: existing VTA-mode configs don't have an `[identity]`
        // block. The loader must default `identity.mode = Vta`.
        let (_dir, path) = write_temp_config(VTA_DEFAULT_TOML);

        let cfg = DaemonConfig::load(Some(path)).expect("load VTA-default config");

        assert_eq!(
            cfg.identity.mode,
            IdentityMode::Vta,
            "missing [identity] block should default to Vta"
        );
        assert_eq!(cfg.vta.url.as_deref(), Some("https://vta.example.com"));
        assert_eq!(cfg.vta.did.as_deref(), Some("did:webvh:vta.example.com"));
    }

    // DID_HOSTING_IDENTITY_MODE env-override coverage lives in did-hosting-common's
    // IdentityMode parsing tests. A daemon-level env test would race
    // against parallel tests in the same process (env vars are
    // process-wide), and the daemon's override code is just a 3-arm
    // match — not worth a serialised mutex harness.
}

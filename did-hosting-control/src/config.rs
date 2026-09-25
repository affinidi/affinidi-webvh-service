use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types so existing code can still use `crate::config::*`
pub use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, HostingConfig, LogConfig, LogFormat, SecretsConfig, ServerConfig,
    StoreConfig, TransportSelection, VtaConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub features: FeaturesConfig,
    pub server_did: Option<String>,
    pub mediator_did: Option<String>,
    pub public_url: Option<String>,
    pub did_hosting_url: Option<String>,
    #[serde(default = "default_server")]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_store")]
    pub store: StoreConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub vta: VtaConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
    /// Multi-domain hosting knobs. Today the control plane reads
    /// `hosting.disable_purge_grace` to schedule the soft-delete
    /// timer; `bootstrap_domains` + `unassigned_purge_grace` are
    /// server-side concerns (replicated here for shared-store
    /// deployments where one fjall directory backs both processes).
    #[serde(default)]
    pub hosting: HostingConfig,
    /// Trust Tasks (v0.7.0+) configuration.
    #[serde(default)]
    pub trust_tasks: TrustTasksConfig,
    /// How the service's own identity is produced, and how long a superseded
    /// generation keeps being honoured after a rotation
    /// (`identity.rotation_grace_period`).
    #[serde(default)]
    pub identity: did_hosting_common::server::config::IdentityConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

/// Trust Tasks framework runtime knobs.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustTasksConfig {
    /// Retained only so an existing config that sets it still parses.
    ///
    /// Proofs are now verified on every trust-task path, and every privileged
    /// document must carry one bound to its sender; there is no mode that
    /// accepts or ignores proofs. `true` (the default) is a no-op, and
    /// `false` is refused at startup by [`AppConfig::load`] rather than
    /// silently disregarded — an operator who turned verification off must
    /// learn that it is back on.
    #[serde(default = "default_enforce_proofs")]
    pub enforce_proofs: bool,
}

fn default_enforce_proofs() -> bool {
    true
}

impl Default for TrustTasksConfig {
    fn default() -> Self {
        Self {
            enforce_proofs: default_enforce_proofs(),
        }
    }
}

fn default_server() -> ServerConfig {
    ServerConfig {
        host: "0.0.0.0".to_string(),
        port: 8532,
        trusted_proxies: Vec::new(),
        trusted_proxy_cidrs: Vec::new(),
    }
}

fn default_store() -> StoreConfig {
    StoreConfig {
        data_dir: PathBuf::from("data/did-hosting-control"),
        ..StoreConfig::default()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistryConfig {
    #[serde(default)]
    pub instances: Vec<InstanceConfig>,
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval: u64,
    /// Hostname allowlist for registered service-instance URLs.
    ///
    /// This bounds two things: which hosts may be **registered** (via the
    /// registration API / `MSG_SERVER_REGISTER`), and — load-bearing for
    /// security — which hosts the Admin **reverse proxy**
    /// (`/api/server|witness/{instance}/{*path}`) will forward the caller's
    /// Admin `Authorization` credential to.
    ///
    /// Matching is on the URL **host only** (scheme and port are ignored),
    /// case-insensitive, and **exact** — an entry `example.com` does NOT match
    /// `evil.example.com`.
    ///
    /// Behaviour by state (post SEC-4045 W6 hardening):
    ///
    /// - **Non-empty:** registration rejects any URL whose host is not listed,
    ///   and the proxy forwards only to listed hosts. This is the recommended
    ///   configuration for any deployment that uses the proxy.
    /// - **Empty (the default):** registration still **default-denies**
    ///   non-routable / internal *literal* hosts (loopback, RFC1918,
    ///   link-local incl. `169.254.169.254`, CGNAT, ULA, IPv4-mapped) — a
    ///   public host is still accepted — and the **proxy is fail-closed**: it
    ///   refuses every request rather than forward an Admin credential to a
    ///   host the operator never vetted. So an unconfigured allowlist disables
    ///   the proxy; it does not open it.
    ///
    /// See `validate_registered_url` (registration) and
    /// `validate_proxy_target_url` (proxy) for the enforcement.
    #[serde(default)]
    pub url_allowlist: Vec<String>,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            instances: Vec::new(),
            health_check_interval: default_health_check_interval(),
            url_allowlist: Vec::new(),
        }
    }
}

fn default_health_check_interval() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstanceConfig {
    pub label: Option<String>,
    pub service_type: String,
    pub url: String,
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("CONTROL_CONFIG_PATH").ok().map(PathBuf::from))
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

        if !config.trust_tasks.enforce_proofs {
            return Err(AppError::Config(
                "trust_tasks.enforce_proofs = false is no longer supported: every privileged \
                 trust task must carry a proof bound to its sender. Remove the setting."
                    .into(),
            ));
        }

        // Apply shared env overrides for common config fields
        did_hosting_common::server::config::apply_env_overrides(
            "CONTROL",
            &mut config.features,
            &mut config.server,
            &mut config.log,
            &mut config.store,
            &mut config.auth,
            &mut config.secrets,
        )?;

        // Control-specific env vars
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

        env_opt!("CONTROL_SERVER_DID", config.server_did);
        env_opt!("CONTROL_MEDIATOR_DID", config.mediator_did);
        env_opt!("CONTROL_PUBLIC_URL", config.public_url);
        env_opt!("CONTROL_DID_HOSTING_URL", config.did_hosting_url);

        // VTA config
        env_opt!("CONTROL_VTA_URL", config.vta.url);
        env_opt!("CONTROL_VTA_DID", config.vta.did);
        env_opt!("CONTROL_VTA_CONTEXT_ID", config.vta.context_id);
        env_parse!(
            "CONTROL_REGISTRY_HEALTH_CHECK_INTERVAL",
            config.registry.health_check_interval
        );

        // Normalize: strip trailing slashes from public_url and did_hosting_url
        if let Some(ref mut url) = config.public_url {
            let trimmed = url.trim_end_matches('/').to_string();
            *url = trimmed;
        }
        if let Some(ref mut url) = config.did_hosting_url {
            let trimmed = url.trim_end_matches('/').to_string();
            *url = trimmed;
        }

        Ok(config)
    }
}

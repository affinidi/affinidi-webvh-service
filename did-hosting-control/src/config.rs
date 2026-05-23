use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types so existing code can still use `crate::config::*`
pub use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, HostingConfig, LogConfig, LogFormat, SecretsConfig, ServerConfig,
    StoreConfig, VtaConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub features: FeaturesConfig,
    pub server_did: Option<String>,
    pub mediator_did: Option<String>,
    /// VTA DID trusted to issue step-up approvals. When set, a VTA-signed
    /// approval token from this DID elevates a session to `aal2`
    /// (`amr: [did, vta]`). The single-trusted-VTA model (this is the RP's
    /// provisioning VTA); per-holder VTA discovery is future work.
    #[serde(default)]
    pub step_up_trusted_vta_did: Option<String>,
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
    #[serde(skip)]
    pub config_path: PathBuf,
}

/// Trust Tasks framework runtime knobs.
///
/// Introduced in v0.7.0 with `enforce_proofs` defaulting to `true`
/// — the framework's 0.1.1 `IS_PROOF_REQUIRED` enforcement makes
/// `acl/grant`, `acl/revoke`, and `acl/change-role` unreachable
/// without a verified proof, and the Web UI ships ephemeral Ed25519
/// session-key signing in this release so the default produces a
/// working deployment out-of-the-box.
///
/// Setting this to `false` switches the dispatcher to
/// [`trust_tasks_rs::ProofPolicy::RejectIfPresent`] — a proof-bearing
/// document is rejected with `malformed_request`. RECOMMENDED specs
/// (acl/list, acl/show, trust-task-discovery) continue to work
/// proofless under either policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrustTasksConfig {
    /// When `true` (default), dispatch passes the configured proof
    /// verifier (`state.trust_tasks_verifier`) through as
    /// [`trust_tasks_rs::ProofPolicy::Verify`]. Proof-bearing documents
    /// are verified; REQUIRED-spec documents without a proof are
    /// rejected with `proof_required`. When `false`, the dispatcher
    /// runs in [`trust_tasks_rs::ProofPolicy::RejectIfPresent`] mode:
    /// proof-bearing documents are rejected with `malformed_request`,
    /// so a producer that signed in-band is never silently
    /// downgraded.
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
    /// Hostname allowlist for service registration via the API.
    ///
    /// When non-empty, `register_service` rejects URLs whose host is not in
    /// this list. The proxy at `/api/server/{instance}/{*path}` only
    /// forwards to URLs that have been registered, so the allowlist
    /// transitively bounds where the proxy can reach. When empty, registry
    /// URLs are accepted unrestricted (back-compat default for trusted
    /// internal deployments).
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
        env_opt!(
            "CONTROL_STEP_UP_TRUSTED_VTA_DID",
            config.step_up_trusted_vta_did
        );
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

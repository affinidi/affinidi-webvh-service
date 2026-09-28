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
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    /// Multi-domain hosting (bootstrap_domains + unassigned_purge_grace).
    /// Daemon mode already exposes this via its own DaemonConfig; the
    /// standalone server gains it here so T28's unassignment handler
    /// (which lives in `did-hosting-server::messaging`) can read the
    /// grace duration uniformly.
    #[serde(default)]
    pub hosting: HostingConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub stats: StatsConfig,
    /// How far behind its control plane this edge may fall before it reports
    /// itself degraded.
    #[serde(default)]
    pub replication: ReplicationConfig,
    /// DID of the control plane that drives this edge — the one party whose
    /// signed Trust Tasks it applies. Required: the server does not start
    /// without it.
    pub control_did: Option<String>,
    #[serde(default)]
    pub vta: VtaConfig,
    /// How the service's own identity is produced, and how long a superseded
    /// generation keeps being honoured after a rotation
    /// (`identity.rotation_grace_period`).
    #[serde(default)]
    pub identity: did_hosting_common::server::config::IdentityConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

/// The replication staleness bound.
///
/// The control plane delivers every change through its outbox and retries
/// until this edge acknowledges it. As a backstop for anything that still goes
/// missing — an outbox entry dropped past its retry budget, a push lost while
/// the edge was down — the edge reconciles against the control plane's
/// `did-management/did/list` every `reconcile_interval_secs`, repairing a
/// missed disable on the spot and asking for a resync of anything else. When it
/// has not completed a clean reconcile within `staleness_bound_secs`, its
/// `/api/health` probe answers `503`, so a load balancer drains it instead of
/// letting it serve state that may be out of date.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReplicationConfig {
    /// The longest an edge may go without a clean reconcile and still report
    /// healthy. Default 300 (5 minutes).
    #[serde(default = "default_staleness_bound_secs")]
    pub staleness_bound_secs: u64,
    /// How often the edge reconciles. Must be shorter than the bound, so a
    /// single missed round does not trip it. Default 60.
    #[serde(default = "default_reconcile_interval_secs")]
    pub reconcile_interval_secs: u64,
}

fn default_staleness_bound_secs() -> u64 {
    300
}

fn default_reconcile_interval_secs() -> u64 {
    60
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            staleness_bound_secs: default_staleness_bound_secs(),
            reconcile_interval_secs: default_reconcile_interval_secs(),
        }
    }
}

impl ReplicationConfig {
    /// Refuse a bound the reconcile interval cannot keep.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.reconcile_interval_secs == 0 {
            return Err(AppError::Config(
                "replication.reconcile_interval_secs must be at least 1".into(),
            ));
        }
        if self.staleness_bound_secs <= self.reconcile_interval_secs {
            return Err(AppError::Config(format!(
                "replication.staleness_bound_secs ({}) must be longer than \
                 replication.reconcile_interval_secs ({})",
                self.staleness_bound_secs, self.reconcile_interval_secs
            )));
        }
        Ok(())
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

/// Stats collection and sync configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatsConfig {
    /// How often (seconds) to flush in-memory counters to storage. Default: 5.
    #[serde(default = "default_stats_flush_interval")]
    pub flush_interval_secs: u64,
    /// How often (seconds) to push aggregate stats to the control plane. Default: 1.
    /// Set to 0 to disable sync.
    #[serde(default = "default_stats_sync_interval")]
    pub sync_interval_secs: u64,
}

fn default_stats_flush_interval() -> u64 {
    5
}

fn default_stats_sync_interval() -> u64 {
    1
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            flush_interval_secs: default_stats_flush_interval(),
            sync_interval_secs: default_stats_sync_interval(),
        }
    }
}

impl AppConfig {
    /// Return the public-facing base URL for this server.
    pub fn public_base_url(&self) -> String {
        self.public_url
            .clone()
            .unwrap_or_else(|| format!("http://{}:{}", self.server.host, self.server.port))
    }

    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| {
                std::env::var("DID_HOSTING_CONFIG_PATH")
                    .ok()
                    .map(PathBuf::from)
            })
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
            "WEBVH",
            &mut config.features,
            &mut config.server,
            &mut config.log,
            &mut config.store,
            &mut config.auth,
            &mut config.secrets,
        )?;

        // Server identity (did-hosting-server specific env vars)
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

        env_opt!("DID_HOSTING_SERVER_DID", config.server_did);
        env_opt!("DID_HOSTING_MEDIATOR_DID", config.mediator_did);
        env_opt!("DID_HOSTING_PUBLIC_URL", config.public_url);
        env_opt!("DID_HOSTING_CONTROL_DID", config.control_did);

        // VTA config
        env_opt!("DID_HOSTING_VTA_URL", config.vta.url);
        env_opt!("DID_HOSTING_VTA_DID", config.vta.did);
        env_opt!("DID_HOSTING_VTA_CONTEXT_ID", config.vta.context_id);

        // Limits
        env_parse!(
            "DID_HOSTING_REPLICATION_STALENESS_BOUND_SECS",
            config.replication.staleness_bound_secs
        );
        env_parse!(
            "DID_HOSTING_REPLICATION_RECONCILE_INTERVAL_SECS",
            config.replication.reconcile_interval_secs
        );
        env_parse!(
            "DID_HOSTING_LIMITS_UPLOAD_BODY_LIMIT",
            config.limits.upload_body_limit
        );
        env_parse!(
            "DID_HOSTING_LIMITS_DEFAULT_MAX_TOTAL_SIZE",
            config.limits.default_max_total_size
        );
        env_parse!(
            "DID_HOSTING_LIMITS_DEFAULT_MAX_DID_COUNT",
            config.limits.default_max_did_count
        );

        // Stats
        env_parse!(
            "DID_HOSTING_STATS_FLUSH_INTERVAL_SECS",
            config.stats.flush_interval_secs
        );
        env_parse!(
            "DID_HOSTING_STATS_SYNC_INTERVAL_SECS",
            config.stats.sync_interval_secs
        );

        // Validate configuration
        config.auth.validate()?;
        if let Some(ref did) = config.server_did
            && !did.starts_with("did:")
        {
            return Err(AppError::Config(format!(
                "server_did must start with 'did:': {did}"
            )));
        }
        if let Some(ref url) = config.public_url
            && !url.starts_with("http://")
            && !url.starts_with("https://")
        {
            return Err(AppError::Config(format!(
                "public_url must start with http:// or https://: {url}"
            )));
        }

        // Normalize: strip trailing slashes from URLs
        if let Some(ref mut url) = config.public_url {
            let trimmed = url.trim_end_matches('/').to_string();
            *url = trimmed;
        }

        Ok(config)
    }
}

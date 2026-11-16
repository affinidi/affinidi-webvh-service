//! The edge's `config.toml`: [`AppConfig`] and its replication, limits and
//! stats sections, loaded from file with environment overrides.

use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export shared config types so existing code can still use `crate::config::*`
pub use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, FjallTuning, HostingConfig, LogConfig, LogFormat, SecretsConfig,
    ServerConfig, StoreConfig, TransportSelection, VtaConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    /// Optional Fjall memory tuning (`[fjall]`) — the block cache, write
    /// buffer and journal-size caps that keep the store's memory use
    /// inside a pod's Kubernetes limit. Every field defaults to `None`
    /// (fjall's own defaults, unchanged). See
    /// [`did_hosting_common::server::config::FjallTuning`].
    #[serde(default)]
    pub fjall: FjallTuning,
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
    /// Bounds of the anti-replay cache for signed Trust Tasks (`[replay]`;
    /// env `DID_HOSTING_REPLAY_*`).
    #[serde(
        default,
        skip_serializing_if = "did_hosting_common::server::config::ReplayConfig::is_default"
    )]
    pub replay: did_hosting_common::server::config::ReplayConfig,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum body size (bytes) for did.jsonl / witness uploads. Default: 100KB.
    #[serde(default = "default_upload_body_limit")]
    pub upload_body_limit: usize,
    /// **Deprecated, read by nothing.** Per-account quotas are enforced by the
    /// control plane (its ACL entries and `[limits]`), never by an edge.
    /// Still accepted so an existing config loads; a warning names it at
    /// startup (see [`AppConfig::ignored_settings`]). Never written back.
    #[serde(default, skip_serializing)]
    pub default_max_total_size: Option<u64>,
    /// **Deprecated, read by nothing**, like `default_max_total_size`.
    #[serde(default, skip_serializing)]
    pub default_max_did_count: Option<u64>,
    /// The most bytes of DID content the resolution cache holds. Default:
    /// 256 MiB. Past it, the oldest entries are dropped.
    #[serde(default = "default_content_cache_bytes")]
    pub content_cache_bytes: usize,
    /// Worker threads of the HTTP (resolution) runtime. Default: one per
    /// available core.
    #[serde(default)]
    pub http_worker_threads: Option<usize>,
}

fn default_content_cache_bytes() -> usize {
    crate::cache::DEFAULT_CONTENT_CACHE_BYTES
}

impl LimitsConfig {
    /// The HTTP runtime's worker threads: `http_worker_threads`, else one
    /// per available core (at least one).
    pub fn http_workers(&self) -> usize {
        self.http_worker_threads
            .filter(|&n| n > 0)
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()))
    }
}

fn default_upload_body_limit() -> usize {
    102_400
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            upload_body_limit: default_upload_body_limit(),
            default_max_total_size: None,
            default_max_did_count: None,
            content_cache_bytes: default_content_cache_bytes(),
            http_worker_threads: None,
        }
    }
}

/// Stats collection and sync configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

/// Environment overrides an edge used to read into settings nothing uses.
const IGNORED_ENV: &[&str] = &[
    "DID_HOSTING_LIMITS_DEFAULT_MAX_TOTAL_SIZE",
    "DID_HOSTING_LIMITS_DEFAULT_MAX_DID_COUNT",
];

impl AppConfig {
    /// Settings this config sets that an edge accepts but never reads — the
    /// shared `[features]` / `[auth]` sections carry control-plane keys, and
    /// `[limits]` used to carry per-account quotas. Each is deprecated: still
    /// accepted so an existing config loads, named here so startup can warn,
    /// to be refused in a later release.
    ///
    /// A key is reported only when it differs from its default, so a config
    /// the setup wizard wrote (which serialises every `[auth]` default) is
    /// quiet.
    pub fn ignored_settings(&self) -> Vec<String> {
        let mut ignored = Vec::new();
        if self.features.http_listener {
            // An edge always binds its HTTP listener.
            ignored.push("features.http_listener".to_string());
        }
        if self.limits.default_max_total_size.is_some() {
            ignored.push("limits.default_max_total_size".to_string());
        }
        if self.limits.default_max_did_count.is_some() {
            ignored.push("limits.default_max_did_count".to_string());
        }
        // `[auth]`: an edge reads `cleanup_ttl_minutes` alone.
        if let (Ok(serde_json::Value::Object(set)), Ok(serde_json::Value::Object(default))) = (
            serde_json::to_value(&self.auth),
            serde_json::to_value(AuthConfig::default()),
        ) {
            for (key, value) in &set {
                if key != "cleanup_ttl_minutes" && default.get(key) != Some(value) {
                    ignored.push(format!("auth.{key}"));
                }
            }
        }
        for name in IGNORED_ENV {
            if std::env::var_os(name).is_some() {
                ignored.push((*name).to_string());
            }
        }
        ignored
    }

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

        // Shared env overrides (features, server, log, store, auth, secrets).
        // `DID_HOSTING_` is the documented prefix. `WEBVH_` is what these were
        // read under before, applied first so a set `DID_HOSTING_` name wins.
        // Deprecated: drop it once deployments have moved.
        for prefix in ["WEBVH", "DID_HOSTING"] {
            did_hosting_common::server::config::apply_env_overrides(
                prefix,
                &mut config.features,
                &mut config.server,
                &mut config.log,
                &mut config.store,
                &mut config.auth,
                &mut config.secrets,
            )?;
        }
        // Fjall memory settings (STORAGE_FJALL_BLOCK_CACHE / _WRITE_BUFFER /
        // _MAX_JOURNAL) — shared, unprefixed names; see
        // `did_hosting_common::server::config::apply_fjall_env_overrides`.
        did_hosting_common::server::config::apply_fjall_env_overrides(&mut config.fjall)?;
        for prefix in ["WEBVH", "DID_HOSTING"] {
            did_hosting_common::server::config::apply_hosting_env_overrides(
                prefix,
                &mut config.hosting,
            )?;
        }

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

        // Stats
        env_parse!(
            "DID_HOSTING_STATS_FLUSH_INTERVAL_SECS",
            config.stats.flush_interval_secs
        );
        env_parse!(
            "DID_HOSTING_STATS_SYNC_INTERVAL_SECS",
            config.stats.sync_interval_secs
        );

        // DID_HOSTING_SERVER_RESOLVE_CACHE_* — Cache-Control on DID
        // resolution. Also validates `[server.resolve_cache]`.
        config
            .server
            .resolve_cache
            .apply_env_overrides("DID_HOSTING")?;
        // DID_HOSTING_REPLAY_* (and the deprecated WEBVH_REPLAY_*, like the
        // shared overrides above) — anti-replay cache bounds. Also validates
        // `[replay]`.
        config
            .replay
            .apply_env_overrides_for(&["WEBVH", "DID_HOSTING"])?;
        // DID_HOSTING_SERVER_RESOLVE_RATE_LIMIT_* — per-address limit on
        // resolution. Also validates `[server.resolve_rate_limit]`.
        config
            .server
            .resolve_rate_limit
            .apply_env_overrides("DID_HOSTING")?;

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

#[cfg(test)]
// `std::env::set_var` / `remove_var` are `unsafe` in edition 2024; these tests
// mutate the process environment, so they opt out of the workspace ban.
#[allow(unsafe_code)]
mod tests {
    use super::*;

    /// The settings an edge accepts but never reads still load, are named by
    /// `ignored_settings`, and are not written back; a default config names
    /// none.
    #[test]
    fn ignored_edge_settings_load_and_are_named() {
        let quiet: AppConfig = toml::from_str("").unwrap();
        assert!(
            quiet.ignored_settings().is_empty(),
            "{:?}",
            quiet.ignored_settings()
        );
        // What the wizard writes (every `[auth]` default) is quiet too.
        let rewritten: AppConfig =
            toml::from_str(&toml::to_string_pretty(&quiet).unwrap()).unwrap();
        assert!(rewritten.ignored_settings().is_empty());

        let noisy: AppConfig = toml::from_str(
            "[features]\nhttp_listener = true\n\
             [auth]\ncleanup_ttl_minutes = 5\nchallenge_ttl = 7\n\
             [limits]\ndefault_max_total_size = 10\ndefault_max_did_count = 2\n",
        )
        .expect("deprecated keys still load");
        let named = noisy.ignored_settings();
        for key in [
            "features.http_listener",
            "auth.challenge_ttl",
            "limits.default_max_total_size",
            "limits.default_max_did_count",
        ] {
            assert!(named.iter().any(|n| n == key), "{key} not in {named:?}");
        }
        assert!(
            !named.iter().any(|n| n == "auth.cleanup_ttl_minutes"),
            "the edge reads cleanup_ttl_minutes"
        );
        let written = toml::to_string_pretty(&noisy).unwrap();
        assert!(!written.contains("default_max_did_count"), "{written}");
    }

    /// What the setup wizard and recipe write (a serialised `AppConfig`)
    /// loads back under the strict parser; a misspelt key does not.
    #[test]
    fn a_written_config_loads_and_an_unknown_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config: AppConfig = toml::from_str("").unwrap();
        config.server_did = Some("did:webvh:abc:server.example.com".into());
        config.public_url = Some("https://server.example.com".into());
        config.control_did = Some("did:webvh:def:control.example.com".into());
        config.mediator_did = Some("did:webvh:ghi:mediator.example.com".into());
        config.features.didcomm = true;
        config.features.tsp = true;
        config.hosting.unassigned_purge_grace =
            did_hosting_common::server::config::GracePeriod::parse("45m").unwrap();
        config.store.dynamodb_billing_mode = Some("provisioned".into());
        config.store.dynamodb_auto_create = Some(false);
        config.store.cosmosdb_container = Some("kv2".into());
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();
        let loaded = AppConfig::load(Some(path.clone())).expect("written config loads");
        assert_eq!(loaded.hosting.unassigned_purge_grace.as_secs(), 45 * 60);
        assert!(loaded.features.didcomm && loaded.features.tsp);
        assert_eq!(loaded.store.dynamodb_auto_create, Some(false));
        assert_eq!(loaded.store.cosmosdb_container.as_deref(), Some("kv2"));

        std::fs::write(&path, "[limits]\nupload_body_limt = 5\n").unwrap();
        let err = AppConfig::load(Some(path.clone())).unwrap_err().to_string();
        assert!(err.contains("upload_body_limt"), "{err}");
        std::fs::write(&path, "contol_did = \"did:example:x\"\n").unwrap();
        assert!(AppConfig::load(Some(path)).is_err());
    }

    /// A malformed `trusted_proxy_cidrs` entry or `rotation_grace_period`
    /// stops the load, naming the key and the value, instead of being
    /// dropped (the CIDR) or read as an hour (the grace period).
    #[test]
    fn a_bad_proxy_cidr_or_grace_period_is_refused_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        std::fs::write(
            &path,
            "[server]\ntrusted_proxy_cidrs = [\"10.0.0.0/8\", \"10.0.0.0/40\"]\n",
        )
        .unwrap();
        let err = AppConfig::load(Some(path.clone())).unwrap_err().to_string();
        assert!(err.contains("trusted_proxy_cidrs"), "{err}");
        assert!(err.contains("10.0.0.0/40"), "{err}");

        std::fs::write(
            &path,
            "[identity]\nrotation_grace_period = \"1 fortnight\"\n",
        )
        .unwrap();
        let err = AppConfig::load(Some(path.clone())).unwrap_err().to_string();
        assert!(err.contains("rotation_grace_period"), "{err}");
        assert!(err.contains("1 fortnight"), "{err}");

        std::fs::write(
            &path,
            "[server]\ntrusted_proxy_cidrs = [\"10.0.0.0/8\"]\n\
             [identity]\nrotation_grace_period = \"15m\"\n",
        )
        .unwrap();
        let config = AppConfig::load(Some(path)).expect("valid values load");
        assert_eq!(config.server.trusted_proxy_cidrs.len(), 1);
        assert_eq!(config.identity.rotation_grace_secs(), 15 * 60);
    }

    /// The documented `DID_HOSTING_` names reach the shared settings, the
    /// legacy `WEBVH_` names still work, and the documented name wins.
    #[test]
    fn shared_env_overrides_read_did_hosting_then_legacy_webvh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();

        // SAFETY: no other test in this crate loads config or reads these
        // names, so nothing races these writes.
        unsafe {
            std::env::set_var("DID_HOSTING_SERVER_PORT", "9999");
            std::env::set_var("WEBVH_LOG_LEVEL", "warn");
        }
        let config = AppConfig::load(Some(path.clone())).unwrap();
        assert_eq!(config.server.port, 9999, "documented name applies");
        assert_eq!(config.log.level, "warn", "legacy name still applies");

        unsafe { std::env::set_var("DID_HOSTING_LOG_LEVEL", "debug") };
        let config = AppConfig::load(Some(path)).unwrap();
        assert_eq!(config.log.level, "debug", "documented name wins");

        unsafe {
            std::env::remove_var("DID_HOSTING_SERVER_PORT");
            std::env::remove_var("WEBVH_LOG_LEVEL");
            std::env::remove_var("DID_HOSTING_LOG_LEVEL");
        }
    }
}

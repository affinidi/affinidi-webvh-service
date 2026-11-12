use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, FjallTuning, IdentityConfig, LogConfig, LogFormat, SecretsConfig,
    ServerConfig, StoreConfig, VtaConfig,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    /// Which transports the Trust Task listener carries on the mediator
    /// connection (`didcomm`, `tsp`), and whether the HTTP listener
    /// (resolution and `POST /api/trust-tasks`) runs (`rest_api`).
    #[serde(default)]
    pub features: FeaturesConfig,
    /// The watcher's own DID, whose keys live in a VTA context: it signs every
    /// Trust Task reply and is the `recipient` every sync document must name.
    pub server_did: Option<String>,
    /// The mediator the watcher's DID advertises for TSP and DIDComm.
    pub mediator_did: Option<String>,
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
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub vta: VtaConfig,
    /// How the watcher's own identity is produced.
    #[serde(default)]
    pub identity: IdentityConfig,
    /// Bounds of the anti-replay cache for signed Trust Tasks (`[replay]`;
    /// env `WATCHER_REPLAY_*`).
    #[serde(
        default,
        skip_serializing_if = "did_hosting_common::server::config::ReplayConfig::is_default"
    )]
    pub replay: did_hosting_common::server::config::ReplayConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(skip)]
    pub config_path: PathBuf,
}

/// Where the watcher takes its content from.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct SyncConfig {
    /// The DIDs of the control planes this watcher mirrors. A
    /// `webvh/sync/*` document is applied only when its proof binds it to one
    /// of them; one from any other signer is refused `notAuthorized`. Empty
    /// means the watcher applies nothing.
    #[serde(default)]
    pub source_dids: Vec<String>,
    /// Sources with settings (`[[sync.sources]]`). A DID listed here is a
    /// configured source too, whether or not `source_dids` also lists it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<SourceConfig>,
}

/// One source, with the settings `source_dids` cannot carry.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// The source's DID.
    pub did: String,
    /// The hosts this source may sync DIDs for, compared with the DID's host
    /// (`host`, or `host:port` when the DID names a port), ignoring case. A
    /// DID on any other host is refused `notAuthorized`. Empty: any host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
}

impl SyncConfig {
    /// Whether `did` is a configured source.
    pub fn is_source(&self, did: &str) -> bool {
        self.source_dids.iter().any(|s| s == did) || self.sources.iter().any(|s| s.did == did)
    }

    /// How many distinct sources are configured.
    pub fn source_count(&self) -> usize {
        let mut all: Vec<&str> = self
            .source_dids
            .iter()
            .map(String::as_str)
            .chain(self.sources.iter().map(|s| s.did.as_str()))
            .collect();
        all.sort_unstable();
        all.dedup();
        all.len()
    }

    /// Whether `source` may sync a DID on `host`. A source with no domains
    /// configured (in any `[[sync.sources]]` entry for it) may sync any host.
    pub fn allows_host(&self, source: &str, host: &str) -> bool {
        let mut domains = self
            .sources
            .iter()
            .filter(|s| s.did == source)
            .flat_map(|s| s.domains.iter())
            .peekable();
        domains.peek().is_none() || domains.any(|d| d.eq_ignore_ascii_case(host))
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            features: FeaturesConfig::default(),
            server_did: None,
            mediator_did: None,
            server: ServerConfig {
                host: "0.0.0.0".into(),
                port: 8533,
                trusted_proxies: Vec::new(),
                trusted_proxy_cidrs: Vec::new(),
                resolve_cache: Default::default(),
                resolve_rate_limit: Default::default(),
            },
            log: LogConfig::default(),
            store: StoreConfig {
                data_dir: PathBuf::from("data/webvh-watcher"),
                ..StoreConfig::default()
            },
            fjall: FjallTuning::default(),
            secrets: SecretsConfig::default(),
            vta: VtaConfig::default(),
            identity: IdentityConfig::default(),
            replay: Default::default(),
            sync: SyncConfig::default(),
            config_path: PathBuf::new(),
        }
    }
}

impl AppConfig {
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, AppError> {
        let path = config_path
            .or_else(|| std::env::var("WATCHER_CONFIG_PATH").ok().map(PathBuf::from))
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

        // Watcher-specific env var overrides
        if let Ok(v) = std::env::var("WATCHER_SERVER_HOST") {
            config.server.host = v;
        }
        if let Ok(v) = std::env::var("WATCHER_SERVER_PORT") {
            config.server.port = v
                .parse()
                .map_err(|e| AppError::Config(format!("invalid WATCHER_SERVER_PORT: {e}")))?;
        }
        did_hosting_common::server::config::apply_env_overrides(
            "WATCHER",
            &mut config.features,
            &mut config.server,
            &mut config.log,
            &mut config.store,
            // The watcher holds no sessions: nothing reads the auth settings.
            &mut AuthConfig::default(),
            &mut config.secrets,
        )?;
        // WATCHER_SERVER_RESOLVE_CACHE_* — Cache-Control on DID resolution.
        config.server.resolve_cache.apply_env_overrides("WATCHER")?;
        // WATCHER_REPLAY_* — anti-replay cache bounds. Also validates `[replay]`.
        config.replay.apply_env_overrides("WATCHER")?;
        // WATCHER_SERVER_RESOLVE_RATE_LIMIT_* — per-address limit on resolution.
        config
            .server
            .resolve_rate_limit
            .apply_env_overrides("WATCHER")?;
        if let Ok(v) = std::env::var("WATCHER_SERVER_DID") {
            config.server_did = Some(v);
        }
        if let Ok(v) = std::env::var("WATCHER_MEDIATOR_DID") {
            config.mediator_did = Some(v);
        }
        if let Ok(v) = std::env::var("WATCHER_SOURCE_DIDS") {
            config.sync.source_dids = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Fjall memory settings (STORAGE_FJALL_BLOCK_CACHE / _WRITE_BUFFER /
        // _MAX_JOURNAL) — shared, unprefixed names; see
        // `did_hosting_common::server::config::apply_fjall_env_overrides`.
        did_hosting_common::server::config::apply_fjall_env_overrides(&mut config.fjall)?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_with_domains_parse_beside_source_dids() {
        let sync: SyncConfig = toml::from_str(
            r#"
            source_dids = ["did:example:a"]

            [[sources]]
            did = "did:example:b"
            domains = ["b.example.com", "localhost:8534"]
            "#,
        )
        .expect("parses");
        assert!(sync.is_source("did:example:a"));
        assert!(sync.is_source("did:example:b"));
        assert!(!sync.is_source("did:example:c"));
        assert_eq!(sync.source_count(), 2);
        assert!(sync.allows_host("did:example:a", "anything.example.com"));
        assert!(sync.allows_host("did:example:b", "B.Example.com"));
        assert!(sync.allows_host("did:example:b", "localhost:8534"));
        assert!(!sync.allows_host("did:example:b", "a.example.com"));
        assert!(!sync.allows_host("did:example:b", "localhost"));

        let unknown = toml::from_str::<SyncConfig>(
            r#"
            [[sources]]
            did = "did:example:b"
            domain = ["b.example.com"]
            "#,
        );
        assert!(unknown.is_err(), "a misspelt setting is refused");
    }
}

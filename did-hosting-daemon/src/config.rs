use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, FjallTuning, HostingConfig, IdentityConfig, IdentityMode,
    LogConfig, SecretsConfig, ServerConfig, StoreConfig,
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
    /// Optional Fjall memory tuning (`[fjall]`) — the block cache, write
    /// buffer and journal-size caps that keep both stores' memory use
    /// inside the pod's Kubernetes limit. Shared by `store` and
    /// `witness_store` — this is a pod-level setting, not a per-store one.
    /// Every field defaults to `None` (fjall's own defaults, unchanged).
    /// See [`did_hosting_common::server::config::FjallTuning`].
    #[serde(default)]
    pub fjall: FjallTuning,

    // Server-specific
    #[serde(default)]
    pub limits: did_hosting_server::config::LimitsConfig,

    // Witness-specific
    #[serde(default)]
    pub vta: did_hosting_common::server::config::VtaConfig,

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

/// Tests that set process-wide `DAEMON_*` environment variables hold this lock,
/// so they cannot see each other's values.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Key namespace the daemon gives its witness store when both its stores share
/// one DynamoDB single table and neither names a namespace.
#[cfg(feature = "store-dynamodb-single")]
const DEFAULT_WITNESS_KEY_NAMESPACE: &str = "witness";

/// Whether two store configs can resolve to the same DynamoDB table: the same
/// table name, in regions that are not provably different. An unset region
/// means "whatever the environment says", which may be the other store's
/// region, so it is treated as possibly the same (fail closed).
#[cfg(feature = "store-dynamodb-single")]
fn same_single_table(a: &StoreConfig, b: &StoreConfig) -> bool {
    let (Some(x), Some(y)) = (&a.dynamodb_table_name, &b.dynamodb_table_name) else {
        return false;
    };
    x == y
        && !matches!(
            (&a.dynamodb_region, &b.dynamodb_region),
            (Some(r1), Some(r2)) if r1 != r2
        )
}

/// Keep the daemon's main store and witness store on separate rows of a shared
/// DynamoDB single table.
///
/// Both stores open keyspaces with the same names (`acl`, `witnesses`), so on
/// one table they would be the same rows: a revoke made through the witness
/// would edit the control plane's ACL. When the stores share a table and
/// neither names a key namespace, the witness store gets
/// [`DEFAULT_WITNESS_KEY_NAMESPACE`]; the main store keeps bare keyspace names,
/// so its existing rows stay where they are. Stores on different tables are left
/// alone. If they still resolve to the same partitions (an explicit, equal
/// namespace), the daemon refuses to start rather than merge them.
#[cfg(feature = "store-dynamodb-single")]
fn separate_witness_store(config: &mut DaemonConfig) -> Result<(), AppError> {
    if !same_single_table(&config.store, &config.witness_store) {
        return Ok(());
    }
    if config.store.dynamodb_key_namespace.is_none()
        && config.witness_store.dynamodb_key_namespace.is_none()
    {
        config.witness_store.dynamodb_key_namespace =
            Some(DEFAULT_WITNESS_KEY_NAMESPACE.to_string());
        tracing::info!(
            table = config
                .store
                .dynamodb_table_name
                .as_deref()
                .unwrap_or_default(),
            namespace = DEFAULT_WITNESS_KEY_NAMESPACE,
            "the witness store shares a DynamoDB table with the main store; \
             giving it its own key namespace so they do not share rows"
        );
    }
    if config.store.dynamodb_key_namespace == config.witness_store.dynamodb_key_namespace {
        return Err(AppError::Config(format!(
            "the daemon's `store` and `witness_store` resolve to the same DynamoDB table \
             (`{}`) and key namespace ({}); they use the same keyspace names (`acl`, \
             `witnesses`), so they would share rows. Give the witness store its own table \
             (DAEMON_WITNESS_STORE_DYNAMODB_TABLE_NAME) or a distinct key namespace \
             (DAEMON_WITNESS_STORE_DYNAMODB_KEY_NAMESPACE)",
            config
                .store
                .dynamodb_table_name
                .as_deref()
                .unwrap_or_default(),
            config
                .store
                .dynamodb_key_namespace
                .as_deref()
                .map_or("none".to_string(), |ns| format!("`{ns}`")),
        )));
    }
    Ok(())
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

        did_hosting_common::server::config::apply_store_env_overrides(
            "DAEMON_STORE",
            &mut config.store,
        );
        did_hosting_common::server::config::apply_store_env_overrides(
            "DAEMON_WITNESS_STORE",
            &mut config.witness_store,
        );
        #[cfg(feature = "store-dynamodb-single")]
        separate_witness_store(&mut config)?;

        // Fjall memory settings (STORAGE_FJALL_BLOCK_CACHE / _WRITE_BUFFER /
        // _MAX_JOURNAL) — shared, unprefixed names; see
        // `did_hosting_common::server::config::apply_fjall_env_overrides`.
        did_hosting_common::server::config::apply_fjall_env_overrides(&mut config.fjall)?;

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
            fjall: self.fjall,
            auth: self.auth.clone(),
            hosting: self.hosting.clone(),
            secrets: self.secrets.clone(),
            limits: self.limits.clone(),
            replication: Default::default(),
            control_did: None,
            vta: self.vta.clone(),
            stats: did_hosting_server::config::StatsConfig::default(),
            // Carried through for completeness. The embedded server runs no
            // DIDComm listener of its own, so its rotation path is inert — the
            // daemon's control plane owns the identity.
            identity: self.identity.clone(),
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
            fjall: self.fjall,
            secrets: self.secrets.clone(),
            vta: self.vta.clone(),
            // Carried through for completeness. The daemon's control plane owns
            // the only DIDComm listener, so the embedded witness's rotation path
            // is inert — its `didcomm_service` slot is never filled.
            identity: self.identity.clone(),
            config_path: self.config_path.clone(),
        }
    }

    /// Build a webvh-watcher AppConfig from the daemon config.
    pub fn watcher_config(&self) -> webvh_watcher::config::AppConfig {
        webvh_watcher::config::AppConfig {
            // The embedded watcher serves resolution only: it has no DID and
            // no listener of its own (see `build_watcher`).
            features: self.features_config(),
            server_did: None,
            mediator_did: None,
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.store.clone(),
            fjall: self.fjall,
            secrets: self.secrets.clone(),
            vta: self.vta.clone(),
            identity: self.identity.clone(),
            sync: Default::default(),
            config_path: self.config_path.clone(),
        }
    }

    /// Build a did-hosting-control AppConfig from the daemon config.
    pub fn control_config(&self) -> did_hosting_control::config::AppConfig {
        did_hosting_control::config::AppConfig {
            features: self.features_config(),
            server_did: self.server_did.clone(),
            mediator_did: self.mediator_did.clone(),
            public_url: self.public_url.clone(),
            did_hosting_url: self.did_hosting_url.clone(),
            server: self.server.clone(),
            log: self.log.clone(),
            store: self.store.clone(),
            fjall: self.fjall,
            auth: self.auth.clone(),
            secrets: self.secrets.clone(),
            vta: self.vta.clone(),
            registry: self.registry.clone(),
            trust_tasks: did_hosting_control::config::TrustTasksConfig::default(),
            hosting: self.hosting.clone(),
            // The daemon's control plane owns the only DIDComm listener, so it
            // is the one that rotates — it needs the daemon's grace period, not
            // a default.
            identity: self.identity.clone(),
            config_path: self.config_path.clone(),
        }
    }

    fn features_config(&self) -> FeaturesConfig {
        FeaturesConfig {
            didcomm: self.features.didcomm,
            tsp: self.features.tsp,
            rest_api: self.features.rest_api,
            agent_names: self.features.agent_names,
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

    /// The two stores of one daemon, as a deployment that runs both on the
    /// single-table backend would configure them.
    #[cfg(feature = "store-dynamodb-single")]
    mod single_table {
        use super::*;
        use did_hosting_common::server::config::StoreConfig;

        fn stores(
            main: (Option<&str>, Option<&str>, Option<&str>),
            witness: (Option<&str>, Option<&str>, Option<&str>),
        ) -> DaemonConfig {
            // Each tuple is (table, region, namespace).
            let to_store =
                |(table, region, ns): (Option<&str>, Option<&str>, Option<&str>)| StoreConfig {
                    dynamodb_table_name: table.map(str::to_string),
                    dynamodb_region: region.map(str::to_string),
                    dynamodb_key_namespace: ns.map(str::to_string),
                    ..StoreConfig::default()
                };
            let mut config: DaemonConfig = toml::from_str(SELF_MANAGED_TOML).expect("parse");
            config.store = to_store(main);
            config.witness_store = to_store(witness);
            config
        }

        const T: Option<&str> = Some("webvh");

        #[test]
        fn a_shared_table_gives_the_witness_store_its_own_namespace() {
            let mut c = stores((T, None, None), (T, None, None));
            separate_witness_store(&mut c).expect("ok");
            assert_eq!(
                c.witness_store.dynamodb_key_namespace.as_deref(),
                Some("witness")
            );
            assert_eq!(
                c.store.dynamodb_key_namespace, None,
                "the main store's rows must not move"
            );
        }

        #[test]
        fn separate_tables_are_left_alone() {
            // An operator already on separate tables must not have their witness
            // rows re-addressed.
            let mut c = stores((T, None, None), (Some("webvh-witness"), None, None));
            separate_witness_store(&mut c).expect("ok");
            assert_eq!(c.witness_store.dynamodb_key_namespace, None);
        }

        #[test]
        fn an_explicit_witness_namespace_is_kept() {
            let mut c = stores((T, None, None), (T, None, Some("w2")));
            separate_witness_store(&mut c).expect("ok");
            assert_eq!(
                c.witness_store.dynamodb_key_namespace.as_deref(),
                Some("w2")
            );
        }

        #[test]
        fn a_namespace_on_the_main_store_alone_already_separates_them() {
            let mut c = stores((T, None, Some("main")), (T, None, None));
            separate_witness_store(&mut c).expect("ok");
            assert_eq!(
                c.witness_store.dynamodb_key_namespace, None,
                "nothing to add"
            );
        }

        #[test]
        fn identical_explicit_namespaces_are_refused_naming_the_fix() {
            let mut c = stores((T, None, Some("x")), (T, None, Some("x")));
            let err = separate_witness_store(&mut c).expect_err("same table and namespace");
            let msg = err.to_string();
            assert!(matches!(err, AppError::Config(_)));
            assert!(
                msg.contains("DAEMON_WITNESS_STORE_DYNAMODB_KEY_NAMESPACE"),
                "{msg}"
            );
            assert!(
                msg.contains("DAEMON_WITNESS_STORE_DYNAMODB_TABLE_NAME"),
                "{msg}"
            );
        }

        #[test]
        fn a_main_store_namespaced_witness_is_never_silently_merged_with_the_witness_store() {
            // Main named "witness" and witness unset: distinct partitions (bare vs
            // namespaced), nothing to add.
            let mut c = stores((T, None, Some("witness")), (T, None, None));
            separate_witness_store(&mut c).expect("ok");
            assert_eq!(c.witness_store.dynamodb_key_namespace, None);
            // Both explicitly "witness": the same partitions, so it is refused.
            let mut c = stores((T, None, Some("witness")), (T, None, Some("witness")));
            assert!(separate_witness_store(&mut c).is_err());
        }

        #[test]
        fn different_regions_are_different_tables() {
            let mut c = stores((T, Some("us-east-1"), None), (T, Some("eu-west-1"), None));
            separate_witness_store(&mut c).expect("ok");
            assert_eq!(c.witness_store.dynamodb_key_namespace, None);
        }

        #[test]
        fn an_unknown_region_is_treated_as_possibly_the_same_table() {
            // `None` means "whatever the environment says", which may be the other
            // store's region: fail closed.
            let mut c = stores((T, None, None), (T, Some("us-east-1"), None));
            separate_witness_store(&mut c).expect("ok");
            assert_eq!(
                c.witness_store.dynamodb_key_namespace.as_deref(),
                Some("witness")
            );
        }

        #[test]
        fn stores_without_a_table_name_are_not_checked() {
            let mut c = stores((None, None, None), (None, None, None));
            separate_witness_store(&mut c).expect("ok");
            assert_eq!(c.witness_store.dynamodb_key_namespace, None);
        }

        #[test]
        fn load_separates_the_stores_when_both_use_the_same_env_table() {
            // The usual single-table deployment: both stores get
            // the same table through the environment.
            let _guard = crate::config::ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let (_dir, path) = write_temp_config(SELF_MANAGED_TOML);
            // SAFETY: serialised by ENV_LOCK; no other thread reads these names.
            unsafe {
                std::env::set_var("DAEMON_STORE_DYNAMODB_TABLE_NAME", "shared");
                std::env::set_var("DAEMON_WITNESS_STORE_DYNAMODB_TABLE_NAME", "shared");
            }
            let loaded = DaemonConfig::load(Some(path));
            unsafe {
                std::env::remove_var("DAEMON_STORE_DYNAMODB_TABLE_NAME");
                std::env::remove_var("DAEMON_WITNESS_STORE_DYNAMODB_TABLE_NAME");
            }
            let config = loaded.expect("loads");
            assert_eq!(config.store.dynamodb_table_name.as_deref(), Some("shared"));
            assert_eq!(config.store.dynamodb_key_namespace, None);
            assert_eq!(
                config.witness_store.dynamodb_key_namespace.as_deref(),
                Some("witness")
            );
            // The embedded witness is built from this store config.
            assert_eq!(
                config
                    .witness_config()
                    .store
                    .dynamodb_key_namespace
                    .as_deref(),
                Some("witness")
            );
        }
    }
}

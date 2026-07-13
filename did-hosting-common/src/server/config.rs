use super::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeaturesConfig {
    #[serde(default)]
    pub didcomm: bool,
    /// Trust Spanning Protocol (TSP) transport. When enabled (and a
    /// `mediator_did` is configured), the mediator listener also carries
    /// TSP on its shared socket and the service's DID document advertises
    /// a `TSPTransport` service. Additive with `didcomm` — a node can
    /// speak both; TSP is preferred when a peer advertises both.
    #[serde(default)]
    pub tsp: bool,
    #[serde(default)]
    pub rest_api: bool,
    /// Serve agent-name redirects (`GET /@alice` -> 302 to a DID).
    ///
    /// **On by default.** A name only resolves if the signed DID document
    /// already claims it via `alsoKnownAs`, so serving the `/@…` namespace
    /// cannot by itself expose a name the controller has not authorised: with
    /// no names bound, every `/@…` request 404s exactly as it did before.
    /// Meanwhile the write path (bind/park/resume, over REST and Trust Tasks)
    /// and the UI that drives it are *not* gated on this flag — leaving it off
    /// let an owner bind a name that then silently failed to resolve, which is
    /// the worse default.
    ///
    /// Set `agent_names = false` (or `…_FEATURES_AGENT_NAMES=0`) to keep the
    /// `/@…` namespace unserved on a host that wants those paths free for
    /// something else.
    #[serde(default = "default_true")]
    pub agent_names: bool,
    /// Deployment mode: "standalone" for individual services, "daemon" for unified binary.
    /// Controls UI behavior (e.g., hiding service topology in daemon mode).
    #[serde(default = "default_deployment_mode")]
    pub deployment_mode: String,
}

fn default_deployment_mode() -> String {
    "standalone".to_string()
}

fn default_true() -> bool {
    true
}

/// Hand-written so the in-code default matches what serde fills in for an
/// absent field — a derived `Default` would give `agent_names: false` and an
/// empty `deployment_mode`, so every `..Default::default()` call site (the
/// setup wizards, the recipe writer, tests) would disagree with the same
/// config round-tripped through TOML.
impl Default for FeaturesConfig {
    fn default() -> Self {
        Self {
            didcomm: false,
            tsp: false,
            rest_api: false,
            agent_names: true,
            deployment_mode: default_deployment_mode(),
        }
    }
}

/// Three-way messaging-transport selection used by setup wizards and
/// recipes. TSP and DIDComm both ride the same mediator socket, so this
/// choice is only meaningful when a `mediator_did` is configured; with no
/// mediator the node is HTTP-only and both flags are false regardless.
///
/// The selection maps directly onto [`FeaturesConfig::didcomm`] /
/// [`FeaturesConfig::tsp`], which in turn drive the listener protocol
/// matrix and (for self-managed DIDs) which service entries the DID
/// document advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSelection {
    Didcomm,
    Tsp,
    Both,
}

impl TransportSelection {
    /// `(didcomm, tsp)` feature flags for this selection.
    pub fn as_flags(self) -> (bool, bool) {
        match self {
            Self::Didcomm => (true, false),
            Self::Tsp => (false, true),
            Self::Both => (true, true),
        }
    }

    /// Inverse of [`Self::as_flags`]: the selection implied by `(didcomm,
    /// tsp)` feature flags. Returns `None` when both are false (no messaging
    /// transport — an HTTP-only node the selection doesn't describe).
    pub fn from_flags(didcomm: bool, tsp: bool) -> Option<Self> {
        match (didcomm, tsp) {
            (true, true) => Some(Self::Both),
            (true, false) => Some(Self::Didcomm),
            (false, true) => Some(Self::Tsp),
            (false, false) => None,
        }
    }

    /// Parse a recipe `transport` string. Recognises `didcomm`, `tsp`, and
    /// `both` (case-insensitive, `+`-joined aliases accepted).
    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "didcomm" => Ok(Self::Didcomm),
            "tsp" => Ok(Self::Tsp),
            "both" | "didcomm+tsp" | "tsp+didcomm" => Ok(Self::Both),
            other => Err(AppError::Config(format!(
                "invalid transport '{other}' (expected 'didcomm', 'tsp', or 'both')"
            ))),
        }
    }

    /// Canonical lower-case string, suitable for persisting into a recipe.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Didcomm => "didcomm",
            Self::Tsp => "tsp",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Trusted reverse-proxy IPs whose `X-Forwarded-For` header is
    /// honoured for client-IP attribution. Empty (default) =
    /// X-Forwarded-For is ignored and the direct TCP peer is used —
    /// safe behind nothing or behind a CDN that strips XFF, but
    /// wrong behind a load balancer (every request appears to come
    /// from the LB, so per-IP rate limits become a global cap).
    /// Configure with the IPs of your reverse proxies (e.g.
    /// `["10.0.0.1", "10.0.0.2"]`) to opt in.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Trusted reverse-proxy CIDRs whose `Forwarded` (RFC 7239) and
    /// `X-Forwarded-Host` headers are honoured for **request host /
    /// domain detection** (multi-domain feature, T19). Distinct from
    /// `trusted_proxies` above: that one is for client-IP
    /// attribution; this one is for which host the request is
    /// claiming to address. Outside this set, the daemon always uses
    /// the literal `Host` header.
    ///
    /// Empty (default) disables `Forwarded` / `X-Forwarded-Host`
    /// trust — appropriate for deployments not behind a reverse
    /// proxy. CIDRs accept `1.2.3.0/24` or `2001:db8::/32`.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StoreConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Redis connection URL (e.g. `redis://localhost:6379`). Used by `store-redis` backend.
    pub redis_url: Option<String>,
    /// DynamoDB table name prefix (default: `"webvh"`). Used by `store-dynamodb` backend.
    pub dynamodb_table_prefix: Option<String>,
    /// AWS region for DynamoDB. Used by `store-dynamodb` and `store-dynamodb-single` backends.
    pub dynamodb_region: Option<String>,
    /// Full DynamoDB table name for the externally-provisioned single-table backend.
    /// Required when the `store-dynamodb-single` feature is enabled. The table must exist —
    /// the backend does not call `CreateTable` / `DescribeTable`.
    pub dynamodb_table_name: Option<String>,
    /// GCP project ID for Firestore. Used by `store-firestore` backend.
    pub firestore_project: Option<String>,
    /// Firestore database name (default: `"(default)"`). Used by `store-firestore` backend.
    pub firestore_database: Option<String>,
    /// Azure Cosmos DB connection string. Used by `store-cosmosdb` backend.
    pub cosmosdb_connection_string: Option<String>,
    /// Cosmos DB database name (default: `"webvh"`). Used by `store-cosmosdb` backend.
    pub cosmosdb_database: Option<String>,
    /// Azure region name for Cosmos DB routing (e.g. `"eastus"`, `"westeurope"`,
    /// or display form `"West US 2"`). Defaults to `"eastus"` when unset. The
    /// SDK normalizes the name; see `azure_data_cosmos::Region` for the list
    /// of well-known regions.
    pub cosmosdb_region: Option<String>,
}

// `redis_url` and `cosmosdb_connection_string` can carry credentials; the
// other backend fields are non-sensitive identifiers. Manual Debug keeps
// startup-config logging from leaking the credential-bearing URLs.
impl std::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreConfig")
            .field("data_dir", &self.data_dir)
            .field("redis_url", &self.redis_url.as_ref().map(|_| "<redacted>"))
            .field("dynamodb_table_prefix", &self.dynamodb_table_prefix)
            .field("dynamodb_region", &self.dynamodb_region)
            .field("dynamodb_table_name", &self.dynamodb_table_name)
            .field("firestore_project", &self.firestore_project)
            .field("firestore_database", &self.firestore_database)
            .field(
                "cosmosdb_connection_string",
                &self
                    .cosmosdb_connection_string
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("cosmosdb_database", &self.cosmosdb_database)
            .field("cosmosdb_region", &self.cosmosdb_region)
            .finish()
    }
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

impl AuthConfig {
    /// Validate configuration values are within acceptable ranges.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.challenge_ttl < 10 {
            return Err(AppError::Config(
                "challenge_ttl must be at least 10 seconds".into(),
            ));
        }
        if self.session_cleanup_interval < 10 {
            return Err(AppError::Config(
                "session_cleanup_interval must be at least 10 seconds".into(),
            ));
        }
        if self.access_token_expiry < 30 {
            return Err(AppError::Config(
                "access_token_expiry must be at least 30 seconds".into(),
            ));
        }
        Ok(())
    }
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
    PathBuf::from("data/did-hosting-server")
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            trusted_proxies: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// HostingConfig — multi-domain bootstrap + unassignment lifecycle
// ---------------------------------------------------------------------------

/// Settings for the multi-domain hosting feature.
///
/// Per `docs/multi-domain-spec.md` §3: domains are runtime-managed,
/// but the daemon needs to know what to seed on a fresh deployment
/// (when no `domains` keyspace entries exist yet) and how long to
/// retain unassigned-domain data before purging.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct HostingConfig {
    /// Domain names to seed into the `domains` keyspace on first boot
    /// when the keyspace is empty. Used only when the operator hasn't
    /// already created domains via the admin API. The first entry
    /// becomes the default domain (per spec §3 cold-start fallback
    /// chain — tier 1).
    ///
    /// Empty (default) falls through to tier 2: derive a single
    /// default domain from the legacy `public_url`'s host.
    #[serde(default)]
    pub bootstrap_domains: Vec<String>,

    /// Grace period before a server-locally-unassigned domain's data
    /// is purged. Per spec §3 retain-then-purge semantics. Format:
    /// duration string (`"2h"`, `"30m"`, `"7d"`). Default: `"2h"`.
    ///
    /// Parsed by the unassignment-purge sweep in T30; the string
    /// here is the canonical config-file representation.
    #[serde(default = "default_unassigned_purge_grace")]
    pub unassigned_purge_grace: String,

    /// Grace period before a *disabled* domain (and every DID hosted
    /// under it) is permanently removed. Disable is a soft-delete:
    /// the operator gets this window to re-enable and cancel the
    /// removal. Format matches `unassigned_purge_grace`. Default:
    /// `"30d"` — long enough to recover from an accidental disable,
    /// short enough that abandoned domains don't accumulate forever.
    #[serde(default = "default_disable_purge_grace")]
    pub disable_purge_grace: String,
}

fn default_unassigned_purge_grace() -> String {
    "2h".to_string()
}

fn default_disable_purge_grace() -> String {
    "30d".to_string()
}

impl Default for HostingConfig {
    fn default() -> Self {
        Self {
            bootstrap_domains: Vec::new(),
            unassigned_purge_grace: default_unassigned_purge_grace(),
            disable_purge_grace: default_disable_purge_grace(),
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
            dynamodb_table_name: None,
            firestore_project: None,
            firestore_database: None,
            cosmosdb_connection_string: None,
            cosmosdb_database: None,
            cosmosdb_region: None,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    pub aws_secret_name: Option<String>,
    pub aws_region: Option<String>,
    pub gcp_project: Option<String>,
    pub gcp_secret_name: Option<String>,
    /// Azure Key Vault DNS URL (e.g. `https://my-vault.vault.azure.net/`).
    /// Required when `azure_secret_name` is set.
    pub azure_vault_url: Option<String>,
    /// Azure Key Vault secret name. Used by `azure-secrets` backend.
    pub azure_secret_name: Option<String>,
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
    /// HashiCorp Vault server URL (vault-secrets feature). Setting this
    /// activates the Vault backend.
    pub vault_addr: Option<String>,
    /// KV v2 mount path (vault-secrets feature). Default `secret`.
    #[serde(default = "default_vault_kv_mount")]
    pub vault_kv_mount: String,
    /// KV v2 secret path under the mount, e.g. `webvh/server-secrets`
    /// (vault-secrets feature). Required when `vault_addr` is set.
    pub vault_secret_path: Option<String>,
    /// Field name within the KV v2 secret that holds the JSON secrets
    /// envelope (vault-secrets feature). Default `seed`.
    #[serde(default = "default_vault_secret_key")]
    pub vault_secret_key: String,
    /// Vault Enterprise namespace, if any (vault-secrets feature).
    pub vault_namespace: Option<String>,
    /// Auth method: `kubernetes` (default), `token`, or `approle`
    /// (vault-secrets feature).
    #[serde(default = "default_vault_auth_method")]
    pub vault_auth_method: String,
    /// Kubernetes auth role name (vault-secrets feature, kubernetes
    /// auth method).
    pub vault_k8s_role: Option<String>,
    /// Kubernetes auth mount path (vault-secrets feature). Default
    /// `kubernetes`.
    #[serde(default = "default_vault_k8s_mount")]
    pub vault_k8s_mount: String,
    /// File holding the ServiceAccount JWT presented to Vault
    /// (vault-secrets feature, kubernetes auth method). Default is the
    /// kubelet-mounted projected volume path.
    #[serde(default = "default_vault_k8s_jwt_path")]
    pub vault_k8s_jwt_path: String,
    /// Static token (vault-secrets feature, token auth method). Prefer
    /// the `VAULT_TOKEN` env var over hard-coding here.
    pub vault_token: Option<String>,
    /// AppRole role_id (vault-secrets feature, approle auth method).
    pub vault_approle_role_id: Option<String>,
    /// AppRole secret_id (vault-secrets feature, approle auth method).
    pub vault_approle_secret_id: Option<String>,
    /// AppRole mount path (vault-secrets feature). Default `approle`.
    #[serde(default = "default_vault_approle_mount")]
    pub vault_approle_mount: String,
    /// Skip TLS certificate verification — dev/test only
    /// (vault-secrets feature).
    #[serde(default, skip_serializing_if = "is_false")]
    pub vault_skip_verify: bool,
    /// Kubernetes `Secret` name holding the JSON secrets envelope
    /// (k8s-secrets feature). Setting this activates the Kubernetes
    /// backend.
    pub k8s_secret_name: Option<String>,
    /// Kubernetes namespace the `Secret` lives in (k8s-secrets feature).
    /// When unset, the in-cluster ServiceAccount namespace (or the
    /// kubeconfig context namespace) is used, falling back to `default`.
    pub k8s_namespace: Option<String>,
    /// Key within the `Secret`'s `data` map that holds the JSON secrets
    /// envelope (k8s-secrets feature). Default `seed`.
    #[serde(default = "default_k8s_secret_key")]
    pub k8s_secret_key: String,
    /// Explicitly select the plaintext backend even when a keyring backend is
    /// compiled in. Without this, a keyring-enabled build always prefers the OS
    /// keyring, which panics on a headless host with no Secret Service. The
    /// non-interactive recipe sets this for `backend = "plaintext"`; cloud
    /// backends (AWS/GCP/Azure), when configured, still take precedence.
    #[serde(default, skip_serializing_if = "is_false")]
    pub plaintext_mode: bool,
    /// Plaintext secrets stored directly in the config file.
    /// Used when no secure backend (keyring, AWS, GCP) is compiled in, or when
    /// `plaintext_mode` explicitly selects it.
    pub plaintext: Option<PlaintextSecrets>,
    /// Plaintext-mode-only stash for the offline-bootstrap ephemeral
    /// seed (base64url-no-pad, 32 raw bytes). Set during phase 1 of
    /// the offline wizard when no secure backend is available, and
    /// removed at the end of phase 2. Never populated when a secure
    /// backend (keyring, AWS, GCP) is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_bootstrap_seed: Option<String>,
}

// Manual `Debug` redacts the only secret-bearing field
// (`plaintext_bootstrap_seed`) and delegates to `PlaintextSecrets`'s own
// redacted Debug for the inline secrets. Cloud-secret-name fields are
// non-secret references (operators paste them into config) so they stay.
impl std::fmt::Debug for SecretsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsConfig")
            .field("aws_secret_name", &self.aws_secret_name)
            .field("aws_region", &self.aws_region)
            .field("gcp_project", &self.gcp_project)
            .field("gcp_secret_name", &self.gcp_secret_name)
            .field("azure_vault_url", &self.azure_vault_url)
            .field("azure_secret_name", &self.azure_secret_name)
            .field("keyring_service", &self.keyring_service)
            .field("vault_addr", &self.vault_addr)
            .field("vault_kv_mount", &self.vault_kv_mount)
            .field("vault_secret_path", &self.vault_secret_path)
            .field("vault_secret_key", &self.vault_secret_key)
            .field("vault_namespace", &self.vault_namespace)
            .field("vault_auth_method", &self.vault_auth_method)
            .field("vault_k8s_role", &self.vault_k8s_role)
            .field("vault_k8s_mount", &self.vault_k8s_mount)
            .field("vault_k8s_jwt_path", &self.vault_k8s_jwt_path)
            .field(
                "vault_token",
                &self.vault_token.as_ref().map(|_| "<redacted>"),
            )
            .field("vault_approle_role_id", &self.vault_approle_role_id)
            .field(
                "vault_approle_secret_id",
                &self.vault_approle_secret_id.as_ref().map(|_| "<redacted>"),
            )
            .field("vault_approle_mount", &self.vault_approle_mount)
            .field("vault_skip_verify", &self.vault_skip_verify)
            .field("k8s_secret_name", &self.k8s_secret_name)
            .field("k8s_namespace", &self.k8s_namespace)
            .field("k8s_secret_key", &self.k8s_secret_key)
            .field("plaintext", &self.plaintext)
            .field(
                "plaintext_bootstrap_seed",
                &self.plaintext_bootstrap_seed.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// VTA (Verifiable Trust Architecture) connection configuration.
///
/// Used by services that integrate with a VTA for key management and DID operations.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct VtaConfig {
    /// VTA REST URL for remote key management
    pub url: Option<String>,
    /// VTA DID for DIDComm communication
    pub did: Option<String>,
    /// VTA context ID for this service's keys
    pub context_id: Option<String>,
}

/// How the service obtains its own operating identity (signing key, KA key, DID).
///
/// `Vta` (the default) means a parent VTA provisions and rotates the service's
/// own keys at setup time. `SelfManaged` means the service generates its own
/// keys and self-hosts a `did:webvh` identifier with no parent VTA — a
/// daemon-only mode in v1. See `docs/self-managed-mode-spec.md`.
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityMode {
    #[default]
    Vta,
    SelfManaged,
}

/// Identity configuration — selects how the service's own keys and DID are
/// produced, and how long a superseded identity keeps being honoured.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IdentityConfig {
    #[serde(default)]
    pub mode: IdentityMode,

    /// How long a superseded identity generation stays decryptable after the
    /// DID document is updated. Format: duration string (`"1h"`, `"30m"`,
    /// `"7d"`); `"0"` retires immediately.
    ///
    /// This exists because peers cache DID documents. After a key rotation they
    /// keep encrypting to the *old* key-agreement key until their cache
    /// expires, and those messages only decrypt while we still hold the old
    /// secret. The window should comfortably exceed the longest DID-document
    /// cache TTL among your peers; the resolver in this workspace defaults to
    /// 300s, so `"1h"` is a wide margin.
    ///
    /// Setting `"0"` is the right choice for a **compromised** key — you want
    /// the old key to stop being honoured at once and you accept that in-flight
    /// messages addressed to it will fail.
    #[serde(default = "default_rotation_grace_period")]
    pub rotation_grace_period: String,
}

fn default_rotation_grace_period() -> String {
    "1h".to_string()
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            mode: IdentityMode::default(),
            rotation_grace_period: default_rotation_grace_period(),
        }
    }
}

impl IdentityConfig {
    /// The grace period in seconds.
    ///
    /// An unparseable value falls back to the default rather than failing the
    /// boot: a typo in a duration string should not take the service down, and
    /// the safe direction is to keep honouring the old key for longer, not
    /// shorter.
    pub fn rotation_grace_secs(&self) -> u64 {
        match crate::server::pending_purge::parse_grace_string(&self.rotation_grace_period) {
            Ok(secs) => secs,
            Err(e) => {
                tracing::warn!(
                    value = %self.rotation_grace_period,
                    "invalid identity.rotation_grace_period ({e}) — falling back to 1h"
                );
                3600
            }
        }
    }
}

/// Plaintext secret key material stored directly in the configuration file.
///
/// **WARNING**: This is insecure and should only be used for testing/development.
/// For production deployments, compile with a secure backend feature:
/// `keyring`, `aws-secrets`, or `gcp-secrets`.
#[derive(Clone, Deserialize, Serialize)]
pub struct PlaintextSecrets {
    pub signing_key: String,
    pub key_agreement_key: String,
    pub jwt_signing_key: String,
    /// VTA credential bundle (base64url-encoded) for re-authenticating with VTA.
    /// Optional — only present when the deployment integrates with a VTA host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_credential: Option<String>,
    /// Key material for identity generations retired but not yet expired.
    /// Mirrors `ServerSecrets::retired` — without it, a plaintext-backed
    /// deployment would lose the outgoing key on the very write that installs
    /// its replacement, and a restart mid-rotation could not decrypt traffic
    /// still addressed to the old key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<crate::server::secret_store::RetiredKeys>,
}

impl std::fmt::Debug for PlaintextSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaintextSecrets")
            .field("signing_key", &"<redacted>")
            .field("key_agreement_key", &"<redacted>")
            .field("jwt_signing_key", &"<redacted>")
            .field(
                "vta_credential",
                &self.vta_credential.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn default_keyring_service() -> String {
    "webvh".to_string()
}

fn default_vault_kv_mount() -> String {
    "secret".to_string()
}

fn default_vault_secret_key() -> String {
    "seed".to_string()
}

fn default_vault_auth_method() -> String {
    "kubernetes".to_string()
}

fn default_vault_k8s_mount() -> String {
    "kubernetes".to_string()
}

fn default_vault_k8s_jwt_path() -> String {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
}

fn default_vault_approle_mount() -> String {
    "approle".to_string()
}

fn default_k8s_secret_key() -> String {
    "seed".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            azure_vault_url: None,
            azure_secret_name: None,
            keyring_service: default_keyring_service(),
            vault_addr: None,
            vault_kv_mount: default_vault_kv_mount(),
            vault_secret_path: None,
            vault_secret_key: default_vault_secret_key(),
            vault_namespace: None,
            vault_auth_method: default_vault_auth_method(),
            vault_k8s_role: None,
            vault_k8s_mount: default_vault_k8s_mount(),
            vault_k8s_jwt_path: default_vault_k8s_jwt_path(),
            vault_token: None,
            vault_approle_role_id: None,
            vault_approle_secret_id: None,
            vault_approle_mount: default_vault_approle_mount(),
            vault_skip_verify: false,
            k8s_secret_name: None,
            k8s_namespace: None,
            k8s_secret_key: default_k8s_secret_key(),
            plaintext_mode: false,
            plaintext: None,
            plaintext_bootstrap_seed: None,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
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
            if let Ok(v) = std::env::var($var) {
                $field = v == "1" || v.eq_ignore_ascii_case("true");
            }
        };
    }

    // Features
    env_bool!(&format!("{prefix}_FEATURES_DIDCOMM"), features.didcomm);
    env_bool!(&format!("{prefix}_FEATURES_TSP"), features.tsp);
    env_bool!(&format!("{prefix}_FEATURES_REST_API"), features.rest_api);
    env_bool!(
        &format!("{prefix}_FEATURES_AGENT_NAMES"),
        features.agent_names
    );

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
    env_opt!(
        &format!("{prefix}_STORE_DYNAMODB_TABLE_PREFIX"),
        store.dynamodb_table_prefix
    );
    env_opt!(
        &format!("{prefix}_STORE_DYNAMODB_REGION"),
        store.dynamodb_region
    );
    env_opt!(
        &format!("{prefix}_STORE_DYNAMODB_TABLE_NAME"),
        store.dynamodb_table_name
    );
    env_opt!(
        &format!("{prefix}_STORE_FIRESTORE_PROJECT"),
        store.firestore_project
    );
    env_opt!(
        &format!("{prefix}_STORE_FIRESTORE_DATABASE"),
        store.firestore_database
    );
    env_opt!(
        &format!("{prefix}_STORE_COSMOSDB_CONNECTION_STRING"),
        store.cosmosdb_connection_string
    );
    env_opt!(
        &format!("{prefix}_STORE_COSMOSDB_DATABASE"),
        store.cosmosdb_database
    );
    env_opt!(
        &format!("{prefix}_STORE_COSMOSDB_REGION"),
        store.cosmosdb_region
    );

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
        &format!("{prefix}_AUTH_PASSKEY_ENROLLMENT_TTL"),
        auth.passkey_enrollment_ttl
    );
    env_parse!(
        &format!("{prefix}_CLEANUP_TTL_MINUTES"),
        auth.cleanup_ttl_minutes
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

/// Initialize the global tracing subscriber based on config.
///
/// Uses `try_init` so that callers embedded inside a host process that has
/// already installed a global subscriber (e.g. when this crate is consumed
/// as a library, or when a test harness has set one up) get a no-op rather
/// than a panic. The first installer wins; later attempts log a debug line
/// and continue. Most production callers run as the daemon binary and are
/// the first installer; the no-op path is for embedded use cases.
pub fn init_tracing(log: &LogConfig) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log.level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    let result = match log.format {
        LogFormat::Json => subscriber.json().try_init(),
        LogFormat::Text => subscriber.try_init(),
    };
    if let Err(e) = result {
        // Best-effort message — we may have no subscriber to deliver it. Print
        // to stderr as a fallback so the operator at least sees a hint when
        // the embedding host's subscriber is silent.
        eprintln!("tracing subscriber already initialised; continuing ({e})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_names_default_on_for_absent_and_empty_config() {
        // An operator who never heard of the flag serves `/@name`.
        assert!(FeaturesConfig::default().agent_names);
        let cfg: FeaturesConfig = toml::from_str("").unwrap();
        assert!(cfg.agent_names);
        // Sibling flags stay opt-in — this changes one default, not all of them.
        assert!(!cfg.didcomm);
        assert!(!cfg.tsp);
        assert!(!cfg.rest_api);
    }

    #[test]
    fn agent_names_can_still_be_switched_off() {
        let cfg: FeaturesConfig = toml::from_str("agent_names = false").unwrap();
        assert!(!cfg.agent_names);
    }

    #[test]
    fn features_default_matches_toml_round_trip() {
        // The hand-written `Default` and the serde defaults must not drift:
        // `..Default::default()` in the setup wizards has to produce the same
        // config an operator gets from an empty `[features]` table.
        let from_toml: FeaturesConfig = toml::from_str("").unwrap();
        let from_default = FeaturesConfig::default();
        assert_eq!(from_toml.agent_names, from_default.agent_names);
        assert_eq!(from_toml.deployment_mode, from_default.deployment_mode);
        assert_eq!(from_default.deployment_mode, "standalone");
    }

    #[test]
    fn identity_mode_default_is_vta() {
        assert_eq!(IdentityMode::default(), IdentityMode::Vta);
        assert_eq!(IdentityConfig::default().mode, IdentityMode::Vta);
    }

    #[test]
    fn identity_mode_serializes_kebab_case() {
        let toml_str = toml::to_string(&IdentityConfig {
            mode: IdentityMode::SelfManaged,
            ..Default::default()
        })
        .unwrap();
        assert!(
            toml_str.contains(r#"mode = "self-managed""#),
            "expected kebab-case `self-managed`, got: {toml_str}"
        );

        let toml_str = toml::to_string(&IdentityConfig {
            mode: IdentityMode::Vta,
            ..Default::default()
        })
        .unwrap();
        assert!(
            toml_str.contains(r#"mode = "vta""#),
            "expected `vta`, got: {toml_str}"
        );
    }

    #[test]
    fn identity_config_deserializes_self_managed() {
        let cfg: IdentityConfig = toml::from_str(r#"mode = "self-managed""#).unwrap();
        assert_eq!(cfg.mode, IdentityMode::SelfManaged);
    }

    #[test]
    fn identity_config_deserializes_vta() {
        let cfg: IdentityConfig = toml::from_str(r#"mode = "vta""#).unwrap();
        assert_eq!(cfg.mode, IdentityMode::Vta);
    }

    #[test]
    fn identity_config_round_trips() {
        let original = IdentityConfig {
            mode: IdentityMode::SelfManaged,
            ..Default::default()
        };
        let serialized = toml::to_string(&original).unwrap();
        let deserialized: IdentityConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn identity_config_missing_mode_defaults_to_vta() {
        // An empty `[identity]` table (no `mode = ...`) should default to Vta
        // — this is the back-compat path for existing VTA-mode configs that
        // grow an `[identity]` section but don't yet set `mode`.
        let cfg: IdentityConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.mode, IdentityMode::Vta);
    }

    #[test]
    fn identity_config_unknown_mode_rejected() {
        let result: Result<IdentityConfig, _> = toml::from_str(r#"mode = "bogus""#);
        assert!(
            result.is_err(),
            "expected unknown mode to be rejected, got: {result:?}"
        );
    }

    #[test]
    fn transport_selection_flags() {
        assert_eq!(TransportSelection::Didcomm.as_flags(), (true, false));
        assert_eq!(TransportSelection::Tsp.as_flags(), (false, true));
        assert_eq!(TransportSelection::Both.as_flags(), (true, true));
    }

    #[test]
    fn transport_selection_parse_accepts_known_values() {
        assert_eq!(
            TransportSelection::parse("didcomm").unwrap(),
            TransportSelection::Didcomm
        );
        assert_eq!(
            TransportSelection::parse("TSP").unwrap(),
            TransportSelection::Tsp
        );
        assert_eq!(
            TransportSelection::parse(" Both ").unwrap(),
            TransportSelection::Both
        );
        assert_eq!(
            TransportSelection::parse("didcomm+tsp").unwrap(),
            TransportSelection::Both
        );
    }

    #[test]
    fn transport_selection_parse_rejects_unknown() {
        assert!(TransportSelection::parse("carrier-pigeon").is_err());
    }

    #[test]
    fn transport_selection_from_flags() {
        assert_eq!(
            TransportSelection::from_flags(true, true),
            Some(TransportSelection::Both)
        );
        assert_eq!(
            TransportSelection::from_flags(true, false),
            Some(TransportSelection::Didcomm)
        );
        assert_eq!(
            TransportSelection::from_flags(false, true),
            Some(TransportSelection::Tsp)
        );
        assert_eq!(TransportSelection::from_flags(false, false), None);
    }

    #[test]
    fn transport_selection_flags_round_trip() {
        for sel in [
            TransportSelection::Didcomm,
            TransportSelection::Tsp,
            TransportSelection::Both,
        ] {
            let (d, t) = sel.as_flags();
            assert_eq!(TransportSelection::from_flags(d, t), Some(sel));
        }
    }

    #[test]
    fn transport_selection_str_round_trips() {
        for sel in [
            TransportSelection::Didcomm,
            TransportSelection::Tsp,
            TransportSelection::Both,
        ] {
            assert_eq!(TransportSelection::parse(sel.as_str()).unwrap(), sel);
        }
    }
}

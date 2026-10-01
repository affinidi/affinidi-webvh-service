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

/// Optional Fjall memory settings, shared by every service that opens a
/// local fjall store (did-hosting-control, did-hosting-server,
/// webvh-witness, webvh-watcher, and did-hosting-daemon, which opens two).
/// Exists so a pod's Kubernetes memory limit can be kept clear of fjall's
/// block cache, buffered writes and startup journal replay — all three
/// grow with the data set and, left at fjall's defaults, are sized for a
/// workstation rather than a constrained pod.
///
/// Deliberately **not** a field of [`StoreConfig`]: that type is
/// constructed as a bare struct literal (`StoreConfig { data_dir: .. }`)
/// at hundreds of call sites across the workspace, mostly tests opening
/// an ad hoc store, and adding a field there would force every one of
/// them to change. Instead this is a sibling value each service loads
/// separately (a `[fjall]` config-file table, see below) and threads
/// explicitly into [`crate::server::store::Store::open_with`] alongside
/// the `StoreConfig` it already had. [`crate::server::store::Store::open`]
/// — what every existing call site still uses — is `open_with` with
/// [`FjallTuning::default()`], so nothing already opening a store needed
/// to change to keep behaving exactly as before.
///
/// Every field is optional and defaults to `None`: unset, byte for byte,
/// leaves fjall's own defaults (and this codebase's behaviour before this
/// type existed) unchanged. Settable in a service's config file under
/// `[fjall]` (a bare integer byte count, or a string like `"64MiB"` /
/// `"512MB"` / `"1GiB"`), and overridable per field by the environment
/// variables named on each field below — the env var wins when both are
/// set. The **same** three env var names are used for every consumer
/// (there is deliberately no per-service prefix): this is a pod-level
/// Kubernetes memory-limit knob, not a per-service setting.
///
/// Validated before use ([`FjallTuning::validate`]): zero, a value fjall
/// itself would refuse (its own `Builder` asserts under 1 MiB for the
/// write buffer and under 64 MiB for the journal — panics this type
/// exists to turn into an ordinary startup error instead), or anything
/// that fails to parse is refused with a message naming the setting,
/// never silently ignored or clamped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FjallTuning {
    /// fjall's shared block cache size, in bytes
    /// (`fjall::Database::builder(..).cache_size(..)`). fjall's own
    /// default is 32 MiB. Env override: `STORAGE_FJALL_BLOCK_CACHE`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_block_cache"
    )]
    pub block_cache: Option<u64>,
    /// Maximum size of all active memtables across every keyspace this
    /// process opens, in bytes
    /// (`fjall::Database::builder(..).max_write_buffer_size(Some(..))`).
    /// fjall's own default is unbounded. Env override:
    /// `STORAGE_FJALL_WRITE_BUFFER`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_write_buffer"
    )]
    pub write_buffer: Option<u64>,
    /// Maximum size of all journals — the write-ahead log fjall replays
    /// on startup — in bytes
    /// (`fjall::Database::builder(..).max_journaling_size(..)`). fjall's
    /// own default is 512 MiB. Env override: `STORAGE_FJALL_MAX_JOURNAL`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_max_journal"
    )]
    pub max_journal: Option<u64>,
}

/// Floor for [`FjallTuning::block_cache`]. fjall places no lower bound on
/// its cache size itself, but a cache below this buys nothing meaningful
/// and is far more likely to be a fat-fingered value (bytes typed where
/// mebibytes were meant) than an intentional setting.
pub const MIN_BLOCK_CACHE_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Floor for [`FjallTuning::write_buffer`] — mirrors fjall's own
/// `Builder::max_write_buffer_size`, which panics below this.
pub const MIN_WRITE_BUFFER_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Floor for [`FjallTuning::max_journal`] — mirrors fjall's own
/// `Builder::max_journaling_size`, which panics below this.
pub const MIN_MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Byte-size suffixes this module accepts, longest first so e.g. `"MiB"`
/// is tried before the bare `"B"` it also ends with. IEC (binary, 1024-based)
/// before SI (decimal, 1000-based) is an arbitrary but fixed tie-break —
/// there is no overlap between the two suffix spellings, so it never
/// actually matters which list comes first.
const BYTE_SIZE_SUFFIXES: &[(&str, u64)] = &[
    ("TiB", 1024 * 1024 * 1024 * 1024),
    ("GiB", 1024 * 1024 * 1024),
    ("MiB", 1024 * 1024),
    ("KiB", 1024),
    ("TB", 1_000_000_000_000),
    ("GB", 1_000_000_000),
    ("MB", 1_000_000),
    ("KB", 1_000),
    ("B", 1),
];

/// Parse a byte-size value: a plain byte count (`"67108864"`), or a
/// number followed by a binary (`KiB`/`MiB`/`GiB`/`TiB`) or decimal
/// (`KB`/`MB`/`GB`/`TB`/`B`) suffix, case-insensitively. Never validates
/// range — callers combine this with a minimum (see
/// [`parse_and_validate_fjall_bytes`]).
pub fn parse_byte_size(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("value is empty".to_string());
    }
    if trimmed.starts_with('-') {
        return Err(format!(
            "{trimmed:?} is negative; a byte size cannot be negative"
        ));
    }
    for (suffix, multiplier) in BYTE_SIZE_SUFFIXES {
        if trimmed.len() > suffix.len()
            && trimmed[trimmed.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            let number_part = trimmed[..trimmed.len() - suffix.len()].trim();
            let value: f64 = number_part.parse().map_err(|_| {
                format!(
                    "{trimmed:?} is not a valid byte size (expected a number before the {suffix:?} suffix)"
                )
            })?;
            if !value.is_finite() || value < 0.0 {
                return Err(format!("{trimmed:?} is not a valid byte size"));
            }
            return Ok((value * (*multiplier as f64)).round() as u64);
        }
    }
    trimmed.parse::<u64>().map_err(|_| {
        format!(
            "{trimmed:?} is not a valid byte size (expected a plain byte count, or a number with \
             a B/KB/MB/GB/TB or KiB/MiB/GiB/TiB suffix)"
        )
    })
}

/// Render a byte count the way this module's error messages and startup
/// log line do: the most natural binary unit, two decimal places.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[(&str, u64)] = &[
        ("TiB", 1024 * 1024 * 1024 * 1024),
        ("GiB", 1024 * 1024 * 1024),
        ("MiB", 1024 * 1024),
        ("KiB", 1024),
    ];
    for (unit, size) in UNITS {
        if bytes >= *size {
            return format!("{:.2} {unit}", bytes as f64 / *size as f64);
        }
    }
    format!("{bytes} B")
}

/// Parse then range-check a byte-size value against `minimum`, producing
/// an error that names `field` (an env var name or a config key path) —
/// used identically by the config-file deserializer and the env var
/// overrides so a bad value is refused wherever it came from, with the
/// same message shape.
pub fn parse_and_validate_fjall_bytes(field: &str, raw: &str, minimum: u64) -> Result<u64, String> {
    let bytes = parse_byte_size(raw).map_err(|e| format!("invalid {field} value {raw:?}: {e}"))?;
    validate_fjall_bytes(field, bytes, minimum, raw)
}

fn validate_fjall_bytes(
    field: &str,
    bytes: u64,
    minimum: u64,
    raw_display: &str,
) -> Result<u64, String> {
    if bytes == 0 {
        return Err(format!(
            "{field} must not be zero (got {raw_display:?}); fjall needs a positive size here"
        ));
    }
    if bytes < minimum {
        return Err(format!(
            "{field} value {raw_display:?} ({bytes} bytes) is too small; must be at least \
             {minimum} bytes ({})",
            human_bytes(minimum)
        ));
    }
    Ok(bytes)
}

/// A `[fjall]` field is either a bare integer byte count or a suffixed
/// string — accept both.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawByteSize {
    Number(u64),
    Text(String),
}

fn deserialize_optional_fjall_byte_size<'de, D>(
    deserializer: D,
    field: &str,
    minimum: u64,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<RawByteSize>::deserialize(deserializer)? {
        None => Ok(None),
        Some(RawByteSize::Number(n)) => validate_fjall_bytes(field, n, minimum, &n.to_string())
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(RawByteSize::Text(s)) => {
            let bytes = parse_byte_size(&s).map_err(|e| {
                serde::de::Error::custom(format!("invalid {field} value {s:?}: {e}"))
            })?;
            validate_fjall_bytes(field, bytes, minimum, &s)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}

fn deserialize_block_cache<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.block_cache", MIN_BLOCK_CACHE_BYTES)
}

fn deserialize_write_buffer<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.write_buffer", MIN_WRITE_BUFFER_BYTES)
}

fn deserialize_max_journal<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.max_journal", MIN_MAX_JOURNAL_BYTES)
}

impl FjallTuning {
    /// Re-check every set field against its floor. Called from
    /// [`crate::server::store::Store::open_with`] right before the values
    /// are handed to fjall's builder, so a `FjallTuning` built any other
    /// way than through the deserializer or [`apply_fjall_env_overrides`]
    /// (a test fixture, a future caller) still can never reach fjall's
    /// own asserting `Builder` methods with a value that would panic.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(bytes) = self.block_cache {
            validate_fjall_bytes(
                "fjall.block_cache",
                bytes,
                MIN_BLOCK_CACHE_BYTES,
                &bytes.to_string(),
            )?;
        }
        if let Some(bytes) = self.write_buffer {
            validate_fjall_bytes(
                "fjall.write_buffer",
                bytes,
                MIN_WRITE_BUFFER_BYTES,
                &bytes.to_string(),
            )?;
        }
        if let Some(bytes) = self.max_journal {
            validate_fjall_bytes(
                "fjall.max_journal",
                bytes,
                MIN_MAX_JOURNAL_BYTES,
                &bytes.to_string(),
            )?;
        }
        Ok(())
    }
}

/// Apply `STORAGE_FJALL_BLOCK_CACHE` / `STORAGE_FJALL_WRITE_BUFFER` /
/// `STORAGE_FJALL_MAX_JOURNAL` onto `config`, one field at a time, if set.
/// The **same** three env var names for every consumer (did-hosting-control,
/// did-hosting-server, webvh-witness, webvh-watcher, did-hosting-daemon, and
/// any future one) — this is a pod-level Kubernetes memory-limit knob, not a
/// per-service setting, so there is deliberately no service-specific prefix.
/// Called by each service's own config loader, after the config file is
/// parsed, so an env var overrides the file — an unset var leaves whatever
/// the file (or the type's `None` default) already set untouched.
pub fn apply_fjall_env_overrides(config: &mut FjallTuning) -> Result<(), AppError> {
    if let Ok(raw) = std::env::var("STORAGE_FJALL_BLOCK_CACHE") {
        config.block_cache = Some(
            parse_and_validate_fjall_bytes(
                "STORAGE_FJALL_BLOCK_CACHE",
                &raw,
                MIN_BLOCK_CACHE_BYTES,
            )
            .map_err(AppError::Config)?,
        );
    }
    if let Ok(raw) = std::env::var("STORAGE_FJALL_WRITE_BUFFER") {
        config.write_buffer = Some(
            parse_and_validate_fjall_bytes(
                "STORAGE_FJALL_WRITE_BUFFER",
                &raw,
                MIN_WRITE_BUFFER_BYTES,
            )
            .map_err(AppError::Config)?,
        );
    }
    if let Ok(raw) = std::env::var("STORAGE_FJALL_MAX_JOURNAL") {
        config.max_journal = Some(
            parse_and_validate_fjall_bytes(
                "STORAGE_FJALL_MAX_JOURNAL",
                &raw,
                MIN_MAX_JOURNAL_BYTES,
            )
            .map_err(AppError::Config)?,
        );
    }
    Ok(())
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
    /// How long an admin session may go without user activity before it may
    /// no longer be renewed, in seconds.
    ///
    /// Distinct from [`Self::access_token_expiry`], which is how often a live
    /// session rotates its token. The console renews on a timer, so if the
    /// two were the same clock a tab left open would hold its session for as
    /// long as the browser ran. This is the value that decides when an
    /// operator who walked away is signed out; it is measured against
    /// `Session::last_seen`, which only real requests advance.
    #[serde(default = "default_admin_idle_timeout")]
    pub admin_idle_timeout: u64,
    #[serde(default = "default_passkey_enrollment_ttl")]
    pub passkey_enrollment_ttl: u64,
    /// How long (in minutes) to keep empty DID records before auto-cleanup.
    #[serde(default = "default_cleanup_ttl_minutes")]
    pub cleanup_ttl_minutes: u64,
    /// Global cap on concurrently-live pending auth challenges across all DIDs
    /// (did-hosting-control's in-memory `PendingChallengeTracker`).
    /// Defence-in-depth bound on the unauthenticated
    /// `POST /api/auth/challenge` surface: an attacker sweeping many distinct
    /// DIDs cannot accumulate more than this many live challenges before
    /// issuance fails closed. Mirrors
    /// `did_hosting_control::pending_challenges::MAX_GLOBAL_PENDING`, the
    /// compiled-in default; the two are pinned equal by a unit test in that
    /// crate. Operators on unusually large or small deployments can tune it.
    #[serde(default = "default_max_global_pending_challenges")]
    pub max_global_pending_challenges: usize,
    /// Per-DID cap on concurrently-live pending auth challenges (the sibling
    /// of `max_global_pending_challenges`). Bounds a single-DID flood. Mirrors
    /// `did_hosting_control::routes::auth::MAX_PENDING_CHALLENGES_PER_DID`, the
    /// compiled-in default; also pinned equal by a unit test in that crate.
    #[serde(default = "default_max_pending_challenges_per_did")]
    pub max_pending_challenges_per_did: usize,
    /// The absolute ceiling on a session's life, in seconds from
    /// authentication (`auth/authenticate/0.2` or `/0.3`'s `Session.issuedAt`).
    /// No `auth/refresh/0.2` may advance `Session.expiresAt` — nor, in this
    /// implementation, the underlying refresh-token deadline — past
    /// `issuedAt + absolute_session_lifetime`; a session that has already
    /// reached it refuses refresh outright
    /// (`auth/refresh:sessionLifetimeExceeded`) rather than silently
    /// returning a token with a shrunk window. This is the backstop for a
    /// refresh token (and, where bound, a session key) that stays quietly
    /// compromised: however long undetected, neither can keep a session
    /// alive past this instant — only a fresh `auth/authenticate` can.
    #[serde(default = "default_absolute_session_lifetime")]
    pub absolute_session_lifetime: u64,
}

/// 15 minutes of inactivity.
///
/// Longer than the 900s access-token lifetime it sits beside, deliberately:
/// before this existed an admin was signed out 15 minutes after logging in
/// whether or not they were working, because nothing renewed the token. The
/// same number now bounds idleness rather than wall-clock.
fn default_admin_idle_timeout() -> u64 {
    900
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

/// Default global pending-challenge cap. Must equal
/// `did_hosting_control::pending_challenges::MAX_GLOBAL_PENDING` (pinned by a
/// unit test in that crate — the constant lives there because the tracker
/// does, and did-hosting-common sits below did-hosting-control in the graph).
fn default_max_global_pending_challenges() -> usize {
    10_000
}

/// Default per-DID pending-challenge cap. Must equal
/// `did_hosting_control::routes::auth::MAX_PENDING_CHALLENGES_PER_DID`.
fn default_max_pending_challenges_per_did() -> usize {
    10
}

/// 30 days. Generous enough that a normally-active session never notices
/// it, tight enough that a compromise nobody caught still ends on its own.
fn default_absolute_session_lifetime() -> u64 {
    30 * 24 * 60 * 60
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
        // A timeout shorter than a minute signs an operator out between
        // keystrokes; it is a misconfiguration, not a strict policy.
        if self.admin_idle_timeout < 60 {
            return Err(AppError::Config(
                "admin_idle_timeout must be at least 60 seconds".into(),
            ));
        }
        if self.access_token_expiry < 30 {
            return Err(AppError::Config(
                "access_token_expiry must be at least 30 seconds".into(),
            ));
        }
        // A zero cap fails every challenge closed — bounded, but it takes
        // authentication down rather than protecting it, so refuse it at load.
        if self.max_global_pending_challenges == 0 {
            return Err(AppError::Config(
                "max_global_pending_challenges must be at least 1".into(),
            ));
        }
        if self.max_pending_challenges_per_did == 0 {
            return Err(AppError::Config(
                "max_pending_challenges_per_did must be at least 1".into(),
            ));
        }
        // Shorter than a single refresh cycle, the ceiling would refuse the
        // very first refresh a normal session attempts.
        if self.absolute_session_lifetime < self.refresh_token_expiry {
            return Err(AppError::Config(
                "absolute_session_lifetime must be at least refresh_token_expiry".into(),
            ));
        }
        Ok(())
    }

    /// `Retry-After` for a refusal on the canonical handler's pending-challenge
    /// cap (did-hosting-server, webvh-witness). That cap counts `ChallengeSent`
    /// rows in the store, so a slot frees when its challenge authenticates, or
    /// when the challenge has expired (`challenge_ttl`) and the session sweep
    /// has then run (every `session_cleanup_interval`): their sum bounds the
    /// wait. did-hosting-control does not use this — its in-memory tracker
    /// frees a slot at `challenge_ttl` and computes the exact hint.
    pub fn pending_challenge_retry_after_secs(&self) -> u64 {
        self.challenge_ttl
            .saturating_add(self.session_cleanup_interval)
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: default_access_token_expiry(),
            refresh_token_expiry: default_refresh_token_expiry(),
            challenge_ttl: default_challenge_ttl(),
            session_cleanup_interval: default_session_cleanup_interval(),
            admin_idle_timeout: default_admin_idle_timeout(),
            passkey_enrollment_ttl: default_passkey_enrollment_ttl(),
            cleanup_ttl_minutes: default_cleanup_ttl_minutes(),
            max_global_pending_challenges: default_max_global_pending_challenges(),
            max_pending_challenges_per_did: default_max_pending_challenges_per_did(),
            absolute_session_lifetime: default_absolute_session_lifetime(),
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
    /// Which backend holds the keys (`keyring`, `aws`, `gcp`, `azure`,
    /// `vault`, `kubernetes`, `plaintext`). When unset, the backend whose
    /// selector field is set is used, and failing that the OS keyring — see
    /// [`crate::server::secret_store::resolve_backend`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<crate::server::secret_store::SecretBackend>,
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
    /// Test-only acknowledgement for `backend = "plaintext"`: the service's
    /// private keys are kept in a clear-text file beside the config. Without
    /// it, the plaintext backend refuses to build.
    #[serde(default, skip_serializing_if = "is_false")]
    pub confirm_plaintext: bool,
}

// Manual `Debug` redacts the Vault credentials. Cloud-secret-name fields are
// non-secret references (operators paste them into config) so they stay.
impl std::fmt::Debug for SecretsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsConfig")
            .field("backend", &self.backend)
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
            .field("confirm_plaintext", &self.confirm_plaintext)
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
            backend: None,
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
            confirm_plaintext: false,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Apply `<var_prefix>_*` environment overrides to a [`StoreConfig`].
///
/// `var_prefix` is the full variable prefix including the store namespace, e.g.
/// `"WEBVH_STORE"` for the main store or `"DAEMON_WITNESS_STORE"` for the
/// daemon's witness store. Recognised suffixes: `DATA_DIR`, `REDIS_URL`,
/// `DYNAMODB_TABLE_PREFIX`, `DYNAMODB_REGION`, `DYNAMODB_TABLE_NAME`,
/// `FIRESTORE_PROJECT`, `FIRESTORE_DATABASE`, `COSMOSDB_CONNECTION_STRING`,
/// `COSMOSDB_DATABASE`, `COSMOSDB_REGION`.
pub fn apply_store_env_overrides(var_prefix: &str, store: &mut StoreConfig) {
    macro_rules! env_opt {
        ($var:expr, $field:expr) => {
            if let Ok(v) = std::env::var($var) {
                $field = Some(v);
            }
        };
    }

    if let Ok(data_dir) = std::env::var(format!("{var_prefix}_DATA_DIR")) {
        store.data_dir = PathBuf::from(data_dir);
    }
    env_opt!(format!("{var_prefix}_REDIS_URL"), store.redis_url);
    env_opt!(
        format!("{var_prefix}_DYNAMODB_TABLE_PREFIX"),
        store.dynamodb_table_prefix
    );
    env_opt!(
        format!("{var_prefix}_DYNAMODB_REGION"),
        store.dynamodb_region
    );
    env_opt!(
        format!("{var_prefix}_DYNAMODB_TABLE_NAME"),
        store.dynamodb_table_name
    );
    env_opt!(
        format!("{var_prefix}_FIRESTORE_PROJECT"),
        store.firestore_project
    );
    env_opt!(
        format!("{var_prefix}_FIRESTORE_DATABASE"),
        store.firestore_database
    );
    env_opt!(
        format!("{var_prefix}_COSMOSDB_CONNECTION_STRING"),
        store.cosmosdb_connection_string
    );
    env_opt!(
        format!("{var_prefix}_COSMOSDB_DATABASE"),
        store.cosmosdb_database
    );
    env_opt!(
        format!("{var_prefix}_COSMOSDB_REGION"),
        store.cosmosdb_region
    );
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
    apply_store_env_overrides(&format!("{prefix}_STORE"), store);

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
    fn store_env_overrides_apply_dynamodb_single_fields() {
        // Unique prefix so parallel tests never observe these vars.
        let p = "TEST_STORE_ENV_A";
        // SAFETY: unique prefix, only this test touches these vars.
        unsafe {
            std::env::set_var(format!("{p}_DYNAMODB_TABLE_NAME"), "tbl");
            std::env::set_var(format!("{p}_DYNAMODB_REGION"), "eu-west-1");
            std::env::set_var(format!("{p}_DATA_DIR"), "/tmp/x");
        }
        let mut store = StoreConfig::default();
        apply_store_env_overrides(p, &mut store);
        assert_eq!(store.dynamodb_table_name.as_deref(), Some("tbl"));
        assert_eq!(store.dynamodb_region.as_deref(), Some("eu-west-1"));
        assert_eq!(store.data_dir, PathBuf::from("/tmp/x"));
        assert!(store.redis_url.is_none());
        unsafe {
            std::env::remove_var(format!("{p}_DYNAMODB_TABLE_NAME"));
            std::env::remove_var(format!("{p}_DYNAMODB_REGION"));
            std::env::remove_var(format!("{p}_DATA_DIR"));
        }
    }

    #[test]
    fn store_env_overrides_leave_config_untouched_when_unset() {
        let mut store = StoreConfig {
            dynamodb_table_name: Some("keep".into()),
            ..StoreConfig::default()
        };
        apply_store_env_overrides("TEST_STORE_ENV_UNSET", &mut store);
        assert_eq!(store.dynamodb_table_name.as_deref(), Some("keep"));
    }

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

#[cfg(test)]
mod fjall_config_tests {
    use super::*;
    use std::sync::Mutex;

    // `apply_fjall_env_overrides` reads process-wide env vars; `cargo test`
    // runs test functions concurrently within one process, so every test
    // here that sets/removes `STORAGE_FJALL_*` serializes on this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const FJALL_ENV_VARS: [&str; 3] = [
        "STORAGE_FJALL_BLOCK_CACHE",
        "STORAGE_FJALL_WRITE_BUFFER",
        "STORAGE_FJALL_MAX_JOURNAL",
    ];

    fn clear_fjall_env() {
        // SAFETY: guarded by `ENV_LOCK`, held by every test in this module
        // that touches these vars — no other test in this crate reads or
        // writes the `STORAGE_FJALL_*` names.
        unsafe {
            for var in FJALL_ENV_VARS {
                std::env::remove_var(var);
            }
        }
    }

    // -----------------------------------------------------------------
    // parse_byte_size: every suffix, plus the error cases
    // -----------------------------------------------------------------

    #[test]
    fn parse_byte_size_accepts_a_plain_byte_count() {
        assert_eq!(parse_byte_size("67108864").unwrap(), 67_108_864);
        assert_eq!(parse_byte_size("0").unwrap(), 0);
        assert_eq!(
            parse_byte_size("  1024  ").unwrap(),
            1024,
            "whitespace is trimmed"
        );
    }

    #[test]
    fn parse_byte_size_accepts_every_binary_suffix() {
        assert_eq!(parse_byte_size("1KiB").unwrap(), 1024);
        assert_eq!(parse_byte_size("64MiB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_byte_size("1GiB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(
            parse_byte_size("2TiB").unwrap(),
            2 * 1024 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn parse_byte_size_accepts_every_decimal_suffix() {
        assert_eq!(parse_byte_size("512B").unwrap(), 512);
        assert_eq!(parse_byte_size("1KB").unwrap(), 1_000);
        assert_eq!(parse_byte_size("512MB").unwrap(), 512_000_000);
        assert_eq!(parse_byte_size("1GB").unwrap(), 1_000_000_000);
        assert_eq!(parse_byte_size("1TB").unwrap(), 1_000_000_000_000);
    }

    #[test]
    fn parse_byte_size_is_case_insensitive_and_accepts_fractions() {
        assert_eq!(parse_byte_size("64mib").unwrap(), 64 * 1024 * 1024);
        assert_eq!(
            parse_byte_size("1.5GiB").unwrap(),
            (1.5 * 1024.0 * 1024.0 * 1024.0) as u64
        );
    }

    #[test]
    fn parse_byte_size_rejects_garbage_and_unknown_suffixes() {
        assert!(parse_byte_size("").is_err(), "empty");
        assert!(parse_byte_size("   ").is_err(), "whitespace only");
        assert!(parse_byte_size("not-a-size").is_err(), "non-numeric");
        assert!(parse_byte_size("64XiB").is_err(), "unrecognised suffix");
        assert!(parse_byte_size("-64MiB").is_err(), "negative");
        assert!(parse_byte_size("-1").is_err(), "negative, no suffix");
        assert!(parse_byte_size("MiB").is_err(), "suffix with no number");
    }

    // -----------------------------------------------------------------
    // Range validation
    // -----------------------------------------------------------------

    #[test]
    fn parse_and_validate_rejects_zero_naming_the_field() {
        let err =
            parse_and_validate_fjall_bytes("STORAGE_FJALL_BLOCK_CACHE", "0", MIN_BLOCK_CACHE_BYTES)
                .unwrap_err();
        assert!(err.contains("STORAGE_FJALL_BLOCK_CACHE"), "got: {err}");
        assert!(err.contains("zero"), "got: {err}");
    }

    #[test]
    fn parse_and_validate_rejects_an_absurdly_small_value_naming_the_field() {
        let err = parse_and_validate_fjall_bytes(
            "STORAGE_FJALL_MAX_JOURNAL",
            "1KiB",
            MIN_MAX_JOURNAL_BYTES,
        )
        .unwrap_err();
        assert!(err.contains("STORAGE_FJALL_MAX_JOURNAL"), "got: {err}");
        assert!(err.contains("too small"), "got: {err}");
    }

    #[test]
    fn parse_and_validate_rejects_an_unparseable_value_naming_the_field() {
        let err = parse_and_validate_fjall_bytes(
            "STORAGE_FJALL_WRITE_BUFFER",
            "garbage",
            MIN_WRITE_BUFFER_BYTES,
        )
        .unwrap_err();
        assert!(err.contains("STORAGE_FJALL_WRITE_BUFFER"), "got: {err}");
    }

    #[test]
    fn parse_and_validate_accepts_a_value_at_exactly_the_floor() {
        assert_eq!(
            parse_and_validate_fjall_bytes(
                "STORAGE_FJALL_MAX_JOURNAL",
                "64MiB",
                MIN_MAX_JOURNAL_BYTES
            )
            .unwrap(),
            MIN_MAX_JOURNAL_BYTES
        );
    }

    #[test]
    fn fjall_tuning_validate_passes_when_every_field_is_unset() {
        assert!(FjallTuning::default().validate().is_ok());
    }

    #[test]
    fn fjall_tuning_validate_reports_a_below_floor_field() {
        let cfg = FjallTuning {
            block_cache: None,
            write_buffer: Some(1024),
            max_journal: None,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("fjall.write_buffer"), "got: {err}");
    }

    // -----------------------------------------------------------------
    // Config-file (de)serialization: `[fjall]`, plain int or suffixed string
    // -----------------------------------------------------------------

    #[test]
    fn an_absent_fjall_table_defaults_every_field_to_unset() {
        let cfg: FjallTuning = toml::from_str("").expect("loads");
        assert_eq!(cfg, FjallTuning::default());
    }

    #[test]
    fn fjall_table_accepts_suffixed_strings_and_plain_integers() {
        let cfg: FjallTuning = toml::from_str(
            r#"
            block_cache = "64MiB"
            write_buffer = "16MiB"
            max_journal = 134217728
            "#,
        )
        .expect("loads");
        assert_eq!(cfg.block_cache, Some(64 * 1024 * 1024));
        assert_eq!(cfg.write_buffer, Some(16 * 1024 * 1024));
        assert_eq!(cfg.max_journal, Some(134_217_728));
    }

    #[test]
    fn fjall_table_refuses_a_below_floor_value_at_parse_time() {
        let err = toml::from_str::<FjallTuning>(r#"block_cache = "1B""#)
            .expect_err("a below-floor block_cache must be refused when the file is parsed");
        let msg = err.to_string();
        assert!(msg.contains("fjall.block_cache"), "got: {msg}");
    }

    #[test]
    fn fjall_table_refuses_an_unknown_suffix_at_parse_time() {
        let err = toml::from_str::<FjallTuning>(r#"max_journal = "64XiB""#)
            .expect_err("an unparseable size must be refused when the file is parsed");
        assert!(err.to_string().contains("fjall.max_journal"));
    }

    // -----------------------------------------------------------------
    // Env overrides the file
    // -----------------------------------------------------------------

    #[test]
    fn env_override_wins_over_the_file_value() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_fjall_env();

        let mut cfg = FjallTuning {
            block_cache: Some(32 * 1024 * 1024),
            write_buffer: None,
            max_journal: None,
        };
        // SAFETY: serialized by `ENV_LOCK`.
        unsafe {
            std::env::set_var("STORAGE_FJALL_BLOCK_CACHE", "8MiB");
        }
        apply_fjall_env_overrides(&mut cfg).expect("valid override applies");
        assert_eq!(
            cfg.block_cache,
            Some(8 * 1024 * 1024),
            "the env var must win over whatever the file set"
        );

        clear_fjall_env();
    }

    #[test]
    fn an_unset_env_var_leaves_the_file_value_untouched() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_fjall_env();

        let mut cfg = FjallTuning {
            block_cache: Some(32 * 1024 * 1024),
            write_buffer: Some(MIN_WRITE_BUFFER_BYTES),
            max_journal: None,
        };
        let before = cfg;
        apply_fjall_env_overrides(&mut cfg).expect("no env vars set: nothing to apply");
        assert_eq!(
            cfg, before,
            "with no STORAGE_FJALL_* vars set, nothing changes"
        );
    }

    #[test]
    fn env_override_refuses_an_invalid_value_naming_the_var() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_fjall_env();

        // SAFETY: serialized by `ENV_LOCK`.
        unsafe {
            std::env::set_var("STORAGE_FJALL_MAX_JOURNAL", "1KiB");
        }
        let err = apply_fjall_env_overrides(&mut FjallTuning::default())
            .expect_err("a below-floor journal size must be refused");
        assert!(
            err.to_string().contains("STORAGE_FJALL_MAX_JOURNAL"),
            "got: {err}"
        );

        clear_fjall_env();
    }

    #[test]
    fn human_bytes_renders_the_natural_unit() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(64 * 1024 * 1024), "64.00 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }
}

//! Shared health-check formatting helpers and common diagnostic checks.
//!
//! Each service binary defines its own `health.rs` that calls into these
//! utilities so the output style is consistent across `did-hosting-server health`,
//! `did-hosting-control health`, etc.
//!
//! Every check records its outcome in a [`HealthReport`]; the binary exits
//! non-zero when any check failed (or, with `--strict`, warned), so
//! `did-hosting-server health && deploy` and container probes can act on it.
//! The report is diagnostics, so it goes to stderr; colour is used only when
//! stderr is a terminal and `NO_COLOR` is unset.

use crate::server::config::{SecretsConfig, StoreConfig};
use crate::server::secret_store::{self, SecretStore};

use std::path::Path;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// ANSI formatting helpers
// ---------------------------------------------------------------------------

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Whether to colour output on stderr: only on a terminal, and never when
/// `NO_COLOR` is set to anything non-empty (<https://no-color.org>).
pub fn stderr_colour_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        use std::io::IsTerminal;
        colour_allowed(std::env::var_os("NO_COLOR").as_deref(), || {
            std::io::stderr().is_terminal()
        })
    })
}

/// [`stderr_colour_enabled`]'s rule, with its inputs passed in.
fn colour_allowed(no_color: Option<&std::ffi::OsStr>, is_terminal: impl FnOnce() -> bool) -> bool {
    no_color.is_none_or(|v| v.is_empty()) && is_terminal()
}

/// `code` when colour is on, otherwise nothing.
fn c(code: &'static str) -> &'static str {
    if stderr_colour_enabled() { code } else { "" }
}

/// The outcome of a `health` run: how many checks failed and how many only
/// warned. Every check helper takes one and records into it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HealthReport {
    pub failed: usize,
    pub warned: usize,
}

impl HealthReport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record and print a passed check.
    pub fn pass(&mut self, msg: &str) {
        pass(msg);
    }

    /// Record and print a failed check.
    pub fn fail(&mut self, msg: &str) {
        self.failed += 1;
        eprintln!("    {}[FAIL]{} {msg}", c(RED), c(RESET));
    }

    /// Record and print a warning.
    pub fn warn(&mut self, msg: &str) {
        self.warned += 1;
        eprintln!("    {}[WARN]{} {msg}", c(YELLOW), c(RESET));
    }

    /// Whether the run is healthy: nothing failed and, under `strict`,
    /// nothing warned either.
    pub fn is_healthy(&self, strict: bool) -> bool {
        self.failed == 0 && (!strict || self.warned == 0)
    }

    /// The process exit code for this run: 0 when healthy, 1 otherwise.
    pub fn exit_code(&self, strict: bool) -> i32 {
        if self.is_healthy(strict) { 0 } else { 1 }
    }

    /// Print the one-line summary that ends the run.
    pub fn print_summary(&self, strict: bool) {
        eprintln!();
        let (colour, verdict) = if self.is_healthy(strict) {
            (GREEN, "healthy")
        } else {
            (RED, "unhealthy")
        };
        eprintln!(
            "  {}{}{verdict}{}: {} failed, {} warning(s){}",
            c(BOLD),
            c(colour),
            c(RESET),
            self.failed,
            self.warned,
            if strict { " (--strict)" } else { "" }
        );
        eprintln!();
    }
}

/// End a `health` run: print the summary (or the error that stopped the run)
/// and return the process exit code — 1 when the run could not complete,
/// when a check failed, or (under `strict`) when one warned; 0 otherwise.
pub fn finish(result: Result<HealthReport, Box<dyn std::error::Error>>, strict: bool) -> i32 {
    match result {
        Ok(report) => {
            report.print_summary(strict);
            report.exit_code(strict)
        }
        Err(e) => {
            eprintln!("    {}[FAIL]{} {e}", c(RED), c(RESET));
            eprintln!();
            eprintln!(
                "  {}{}unhealthy{}: the check could not run",
                c(BOLD),
                c(RED),
                c(RESET)
            );
            eprintln!();
            1
        }
    }
}

/// Print a passed check (counts as neither a failure nor a warning).
pub fn pass(msg: &str) {
    eprintln!("    {}[PASS]{} {msg}", c(GREEN), c(RESET));
}

pub fn info_msg(msg: &str) {
    eprintln!("    {}[INFO]{} {msg}", c(CYAN), c(RESET));
}

pub fn skip(msg: &str) {
    eprintln!("    {}[----]{} {msg}", c(DIM), c(RESET));
}

pub fn feature_on(name: &str) {
    eprintln!("    {}[ON ]{} {name}", c(GREEN), c(RESET));
}

pub fn feature_off(name: &str) {
    eprintln!("    {}[OFF]{} {name}", c(DIM), c(RESET));
}

pub fn section(title: &str) {
    eprintln!();
    eprintln!("  {}{title}{}", c(BOLD), c(RESET));
}

pub fn header(service: &str, version: &str) {
    eprintln!();
    eprintln!(
        "  {}Health Check — {service} v{version}{}",
        c(BOLD),
        c(RESET)
    );
    eprintln!("  {}", "=".repeat(40));
}

/// Print a feature flag indicator using a compile-time boolean.
pub fn print_feature(name: &str, enabled: bool) {
    if enabled {
        feature_on(name);
    } else {
        feature_off(name);
    }
}

// ---------------------------------------------------------------------------
// Config checks
// ---------------------------------------------------------------------------

pub fn check_config_loaded(path: &Path) {
    pass(&format!("Config loaded from: {}", path.display()));
}

pub fn check_value(label: &str, value: &Option<String>) {
    match value {
        Some(v) => pass(&format!("{label}: {v}")),
        None => skip(&format!("{label}: (not configured)")),
    }
}

// ---------------------------------------------------------------------------
// Secrets check
// ---------------------------------------------------------------------------

/// Determine the human-readable name of the active secrets backend.
pub fn active_secrets_backend(secrets: &SecretsConfig) -> &'static str {
    secret_store::backend_label(secrets)
}

/// Load secrets and report status.
pub async fn check_secrets(
    report: &mut HealthReport,
    secrets_config: &SecretsConfig,
    config_path: &Path,
) {
    let backend_name = active_secrets_backend(secrets_config);

    let store: Box<dyn SecretStore> =
        match secret_store::create_secret_store(secrets_config, config_path) {
            Ok(s) => s,
            Err(e) => {
                report.fail(&format!("Secret store creation failed: {e}"));
                return;
            }
        };

    if secret_store::is_plaintext_backend(secrets_config) {
        report.warn(&format!("Secret store backend: {backend_name} (INSECURE)"));
    } else {
        report.pass(&format!("Secret store backend: {backend_name}"));
    }

    match store.get().await {
        Ok(Some(_)) => {
            report.pass("Secrets loaded (signing_key, key_agreement_key, jwt_signing_key)")
        }
        Ok(None) => report.fail("No secrets found — run setup first"),
        Err(e) => report.fail(&format!("Failed to load secrets: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Store check
// ---------------------------------------------------------------------------

/// Try to open the store and report success/failure.
///
/// Returns `Some(store)` on success so the caller can run further checks.
/// A store held by a running service is a warning, not a failure: `health`
/// is often run beside the service it checks.
pub async fn check_store(
    report: &mut HealthReport,
    store_config: &StoreConfig,
) -> Option<crate::server::store::Store> {
    let backend_name = active_store_backend();
    let locator = store_locator(store_config);
    match crate::server::store::Store::open(store_config).await {
        Ok(store) => {
            report.pass(&format!("Store opened ({backend_name} @ {locator})"));
            Some(store)
        }
        Err(crate::server::error::AppError::StoreLocked(msg)) => {
            report.warn(&format!(
                "Store locked (is the service running?) ({backend_name} @ {locator}): {msg}"
            ));
            None
        }
        Err(e) => {
            report.fail(&format!(
                "Store open failed ({backend_name} @ {locator}): {e}"
            ));
            None
        }
    }
}

/// Where the compiled store backend keeps its data, for display: the data
/// directory for fjall, the server (credentials removed) for Redis, the table
/// prefix and region for DynamoDB, the project and database for Firestore,
/// and the database and region for Cosmos DB (never its connection string).
pub fn store_locator(store: &StoreConfig) -> String {
    locator_for(active_store_backend(), store)
}

fn locator_for(backend: &str, store: &StoreConfig) -> String {
    let or = |v: &Option<String>, default: &str| v.clone().unwrap_or_else(|| default.to_string());
    match backend {
        "redis" => match store.redis_url.as_deref() {
            Some(raw) => match url::Url::parse(raw) {
                Ok(u) => {
                    let host = u.host_str().unwrap_or("?");
                    match u.port() {
                        Some(port) => format!("{}://{host}:{port}{}", u.scheme(), u.path()),
                        None => format!("{}://{host}{}", u.scheme(), u.path()),
                    }
                }
                Err(_) => "redis_url (unparseable)".to_string(),
            },
            None => "redis_url not set".to_string(),
        },
        "dynamodb" => format!(
            "table prefix {}, region {}",
            or(&store.dynamodb_table_prefix, "webvh"),
            or(&store.dynamodb_region, "from the environment")
        ),
        "firestore" => format!(
            "project {}, database {}",
            or(&store.firestore_project, "from the environment"),
            or(&store.firestore_database, "(default)")
        ),
        "cosmosdb" => format!(
            "database {}, region {}",
            or(&store.cosmosdb_database, "webvh"),
            or(&store.cosmosdb_region, "eastus")
        ),
        _ => store.data_dir.display().to_string(),
    }
}

/// Human-readable name of the compiled store backend.
pub fn active_store_backend() -> &'static str {
    if cfg!(feature = "store-fjall") {
        "fjall"
    } else if cfg!(feature = "store-redis") {
        "redis"
    } else if cfg!(feature = "store-dynamodb") {
        "dynamodb"
    } else if cfg!(feature = "store-firestore") {
        "firestore"
    } else if cfg!(feature = "store-cosmosdb") {
        "cosmosdb"
    } else {
        "unknown"
    }
}

// ---------------------------------------------------------------------------
// DID resolution check
// ---------------------------------------------------------------------------

/// Resolve a DID using the default cache client.
pub async fn check_did_resolution(report: &mut HealthReport, label: &str, did: &str) -> bool {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    let client = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(c) => c,
        Err(e) => {
            report.fail(&format!("{label}: DID resolver init failed: {e}"));
            return false;
        }
    };

    match client.resolve(did).await {
        Ok(_) => {
            report.pass(&format!("{label}: {did}"));
            true
        }
        Err(e) => {
            report.fail(&format!("{label}: {did} — {e}"));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// URL reachability check
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Own-DID local-resolution check (unauthenticated HTTP `/api/health` probe)
// ---------------------------------------------------------------------------

/// Whether the service's own root DID (`.well-known`) would resolve from the
/// local store — the same content `GET /.well-known/did.jsonl` serves.
///
/// Used by the unauthenticated `/api/health` HTTP probe, which stays
/// deliberately generic (liveness + this one check, no detail) rather than
/// the verbose `did-hosting-* health` CLI diagnostic above.
///
/// `expected_did_id` is `None` when the deployment hasn't configured a
/// `server_did` yet — nothing to check, so this reports healthy. When a
/// `server_did` *is* configured but nothing is stored at `.well-known`, this
/// also reports healthy: many valid deployments host their own DID on a
/// separate process or server and never import it into this store, and
/// telling that apart from "not set up yet" isn't this check's job. Only a
/// *stale* or *broken* record at `.well-known` fails it — the Keyring
/// VTI-17 case, where a `--force-reprovision` to a new `public_url` left the
/// previous DID behind, serving the wrong identity while reporting healthy.
pub async fn own_did_served_locally(
    dids_ks: &crate::server::store::KeyspaceHandle,
    expected_did_id: Option<&str>,
) -> bool {
    let Some(expected) = expected_did_id else {
        return true;
    };

    let record = match dids_ks
        .get::<crate::did_ops::DidRecord>(crate::did_ops::did_key(".well-known"))
        .await
    {
        Ok(r) => r,
        Err(_) => return false,
    };
    let Some(record) = record else {
        return true;
    };
    if record.disabled || record.deleted_at.is_some() {
        return false;
    }
    if record.did_id.as_deref() != Some(expected) {
        return false;
    }
    matches!(
        dids_ks
            .get_raw(crate::did_ops::content_log_key(".well-known"))
            .await,
        Ok(Some(_))
    )
}

/// HTTP GET with a 5-second timeout to verify connectivity. Redirects are
/// not followed: a 3xx is reported as the status it is.
pub async fn check_url_reachable(report: &mut HealthReport, label: &str, url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            report.fail(&format!(
                "{label}: {url} — could not build an HTTP client: {e}"
            ));
            return false;
        }
    };

    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                report.pass(&format!("{label}: {url}"));
            } else {
                report.warn(&format!("{label}: {url} (HTTP {status})"));
            }
            true
        }
        Err(e) => {
            report.fail(&format!("{label}: {url} — {e}"));
            false
        }
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    #[test]
    fn failures_make_a_run_unhealthy_and_warnings_only_under_strict() {
        let mut r = HealthReport::new();
        assert_eq!(r.exit_code(false), 0);
        r.warn("w");
        assert_eq!(r.warned, 1);
        assert_eq!(r.exit_code(false), 0, "a warning alone passes");
        assert_eq!(r.exit_code(true), 1, "--strict fails on a warning");
        r.fail("f");
        assert_eq!(r.failed, 1);
        assert_eq!(r.exit_code(false), 1);
    }

    #[test]
    fn colour_needs_a_terminal_and_no_no_color() {
        use std::ffi::OsStr;
        assert!(colour_allowed(None, || true));
        assert!(!colour_allowed(None, || false));
        assert!(!colour_allowed(Some(OsStr::new("1")), || true));
        // An empty NO_COLOR does not count as set.
        assert!(colour_allowed(Some(OsStr::new("")), || true));
    }

    #[test]
    fn store_locator_names_each_backend_and_never_a_credential() {
        let store = StoreConfig {
            data_dir: "data/x".into(),
            redis_url: Some("redis://user:s3cret@cache.internal:6380/2".into()),
            cosmosdb_connection_string: Some("AccountKey=s3cret".into()),
            dynamodb_table_prefix: Some("tbl".into()),
            dynamodb_region: Some("eu-west-1".into()),
            ..StoreConfig::default()
        };
        assert_eq!(locator_for("fjall", &store), "data/x");
        let redis = locator_for("redis", &store);
        assert_eq!(redis, "redis://cache.internal:6380/2");
        assert!(!redis.contains("s3cret"));
        assert_eq!(
            locator_for("dynamodb", &store),
            "table prefix tbl, region eu-west-1"
        );
        let cosmos = locator_for("cosmosdb", &store);
        assert!(!cosmos.contains("s3cret"), "{cosmos}");
        assert!(locator_for("firestore", &store).contains("(default)"));
    }
}

#[cfg(all(test, feature = "store-fjall"))]
mod own_did_served_locally_tests {
    use super::*;
    use crate::did_ops::{DidRecord, content_log_key, did_key};
    use crate::server::config::StoreConfig;
    use crate::server::store::{KS_DIDS, Store};

    async fn dids_ks() -> (tempfile::TempDir, crate::server::store::KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open store");
        let ks = store.keyspace(KS_DIDS).expect("dids keyspace");
        (dir, ks)
    }

    fn record(did_id: &str) -> DidRecord {
        DidRecord {
            owner: "system".into(),
            mnemonic: ".well-known".into(),
            created_at: 0,
            updated_at: 0,
            version_count: 1,
            did_id: Some(did_id.into()),
            content_size: 2,
            disabled: false,
            disabled_by_admin: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: String::new(),
            services: None,
            agent_names: Vec::new(),
        }
    }

    /// No `expected_did_id` at all — nothing configured to check yet.
    #[tokio::test]
    async fn healthy_when_nothing_expected() {
        let (_dir, ks) = dids_ks().await;
        assert!(own_did_served_locally(&ks, None).await);
    }

    /// A `server_did` is configured, but nothing was ever imported at
    /// `.well-known` — a deployment that hosts its own DID elsewhere.
    #[tokio::test]
    async fn healthy_when_well_known_absent() {
        let (_dir, ks) = dids_ks().await;
        assert!(own_did_served_locally(&ks, Some("did:webvh:abc:host.example")).await);
    }

    /// The record and its content both match — the healthy, fully set-up
    /// case.
    #[tokio::test]
    async fn healthy_when_matching_and_content_present() {
        let (_dir, ks) = dids_ks().await;
        ks.insert(
            did_key(".well-known"),
            &record("did:webvh:abc:host.example"),
        )
        .await
        .unwrap();
        ks.insert_raw(content_log_key(".well-known"), b"{}".to_vec())
            .await
            .unwrap();
        assert!(own_did_served_locally(&ks, Some("did:webvh:abc:host.example")).await);
    }

    /// Keyring VTI-17: a stale DID at `.well-known` — bound to a
    /// `public_url` that reprovisioning already moved away from.
    #[tokio::test]
    async fn unhealthy_when_did_id_mismatches() {
        let (_dir, ks) = dids_ks().await;
        ks.insert(
            did_key(".well-known"),
            &record("did:webvh:stale:old-host.example"),
        )
        .await
        .unwrap();
        ks.insert_raw(content_log_key(".well-known"), b"{}".to_vec())
            .await
            .unwrap();
        assert!(!own_did_served_locally(&ks, Some("did:webvh:abc:new-host.example")).await);
    }

    /// Disabled means "don't serve this", even if the id still matches.
    #[tokio::test]
    async fn unhealthy_when_disabled() {
        let (_dir, ks) = dids_ks().await;
        let mut r = record("did:webvh:abc:host.example");
        r.disabled = true;
        ks.insert(did_key(".well-known"), &r).await.unwrap();
        ks.insert_raw(content_log_key(".well-known"), b"{}".to_vec())
            .await
            .unwrap();
        assert!(!own_did_served_locally(&ks, Some("did:webvh:abc:host.example")).await);
    }

    /// The record matches but its content bytes are missing — a partial
    /// write the route could never actually serve.
    #[tokio::test]
    async fn unhealthy_when_content_missing() {
        let (_dir, ks) = dids_ks().await;
        ks.insert(
            did_key(".well-known"),
            &record("did:webvh:abc:host.example"),
        )
        .await
        .unwrap();
        assert!(!own_did_served_locally(&ks, Some("did:webvh:abc:host.example")).await);
    }
}

//! Shared health-check formatting helpers and common diagnostic checks.
//!
//! Each service binary defines its own `health.rs` that calls into these
//! utilities so the output style is consistent across `did-hosting-server health`,
//! `did-hosting-control health`, etc.

use crate::server::config::SecretsConfig;
use crate::server::secret_store::{self, SecretStore};

use std::path::Path;

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

pub fn pass(msg: &str) {
    eprintln!("    {GREEN}[PASS]{RESET} {msg}");
}

pub fn fail(msg: &str) {
    eprintln!("    {RED}[FAIL]{RESET} {msg}");
}

pub fn warn_msg(msg: &str) {
    eprintln!("    {YELLOW}[WARN]{RESET} {msg}");
}

pub fn info_msg(msg: &str) {
    eprintln!("    {CYAN}[INFO]{RESET} {msg}");
}

pub fn skip(msg: &str) {
    eprintln!("    {DIM}[----]{RESET} {msg}");
}

pub fn feature_on(name: &str) {
    eprintln!("    {GREEN}[ON ]{RESET} {name}");
}

pub fn feature_off(name: &str) {
    eprintln!("    {DIM}[OFF]{RESET} {name}");
}

pub fn section(title: &str) {
    eprintln!();
    eprintln!("  {BOLD}{title}{RESET}");
}

pub fn header(service: &str, version: &str) {
    eprintln!();
    eprintln!("  {BOLD}Health Check — {service} v{version}{RESET}");
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
    #[cfg(feature = "aws-secrets")]
    if secrets.aws_secret_name.is_some() {
        return "AWS Secrets Manager";
    }

    #[cfg(feature = "gcp-secrets")]
    if secrets.gcp_secret_name.is_some() {
        return "GCP Secret Manager";
    }

    #[cfg(feature = "keyring")]
    {
        let _ = secrets;
        return "OS keyring";
    }

    #[allow(unreachable_code)]
    {
        let _ = secrets;
        "Plaintext (config file)"
    }
}

/// Load secrets and report status.
pub async fn check_secrets(secrets_config: &SecretsConfig, config_path: &Path) {
    let backend_name = active_secrets_backend(secrets_config);

    let store: Box<dyn SecretStore> =
        match secret_store::create_secret_store(secrets_config, config_path) {
            Ok(s) => s,
            Err(e) => {
                fail(&format!("Secret store creation failed: {e}"));
                return;
            }
        };

    if secret_store::is_plaintext_backend(secrets_config) {
        warn_msg(&format!("Secret store backend: {backend_name} (INSECURE)"));
    } else {
        pass(&format!("Secret store backend: {backend_name}"));
    }

    match store.get().await {
        Ok(Some(_)) => pass("Secrets loaded (signing_key, key_agreement_key, jwt_signing_key)"),
        Ok(None) => fail("No secrets found — run setup first"),
        Err(e) => fail(&format!("Failed to load secrets: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Store check
// ---------------------------------------------------------------------------

/// Try to open the store and report success/failure.
///
/// Returns `Some(store)` on success so the caller can run further checks.
pub async fn check_store(
    store_config: &crate::server::config::StoreConfig,
) -> Option<crate::server::store::Store> {
    let backend_name = active_store_backend();
    match crate::server::store::Store::open(store_config).await {
        Ok(store) => {
            pass(&format!(
                "Store opened ({backend_name} @ {})",
                store_config.data_dir.display()
            ));
            Some(store)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("lock") || msg.contains("Lock") {
                warn_msg(&format!("Store locked (is the server running?): {msg}"));
            } else {
                fail(&format!("Store open failed: {msg}"));
            }
            None
        }
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
pub async fn check_did_resolution(label: &str, did: &str) -> bool {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    let client = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(c) => c,
        Err(e) => {
            fail(&format!("{label}: DID resolver init failed: {e}"));
            return false;
        }
    };

    match client.resolve(did).await {
        Ok(_) => {
            pass(&format!("{label}: {did}"));
            true
        }
        Err(e) => {
            fail(&format!("{label}: {did} — {e}"));
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

/// HTTP GET with a 5-second timeout to verify connectivity.
pub async fn check_url_reachable(label: &str, url: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                pass(&format!("{label}: {url}"));
            } else {
                warn_msg(&format!("{label}: {url} (HTTP {status})"));
            }
            true
        }
        Err(e) => {
            fail(&format!("{label}: {url} — {e}"));
            false
        }
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

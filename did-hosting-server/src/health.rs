//! Health check diagnostic for `did-hosting-server health`.

use std::error::Error;
use std::path::PathBuf;

use did_hosting_common::server::health::{self, HealthReport};

use crate::config::AppConfig;
use did_hosting_common::server::store::KS_DIDS;

/// Run every check and return what they found. A config that does not load
/// is an error: nothing else can be checked without it.
pub async fn run_health(config_path: Option<PathBuf>) -> Result<HealthReport, Box<dyn Error>> {
    let mut report = HealthReport::new();
    health::header("did-hosting-server", env!("CARGO_PKG_VERSION"));

    // ── Configuration ──────────────────────────────────────────────
    health::section("Configuration");
    let config = match AppConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            return Err(format!("config load failed: {e}").into());
        }
    };
    health::check_config_loaded(&config.config_path);
    health::check_value("public_url", &config.public_url);
    health::check_value("server_did", &config.server_did);
    health::check_value("mediator_did", &config.mediator_did);
    health::check_value("control_did", &config.control_did);

    // ── Compile Features ───────────────────────────────────────────
    health::section("Compile Features");
    health::print_feature("store-fjall", cfg!(feature = "store-fjall"));
    health::print_feature("store-redis", cfg!(feature = "store-redis"));
    health::print_feature("store-dynamodb", cfg!(feature = "store-dynamodb"));
    health::print_feature("store-firestore", cfg!(feature = "store-firestore"));
    health::print_feature("store-cosmosdb", cfg!(feature = "store-cosmosdb"));
    health::print_feature("keyring", cfg!(feature = "keyring"));
    health::print_feature("aws-secrets", cfg!(feature = "aws-secrets"));
    health::print_feature("gcp-secrets", cfg!(feature = "gcp-secrets"));

    // ── Secrets ────────────────────────────────────────────────────
    health::section("Secrets");
    health::check_secrets(&mut report, &config.secrets, &config.config_path).await;

    // ── Store ──────────────────────────────────────────────────────
    health::section("Store");
    let store = health::check_store(&mut report, &config.store).await;

    // ── Root DID (.well-known) ─────────────────────────────────────
    if let Some(ref store) = store
        && let Ok(dids_ks) = store.keyspace(KS_DIDS)
    {
        health::section("Root DID (.well-known)");
        match crate::bootstrap::root_did_exists(&dids_ks).await {
            Ok(true) => {
                report.pass("Root DID exists");
                // Try to read the DidRecord for more info
                match dids_ks
                    .get::<crate::did_ops::DidRecord>(crate::did_ops::did_key(".well-known"))
                    .await
                {
                    Ok(Some(record)) => {
                        if let Some(ref did_id) = record.did_id {
                            health::info_msg(&format!("DID: {did_id}"));
                        }
                        health::info_msg(&format!("Version count: {}", record.version_count));
                    }
                    Ok(None) => {}
                    Err(e) => report.warn(&format!("Could not read DID record: {e}")),
                }
            }
            Ok(false) => {
                health::skip("Root DID not yet bootstrapped");
            }
            Err(e) => report.fail(&format!("Root DID check failed: {e}")),
        }
    }

    // ── DID Resolution ─────────────────────────────────────────────
    if let Some(ref did) = config.server_did {
        health::section("DID Resolution");
        health::check_did_resolution(&mut report, "Server DID resolves", did).await;
    }

    if let Some(ref did) = config.mediator_did {
        health::section("Mediator DID Resolution");
        health::check_did_resolution(&mut report, "Mediator DID resolves", did).await;
    }

    // ── Control Plane ──────────────────────────────────────────────
    health::section("Control Plane");
    match config.control_did {
        Some(ref did) => {
            health::check_did_resolution(&mut report, "Control plane DID resolves", did).await;
        }
        None => report.fail(
            "control_did is not set — an edge does not run without a control plane \
             (use did-hosting-daemon for a single host)",
        ),
    }

    Ok(report)
}

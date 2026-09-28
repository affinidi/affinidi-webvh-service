//! Health check diagnostic for `did-hosting-server health`.

use std::error::Error;
use std::path::PathBuf;

use did_hosting_common::server::health;

use crate::config::AppConfig;
use did_hosting_common::server::store::KS_DIDS;

pub async fn run_health(config_path: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    health::header("did-hosting-server", env!("CARGO_PKG_VERSION"));

    // ── Configuration ──────────────────────────────────────────────
    let config = match AppConfig::load(config_path) {
        Ok(c) => {
            health::section("Configuration");
            health::check_config_loaded(&c.config_path);
            health::check_value("public_url", &c.public_url);
            health::check_value("server_did", &c.server_did);
            health::check_value("mediator_did", &c.mediator_did);
            health::check_value("control_did", &c.control_did);
            Some(c)
        }
        Err(e) => {
            health::section("Configuration");
            health::fail(&format!("Config load failed: {e}"));
            None
        }
    };

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

    let config = match config {
        Some(c) => c,
        None => {
            eprintln!();
            return Ok(());
        }
    };

    // ── Secrets ────────────────────────────────────────────────────
    health::section("Secrets");
    health::check_secrets(&config.secrets, &config.config_path).await;

    // ── Store ──────────────────────────────────────────────────────
    health::section("Store");
    let store = health::check_store(&config.store).await;

    // ── Root DID (.well-known) ─────────────────────────────────────
    if let Some(ref store) = store
        && let Ok(dids_ks) = store.keyspace(KS_DIDS)
    {
        health::section("Root DID (.well-known)");
        match crate::bootstrap::root_did_exists(&dids_ks).await {
            Ok(true) => {
                health::pass("Root DID exists");
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
                    Err(e) => health::warn_msg(&format!("Could not read DID record: {e}")),
                }
            }
            Ok(false) => {
                health::skip("Root DID not yet bootstrapped");
            }
            Err(e) => health::fail(&format!("Root DID check failed: {e}")),
        }
    }

    // ── DID Resolution ─────────────────────────────────────────────
    if let Some(ref did) = config.server_did {
        health::section("DID Resolution");
        health::check_did_resolution("Server DID resolves", did).await;
    }

    if let Some(ref did) = config.mediator_did {
        health::section("Mediator DID Resolution");
        health::check_did_resolution("Mediator DID resolves", did).await;
    }

    // ── Control Plane ──────────────────────────────────────────────
    health::section("Control Plane");
    match config.control_did {
        Some(ref did) => {
            health::check_did_resolution("Control plane DID resolves", did).await;
        }
        None => health::fail(
            "control_did is not set — an edge does not run without a control plane \
             (use did-hosting-daemon for a single host)",
        ),
    }

    eprintln!();
    Ok(())
}

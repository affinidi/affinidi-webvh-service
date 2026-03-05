//! Health check diagnostic for `webvh-witness health`.

use std::error::Error;
use std::path::PathBuf;

use affinidi_webvh_common::server::health;

use crate::config::AppConfig;

pub async fn run_health(config_path: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    health::header("webvh-witness", env!("CARGO_PKG_VERSION"));

    // ── Configuration ──────────────────────────────────────────────
    let config = match AppConfig::load(config_path) {
        Ok(c) => {
            health::section("Configuration");
            health::check_config_loaded(&c.config_path);
            health::check_value("server_did", &c.server_did);
            health::check_value("mediator_did", &c.mediator_did);
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
    health::check_store(&config.store).await;

    // ── DID Resolution ─────────────────────────────────────────────
    if let Some(ref did) = config.server_did {
        health::section("DID Resolution");
        health::check_did_resolution("Server DID resolves", did).await;
    }

    if let Some(ref did) = config.mediator_did {
        health::section("Mediator DID Resolution");
        health::check_did_resolution("Mediator DID resolves", did).await;
    }

    eprintln!();
    Ok(())
}

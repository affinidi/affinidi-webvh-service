//! Health check diagnostic for `webvh-witness health`.

use std::error::Error;
use std::path::PathBuf;

use did_hosting_common::server::health::{self, HealthReport};

use crate::config::AppConfig;

/// Run every check and return what they found. A config that does not load
/// is an error: nothing else can be checked without it.
pub async fn run_health(config_path: Option<PathBuf>) -> Result<HealthReport, Box<dyn Error>> {
    let mut report = HealthReport::new();
    health::header("webvh-witness", env!("CARGO_PKG_VERSION"));

    // ── Configuration ──────────────────────────────────────────────
    health::section("Configuration");
    let config = AppConfig::load(config_path)
        .map_err(|e| -> Box<dyn Error> { format!("config load failed: {e}").into() })?;
    health::check_config_loaded(&config.config_path);
    health::check_value("server_did", &config.server_did);
    health::check_value("mediator_did", &config.mediator_did);

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
    health::check_store(&mut report, &config.store).await;

    // ── DID Resolution ─────────────────────────────────────────────
    if let Some(ref did) = config.server_did {
        health::section("DID Resolution");
        health::check_did_resolution(&mut report, "Server DID resolves", did).await;
    }

    if let Some(ref did) = config.mediator_did {
        health::section("Mediator DID Resolution");
        health::check_did_resolution(&mut report, "Mediator DID resolves", did).await;
    }

    Ok(report)
}

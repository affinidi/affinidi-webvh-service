//! Health check diagnostic for `webvh-watcher health`.

use std::error::Error;
use std::path::PathBuf;

use affinidi_webvh_common::server::health;

use crate::config::AppConfig;

pub async fn run_health(config_path: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    health::header("webvh-watcher", env!("CARGO_PKG_VERSION"));

    // ── Configuration ──────────────────────────────────────────────
    let config = match AppConfig::load(config_path) {
        Ok(c) => {
            health::section("Configuration");
            health::check_config_loaded(&c.config_path);
            let listen = format!("{}:{}", c.server.host, c.server.port);
            health::pass(&format!("Listen address: {listen}"));
            health::info_msg(&format!("Sync sources: {}", c.sync.sources.len()));
            if c.sync.reconcile_interval > 0 {
                health::info_msg(&format!(
                    "Reconcile interval: {}s",
                    c.sync.reconcile_interval
                ));
            } else {
                health::info_msg("Reconcile interval: disabled");
            }
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

    let config = match config {
        Some(c) => c,
        None => {
            eprintln!();
            return Ok(());
        }
    };

    // ── Store ──────────────────────────────────────────────────────
    health::section("Store");
    health::check_store(&config.store).await;

    eprintln!();
    Ok(())
}

//! Interactive setup wizard for generating a watcher config.toml.
//!
//! Unlike the other webvh services, the watcher has no VTA integration
//! and no DID identity of its own — it's a read-only mirror that accepts
//! pushes from source servers and optionally reconciles on a timer. The
//! wizard is therefore pure config-generation.

use std::path::PathBuf;

use dialoguer::{Confirm, Input, Select};

use crate::config::{AppConfig, LogFormat, ServerConfig, SourceConfig, StoreConfig, SyncConfig};

pub async fn run_wizard(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Watcher — Setup Wizard");
    eprintln!("  =============================");
    eprintln!();
    eprintln!("  The watcher is a read-only DID mirror. Source servers push");
    eprintln!("  DID updates here; public readers resolve DIDs against this");
    eprintln!("  process. No DID identity or VTA integration is required.");
    eprintln!();

    let default_path = config_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "config.toml".to_string());

    let output_path: String = Input::new()
        .with_prompt("Configuration file path")
        .default(default_path)
        .interact_text()?;
    let output_path = PathBuf::from(&output_path);

    if output_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                output_path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8533u16)
        .interact_text()?;

    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(log_levels)
        .default(0)
        .interact()?;
    let log_level = log_levels[log_level_idx].to_string();

    let format_options = &["text", "json"];
    let format_idx = Select::new()
        .with_prompt("Log format")
        .items(format_options)
        .default(0)
        .interact()?;
    let log_format = match format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-watcher".to_string())
        .interact_text()?;

    // Inbound push auth — comma-separated tokens that source servers
    // must present on push. Leaving empty disables auth checks (only
    // acceptable when the watcher is on a trusted private network).
    eprintln!();
    eprintln!("  Inbound push authentication.");
    eprintln!("  Source servers present a bearer token on each push. Enter a");
    eprintln!("  comma-separated list of accepted tokens, or leave empty to");
    eprintln!("  disable auth (only safe on a trusted private network).");
    eprintln!();
    let push_tokens_raw: String = Input::new()
        .with_prompt("Push tokens (comma-separated)")
        .default(String::new())
        .allow_empty(true)
        .interact_text()?;
    let push_tokens: Vec<String> = push_tokens_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Outbound reconcile loop — optional source list + interval. A zero
    // interval disables the loop; the watcher is then push-only.
    let add_sources = Confirm::new()
        .with_prompt("Configure source servers for outbound reconciliation?")
        .default(false)
        .interact()?;

    let mut sources: Vec<SourceConfig> = Vec::new();
    let mut reconcile_interval: u64 = 0;
    if add_sources {
        loop {
            let url: String = Input::new()
                .with_prompt("Source URL (blank to stop)")
                .default(String::new())
                .allow_empty(true)
                .interact_text()?;
            if url.trim().is_empty() {
                break;
            }
            let token: String = Input::new()
                .with_prompt("Token (blank for none)")
                .default(String::new())
                .allow_empty(true)
                .interact_text()?;
            sources.push(SourceConfig {
                url: url.trim().trim_end_matches('/').to_string(),
                token: if token.is_empty() { None } else { Some(token) },
            });
        }

        if !sources.is_empty() {
            reconcile_interval = Input::new()
                .with_prompt("Reconcile interval (seconds, 0 = disabled)")
                .default(300u64)
                .interact_text()?;
        }
    }

    let config = AppConfig {
        server: ServerConfig {
            host,
            port,
            trusted_proxies: Vec::new(),
        },
        log: crate::config::LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(&data_dir),
            ..StoreConfig::default()
        },
        sync: SyncConfig {
            push_tokens,
            sources,
            reconcile_interval,
        },
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!();
    eprintln!("  Configuration written to {}", output_path.display());
    eprintln!();
    eprintln!("  Next:");
    eprintln!("    webvh-watcher --config {}", output_path.display());
    eprintln!();

    Ok(())
}

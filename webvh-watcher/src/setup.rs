//! Interactive setup wizard for generating a watcher config.toml.
//!
//! Unlike the other webvh services, the watcher has no VTA integration
//! and no DID identity of its own — it's a read-only mirror that accepts
//! pushes from source servers and optionally reconciles on a timer. The
//! wizard is therefore pure config-generation.

use std::path::{Path, PathBuf};

use did_hosting_common::server::setup_recipe::{
    ServiceKind, SetupRecipe, load_recipe, require_service, to_log_format,
};
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
            trusted_proxy_cidrs: Vec::new(),
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

/// Non-interactive setup driven by a [`SetupRecipe`] TOML file.
///
/// The watcher has no VTA / no secrets backend, so the recipe only needs
/// `[deployment]`, `[output]`, `[server]`, and `[watcher]` sections.
/// `force_reprovision` is accepted for parity with the other binaries
/// but the watcher only ever has a local config file at stake — we still
/// honour it for the `config.toml.bak` backup on overwrite.
pub async fn run_from_recipe(
    recipe_path: &Path,
    force_reprovision: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let recipe = load_recipe(recipe_path)?;
    require_service(&recipe, ServiceKind::Watcher)?;
    did_hosting_common::server::setup_recipe::print_recipe_banner("webvh-watcher", &recipe);
    apply_recipe(&recipe, force_reprovision).await
}

/// Apply an in-memory [`SetupRecipe`]. Split out so a future
/// `--non-interactive` CLI flag (with shortcut args) can populate the
/// recipe in memory and reuse this path.
pub async fn apply_recipe(
    recipe: &SetupRecipe,
    force_reprovision: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = recipe.output.config_path.clone();

    if output_path.exists() {
        if !force_reprovision {
            eprintln!(
                "  Refusing to overwrite {} — re-run with --force-reprovision \
                 to back up and replace.",
                output_path.display()
            );
            return Err("watcher config already exists".into());
        }
        // Back up before overwriting so the previous push tokens aren't
        // silently lost.
        did_hosting_common::server::setup_recipe::back_up_config(&output_path)?;
    }

    let host = recipe
        .server
        .host
        .clone()
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let port = recipe
        .server
        .port
        .unwrap_or(SetupRecipe::default_port(ServiceKind::Watcher));
    let log_level = recipe
        .server
        .log_level
        .clone()
        .unwrap_or_else(|| "info".to_string());
    let log_format = recipe
        .server
        .log_format
        .map(to_log_format)
        .unwrap_or(LogFormat::Text);
    let data_dir = recipe
        .server
        .data_dir
        .clone()
        .unwrap_or_else(|| SetupRecipe::default_data_dir(ServiceKind::Watcher));

    let sources: Vec<SourceConfig> = recipe
        .watcher
        .sources
        .iter()
        .map(|s| SourceConfig {
            url: s.url.trim_end_matches('/').to_string(),
            token: s.token.clone(),
        })
        .collect();

    let config = AppConfig {
        server: ServerConfig {
            host,
            port,
            trusted_proxies: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
        },
        log: crate::config::LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir,
            ..StoreConfig::default()
        },
        sync: SyncConfig {
            push_tokens: recipe.watcher.push_tokens.clone(),
            sources,
            reconcile_interval: recipe.watcher.reconcile_interval,
        },
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output_path, &toml_str)?;
    eprintln!(
        "  [setup-recipe] watcher config written to {}",
        output_path.display()
    );
    Ok(())
}

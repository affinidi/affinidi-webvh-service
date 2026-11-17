//! `did-hosting-control`: the control plane binary. Parses the CLI and hands
//! the chosen subcommand to the library ([`did_hosting_control::cli`]).

use clap::Parser;
use did_hosting_common::server::cli::{Loader, Service, exit_on_error};
use did_hosting_common::server::store;
use did_hosting_control::cli::{Cli, Command};
use did_hosting_control::config::AppConfig;
use did_hosting_control::{health, secret_store, server, setup, setup_recipe};
use std::path::PathBuf;

// ─── Allocator ──────────────────────────────────────────────────────────────
//
// Set on the binary only. A library that installs a #[global_allocator] forces
// it on every consumer, so this deliberately does not live in lib.rs.
//
// Why not the system allocator: the control plane churns short-lived buffers
// (Trust Task envelopes, DID logs being verified, UI and API responses, store
// batches). glibc malloc keeps those arenas rather than returning them, so RSS
// ratchets to the high-water mark and never falls back — indistinguishable
// from a leak on a memory graph.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read by jemalloc itself at startup via this well-known symbol.
///
/// `background_thread:true` runs the purger off the request path.
/// `dirty_decay_ms` / `muzzy_decay_ms` are how long freed pages linger before
/// being returned to the OS; jemalloc's defaults (10s / 10s) are tuned for
/// throughput on allocation-heavy workloads, and hold RSS well above the live
/// heap. 5s keeps the memory graph honest at a negligible cost here, because
/// the service's hot path is I/O-bound, not allocation-bound.
///
/// Raise these (or drop the `jemalloc` feature) if you are optimising for
/// allocation throughput over resident footprint.
///
/// The symbol must be `_rjem_malloc_conf`, not the `malloc_conf` jemalloc
/// documents: tikv-jemalloc-sys (default features) builds jemalloc with
/// `--with-jemalloc-prefix=_rjem_`, which prefixes every public symbol,
/// including the one it reads its configuration from. An unprefixed
/// `malloc_conf` would compile and link fine and be silently ignored.
///
/// SAFETY: exporting a symbol is unsafe because it could clash with another
/// definition of the same name. `_rjem_malloc_conf` is the (prefixed) name
/// jemalloc reads for exactly this, it is defined once (in the binary, never
/// the library), and the value is the NUL-terminated static string jemalloc
/// expects. This is the one `unsafe` outside tests (CONTRIBUTING rule 6),
/// signed off in the PR that added it.
///
/// The type is `&[u8; 63]`, a reference to a fixed-size array: a thin pointer,
/// which is what jemalloc's `const char *malloc_conf` is. A `&[u8]` slice
/// reference is a two-word fat pointer (address + length), which matches
/// `const char *` only by the accident of field order.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[allow(unsafe_code)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8; 63] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000\0";

const SERVICE: Service = Service::Control;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    let config_path = cli.config;
    let load = || -> Loader<'static, AppConfig> {
        let path = config_path.clone();
        Box::new(move || Ok(AppConfig::load(path)?))
    };

    match cli.command {
        Some(Command::Setup {
            setup_key_out,
            setup_key_file,
            context,
            from,
            force_reprovision,
            non_interactive: _,
        }) => {
            if let Some(path) = setup_key_out {
                exit_on_error(
                    "Setup error",
                    setup::run_setup_phase1(&path, &context).await,
                );
            } else if let Some(recipe_path) = from {
                if let Err(e) =
                    setup_recipe::run_from_recipe(&recipe_path, setup_key_file, force_reprovision)
                        .await
                {
                    eprintln!("Setup error: {e}");
                    std::process::exit(setup_recipe::map_exit_code(&e));
                }
            } else {
                exit_on_error("Setup error", setup::run_setup(setup_key_file).await);
            }
        }
        Some(Command::Uninstall { yes }) => {
            let config_path = config_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("config.toml"));
            exit_on_error(
                "Uninstall error",
                setup_recipe::run_uninstall(&config_path, yes).await,
            );
        }
        Some(Command::Health { strict }) => {
            let code = did_hosting_common::server::health::finish(
                health::run_health(config_path.clone()).await,
                strict,
            );
            std::process::exit(code);
        }
        Some(Command::SetupOfflinePrepare { request, state }) => exit_on_error(
            "Setup error",
            setup::run_setup_offline_prepare(request, state).await,
        ),
        Some(Command::SetupOfflineComplete {
            bundle,
            expect_digest,
            state,
        }) => exit_on_error(
            "Setup error",
            setup::run_setup_offline_complete(bundle, expect_digest, state).await,
        ),
        Some(Command::Admin(cmd)) => exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Stats(cmd)) => exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Identity(cmd)) => exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Tsp(cmd)) => exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Keys(cmd)) => exit_on_error("Error", cmd.run(SERVICE, load()).await),
        Some(Command::Vta(cmd)) => exit_on_error("Error", cmd.run(SERVICE).await),
        None => run_control(config_path).await,
    }
}

async fn run_control(config_path: Option<PathBuf>) {
    let config = match AppConfig::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Create a config.toml or specify one:");
            eprintln!("  did-hosting-control --config <path>");
            eprintln!("  did-hosting-control setup");
            std::process::exit(1);
        }
    };

    did_hosting_common::server::config::init_tracing(&config.log);

    // Load secrets from the configured backend
    let secret_store = match secret_store::create_secret_store(&config) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to create secret store: {e}");
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let secrets = match secret_store.get().await {
        Ok(Some(s)) => {
            tracing::info!("secrets loaded from secret store");
            s
        }
        Ok(None) => {
            eprintln!("Error: no secrets found — run `did-hosting-control setup` first");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error loading secrets: {e}");
            std::process::exit(1);
        }
    };

    let store = match store::Store::open_with(&config.store, &config.fjall).await {
        Ok(store) => store,
        Err(e) => {
            tracing::error!("failed to open store: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = server::run(config, store, secrets).await {
        tracing::error!("control plane error: {e}");
        std::process::exit(1);
    }
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan}██████╗{magenta} ████████╗{yellow}██████╗ {cyan}██╗     {reset}
{cyan}██╔═══╝{magenta} ╚══██╔══╝{yellow}██╔══██╗{cyan}██║     {reset}
{cyan}██║    {magenta}    ██║   {yellow}██████╔╝{cyan}██║     {reset}
{cyan}██║    {magenta}    ██║   {yellow}██╔══██╗{cyan}██║     {reset}
{cyan}╚██████╗{magenta}   ██║   {yellow}██║  ██║{cyan}███████╗{reset}
{cyan} ╚═════╝{magenta}   ╚═╝   {yellow}╚═╝  ╚═╝{cyan}╚══════╝{reset}
{dim}  DID Hosting Control Plane v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

#[cfg(test)]
mod cli_reference_tests {
    did_hosting_common::cli_reference_test!(did_hosting_control::cli::Cli, "did-hosting-control");
}

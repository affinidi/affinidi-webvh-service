//! `webvh-watcher` binary: `setup`, `health`, and running the mirror.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use webvh_watcher::config::AppConfig;
use webvh_watcher::{health, secret_store, server, setup, store};

// ─── Allocator ──────────────────────────────────────────────────────────────
//
// Set on the binary only. A library that installs a #[global_allocator] forces
// it on every consumer, so this deliberately does not live in lib.rs.
//
// Why not the system allocator: the watcher churns short-lived buffers (DID
// logs mirrored from their sources, resolution responses). glibc malloc keeps
// those arenas rather than returning them, so RSS ratchets to the high-water
// mark and never falls back — indistinguishable from a leak on a memory graph.
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

#[derive(Parser)]
#[command(
    name = "webvh-watcher",
    about = "WebVH Watcher — Read-Only DID Mirror",
    version
)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Provision the watcher's DID from a VTA context and write config.toml.
    ///
    /// Interactive by default (online VTA). For scripted setup, pass
    /// `--from <recipe.toml>`; an online recipe also needs
    /// `--setup-key-file`, minted first with `--setup-key-out`.
    Setup {
        /// Path to a declarative setup recipe TOML. Skips every prompt.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Mint an ephemeral setup did:key, persist it to <path>, print the
        /// `pnm contexts create` command, and exit.
        #[arg(long, conflicts_with = "setup_key_file")]
        setup_key_out: Option<PathBuf>,
        /// Reuse the setup did:key persisted by `--setup-key-out`.
        #[arg(long)]
        setup_key_file: Option<PathBuf>,
        /// Context id for `--setup-key-out`'s PNM command.
        #[arg(long, default_value = "did-hosting", requires = "setup_key_out")]
        context: String,
        /// Allow overwriting an existing config.toml. The previous file
        /// is moved to config.toml.bak.
        #[arg(long)]
        force_reprovision: bool,
    },
    /// Run health check diagnostics. Exits non-zero when a check fails (or,
    /// with --strict, warns), so it can gate a deploy or a container probe.
    Health {
        /// Also exit non-zero when a check only warned (a store held by the
        /// running service, plaintext secrets, a non-2xx reachability probe).
        #[arg(long)]
        strict: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Some(Command::Setup {
            from,
            setup_key_out,
            setup_key_file,
            context,
            force_reprovision,
        }) => {
            let result = if let Some(path) = setup_key_out {
                setup::run_setup_phase1(&path, &context).await
            } else if let Some(path) = from {
                setup::run_from_recipe(&path, setup_key_file, force_reprovision).await
            } else {
                setup::run_wizard(cli.config, setup_key_file).await
            };
            if let Err(e) = result {
                eprintln!("Setup error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Health { strict }) => {
            let code = did_hosting_common::server::health::finish(
                health::run_health(cli.config).await,
                strict,
            );
            std::process::exit(code);
        }
        None => run_watcher(cli.config).await,
    }
}

async fn run_watcher(config_path: Option<PathBuf>) {
    let config = match AppConfig::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Create a config.toml or specify one:");
            eprintln!("  webvh-watcher --config <path>");
            std::process::exit(1);
        }
    };

    did_hosting_common::server::config::init_tracing(&config.log);

    let store = store::Store::open_with(&config.store, &config.fjall)
        .await
        .expect("failed to open store");

    let secrets = match secret_store::create_secret_store(&config) {
        Ok(backend) => match backend.get().await {
            Ok(Some(secrets)) => secrets,
            Ok(None) => {
                eprintln!("Error: no secrets found — run `webvh-watcher setup` first");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error: failed to read secrets: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error: secret store: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = server::run(config, store, secrets).await {
        tracing::error!("watcher error: {e}");
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
{cyan}██╗    ██╗{magenta} █████╗ {yellow}████████╗{cyan} ██████╗{magenta}██╗  ██╗{reset}
{cyan}██║    ██║{magenta}██╔══██╗{yellow}╚══██╔══╝{cyan}██╔════╝{magenta}██║  ██║{reset}
{cyan}██║ █╗ ██║{magenta}███████║{yellow}   ██║   {cyan}██║     {magenta}███████║{reset}
{cyan}██║███╗██║{magenta}██╔══██║{yellow}   ██║   {cyan}██║     {magenta}██╔══██║{reset}
{cyan}╚███╔███╔╝{magenta}██║  ██║{yellow}   ██║   {cyan}╚██████╗{magenta}██║  ██║{reset}
{cyan} ╚══╝╚══╝ {magenta}╚═╝  ╚═╝{yellow}   ╚═╝   {cyan} ╚═════╝{magenta}╚═╝  ╚═╝{reset}
{dim}  WebVH Watcher v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

#[cfg(test)]
mod cli_reference_tests {
    did_hosting_common::cli_reference_test!(super::Cli, "webvh-watcher");
}

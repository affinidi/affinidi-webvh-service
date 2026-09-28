use clap::{Parser, Subcommand};
use std::path::PathBuf;
use webvh_watcher::config::AppConfig;
use webvh_watcher::{health, secret_store, server, setup, store};

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
        #[arg(long, default_value = "webvh", requires = "setup_key_out")]
        context: String,
        /// Allow overwriting an existing config.toml. The previous file
        /// is moved to config.toml.bak.
        #[arg(long)]
        force_reprovision: bool,
    },
    /// Run health check diagnostics
    Health,
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
        Some(Command::Health) => {
            if let Err(e) = health::run_health(cli.config).await {
                eprintln!("Health check error: {e}");
                std::process::exit(1);
            }
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

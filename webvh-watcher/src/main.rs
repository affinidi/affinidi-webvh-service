use clap::{Parser, Subcommand};
use std::path::PathBuf;
use webvh_watcher::config::AppConfig;
use webvh_watcher::{health, server, setup, store};

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
    /// Run interactive setup wizard to generate config.toml.
    ///
    /// For non-interactive / scripted setup, pass `--from <recipe.toml>`.
    /// The watcher has no VTA / no secrets, so the recipe only needs
    /// `[deployment]`, `[output]`, `[server]`, and `[watcher]`.
    Setup {
        /// Path to a declarative setup recipe TOML. Skips every prompt.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
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
            force_reprovision,
        }) => {
            let result = if let Some(path) = from {
                setup::run_from_recipe(&path, force_reprovision).await
            } else {
                setup::run_wizard(cli.config).await
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

    if let Err(e) = server::run(config, store).await {
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

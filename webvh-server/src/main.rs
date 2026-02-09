mod acl;
mod auth;
mod config;
mod error;
mod mnemonic;
mod routes;
mod server;
mod stats;
mod store;

use std::path::PathBuf;

use clap::Parser;
use config::{AppConfig, LogFormat};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "webvh-server", about = "WebVH DID Hosting Server", version)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    let config = match AppConfig::load(cli.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Create a config.toml or specify one:");
            eprintln!("  webvh-server --config <path>");
            std::process::exit(1);
        }
    };

    init_tracing(&config);

    let store = store::Store::open(&config.store).expect("failed to open store");

    if let Err(e) = server::run(config, store).await {
        tracing::error!("server error: {e}");
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
{cyan}██╗    ██╗{magenta}███████╗{yellow}██████╗ {cyan}██╗   ██╗{magenta}██╗  ██╗{reset}
{cyan}██║    ██║{magenta}██╔════╝{yellow}██╔══██╗{cyan}██║   ██║{magenta}██║  ██║{reset}
{cyan}██║ █╗ ██║{magenta}█████╗  {yellow}██████╔╝{cyan}██║   ██║{magenta}███████║{reset}
{cyan}██║███╗██║{magenta}██╔══╝  {yellow}██╔══██╗{cyan}╚██╗ ██╔╝{magenta}██╔══██║{reset}
{cyan}╚███╔███╔╝{magenta}███████╗{yellow}██████╔╝{cyan} ╚████╔╝ {magenta}██║  ██║{reset}
{cyan} ╚══╝╚══╝ {magenta}╚══════╝{yellow}╚═════╝ {cyan}  ╚═══╝  {magenta}╚═╝  ╚═╝{reset}
{dim}  WebVH Server v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

fn init_tracing(config: &AppConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    match config.log.format {
        LogFormat::Json => subscriber.json().init(),
        LogFormat::Text => subscriber.init(),
    }
}

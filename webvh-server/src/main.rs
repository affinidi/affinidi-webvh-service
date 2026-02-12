mod acl;
mod auth;
mod config;
mod error;
#[cfg(feature = "ui")]
mod frontend;
mod mnemonic;
mod passkey;
mod routes;
mod server;
mod setup;
mod stats;
mod store;

#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};
use config::AppConfig;
use config::LogFormat;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "webvh-server", about = "WebVH DID Hosting Server", version)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run interactive setup wizard to generate config.toml
    Setup,
    /// Generate a one-time passkey enrollment link
    Invite {
        /// DID to associate with this enrollment
        #[arg(long)]
        did: String,
        /// Role: admin or owner
        #[arg(long, default_value = "admin")]
        role: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Some(Command::Setup) => {
            if let Err(e) = setup::run_wizard(cli.config).await {
                eprintln!("Setup error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Invite { did, role }) => {
            if let Err(e) = run_invite(cli.config, did, role).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        None => run_server(cli.config).await,
    }
}

async fn run_invite(
    config_path: Option<PathBuf>,
    did: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::acl::Role;
    use crate::auth::session::now_epoch;
    use crate::passkey::store::{Enrollment, store_enrollment};

    // Validate role
    let _role = Role::from_str(&role)
        .map_err(|_| format!("invalid role '{role}': use 'admin' or 'owner'"))?;

    let config = AppConfig::load(config_path)?;

    let public_url = config
        .public_url
        .as_ref()
        .ok_or("public_url must be set in config to generate enrollment links")?;

    let st = store::Store::open(&config.store)?;
    let sessions_ks = st.keyspace("sessions")?;

    let token = uuid::Uuid::new_v4().to_string();
    let now = now_epoch();
    let enrollment = Enrollment {
        token: token.clone(),
        did: did.clone(),
        role: role.clone(),
        created_at: now,
        expires_at: now + config.auth.passkey_enrollment_ttl,
    };

    store_enrollment(&sessions_ks, &enrollment).await?;

    let url = format!("{public_url}/enroll?token={token}");
    eprintln!();
    eprintln!("  Enrollment link created!");
    eprintln!();
    eprintln!("  DID:     {did}");
    eprintln!("  Role:    {role}");
    eprintln!("  Expires: {} seconds", config.auth.passkey_enrollment_ttl);
    eprintln!();
    eprintln!("  URL: {url}");
    eprintln!();

    Ok(())
}

async fn run_server(config_path: Option<PathBuf>) {
    let config = match AppConfig::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Create a config.toml or specify one:");
            eprintln!("  webvh-server --config <path>");
            eprintln!();
            eprintln!("Or run the setup wizard:");
            eprintln!("  webvh-server setup");
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

use affinidi_webvh_common::server::cli;
use affinidi_webvh_control::config::AppConfig;
use affinidi_webvh_control::{health, secret_store, server, setup, store};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "webvh-control",
    about = "WebVH Control Plane — Unified Management",
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
    /// Run interactive setup wizard to generate config.toml
    Setup,
    /// Run health check diagnostics
    Health,
    /// Add an ACL entry
    AddAcl {
        /// DID to add to the ACL
        #[arg(long)]
        did: String,
        /// Role (admin or owner)
        #[arg(long, default_value = "owner")]
        role: String,
        /// Optional label
        #[arg(long)]
        label: Option<String>,
    },
    /// List all ACL entries
    ListAcl,
    /// Remove an ACL entry
    RemoveAcl {
        /// DID to remove from the ACL
        #[arg(long)]
        did: String,
    },
    /// Create a passkey enrollment invite
    Invite {
        /// DID to invite
        #[arg(long)]
        did: String,
        /// Role (admin or owner)
        #[arg(long, default_value = "owner")]
        role: String,
        /// Override enrollment TTL (in hours)
        #[arg(long)]
        ttl_hours: Option<u64>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Some(Command::Setup) => {
            if let Err(e) = setup::run_setup().await {
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
        Some(Command::AddAcl { did, role, label }) => {
            if let Err(e) = run_add_acl(cli.config, did, role, label).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::ListAcl) => {
            if let Err(e) = run_list_acl(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::RemoveAcl { did }) => {
            if let Err(e) = run_remove_acl(cli.config, did).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Invite {
            did,
            role,
            ttl_hours,
        }) => {
            if let Err(e) = run_invite(cli.config, did, role, ttl_hours).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        None => run_control(cli.config).await,
    }
}

async fn run_control(config_path: Option<PathBuf>) {
    let config = match AppConfig::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Create a config.toml or specify one:");
            eprintln!("  webvh-control --config <path>");
            eprintln!("  webvh-control setup");
            std::process::exit(1);
        }
    };

    affinidi_webvh_common::server::config::init_tracing(&config.log);

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
            eprintln!("Error: no secrets found — run `webvh-control setup` first");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error loading secrets: {e}");
            std::process::exit(1);
        }
    };

    let store = store::Store::open(&config.store)
        .await
        .expect("failed to open store");

    if let Err(e) = server::run(config, store, secrets).await {
        tracing::error!("control plane error: {e}");
        std::process::exit(1);
    }
}

async fn run_add_acl(
    config_path: Option<PathBuf>,
    did: String,
    role_str: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    cli::add_acl(&config.store, &did, &role_str, label.as_deref(), None, None).await
}

async fn run_list_acl(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    cli::list_acl(&config.store).await
}

async fn run_remove_acl(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    cli::remove_acl(&config.store, &did).await
}

async fn run_invite(
    config_path: Option<PathBuf>,
    did: String,
    role: String,
    ttl_hours: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;

    let base_url = config
        .public_url
        .as_deref()
        .ok_or("public_url must be set in config for enrollment invites")?;

    let enrollment_ttl = match ttl_hours {
        Some(hours) => hours * 3600,
        None => config.auth.passkey_enrollment_ttl,
    };

    cli::invite(&config.store, base_url, enrollment_ttl, &did, &role).await
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
{dim}  WebVH Control Plane v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

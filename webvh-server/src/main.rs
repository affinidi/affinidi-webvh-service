mod acl;
mod auth;
mod backup;
mod config;
mod did_ops;
mod error;
#[cfg(feature = "ui")]
mod frontend;
mod messaging;
mod mnemonic;
mod passkey;
mod routes;
mod secret_store;
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
    /// Add an access control entry
    AddAcl {
        /// DID to grant access to
        #[arg(long)]
        did: String,
        /// Role: admin or owner
        #[arg(long, default_value = "owner")]
        role: String,
        /// Per-account max total DID document size in bytes (overrides global default)
        #[arg(long)]
        max_total_size: Option<u64>,
        /// Per-account max number of DIDs (overrides global default)
        #[arg(long)]
        max_did_count: Option<u64>,
    },
    /// List all access control entries
    ListAcl,
    /// Export server data to a backup file
    Backup {
        /// Output file path (use "-" for stdout)
        #[arg(short, long, default_value = "webvh-backup.json")]
        output: String,
    },
    /// Restore server data from a backup file
    Restore {
        /// Input backup file path
        #[arg(short, long)]
        input: String,
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
        Some(Command::AddAcl {
            did,
            role,
            max_total_size,
            max_did_count,
        }) => {
            if let Err(e) = run_add_acl(cli.config, did, role, max_total_size, max_did_count).await
            {
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
        Some(Command::Backup { output }) => {
            if let Err(e) = backup::run_backup(cli.config, output).await {
                eprintln!("Backup error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Restore { input }) => {
            if let Err(e) = backup::run_restore(cli.config, input).await {
                eprintln!("Restore error: {e}");
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

    let st = store::Store::open(&config.store).await?;
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

    #[cfg(not(feature = "ui"))]
    {
        eprintln!("  WARNING: The server was compiled without the 'ui' feature.");
        eprintln!("  The enrollment URL will not work unless the UI is enabled.");
        eprintln!("  Rebuild with: cargo build --features ui");
        eprintln!();
    }

    Ok(())
}

async fn run_add_acl(
    config_path: Option<PathBuf>,
    did: String,
    role: String,
    max_total_size: Option<u64>,
    max_did_count: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
    use crate::auth::session::now_epoch;

    let role_parsed = Role::from_str(&role)
        .map_err(|_| format!("invalid role '{role}': use 'admin' or 'owner'"))?;

    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let acl_ks = store.keyspace("acl")?;

    // Check if the entry already exists
    if let Some(existing) = get_acl_entry(&acl_ks, &did).await? {
        eprintln!();
        eprintln!("  ACL entry already exists for this DID:");
        eprintln!("  DID:  {}", existing.did);
        eprintln!("  Role: {}", existing.role);
        eprintln!();
        return Err("ACL entry already exists — delete it first to change the role".into());
    }

    let entry = AclEntry {
        did: did.clone(),
        role: role_parsed.clone(),
        label: None,
        created_at: now_epoch(),
        max_total_size,
        max_did_count,
    };

    store_acl_entry(&acl_ks, &entry).await?;

    eprintln!();
    eprintln!("  ACL entry created!");
    eprintln!();
    eprintln!("  DID:  {did}");
    eprintln!("  Role: {role_parsed}");
    if let Some(size) = max_total_size {
        eprintln!("  Max total size: {size} bytes");
    }
    if let Some(count) = max_did_count {
        eprintln!("  Max DID count:  {count}");
    }
    eprintln!();

    Ok(())
}

async fn run_list_acl(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::acl::{list_acl_entries};

    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let acl_ks = store.keyspace("acl")?;

    let entries = list_acl_entries(&acl_ks).await?;

    if entries.is_empty() {
        eprintln!();
        eprintln!("  No ACL entries found.");
        eprintln!();
        return Ok(());
    }

    eprintln!();
    eprintln!(
        "  {:<50} {:<8} {:<15} {:<15} {}",
        "DID", "ROLE", "MAX SIZE", "MAX DIDS", "LABEL"
    );
    eprintln!("  {}", "-".repeat(100));

    for entry in &entries {
        let max_size = entry
            .max_total_size
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into());
        let max_dids = entry
            .max_did_count
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".into());
        let label = entry.label.as_deref().unwrap_or("-");
        eprintln!(
            "  {:<50} {:<8} {:<15} {:<15} {}",
            entry.did, entry.role, max_size, max_dids, label
        );
    }

    eprintln!();
    eprintln!("  {} entries total", entries.len());
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

    // Load secrets from the configured backend
    let secret_store = match secret_store::create_secret_store(&config) {
        Ok(s) => s,
        Err(e) => {
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
            eprintln!("Error: no secrets found — run `webvh-server setup` first");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error loading secrets: {e}");
            std::process::exit(1);
        }
    };

    if config.secrets.plaintext.is_some() {
        tracing::warn!("============================================================");
        tracing::warn!("  PLAINTEXT SECRETS MODE - INSECURE");
        tracing::warn!("  Server secrets are stored as plaintext in the config file.");
        tracing::warn!("  DO NOT use this in production.");
        tracing::warn!("  For production, recompile with a secure backend:");
        tracing::warn!("    keyring, aws-secrets, or gcp-secrets");
        tracing::warn!("============================================================");
    }

    let store = store::Store::open(&config.store)
        .await
        .expect("failed to open store");

    if let Err(e) = server::run(config, store, secrets).await {
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

use affinidi_webvh_witness::config::AppConfig;
use affinidi_webvh_witness::{health, secret_store, server, setup, store, witness_ops};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "webvh-witness", about = "WebVH Witness Node", version)]
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
    /// Add an access control entry
    AddAcl {
        /// DID to grant access to
        #[arg(long)]
        did: String,
        /// Role: admin or owner
        #[arg(long, default_value = "owner")]
        role: String,
    },
    /// List all access control entries
    ListAcl,
    /// Remove an access control entry
    RemoveAcl {
        /// DID to remove from the ACL
        #[arg(long)]
        did: String,
    },
    /// Create a new witness identity
    CreateWitness {
        /// Optional label for the witness
        #[arg(long)]
        label: Option<String>,
    },
    /// List all witness identities
    ListWitnesses,
    /// Delete a witness identity
    DeleteWitness {
        /// Witness ID (multibase public key)
        #[arg(long)]
        id: String,
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
        Some(Command::Health) => {
            if let Err(e) = health::run_health(cli.config).await {
                eprintln!("Health check error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::AddAcl { did, role }) => {
            if let Err(e) = run_add_acl(cli.config, did, role).await {
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
        Some(Command::CreateWitness { label }) => {
            if let Err(e) = run_create_witness(cli.config, label).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::ListWitnesses) => {
            if let Err(e) = run_list_witnesses(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::DeleteWitness { id }) => {
            if let Err(e) = run_delete_witness(cli.config, id).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        None => run_server(cli.config).await,
    }
}

async fn run_add_acl(
    config_path: Option<PathBuf>,
    did: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_witness::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
    use affinidi_webvh_witness::auth::session::now_epoch;

    let role_parsed = Role::from_str(&role)
        .map_err(|_| format!("invalid role '{role}': use 'admin' or 'owner'"))?;

    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let acl_ks = store.keyspace("acl")?;

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
        max_total_size: None,
        max_did_count: None,
    };

    store_acl_entry(&acl_ks, &entry).await?;

    eprintln!();
    eprintln!("  ACL entry created!");
    eprintln!();
    eprintln!("  DID:  {did}");
    eprintln!("  Role: {role_parsed}");
    eprintln!();

    Ok(())
}

async fn run_list_acl(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_witness::acl::list_acl_entries;

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
    eprintln!("  {:<50} {:<8} {}", "DID", "ROLE", "LABEL");
    eprintln!("  {}", "-".repeat(80));

    for entry in &entries {
        let label = entry.label.as_deref().unwrap_or("-");
        eprintln!("  {:<50} {:<8} {}", entry.did, entry.role, label);
    }

    eprintln!();
    eprintln!("  {} entries total", entries.len());
    eprintln!();

    Ok(())
}

async fn run_remove_acl(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_witness::acl::{delete_acl_entry, get_acl_entry};

    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let acl_ks = store.keyspace("acl")?;

    let existing = get_acl_entry(&acl_ks, &did).await?;
    if existing.is_none() {
        eprintln!();
        eprintln!("  No ACL entry found for {did}");
        eprintln!();
        return Ok(());
    }

    let entry = existing.unwrap();
    delete_acl_entry(&acl_ks, &did).await?;
    store.persist().await?;

    eprintln!();
    eprintln!("  ACL entry removed!");
    eprintln!();
    eprintln!("  DID:  {}", entry.did);
    eprintln!("  Role: {}", entry.role);
    eprintln!();

    Ok(())
}

async fn run_create_witness(
    config_path: Option<PathBuf>,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let witnesses_ks = store.keyspace("witnesses")?;

    let record = witness_ops::create_witness(&witnesses_ks, label).await?;

    eprintln!();
    eprintln!("  Witness created!");
    eprintln!();
    eprintln!("  Witness ID : {}", record.witness_id);
    eprintln!("  DID        : {}", record.did);
    if let Some(ref label) = record.label {
        eprintln!("  Label      : {label}");
    }
    eprintln!();

    Ok(())
}

async fn run_list_witnesses(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let witnesses_ks = store.keyspace("witnesses")?;

    let records = witness_ops::list_witnesses(&witnesses_ks).await?;

    if records.is_empty() {
        eprintln!();
        eprintln!("  No witnesses found.");
        eprintln!();
        return Ok(());
    }

    eprintln!();
    eprintln!(
        "  {:<50} {:<50} {:<10} {}",
        "WITNESS ID", "DID", "PROOFS", "LABEL"
    );
    eprintln!("  {}", "-".repeat(120));

    for record in &records {
        let label = record.label.as_deref().unwrap_or("-");
        eprintln!(
            "  {:<50} {:<50} {:<10} {}",
            record.witness_id, record.did, record.proofs_signed, label
        );
    }

    eprintln!();
    eprintln!("  {} witnesses total", records.len());
    eprintln!();

    Ok(())
}

async fn run_delete_witness(
    config_path: Option<PathBuf>,
    witness_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let witnesses_ks = store.keyspace("witnesses")?;

    // Check if witness exists
    if witness_ops::get_witness(&witnesses_ks, &witness_id)
        .await?
        .is_none()
    {
        return Err(format!("witness not found: {witness_id}").into());
    }

    witness_ops::delete_witness(&witnesses_ks, &witness_id).await?;

    eprintln!();
    eprintln!("  Witness deleted: {witness_id}");
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
            eprintln!("  webvh-witness --config <path>");
            eprintln!();
            eprintln!("Or run the setup wizard:");
            eprintln!("  webvh-witness setup");
            std::process::exit(1);
        }
    };

    affinidi_webvh_common::server::config::init_tracing(&config.log);

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
            eprintln!("Error: no secrets found — run `webvh-witness setup` first");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error loading secrets: {e}");
            std::process::exit(1);
        }
    };

    if secret_store::is_plaintext_backend(&config.secrets) {
        tracing::warn!("============================================================");
        tracing::warn!("  PLAINTEXT SECRETS MODE - INSECURE");
        tracing::warn!("  Server secrets are stored as plaintext in the config file.");
        tracing::warn!("  DO NOT use this in production.");
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
{cyan}██╗    ██╗{magenta}██╗{yellow}████████╗{cyan}███╗   ██╗{magenta}███████╗{yellow}███████╗{yellow}███████╗{reset}
{cyan}██║    ██║{magenta}██║{yellow}╚══██╔══╝{cyan}████╗  ██║{magenta}██╔════╝{yellow}██╔════╝{yellow}██╔════╝{reset}
{cyan}██║ █╗ ██║{magenta}██║{yellow}   ██║   {cyan}██╔██╗ ██║{magenta}█████╗  {yellow}███████╗{yellow}███████╗{reset}
{cyan}██║███╗██║{magenta}██║{yellow}   ██║   {cyan}██║╚██╗██║{magenta}██╔══╝  {yellow}╚════██║{yellow}╚════██║{reset}
{cyan}╚███╔███╔╝{magenta}██║{yellow}   ██║   {cyan}██║ ╚████║{magenta}███████╗{yellow}███████║{yellow}███████║{reset}
{cyan} ╚══╝╚══╝ {magenta}╚═╝{yellow}   ╚═╝   {cyan}╚═╝  ╚═══╝{magenta}╚══════╝{yellow}╚══════╝{yellow}╚══════╝{reset}
{dim}  WebVH Witness v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

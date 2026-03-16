use clap::{Parser, Subcommand};
use affinidi_webvh_server::config::{AppConfig, LogFormat};
use affinidi_webvh_server::{backup, bootstrap, health, secret_store, server, setup, store};
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
        /// Per-account max total DID document size in bytes (overrides global default)
        #[arg(long)]
        max_total_size: Option<u64>,
        /// Per-account max number of DIDs (overrides global default)
        #[arg(long)]
        max_did_count: Option<u64>,
    },
    /// List all access control entries
    ListAcl,
    /// Remove an access control entry
    RemoveAcl {
        /// DID to remove from the ACL
        #[arg(long)]
        did: String,
    },
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
    /// Load a DID at an arbitrary path (e.g., "services/control")
    LoadDid {
        /// Path to store the DID at (e.g., "services/control")
        #[arg(long)]
        path: String,
        /// Path to the did.jsonl file
        #[arg(long)]
        did_log: PathBuf,
        /// Optional did-witness.json file
        #[arg(long)]
        did_witness: Option<PathBuf>,
    },
    /// Bootstrap a DID for this server (defaults to root .well-known)
    BootstrapDid {
        /// DID path/mnemonic to bootstrap (e.g. "my-org", "services/auth")
        /// Defaults to ".well-known" (the root DID for this server)
        #[arg(long, default_value = ".well-known")]
        path: String,
        /// Path to an existing did.jsonl file to import
        #[arg(long)]
        did_log: Option<PathBuf>,
        /// Path to an existing did-witness.json file to import (requires --did-log)
        #[arg(long)]
        did_witness: Option<PathBuf>,
        /// Witness service URL for requesting a proof (auto-bootstrap only)
        #[arg(long)]
        witness_url: Option<String>,
        /// Witness ID to use when requesting a proof (auto-bootstrap only)
        #[arg(long)]
        witness_id: Option<String>,
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
        Some(Command::RemoveAcl { did }) => {
            if let Err(e) = run_remove_acl(cli.config, did).await {
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
        Some(Command::LoadDid {
            path,
            did_log,
            did_witness,
        }) => {
            if let Err(e) = run_load_did(cli.config, path, did_log, did_witness).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::BootstrapDid {
            path,
            did_log,
            did_witness,
            witness_url,
            witness_id,
        }) => {
            if let Err(e) =
                run_bootstrap_did(cli.config, path, did_log, did_witness, witness_url, witness_id)
                    .await
            {
                eprintln!("Bootstrap error: {e}");
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
    max_total_size: Option<u64>,
    max_did_count: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_server::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
    use affinidi_webvh_server::auth::session::now_epoch;

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
    use affinidi_webvh_server::acl::list_acl_entries;

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

async fn run_remove_acl(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_server::acl::{delete_acl_entry, get_acl_entry};

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

async fn run_load_did(
    config_path: Option<PathBuf>,
    path: String,
    did_log: PathBuf,
    did_witness: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let dids_ks = store.keyspace("dids")?;

    let jsonl = std::fs::read_to_string(&did_log)
        .map_err(|e| format!("failed to read {}: {e}", did_log.display()))?;

    let witness_content = match &did_witness {
        Some(wp) => Some(
            std::fs::read_to_string(wp)
                .map_err(|e| format!("failed to read {}: {e}", wp.display()))?,
        ),
        None => None,
    };

    let result = bootstrap::import_did_at_path(
        &store,
        &dids_ks,
        &path,
        &jsonl,
        witness_content.as_deref(),
    )
    .await?;

    store.persist().await?;

    eprintln!();
    eprintln!("  DID loaded at path '{path}'!");
    eprintln!();
    eprintln!("  DID:  {}", result.did_id);
    eprintln!("  SCID: {}", result.scid);
    eprintln!("  Path: {path}/did.jsonl");
    eprintln!();

    Ok(())
}

async fn run_bootstrap_did(
    config_path: Option<PathBuf>,
    mnemonic: String,
    did_log: Option<PathBuf>,
    did_witness: Option<PathBuf>,
    witness_url: Option<String>,
    witness_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    if did_witness.is_some() && did_log.is_none() {
        return Err("--did-witness requires --did-log".into());
    }

    let config = AppConfig::load(config_path)?;

    let public_url = config
        .public_url
        .as_deref()
        .ok_or("public_url must be set in config for bootstrap")?;

    let store = store::Store::open(&config.store).await?;
    let dids_ks = store.keyspace("dids")?;

    // Check if DID already exists at this path
    let did_key = affinidi_webvh_server::did_ops::did_key(&mnemonic);
    if dids_ks.contains_key(did_key).await? {
        eprintln!();
        eprintln!("  DID at path '{mnemonic}' already exists.");
        eprintln!("  No action taken.");
        eprintln!();
        return Ok(());
    }

    let result = if let Some(log_path) = did_log {
        // Import from existing files
        let jsonl = std::fs::read_to_string(&log_path)
            .map_err(|e| format!("failed to read {}: {e}", log_path.display()))?;

        let witness_content = match &did_witness {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("failed to read {}: {e}", path.display()))?,
            ),
            None => None,
        };

        let result = bootstrap::import_did_at_path(
            &store,
            &dids_ks,
            &mnemonic,
            &jsonl,
            witness_content.as_deref(),
        )
        .await?;

        if did_witness.is_some() {
            eprintln!("  Witness data imported.");
        }

        result
    } else {
        // Auto-bootstrap: generate a new DID
        let secret_store = secret_store::create_secret_store(&config)?;
        let secrets = secret_store
            .get()
            .await?
            .ok_or("no secrets found — run `webvh-server setup` first")?;

        let signing_secret = Secret::from_multibase(&secrets.signing_key, None)
            .map_err(|e| format!("invalid signing_key: {e}"))?;

        let result =
            bootstrap::bootstrap_did(&store, &dids_ks, &signing_secret, public_url, &mnemonic)
                .await?;

        // Optional: request witness proof
        if let (Some(w_url), Some(w_id)) = (witness_url, witness_id) {
            use affinidi_webvh_common::WitnessClient;

            eprintln!("  Requesting witness proof...");
            eprintln!("  NOTE: the server must be running (on another process) for the");
            eprintln!("  witness to resolve the DID during authentication.");
            eprintln!();

            let mut witness_client = WitnessClient::new(&w_url);
            if let Err(e) = witness_client
                .authenticate(&result.did_id, &signing_secret)
                .await
            {
                eprintln!("  Warning: witness authentication failed: {e}");
                eprintln!("  The DID was created but has no witness proof.");
            } else {
                let version_id = result
                    .jsonl
                    .lines()
                    .last()
                    .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .and_then(|v| {
                        v.get("versionId")
                            .and_then(|id| id.as_str())
                            .map(String::from)
                    });

                if let Some(vid) = version_id {
                    match witness_client.request_proof(&w_id, &vid).await {
                        Ok(proof) => {
                            let proof_json = serde_json::to_string(&proof)?;
                            dids_ks
                                .insert_raw(
                                    affinidi_webvh_server::did_ops::content_witness_key(&mnemonic),
                                    proof_json.into_bytes(),
                                )
                                .await?;
                            eprintln!("  Witness proof stored.");
                        }
                        Err(e) => {
                            eprintln!("  Warning: witness proof request failed: {e}");
                        }
                    }
                } else {
                    eprintln!("  Warning: could not extract versionId for witness proof.");
                }
            }
        }

        result
    };

    store.persist().await?;

    let is_root = mnemonic == ".well-known";
    let url_path = if is_root {
        ".well-known/did.jsonl".to_string()
    } else {
        format!("{mnemonic}/did.jsonl")
    };

    eprintln!();
    if is_root {
        eprintln!("  Root DID bootstrapped!");
    } else {
        eprintln!("  DID bootstrapped at path '{mnemonic}'!");
    }
    eprintln!();
    eprintln!("  DID:   {}", result.did_id);
    eprintln!("  SCID:  {}", result.scid);
    eprintln!("  JSONL: {public_url}/{url_path}");
    eprintln!();
    if is_root && config.server_did.is_none() {
        eprintln!("  Hint: set server_did in your config.toml:");
        eprintln!("    server_did = \"{}\"", result.did_id);
        eprintln!();
    }

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

    if secret_store::is_plaintext_backend(&config.secrets) {
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

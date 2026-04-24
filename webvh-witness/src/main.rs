use affinidi_webvh_witness::config::AppConfig;
use affinidi_webvh_witness::{health, secret_store, server, setup, store, witness_ops};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    /// Write an offline VTA bootstrap request (for air-gapped VTAs).
    ///
    /// Generates an ephemeral Ed25519 keypair and writes a JSON request
    /// the operator ferries to the VTA admin. Keep the companion seed
    /// file safe — it's needed to open the sealed response.
    VtaRequest {
        /// Path for the bootstrap-request.json file.
        #[arg(long, default_value = "bootstrap-request.json")]
        out: PathBuf,
        /// Path for the ephemeral seed (keep this secret; chmod 0600 on Unix).
        #[arg(long, default_value = "bootstrap-seed.bin")]
        seed: PathBuf,
        /// Operator-visible label identifying this request.
        #[arg(long, default_value = "webvh-witness")]
        label: String,
    },
    /// Open a sealed VTA bootstrap response.
    ///
    /// Reads the armored bundle the operator ferried back, verifies the
    /// out-of-band digest, opens the HPKE sealed payload with the
    /// ephemeral seed, and emits the DID document + signed DID log for
    /// import via `webvh-server bootstrap-did` on the hosting server.
    VtaOpen {
        /// Path to the ASCII-armored sealed bundle.
        #[arg(long)]
        bundle: PathBuf,
        /// Expected SHA-256 digest of the armored ciphertext (from the
        /// operator, out-of-band).
        #[arg(long)]
        expect_digest: String,
        /// Path to the ephemeral seed saved by `vta-request`.
        #[arg(long, default_value = "bootstrap-seed.bin")]
        seed: PathBuf,
        /// Where to write the rendered DID document as JSON.
        #[arg(long, default_value = "witness-did.json")]
        did_doc_out: PathBuf,
        /// Where to write the signed DID log (JSONL). Omitted when the
        /// template didn't emit a WebvhLog output.
        #[arg(long, default_value = "witness-did.jsonl")]
        did_log_out: PathBuf,
        /// Where to save the minted private signing + KA key pair plus
        /// VTA trust material (authorization VC, pinned VTA DID) as JSON.
        /// Feed into `webvh-witness setup` to persist via the configured
        /// secret backend.
        #[arg(long, default_value = "witness-secrets.json")]
        secrets_out: PathBuf,
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
        Some(Command::VtaRequest { out, seed, label }) => {
            if let Err(e) = affinidi_webvh_common::server::vta_setup::run_offline_request_cli(
                &out,
                &seed,
                &label,
                "webvh-witness",
            ) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::VtaOpen {
            bundle,
            expect_digest,
            seed,
            did_doc_out,
            did_log_out,
            secrets_out,
        }) => {
            if let Err(e) = affinidi_webvh_common::server::vta_setup::run_offline_open_cli(
                &bundle,
                &expect_digest,
                &seed,
                &did_doc_out,
                &did_log_out,
                &secrets_out,
                affinidi_webvh_common::server::vta_setup::OfflineOpenNextStep::Setup {
                    binary: "webvh-witness",
                },
            ) {
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
    let config = AppConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_add_acl(&config.store, did, role, None, None, None)
        .await
}

async fn run_list_acl(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_list_acl(&config.store).await
}

async fn run_remove_acl(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_remove_acl(&config.store, did).await
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
        "  {:<50} {:<50} {:<10} LABEL",
        "WITNESS ID", "DID", "PROOFS"
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

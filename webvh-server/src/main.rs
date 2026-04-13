use affinidi_webvh_server::config::AppConfig;
use affinidi_webvh_server::{backup, bootstrap, health, secret_store, server, setup, store};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    /// Recreate a DID at a given path (deletes existing, creates new, updates config)
    RecreateDid {
        /// DID path/mnemonic to recreate (e.g. "webvh/server1")
        #[arg(long)]
        path: String,
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
    /// Recover a soft-deleted DID
    RecoverDid {
        /// DID path/mnemonic to recover (e.g. "webvh/server1")
        #[arg(long)]
        path: String,
    },
    /// Import secrets from a VTA secrets bundle or individual keys
    ImportSecrets {
        /// Base64url-encoded VTA secrets bundle (from `vta create-did-webvh`)
        #[arg(long, group = "source")]
        vta_bundle: Option<String>,
        /// Ed25519 signing key (multibase-encoded)
        #[arg(long, group = "source")]
        signing_key: Option<String>,
        /// X25519 key agreement key (multibase-encoded, required with --signing-key)
        #[arg(long)]
        ka_key: Option<String>,
        /// Ed25519 JWT signing key (multibase-encoded, auto-generated if omitted)
        #[arg(long)]
        jwt_key: Option<String>,
        /// VTA credential bundle (base64url-encoded, optional)
        #[arg(long)]
        vta_credential: Option<String>,
        /// Overwrite existing secrets without prompting
        #[arg(long)]
        force: bool,
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
        Some(Command::RecreateDid { path }) => {
            if let Err(e) = run_recreate_did(cli.config, path).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::RecoverDid { path }) => {
            if let Err(e) = run_recover_did(cli.config, path).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::ImportSecrets {
            vta_bundle,
            signing_key,
            ka_key,
            jwt_key,
            vta_credential,
            force,
        }) => {
            if let Err(e) = run_import_secrets(
                cli.config,
                vta_bundle,
                signing_key,
                ka_key,
                jwt_key,
                vta_credential,
                force,
            )
            .await
            {
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
            if let Err(e) = run_bootstrap_did(
                cli.config,
                path,
                did_log,
                did_witness,
                witness_url,
                witness_id,
            )
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
    let config = AppConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_add_acl(
        &config.store,
        did,
        role,
        None,
        max_total_size,
        max_did_count,
    )
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

    let result =
        bootstrap::import_did_at_path(&store, &dids_ks, &path, &jsonl, witness_content.as_deref())
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

async fn run_recover_did(
    config_path: Option<PathBuf>,
    mnemonic: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::did_ops::DidRecord;

    let config = AppConfig::load(config_path)?;
    let store_instance = store::Store::open(&config.store).await?;
    let dids_ks = store_instance.keyspace("dids")?;

    let did_key = format!("did:{mnemonic}");
    let mut record: DidRecord = dids_ks
        .get(did_key.as_str())
        .await?
        .ok_or(format!("DID not found at path '{mnemonic}'"))?;

    if record.deleted_at.is_none() {
        eprintln!("  DID at path '{mnemonic}' is not deleted.");
        return Ok(());
    }

    record.deleted_at = None;
    dids_ks.insert(did_key.as_str(), &record).await?;
    store_instance.persist().await?;

    eprintln!();
    eprintln!("  DID recovered at path '{mnemonic}'!");
    if let Some(ref did_id) = record.did_id {
        eprintln!("  DID: {did_id}");
    }
    eprintln!();

    Ok(())
}

async fn run_recreate_did(
    config_path: Option<PathBuf>,
    mnemonic: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let config = AppConfig::load(config_path)?;
    let config_file = config.config_path.clone();

    let public_url = config
        .public_url
        .as_deref()
        .ok_or("public_url must be set in config")?;

    let store = store::Store::open(&config.store).await?;
    let dids_ks = store.keyspace("dids")?;

    // Delete existing DID at this path if it exists
    let did_key = affinidi_webvh_server::did_ops::did_key(&mnemonic);
    if dids_ks.contains_key(did_key.clone()).await? {
        // Remove the DID record and its content
        dids_ks.remove(did_key).await?;
        dids_ks
            .remove(affinidi_webvh_server::did_ops::content_log_key(&mnemonic))
            .await?;
        dids_ks
            .remove(affinidi_webvh_server::did_ops::content_witness_key(
                &mnemonic,
            ))
            .await?;
        // Remove owner index entry (owner is "system" for bootstrapped DIDs)
        dids_ks
            .remove(affinidi_webvh_server::did_ops::owner_key(
                "system", &mnemonic,
            ))
            .await?;
        eprintln!("  Removed existing DID at path '{mnemonic}'");
    }

    // Create new DID
    let secret_store = secret_store::create_secret_store(&config)?;
    let secrets = secret_store
        .get()
        .await?
        .ok_or("no secrets found — run `webvh-server setup` first")?;

    let signing_secret = Secret::from_multibase(&secrets.signing_key, None)
        .map_err(|e| format!("invalid signing_key: {e}"))?;
    let ka_secret = Secret::from_multibase(&secrets.key_agreement_key, None).ok();

    // Discover mediator from VTA DID for the DIDCommMessaging service
    let mediator_uri = if let Some(ref vta_did) = config.mediator_did {
        use affinidi_webvh_common::server::didcomm_profile::resolve_mediator_did;
        resolve_mediator_did(vta_did, None).await
    } else {
        None
    };

    let result = bootstrap::bootstrap_did(
        &store,
        &dids_ks,
        &signing_secret,
        ka_secret.as_ref(),
        mediator_uri.as_deref(),
        public_url,
        &mnemonic,
    )
    .await?;

    store.persist().await?;

    // Update server_did in config file
    setup::update_server_did_in_config(&config_file, &result.did_id)?;

    let url_path = if mnemonic == ".well-known" {
        ".well-known/did.jsonl".to_string()
    } else {
        format!("{mnemonic}/did.jsonl")
    };

    eprintln!();
    eprintln!("  DID recreated at path '{mnemonic}'!");
    eprintln!();
    eprintln!("  DID:   {}", result.did_id);
    eprintln!("  SCID:  {}", result.scid);
    eprintln!("  JSONL: {public_url}/{url_path}");
    eprintln!();
    eprintln!("  config.toml updated with new server_did.");
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
        let ka_secret = Secret::from_multibase(&secrets.key_agreement_key, None).ok();

        // Discover mediator from VTA DID for the DIDCommMessaging service
        let mediator_uri = if let Some(ref vta_did) = config.mediator_did {
            use affinidi_webvh_common::server::didcomm_profile::resolve_mediator_did;
            resolve_mediator_did(vta_did, None).await
        } else {
            None
        };

        let result = bootstrap::bootstrap_did(
            &store,
            &dids_ks,
            &signing_secret,
            ka_secret.as_ref(),
            mediator_uri.as_deref(),
            public_url,
            &mnemonic,
        )
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

async fn run_import_secrets(
    config_path: Option<PathBuf>,
    vta_bundle: Option<String>,
    signing_key: Option<String>,
    ka_key: Option<String>,
    jwt_key: Option<String>,
    vta_credential: Option<String>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use affinidi_webvh_common::server::vta_setup::generate_ed25519_multibase;
    use vta_sdk::did_secrets::DidSecretsBundle;
    use vta_sdk::keys::KeyType;

    let config = AppConfig::load(config_path)?;
    let secret_store = secret_store::create_secret_store(&config)?;

    // Check for existing secrets
    if !force && let Ok(Some(_)) = secret_store.get().await {
        return Err("secrets already exist — use --force to overwrite".into());
    }

    let (resolved_signing, resolved_ka, resolved_vta_cred) =
        if let Some(ref bundle_str) = vta_bundle {
            // Decode VTA secrets bundle
            let bundle = DidSecretsBundle::decode(bundle_str)
                .map_err(|e| format!("failed to decode VTA secrets bundle: {e}"))?;

            let mut signing = None;
            let mut ka = None;

            for entry in &bundle.secrets {
                match entry.key_type {
                    KeyType::Ed25519 => {
                        if signing.is_none() {
                            signing = Some(entry.private_key_multibase.clone());
                        }
                    }
                    KeyType::X25519 => {
                        if ka.is_none() {
                            ka = Some(entry.private_key_multibase.clone());
                        }
                    }
                    _ => {}
                }
            }

            let signing = signing.ok_or("VTA bundle contains no Ed25519 signing key")?;
            let ka = ka.ok_or("VTA bundle contains no X25519 key agreement key")?;

            eprintln!("  VTA bundle decoded for DID: {}", bundle.did);
            eprintln!("  Found {} secret(s)", bundle.secrets.len());

            (signing, ka, vta_credential)
        } else if let Some(signing) = signing_key {
            let ka = ka_key.ok_or("--ka-key is required when using --signing-key")?;
            (signing, ka, vta_credential)
        } else {
            return Err("provide either --vta-bundle or --signing-key + --ka-key".into());
        };

    // Validate keys by attempting to parse them
    Secret::from_multibase(&resolved_signing, None)
        .map_err(|e| format!("invalid signing key: {e}"))?;
    Secret::from_multibase(&resolved_ka, None)
        .map_err(|e| format!("invalid key agreement key: {e}"))?;

    // Generate or validate JWT key
    let resolved_jwt = match jwt_key {
        Some(key) => {
            Secret::from_multibase(&key, None)
                .map_err(|e| format!("invalid JWT signing key: {e}"))?;
            key
        }
        None => {
            eprintln!("  Generated JWT signing key.");
            generate_ed25519_multibase()
        }
    };

    let server_secrets = secret_store::ServerSecrets {
        signing_key: resolved_signing,
        key_agreement_key: resolved_ka,
        jwt_signing_key: resolved_jwt,
        vta_credential: resolved_vta_cred,
    };

    secret_store.set(&server_secrets).await?;

    eprintln!();
    eprintln!("  Secrets imported successfully!");
    eprintln!();
    if secret_store::is_plaintext_backend(&config.secrets) {
        eprintln!("  WARNING: secrets stored in plaintext — not for production use.");
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

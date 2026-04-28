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
    /// Run interactive setup wizard to generate config.toml.
    ///
    /// Headless mode (for CI / scripted setup):
    ///
    /// 1. Run with `--setup-key-out <path> --context <id>` to mint an
    ///    ephemeral did:key, persist it (chmod 0600), and print the
    ///    `pnm contexts create` command. Exits without further prompts.
    /// 2. Run again with `--setup-key-file <path>` to drive the rest of
    ///    the wizard reusing the persisted setup DID.
    Setup {
        /// Phase 1: mint an ephemeral did:key, persist to <path>, and
        /// print the `pnm contexts create` command + exit.
        #[arg(long, conflicts_with = "setup_key_file")]
        setup_key_out: Option<PathBuf>,
        /// Phase 2: reuse the setup DID persisted at <path>; skip the
        /// interactive "Has the context been created?" confirmation.
        #[arg(long, conflicts_with = "setup_key_out")]
        setup_key_file: Option<PathBuf>,
        /// Context id for phase 1's PNM command. Defaults to `webvh`.
        #[arg(long, default_value = "webvh", requires = "setup_key_out")]
        context: String,
    },
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
    /// Dump the DID log (did.jsonl) for a given path
    DumpDid {
        /// DID path/mnemonic to dump (e.g. ".well-known", "my-org")
        #[arg(long)]
        path: String,
        /// Also dump the witness proof (did-witness.json)
        #[arg(long)]
        witness: bool,
    },
    /// List all DIDs in the store
    ListDids,
    /// Remove a DID and all its data from the store
    RemoveDid {
        /// DID path/mnemonic to remove (e.g. "glenn", ".well-known")
        #[arg(long)]
        path: String,
    },
    /// Export this server's DID + signing/KA keys as an HPKE-sealed
    /// migration bundle.
    ///
    /// Reads the receiver's `bootstrap-request.json` (same shape that
    /// `vta-request` or `setup-offline-prepare` produces), loads the
    /// existing server identity from the configured secret store,
    /// wraps the keys as a `DidSecrets` payload, and seals to the
    /// receiver's ephemeral X25519 pubkey. Prints a SHA-256 digest
    /// that the receiver MUST verify out-of-band before opening —
    /// the current `PinnedOnly` producer assertion has no in-band
    /// integrity anchor.
    ExportSealed {
        /// Path to the receiver's bootstrap-request.json.
        #[arg(long)]
        request: PathBuf,
        /// Path for the ASCII-armored sealed output.
        #[arg(long, default_value = "sealed-export.txt")]
        out: PathBuf,
        /// Optional file to write the SHA-256 digest to. Always
        /// printed to stderr regardless.
        #[arg(long)]
        digest_out: Option<PathBuf>,
    },
    /// Open a sealed `DidSecrets` migration bundle and import the
    /// contained keys as this server's identity. Inverse of
    /// `export-sealed` on the sending side.
    ImportSealed {
        /// Path to the ASCII-armored sealed bundle.
        #[arg(long)]
        bundle: PathBuf,
        /// Expected SHA-256 digest of the armored ciphertext (from
        /// the operator, out-of-band).
        #[arg(long)]
        expect_digest: String,
        /// Path to the ephemeral seed the receiver saved when
        /// generating the bootstrap-request.json.
        #[arg(long, default_value = "bootstrap-seed.bin")]
        seed: PathBuf,
        /// Optional Ed25519 public key of the producer (multibase-
        /// encoded, matches `#key-0` in the producer's DID document).
        /// When supplied, the bundle's `DidSigned` assertion is
        /// verified against it; omit to fall back to PinnedOnly trust.
        #[arg(long)]
        producer_pubkey: Option<String>,
        /// Optional Ed25519 JWT signing key (multibase-encoded,
        /// auto-generated if omitted).
        #[arg(long)]
        jwt_key: Option<String>,
        /// Overwrite existing secrets without prompting.
        #[arg(long)]
        force: bool,
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
    /// Step 1/2 of the offline (air-gapped VTA) setup wizard.
    ///
    /// Runs the interactive prompts, writes the bootstrap-request.json +
    /// ephemeral seed, and serialises the operator's answers to a state
    /// TOML file. After the VTA admin returns a sealed bundle, run
    /// `setup-offline-complete`.
    SetupOfflinePrepare {
        /// Path for the bootstrap-request.json file.
        #[arg(long, default_value = "bootstrap-request.json")]
        request: PathBuf,
        /// Path for the pending state file (plain TOML, no secrets).
        ///
        /// The ephemeral bootstrap seed is persisted to the configured
        /// secrets backend (keyring / AWS / GCP / plaintext-in-config),
        /// not to a file.
        #[arg(long, default_value = "setup-offline-state.toml")]
        state: PathBuf,
    },
    /// Step 2/2 of the offline setup wizard.
    ///
    /// Opens the sealed bundle with the seed saved during step 1, then
    /// persists the DID + keys + config per the choices captured in the
    /// state file, and imports the server's own DID into the local store.
    SetupOfflineComplete {
        /// Path to the ASCII-armored sealed bundle from the VTA admin.
        #[arg(long)]
        bundle: PathBuf,
        /// Expected SHA-256 digest (lowercase hex) of the armored
        /// ciphertext; communicated out-of-band.
        #[arg(long)]
        expect_digest: String,
        /// Path to the state file written by `setup-offline-prepare`.
        #[arg(long, default_value = "setup-offline-state.toml")]
        state: PathBuf,
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
        #[arg(long, default_value = "webvh-server")]
        label: String,
        /// Public URL where this server serves DIDs. Bound to the
        /// `webvh-daemon` template's `URL` variable so the rendered DID
        /// exposes a `WebVHHosting` service at this URL. Runtime DIDComm
        /// (sync from the control plane) uses the daemon's separately
        /// configured mediator and is not embedded in this DID document.
        #[arg(long)]
        public_url: String,
        /// VTA context the integration will live in. Embedded as
        /// `contextHint` in the request so the VTA admin can run
        /// `vta bootstrap provision-integration` without `--context`.
        #[arg(long, default_value = "webvh")]
        context: String,
    },
    /// Open a sealed VTA bootstrap response.
    ///
    /// Reads the armored bundle the operator ferried back, verifies the
    /// out-of-band digest, opens the HPKE sealed payload with the
    /// ephemeral seed, and emits the DID document + signed DID log for
    /// import via `webvh-server bootstrap-did` / `import-secrets`.
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
        #[arg(long, default_value = "server-did.json")]
        did_doc_out: PathBuf,
        /// Where to write the signed DID log (JSONL). Omitted when the
        /// template didn't emit a WebvhLog output.
        #[arg(long, default_value = "server-did.jsonl")]
        did_log_out: PathBuf,
        /// Where to save the minted private signing + KA key pair plus
        /// VTA trust material (authorization VC, pinned VTA DID) as JSON.
        /// Feed the multibase keys into `webvh-server import-secrets`.
        #[arg(long, default_value = "server-secrets.json")]
        secrets_out: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Some(Command::Setup {
            setup_key_out,
            setup_key_file,
            context,
        }) => {
            if let Some(path) = setup_key_out {
                if let Err(e) = setup::run_setup_phase1(&path, &context).await {
                    eprintln!("Setup error: {e}");
                    std::process::exit(1);
                }
            } else if let Err(e) = setup::run_wizard(cli.config, setup_key_file).await {
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
        Some(Command::ExportSealed {
            request,
            out,
            digest_out,
        }) => {
            if let Err(e) = run_export_sealed(cli.config, request, out, digest_out).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::ImportSealed {
            bundle,
            expect_digest,
            seed,
            producer_pubkey,
            jwt_key,
            force,
        }) => {
            if let Err(e) = run_import_sealed(
                cli.config,
                bundle,
                expect_digest,
                seed,
                producer_pubkey,
                jwt_key,
                force,
            )
            .await
            {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::SetupOfflinePrepare { request, state }) => {
            if let Err(e) = setup::run_setup_offline_prepare(cli.config, request, state).await {
                eprintln!("Setup error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::SetupOfflineComplete {
            bundle,
            expect_digest,
            state,
        }) => {
            if let Err(e) = setup::run_setup_offline_complete(bundle, expect_digest, state).await {
                eprintln!("Setup error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::VtaRequest {
            out,
            seed,
            label,
            public_url,
            context,
        }) => {
            if let Err(e) = affinidi_webvh_common::server::vta_setup::run_offline_request_cli(
                &out,
                &seed,
                &label,
                "webvh-server",
                "webvh-daemon",
                &[("URL", public_url.as_str())],
                &context,
            )
            .await
            {
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
                affinidi_webvh_common::server::vta_setup::OfflineOpenNextStep::ImportSecrets {
                    binary: "webvh-server",
                },
            ) {
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
        Some(Command::DumpDid { path, witness }) => {
            if let Err(e) = run_dump_did(cli.config, path, witness).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::ListDids) => {
            if let Err(e) = run_list_dids(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::RemoveDid { path }) => {
            if let Err(e) = run_remove_did(cli.config, path).await {
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

async fn run_dump_did(
    config_path: Option<PathBuf>,
    mnemonic: String,
    witness: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::did_ops::{content_log_key, content_witness_key, did_key};

    let config = AppConfig::load(config_path)?;
    let store_handle = store::Store::open(&config.store).await?;
    let dids_ks = store_handle.keyspace("dids")?;

    // Verify the DID exists
    let _: affinidi_webvh_common::did_ops::DidRecord = dids_ks
        .get(did_key(&mnemonic))
        .await?
        .ok_or(format!("DID not found at path '{mnemonic}'"))?;

    // Dump did.jsonl to stdout
    let log_bytes = dids_ks
        .get_raw(content_log_key(&mnemonic))
        .await?
        .ok_or(format!("no log content for path '{mnemonic}'"))?;
    let log = String::from_utf8(log_bytes)
        .map_err(|_| format!("invalid UTF-8 in log content for '{mnemonic}'"))?;
    print!("{log}");

    // Optionally dump witness
    if witness {
        if let Some(witness_bytes) = dids_ks.get_raw(content_witness_key(&mnemonic)).await? {
            let witness_str = String::from_utf8(witness_bytes)
                .map_err(|_| format!("invalid UTF-8 in witness content for '{mnemonic}'"))?;
            eprintln!("--- did-witness.json ---");
            print!("{witness_str}");
        } else {
            eprintln!("(no witness content)");
        }
    }

    Ok(())
}

async fn run_list_dids(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::did_ops::DidRecord;

    let config = AppConfig::load(config_path)?;
    let store_handle = store::Store::open(&config.store).await?;
    let dids_ks = store_handle.keyspace("dids")?;

    let raw = dids_ks.prefix_iter_raw("did:").await?;

    if raw.is_empty() {
        eprintln!("  No DIDs in store.");
        return Ok(());
    }

    eprintln!("  {:<25} {:<15} {:<60}", "PATH", "VERSIONS", "DID ID");
    eprintln!("  {}", "-".repeat(100));

    for (_key, value) in &raw {
        if let Ok(record) = serde_json::from_slice::<DidRecord>(value) {
            let did_id = record.did_id.as_deref().unwrap_or("(unpublished)");
            let deleted = if record.deleted_at.is_some() {
                " [deleted]"
            } else {
                ""
            };
            let disabled = if record.disabled { " [disabled]" } else { "" };
            eprintln!(
                "  {:<25} {:<15} {}{}{}",
                record.mnemonic, record.version_count, did_id, deleted, disabled
            );
        }
    }

    eprintln!();
    eprintln!("  Total: {} DIDs", raw.len());

    Ok(())
}

async fn run_remove_did(
    config_path: Option<PathBuf>,
    path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::did_ops::{
        DidRecord, content_log_key, content_witness_key, did_key, owner_key,
    };

    let config = AppConfig::load(config_path)?;
    let store_handle = store::Store::open(&config.store).await?;
    let dids_ks = store_handle.keyspace("dids")?;

    let record: Option<DidRecord> = dids_ks.get(did_key(&path)).await?;
    let record = match record {
        Some(r) => r,
        None => {
            eprintln!("  DID not found at path '{path}'");
            std::process::exit(1);
        }
    };

    let did_id = record.did_id.as_deref().unwrap_or("(unpublished)");
    eprintln!("  Removing DID at path '{path}'");
    eprintln!("  DID ID: {did_id}");
    eprintln!("  Owner:  {}", record.owner);

    let mut batch = store_handle.batch();
    batch.remove(&dids_ks, did_key(&path));
    batch.remove(&dids_ks, content_log_key(&path));
    batch.remove(&dids_ks, content_witness_key(&path));
    batch.remove(&dids_ks, owner_key(&record.owner, &path));
    batch.commit().await?;

    eprintln!("  DID removed.");
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
            // vta-sdk 0.5 dropped DidSecretsBundle::decode — operators still
            // paste a base64url blob, so deserialize inline:
            // base64url → JSON → bundle.
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
            let bundle_json = BASE64
                .decode(bundle_str.as_bytes())
                .map_err(|e| format!("failed to decode VTA secrets bundle base64: {e}"))?;
            let bundle: DidSecretsBundle = serde_json::from_slice(&bundle_json)
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

async fn run_export_sealed(
    config_path: Option<PathBuf>,
    request: PathBuf,
    out: PathBuf,
    digest_out: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;

    let producer_did = config
        .server_did
        .clone()
        .ok_or("server_did not set in config — run setup first")?;

    // Load the existing signing + KA keys from the configured secret store.
    let secret_store = secret_store::create_secret_store(&config)?;
    let secrets = secret_store
        .get()
        .await?
        .ok_or("no secrets found — run setup or import-secrets first")?;

    let info = affinidi_webvh_common::server::vta_setup::export_sealed_did_secrets(
        &request,
        &out,
        &producer_did,
        &producer_did,
        secrets.signing_key.clone(),
        secrets.key_agreement_key.clone(),
        affinidi_webvh_common::server::vta_setup::ExportAssertionMode::DidSigned {
            signing_key_multibase: secrets.signing_key.clone(),
            verification_method: format!("{producer_did}#key-0"),
        },
    )
    .await?;

    if let Some(ref digest_path) = digest_out {
        if let Some(parent) = digest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(digest_path, format!("{}\n", info.digest))?;
    }

    eprintln!();
    eprintln!("  Sealed export ready.");
    eprintln!();
    eprintln!("  Out:            {}", info.out_path.display());
    eprintln!("  Recipient DID:  {}", info.recipient_did);
    eprintln!("  Bundle id:      {}", info.bundle_id_hex);
    eprintln!();
    eprintln!("  SHA-256 digest (send OOB to receiver):");
    eprintln!("    {}", info.digest);
    if let Some(ref p) = digest_out {
        eprintln!("  Digest also written to {}", p.display());
    }
    eprintln!();
    // Extract the Ed25519 public-key multibase so the operator can
    // share it with the receiver (for DidSigned verification).
    let producer_pub = affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
        &secrets.signing_key,
        None,
    )?
    .get_public_keymultibase()?;

    eprintln!("  Producer assertion mode: DidSigned. The bundle is signed by");
    eprintln!("  this server's `#key-0` Ed25519 key. Receivers who pin the");
    eprintln!("  producer pubkey via --producer-pubkey get cryptographic");
    eprintln!("  verification; without it the OOB digest stays the only anchor.");
    eprintln!();
    eprintln!("  Producer pubkey (share with receiver — matches #key-0):");
    eprintln!("    {producer_pub}");
    eprintln!();
    eprintln!("  Next steps on the receiver:");
    eprintln!(
        "    webvh-server import-sealed --bundle {} \\\n      --expect-digest {} \\\n      --producer-pubkey {producer_pub}",
        info.out_path.display(),
        info.digest
    );
    eprintln!();

    Ok(())
}

async fn run_import_sealed(
    config_path: Option<PathBuf>,
    bundle: PathBuf,
    expect_digest: String,
    seed: PathBuf,
    producer_pubkey: Option<String>,
    jwt_key: Option<String>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use affinidi_webvh_common::server::vta_setup::{
        generate_ed25519_multibase, open_sealed_did_secrets,
    };

    let config = AppConfig::load(config_path)?;
    let secret_store = secret_store::create_secret_store(&config)?;

    if !force && let Ok(Some(_)) = secret_store.get().await {
        return Err("secrets already exist — use --force to overwrite".into());
    }

    // Decode the optional producer pubkey (multibase-encoded Ed25519
    // public) for DidSigned verification. None falls back to
    // digest-only trust (accepts any assertion variant, unverified).
    let expected_pubkey_bytes = match producer_pubkey.as_deref() {
        Some(mb) => Some(decode_ed25519_pubkey_multibase(mb)?),
        None => None,
    };

    let armor =
        std::fs::read_to_string(&bundle).map_err(|e| format!("read {}: {e}", bundle.display()))?;
    let result = open_sealed_did_secrets(
        &armor,
        &expect_digest,
        &seed,
        expected_pubkey_bytes.as_ref(),
    )?;

    // Sanity-check the keys parse before writing anything.
    Secret::from_multibase(&result.signing_key_multibase, None)
        .map_err(|e| format!("invalid signing key in bundle: {e}"))?;
    Secret::from_multibase(&result.key_agreement_multibase, None)
        .map_err(|e| format!("invalid key-agreement key in bundle: {e}"))?;

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
        signing_key: result.signing_key_multibase,
        key_agreement_key: result.key_agreement_multibase,
        jwt_signing_key: resolved_jwt,
        vta_credential: None,
    };

    secret_store.set(&server_secrets).await?;

    eprintln!();
    eprintln!("  Sealed bundle opened and imported.");
    eprintln!();
    eprintln!("  DID:            {}", result.did);
    if result.assertion_verified {
        eprintln!(
            "  Producer DID:   {} (DidSigned — signature verified)",
            result.producer_did
        );
    } else {
        eprintln!(
            "  Producer DID:   {} (informational — no producer pubkey supplied)",
            result.producer_did
        );
    }
    eprintln!();
    eprintln!(
        "  Note: update server_did in config.toml to {} if not already set.",
        result.did
    );
    eprintln!();

    Ok(())
}

/// Decode a multibase-encoded Ed25519 public key into the raw 32-byte
/// array. Accepts both the bare-key form (32 bytes after multibase
/// decode) and the multicodec-prefixed form (34 bytes, leading
/// 0xED 0x01).
fn decode_ed25519_pubkey_multibase(mb: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let (_, raw) =
        multibase::decode(mb).map_err(|e| format!("invalid producer pubkey multibase: {e}"))?;
    let pk_bytes: &[u8] = if raw.len() == 34 && raw[0] == 0xed && raw[1] == 0x01 {
        &raw[2..]
    } else {
        &raw[..]
    };
    pk_bytes
        .try_into()
        .map_err(|_| "producer pubkey is not a 32-byte Ed25519 key".into())
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

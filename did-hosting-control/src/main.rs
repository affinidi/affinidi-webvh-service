use clap::{Parser, Subcommand};
use did_hosting_common::server::store::KS_SESSIONS;
use did_hosting_control::config::AppConfig;
use did_hosting_control::{health, secret_store, server, setup, setup_recipe, store};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "did-hosting-control",
    about = "DID Hosting Control Plane — Unified Management",
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
        /// Path to a declarative setup recipe TOML. Drives the wizard
        /// non-interactively. See `examples/did-hosting-control-build.toml`.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Refuse to run when an existing setup is detected, unless this
        /// flag is set. Exit 4 protects issued JWTs / active VTA sessions.
        #[arg(long)]
        force_reprovision: bool,
        /// Explicit "no TTY available" flag. Requires `--from`.
        #[arg(long, requires = "from")]
        non_interactive: bool,
    },
    /// Teardown a control plane install: clears managed secrets and
    /// removes the config file (+ `.bak`, + `control-did.jsonl`).
    Uninstall {
        /// Skip the typed "DELETE" confirmation prompt. CI use only.
        #[arg(long)]
        yes: bool,
    },
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
    /// List the service's own identity generations (key material still honoured).
    IdentityList,
    /// Rotate the service's own key-agreement key.
    ///
    /// Publishes a new DID log entry installing a fresh key-agreement key on a
    /// NEW verification-method fragment, and keeps the outgoing key honoured for
    /// the grace period so peers holding a cached DID document can still reach
    /// this service.
    ///
    /// The fresh fragment is not cosmetic: a kid identifies exactly one key, so
    /// reusing `#key-1` would make any grace period impossible.
    ///
    /// The service must be STOPPED (the store is exclusively locked).
    IdentityRotateKeys {
        /// X25519 key-agreement key to install (multibase). Generated if omitted.
        #[arg(long)]
        ka_key: Option<String>,
        /// How long to keep honouring the outgoing key ("1h", "30m", "0").
        /// Defaults to `[identity] rotation_grace_period`.
        #[arg(long)]
        grace: Option<String>,
    },
    /// Stop honouring a superseded identity generation immediately.
    ///
    /// The offline kill switch, for a compromised key. Messages still addressed
    /// to that generation's key-agreement key will no longer decrypt.
    ///
    /// The service must be stopped (the store is exclusively locked). For a
    /// LIVE service use the control plane's
    /// `POST /api/identity/generations/{id}/retire` or the UI button, which
    /// drops the key from the running process immediately.
    IdentityRetireNow {
        /// Generation id to retire (see `identity-list`).
        #[arg(long)]
        generation: u64,
    },
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
        #[arg(long, default_value = "did-hosting-control")]
        label: String,
        /// DID hosting URL. Bound to the `did-hosting-control` template's
        /// `URL` variable so the rendered DID exposes a `WebVHHosting`
        /// service at this URL.
        #[arg(long)]
        did_hosting_url: String,
        /// DIDComm mediator DID. Bound to the `did-hosting-control` template's
        /// `MEDIATOR_DID` variable so the rendered DID document advertises
        /// the right mediator endpoint.
        #[arg(long)]
        mediator_did: String,
        /// VTA context the integration will live in. Embedded as
        /// `contextHint` in the request so the VTA admin can run
        /// `vta bootstrap provision-integration` without `--context`.
        #[arg(long, default_value = "webvh")]
        context: String,
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
    /// persists the DID + keys + config + admin ACL per the choices
    /// captured in the state file.
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
    /// Export this control plane's DID + signing/KA keys as an
    /// HPKE-sealed migration bundle. See `did-hosting-server export-sealed`
    /// for full semantics; the receiver opens with `import-sealed`.
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
    /// contained keys as this control plane's identity. Inverse of
    /// `export-sealed` on the sending side.
    ImportSealed {
        /// Path to the ASCII-armored sealed bundle.
        #[arg(long)]
        bundle: PathBuf,
        /// Expected SHA-256 digest of the armored ciphertext.
        #[arg(long)]
        expect_digest: String,
        /// Path to the ephemeral seed the receiver saved when
        /// generating the bootstrap-request.json.
        #[arg(long, default_value = "bootstrap-seed.bin")]
        seed: PathBuf,
        /// Optional Ed25519 public key of the producer (multibase-
        /// encoded, matches `#key-0` in the producer's DID document).
        /// When supplied, the bundle's `DidSigned` assertion is
        /// verified against it; omit to fall back to digest-only trust.
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
    /// Open a sealed VTA bootstrap response (primitive — prefer
    /// `setup-offline-complete` for a full wizard-driven finish).
    ///
    /// Reads the armored bundle the operator ferried back, verifies the
    /// out-of-band digest, opens the HPKE sealed payload with the
    /// ephemeral seed, and emits the DID document + signed DID log for
    /// import via the did-hosting-server bootstrap-did / load-did commands.
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
        #[arg(long, default_value = "control-did.json")]
        did_doc_out: PathBuf,
        /// Where to write the signed DID log (JSONL). Omitted when the
        /// template didn't emit a WebvhLog output.
        #[arg(long, default_value = "control-did.jsonl")]
        did_log_out: PathBuf,
        /// Where to save the minted private signing + KA key pair plus
        /// VTA trust material (authorization VC, pinned VTA DID) as JSON.
        /// Feed into `did-hosting-control setup` to persist via the configured
        /// secret backend.
        #[arg(long, default_value = "control-secrets.json")]
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
            from,
            force_reprovision,
            non_interactive: _,
        }) => {
            if let Some(path) = setup_key_out {
                if let Err(e) = setup::run_setup_phase1(&path, &context).await {
                    eprintln!("Setup error: {e}");
                    std::process::exit(1);
                }
            } else if let Some(recipe_path) = from {
                match setup_recipe::run_from_recipe(&recipe_path, setup_key_file, force_reprovision)
                    .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("Setup error: {e}");
                        std::process::exit(setup_recipe::map_exit_code(&e));
                    }
                }
            } else if let Err(e) = setup::run_setup(setup_key_file).await {
                eprintln!("Setup error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Uninstall { yes }) => {
            let config_path = cli
                .config
                .clone()
                .unwrap_or_else(|| PathBuf::from("config.toml"));
            if let Err(e) = setup_recipe::run_uninstall(&config_path, yes).await {
                eprintln!("Uninstall error: {e}");
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
        Some(Command::IdentityRotateKeys { ka_key, grace }) => {
            if let Err(e) = run_identity_rotate_keys(cli.config, ka_key, grace).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::IdentityList) => {
            if let Err(e) = run_identity_list(cli.config).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::IdentityRetireNow { generation }) => {
            if let Err(e) = run_identity_retire_now(cli.config, generation).await {
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
        Some(Command::SetupOfflinePrepare { request, state }) => {
            if let Err(e) = setup::run_setup_offline_prepare(request, state).await {
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
        Some(Command::VtaRequest {
            out,
            seed,
            label,
            did_hosting_url,
            mediator_did,
            context,
        }) => {
            // `did_hosting_url` may already carry the DID path; split it back
            // out so the shared builder folds it identically to the wizard.
            let (origin, did_path) =
                did_hosting_common::server::setup_recipe::split_origin_and_did_path(
                    &did_hosting_url,
                );
            let shape = did_hosting_common::server::vta_setup::WebvhDidShape::Hosted {
                origin: &origin,
                did_path: &did_path,
                mediator_did: Some(mediator_did.as_str()),
                // The low-level offline-request CLI has no transport flag;
                // default to advertising both (prior behaviour).
                transport: did_hosting_common::server::config::TransportSelection::Both,
                remote: None,
            };
            let ask = did_hosting_common::server::vta_setup::build_webvh_provision_ask(
                &context,
                &shape,
                Some(&label),
            );
            if let Err(e) = did_hosting_common::server::vta_setup::run_offline_request_cli(
                &out,
                &seed,
                "did-hosting-control",
                &ask,
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
            if let Err(e) = did_hosting_common::server::vta_setup::run_offline_open_cli(
                &bundle,
                &expect_digest,
                &seed,
                &did_doc_out,
                &did_log_out,
                &secrets_out,
                did_hosting_common::server::vta_setup::OfflineOpenNextStep::Setup {
                    binary: "did-hosting-control",
                },
            ) {
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
            eprintln!("  did-hosting-control --config <path>");
            eprintln!("  did-hosting-control setup");
            std::process::exit(1);
        }
    };

    did_hosting_common::server::config::init_tracing(&config.log);

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
            eprintln!("Error: no secrets found — run `did-hosting-control setup` first");
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
    did_hosting_common::server::cli_acl::run_add_acl(
        &config.store,
        did,
        role_str,
        label,
        None,
        None,
    )
    .await
}

async fn run_list_acl(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    did_hosting_common::server::cli_acl::run_list_acl(&config.store).await
}

async fn run_remove_acl(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    did_hosting_common::server::cli_acl::run_remove_acl(&config.store, did).await
}

async fn run_invite(
    config_path: Option<PathBuf>,
    did: String,
    role: String,
    ttl_hours: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use did_hosting_common::server::passkey::routes::create_enrollment_invite;

    let config = AppConfig::load(config_path)?;

    let base_url = config
        .public_url
        .as_deref()
        .ok_or("public_url must be set in config for enrollment invites")?;

    let enrollment_ttl = match ttl_hours {
        Some(hours) => hours * 3600,
        None => config.auth.passkey_enrollment_ttl,
    };

    let store = store::Store::open(&config.store).await?;
    let sessions_ks = store.keyspace(KS_SESSIONS)?;

    let resp =
        create_enrollment_invite(&sessions_ks, base_url, enrollment_ttl, &did, &role).await?;

    eprintln!();
    eprintln!("  Enrollment invite created!");
    eprintln!();
    eprintln!("  DID:     {did}");
    eprintln!("  Role:    {role}");
    let ttl_hours = enrollment_ttl / 3600;
    eprintln!("  Expires: in {ttl_hours}h (epoch {})", resp.expires_at);
    eprintln!();
    eprintln!("  Enrollment URL:");
    eprintln!("  {}", resp.enrollment_url);
    eprintln!();

    Ok(())
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

    let secret_store = secret_store::create_secret_store(&config)?;
    let secrets = secret_store
        .get()
        .await?
        .ok_or("no secrets found — run setup first")?;

    let info = did_hosting_common::server::vta_setup::export_sealed_did_secrets(
        &request,
        &out,
        &producer_did,
        &producer_did,
        secrets.signing_key.clone(),
        secrets.key_agreement_key.clone(),
        did_hosting_common::server::vta_setup::ExportAssertionMode::DidSigned {
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

    let producer_pub = affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
        &secrets.signing_key,
        None,
    )?
    .get_public_keymultibase()?;

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
    eprintln!("  Producer assertion mode: DidSigned. The bundle is signed by");
    eprintln!("  this control plane's `#key-0` Ed25519 key. Receivers who pin");
    eprintln!("  the pubkey get cryptographic verification; without it the OOB");
    eprintln!("  digest stays the only anchor.");
    eprintln!();
    eprintln!("  Producer pubkey (share with receiver — matches #key-0):");
    eprintln!("    {producer_pub}");
    eprintln!();
    eprintln!("  Next on the receiver:");
    eprintln!(
        "    did-hosting-control import-sealed --bundle {} \\\n      --expect-digest {} \\\n      --producer-pubkey {producer_pub}",
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
    use did_hosting_common::server::vta_setup::{
        generate_ed25519_multibase, open_sealed_did_secrets,
    };

    let config = AppConfig::load(config_path)?;
    let secret_store = secret_store::create_secret_store(&config)?;

    if !force && let Ok(Some(_)) = secret_store.get().await {
        return Err("secrets already exist — use --force to overwrite".into());
    }

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
        retired: Vec::new(),
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
{cyan}██████╗{magenta} ████████╗{yellow}██████╗ {cyan}██╗     {reset}
{cyan}██╔═══╝{magenta} ╚══██╔══╝{yellow}██╔══██╗{cyan}██║     {reset}
{cyan}██║    {magenta}    ██║   {yellow}██████╔╝{cyan}██║     {reset}
{cyan}██║    {magenta}    ██║   {yellow}██╔══██╗{cyan}██║     {reset}
{cyan}╚██████╗{magenta}   ██║   {yellow}██║  ██║{cyan}███████╗{reset}
{cyan} ╚═════╝{magenta}   ╚═╝   {yellow}╚═╝  ╚═╝{cyan}╚══════╝{reset}
{dim}  DID Hosting Control Plane v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// `identity-list` — show which key material this service still honours.
async fn run_identity_list(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    did_hosting_common::server::cli_identity::run_list_generations(&config.store).await
}

/// `identity-retire-now` — the offline kill switch.
///
/// Opens the store directly, so it only works against a *stopped* service. A
/// live service must be retired through the control plane's REST endpoint (or
/// the UI button), which drops the key from the running process's secrets
/// resolver — deleting a record on disk would not.
async fn run_identity_retire_now(
    config_path: Option<PathBuf>,
    generation: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    did_hosting_common::server::cli_identity::run_retire_generation(
        &config.store,
        &config.secrets,
        &config.config_path,
        generation,
    )
    .await
}

/// `identity-rotate-keys` — rotate the service's own key-agreement key, offline.
///
/// Writes the new DID log entry, the new key material (carrying the outgoing key
/// into the retired set in the same write), and the generation records. The
/// service comes back up already holding both keys.
async fn run_identity_rotate_keys(
    config_path: Option<PathBuf>,
    ka_key: Option<String>,
    grace: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use did_hosting_common::server::identity_rotate::rotate_key_agreement_key;
    use did_hosting_common::server::secret_store::create_secret_store;
    use did_hosting_common::server::store::Store;

    let config = AppConfig::load(config_path)?;
    let server_did = config
        .server_did
        .as_deref()
        .ok_or("server_did is not set — this service has no identity to rotate")?;

    let grace_secs = match grace.as_deref() {
        Some(s) => did_hosting_common::server::pending_purge::parse_grace_string(s)
            .map_err(|e| format!("invalid --grace: {e}"))?,
        None => config.identity.rotation_grace_secs(),
    };

    let store = Store::open(&config.store).await?;
    let secret_store = create_secret_store(&config.secrets, &config.config_path)?;

    let report = rotate_key_agreement_key(
        &store,
        secret_store.as_ref(),
        server_did,
        ka_key.as_deref(),
        grace_secs,
    )
    .await?;

    eprintln!();
    eprintln!("  Rotated the key-agreement key for {}", report.did);
    eprintln!(
        "    new key    : {}  (generation {})",
        report.new_ka_kid, report.new_generation
    );
    if grace_secs > 0 {
        eprintln!(
            "    retiring   : {}  (generation {}, honoured for {}m)",
            report.retired_ka_kid,
            report.retired_generation,
            grace_secs / 60
        );
    } else {
        eprintln!(
            "    retiring   : {}  (RETIRED IMMEDIATELY — no grace period)",
            report.retired_ka_kid
        );
    }
    eprintln!("    did.jsonl  : now {} entries", report.version_count);
    eprintln!();
    if grace_secs > 0 {
        eprintln!("  Start the service. It will honour BOTH keys, so peers holding a cached");
        eprintln!("  DID document can still reach it until the old key expires.");
    } else {
        eprintln!("  Start the service. Messages still encrypted to the old key will NOT");
        eprintln!("  decrypt — peers must re-resolve the DID document first.");
    }
    eprintln!();

    Ok(())
}

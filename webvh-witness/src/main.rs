//! `webvh-witness` binary: setup, the service itself, and local admin
//! subcommands (ACL, witness identities, VTA and sealed-key operations).

use clap::{Parser, Subcommand};
use did_hosting_common::server::store::KS_WITNESSES;
use std::path::PathBuf;
use webvh_witness::config::AppConfig;
use webvh_witness::{health, secret_store, server, setup, setup_recipe, store, witness_ops};

// ─── Allocator ──────────────────────────────────────────────────────────────
//
// Set on the binary only. A library that installs a #[global_allocator] forces
// it on every consumer, so this deliberately does not live in lib.rs.
//
// Why not the system allocator: the witness churns short-lived buffers (DID
// logs being verified and signed, DIDComm and TSP messages). glibc malloc
// keeps those arenas rather than returning them, so RSS ratchets to the
// high-water mark and never falls back — indistinguishable from a leak on a
// memory graph.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read by jemalloc itself at startup via this well-known symbol.
///
/// `background_thread:true` runs the purger off the request path.
/// `dirty_decay_ms` / `muzzy_decay_ms` are how long freed pages linger before
/// being returned to the OS; jemalloc's defaults (10s / 10s) are tuned for
/// throughput on allocation-heavy workloads, and hold RSS well above the live
/// heap. 5s keeps the memory graph honest at a negligible cost here, because
/// the service's hot path is I/O-bound, not allocation-bound.
///
/// Raise these (or drop the `jemalloc` feature) if you are optimising for
/// allocation throughput over resident footprint.
///
/// The symbol must be `_rjem_malloc_conf`, not the `malloc_conf` jemalloc
/// documents: tikv-jemalloc-sys (default features) builds jemalloc with
/// `--with-jemalloc-prefix=_rjem_`, which prefixes every public symbol,
/// including the one it reads its configuration from. An unprefixed
/// `malloc_conf` would compile and link fine and be silently ignored.
///
/// SAFETY: exporting a symbol is unsafe because it could clash with another
/// definition of the same name. `_rjem_malloc_conf` is the (prefixed) name
/// jemalloc reads for exactly this, it is defined once (in the binary, never
/// the library), and the value is the NUL-terminated static string jemalloc
/// expects. This is the one `unsafe` outside tests (CONTRIBUTING rule 6),
/// signed off in the PR that added it.
///
/// The type is `&[u8; 63]`, a reference to a fixed-size array: a thin pointer,
/// which is what jemalloc's `const char *malloc_conf` is. A `&[u8]` slice
/// reference is a two-word fat pointer (address + length), which matches
/// `const char *` only by the accident of field order.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[allow(unsafe_code)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8; 63] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000\0";

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
        /// Context id for phase 1's PNM command. Defaults to `did-hosting`.
        #[arg(long, default_value = "did-hosting", requires = "setup_key_out")]
        context: String,
        /// Path to a declarative setup recipe TOML.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Refuse to run when an existing setup is detected, unless set.
        #[arg(long)]
        force_reprovision: bool,
        /// Explicit "no TTY available" flag. Requires `--from`.
        #[arg(long, requires = "from")]
        non_interactive: bool,
    },
    /// Teardown a witness install: clears managed secrets and removes
    /// the config file (+ `.bak`, + `witness-did.jsonl`).
    Uninstall {
        /// Skip the typed "DELETE" confirmation prompt. CI use only.
        #[arg(long)]
        yes: bool,
    },
    /// Run health check diagnostics. Exits non-zero when a check fails (or,
    /// with --strict, warns), so it can gate a deploy or a container probe.
    Health {
        /// Also exit non-zero when a check only warned (a store held by the
        /// running service, plaintext secrets, a non-2xx reachability probe).
        #[arg(long)]
        strict: bool,
    },
    /// Add an access control entry
    AddAcl {
        /// DID to grant access to
        #[arg(long)]
        did: String,
        /// Role, required: `admin` (create, list and delete witness
        /// identities, administer this ACL, and request signatures) or
        /// `service` (request signatures only: for a control plane, VTA or
        /// edge that needs proofs). No other role can do anything on a
        /// witness, so no other is accepted.
        #[arg(long, value_parser = ["admin", "service"])]
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
    /// Clear a key-encryption-key creation claim left by a witness process
    /// that stopped while creating it. Refused once a key is recorded.
    ResetWitnessKekClaim,
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
        /// DIDComm mediator DID. Bound to the `did-hosting-server` template's
        /// `MEDIATOR_DID` variable so the rendered DID document advertises
        /// the right mediator endpoint.
        #[arg(long)]
        mediator_did: String,
        /// VTA context the integration will live in. Embedded as
        /// `contextHint` in the request so the VTA admin can run
        /// `vta bootstrap provision-integration` without `--context`.
        #[arg(long, default_value = "did-hosting")]
        context: String,
    },
    /// Export this witness's DID + signing/KA keys as an HPKE-sealed
    /// migration bundle. See `did-hosting-server export-sealed` for semantics.
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
    /// contained keys as this witness's identity.
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
    /// Open a sealed VTA bootstrap response.
    ///
    /// Reads the armored bundle the operator ferried back, verifies the
    /// out-of-band digest, opens the HPKE sealed payload with the
    /// ephemeral seed, and emits the DID document + signed DID log for
    /// import via `did-hosting-server bootstrap-did` on the hosting server.
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

    let config = cli.config;
    match cli.command {
        Some(Command::Setup {
            setup_key_out,
            setup_key_file,
            context,
            from,
            force_reprovision,
            non_interactive: _,
        }) => {
            run_setup_command(
                config,
                setup_key_out,
                setup_key_file,
                &context,
                from,
                force_reprovision,
            )
            .await
        }
        Some(Command::Uninstall { yes }) => {
            let config_path = config.unwrap_or_else(|| PathBuf::from("config.toml"));
            or_exit(
                "Uninstall error",
                setup_recipe::run_uninstall(&config_path, yes).await,
            );
        }
        Some(Command::Health { strict }) => {
            let code = did_hosting_common::server::health::finish(
                health::run_health(config).await,
                strict,
            );
            std::process::exit(code);
        }
        Some(Command::AddAcl { did, role }) => {
            or_exit("Error", run_add_acl(config, did, role).await);
        }
        Some(Command::ListAcl) => or_exit("Error", run_list_acl(config).await),
        Some(Command::RemoveAcl { did }) => or_exit("Error", run_remove_acl(config, did).await),
        Some(Command::CreateWitness { label }) => {
            or_exit("Error", run_create_witness(config, label).await);
        }
        Some(Command::ListWitnesses) => or_exit("Error", run_list_witnesses(config).await),
        Some(Command::DeleteWitness { id }) => {
            or_exit("Error", run_delete_witness(config, id).await);
        }
        Some(Command::ResetWitnessKekClaim) => {
            or_exit("Error", run_reset_witness_kek_claim(config).await);
        }
        Some(Command::SetupOfflinePrepare { request, state }) => or_exit(
            "Setup error",
            setup::run_setup_offline_prepare(config, request, state).await,
        ),
        Some(Command::SetupOfflineComplete {
            bundle,
            expect_digest,
            state,
        }) => or_exit(
            "Setup error",
            setup::run_setup_offline_complete(bundle, expect_digest, state).await,
        ),
        Some(Command::ExportSealed {
            request,
            out,
            digest_out,
        }) => or_exit(
            "Error",
            run_export_sealed(config, request, out, digest_out).await,
        ),
        Some(Command::ImportSealed {
            bundle,
            expect_digest,
            seed,
            producer_pubkey,
            jwt_key,
            force,
        }) => or_exit(
            "Error",
            run_import_sealed(
                config,
                bundle,
                expect_digest,
                seed,
                producer_pubkey,
                jwt_key,
                force,
            )
            .await,
        ),
        Some(Command::VtaRequest {
            out,
            seed,
            label,
            mediator_did,
            context,
        }) => or_exit(
            "Error",
            run_vta_request(&out, &seed, &label, &mediator_did, &context).await,
        ),
        Some(Command::VtaOpen {
            bundle,
            expect_digest,
            seed,
            did_doc_out,
            did_log_out,
            secrets_out,
        }) => or_exit(
            "Error",
            did_hosting_common::server::vta_setup::run_offline_open_cli(
                &bundle,
                &expect_digest,
                &seed,
                &did_doc_out,
                &did_log_out,
                &secrets_out,
                did_hosting_common::server::vta_setup::OfflineOpenNextStep::Setup {
                    binary: "webvh-witness",
                },
            ),
        ),
        None => run_server(config).await,
    }
}

/// Print `{context}: {error}` and exit non-zero when `result` failed.
fn or_exit<E: std::fmt::Display>(context: &str, result: Result<(), E>) {
    if let Err(e) = result {
        eprintln!("{context}: {e}");
        std::process::exit(1);
    }
}

/// `setup`: headless phase 1 (`--setup-key-out`), a recipe (`--from`, whose
/// failure picks the exit code), or the interactive wizard.
async fn run_setup_command(
    config: Option<PathBuf>,
    setup_key_out: Option<PathBuf>,
    setup_key_file: Option<PathBuf>,
    context: &str,
    from: Option<PathBuf>,
    force_reprovision: bool,
) {
    if let Some(path) = setup_key_out {
        or_exit("Setup error", setup::run_setup_phase1(&path, context).await);
    } else if let Some(recipe_path) = from {
        if let Err(e) =
            setup_recipe::run_from_recipe(&recipe_path, setup_key_file, force_reprovision).await
        {
            eprintln!("Setup error: {e}");
            std::process::exit(setup_recipe::map_exit_code(&e));
        }
    } else {
        or_exit(
            "Setup error",
            setup::run_wizard(config, setup_key_file).await,
        );
    }
}

/// `vta-request`: the witness DID is DIDComm-only (`did-hosting-server`
/// template, MEDIATOR_DID only — no hosting URL).
async fn run_vta_request(
    out: &std::path::Path,
    seed: &std::path::Path,
    label: &str,
    mediator_did: &str,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let shape = did_hosting_common::server::vta_setup::WebvhDidShape::DidcommOnly { mediator_did };
    let ask = did_hosting_common::server::vta_setup::build_webvh_provision_ask(
        context,
        &shape,
        Some(label),
    );
    did_hosting_common::server::vta_setup::run_offline_request_cli(out, seed, "webvh-witness", &ask)
        .await
}

async fn run_add_acl(
    config_path: Option<PathBuf>,
    did: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    did_hosting_common::server::cli_acl::run_add_acl(&config.store, did, role, None, None, None)
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

async fn run_create_witness(
    config_path: Option<PathBuf>,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let witnesses_ks = store.keyspace(KS_WITNESSES)?;

    // The private key is stored sealed to the witness key-encryption key,
    // which the configured secret store holds (created here on first use).
    let keys = webvh_witness::witness_keys::load_or_create(
        &secret_store::create_witness_kek_store(&config.secrets, &config.config_path)?,
        &witnesses_ks,
    )
    .await?;
    let record = witness_ops::create_witness(&witnesses_ks, &keys, label).await?;

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
    let witnesses_ks = store.keyspace(KS_WITNESSES)?;

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
    let witnesses_ks = store.keyspace(KS_WITNESSES)?;

    // Check if witness exists
    if witness_ops::get_witness(&witnesses_ks, &witness_id)
        .await?
        .is_none()
    {
        return Err(format!("witness not found: {witness_id}").into());
    }

    witness_ops::delete_witness(&store, &witnesses_ks, &witness_id).await?;

    eprintln!();
    eprintln!("  Witness deleted: {witness_id}");
    eprintln!();

    Ok(())
}

async fn run_reset_witness_kek_claim(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    let store = store::Store::open(&config.store).await?;
    let witnesses_ks = store.keyspace(KS_WITNESSES)?;
    let kek_store = secret_store::create_witness_kek_store(&config.secrets, &config.config_path)?;
    let had = webvh_witness::witness_keys::reset_kek_claim(&kek_store, &witnesses_ks).await?;
    eprintln!();
    if had {
        eprintln!("  Key-encryption-key creation claim cleared; start the witness again.");
    } else {
        eprintln!("  No key-encryption-key creation claim was held.");
    }
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

    did_hosting_common::server::config::init_tracing(&config.log);

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

    let store = store::Store::open_with(&config.store, &config.fjall)
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
    eprintln!("  this witness's `#key-0` Ed25519 key. Receivers who pin the");
    eprintln!("  pubkey get cryptographic verification; without it the OOB");
    eprintln!("  digest stays the only anchor.");
    eprintln!();
    eprintln!("  Producer pubkey (share with receiver — matches #key-0):");
    eprintln!("    {producer_pub}");
    eprintln!();
    eprintln!("  Next on the receiver:");
    eprintln!(
        "    webvh-witness import-sealed --bundle {} \\\n      --expect-digest {} \\\n      --producer-pubkey {producer_pub}",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_acl_takes_only_a_role_that_does_something_on_a_witness() {
        for role in ["admin", "service"] {
            assert!(
                Cli::try_parse_from([
                    "webvh-witness",
                    "add-acl",
                    "--did",
                    "did:key:z",
                    "--role",
                    role
                ])
                .is_ok(),
                "{role}"
            );
        }
        for args in [
            vec!["webvh-witness", "add-acl", "--did", "did:key:z"],
            vec![
                "webvh-witness",
                "add-acl",
                "--did",
                "did:key:z",
                "--role",
                "owner",
            ],
            vec![
                "webvh-witness",
                "add-acl",
                "--did",
                "did:key:z",
                "--role",
                "metricsReader",
            ],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
    }
}

#[cfg(test)]
mod cli_reference_tests {
    did_hosting_common::cli_reference_test!(super::Cli, "webvh-witness");
}

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
        #[arg(long, default_value = "webvh-control")]
        label: String,
    },
    /// Open a sealed VTA bootstrap response.
    ///
    /// Reads the armored bundle the operator ferried back, verifies the
    /// out-of-band digest, opens the HPKE sealed payload with the
    /// ephemeral seed, and emits the DID document + signed DID log for
    /// import via the webvh-server bootstrap-did / load-did commands.
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
        /// Feed into `webvh-control setup` to persist via the configured
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
        Some(Command::VtaRequest { out, seed, label }) => {
            if let Err(e) = run_vta_request(&out, &seed, &label) {
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
            if let Err(e) = run_vta_open(
                &bundle,
                &expect_digest,
                &seed,
                &did_doc_out,
                &did_log_out,
                &secrets_out,
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
    affinidi_webvh_common::server::cli_acl::run_add_acl(
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
    affinidi_webvh_common::server::cli_acl::run_list_acl(&config.store).await
}

async fn run_remove_acl(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_remove_acl(&config.store, did).await
}

async fn run_invite(
    config_path: Option<PathBuf>,
    did: String,
    role: String,
    ttl_hours: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::passkey::routes::create_enrollment_invite;

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
    let sessions_ks = store.keyspace("sessions")?;

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

fn run_vta_request(
    out: &PathBuf,
    seed: &PathBuf,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::vta_setup::write_offline_bootstrap_request;

    let info = write_offline_bootstrap_request(out, seed, Some(label))?;

    eprintln!();
    eprintln!("  Offline bootstrap request ready.");
    eprintln!();
    eprintln!("  Request file:   {}", info.request_path.display());
    eprintln!("  Seed (secret):  {}", info.seed_path.display());
    eprintln!();
    eprintln!("  Consumer DID:   {}", info.client_did);
    eprintln!("  Nonce:          {}", info.nonce);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!(
        "    1. Ferry {} to your VTA admin.",
        info.request_path.display()
    );
    eprintln!("    2. Ask them to run:");
    eprintln!(
        "         vta bootstrap seal --request <request-file> \\\n           --template webvh-service --var MEDIATOR_DID=<mediator-did>"
    );
    eprintln!("    3. They send back an ASCII-armored sealed bundle + SHA-256 digest.");
    eprintln!("    4. Run:");
    eprintln!("         webvh-control vta-open --bundle <bundle> --expect-digest <hex>");
    eprintln!();
    eprintln!("  KEEP THE SEED FILE. Losing it means you cannot open the response.");
    eprintln!();

    Ok(())
}

fn run_vta_open(
    bundle: &PathBuf,
    expect_digest: &str,
    seed: &PathBuf,
    did_doc_out: &PathBuf,
    did_log_out: &PathBuf,
    secrets_out: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::vta_setup::open_offline_bootstrap_response;

    let armor =
        std::fs::read_to_string(bundle).map_err(|e| format!("read {}: {e}", bundle.display()))?;

    let result = open_offline_bootstrap_response(&armor, expect_digest, seed)?;

    // DID document (pretty JSON, for publishing via webvh-server bootstrap-did).
    let did_doc_json = serde_json::to_string_pretty(&result.did_document)?;
    std::fs::write(did_doc_out, &did_doc_json)?;

    // DID log (JSONL, when the template emitted one — the usual case).
    if let Some(ref log) = result.log_entry {
        std::fs::write(did_log_out, log)?;
    }

    // Minimal secrets JSON for the operator to hand to the control plane's
    // secret store (via `webvh-control setup`, which prompts for a backend
    // and persists there). Also carries the extra VTA metadata the caller
    // may want to keep — authorization VC, pinned VTA DID — so nothing from
    // the sealed response is lost. Kept plaintext; colocate with the seed
    // file under operator-controlled ACLs.
    let secrets_payload = serde_json::json!({
        "did": result.did,
        "signing_key_multibase": result.signing_key_multibase,
        "key_agreement_multibase": result.key_agreement_multibase,
        "vta_did": result.vta_did,
        "vta_url": result.vta_url,
        "authorization_vc": result.authorization_vc,
    });
    std::fs::write(secrets_out, serde_json::to_string_pretty(&secrets_payload)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(secrets_out)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(secrets_out, perms)?;
    }

    eprintln!();
    eprintln!("  Sealed response opened.");
    eprintln!();
    eprintln!("  DID:            {}", result.did);
    eprintln!("  VTA DID:        {}", result.vta_did);
    if let Some(ref url) = result.vta_url {
        eprintln!("  VTA URL:        {url}");
    }
    eprintln!();
    eprintln!("  Wrote {}", did_doc_out.display());
    if result.log_entry.is_some() {
        eprintln!("  Wrote {}", did_log_out.display());
    } else {
        eprintln!("  No WebvhLog output in the sealed response — did_log_out not written.");
    }
    eprintln!("  Wrote {} (0600)", secrets_out.display());
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Publish the DID document at <hosting-url>/<path>/did.jsonl using");
    eprintln!(
        "       `webvh-server bootstrap-did --did-log {}` on the hosting server.",
        did_log_out.display()
    );
    eprintln!("    2. Run `webvh-control setup` and when the wizard asks for keys,");
    eprintln!("       feed in the `signing_key_multibase` and `key_agreement_multibase`");
    eprintln!("       values from {}.", secrets_out.display());
    eprintln!("       (A dedicated `import-secrets` subcommand for webvh-control is");
    eprintln!("       planned; for now the setup wizard is the supported entry point.)");
    eprintln!();

    Ok(())
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

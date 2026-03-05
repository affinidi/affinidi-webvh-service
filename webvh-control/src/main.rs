use clap::{Parser, Subcommand};
use affinidi_webvh_control::config::AppConfig;
use affinidi_webvh_control::{server, setup, store, secret_store};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "webvh-control", about = "WebVH Control Plane — Unified Management", version)]
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
    /// Import a PNM provision bundle to bootstrap the control plane.
    ///
    /// Use the PNM CLI to provision a VTA context with a DID first:
    ///
    ///   pnm contexts provision --name webvh-control \
    ///     --did-url https://did.example.com/services/control
    ///
    /// Then pass the output bundle here:
    ///
    ///   webvh-control bootstrap \
    ///     --control-bundle <base64url from provision> \
    ///     --output-dir ./bootstrap-output
    ///
    /// For webvh-server, use `webvh-server setup` to import its own bundle.
    #[command(verbatim_doc_comment)]
    Bootstrap {
        /// PNM provision bundle for webvh-control (base64url string from `pnm contexts provision`)
        #[arg(long)]
        control_bundle: String,
        /// Output directory for secrets bundles and DID log files
        #[arg(long, default_value = "./bootstrap-output")]
        output_dir: PathBuf,
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
        Some(Command::Bootstrap {
            control_bundle,
            output_dir,
        }) => {
            use affinidi_webvh_control::vta_bootstrap::{ServiceBundle, run_bootstrap, print_next_steps};

            let bundles = vec![
                ServiceBundle { label: "webvh-control", encoded: &control_bundle },
            ];

            if let Err(e) = run_bootstrap(&bundles, &output_dir) {
                eprintln!("Bootstrap error: {e}");
                std::process::exit(1);
            }

            print_next_steps(&output_dir);
        }
        Some(Command::Invite { did, role, ttl_hours }) => {
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
    use affinidi_webvh_control::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
    use affinidi_webvh_control::auth::session::now_epoch;

    let role = Role::from_str(&role_str)
        .map_err(|_| format!("invalid role '{role_str}': use 'admin' or 'owner'"))?;

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
        role: role.clone(),
        label,
        created_at: now_epoch(),
        max_total_size: None,
        max_did_count: None,
    };

    store_acl_entry(&acl_ks, &entry).await?;

    eprintln!();
    eprintln!("  ACL entry created!");
    eprintln!();
    eprintln!("  DID:  {did}");
    eprintln!("  Role: {role}");
    eprintln!();

    Ok(())
}

async fn run_list_acl(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_control::acl::list_acl_entries;

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
        "  {:<50} {:<8} {}",
        "DID", "ROLE", "LABEL"
    );
    eprintln!("  {}", "-".repeat(80));

    for entry in &entries {
        let label = entry.label.as_deref().unwrap_or("-");
        eprintln!(
            "  {:<50} {:<8} {}",
            entry.did, entry.role, label
        );
    }

    eprintln!();
    eprintln!("  {} entries total", entries.len());
    eprintln!();

    Ok(())
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

    let resp = create_enrollment_invite(&sessions_ks, base_url, enrollment_ttl, &did, &role).await?;

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

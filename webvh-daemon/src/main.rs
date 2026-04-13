mod config;

use axum::Router;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use axum::routing::get;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, error, info, warn};

use affinidi_webvh_common::server::config::init_tracing;
use affinidi_webvh_common::server::error::AppError;
use affinidi_webvh_common::server::init;
use affinidi_webvh_common::server::secret_store::ServerSecrets;

use config::DaemonConfig;

#[derive(Parser)]
#[command(
    name = "webvh-daemon",
    about = "WebVH Daemon — Unified Service",
    version
)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<std::path::PathBuf>,

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
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Some(Command::Setup) => {
            eprintln!("  Setup wizard not yet implemented for the daemon.");
            eprintln!("  Configure each service individually, then create a combined config.toml.");
            std::process::exit(1);
        }
        Some(Command::Health) => {
            if let Err(e) = run_health(cli.config).await {
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
        None => run_daemon(cli.config).await,
    }
}

async fn run_daemon(config_path: Option<std::path::PathBuf>) {
    let config = match DaemonConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Create a config.toml or specify one:");
            eprintln!("  webvh-daemon --config <path>");
            std::process::exit(1);
        }
    };

    init_tracing(&config.log);

    // Load secrets (shared across server, witness, control)
    let secrets = load_secrets(&config).await;

    // Open each unique store path once — fjall locks the directory, so
    // server/watcher/control must share a single Store handle.
    let main_store = affinidi_webvh_common::server::store::Store::open(&config.store)
        .await
        .unwrap_or_else(|e| {
            error!("failed to open main store: {e}");
            std::process::exit(1);
        });

    let witness_store = affinidi_webvh_common::server::store::Store::open(&config.witness_store)
        .await
        .unwrap_or_else(|e| {
            error!("failed to open witness store: {e}");
            std::process::exit(1);
        });

    // Build each enabled service's router
    let mut combined: Router = Router::new();
    let mut server_state: Option<affinidi_webvh_server::server::AppState> = None;

    // Track what's enabled for the summary
    let mut enabled_services = Vec::new();

    // 1. Server — public DID-serving routes only (.well-known).
    //    All /api management routes come from the control plane.
    if config.enable.server {
        match build_server(&config, &secrets, &main_store).await {
            Ok((router, state)) => {
                combined = combined.merge(router);
                server_state = Some(state);
                enabled_services.push("server (/)");
            }
            Err(e) => {
                error!("failed to initialize server: {e}");
                std::process::exit(1);
            }
        }
    }

    // 2. Witness (nested at /witness)
    if config.enable.witness {
        match build_witness(&config, &secrets, &witness_store).await {
            Ok(router) => {
                combined = combined.nest("/witness", router);
                enabled_services.push("witness (/witness)");
            }
            Err(e) => {
                error!("failed to initialize witness: {e}");
                std::process::exit(1);
            }
        }
    }

    // 3. Watcher (nested at /watcher)
    if config.enable.watcher {
        match build_watcher(&config, &main_store).await {
            Ok(router) => {
                combined = combined.nest("/watcher", router);
                enabled_services.push("watcher (/watcher)");
            }
            Err(e) => {
                error!("failed to initialize watcher: {e}");
                std::process::exit(1);
            }
        }
    }

    // 4. Control plane — merged at root (no /control prefix) so that
    //    URLs like /enroll and /api/... work identically in daemon and
    //    standalone modes.
    if config.enable.control {
        match build_control(&config, &secrets, &main_store).await {
            Ok(router) => {
                combined = combined.merge(router);
                enabled_services.push("control (/)");
            }
            Err(e) => {
                error!("failed to initialize control plane: {e}");
                std::process::exit(1);
            }
        }
    }

    // Combined fallback: try DID public serving first, then the SPA UI.
    // This lets /{mnemonic}/did.jsonl resolve DIDs while /enroll (etc.)
    // serves index.html for client-side routing.
    combined = match server_state {
        Some(state) => combined.fallback({
            let state = state.clone();
            move |uri: Uri| {
                let state = state.clone();
                async move { daemon_fallback(state, uri).await }
            }
        }),
        None => {
            // No server enabled — just use the UI fallback
            #[cfg(feature = "ui")]
            {
                combined.fallback(affinidi_webvh_control::frontend::static_handler)
            }
            #[cfg(not(feature = "ui"))]
            {
                combined
            }
        }
    };

    // Apply tracing layer, then add health route *after* so it's not traced
    let app = combined
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::DEBUG)
                        .latency_unit(tower_http::LatencyUnit::Millis),
                ),
        )
        .route("/health", get(daemon_health));

    // Log startup summary
    info!("--- daemon services ---");
    for svc in &enabled_services {
        info!("  {svc}");
    }

    // Bind and serve
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            error!("failed to bind {addr}: {e}");
            std::process::exit(1);
        });
    info!("daemon listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(init::shutdown_signal())
        .await
        .expect("axum serve failed");

    // Persist stores on shutdown
    if let Err(e) = main_store.persist().await {
        error!("failed to persist main store: {e}");
    }
    if let Err(e) = witness_store.persist().await {
        error!("failed to persist witness store: {e}");
    }

    info!("daemon shut down");
}

// ---------------------------------------------------------------------------
// Service builders
// ---------------------------------------------------------------------------

type ServiceResult = Result<Router, AppError>;

/// Build the server — returns both the router and the AppState.
///
/// In daemon mode the server only exposes public DID-serving routes
/// (`.well-known`). All `/api/…` management routes come from the
/// control plane, which is merged at root to avoid a `/control` prefix.
/// The AppState is returned so the daemon can wire up the combined
/// DID-serving + UI fallback.
async fn build_server(
    config: &DaemonConfig,
    secrets: &ServerSecrets,
    store: &affinidi_webvh_common::server::store::Store,
) -> Result<(Router, affinidi_webvh_server::server::AppState), AppError> {
    use affinidi_webvh_server::server::AppState;

    let server_config = config.server_config();

    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let dids_ks = store.keyspace("dids")?;
    let (did_resolver, secrets_resolver) =
        init::init_didcomm_auth(config.server_did.as_deref(), secrets).await;
    let jwt_keys = init::init_jwt_keys(secrets);
    let signing_key_bytes = init::decode_multibase_ed25519_key(&secrets.signing_key).ok();

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        dids_ks,
        config: Arc::new(server_config),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        signing_key_bytes,
        http_client: reqwest::Client::new(),
        stats_collector: None,
        did_cache: std::sync::Arc::new(affinidi_webvh_server::cache::ContentCache::new(
            std::time::Duration::from_secs(300),
        )),
    };

    // Public-only: .well-known routes, no /api (control plane provides those)
    let router = affinidi_webvh_server::routes::router_public_only().with_state(state.clone());
    info!("server service initialized (public-only, daemon mode)");

    Ok((router, state))
}

async fn build_witness(
    config: &DaemonConfig,
    secrets: &ServerSecrets,
    store: &affinidi_webvh_common::server::store::Store,
) -> ServiceResult {
    use affinidi_webvh_witness::server::AppState;
    use affinidi_webvh_witness::signing::LocalSigner;

    let witness_config = config.witness_config();

    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let witnesses_ks = store.keyspace("witnesses")?;

    let (did_resolver, secrets_resolver) =
        init::init_didcomm_auth(config.server_did.as_deref(), secrets).await;
    let jwt_keys = init::init_jwt_keys(secrets);

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        witnesses_ks,
        config: Arc::new(witness_config),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        signer: Arc::new(LocalSigner),
    };

    let router = affinidi_webvh_witness::routes::router().with_state(state);
    info!("witness service initialized");

    Ok(router)
}

async fn build_watcher(
    config: &DaemonConfig,
    store: &affinidi_webvh_common::server::store::Store,
) -> ServiceResult {
    use affinidi_webvh_watcher::server::AppState;

    let watcher_config = config.watcher_config();

    let dids_ks = store.keyspace("dids")?;

    let state = AppState {
        store: store.clone(),
        dids_ks,
        config: Arc::new(watcher_config),
    };

    let router = affinidi_webvh_watcher::routes::router().with_state(state);
    info!("watcher service initialized");

    Ok(router)
}

async fn build_control(
    config: &DaemonConfig,
    secrets: &ServerSecrets,
    store: &affinidi_webvh_common::server::store::Store,
) -> ServiceResult {
    use affinidi_webvh_control::server::AppState;

    let control_config = config.control_config();

    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let registry_ks = store.keyspace("registry")?;
    let dids_ks = store.keyspace("dids")?;

    let (did_resolver, secrets_resolver) =
        init::init_didcomm_auth(config.server_did.as_deref(), secrets).await;
    let jwt_keys = init::init_jwt_keys(secrets);

    // Initialize WebAuthn for passkeys
    let webauthn = control_config.public_url.as_ref().and_then(|url| {
        match affinidi_webvh_common::server::passkey::build_webauthn(url) {
            Ok(w) => {
                info!("WebAuthn (passkey) auth enabled for control plane");
                Some(Arc::new(w))
            }
            Err(e) => {
                warn!("WebAuthn initialization failed: {e} — passkey auth disabled");
                None
            }
        }
    });

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        registry_ks,
        dids_ks,
        config: Arc::new(control_config),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        webauthn,
        http_client: reqwest::Client::new(),
        atm: None,
        atm_profile: None,
        stats_collector: {
            let collector = affinidi_webvh_common::server::stats_collector::StatsCollector::new();
            // Daemon mode: basic init, no seeding from store
            std::sync::Arc::new(collector)
        },
        stats_ks: store
            .keyspace("stats")
            .expect("failed to open stats keyspace"),
    };

    // Use router_without_fallback — the daemon sets its own combined fallback
    // that handles both DID serving and SPA UI.
    let router = affinidi_webvh_control::routes::router_without_fallback().with_state(state);
    info!("control plane service initialized");

    Ok(router)
}

// ---------------------------------------------------------------------------
// Shared init helpers
// ---------------------------------------------------------------------------

async fn load_secrets(config: &DaemonConfig) -> ServerSecrets {
    // Use the server's secret store config (shared across all services)
    let secret_store = affinidi_webvh_common::server::secret_store::create_secret_store(
        &config.secrets,
        &config.config_path,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error creating secret store: {e}");
        std::process::exit(1);
    });

    match secret_store.get().await {
        Ok(Some(s)) => {
            info!("secrets loaded from secret store");
            s
        }
        Ok(None) => {
            eprintln!("Error: no secrets found — run service setup first");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error loading secrets: {e}");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Combined fallback: DID serving + SPA UI
// ---------------------------------------------------------------------------

/// Fallback handler for the daemon's combined router.
///
/// Tries DID public serving first (e.g. `/{mnemonic}/did.jsonl`).
/// If that returns 404, falls through to the SPA static handler so that
/// paths like `/enroll` serve `index.html` for client-side routing.
async fn daemon_fallback(state: affinidi_webvh_server::server::AppState, uri: Uri) -> Response {
    // Try DID public serving
    let did_resp = affinidi_webvh_server::routes::did_public::serve_public(
        axum::extract::State(state),
        uri.clone(),
    )
    .await;

    if did_resp.status() != StatusCode::NOT_FOUND {
        return did_resp;
    }

    // Fall through to SPA UI
    #[cfg(feature = "ui")]
    {
        affinidi_webvh_control::frontend::static_handler(uri).await
    }

    #[cfg(not(feature = "ui"))]
    {
        StatusCode::NOT_FOUND.into_response()
    }
}

// ---------------------------------------------------------------------------
// CLI management commands (delegated to webvh-common / webvh-control helpers)
// ---------------------------------------------------------------------------

async fn run_add_acl(
    config_path: Option<std::path::PathBuf>,
    did: String,
    role_str: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::load(config_path)?;
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

async fn run_list_acl(
    config_path: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_list_acl(&config.store).await
}

async fn run_remove_acl(
    config_path: Option<std::path::PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_remove_acl(&config.store, did).await
}

async fn run_invite(
    config_path: Option<std::path::PathBuf>,
    did: String,
    role: String,
    ttl_hours: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::passkey::routes::create_enrollment_invite;

    let config = DaemonConfig::load(config_path)?;
    let control_config = config.control_config();

    let base_url = control_config
        .public_url
        .as_deref()
        .ok_or("public_url must be set in config for enrollment invites")?;

    let enrollment_ttl = match ttl_hours {
        Some(hours) => hours * 3600,
        None => control_config.auth.passkey_enrollment_ttl,
    };

    let store = affinidi_webvh_control::store::Store::open(&control_config.store).await?;
    let sessions_ks = store.keyspace("sessions")?;

    let resp =
        create_enrollment_invite(&sessions_ks, base_url, enrollment_ttl, &did, &role).await?;

    eprintln!();
    eprintln!("  Enrollment invite created!");
    eprintln!();
    eprintln!("  DID:     {did}");
    eprintln!("  Role:    {role}");
    let ttl_hours_display = enrollment_ttl / 3600;
    eprintln!(
        "  Expires: in {ttl_hours_display}h (epoch {})",
        resp.expires_at
    );
    eprintln!();
    eprintln!("  Enrollment URL:");
    eprintln!("  {}", resp.enrollment_url);
    eprintln!();

    Ok(())
}

// ---------------------------------------------------------------------------
// CLI health check
// ---------------------------------------------------------------------------

async fn run_health(
    config_path: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::health;

    health::header("webvh-daemon", env!("CARGO_PKG_VERSION"));

    // ── Configuration ──────────────────────────────────────────────
    let config = match DaemonConfig::load(config_path) {
        Ok(c) => {
            health::section("Configuration");
            health::check_config_loaded(&c.config_path);
            health::check_value("server_did", &c.server_did);
            health::check_value("public_url", &c.public_url);
            health::check_value("did_hosting_url", &c.did_hosting_url);
            health::check_value("mediator_did", &c.mediator_did);
            Some(c)
        }
        Err(e) => {
            health::section("Configuration");
            health::fail(&format!("Config load failed: {e}"));
            None
        }
    };

    // ── Compile Features ───────────────────────────────────────────
    health::section("Compile Features");
    health::print_feature("store-fjall", cfg!(feature = "store-fjall"));
    health::print_feature("keyring", cfg!(feature = "keyring"));
    health::print_feature("ui", cfg!(feature = "ui"));
    health::print_feature("passkey", cfg!(feature = "passkey"));

    let config = match config {
        Some(c) => c,
        None => {
            eprintln!();
            return Ok(());
        }
    };

    // ── Enabled Services ───────────────────────────────────────────
    health::section("Enabled Services");
    health::print_feature("server", config.enable.server);
    health::print_feature("witness", config.enable.witness);
    health::print_feature("watcher", config.enable.watcher);
    health::print_feature("control", config.enable.control);

    // ── Secrets ────────────────────────────────────────────────────
    health::section("Secrets");
    health::check_secrets(&config.secrets, &config.config_path).await;

    // ── Per-service Stores ─────────────────────────────────────────
    if config.enable.server {
        health::section("Store (server)");
        let store = health::check_store(&config.store).await;

        // Root DID check via server store
        if let Some(ref store) = store
            && let Ok(dids_ks) = store.keyspace("dids")
        {
            health::section("Root DID (.well-known)");
            match affinidi_webvh_server::bootstrap::root_did_exists(&dids_ks).await {
                Ok(true) => {
                    health::pass("Root DID exists");
                    match dids_ks
                        .get::<affinidi_webvh_server::did_ops::DidRecord>(
                            affinidi_webvh_server::did_ops::did_key(".well-known"),
                        )
                        .await
                    {
                        Ok(Some(record)) => {
                            if let Some(ref did_id) = record.did_id {
                                health::info_msg(&format!("DID: {did_id}"));
                            }
                            health::info_msg(&format!("Version count: {}", record.version_count));
                        }
                        Ok(None) => {}
                        Err(e) => health::warn_msg(&format!("Could not read DID record: {e}")),
                    }
                }
                Ok(false) => health::skip("Root DID not yet bootstrapped"),
                Err(e) => health::fail(&format!("Root DID check failed: {e}")),
            }
        }
    }

    if config.enable.witness {
        health::section("Store (witness)");
        health::check_store(&config.witness_store).await;
    }

    if config.enable.watcher {
        health::section("Store (watcher — shared with server)");
        health::check_store(&config.store).await;
    }

    if config.enable.control {
        health::section("Store (control — shared with server)");
        health::check_store(&config.store).await;
    }

    // ── DID Resolution ─────────────────────────────────────────────
    if let Some(ref did) = config.server_did {
        health::section("DID Resolution");
        health::check_did_resolution("Server DID resolves", did).await;
    }

    if let Some(ref did) = config.mediator_did {
        health::section("Mediator DID Resolution");
        health::check_did_resolution("Mediator DID resolves", did).await;
    }

    eprintln!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Health & shutdown
// ---------------------------------------------------------------------------

async fn daemon_health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "webvh-daemon",
    }))
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan}██████╗ {magenta}█████╗ {yellow}███████╗{cyan}███╗   ███╗{magenta} ██████╗ {yellow}███╗   ██╗{reset}
{cyan}██╔══██╗{magenta}██╔══██╗{yellow}██╔════╝{cyan}████╗ ████║{magenta}██╔═══██╗{yellow}████╗  ██║{reset}
{cyan}██║  ██║{magenta}███████║{yellow}█████╗  {cyan}██╔████╔██║{magenta}██║   ██║{yellow}██╔██╗ ██║{reset}
{cyan}██║  ██║{magenta}██╔══██║{yellow}██╔══╝  {cyan}██║╚██╔╝██║{magenta}██║   ██║{yellow}██║╚██╗██║{reset}
{cyan}██████╔╝{magenta}██║  ██║{yellow}███████╗{cyan}██║ ╚═╝ ██║{magenta}╚██████╔╝{yellow}██║ ╚████║{reset}
{cyan}╚═════╝ {magenta}╚═╝  ╚═╝{yellow}╚══════╝{cyan}╚═╝     ╚═╝{magenta} ╚═════╝ {yellow}╚═╝  ╚═══╝{reset}
{dim}  WebVH Daemon v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

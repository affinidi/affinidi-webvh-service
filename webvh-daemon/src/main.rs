mod config;

use axum::Router;
use axum::routing::get;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, error, info, warn};

use affinidi_webvh_common::server::config::init_tracing;
use affinidi_webvh_common::server::error::AppError;
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

    // Build each enabled service's router
    let mut combined: Router = Router::new();
    let mut stores: Vec<affinidi_webvh_common::server::store::Store> = Vec::new();

    // Track what's enabled for the summary
    let mut enabled_services = Vec::new();

    // 1. Server (mounted at root — DID serving needs /)
    if config.enable.server {
        match build_server(&config, &secrets).await {
            Ok((router, store)) => {
                combined = combined.merge(router);
                stores.push(store);
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
        match build_witness(&config, &secrets).await {
            Ok((router, store)) => {
                combined = combined.nest("/witness", router);
                stores.push(store);
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
        match build_watcher(&config).await {
            Ok((router, store)) => {
                combined = combined.nest("/watcher", router);
                stores.push(store);
                enabled_services.push("watcher (/watcher)");
            }
            Err(e) => {
                error!("failed to initialize watcher: {e}");
                std::process::exit(1);
            }
        }
    }

    // 4. Control plane (nested at /control)
    if config.enable.control {
        match build_control(&config, &secrets).await {
            Ok((router, store)) => {
                combined = combined.nest("/control", router);
                stores.push(store);
                enabled_services.push("control (/control)");
            }
            Err(e) => {
                error!("failed to initialize control plane: {e}");
                std::process::exit(1);
            }
        }
    }

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
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("axum serve failed");

    // Persist all stores on shutdown
    for store in &stores {
        if let Err(e) = store.persist().await {
            error!("failed to persist store: {e}");
        }
    }

    info!("daemon shut down");
}

// ---------------------------------------------------------------------------
// Service builders
// ---------------------------------------------------------------------------

type ServiceResult = Result<(Router, affinidi_webvh_common::server::store::Store), AppError>;

async fn build_server(config: &DaemonConfig, secrets: &ServerSecrets) -> ServiceResult {
    use affinidi_webvh_server::server::AppState;
    use affinidi_webvh_server::store::Store;

    let server_config = config.server_config();
    let upload_body_limit = server_config.limits.upload_body_limit;

    let store = Store::open(&server_config.store).await?;
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let dids_ks = store.keyspace("dids")?;
    let (did_resolver, secrets_resolver) = init_didcomm_auth(config, secrets).await;
    let jwt_keys = init_jwt_keys(secrets);
    let signing_key_bytes = decode_signing_key(secrets);

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
        stats_collector: None, // daemon mode doesn't run the storage thread; stats flush is manual
        did_cache: std::sync::Arc::new(affinidi_webvh_server::cache::ContentCache::new(
            std::time::Duration::from_secs(300),
        )),
    };

    let router = affinidi_webvh_server::routes::router(upload_body_limit).with_state(state);
    info!("server service initialized");

    Ok((router, store))
}

async fn build_witness(config: &DaemonConfig, secrets: &ServerSecrets) -> ServiceResult {
    use affinidi_webvh_witness::server::AppState;
    use affinidi_webvh_witness::signing::LocalSigner;
    use affinidi_webvh_witness::store::Store;

    let witness_config = config.witness_config();

    let store = Store::open(&witness_config.store).await?;
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let witnesses_ks = store.keyspace("witnesses")?;

    let (did_resolver, secrets_resolver) = init_didcomm_auth(config, secrets).await;
    let jwt_keys = init_jwt_keys(secrets);

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

    Ok((router, store))
}

async fn build_watcher(config: &DaemonConfig) -> ServiceResult {
    use affinidi_webvh_watcher::server::AppState;
    use affinidi_webvh_watcher::store::Store;

    let watcher_config = config.watcher_config();

    let store = Store::open(&watcher_config.store).await?;
    let dids_ks = store.keyspace("dids")?;

    let state = AppState {
        store: store.clone(),
        dids_ks,
        config: Arc::new(watcher_config),
    };

    let router = affinidi_webvh_watcher::routes::router().with_state(state);
    info!("watcher service initialized");

    Ok((router, store))
}

async fn build_control(config: &DaemonConfig, secrets: &ServerSecrets) -> ServiceResult {
    use affinidi_webvh_control::server::AppState;
    use affinidi_webvh_control::store::Store;

    let control_config = config.control_config();

    let store = Store::open(&control_config.store).await?;
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let registry_ks = store.keyspace("registry")?;
    let dids_ks = store.keyspace("dids")?;

    let (did_resolver, secrets_resolver) = init_didcomm_auth(config, secrets).await;
    let jwt_keys = init_jwt_keys(secrets);

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

    let router = affinidi_webvh_control::routes::router().with_state(state);
    info!("control plane service initialized");

    Ok((router, store))
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

fn init_jwt_keys(
    secrets: &ServerSecrets,
) -> Option<Arc<affinidi_webvh_common::server::auth::jwt::JwtKeys>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use affinidi_webvh_common::server::auth::jwt::JwtKeys;

    let secret = match Secret::from_multibase(&secrets.jwt_signing_key, None) {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to decode JWT signing key: {e} — auth disabled");
            return None;
        }
    };

    let bytes = secret.get_private_bytes();
    let key_bytes: [u8; 32] = match bytes.try_into() {
        Ok(b) => b,
        Err(_) => {
            warn!("JWT signing key must be 32 bytes — auth disabled");
            return None;
        }
    };

    match JwtKeys::from_ed25519_bytes(&key_bytes) {
        Ok(keys) => Some(Arc::new(keys)),
        Err(e) => {
            warn!("failed to construct JWT keys: {e} — auth disabled");
            None
        }
    }
}

fn decode_signing_key(secrets: &ServerSecrets) -> Option<[u8; 32]> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let secret = Secret::from_multibase(&secrets.signing_key, None).ok()?;
    secret.get_private_bytes().try_into().ok()
}

async fn init_didcomm_auth(
    config: &DaemonConfig,
    secrets: &ServerSecrets,
) -> (
    Option<affinidi_did_resolver_cache_sdk::DIDCacheClient>,
    Option<Arc<affinidi_tdk::secrets_resolver::ThreadedSecretsResolver>>,
) {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
    use tracing::debug;

    let server_did = match &config.server_did {
        Some(did) => did.clone(),
        None => return (None, None),
    };

    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e}");
            return (None, None);
        }
    };

    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    let kid = format!("{server_did}#key-0");
    if let Ok(secret) = Secret::from_multibase(&secrets.signing_key, Some(&kid)) {
        secrets_resolver.insert(secret).await;
        debug!(kid = %kid, "signing secret loaded");
    }

    let kid = format!("{server_did}#key-1");
    if let Ok(secret) = Secret::from_multibase(&secrets.key_agreement_key, Some(&kid)) {
        secrets_resolver.insert(secret).await;
        debug!(kid = %kid, "key-agreement secret loaded");
    }

    (Some(did_resolver), Some(Arc::new(secrets_resolver)))
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
        if let Some(ref store) = store {
            if let Ok(dids_ks) = store.keyspace("dids") {
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
                                health::info_msg(&format!(
                                    "Version count: {}",
                                    record.version_count
                                ));
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

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received SIGINT"),
        () = terminate => info!("received SIGTERM"),
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

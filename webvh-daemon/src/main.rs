mod config;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use axum::routing::get;
use clap::{Parser, Subcommand};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, error, info, warn};

use affinidi_webvh_common::server::config::init_tracing;
use affinidi_webvh_common::server::error::AppError;
use affinidi_webvh_common::server::init;
use affinidi_webvh_common::server::secret_store::ServerSecrets;
use affinidi_webvh_common::server::stats_collector::StatsCollector;
use affinidi_webvh_common::server::store::{KeyspaceHandle, Store};

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
    /// Bootstrap a DID for this server
    BootstrapDid {
        /// DID path/mnemonic (defaults to root ".well-known")
        #[arg(long, default_value = ".well-known")]
        path: String,
        /// Path to an existing did.jsonl file to import
        #[arg(long)]
        did_log: Option<PathBuf>,
        /// Path to an existing did-witness.json file to import (requires --did-log)
        #[arg(long)]
        did_witness: Option<PathBuf>,
        /// Witness service URL for requesting a proof
        #[arg(long)]
        witness_url: Option<String>,
        /// Witness ID to use when requesting a proof
        #[arg(long)]
        witness_id: Option<String>,
    },
    /// Recreate a DID at a given path
    RecreateDid {
        /// DID path/mnemonic to recreate
        #[arg(long)]
        path: String,
    },
    /// Recover a soft-deleted DID
    RecoverDid {
        /// DID path/mnemonic to recover
        #[arg(long)]
        path: String,
    },
    /// Load a DID from existing files
    LoadDid {
        /// Path to store the DID at
        #[arg(long)]
        path: String,
        /// Path to the did.jsonl file
        #[arg(long)]
        did_log: PathBuf,
        /// Optional did-witness.json file
        #[arg(long)]
        did_witness: Option<PathBuf>,
    },
    /// Import secrets from a VTA bundle or individual keys
    ImportSecrets {
        /// Base64url-encoded VTA secrets bundle
        #[arg(long, group = "source")]
        vta_bundle: Option<String>,
        /// Ed25519 signing key (multibase-encoded)
        #[arg(long, group = "source")]
        signing_key: Option<String>,
        /// X25519 key agreement key (multibase-encoded)
        #[arg(long)]
        ka_key: Option<String>,
        /// Ed25519 JWT signing key (multibase-encoded, auto-generated if omitted)
        #[arg(long)]
        jwt_key: Option<String>,
        /// VTA credential bundle (base64url-encoded)
        #[arg(long)]
        vta_credential: Option<String>,
        /// Overwrite existing secrets without prompting
        #[arg(long)]
        force: bool,
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
        Some(Command::Backup { output }) => {
            if let Err(e) = affinidi_webvh_server::backup::run_backup(cli.config, output).await {
                eprintln!("Backup error: {e}");
                std::process::exit(1);
            }
        }
        Some(Command::Restore { input }) => {
            if let Err(e) = affinidi_webvh_server::backup::run_restore(cli.config, input).await {
                eprintln!("Restore error: {e}");
                std::process::exit(1);
            }
        }
        None => run_daemon(cli.config).await,
    }
}

// ===========================================================================
// Daemon lifecycle
// ===========================================================================

async fn run_daemon(config_path: Option<PathBuf>) {
    let mut config = match DaemonConfig::load(config_path) {
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

    // ── Open stores ───────────────────────────────────────────────────
    // fjall locks the directory, so server/watcher/control share one handle.
    let main_store = Store::open(&config.store).await.unwrap_or_else(|e| {
        error!("failed to open main store: {e}");
        std::process::exit(1);
    });

    let witness_store = Store::open(&config.witness_store)
        .await
        .unwrap_or_else(|e| {
            error!("failed to open witness store: {e}");
            std::process::exit(1);
        });

    // Open keyspaces early — needed for bootstrap, stats seeding, and builders.
    let dids_ks = main_store.keyspace("dids").unwrap_or_else(|e| {
        error!("failed to open dids keyspace: {e}");
        std::process::exit(1);
    });
    let stats_ks = main_store.keyspace("stats").unwrap_or_else(|e| {
        error!("failed to open stats keyspace: {e}");
        std::process::exit(1);
    });

    // ── Phase 1: Pre-serve initialization ─────────────────────────────

    // 1a. DID store integrity check
    if config.enable.server {
        match dids_ks.verify_integrity().await {
            Ok(0) => debug!("store integrity check passed"),
            Ok(n) => warn!(
                corrupted = n,
                "store integrity check found corrupted entries"
            ),
            Err(e) => warn!(error = %e, "store integrity check failed"),
        }
    }

    // 1b. Auto-bootstrap root DID (if server enabled and public_url set)
    if config.enable.server {
        let server_config = config.server_config();
        let bootstrapped = affinidi_webvh_server::server::auto_bootstrap_dids(
            server_config,
            &main_store,
            &dids_ks,
            &secrets,
        )
        .await;
        // Propagate server_did if it was set by auto-bootstrap
        if config.server_did.is_none() && bootstrapped.server_did.is_some() {
            config.server_did = bootstrapped.server_did;
        }
    }

    // 1c. Seed stats collector from persisted store
    let stats_collector = {
        use affinidi_webvh_common::server::stats_collector::StatsAggregate;
        let collector = StatsCollector::new();
        let mut total_resolves = 0u64;
        let mut total_updates = 0u64;
        let mut last_resolved_at: Option<u64> = None;
        let mut last_updated_at: Option<u64> = None;
        if let Ok(raw) = stats_ks.prefix_iter_raw("stats:").await {
            for (_key, value) in raw {
                if let Ok(s) = serde_json::from_slice::<affinidi_webvh_common::DidStats>(&value) {
                    total_resolves += s.total_resolves;
                    total_updates += s.total_updates;
                    last_resolved_at = match (last_resolved_at, s.last_resolved_at) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    last_updated_at = match (last_updated_at, s.last_updated_at) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                }
            }
        }
        let total_dids = dids_ks
            .prefix_iter_raw("did:")
            .await
            .map(|v| v.len())
            .unwrap_or(0) as u64;
        collector.seed_aggregate(&StatsAggregate {
            total_dids,
            total_resolves,
            total_updates,
            last_resolved_at,
            last_updated_at,
        });
        info!(
            total_dids,
            total_resolves, total_updates, "stats collector seeded from store"
        );
        Arc::new(collector)
    };

    // ── Phase 2: Build service routers ────────────────────────────────

    let mut combined: Router = Router::new();
    let mut server_state: Option<affinidi_webvh_server::server::AppState> = None;

    let mut enabled_services = Vec::new();

    // HTTP client with timeouts (shared config for both server and control)
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HTTP client");

    // 2a. Server — public DID-serving routes only (.well-known)
    if config.enable.server {
        match build_server(
            &config,
            &secrets,
            &main_store,
            &stats_collector,
            &http_client,
        )
        .await
        {
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

    // 2b. Witness (nested at /witness)
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

    // 2c. Watcher (nested at /watcher)
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

    // 2d. Control plane — merged at root (no prefix)
    if config.enable.control {
        match build_control(
            &config,
            &secrets,
            &main_store,
            &stats_collector,
            &stats_ks,
            &http_client,
        )
        .await
        {
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
    combined = match server_state {
        Some(ref state) => combined.fallback({
            let state = state.clone();
            move |uri: Uri| {
                let state = state.clone();
                async move { daemon_fallback(state, uri).await }
            }
        }),
        None => {
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

    // ── Phase 3: Spawn background tasks ───────────────────────────────

    // 3a. Unified storage task (session cleanup, DID cleanup, stats flush, health checks)
    let (storage_shutdown_tx, storage_shutdown_rx) = watch::channel(false);
    let sessions_ks = main_store.keyspace("sessions").unwrap_or_else(|e| {
        error!("failed to open sessions keyspace: {e}");
        std::process::exit(1);
    });
    let registry_ks = main_store.keyspace("registry").unwrap_or_else(|e| {
        error!("failed to open registry keyspace: {e}");
        std::process::exit(1);
    });

    let storage_handle = tokio::spawn(run_daemon_storage_task(
        DaemonStorageParams {
            store: main_store.clone(),
            sessions_ks,
            dids_ks: dids_ks.clone(),
            registry_ks,
            stats_ks,
            auth_config: config.auth.clone(),
            registry_config: config.registry.clone(),
            has_auth: config.server_did.is_some(),
            collector: stats_collector.clone(),
            http: http_client,
        },
        storage_shutdown_rx,
    ));

    // 3b. DIDComm service (for VTA integration)
    let didcomm_shutdown = CancellationToken::new();
    let didcomm_service = if config.didcomm {
        if let Some(ref state) = server_state {
            match affinidi_webvh_server::server::start_didcomm_service(
                state,
                &secrets,
                didcomm_shutdown.clone(),
            )
            .await
            {
                Ok(Some(svc)) => Some(svc),
                Ok(None) => None,
                Err(e) => {
                    warn!("failed to start DIDComm service: {e}");
                    None
                }
            }
        } else {
            warn!("DIDComm enabled but server not enabled — skipping");
            None
        }
    } else {
        None
    };

    // ── Phase 4: Serve HTTP ───────────────────────────────────────────

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

    // ── Phase 5: Ordered shutdown ─────────────────────────────────────

    // 5a. Cancel DIDComm
    didcomm_shutdown.cancel();
    if let Some(svc) = didcomm_service {
        svc.shutdown().await;
        info!("DIDComm service stopped");
    }

    // 5b. Stop storage task (includes final flush + persist main_store)
    let _ = storage_shutdown_tx.send(true);
    match storage_handle.await {
        Ok(()) => info!("storage task stopped"),
        Err(e) => error!("storage task panicked: {e}"),
    }

    // 5c. Persist witness store (not managed by storage task)
    if let Err(e) = witness_store.persist().await {
        error!("failed to persist witness store: {e}");
    }

    info!("daemon shut down");
}

// ===========================================================================
// Unified storage task
// ===========================================================================

struct DaemonStorageParams {
    store: Store,
    sessions_ks: KeyspaceHandle,
    dids_ks: KeyspaceHandle,
    registry_ks: KeyspaceHandle,
    stats_ks: KeyspaceHandle,
    auth_config: affinidi_webvh_common::server::config::AuthConfig,
    registry_config: affinidi_webvh_control::config::RegistryConfig,
    has_auth: bool,
    collector: Arc<StatsCollector>,
    http: reqwest::Client,
}

async fn run_daemon_storage_task(
    params: DaemonStorageParams,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!("storage task started");

    let session_interval = Duration::from_secs(params.auth_config.session_cleanup_interval);
    let did_ttl_seconds = params.auth_config.cleanup_ttl_minutes * 60;
    let did_interval = Duration::from_secs(did_ttl_seconds.max(60));
    let health_interval = Duration::from_secs(params.registry_config.health_check_interval.max(10));
    let flush_interval = Duration::from_secs(10);

    let mut session_timer = tokio::time::interval(session_interval);
    let mut did_timer = tokio::time::interval(did_interval);
    let mut health_timer = tokio::time::interval(health_interval);
    let mut flush_timer = tokio::time::interval(flush_interval);

    // Skip first ticks (immediate)
    session_timer.tick().await;
    did_timer.tick().await;
    health_timer.tick().await;
    flush_timer.tick().await;

    loop {
        tokio::select! {
            _ = session_timer.tick(), if params.has_auth => {
                if let Err(e) = affinidi_webvh_common::server::auth::session::cleanup_expired_sessions(
                    &params.sessions_ks,
                    params.auth_config.challenge_ttl,
                ).await {
                    warn!("session cleanup error: {e}");
                }
            }
            _ = did_timer.tick() => {
                match affinidi_webvh_server::did_ops::cleanup_empty_dids(
                    &params.dids_ks,
                    did_ttl_seconds,
                ).await {
                    Ok(0) => {}
                    Ok(n) => {
                        info!(count = n, "cleaned up empty DID records");
                        for _ in 0..n {
                            params.collector.decrement_total_dids();
                        }
                    }
                    Err(e) => warn!("DID cleanup error: {e}"),
                }
            }
            _ = health_timer.tick() => {
                if let Err(e) = affinidi_webvh_control::server::run_health_checks(
                    &params.registry_ks,
                    &params.http,
                ).await {
                    warn!("health check error: {e}");
                }
            }
            _ = flush_timer.tick() => {
                if let Err(e) = affinidi_webvh_control::server::flush_stats_to_store(
                    &params.collector,
                    &params.stats_ks,
                    &params.dids_ks,
                    &params.store,
                ).await {
                    warn!("stats flush error: {e}");
                }
            }
            _ = shutdown_rx.changed() => {
                info!("storage task shutting down");
                break;
            }
        }
    }

    // Final flush before exit
    let _ = affinidi_webvh_control::server::flush_stats_to_store(
        &params.collector,
        &params.stats_ks,
        &params.dids_ks,
        &params.store,
    )
    .await;

    if let Err(e) = params.store.persist().await {
        error!("failed to persist main store on shutdown: {e}");
    } else {
        info!("main store persisted");
    }
}

// ===========================================================================
// Service builders
// ===========================================================================

type ServiceResult = Result<Router, AppError>;

/// Build the server — returns both the router and the AppState.
///
/// In daemon mode the server only exposes public DID-serving routes
/// (`.well-known`). All `/api/…` management routes come from the
/// control plane, which is merged at root.
async fn build_server(
    config: &DaemonConfig,
    secrets: &ServerSecrets,
    store: &Store,
    stats_collector: &Arc<StatsCollector>,
    http_client: &reqwest::Client,
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
        http_client: http_client.clone(),
        stats_collector: Some(stats_collector.clone()),
        did_cache: Arc::new(affinidi_webvh_server::cache::ContentCache::new(
            Duration::from_secs(300),
        )),
    };

    let router = affinidi_webvh_server::routes::router_public_only().with_state(state.clone());
    info!("server service initialized (public-only, daemon mode)");

    Ok((router, state))
}

async fn build_witness(
    config: &DaemonConfig,
    secrets: &ServerSecrets,
    store: &Store,
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

async fn build_watcher(config: &DaemonConfig, store: &Store) -> ServiceResult {
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
    store: &Store,
    stats_collector: &Arc<StatsCollector>,
    stats_ks: &KeyspaceHandle,
    http_client: &reqwest::Client,
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

    let mut state = AppState {
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
        http_client: http_client.clone(),
        atm: None,
        atm_profile: None,
        stats_collector: stats_collector.clone(),
        stats_ks: stats_ks.clone(),
    };

    // Seed registry from static config
    affinidi_webvh_control::server::seed_registry(&state).await;

    // Initialize outbound ATM for DIDComm sync push messages
    if config.didcomm {
        if let Some(ref control_did) = config.server_did {
            if let Some((atm, profile)) = affinidi_webvh_control::messaging::init_outbound_atm(
                &state.config,
                control_did,
                secrets,
            )
            .await
            {
                state.atm = Some(atm);
                state.atm_profile = Some(profile);
            }
        } else {
            warn!("DIDComm enabled but server_did not configured — outbound messaging disabled");
        }
    }

    // Build router without UI fallback — daemon adds its own combined fallback
    let router = affinidi_webvh_control::routes::router_without_fallback().with_state(state);
    info!("control plane service initialized");

    Ok(router)
}

// ===========================================================================
// Combined fallback: DID serving + SPA UI
// ===========================================================================

/// Fallback handler for the daemon's combined router.
///
/// Tries DID public serving first (e.g. `/{mnemonic}/did.jsonl`).
/// If that returns 404, falls through to the SPA static handler so that
/// paths like `/enroll` serve `index.html` for client-side routing.
async fn daemon_fallback(state: affinidi_webvh_server::server::AppState, uri: Uri) -> Response {
    let did_resp = affinidi_webvh_server::routes::did_public::serve_public(
        axum::extract::State(state),
        uri.clone(),
    )
    .await;

    if did_resp.status() != StatusCode::NOT_FOUND {
        return did_resp;
    }

    #[cfg(feature = "ui")]
    {
        affinidi_webvh_control::frontend::static_handler(uri).await
    }

    #[cfg(not(feature = "ui"))]
    {
        StatusCode::NOT_FOUND.into_response()
    }
}

// ===========================================================================
// Shared init helpers
// ===========================================================================

async fn load_secrets(config: &DaemonConfig) -> ServerSecrets {
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

// ===========================================================================
// CLI management commands
// ===========================================================================

async fn run_add_acl(
    config_path: Option<PathBuf>,
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

async fn run_list_acl(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_list_acl(&config.store).await
}

async fn run_remove_acl(
    config_path: Option<PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::load(config_path)?;
    affinidi_webvh_common::server::cli_acl::run_remove_acl(&config.store, did).await
}

async fn run_invite(
    config_path: Option<PathBuf>,
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

    let store = Store::open(&control_config.store).await?;
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

async fn run_bootstrap_did(
    config_path: Option<PathBuf>,
    mnemonic: String,
    did_log: Option<PathBuf>,
    did_witness: Option<PathBuf>,
    witness_url: Option<String>,
    witness_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use affinidi_webvh_server::bootstrap;

    if did_witness.is_some() && did_log.is_none() {
        return Err("--did-witness requires --did-log".into());
    }

    let config = DaemonConfig::load(config_path)?;
    let server_config = config.server_config();

    let public_url = server_config
        .public_url
        .as_deref()
        .ok_or("public_url must be set in config for bootstrap")?;

    let store = Store::open(&config.store).await?;
    let dids_ks = store.keyspace("dids")?;

    let did_key = affinidi_webvh_server::did_ops::did_key(&mnemonic);
    if dids_ks.contains_key(did_key).await? {
        eprintln!();
        eprintln!("  DID at path '{mnemonic}' already exists.");
        eprintln!("  No action taken.");
        eprintln!();
        return Ok(());
    }

    let result = if let Some(log_path) = did_log {
        let jsonl = std::fs::read_to_string(&log_path)
            .map_err(|e| format!("failed to read {}: {e}", log_path.display()))?;
        let witness_content = match &did_witness {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("failed to read {}: {e}", path.display()))?,
            ),
            None => None,
        };
        bootstrap::import_did_at_path(
            &store,
            &dids_ks,
            &mnemonic,
            &jsonl,
            witness_content.as_deref(),
        )
        .await?
    } else {
        let secret_store = affinidi_webvh_common::server::secret_store::create_secret_store(
            &config.secrets,
            &config.config_path,
        )?;
        let secrets = secret_store
            .get()
            .await?
            .ok_or("no secrets found — run setup first")?;

        let signing_secret = Secret::from_multibase(&secrets.signing_key, None)
            .map_err(|e| format!("invalid signing_key: {e}"))?;
        let ka_secret = Secret::from_multibase(&secrets.key_agreement_key, None).ok();

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
            let mut witness_client = WitnessClient::new(&w_url);
            if let Err(e) = witness_client
                .authenticate(&result.did_id, &signing_secret)
                .await
            {
                eprintln!("  Warning: witness authentication failed: {e}");
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
                }
            }
        }

        result
    };

    store.persist().await?;

    let url_path = if mnemonic == ".well-known" {
        ".well-known/did.jsonl".to_string()
    } else {
        format!("{mnemonic}/did.jsonl")
    };

    eprintln!();
    if mnemonic == ".well-known" {
        eprintln!("  Root DID bootstrapped!");
    } else {
        eprintln!("  DID bootstrapped at path '{mnemonic}'!");
    }
    eprintln!();
    eprintln!("  DID:   {}", result.did_id);
    eprintln!("  SCID:  {}", result.scid);
    eprintln!("  JSONL: {public_url}/{url_path}");
    eprintln!();

    Ok(())
}

async fn run_recreate_did(
    config_path: Option<PathBuf>,
    mnemonic: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use affinidi_webvh_server::bootstrap;

    let config = DaemonConfig::load(config_path)?;
    let config_file = config.config_path.clone();
    let server_config = config.server_config();

    let public_url = server_config
        .public_url
        .as_deref()
        .ok_or("public_url must be set in config")?;

    let store = Store::open(&config.store).await?;
    let dids_ks = store.keyspace("dids")?;

    // Delete existing DID at this path
    let did_key = affinidi_webvh_server::did_ops::did_key(&mnemonic);
    if dids_ks.contains_key(did_key.clone()).await? {
        dids_ks.remove(did_key).await?;
        dids_ks
            .remove(affinidi_webvh_server::did_ops::content_log_key(&mnemonic))
            .await?;
        dids_ks
            .remove(affinidi_webvh_server::did_ops::content_witness_key(
                &mnemonic,
            ))
            .await?;
        dids_ks
            .remove(affinidi_webvh_server::did_ops::owner_key(
                "system", &mnemonic,
            ))
            .await?;
        eprintln!("  Removed existing DID at path '{mnemonic}'");
    }

    let secret_store = affinidi_webvh_common::server::secret_store::create_secret_store(
        &config.secrets,
        &config.config_path,
    )?;
    let secrets = secret_store
        .get()
        .await?
        .ok_or("no secrets found — run setup first")?;

    let signing_secret = Secret::from_multibase(&secrets.signing_key, None)
        .map_err(|e| format!("invalid signing_key: {e}"))?;
    let ka_secret = Secret::from_multibase(&secrets.key_agreement_key, None).ok();

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

    affinidi_webvh_server::setup::update_server_did_in_config(&config_file, &result.did_id)?;

    eprintln!();
    eprintln!("  DID recreated at path '{mnemonic}'!");
    eprintln!();
    eprintln!("  DID:   {}", result.did_id);
    eprintln!("  SCID:  {}", result.scid);
    eprintln!("  config.toml updated with new server_did.");
    eprintln!();

    Ok(())
}

async fn run_recover_did(
    config_path: Option<PathBuf>,
    mnemonic: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::did_ops::DidRecord;

    let config = DaemonConfig::load(config_path)?;
    let store = Store::open(&config.store).await?;
    let dids_ks = store.keyspace("dids")?;

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
    store.persist().await?;

    eprintln!();
    eprintln!("  DID recovered at path '{mnemonic}'!");
    if let Some(ref did_id) = record.did_id {
        eprintln!("  DID: {did_id}");
    }
    eprintln!();

    Ok(())
}

async fn run_load_did(
    config_path: Option<PathBuf>,
    path: String,
    did_log: PathBuf,
    did_witness: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::load(config_path)?;
    let store = Store::open(&config.store).await?;
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

    let result = affinidi_webvh_server::bootstrap::import_did_at_path(
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

    let config = DaemonConfig::load(config_path)?;
    let secret_store = affinidi_webvh_common::server::secret_store::create_secret_store(
        &config.secrets,
        &config.config_path,
    )?;

    if !force && let Ok(Some(_)) = secret_store.get().await {
        return Err("secrets already exist — use --force to overwrite".into());
    }

    let (resolved_signing, resolved_ka, resolved_vta_cred) =
        if let Some(ref bundle_str) = vta_bundle {
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

    Secret::from_multibase(&resolved_signing, None)
        .map_err(|e| format!("invalid signing key: {e}"))?;
    Secret::from_multibase(&resolved_ka, None)
        .map_err(|e| format!("invalid key agreement key: {e}"))?;

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

    let server_secrets = ServerSecrets {
        signing_key: resolved_signing,
        key_agreement_key: resolved_ka,
        jwt_signing_key: resolved_jwt,
        vta_credential: resolved_vta_cred,
    };

    secret_store.set(&server_secrets).await?;

    eprintln!();
    eprintln!("  Secrets imported successfully!");
    eprintln!();

    Ok(())
}

// ===========================================================================
// CLI health check
// ===========================================================================

async fn run_health(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
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
    health::print_feature("didcomm", config.didcomm);

    // ── Secrets ────────────────────────────────────────────────────
    health::section("Secrets");
    health::check_secrets(&config.secrets, &config.config_path).await;

    // ── Per-service Stores ─────────────────────────────────────────
    if config.enable.server {
        health::section("Store (server)");
        let store = health::check_store(&config.store).await;

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

// ===========================================================================
// Health & banner
// ===========================================================================

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

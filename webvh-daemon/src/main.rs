mod config;

use axum::Extension;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
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
    /// Add an ACL entry (control plane store)
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
    /// List all ACL entries (control plane store)
    ListAcl,
    /// Remove an ACL entry (control plane store)
    RemoveAcl {
        /// DID to remove from the ACL
        #[arg(long)]
        did: String,
    },
    /// Create a passkey enrollment invite (control plane)
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

    // Server AppState needed for the combined DID-serving fallback
    let mut server_state: Option<affinidi_webvh_server::server::AppState> = None;

    // 1. Server (mounted at root — DID serving needs /)
    if config.enable.server {
        match build_server(&config, &secrets).await {
            Ok((router, store, state)) => {
                server_state = Some(state);
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

    // 4. Control plane (nested at /control, UI also served at /)
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

    // Combined fallback: try DID serving first, then UI static assets.
    // When server is enabled, unmatched paths check for DID documents before
    // falling through to the control plane UI. When only control is enabled,
    // the fallback serves the UI directly.
    #[cfg(feature = "ui")]
    if let Some(state) = server_state {
        combined = combined
            .layer(Extension(Arc::new(state)))
            .fallback(daemon_fallback_with_dids);
    } else {
        combined = combined.fallback(affinidi_webvh_control::frontend::static_handler);
    }

    #[cfg(not(feature = "ui"))]
    if let Some(state) = server_state {
        combined = combined
            .layer(Extension(Arc::new(state)))
            .fallback(daemon_fallback_dids_only);
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
type ServerServiceResult = Result<
    (
        Router,
        affinidi_webvh_common::server::store::Store,
        affinidi_webvh_server::server::AppState,
    ),
    AppError,
>;

async fn build_server(config: &DaemonConfig, secrets: &ServerSecrets) -> ServerServiceResult {
    use affinidi_webvh_common::server::stats_collector::StatsCollector;
    use affinidi_webvh_server::server::AppState;
    use affinidi_webvh_server::store::Store;
    use tracing::debug;

    let server_config = config.server_config();
    let upload_body_limit = server_config.limits.upload_body_limit;

    let store = Store::open(&server_config.store).await?;
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let dids_ks = store.keyspace("dids")?;

    // Integrity check on DID keyspace (matches standalone server behavior)
    match dids_ks.verify_integrity().await {
        Ok(0) => debug!("store integrity check passed"),
        Ok(n) => warn!(
            corrupted = n,
            "store integrity check found corrupted entries"
        ),
        Err(e) => warn!(error = %e, "store integrity check failed"),
    }

    // Auto-bootstrap DIDs (root DID, server_did verification, DID listing)
    let server_config = affinidi_webvh_server::server::auto_bootstrap_dids(
        server_config,
        &store,
        &dids_ks,
        secrets,
    )
    .await;

    // Re-initialize DIDComm auth after bootstrap (server_did may have been set)
    let (did_resolver, secrets_resolver) = init_didcomm_auth(config, secrets).await;
    let jwt_keys = init_jwt_keys(secrets);
    let signing_key_bytes = decode_signing_key(secrets);

    // Initialize stats collector with actual DID count
    let stats_collector = {
        let collector = StatsCollector::new();
        let total_dids = dids_ks
            .prefix_iter_raw("did:")
            .await
            .map(|v| v.len())
            .unwrap_or(0) as u64;
        collector.set_total_dids(total_dids);
        Arc::new(collector)
    };

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
        stats_collector: Some(stats_collector),
        did_cache: std::sync::Arc::new(affinidi_webvh_server::cache::ContentCache::new(
            std::time::Duration::from_secs(300),
        )),
    };

    // Use router without fallback — daemon adds a combined DID + UI fallback
    let router = affinidi_webvh_server::routes::router_without_fallback(upload_body_limit)
        .with_state(state.clone());
    info!("server service initialized");

    Ok((router, store, state))
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
// CLI management commands (operate on the control plane store)
// ---------------------------------------------------------------------------

async fn run_add_acl(
    config_path: Option<std::path::PathBuf>,
    did: String,
    role_str: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::acl::{AclEntry, Role, get_acl_entry, store_acl_entry};
    use affinidi_webvh_common::server::auth::session::now_epoch;

    let role = role_str
        .parse::<Role>()
        .map_err(|_| format!("invalid role '{role_str}': use 'admin' or 'owner'"))?;

    let config = DaemonConfig::load(config_path)?;
    let store = affinidi_webvh_common::server::store::Store::open(&config.control_store).await?;
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
    store.persist().await?;

    eprintln!();
    eprintln!("  ACL entry created!");
    eprintln!();
    eprintln!("  DID:  {did}");
    eprintln!("  Role: {role}");
    eprintln!();

    Ok(())
}

async fn run_list_acl(
    config_path: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::acl::list_acl_entries;

    let config = DaemonConfig::load(config_path)?;
    let store = affinidi_webvh_common::server::store::Store::open(&config.control_store).await?;
    let acl_ks = store.keyspace("acl")?;

    let entries = list_acl_entries(&acl_ks).await?;

    if entries.is_empty() {
        eprintln!();
        eprintln!("  No ACL entries found.");
        eprintln!();
        return Ok(());
    }

    eprintln!();
    eprintln!("  {:<50} {:<8} LABEL", "DID", "ROLE");
    eprintln!("  {}", "-".repeat(80));

    for entry in &entries {
        let label = entry.label.as_deref().unwrap_or("-");
        eprintln!("  {:<50} {:<8} {}", entry.did, entry.role, label);
    }

    eprintln!();
    eprintln!("  {} entries total", entries.len());
    eprintln!();

    Ok(())
}

async fn run_remove_acl(
    config_path: Option<std::path::PathBuf>,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::acl::{delete_acl_entry, get_acl_entry};

    let config = DaemonConfig::load(config_path)?;
    let store = affinidi_webvh_common::server::store::Store::open(&config.control_store).await?;
    let acl_ks = store.keyspace("acl")?;

    let existing = get_acl_entry(&acl_ks, &did).await?;
    if existing.is_none() {
        eprintln!();
        eprintln!("  No ACL entry found for {did}");
        eprintln!();
        return Ok(());
    }

    let entry = existing.unwrap();
    delete_acl_entry(&acl_ks, &did).await?;
    store.persist().await?;

    eprintln!();
    eprintln!("  ACL entry removed!");
    eprintln!();
    eprintln!("  DID:  {}", entry.did);
    eprintln!("  Role: {}", entry.role);
    eprintln!();

    Ok(())
}

async fn run_invite(
    config_path: Option<std::path::PathBuf>,
    did: String,
    role: String,
    ttl_hours: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::passkey::routes::create_enrollment_invite;

    let config = DaemonConfig::load(config_path)?;

    let base_url = config
        .public_url
        .as_deref()
        .ok_or("public_url must be set in config for enrollment invites")?;

    let enrollment_ttl = match ttl_hours {
        Some(hours) => hours * 3600,
        None => config.auth.passkey_enrollment_ttl,
    };

    let store = affinidi_webvh_common::server::store::Store::open(&config.control_store).await?;
    let sessions_ks = store.keyspace("sessions")?;

    let resp =
        create_enrollment_invite(&sessions_ks, base_url, enrollment_ttl, &did, &role).await?;

    store.persist().await?;

    eprintln!();
    eprintln!("  Enrollment invite created!");
    eprintln!();
    eprintln!("  DID:     {did}");
    eprintln!("  Role:    {role}");
    let ttl_display = enrollment_ttl / 3600;
    eprintln!("  Expires: in {ttl_display}h (epoch {})", resp.expires_at);
    eprintln!();
    eprintln!("  Enrollment URL:");
    eprintln!("  {}", resp.enrollment_url);
    eprintln!();

    Ok(())
}

async fn run_import_secrets(
    config_path: Option<std::path::PathBuf>,
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
    if affinidi_webvh_common::server::secret_store::is_plaintext_backend(&config.secrets) {
        eprintln!("  WARNING: secrets stored in plaintext — not for production use.");
        eprintln!();
    }

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
        let store = health::check_store(&config.server_store).await;

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
        health::section("Store (watcher)");
        health::check_store(&config.watcher_store).await;
    }

    if config.enable.control {
        health::section("Store (control)");
        health::check_store(&config.control_store).await;
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

// ---------------------------------------------------------------------------
// Combined daemon fallback handlers
// ---------------------------------------------------------------------------

/// Fallback when both server and UI are enabled: try DID serving, then UI.
#[cfg(feature = "ui")]
async fn daemon_fallback_with_dids(
    Extension(state): Extension<Arc<affinidi_webvh_server::server::AppState>>,
    uri: Uri,
) -> Response {
    let resp = affinidi_webvh_server::routes::did_public::serve_public(
        State((*state).clone()),
        uri.clone(),
    )
    .await;
    if resp.status() == StatusCode::NOT_FOUND {
        // DID not found — try serving UI static assets
        return affinidi_webvh_control::frontend::static_handler(uri).await;
    }
    resp
}

/// Fallback when server is enabled but UI is not: DID serving only.
#[cfg(not(feature = "ui"))]
async fn daemon_fallback_dids_only(
    Extension(state): Extension<Arc<affinidi_webvh_server::server::AppState>>,
    uri: Uri,
) -> Response {
    affinidi_webvh_server::routes::did_public::serve_public(State((*state).clone()), uri).await
}

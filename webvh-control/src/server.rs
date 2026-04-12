use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, ListenerConfig, RestartPolicy, RetryConfig,
};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use affinidi_webvh_common::server::auth::extractor::AuthState;
use affinidi_webvh_common::server::didcomm_profile::build_tdk_profile;
use affinidi_webvh_common::server::passkey::PasskeyState;
use affinidi_webvh_common::server::tasks::{cleanup_old_buckets, flush_stats_to_store};
use tokio_util::sync::CancellationToken;
use webauthn_rs::prelude::Webauthn;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::messaging;
use crate::registry::{self, ServiceStatus};
use crate::routes;
use crate::secret_store::ServerSecrets;
use crate::store::{KeyspaceHandle, Store};
use tokio::sync::{oneshot, watch};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub registry_ks: KeyspaceHandle,
    pub dids_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub webauthn: Option<Arc<Webauthn>>,
    pub http_client: reqwest::Client,
    /// ATM instance for outbound mediator-based DIDComm messaging (None if not configured).
    pub atm: Option<Arc<ATM>>,
    /// ATM profile for the control plane's outbound mediator connection.
    pub atm_profile: Option<Arc<ATMProfile>>,
    /// In-memory stats collector — accumulates per-DID deltas from servers,
    /// flushed periodically to the stats keyspace.
    pub stats_collector: Arc<affinidi_webvh_common::server::stats_collector::StatsCollector>,
    /// Stats keyspace for persistent per-DID stats.
    pub stats_ks: KeyspaceHandle,
}

impl AppState {
    /// Unwrap the DIDComm auth components, returning an error if any are not configured.
    pub fn require_didcomm_auth(
        &self,
    ) -> Result<(&DIDCacheClient, &ThreadedSecretsResolver, &JwtKeys), AppError> {
        let did_resolver = self
            .did_resolver
            .as_ref()
            .ok_or_else(|| AppError::Authentication("DID resolver not configured".into()))?;
        let secrets_resolver = self
            .secrets_resolver
            .as_ref()
            .ok_or_else(|| AppError::Authentication("secrets resolver not configured".into()))?;
        let jwt_keys = self
            .jwt_keys
            .as_ref()
            .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))?;
        Ok((did_resolver, secrets_resolver.as_ref(), jwt_keys.as_ref()))
    }
}

impl AuthState for AppState {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>> {
        self.jwt_keys.as_ref()
    }

    fn sessions_ks(&self) -> &KeyspaceHandle {
        &self.sessions_ks
    }
}

impl PasskeyState for AppState {
    fn webauthn(&self) -> Option<&Arc<Webauthn>> {
        self.webauthn.as_ref()
    }

    fn acl_ks(&self) -> &KeyspaceHandle {
        &self.acl_ks
    }

    fn access_token_expiry(&self) -> u64 {
        self.config.auth.access_token_expiry
    }

    fn refresh_token_expiry(&self) -> u64 {
        self.config.auth.refresh_token_expiry
    }

    fn public_url(&self) -> Option<&str> {
        self.config.public_url.as_deref()
    }

    fn enrollment_ttl(&self) -> u64 {
        self.config.auth.passkey_enrollment_ttl
    }
}

pub async fn run(config: AppConfig, store: Store, secrets: ServerSecrets) -> Result<(), AppError> {
    // Open keyspace handles
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let registry_ks = store.keyspace("registry")?;
    let dids_ks = store.keyspace("dids")?;
    let stats_ks = store.keyspace("stats")?;

    // Initialize DIDComm auth infrastructure (requires server_did)
    let (did_resolver, secrets_resolver) = init_didcomm_auth(&config, &secrets).await;

    // Initialize JWT keys
    let jwt_keys = init_jwt_keys(&secrets);

    // Initialize WebAuthn for passkeys
    let webauthn = config.public_url.as_ref().and_then(|url| {
        match affinidi_webvh_common::server::passkey::build_webauthn(url) {
            Ok(w) => {
                info!("WebAuthn (passkey) auth enabled");
                Some(Arc::new(w))
            }
            Err(e) => {
                warn!("WebAuthn initialization failed: {e} — passkey auth disabled");
                None
            }
        }
    });

    // Bind TCP listener on the main thread
    let std_listener = if config.features.rest_api {
        let addr = format!("{}:{}", config.server.host, config.server.port);
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("control plane listening addr={addr}");
        Some(listener)
    } else {
        None
    };

    // Gather storage thread inputs before moving config into Arc
    let storage_sessions_ks = sessions_ks.clone();
    let storage_registry_ks = registry_ks.clone();
    let storage_auth_config = config.auth.clone();
    let storage_registry_config = config.registry.clone();
    let has_auth = jwt_keys.is_some();

    let stats_dids_ks = dids_ks.clone();
    let mut state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        registry_ks,
        dids_ks,
        config: Arc::new(config),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        webauthn,
        http_client: reqwest::Client::new(),
        atm: None,
        atm_profile: None,
        stats_collector: {
            use affinidi_webvh_common::server::stats_collector::{StatsAggregate, StatsCollector};
            let collector = StatsCollector::new();
            // Seed aggregate from stored per-DID stats
            let mut total_resolves = 0u64;
            let mut total_updates = 0u64;
            let mut last_resolved_at: Option<u64> = None;
            let mut last_updated_at: Option<u64> = None;
            if let Ok(raw) = stats_ks.prefix_iter_raw("stats:").await {
                for (_key, value) in raw {
                    if let Ok(s) = serde_json::from_slice::<affinidi_webvh_common::DidStats>(&value)
                    {
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
            let total_dids = stats_dids_ks
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
        },
        stats_ks: stats_ks.clone(),
    };

    // Seed registry from static config
    seed_registry(&state).await;

    // Initialize outbound ATM connection for sync push messages
    if state.config.features.didcomm {
        if let Some(ref control_did) = state.config.server_did {
            if let Some((atm, profile)) =
                messaging::init_outbound_atm(&state.config, control_did, &secrets).await
            {
                state.atm = Some(atm);
                state.atm_profile = Some(profile);
            }
        } else {
            warn!("DIDComm enabled but server_did not configured — messaging disabled");
        }
    }

    // Log startup configuration
    info!("--- enabled services ---");
    info!(
        "  REST API : {}",
        if state.config.features.rest_api {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        "  DIDComm  : {}",
        if state.atm.is_some() {
            "enabled (mediator connected)"
        } else {
            "disabled"
        }
    );
    if let Some(ref url) = state.config.public_url {
        info!("  public URL   : {url}");
    }
    if let Some(ref did) = state.config.server_did {
        info!("  control DID  : {did}");
    }
    if let Some(ref did) = state.config.mediator_did {
        info!("  mediator DID : {did}");
    }

    // Shutdown channels
    let (rest_shutdown_tx, rest_shutdown_rx) = watch::channel(false);
    let (storage_shutdown_tx, storage_shutdown_rx) = watch::channel(false);
    let (rest_ready_tx, rest_ready_rx) = oneshot::channel::<()>();

    // 1. Spawn REST thread
    let rest_handle = if let Some(listener) = std_listener {
        let mut rest_shutdown = rest_shutdown_rx.clone();
        let rest_state = state.clone();
        Some(
            std::thread::Builder::new()
                .name("control-rest".into())
                .spawn(move || {
                    run_rest_thread(listener, rest_state, &mut rest_shutdown, rest_ready_tx)
                })
                .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?,
        )
    } else {
        let _ = rest_ready_tx.send(());
        None
    };

    // 2. Spawn storage thread (cleanup + health checks + stats flush)
    let mut storage_shutdown = storage_shutdown_rx.clone();
    let storage_http = state.http_client.clone();
    let storage_stats_ks = state.stats_ks.clone();
    let storage_dids_ks = state.dids_ks.clone();
    let storage_collector = state.stats_collector.clone();
    let storage_handle = std::thread::Builder::new()
        .name("control-storage".into())
        .spawn(move || {
            run_storage_thread(
                StorageThreadParams {
                    store,
                    sessions_ks: storage_sessions_ks,
                    registry_ks: storage_registry_ks,
                    stats_ks: storage_stats_ks,
                    dids_ks: storage_dids_ks,
                    auth_config: storage_auth_config,
                    registry_config: storage_registry_config,
                    has_auth,
                    http: storage_http,
                    collector: storage_collector,
                },
                &mut storage_shutdown,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // Wait for REST to be ready before starting DIDComm
    let _ = rest_ready_rx.await;

    // 3. Start DIDComm service for inbound messages
    let didcomm_shutdown = CancellationToken::new();
    let didcomm_service = if state.config.features.didcomm {
        match start_didcomm_service(&state, &secrets, didcomm_shutdown.clone()).await {
            Ok(Some(svc)) => Some(svc),
            Ok(None) => None,
            Err(e) => {
                warn!("failed to start DIDComm service: {e}");
                None
            }
        }
    } else {
        None
    };

    // Wait for shutdown signal
    shutdown_signal().await;

    // Ordered shutdown: DIDComm → REST → Storage
    let mut any_panic = false;

    didcomm_shutdown.cancel();
    if let Some(svc) = didcomm_service {
        svc.shutdown().await;
        info!("DIDComm service stopped");
    }

    let _ = rest_shutdown_tx.send(true);
    if let Some(handle) = rest_handle {
        match tokio::task::spawn_blocking(move || handle.join()).await {
            Ok(Ok(())) => info!("REST thread stopped"),
            Ok(Err(_)) => {
                error!("REST thread panicked");
                any_panic = true;
            }
            Err(e) => {
                error!("failed to join REST thread: {e}");
                any_panic = true;
            }
        }
    }

    let _ = storage_shutdown_tx.send(true);
    match tokio::task::spawn_blocking(move || storage_handle.join()).await {
        Ok(Ok(())) => info!("storage thread stopped"),
        Ok(Err(_)) => {
            error!("storage thread panicked");
            any_panic = true;
        }
        Err(e) => {
            error!("failed to join storage thread: {e}");
            any_panic = true;
        }
    }

    if any_panic {
        return Err(AppError::Internal("one or more threads panicked".into()));
    }

    info!("control plane shut down");
    Ok(())
}

// ---------------------------------------------------------------------------
// DIDComm service startup (inbound)
// ---------------------------------------------------------------------------

async fn start_didcomm_service(
    state: &AppState,
    secrets: &ServerSecrets,
    shutdown: CancellationToken,
) -> Result<Option<DIDCommService>, AppError> {
    let control_did = match &state.config.server_did {
        Some(did) => did.as_str(),
        None => {
            info!("DIDComm not configured — server_did not set");
            return Ok(None);
        }
    };

    let mediator_did = match &state.config.mediator_did {
        Some(did) => did.as_str(),
        None => {
            info!("mediator_did not configured — DIDComm messaging disabled");
            return Ok(None);
        }
    };

    let profile = build_tdk_profile(
        "control",
        control_did,
        Some(mediator_did),
        secrets,
        state.did_resolver.as_ref(),
    )
    .await?;

    let listener = ListenerConfig {
        id: "control".into(),
        profile,
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        ..Default::default()
    };

    let router = messaging::build_control_router()
        .map_err(|e| AppError::Internal(format!("failed to build DIDComm router: {e}")))?;

    let svc = DIDCommService::start(
        DIDCommServiceConfig {
            listeners: vec![listener],
        },
        router,
        shutdown,
    )
    .await
    .map_err(|e| AppError::Internal(format!("failed to start DIDComm service: {e}")))?;

    info!("DIDComm service started for {control_did}");
    Ok(Some(svc))
}

// ---------------------------------------------------------------------------
// Registry seeding
// ---------------------------------------------------------------------------

/// Seed the registry with statically configured instances.
async fn seed_registry(state: &AppState) {
    for instance_config in &state.config.registry.instances {
        let service_type = match instance_config.service_type.as_str() {
            "server" => registry::ServiceType::Server,
            "witness" => registry::ServiceType::Witness,
            "watcher" => registry::ServiceType::Watcher,
            other => {
                warn!(service_type = %other, "unknown service type in registry config, skipping");
                continue;
            }
        };

        let instance_id = uuid::Uuid::new_v4().to_string();
        let instance = registry::ServiceInstance {
            instance_id,
            service_type,
            label: instance_config.label.clone(),
            url: instance_config.url.clone(),
            status: ServiceStatus::Active,
            last_health_check: None,
            registered_at: crate::auth::session::now_epoch(),
            metadata: serde_json::Value::Null,
        };

        if let Err(e) = registry::register_instance(&state.registry_ks, &instance).await {
            warn!(url = %instance_config.url, error = %e, "failed to seed registry instance");
        } else {
            info!(
                url = %instance_config.url,
                service_type = %instance_config.service_type,
                "seeded registry instance"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// REST thread
// ---------------------------------------------------------------------------

fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
    ready_tx: oneshot::Sender<()>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        info!("REST thread started");

        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert std TcpListener to tokio TcpListener");

        let app = routes::router()
            .with_state(state)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                    .on_response(
                        DefaultOnResponse::new()
                            .level(Level::DEBUG)
                            .latency_unit(tower_http::LatencyUnit::Millis),
                    ),
            )
            .layer(axum::middleware::from_fn(
                affinidi_webvh_common::server::security_headers,
            ));

        let _ = ready_tx.send(());

        let mut rx = shutdown_rx.clone();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.changed().await;
            })
            .await
            .expect("axum serve failed");

        info!("REST thread shutting down");
    });
}

// ---------------------------------------------------------------------------
// Storage thread
// ---------------------------------------------------------------------------

struct StorageThreadParams {
    store: Store,
    sessions_ks: KeyspaceHandle,
    registry_ks: KeyspaceHandle,
    stats_ks: KeyspaceHandle,
    dids_ks: KeyspaceHandle,
    auth_config: AuthConfig,
    registry_config: crate::config::RegistryConfig,
    has_auth: bool,
    http: reqwest::Client,
    collector: Arc<affinidi_webvh_common::server::stats_collector::StatsCollector>,
}

fn run_storage_thread(params: StorageThreadParams, shutdown_rx: &mut watch::Receiver<bool>) {
    let StorageThreadParams {
        store,
        sessions_ks,
        registry_ks,
        stats_ks,
        dids_ks,
        auth_config,
        registry_config,
        has_auth,
        http,
        collector,
    } = params;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");

        let session_interval = Duration::from_secs(auth_config.session_cleanup_interval);
        let health_interval = Duration::from_secs(registry_config.health_check_interval.max(10));
        let flush_interval = Duration::from_secs(10);
        let cleanup_interval = Duration::from_secs(3600); // 1 hour

        let mut session_timer = tokio::time::interval(session_interval);
        let mut health_timer = tokio::time::interval(health_interval);
        let mut flush_timer = tokio::time::interval(flush_interval);
        let mut cleanup_timer = tokio::time::interval(cleanup_interval);

        // Skip first tick (immediate)
        session_timer.tick().await;
        health_timer.tick().await;
        flush_timer.tick().await;
        cleanup_timer.tick().await;

        loop {
            tokio::select! {
                _ = session_timer.tick(), if has_auth => {
                    if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
                        warn!("session cleanup error: {e}");
                    }
                }
                _ = health_timer.tick() => {
                    if let Err(e) = run_health_checks(&registry_ks, &http).await {
                        warn!("health check error: {e}");
                    }
                }
                _ = flush_timer.tick() => {
                    if let Err(e) = flush_stats_to_store(&collector, &stats_ks, &dids_ks, &store).await {
                        warn!("stats flush error: {e}");
                    }
                }
                _ = cleanup_timer.tick() => {
                    match cleanup_old_buckets(&stats_ks).await {
                        Ok(0) => {}
                        Ok(n) => info!(removed = n, "cleaned up old time-series buckets"),
                        Err(e) => warn!("bucket cleanup error: {e}"),
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("storage thread shutting down");
                    break;
                }
            }
        }

        // Final flush before shutdown
        let _ = flush_stats_to_store(&collector, &stats_ks, &dids_ks, &store).await;

        if let Err(e) = store.persist().await {
            error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
}

/// Run health checks against all registered instances in parallel.
async fn run_health_checks(
    registry_ks: &KeyspaceHandle,
    http: &reqwest::Client,
) -> Result<(), AppError> {
    let instances = registry::list_instances(registry_ks).await?;
    let now = crate::auth::session::now_epoch();

    // Run all health checks concurrently
    let mut handles = Vec::with_capacity(instances.len());
    for inst in instances {
        let http = http.clone();
        handles.push(tokio::spawn(async move {
            let new_status = registry::health_check(&http, &inst).await;
            (inst, new_status)
        }));
    }

    for handle in handles {
        if let Ok((inst, new_status)) = handle.await {
            if new_status != inst.status {
                info!(
                    instance_id = %inst.instance_id,
                    url = %inst.url,
                    old_status = ?inst.status,
                    new_status = ?new_status,
                    "instance status changed"
                );
            }
            registry::update_instance_status(registry_ks, &inst.instance_id, new_status, now)
                .await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Auth initialization
// ---------------------------------------------------------------------------

fn init_jwt_keys(secrets: &ServerSecrets) -> Option<Arc<JwtKeys>> {
    match decode_multibase_ed25519_key(&secrets.jwt_signing_key) {
        Ok(key_bytes) => match JwtKeys::from_ed25519_bytes(&key_bytes) {
            Ok(keys) => {
                debug!("JWT signing key loaded");
                Some(Arc::new(keys))
            }
            Err(e) => {
                warn!("failed to construct JWT keys: {e} — auth endpoints will not work");
                None
            }
        },
        Err(e) => {
            warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
            None
        }
    }
}

async fn init_didcomm_auth(
    config: &AppConfig,
    secrets: &ServerSecrets,
) -> (Option<DIDCacheClient>, Option<Arc<ThreadedSecretsResolver>>) {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let server_did = match &config.server_did {
        Some(did) => did.clone(),
        None => {
            warn!("server_did not configured — DIDComm auth endpoints will not work");
            return (None, None);
        }
    };

    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — DIDComm auth endpoints will not work");
            return (None, None);
        }
    };

    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    let kid = format!("{server_did}#key-0");
    match Secret::from_multibase(&secrets.signing_key, Some(&kid)) {
        Ok(secret) => {
            secrets_resolver.insert(secret).await;
            debug!(kid = %kid, "server signing secret loaded");
        }
        Err(e) => warn!("failed to decode signing_key: {e}"),
    }

    let kid = format!("{server_did}#key-1");
    match Secret::from_multibase(&secrets.key_agreement_key, Some(&kid)) {
        Ok(secret) => {
            secrets_resolver.insert(secret).await;
            debug!(kid = %kid, "server key-agreement secret loaded");
        }
        Err(e) => warn!("failed to decode key_agreement_key: {e}"),
    }

    info!("DIDComm auth initialized for DID {server_did}");

    (Some(did_resolver), Some(Arc::new(secrets_resolver)))
}

pub(crate) fn decode_multibase_ed25519_key(multibase_key: &str) -> Result<[u8; 32], AppError> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let secret = Secret::from_multibase(multibase_key, None)
        .map_err(|e| AppError::Config(format!("invalid multibase key: {e}")))?;

    let bytes = secret.get_private_bytes();
    bytes
        .try_into()
        .map_err(|_| AppError::Config("key must be exactly 32 bytes".into()))
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

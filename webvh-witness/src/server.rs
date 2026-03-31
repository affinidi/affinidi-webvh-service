use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, ListenerConfig, RestartPolicy, RetryConfig,
};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use affinidi_webvh_common::server::auth::extractor::AuthState;
use affinidi_webvh_common::server::didcomm_profile::build_tdk_profile;
use tokio_util::sync::CancellationToken;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::error::AppError;
use crate::messaging;
use crate::routes;
use crate::secret_store::ServerSecrets;
use crate::signing::{LocalSigner, WitnessSigner};
use crate::store::{KeyspaceHandle, Store};
use axum::routing::get;
use tokio::sync::{oneshot, watch};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, error, info, warn};

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub store: Store,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub witnesses_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub signer: Arc<dyn WitnessSigner>,
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

pub async fn run(config: AppConfig, store: Store, secrets: ServerSecrets) -> Result<(), AppError> {
    // Open keyspace handles
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let witnesses_ks = store.keyspace("witnesses")?;

    // Initialize DIDComm auth infrastructure (requires server_did)
    let (did_resolver, secrets_resolver) = init_didcomm_auth(&config, &secrets).await;

    // Initialize JWT keys
    let jwt_keys = init_jwt_keys(&secrets);

    // Bind TCP listener on the main thread for early port validation
    let std_listener = if config.features.rest_api {
        let addr = format!("{}:{}", config.server.host, config.server.port);
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("server listening addr={addr}");
        Some(listener)
    } else {
        None
    };

    // Gather storage thread inputs before moving config into Arc
    let storage_sessions_ks = sessions_ks.clone();
    let storage_auth_config = config.auth.clone();
    let has_auth = jwt_keys.is_some();

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        witnesses_ks,
        config: Arc::new(config),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        signer: Arc::new(LocalSigner),
    };

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
        if state.config.features.didcomm {
            "enabled"
        } else {
            "disabled"
        }
    );
    if let Some(ref did) = state.config.server_did {
        info!("  server DID   : {did}");
    }
    if let Some(ref did) = state.config.mediator_did {
        info!("  mediator DID : {did}");
    }

    // Separate shutdown channels for ordered shutdown (DIDComm -> REST -> Storage)
    let (rest_shutdown_tx, rest_shutdown_rx) = watch::channel(false);
    let (storage_shutdown_tx, storage_shutdown_rx) = watch::channel(false);

    // REST ready signal — DIDComm waits for this before starting
    let (rest_ready_tx, rest_ready_rx) = oneshot::channel::<()>();

    // 1. Spawn REST thread
    let rest_handle = if let Some(listener) = std_listener {
        let mut rest_shutdown = rest_shutdown_rx.clone();
        let rest_state = state.clone();
        Some(
            std::thread::Builder::new()
                .name("witness-rest".into())
                .spawn(move || {
                    run_rest_thread(listener, rest_state, &mut rest_shutdown, rest_ready_tx)
                })
                .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?,
        )
    } else {
        let _ = rest_ready_tx.send(());
        None
    };

    // 2. Spawn storage thread
    let mut storage_shutdown = storage_shutdown_rx.clone();
    let storage_handle = std::thread::Builder::new()
        .name("witness-storage".into())
        .spawn(move || {
            run_storage_thread(
                store,
                storage_sessions_ks,
                storage_auth_config,
                has_auth,
                &mut storage_shutdown,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // 3. Wait for REST, then start DIDComm service
    let _ = rest_ready_rx.await;

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

    // Ordered shutdown: DIDComm -> REST -> Storage
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

    info!("server shut down");
    Ok(())
}

// ---------------------------------------------------------------------------
// DIDComm service startup
// ---------------------------------------------------------------------------

async fn start_didcomm_service(
    state: &AppState,
    secrets: &ServerSecrets,
    shutdown: CancellationToken,
) -> Result<Option<DIDCommService>, AppError> {
    let server_did = match &state.config.server_did {
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
        "witness",
        server_did,
        Some(mediator_did),
        secrets,
        state.did_resolver.as_ref(),
    )
    .await?;

    let listener = ListenerConfig {
        id: "witness".into(),
        profile,
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        ..Default::default()
    };

    let router = messaging::build_witness_router(state.clone())
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

    info!("DIDComm service started for {server_did}");
    Ok(Some(svc))
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
            ))
            .route("/api/health", get(routes::health::health));

        let _ = ready_tx.send(());

        let shutdown_rx = shutdown_rx.clone();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let mut rx = shutdown_rx;
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

fn run_storage_thread(
    store: Store,
    sessions_ks: KeyspaceHandle,
    auth_config: AuthConfig,
    has_auth: bool,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");

        let session_interval = Duration::from_secs(auth_config.session_cleanup_interval);
        let mut session_timer = tokio::time::interval(session_interval);
        session_timer.tick().await; // skip first immediate tick

        loop {
            tokio::select! {
                _ = session_timer.tick(), if has_auth => {
                    if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
                        warn!("session cleanup error: {e}");
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("storage thread shutting down");
                    break;
                }
            }
        }

        if let Err(e) = store.persist().await {
            error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
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

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};

use webauthn_rs::prelude::Webauthn;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::did_ops::cleanup_empty_dids;
use crate::error::AppError;
use crate::messaging;
use crate::passkey;
use crate::routes;
use crate::secret_store::ServerSecrets;
use crate::stats;
use crate::store::{KeyspaceHandle, Store};
use tokio::sync::{oneshot, watch};
use axum::routing::get;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub dids_ks: KeyspaceHandle,
    pub stats_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub webauthn: Option<Arc<Webauthn>>,
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

pub async fn run(
    config: AppConfig,
    store: Store,
    secrets: ServerSecrets,
) -> Result<(), AppError> {
    // Open keyspace handles
    let sessions_ks = store.keyspace("sessions")?;
    let acl_ks = store.keyspace("acl")?;
    let dids_ks = store.keyspace("dids")?;
    let stats_ks = store.keyspace("stats")?;

    // Initialize DIDComm auth infrastructure (requires server_did)
    let (did_resolver, secrets_resolver) = init_didcomm_auth(&config, &secrets).await;

    // Initialize JWT keys independently — needed by both DIDComm and passkey auth
    let jwt_keys = init_jwt_keys(&secrets);

    // Initialize passkey/WebAuthn if public_url is configured
    let webauthn = config.public_url.as_ref().and_then(|url| {
        match passkey::build_webauthn(url) {
            Ok(w) => {
                info!("passkey auth enabled (rp_origin={})", url);
                Some(Arc::new(w))
            }
            Err(e) => {
                warn!("passkey auth disabled: {e}");
                None
            }
        }
    });

    // Bind TCP listener on the main thread for early port validation (only if REST is enabled)
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
    let storage_dids_ks = dids_ks.clone();
    let storage_stats_ks = stats_ks.clone();
    let storage_auth_config = config.auth.clone();
    let has_auth = jwt_keys.is_some();

    let upload_body_limit = config.limits.upload_body_limit;

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        dids_ks,
        stats_ks,
        config: Arc::new(config),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        webauthn,
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
    if let Some(ref url) = state.config.public_url {
        info!("  public URL   : {url}");
    }
    if let Some(ref did) = state.config.server_did {
        info!("  server DID   : {did}");
    }
    if let Some(ref did) = state.config.mediator_did {
        info!("  mediator DID : {did}");
    }

    // Separate shutdown channels for ordered shutdown (DIDComm → REST → Storage)
    let (rest_shutdown_tx, rest_shutdown_rx) = watch::channel(false);
    let (didcomm_shutdown_tx, didcomm_shutdown_rx) = watch::channel(false);
    let (storage_shutdown_tx, storage_shutdown_rx) = watch::channel(false);

    // REST ready signal — DIDComm thread waits for this before starting
    let (rest_ready_tx, rest_ready_rx) = oneshot::channel::<()>();

    // 1. Spawn REST thread first — HTTP must be available before DIDComm starts
    let rest_handle = if let Some(listener) = std_listener {
        let mut rest_shutdown = rest_shutdown_rx.clone();
        let rest_state = state.clone();
        Some(
            std::thread::Builder::new()
                .name("webvh-rest".into())
                .spawn(move || {
                    run_rest_thread(
                        listener,
                        rest_state,
                        upload_body_limit,
                        &mut rest_shutdown,
                        rest_ready_tx,
                    )
                })
                .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?,
        )
    } else {
        // Signal ready immediately so DIDComm doesn't wait forever
        let _ = rest_ready_tx.send(());
        None
    };

    // 2. Spawn storage thread (independent cleanup, can run alongside REST)
    let mut storage_shutdown = storage_shutdown_rx.clone();
    let storage_handle = std::thread::Builder::new()
        .name("webvh-storage".into())
        .spawn(move || {
            run_storage_thread(
                store,
                storage_sessions_ks,
                storage_dids_ks,
                storage_stats_ks,
                storage_auth_config,
                has_auth,
                &mut storage_shutdown,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // 3. Wait for REST to be serving (or immediate if REST disabled) before starting DIDComm
    let _ = rest_ready_rx.await;

    let didcomm_handle = if state.config.features.didcomm {
        let mut didcomm_shutdown = didcomm_shutdown_rx.clone();
        let didcomm_state = state.clone();
        let didcomm_secrets = secrets;
        Some(
            std::thread::Builder::new()
                .name("webvh-didcomm".into())
                .spawn(move || {
                    run_didcomm_thread(didcomm_state, didcomm_secrets, &mut didcomm_shutdown)
                })
                .map_err(|e| {
                    AppError::Internal(format!("failed to spawn DIDComm thread: {e}"))
                })?,
        )
    } else {
        None
    };

    // Wait for shutdown signal
    shutdown_signal().await;

    // Ordered shutdown: DIDComm → REST → Storage
    let mut any_panic = false;

    let _ = didcomm_shutdown_tx.send(true);
    if let Some(handle) = didcomm_handle {
        match tokio::task::spawn_blocking(move || handle.join()).await {
            Ok(Ok(())) => info!("DIDComm thread stopped"),
            Ok(Err(_panic)) => {
                error!("DIDComm thread panicked");
                any_panic = true;
            }
            Err(e) => {
                error!("failed to join DIDComm thread: {e}");
                any_panic = true;
            }
        }
    }

    let _ = rest_shutdown_tx.send(true);
    if let Some(handle) = rest_handle {
        match tokio::task::spawn_blocking(move || handle.join()).await {
            Ok(Ok(())) => info!("REST thread stopped"),
            Ok(Err(_panic)) => {
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
        Ok(Err(_panic)) => {
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
// REST thread
// ---------------------------------------------------------------------------

/// REST thread: serves the Axum HTTP server.
///
/// Sends a signal on `ready_tx` once the router is built and `axum::serve` is
/// about to start accepting connections. The main thread waits for this before
/// spawning the DIDComm thread.
fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
    upload_body_limit: usize,
    shutdown_rx: &mut watch::Receiver<bool>,
    ready_tx: oneshot::Sender<()>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        info!("REST thread started");

        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert std TcpListener to tokio TcpListener");

        let app = routes::router(upload_body_limit)
            .with_state(state)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(
                        DefaultOnResponse::new()
                            .level(Level::INFO)
                            .latency_unit(tower_http::LatencyUnit::Millis),
                    ),
            )
            // Health route mounted after the TraceLayer so it bypasses tracing
            .route("/api/health", get(routes::health::health));

        // Signal that REST is ready to serve
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
// DIDComm thread
// ---------------------------------------------------------------------------

/// DIDComm thread: connects to the mediator and processes inbound messages.
fn run_didcomm_thread(
    state: AppState,
    secrets: ServerSecrets,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build DIDComm runtime");

    rt.block_on(async {
        info!("DIDComm thread started");

        // Check preconditions
        let server_did = match &state.config.server_did {
            Some(did) => did.as_str(),
            None => {
                info!("DIDComm not configured — server_did not set, thread idle");
                let _ = shutdown_rx.changed().await;
                info!("DIDComm thread shutting down (idle)");
                return;
            }
        };

        // Initialize ATM connection
        let (atm, profile) =
            match messaging::init_didcomm_connection(&state.config, server_did, &secrets).await {
                Some(handles) => handles,
                None => {
                    let _ = shutdown_rx.changed().await;
                    info!("DIDComm thread shutting down (init failed)");
                    return;
                }
            };

        // Run message loop until shutdown
        messaging::run_didcomm_loop(&atm, &profile, server_did, &state, shutdown_rx).await;

        info!("DIDComm thread shutting down");
    });
}

// ---------------------------------------------------------------------------
// Storage thread
// ---------------------------------------------------------------------------

/// Storage thread: runs cleanup loops and persists the store on shutdown.
fn run_storage_thread(
    store: Store,
    sessions_ks: KeyspaceHandle,
    dids_ks: KeyspaceHandle,
    stats_ks: KeyspaceHandle,
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
        let did_ttl_seconds = auth_config.cleanup_ttl_minutes * 60;
        let did_interval = Duration::from_secs(did_ttl_seconds.max(60));

        let mut session_timer = tokio::time::interval(session_interval);
        let mut did_timer = tokio::time::interval(did_interval);

        // First tick completes immediately; skip so cleanup doesn't run at startup
        session_timer.tick().await;
        did_timer.tick().await;

        loop {
            tokio::select! {
                _ = session_timer.tick(), if has_auth => {
                    if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
                        warn!("session cleanup error: {e}");
                    }
                }
                _ = did_timer.tick() => {
                    match cleanup_empty_dids(&dids_ks, &stats_ks, did_ttl_seconds).await {
                        Ok(0) => {}
                        Ok(n) => info!(count = n, "cleaned up empty DID records"),
                        Err(e) => warn!("DID cleanup error: {e}"),
                    }
                    match stats::cleanup_old_timeseries(&stats_ks).await {
                        Ok(0) => {}
                        Ok(n) => info!(count = n, "cleaned up old time-series buckets"),
                        Err(e) => warn!("time-series cleanup error: {e}"),
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("storage thread shutting down");
                    break;
                }
            }
        }

        // Persist store before closing
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

/// Initialize JWT keys from secrets. Works independently of DIDComm setup,
/// so passkey auth can issue tokens even without server_did.
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

/// Initialize DID resolver and secrets resolver for DIDComm authentication.
///
/// Keys are stored as multibase-encoded private keys in `ServerSecrets`.
/// `Secret::from_multibase()` reconstructs the full `Secret` object including
/// the multicodec type prefix, then the key ID is overridden to match the
/// server DID fragment.
///
/// Returns `None` values if the server DID is not configured (server still starts
/// but DIDComm auth endpoints will not work).
async fn init_didcomm_auth(
    config: &AppConfig,
    secrets: &ServerSecrets,
) -> (
    Option<DIDCacheClient>,
    Option<Arc<ThreadedSecretsResolver>>,
) {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let server_did = match &config.server_did {
        Some(did) => did.clone(),
        None => {
            warn!("server_did not configured — DIDComm auth endpoints will not work");
            return (None, None);
        }
    };

    // 1. DID resolver (local mode)
    let did_resolver = match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to create DID resolver: {e} — DIDComm auth endpoints will not work");
            return (None, None);
        }
    };

    // 2. Secrets resolver with server's Ed25519 + X25519 secrets
    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;

    // Load and insert server signing key (Ed25519) from multibase
    let kid = format!("{server_did}#key-0");
    match Secret::from_multibase(&secrets.signing_key, Some(&kid)) {
        Ok(secret) => {
            secrets_resolver.insert(secret).await;
            debug!(kid = %kid, "server signing secret loaded");
        }
        Err(e) => warn!("failed to decode signing_key: {e}"),
    }

    // Load and insert server key-agreement key (X25519) from multibase
    let kid = format!("{server_did}#key-1");
    match Secret::from_multibase(&secrets.key_agreement_key, Some(&kid)) {
        Ok(secret) => {
            secrets_resolver.insert(secret).await;
            debug!(kid = %kid, "server key-agreement secret loaded");
        }
        Err(e) => warn!("failed to decode key_agreement_key: {e}"),
    }

    info!("DIDComm auth initialized for DID {server_did}");

    (
        Some(did_resolver),
        Some(Arc::new(secrets_resolver)),
    )
}

/// Decode a multibase-encoded Ed25519 private key to raw 32 bytes.
///
/// Used for JWT key initialization, which needs raw bytes rather than a
/// `Secret` object.
pub(crate) fn decode_multibase_ed25519_key(
    multibase_key: &str,
) -> Result<[u8; 32], AppError> {
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

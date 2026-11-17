//! The watcher's runtime: [`AppState`], startup ([`run`]), its messaging
//! listener, and the HTTP and storage threads.

use std::sync::{Arc, OnceLock};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_service::{DIDCommService, DIDCommServiceConfig};
use axum::routing::get;
use did_hosting_common::server::didcomm_profile::build_own_listener;
use did_hosting_common::server::identity::{self, ServiceIdentity};
use did_hosting_common::server::init;
use did_hosting_common::server::replay::ReplayCache;
use did_hosting_common::server::secret_store::ServerSecrets;
use did_hosting_common::server::store::KS_DIDS;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, error, info, warn};

use crate::config::AppConfig;
use crate::error::AppError;
use crate::routes;
use crate::store::{KeyspaceHandle, Store};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub dids_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    /// The watcher's own DID identity: signs every Trust Task reply, and its
    /// resolver verifies every inbound proof.
    pub identity: Option<Arc<ServiceIdentity>>,
    /// Verifies every inbound Trust Task's proof. `None` when no resolver is
    /// configured, in which case no sync is accepted.
    pub trust_tasks_verifier: Option<Arc<TransportBoundVerifier>>,
    /// Syncs already applied, keyed on `(proven source, document id)`.
    pub replay_cache: Arc<ReplayCache>,
    /// Serialises the syncs of one slot, and of one DID: each reads what is
    /// mirrored, checks the new log extends it, and writes — two at once could
    /// each pass against the same old state and leave a fork mirrored. Syncs of
    /// different slots run in parallel.
    pub sync_locks: did_hosting_common::server::path_locks::PathLocks,
    /// The slots held as disabled, so resolution answers from one store read.
    pub disabled: crate::watcher_ops::DisabledSlots,
    /// The running messaging service, once started.
    pub didcomm_service: Arc<OnceLock<DIDCommService>>,
    /// Per-address rate limiter for `POST /api/trust-tasks`. Applied before
    /// the document's claimed issuer is checked against the source allowlist,
    /// so a single address cannot force unbounded DID-resolution work by
    /// posting documents that name a fresh issuer on every request.
    pub trust_tasks_rate_limiter: Arc<did_hosting_common::server::rate_limit::IpRateLimiter>,
    /// Who an HTTPS request's client is, from `server.trusted_proxies`: built
    /// once with the state and shared by the Trust Task listener and the
    /// resolution limit.
    pub client_ips: did_hosting_common::server::rate_limit::ClientIps,
    /// How long `POST /api/trust-tasks` waits for a whole body, once the
    /// address is admitted.
    pub body_read_timeout: std::time::Duration,
}

impl AppState {
    /// A watcher state over `store`, verifying with `identity`'s resolver.
    pub fn new(
        store: Store,
        config: AppConfig,
        identity: Option<Arc<ServiceIdentity>>,
    ) -> Result<Self, AppError> {
        let did_resolver: Option<DIDCacheClient> =
            identity.as_ref().map(|i| i.did_resolver.clone());
        let replay_cache = Arc::new(ReplayCache::with_config(config.replay.clone())?);
        let client_ips =
            did_hosting_common::server::rate_limit::ClientIps::from_server_config(&config.server)?;
        Ok(Self {
            dids_ks: store.keyspace(KS_DIDS)?,
            store,
            config: Arc::new(config),
            trust_tasks_verifier: crate::trust_tasks::build_verifier(did_resolver.as_ref()),
            identity,
            replay_cache,
            sync_locks: Default::default(),
            disabled: Default::default(),
            didcomm_service: Arc::new(OnceLock::new()),
            client_ips,
            body_read_timeout: did_hosting_common::server::listener::BODY_READ_TIMEOUT,
            trust_tasks_rate_limiter: Arc::new(
                did_hosting_common::server::rate_limit::IpRateLimiter::new(
                    did_hosting_common::server::rate_limit::TRUST_TASKS_RATE_LIMIT_NAME,
                    did_hosting_common::server::rate_limit::TRUST_TASKS_MAX_PER_WINDOW,
                    did_hosting_common::server::rate_limit::TRUST_TASKS_WINDOW_SECS,
                ),
            ),
        })
    }

    /// What a sync runs against.
    pub fn mirror(&self) -> crate::watcher_ops::Mirror<'_> {
        crate::watcher_ops::Mirror {
            store: &self.store,
            ks: &self.dids_ks,
            sync: &self.config.sync,
            locks: &self.sync_locks,
            disabled: &self.disabled,
        }
    }

    /// Boot-time preparation of the mirror: rewrite high-water rows an
    /// earlier release stored as full logs, and load the disabled slots.
    pub async fn prepare_mirror(&self) -> Result<(), AppError> {
        let migrated = crate::watcher_ops::migrate_high_water_marks(&self.dids_ks).await?;
        if migrated > 0 {
            info!(migrated, "high-water marks rewritten in compact form");
        }
        let disabled = self.disabled.load(&self.dids_ks).await?;
        info!(disabled, "disabled slots loaded");
        Ok(())
    }
}

pub async fn run(config: AppConfig, store: Store, secrets: ServerSecrets) -> Result<(), AppError> {
    if config.server_did.is_none() {
        return Err(AppError::Config(
            "server_did is not set: the watcher needs its own DID — run `webvh-watcher setup`"
                .into(),
        ));
    }
    if config.sync.source_count() == 0 {
        warn!("no sync sources are configured: this watcher will apply no sync from anyone");
    }

    let identity = identity::load_identity(
        config.server_did.as_deref(),
        config.mediator_did.as_deref(),
        identity::ProtocolSet {
            didcomm: config.features.didcomm,
            tsp: config.features.tsp,
        },
        &secrets,
        &store,
    )
    .await;

    let std_listener = if config.features.http_listener {
        let addr = format!("{}:{}", config.server.host, config.server.port);
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("watcher listening addr={addr}");
        Some(listener)
    } else {
        None
    };

    let state = AppState::new(store.clone(), config, identity)?;
    // Before the REST thread starts: resolution relies on the disabled set.
    state.prepare_mirror().await?;
    info!(
        watcher_did = state.config.server_did.as_deref().unwrap_or_default(),
        sources = state.config.sync.source_count(),
        "watcher starting"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (rest_ready_tx, rest_ready_rx) = oneshot::channel::<()>();

    // REST thread: resolution and `POST /api/trust-tasks`.
    let rest_handle = match std_listener {
        Some(listener) => {
            let rest_state = state.clone();
            let mut rest_shutdown = shutdown_rx.clone();
            Some(
                std::thread::Builder::new()
                    .name("watcher-rest".into())
                    .spawn(move || {
                        run_rest_thread(listener, rest_state, &mut rest_shutdown, rest_ready_tx)
                    })
                    .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?,
            )
        }
        None => {
            let _ = rest_ready_tx.send(());
            None
        }
    };

    // Storage thread (persists on shutdown).
    let mut storage_shutdown = shutdown_rx.clone();
    let storage_handle = std::thread::Builder::new()
        .name("watcher-storage".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build storage runtime");
            rt.block_on(async {
                let _ = storage_shutdown.changed().await;
                if let Err(e) = store.persist().await {
                    error!("failed to persist store on shutdown: {e}");
                } else {
                    info!("store persisted");
                }
            });
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    let _ = rest_ready_rx.await;

    // Now that we are serving HTTP, resolve our *own* DID for the first time.
    // `load_identity` may have come up on guessed `#key-0`/`#key-1` kids and
    // persisted nothing; this records the generation with the kids the document
    // really uses — and must run before the listener is built on the guess.
    if let Err(e) = crate::identity_rotation::reload_now(&state).await {
        warn!("failed to establish the service identity from its DID document: {e}");
    }

    // TSP and DIDComm on the mediator connection.
    let messaging_shutdown = CancellationToken::new();
    match start_messaging_service(&state, messaging_shutdown.clone()).await {
        Ok(Some(svc)) => {
            let _ = state.didcomm_service.set(svc);
        }
        Ok(None) => {}
        Err(e) => warn!("failed to start the messaging service: {e}"),
    }

    // Reconnect to any mediator we rotated away from but whose grace period
    // has not elapsed — a restart mid-window must not abandon that queue.
    crate::identity_rotation::resume_mediator_drains(&state);

    // The identity sweep. The watcher's own DID is published elsewhere, so it
    // never sees it change — this sweep is its *only* way to notice a rotation,
    // as well as what expires a superseded generation's key material.
    let (identity_shutdown_tx, identity_shutdown_rx) = watch::channel(false);
    let identity_state = state.clone();
    let identity_handle = tokio::spawn(async move {
        crate::identity_rotation::run_identity_sweep_loop(identity_state, identity_shutdown_rx)
            .await;
    });

    init::shutdown_signal().await;

    // Ordered shutdown: identity -> messaging -> REST + storage.
    let _ = identity_shutdown_tx.send(true);
    if let Err(e) = identity_handle.await {
        warn!("identity sweep task didn't shut down cleanly: {e}");
    }

    messaging_shutdown.cancel();
    if let Some(svc) = state.didcomm_service.get() {
        svc.shutdown().await;
        info!("messaging service stopped");
    }
    let _ = shutdown_tx.send(true);

    let mut any_panic = false;
    if let Some(handle) = rest_handle
        && !matches!(
            tokio::task::spawn_blocking(move || handle.join()).await,
            Ok(Ok(()))
        )
    {
        error!("REST thread did not stop cleanly");
        any_panic = true;
    }
    if !matches!(
        tokio::task::spawn_blocking(move || storage_handle.join()).await,
        Ok(Ok(()))
    ) {
        error!("storage thread did not stop cleanly");
        any_panic = true;
    }
    if any_panic {
        return Err(AppError::Internal("one or more threads panicked".into()));
    }
    info!("watcher shut down");
    Ok(())
}

/// Start the Trust Task listener on the mediator connection, carrying every
/// transport the watcher's own DID document advertises.
async fn start_messaging_service(
    state: &AppState,
    shutdown: CancellationToken,
) -> Result<Option<DIDCommService>, AppError> {
    let Some(identity) = state.identity.as_ref() else {
        info!("no identity loaded — messaging disabled");
        return Ok(None);
    };
    let Some(mediator_did) = identity.mediator_did() else {
        info!("mediator_did not configured — TSP/DIDComm listener disabled");
        return Ok(None);
    };
    // Built by the same function the identity rebuild uses, so a rotation
    // cannot come back with a different listener.
    let (listener, transports) = build_own_listener(
        crate::identity_rotation::LISTENER_ID,
        identity,
        &mediator_did,
        &state.store,
    )
    .await?;
    let tsp_enabled = transports.tsp;
    let router = crate::messaging::build_watcher_router(state.clone())
        .map_err(|e| AppError::Internal(format!("failed to build DIDComm router: {e}")))?;
    let config = DIDCommServiceConfig {
        listeners: vec![listener],
    };
    // The TSP handler is installed whether or not this listener carries TSP
    // yet: the service holds one handler for its lifetime and the listener's
    // `protocols` gate whether TSP frames reach it, so a service started
    // without one could never dispatch TSP after a rotation rebuilt the
    // listener with TSP on (`rebuild_own_listener`).
    let svc = DIDCommService::start_with_tsp(
        config,
        router,
        crate::tsp::WatcherTspHandler::new(state.clone()),
        shutdown,
    )
    .await
    .map_err(|e| AppError::Internal(format!("failed to start messaging service: {e}")))?;
    info!(tsp = tsp_enabled, watcher_did = %identity.did, "messaging service started");
    Ok(Some(svc))
}

fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
    shutdown_rx: &mut watch::Receiver<bool>,
    ready_tx: oneshot::Sender<()>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        let listener =
            tokio::net::TcpListener::from_std(std_listener).expect("failed to convert TcpListener");
        let resolve_limit = Arc::new(
            did_hosting_common::server::rate_limit::ResolveRateLimiter::new(
                &state.config.server,
                &state.client_ips,
            ),
        );
        let rate_limit_gc = CancellationToken::new();
        resolve_limit.spawn_gc(rate_limit_gc.clone());
        state
            .trust_tasks_rate_limiter
            .spawn_gc(rate_limit_gc.clone());
        let trusted_proxies = state.config.server.trusted_proxies.clone();
        let app = routes::router_with_resolve_limit(resolve_limit)
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
                did_hosting_common::server::security_headers,
            ))
            .route("/api/health", get(routes::health::health));
        let _ = ready_tx.send(());
        let mut rx = shutdown_rx.clone();
        // Header, idle, connection and per-address limits: see `listener`.
        axum::serve(
            did_hosting_common::server::listener::bounded(listener, &trusted_proxies),
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = rx.changed().await;
        })
        .await
        .expect("axum serve failed");
        rate_limit_gc.cancel();
    });
}

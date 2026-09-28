use std::sync::{Arc, OnceLock};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, ListenerConfig, Protocols, RestartPolicy, RetryConfig,
};
use axum::routing::get;
use did_hosting_common::server::didcomm_profile::{
    advertised_protocols, build_tdk_profile_for_identity, reconcile_listener_protocols,
};
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
    /// The running messaging service, once started.
    pub didcomm_service: Arc<OnceLock<DIDCommService>>,
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
        Ok(Self {
            dids_ks: store.keyspace(KS_DIDS)?,
            store,
            config: Arc::new(config),
            trust_tasks_verifier: crate::trust_tasks::build_verifier(did_resolver.as_ref()),
            identity,
            replay_cache: Arc::new(ReplayCache::new()),
            didcomm_service: Arc::new(OnceLock::new()),
        })
    }
}

pub async fn run(config: AppConfig, store: Store, secrets: ServerSecrets) -> Result<(), AppError> {
    if config.server_did.is_none() {
        return Err(AppError::Config(
            "server_did is not set: the watcher needs its own DID — run `webvh-watcher setup`"
                .into(),
        ));
    }
    if config.sync.source_dids.is_empty() {
        warn!("sync.source_dids is empty: this watcher will apply no sync from anyone");
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

    let std_listener = if config.features.rest_api {
        let addr = format!("{}:{}", config.server.host, config.server.port);
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("watcher listening addr={addr}");
        Some(listener)
    } else {
        None
    };

    let state = AppState::new(store.clone(), config, identity)?;
    info!(
        watcher_did = state.config.server_did.as_deref().unwrap_or_default(),
        sources = state.config.sync.source_dids.len(),
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

    // TSP and DIDComm on the mediator connection.
    let messaging_shutdown = CancellationToken::new();
    match start_messaging_service(&state, messaging_shutdown.clone()).await {
        Ok(Some(svc)) => {
            let _ = state.didcomm_service.set(svc);
        }
        Ok(None) => {}
        Err(e) => warn!("failed to start the messaging service: {e}"),
    }

    init::shutdown_signal().await;

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
    let profile = build_tdk_profile_for_identity("watcher", identity, Some(&mediator_did)).await?;

    let advertised = advertised_protocols(&identity.did, Some(&identity.did_resolver)).await;
    let transports = reconcile_listener_protocols(identity.protocols(), advertised, &identity.did);
    let tsp_enabled = transports.tsp;
    let protocols = match (transports.didcomm, transports.tsp) {
        (true, true) => Protocols::BOTH,
        (false, true) => Protocols::TSP_ONLY,
        _ => Protocols::DIDCOMM_ONLY,
    };
    let mut listener = ListenerConfig {
        id: "watcher".into(),
        profile,
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        protocols,
        ..Default::default()
    };
    if tsp_enabled {
        listener.relationship_store = Some(
            did_hosting_common::server::tsp_relationship_store::build_relationship_store(
                &state.store,
            )?,
        );
    }
    let router = crate::messaging::build_watcher_router(state.clone())
        .map_err(|e| AppError::Internal(format!("failed to build DIDComm router: {e}")))?;
    let config = DIDCommServiceConfig {
        listeners: vec![listener],
    };
    let svc = if tsp_enabled {
        DIDCommService::start_with_tsp(
            config,
            router,
            crate::tsp::WatcherTspHandler::new(state.clone()),
            shutdown,
        )
        .await
    } else {
        DIDCommService::start(config, router, shutdown).await
    }
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
                did_hosting_common::server::security_headers,
            ))
            .route("/api/health", get(routes::health::health));
        let _ = ready_tx.send(());
        let mut rx = shutdown_rx.clone();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.changed().await;
            })
            .await
            .expect("axum serve failed");
    });
}

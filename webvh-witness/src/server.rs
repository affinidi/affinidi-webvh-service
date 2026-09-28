use std::sync::{Arc, OnceLock};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, ListenerConfig, Protocols, RestartPolicy, RetryConfig,
};
use affinidi_tdk::secrets_resolver::ThreadedSecretsResolver;
use did_hosting_common::server::didcomm_profile::{
    advertised_protocols, build_tdk_profile_for_identity, reconcile_listener_protocols,
};
use did_hosting_common::server::identity::{self, ServiceIdentity};
use did_hosting_common::server::init;
use did_hosting_common::server::path_locks::PathLocks;
use did_hosting_common::server::replay::ReplayCache;
use did_hosting_common::server::store::{KS_ACL, KS_WITNESSES};
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use tokio_util::sync::CancellationToken;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::messaging;
use crate::routes;
use crate::secret_store::ServerSecrets;
use crate::signing::{LocalSigner, WitnessSigner};
use crate::store::{KeyspaceHandle, Store};
use axum::routing::get;
use tokio::sync::{oneshot, watch};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub acl_ks: KeyspaceHandle,
    pub witnesses_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    /// The service's own DID identity — every generation of key material still
    /// honoured, and the kids each one answers to. The two resolvers above are
    /// cheap clones taken from this. Signs every Trust Task reply.
    pub identity: Option<Arc<ServiceIdentity>>,
    /// The running messaging service, once started.
    ///
    /// Lifted into `AppState` (it used to be a local in `run()`) so the identity
    /// sweep can hot-swap the listener when the witness's own DID rotates:
    /// `remove_listener` / `add_listener` take `&self`, so the *service* is
    /// never replaced — only its one listener — and a `OnceLock` suffices.
    pub didcomm_service: Arc<OnceLock<DIDCommService>>,
    pub signer: Arc<dyn WitnessSigner>,
    /// Verifies every inbound Trust Task's proof. `None` when no resolver is
    /// configured, in which case no request is accepted.
    pub trust_tasks_verifier: Option<Arc<TransportBoundVerifier>>,
    /// Serialises the ACL write handlers (`acl/grant|revoke|change-role`).
    pub acl_locks: PathLocks,
    /// Requests already acted on, keyed on `(proven issuer, document id)`.
    pub replay_cache: Arc<ReplayCache>,
    /// Serialises `witness/sign`: the check that an entry extends what the
    /// witness has already witnessed, the signature, and the record of it are
    /// one step, so two forks of the same DID cannot both be witnessed.
    pub sign_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AppState {
    /// A witness state over `store`, with the Trust Task machinery built from
    /// `identity`'s resolver.
    pub fn new(
        store: Store,
        config: AppConfig,
        identity: Option<Arc<ServiceIdentity>>,
        signer: Arc<dyn WitnessSigner>,
    ) -> Result<Self, AppError> {
        let did_resolver = identity.as_ref().map(|i| i.did_resolver.clone());
        let secrets_resolver = identity.as_ref().map(|i| i.secrets_resolver.clone());
        Ok(Self {
            acl_ks: store.keyspace(KS_ACL)?,
            witnesses_ks: store.keyspace(KS_WITNESSES)?,
            store,
            config: Arc::new(config),
            trust_tasks_verifier: crate::trust_tasks::build_verifier(did_resolver.as_ref()),
            did_resolver,
            secrets_resolver,
            identity,
            didcomm_service: Arc::new(OnceLock::new()),
            signer,
            acl_locks: PathLocks::new(),
            replay_cache: Arc::new(ReplayCache::new()),
            sign_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
}

pub async fn run(config: AppConfig, store: Store, secrets: ServerSecrets) -> Result<(), AppError> {
    // Load the service's own identity (requires server_did). Resolves the DID
    // document for the *real* verification-method key IDs and seeds the secrets
    // resolver under them, rather than assuming `#key-0` / `#key-1`.
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

    let state = AppState::new(store.clone(), config, identity, Arc::new(LocalSigner))?;

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
        .spawn(move || run_storage_thread(store, &mut storage_shutdown))
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // 3. Wait for REST, then start DIDComm service
    let _ = rest_ready_rx.await;

    // Now that we are serving HTTP, resolve our *own* DID for the first time.
    // A self-hosting service cannot resolve its own DID at boot — it is the thing
    // that serves it — so `load_identity` came up on guessed `#key-0`/`#key-1`
    // kids and persisted nothing. This is the first moment the document is
    // fetchable, and it must run before the listener is built on the guess.
    if let Err(e) = crate::identity_rotation::reload_now(&state).await {
        warn!("failed to establish the service identity from its DID document: {e}");
    }

    let didcomm_shutdown = CancellationToken::new();
    if state.config.features.didcomm {
        match start_didcomm_service(&state, didcomm_shutdown.clone()).await {
            Ok(Some(svc)) => {
                let _ = state.didcomm_service.set(svc);
            }
            Ok(None) => {}
            Err(e) => warn!("failed to start DIDComm service: {e}"),
        }
    }
    let didcomm_service = state.didcomm_service.get();

    // 3b. Reconnect to any mediator we rotated away from but whose grace period
    // has not elapsed — a restart mid-window must not abandon that queue.
    crate::identity_rotation::resume_mediator_drains(&state);

    // 4. Spawn the identity sweep. The witness hosts no DIDs, so it has no
    // publish hook — this sweep is its *only* way to notice its own DID rotated,
    // as well as what expires a superseded generation's key material.
    let (identity_shutdown_tx, identity_shutdown_rx) = watch::channel(false);
    let identity_state = state.clone();
    let identity_handle = tokio::spawn(async move {
        crate::identity_rotation::run_identity_sweep_loop(identity_state, identity_shutdown_rx)
            .await;
    });

    // Wait for shutdown signal
    init::shutdown_signal().await;

    // Ordered shutdown: identity -> DIDComm -> REST -> Storage
    let mut any_panic = false;

    let _ = identity_shutdown_tx.send(true);
    if let Err(e) = identity_handle.await {
        warn!("identity sweep task didn't shut down cleanly: {e}");
    }

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
    shutdown: CancellationToken,
) -> Result<Option<DIDCommService>, AppError> {
    let identity = match state.identity.as_ref() {
        Some(identity) => identity,
        None => {
            info!("DIDComm not configured — server_did not set");
            return Ok(None);
        }
    };

    let mediator_did = match identity.mediator_did() {
        Some(did) => did,
        None => {
            info!("mediator_did not configured — DIDComm messaging disabled");
            return Ok(None);
        }
    };

    // Carries the key material of every live generation, keyed on the kids the
    // DID document actually resolved to — the same kids the secrets resolver
    // was seeded with.
    let profile = build_tdk_profile_for_identity("witness", identity, Some(&mediator_did)).await?;

    // DIDComm and/or TSP ride the same mediator socket. The listener carries
    // every transport the witness's own DID document advertises, whatever the
    // config flags say — the document is how peers reach it.
    let advertised = advertised_protocols(&identity.did, Some(&identity.did_resolver)).await;
    let transports = reconcile_listener_protocols(identity.protocols(), advertised, &identity.did);
    let tsp_enabled = transports.tsp;
    let protocols = match (transports.didcomm, transports.tsp) {
        (true, true) => Protocols::BOTH,
        (false, true) => Protocols::TSP_ONLY,
        _ => Protocols::DIDCOMM_ONLY,
    };

    let mut listener = ListenerConfig {
        id: "witness".into(),
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

    let router = messaging::build_witness_router(state.clone())
        .map_err(|e| AppError::Internal(format!("failed to build DIDComm router: {e}")))?;

    let config = DIDCommServiceConfig {
        listeners: vec![listener],
    };
    let svc = if tsp_enabled {
        DIDCommService::start_with_tsp(
            config,
            router,
            crate::tsp::WitnessTspHandler::new(state.clone()),
            shutdown,
        )
        .await
    } else {
        DIDCommService::start(config, router, shutdown).await
    }
    .map_err(|e| AppError::Internal(format!("failed to start messaging service: {e}")))?;

    info!(tsp = tsp_enabled, witness_did = %identity.did, "messaging service started");
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
                did_hosting_common::server::security_headers,
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

fn run_storage_thread(store: Store, shutdown_rx: &mut watch::Receiver<bool>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");
        let _ = shutdown_rx.changed().await;
        info!("storage thread shutting down");

        if let Err(e) = store.persist().await {
            error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
}

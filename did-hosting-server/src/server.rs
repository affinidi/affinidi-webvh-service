//! The edge's runtime: [`AppState`], startup ([`run`]), the messaging
//! listener and control-plane registration, and the HTTP and storage threads
//! (also reused by the daemon through [`EdgeStorage`] and [`storage_tasks`]).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_service::{DIDCommService, DIDCommServiceConfig, ListenerEvent};
use affinidi_tdk::secrets_resolver::ThreadedSecretsResolver;
use axum::routing::get;
use did_hosting_common::server::store::KS_DIDS;
use ipnetwork::IpNetwork;

use did_hosting_common::server::didcomm_profile::{build_own_listener, wait_for_did_resolution};
use did_hosting_common::server::identity::{self, ServiceIdentity};
use did_hosting_common::server::init;
use did_hosting_common::server::supervise::{
    PeriodicTask, Policy, SHUTDOWN_STAGE_DEADLINE, Stage, Supervisor, run_periodic,
};
use tokio_util::sync::CancellationToken;

use crate::config::AppConfig;
use crate::control_register;
use crate::did_ops::cleanup_empty_dids;
use crate::error::AppError;
use crate::messaging;
use crate::routes;
use crate::secret_store::ServerSecrets;
use crate::stats;
use crate::store::{KeyspaceHandle, Store};
use tokio::sync::{oneshot, watch};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub dids_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    pub did_resolver: Option<DIDCacheClient>,
    /// The proof verifier for control-plane documents, built once over
    /// `did_resolver` so its DID-status verdicts and forced-refresh rate limit
    /// persist across messages. `None` when no resolver is configured, in which
    /// case no control-plane document can be accepted.
    pub trust_tasks_verifier:
        Option<Arc<did_hosting_common::server::trust_tasks::TransportBoundVerifier>>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    /// The service's own DID identity: every generation of key material still
    /// honoured, and the kids each one answers to. `did_resolver` and
    /// `secrets_resolver` above are cheap clones taken from this; it is the
    /// source of truth for which kids they answer to, and the listener's
    /// profile is built from it so the two cannot drift apart.
    pub identity: Option<Arc<ServiceIdentity>>,
    /// The running messaging service, once started.
    ///
    /// Lifted into `AppState` (it used to be a local in `run()`, unreachable at
    /// runtime) so listeners can be hot-swapped without bouncing the process:
    /// `remove_listener` / `add_listener` take `&self`, which is what lets a
    /// rotation rebuild the profile in place. A `OnceLock` suffices precisely
    /// because the *service* is never replaced — only its listeners are.
    pub didcomm_service: Arc<OnceLock<DIDCommService>>,
    pub stats_collector: Option<Arc<stats::StatsCollector>>,
    /// In-memory cache for DID content (did.jsonl). TTL-based eviction on read.
    pub did_cache: Arc<crate::cache::ContentCache>,
    /// The records and domains resolution checks, cached. `None` (read the
    /// store on every resolve) unless every change to them is made in this
    /// process: a standalone edge (`run`) and a daemon with its control plane
    /// on set it. See [`crate::cache::GateCache`].
    pub gate_cache: Option<Arc<crate::cache::GateCache>>,
    /// Parsed `server.trusted_proxy_cidrs` — peers inside this set
    /// have their `Forwarded` / `X-Forwarded-Host` headers honoured
    /// for request-host detection (multi-domain, T19/T21).
    pub trusted_proxy_cidrs: Arc<Vec<IpNetwork>>,
    /// How far this edge is behind its control plane — the reconcile loop
    /// writes it, `/api/health` and `server/metrics` read it.
    pub replication: Arc<crate::replication::ReplicationStatus>,
    /// Per-address rate limiter for `POST /api/trust-tasks`. Applied before
    /// the document's claimed issuer is checked against `control_did`, so a
    /// single address cannot force unbounded DID-resolution work by posting
    /// documents that name a fresh issuer on every request.
    pub trust_tasks_rate_limiter: Arc<did_hosting_common::server::rate_limit::IpRateLimiter>,
    /// Who an HTTPS request's client is, from `server.trusted_proxies`: built
    /// once with the state and shared by the Trust Task listener and the
    /// resolution limit.
    pub client_ips: did_hosting_common::server::rate_limit::ClientIps,
    /// Per-slot and per-DID locks serialising `sync/update`, `sync/batch`,
    /// `sync/delete` and the reconcile repair: each reads what this edge holds
    /// for a slot (and the high-water mark of its DID), checks the new log
    /// extends it, and writes — two such operations on the same slot or DID
    /// running at once could each pass their read-check against the same stale
    /// state. Operations on different slots run in parallel. A writer takes
    /// the slot's lock ([`crate::control_register::slot_lock_key`]) before the
    /// DID's ([`crate::control_register::identity_lock_key`]).
    pub sync_locks: did_hosting_common::server::path_locks::PathLocks,
    /// Control-plane documents already applied, keyed on `(issuer, id)`,
    /// with this edge's `[replay]` bounds. Every sync document is signed by
    /// the control plane, so its per-signer bound caps how fast the edge
    /// can follow DID changes.
    pub replay_cache: Arc<did_hosting_common::server::replay::ReplayCache>,
}

impl AppState {
    /// An edge over `store` with nothing wired but its configuration and a
    /// fresh content cache: no identity, no resolver, no messaging service.
    /// The caller — `run`, the daemon, a test — fills in what it has.
    pub fn new(store: Store, config: AppConfig) -> Result<Self, AppError> {
        // Parsed (and refused when malformed) at config load.
        let parsed_cidrs = config.server.trusted_proxy_cidrs.clone();
        // The two proxy lists are read separately (client address vs. request
        // host), and a deployment behind a proxy almost always needs both.
        if parsed_cidrs.is_empty() != config.server.trusted_proxies.is_empty() {
            warn!(
                trusted_proxies = config.server.trusted_proxies.len(),
                trusted_proxy_cidrs = parsed_cidrs.len(),
                "only one of server.trusted_proxies (client address) and \
                 server.trusted_proxy_cidrs (request host) is set; behind a reverse proxy, \
                 list the proxy in both"
            );
        }
        let replay_cache = Arc::new(
            did_hosting_common::server::replay::ReplayCache::with_config(config.replay.clone())?,
        );
        let client_ips =
            did_hosting_common::server::rate_limit::ClientIps::from_server_config(&config.server)?;
        let content_cache_bytes = config.limits.content_cache_bytes;
        Ok(Self {
            dids_ks: store.keyspace(KS_DIDS)?,
            store,
            config: Arc::new(config),
            replay_cache,
            did_resolver: None,
            trust_tasks_verifier: None,
            secrets_resolver: None,
            identity: None,
            didcomm_service: Arc::new(OnceLock::new()),
            stats_collector: None,
            did_cache: Arc::new(crate::cache::ContentCache::with_capacity(
                crate::cache::RESOLUTION_CACHE_TTL,
                content_cache_bytes,
            )),
            gate_cache: None,
            trusted_proxy_cidrs: Arc::new(parsed_cidrs),
            replication: Arc::new(crate::replication::ReplicationStatus::new(
                did_hosting_common::server::auth::session::now_epoch(),
            )),
            client_ips,
            trust_tasks_rate_limiter: Arc::new(
                did_hosting_common::server::rate_limit::IpRateLimiter::new(
                    did_hosting_common::server::rate_limit::TRUST_TASKS_RATE_LIMIT_NAME,
                    did_hosting_common::server::rate_limit::TRUST_TASKS_MAX_PER_WINDOW,
                    did_hosting_common::server::rate_limit::TRUST_TASKS_WINDOW_SECS,
                ),
            ),
            sync_locks: did_hosting_common::server::path_locks::PathLocks::new(),
        })
    }

    /// The caches resolution reads through, to clear after a write: the one
    /// way every edge write path tells resolution what changed.
    pub fn resolution_caches(&self) -> crate::cache::ResolutionCaches {
        crate::cache::ResolutionCaches {
            content: self.did_cache.clone(),
            gate: self.gate_cache.clone(),
        }
    }

    /// Carry `identity`: the resolvers and proof verifier are taken from it.
    pub fn with_identity(mut self, identity: Option<Arc<ServiceIdentity>>) -> Self {
        self.did_resolver = identity.as_ref().map(|i| i.did_resolver.clone());
        self.secrets_resolver = identity.as_ref().map(|i| i.secrets_resolver.clone());
        self.trust_tasks_verifier = crate::messaging::build_verifier(self.did_resolver.as_ref());
        self.identity = identity;
        self
    }
}

/// Refuse to start an edge that no control plane drives.
///
/// An edge is a cache of its control plane: every write it applies is a Trust
/// Task that control plane signed, and it has no management surface of its
/// own. Without `control_did` nothing could ever write to it, so a
/// single-host deployment runs `did-hosting-daemon` instead.
pub fn require_control_plane(config: &AppConfig) -> Result<(), AppError> {
    config.replication.validate()?;
    if config.control_did.as_deref().is_none_or(str::is_empty) {
        return Err(AppError::Config(
            "control_did is not set. did-hosting-server is an edge that a control plane drives \
             over Trust Tasks, and does not run without one; for a single-host deployment run \
             did-hosting-daemon"
                .into(),
        ));
    }
    if config.server_did.as_deref().is_none_or(str::is_empty) {
        return Err(AppError::Config(
            "server_did is not set: the control plane addresses and verifies this edge by it"
                .into(),
        ));
    }
    Ok(())
}

/// The names of the edge's background tasks: what its supervisor logs, and
/// what the daemon's skip list and parity test refer to.
pub mod tasks {
    /// Empty DID slots past their TTL are deleted (storage).
    pub const EMPTY_DID_CLEANUP: &str = "empty-did-cleanup";
    /// The hosted-DID count is recounted from the keys (storage). The
    /// control plane's tick of the same name does the same.
    pub const DID_COUNT_RECONCILE: &str = "did-count-reconcile";
    /// Ripe pending purges (an unassign or a domain disable past its grace)
    /// are carried out, and expired resolution cache entries dropped
    /// (storage).
    pub const PURGE_SWEEP: &str = "purge-sweep";
    /// Registration with the control plane, repeated on every reconnect and
    /// every [`super::RESYNC_INTERVAL`].
    pub const KEEP_REGISTERED: &str = "keep-registered";
    /// The reconcile loop against the control plane's listing.
    pub const REPLICATION_RECONCILE: &str = "replication-reconcile";
    /// The TSP relationship with the control plane, re-ensured on reconnect.
    pub const CONTROL_TSP_RELATIONSHIP: &str = "control-tsp-relationship";
    /// Statistics deltas sent to the control plane.
    pub const STATS_SYNC: &str = "stats-sync";
    /// The edge's own identity expiry and reload.
    pub const IDENTITY_SWEEP: &str = "identity-sweep";

    /// Every storage tick ([`super::storage_tasks`]).
    pub const STORAGE: [&str; 3] = [EMPTY_DID_CLEANUP, DID_COUNT_RECONCILE, PURGE_SWEEP];
    /// Every task that talks to the control plane or runs the edge's own
    /// identity: all need the edge's own messaging service.
    pub const MESSAGING: [&str; 5] = [
        KEEP_REGISTERED,
        REPLICATION_RECONCILE,
        CONTROL_TSP_RELATIONSHIP,
        STATS_SYNC,
        IDENTITY_SWEEP,
    ];
}

/// Told the mnemonics of the DIDs a storage tick deleted (the daemon deletes
/// their statistics, which an edge does not keep).
pub type RemovedDidsHook =
    Arc<dyn Fn(Vec<String>) -> did_hosting_common::server::supervise::BoxFuture + Send + Sync>;

/// What the edge's storage ticks work on. The daemon builds one over its own
/// store, with its control plane's path locks and a hook for statistics.
#[derive(Clone)]
pub struct EdgeStorage {
    pub store: Store,
    pub dids_ks: KeyspaceHandle,
    /// How long an empty slot is kept (`auth.cleanup_ttl_minutes`).
    pub did_ttl_seconds: u64,
    pub collector: Arc<stats::StatsCollector>,
    pub caches: crate::cache::ResolutionCaches,
    /// The path locks of a control plane writing the same store (the
    /// daemon); `None` on an edge, whose writes take none.
    pub path_locks: Option<did_hosting_common::server::path_locks::PathLocks>,
    pub on_removed: Option<RemovedDidsHook>,
}

impl EdgeStorage {
    async fn removed(&self, mnemonics: Vec<String>) {
        if let Some(hook) = &self.on_removed
            && !mnemonics.is_empty()
        {
            hook(mnemonics).await;
        }
    }
}

/// The edge's storage ticks ([`tasks::STORAGE`]): run on its storage thread,
/// and in the daemon's storage task.
pub fn storage_tasks(storage: &EdgeStorage) -> Vec<PeriodicTask> {
    let cleanup = {
        let s = storage.clone();
        PeriodicTask::new(
            tasks::EMPTY_DID_CLEANUP,
            Duration::from_secs(s.did_ttl_seconds.max(60)),
            move |_| {
                let s = s.clone();
                async move {
                    match cleanup_empty_dids(&s.dids_ks, s.did_ttl_seconds, s.path_locks.as_ref())
                        .await
                    {
                        Ok(removed) if removed.is_empty() => {}
                        Ok(removed) => {
                            info!(count = removed.len(), "cleaned up empty DID records");
                            for mnemonic in &removed {
                                s.caches.forget_did(mnemonic);
                            }
                            s.collector.subtract_total_dids(removed.len() as u64);
                            s.removed(removed).await;
                        }
                        Err(e) => warn!("DID cleanup error: {e}"),
                    }
                }
            },
        )
    };

    // DIDs reach an edge by sync, which does not count them; the recount
    // keeps the edge's figure in step.
    let recount = {
        let s = storage.clone();
        PeriodicTask::new(
            tasks::DID_COUNT_RECONCILE,
            did_hosting_common::server::stats_collector::DID_COUNT_RECONCILE_INTERVAL,
            move |_| {
                let s = s.clone();
                async move {
                    if let Err(e) =
                        did_hosting_common::server::stats_collector::reconcile_total_dids(
                            &s.collector,
                            &s.dids_ks,
                        )
                        .await
                    {
                        warn!("DID count reconcile error: {e}");
                    }
                }
            },
        )
    };

    // Each minute: run the grace-expired purge sweep (the schedule an
    // unassign or a domain disable acknowledged to the control plane), then
    // drop expired content cache entries (they live `RESOLUTION_CACHE_TTL`)
    // so DIDs nobody asks for again do not stay in memory — or the whole
    // cache, when the sweep purged something.
    let purge = {
        let s = storage.clone();
        PeriodicTask::new(
            tasks::PURGE_SWEEP,
            crate::purge_sweep::DEFAULT_SWEEP_INTERVAL,
            move |_| {
                let s = s.clone();
                async move {
                    let sweep = crate::purge_sweep::run_edge_sweep_tick(
                        &s.store,
                        s.path_locks.as_ref(),
                        &s.caches.content,
                        s.caches.gate.as_deref(),
                        Some(&s.collector),
                    )
                    .await;
                    s.removed(sweep.purged_dids).await;
                }
            },
        )
    };

    vec![cleanup, recount, purge]
}

/// Integrity check of the DID keyspace: logged, never fatal. Shared with the
/// daemon.
pub async fn check_store_integrity(dids_ks: &KeyspaceHandle) {
    match dids_ks.verify_integrity().await {
        Ok(0) => debug!("store integrity check passed"),
        Ok(n) => warn!(
            corrupted = n,
            "store integrity check found corrupted entries"
        ),
        Err(e) => warn!(error = %e, "store integrity check failed"),
    }
}

/// Start the edge's messaging service (DIDComm and/or TSP), retrying with
/// backoff while it fails — an edge without one can never reconcile —
/// until it starts or `shutdown` is cancelled. `None` when none is
/// configured or on shutdown.
pub async fn start_messaging(
    state: &AppState,
    shutdown: CancellationToken,
) -> Option<DIDCommService> {
    did_hosting_common::server::supervise::retry_with_backoff(
        "the messaging service",
        &shutdown,
        || start_didcomm_service(state, shutdown.clone()),
    )
    .await
    .flatten()
}

/// Start the tasks that talk to the control plane over `svc`
/// ([`tasks::MESSAGING`] but the identity sweep, which needs no service).
/// Each restarts with backoff if it stops: all are idempotent, and each one
/// stopping would silently stop this edge following its control plane.
fn spawn_messaging_tasks(state: &AppState, svc: &DIDCommService, sup: &mut Supervisor) {
    // Register with control plane via DIDComm (uses the shared connection)
    if state.config.control_did.is_some() {
        let (state, svc) = (state.clone(), svc.clone());
        sup.spawn(
            Stage::Workers,
            tasks::KEEP_REGISTERED,
            Policy::Restart,
            move |sd| {
                let (state, svc) = (state.clone(), svc.clone());
                async move {
                    tokio::select! {
                        _ = keep_registered(state, svc) => {}
                        _ = sd.stopped() => {}
                    }
                }
            },
        );
    }

    // Reconcile against the control plane's listing every interval — the
    // backstop behind the outbox, and what the staleness bound measures.
    {
        let (state, svc) = (state.clone(), svc.clone());
        sup.spawn(
            Stage::Workers,
            tasks::REPLICATION_RECONCILE,
            Policy::Restart,
            move |sd| {
                crate::replication::run_reconcile_loop(state.clone(), svc.clone(), sd.watch())
            },
        );
    }

    // Keep a TSP relationship with the control plane established. Under Rev 3
    // §7.2.2 the control plane's application pushes (sync/health) are dropped
    // unless this edge holds a relationship with it, and forming one is the
    // edge's job — the control plane persists its half and does not re-invite.
    // The ensure is idempotent (skips when already Bidirectional) and MUST
    // fire on every (re)connect, not just first boot: a control-plane restart,
    // or a handshake that never completed, is repaired on the edge's next
    // connect. See docs/tsp-transport.md.
    if let Some(control_did) = state.config.control_did.clone()
        && state.config.features.tsp
    {
        let svc = svc.clone();
        sup.spawn(
            Stage::Workers,
            tasks::CONTROL_TSP_RELATIONSHIP,
            Policy::Restart,
            move |sd| {
                let (svc, control_did) = (svc.clone(), control_did.clone());
                async move {
                    tokio::select! {
                        _ = ensure_control_tsp_relationship(svc, control_did) => {}
                        _ = sd.stopped() => {}
                    }
                }
            },
        );
    }

    // Stats sync — TSP or DIDComm, per the control DID.
    let interval = state.config.stats.sync_interval_secs;
    if let (Some(control_did), Some(server_did), Some(collector)) = (
        state.config.control_did.clone(),
        state.config.server_did.clone(),
        state.stats_collector.clone(),
    ) && interval > 0
    {
        let (state, svc) = (state.clone(), svc.clone());
        sup.spawn(
            Stage::Workers,
            tasks::STATS_SYNC,
            Policy::Restart,
            move |sd| {
                let task = {
                    let (state, svc) = (state.clone(), svc.clone());
                    let (control_did, server_did) = (control_did.clone(), server_did.clone());
                    let collector = collector.clone();
                    PeriodicTask::new(
                        tasks::STATS_SYNC,
                        Duration::from_secs(interval.max(1)),
                        move |_| {
                            let (state, svc) = (state.clone(), svc.clone());
                            let (control_did, server_did) =
                                (control_did.clone(), server_did.clone());
                            let collector = collector.clone();
                            async move {
                                stats::sync_to_control_messaging(
                                    &svc,
                                    &state,
                                    &server_did,
                                    &control_did,
                                    &collector,
                                )
                                .await;
                            }
                        },
                    )
                };
                run_periodic(vec![task], sd.watch())
            },
        );
    }
}

pub async fn run(config: AppConfig, store: Store, secrets: ServerSecrets) -> Result<(), AppError> {
    require_control_plane(&config)?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    check_store_integrity(&dids_ks).await;

    // First-boot multi-domain init, shared with the daemon (which treats a
    // failure as fatal). See `run_first_boot_init`.
    if let Err(e) = run_first_boot_init(
        &store,
        &config,
        did_hosting_common::server::migrations::registry(),
        FirstBoot::Lenient,
    )
    .await
    {
        warn!(error = %e, "first-boot init incomplete");
    }
    // High-water rows written before the compact mark held whole logs. An
    // edge's own state (the daemon keeps no high-water rows).
    match crate::control_register::migrate_high_water_marks(&dids_ks, &store).await {
        Ok(0) => {}
        Ok(n) => info!(rewritten = n, "high-water marks compacted"),
        Err(e) => warn!(error = %e, "high-water mark migration failed; legacy rows are still read"),
    }
    // Auto-bootstrap DIDs if public_url is set and they don't exist yet
    let config =
        auto_bootstrap_dids("did-hosting-server", config, &store, &dids_ks, &secrets).await;

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
    // The control plane is authorised here by configuration, not by an ACL
    // entry, so its did:scid floor is kept on that ground (VTI-KEY-162).
    if let (Some(keeper), Some(control_did)) = (
        identity.as_ref().and_then(|i| i.scid_floors.as_ref()),
        config.control_did.as_deref(),
    ) {
        keeper.authorise(control_did);
    }
    // Bind TCP before anything else: public resolution and the Trust Task
    // listener's HTTPS binding are served from it.
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let std_listener = {
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("server listening addr={addr}");
        listener
    };

    let did_ttl_seconds = config.auth.cleanup_ttl_minutes * 60;
    let upload_body_limit = config.limits.upload_body_limit;

    // Initialize in-memory stats collector (starts at zero — no disk persistence)
    let stats_collector = {
        // An edge syncs only per-DID deltas, so it keeps no time-series
        // buckets: nothing would ever drain them.
        let collector = stats::StatsCollector::without_timeseries();
        // Counted from the keys, without reading the records.
        let total_dids = match dids_ks.prefix_count("did:").await {
            Ok(n) => n as u64,
            Err(e) => {
                warn!(error = %e, "could not count hosted DIDs; the hourly recount will");
                0
            }
        };
        collector.set_total_dids(total_dids);
        info!(total_dids, "stats collector initialized");
        Arc::new(collector)
    };

    let mut state = AppState::new(store.clone(), config)?.with_identity(identity);
    state.stats_collector = Some(stats_collector.clone());
    // Every change an edge serves arrives as a directive it applies in this
    // process, and each clears what it changed (`AppState::resolution_caches`),
    // so a warm resolve reads nothing from the store.
    state.gate_cache = Some(Arc::new(crate::cache::GateCache::new(
        &store,
        crate::cache::RESOLUTION_CACHE_TTL,
    )?));

    // Log startup configuration
    info!("--- enabled services ---");
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

    let mut sup = Supervisor::new("did-hosting-server");
    let mut signal = std::pin::pin!(init::shutdown_signal());

    // REST ready signal — DIDComm waits for this before starting
    let (rest_ready_tx, rest_ready_rx) = oneshot::channel::<()>();

    // 1. HTTP thread first — must be serving before DIDComm starts (the
    //    server's own DID needs to be resolvable for mediator auth). Critical:
    //    it owns the listening socket, and an edge without HTTP serves nothing.
    let rest_state = state.clone();
    sup.spawn_thread(Stage::Listeners, "server-rest", move |sd| {
        run_rest_thread(
            std_listener,
            rest_state,
            upload_body_limit,
            sd.watch(),
            rest_ready_tx,
        )
    })
    .map_err(|e| AppError::Internal(format!("failed to spawn HTTP thread: {e}")))?;

    // 2. The storage thread (cleanup, recount, purge; then the persist).
    //    Critical: it is what persists the store at shutdown.
    let storage = EdgeStorage {
        store: store.clone(),
        dids_ks,
        did_ttl_seconds,
        collector: stats_collector,
        caches: state.resolution_caches(),
        path_locks: None,
        on_removed: None,
    };
    sup.spawn_thread(Stage::Storage, "server-storage", move |sd| {
        run_storage_thread(storage, sd.watch())
    })
    .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // 3. Wait for REST to be serving before starting DIDComm
    //    (the server's own DID needs to be resolvable for mediator auth)
    let _ = rest_ready_rx.await;

    // Now that we are serving HTTP, resolve our *own* DID for the first time.
    // A self-hosting service cannot resolve its own DID at boot — it is the thing
    // that serves it — so `load_identity` came up on guessed `#key-0`/`#key-1`
    // kids and persisted nothing. This is the first moment the document is
    // fetchable, and it must run before the listener is built on the guess.
    if let Err(e) = crate::identity_rotation::reload_now(&state).await {
        warn!("failed to establish the service identity from its DID document: {e}");
    }

    // 4. The identity sweep. Expires generations whose grace period has
    // elapsed (so a superseded key stops decrypting) and backstops identity
    // changes that never came through our own publish or sync path — one
    // applied out-of-band, or while this process was down.
    let identity_state = state.clone();
    sup.spawn(
        Stage::Workers,
        tasks::IDENTITY_SWEEP,
        Policy::Restart,
        move |sd| {
            crate::identity_rotation::run_identity_sweep_loop(identity_state.clone(), sd.watch())
        },
    );

    // 5. The mediator messaging service (DIDComm and/or TSP) — one connection
    //    for both receiving and sending, retried with backoff while it fails.
    //    TSP-only deployments (didcomm off, tsp on) must still start it.
    let mut interrupted = false;
    if state.config.features.didcomm || state.config.features.tsp {
        tokio::select! {
            svc = start_messaging(&state, sup.signal(Stage::Workers).token()) => {
                if let Some(svc) = svc {
                    let _ = state.didcomm_service.set(svc);
                }
            }
            _ = &mut signal => interrupted = true,
        }
    }

    // 6. Registration, reconcile, the TSP relationship and stats sync.
    if let Some(svc) = state.didcomm_service.get() {
        spawn_messaging_tasks(&state, svc, &mut sup);
    } else if !interrupted {
        warn!(
            "no messaging service: this edge cannot reconcile with its control plane, and will \
             report degraded once the staleness bound passes"
        );
    }

    // 6b. Reconnect to any mediator we rotated *away* from but whose grace period
    // has not elapsed. Peers holding a stale DID document are still delivering
    // there, and a restart part-way through the window must not abandon that
    // queue. No-op unless a rotation actually changed the mediator.
    crate::identity_rotation::resume_mediator_drains(&state);

    // Run until the shutdown signal, or until a critical task stops.
    let outcome = if interrupted {
        Ok(())
    } else {
        sup.run_until(&mut signal).await
    };

    // Ordered shutdown: workers (identity, registration, reconcile, stats
    // sync) → the messaging service, awaited → HTTP → storage (persist), each
    // within `SHUTDOWN_STAGE_DEADLINE`.
    sup.stop_stage(Stage::Workers, SHUTDOWN_STAGE_DEADLINE)
        .await;
    if let Some(svc) = state.didcomm_service.get() {
        match tokio::time::timeout(SHUTDOWN_STAGE_DEADLINE, svc.shutdown()).await {
            Ok(()) => info!("DIDComm service stopped"),
            Err(_) => warn!("DIDComm service did not stop within {SHUTDOWN_STAGE_DEADLINE:?}"),
        }
    }
    let stopped = sup.finish(SHUTDOWN_STAGE_DEADLINE).await;

    if let Err(failure) = outcome {
        return Err(AppError::Internal(format!("shut down because {failure}")));
    }
    if let Err(failures) = stopped {
        return Err(AppError::Internal(format!(
            "{} task(s) failed: {}",
            failures.len(),
            failures
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }

    info!("server shut down");
    Ok(())
}

// ---------------------------------------------------------------------------
// DIDComm service startup
// ---------------------------------------------------------------------------

/// The listener id [`start_didcomm_service`] registers for the edge's mediator
/// connection. Must match, or the relationship ensure targets a listener that
/// does not exist.
const SERVER_LISTENER_ID: &str = "server";

/// Establish, and keep re-establishing, this edge's TSP relationship with its
/// control plane.
///
/// Under Rev 3 §7.2.2 the control plane's application pushes are dropped unless
/// this edge holds a relationship with it. Forming one is a control message the
/// edge must actually *send* — a relationship never forms as a side effect of an
/// application send, so this has to run explicitly, and on **every** (re)connect
/// before the first send, not just first boot: the durable store keeps a formed
/// relationship across our own restarts, but a control-plane restart, or a
/// handshake that never completed, is only repaired when the edge re-invites on
/// its next connection.
///
/// [`DIDCommService::tsp_ensure_relationship`] is idempotent (it skips when the
/// relationship already admits application messages), so re-running it every
/// connect is cheap and a duplicate for the initial connect is harmless.
/// How often an edge re-registers with its control plane even when nothing
/// else prompts it. Registration reports the DIDs this edge holds, and the
/// control plane answers with whatever it is missing or behind on (and deletes
/// for what it should no longer serve) — so this bounds how long an edge can
/// serve stale state after missing pushes.
pub const RESYNC_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Register with the control plane at startup, again on every mediator
/// reconnect, and every [`RESYNC_INTERVAL`] — each registration is a delta
/// re-sync request.
async fn keep_registered(state: AppState, svc: DIDCommService) {
    let mut events = svc.subscribe();
    control_register::register_via_didcomm(&state, &svc).await;
    let mut timer = tokio::time::interval(RESYNC_INTERVAL);
    timer.tick().await; // the first tick is immediate; registration just ran
    loop {
        tokio::select! {
            _ = timer.tick() => {}
            event = events.recv() => match event {
                Ok(ListenerEvent::Connected { listener_id }) if listener_id == SERVER_LISTENER_ID => {}
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
        }
        control_register::register_via_didcomm(&state, &svc).await;
    }
}

async fn ensure_control_tsp_relationship(svc: DIDCommService, control_did: String) {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

    // Subscribe before the initial wait so a reconnect that races the first
    // ensure is not missed.
    let mut events = svc.subscribe();

    // The initial connection may have completed before `subscribe`, so its
    // `Connected` event can be absent from the stream — cover it explicitly.
    if svc
        .wait_connected(SERVER_LISTENER_ID, CONNECT_TIMEOUT)
        .await
        .is_ok()
    {
        ensure_control_tsp_relationship_once(&svc, &control_did).await;
    }

    loop {
        match events.recv().await {
            Ok(ListenerEvent::Connected { listener_id }) if listener_id == SERVER_LISTENER_ID => {
                ensure_control_tsp_relationship_once(&svc, &control_did).await;
            }
            Ok(_) => {}
            // A lagged receiver only means we missed some events; the next
            // `Connected` still re-ensures, and the relationship is idempotent.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            // The service shut down; nothing more to ensure.
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn ensure_control_tsp_relationship_once(svc: &DIDCommService, control_did: &str) {
    match svc
        .tsp_ensure_relationship(SERVER_LISTENER_ID, control_did)
        .await
    {
        Ok(()) => {
            debug!(control = %control_did, "TSP: relationship with control plane ensured")
        }
        Err(e) => warn!(
            control = %control_did,
            error = %e,
            "TSP: failed to ensure relationship with control plane — control-plane pushes may be \
             dropped until the next reconnect"
        ),
    }
}

pub async fn start_didcomm_service(
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

    // Block until the mediator DID document is resolvable. On a cold start
    // the mediator DID may be hosted by a control plane / did-hosting-server that
    // has not yet published its log, so we retry instead of starting the
    // listener against an unreachable mediator (which surfaces as a cryptic
    // "No Mediator is configured for this Profile" later).
    wait_for_did_resolution(&mediator_did, "mediator", &identity.did_resolver, &shutdown).await?;

    // Transport selection — DIDComm and/or TSP ride the same mediator
    // socket. Inbound TSP frames (sync/domain pushes from the control
    // plane's outbox) are routed to the `ServerTspHandler` when TSP is on.
    // "neither flag set but a mediator is configured" defaults to
    // DIDComm-only for back-compat.
    //
    // The union across live generations, not just the current one's config
    // flags — a generation retiring out of DIDComm still has peers delivering
    // to it until it expires, and the single listener has to carry both.
    //
    // Then reconcile against what our own DID document actually advertises: the
    // document is authoritative for how peers reach us, so the listener must
    // carry every transport it advertises. Without this, a node whose config
    // disables a transport its DID still advertises (e.g. `features.tsp = false`
    // while the DID carries `TSPTransport`, since `did-host-didcomm` advertises
    // both) silently drops — and acks — every inbound frame on that transport.
    //
    // The profile carries the key material of every live generation, and with
    // TSP on the listener persists its relationships (Rev 3 §7.2.2) so a restart
    // does not forget every peer. Built by the same function the identity
    // rebuild uses, so a rotation cannot come back with a different listener.
    let (listener, transports) = build_own_listener(
        crate::identity_rotation::LISTENER_ID,
        identity,
        &mediator_did,
        &state.store,
    )
    .await?;
    let tsp_enabled = transports.tsp;

    let router = messaging::build_server_router(state.clone())
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
        crate::tsp::ServerTspHandler::new(state.clone()),
        shutdown,
    )
    .await
    .map_err(|e| AppError::Internal(format!("failed to start messaging service: {e}")))?;

    info!(
        tsp = tsp_enabled,
        server_did = %identity.did,
        "messaging service started"
    );
    Ok(Some(svc))
}

// ---------------------------------------------------------------------------
// REST thread
// ---------------------------------------------------------------------------

fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
    upload_body_limit: usize,
    mut shutdown_rx: watch::Receiver<bool>,
    ready_tx: oneshot::Sender<()>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(state.config.limits.http_workers())
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert std TcpListener to tokio TcpListener");

        // Public DID resolution and the Trust Task listener's HTTPS binding.
        // There is no management surface to switch on.
        info!("HTTP thread started (public DID serving + Trust Task listener)");
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
        let base_router = routes::router_with_resolve_limit(upload_body_limit, resolve_limit);

        // Cloned before `with_state` consumes `state`: the health route is
        // added below the router's state type has already collapsed to
        // `()` (deliberately, so it sits outside the CORS/security-header
        // layers), so it closes over its own `AppState` rather than using
        // axum's `State` extractor.
        let health_state = state.clone();
        let trusted_proxies = state.config.server.trusted_proxies.clone();
        let app = base_router
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
            // Allow browser-based resolvers to fetch public DID documents
            // cross-origin. Read-only, unauthenticated, wildcard origin.
            .layer(did_hosting_common::server::public_resolution_cors())
            .route(
                "/api/health",
                get(move || {
                    let health_state = health_state.clone();
                    async move { routes::health::health(health_state).await }
                }),
            );

        // Signal that REST is ready to serve
        let _ = ready_tx.send(());

        // Header, idle, connection and per-address limits: see `listener`.
        // An error ends the thread, which the supervisor reports as a
        // critical exit.
        if let Err(e) = axum::serve(
            did_hosting_common::server::listener::bounded(listener, &trusted_proxies),
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        })
        .await
        {
            error!("HTTP server failed: {e}");
        }

        rate_limit_gc.cancel();
        info!("REST thread shutting down");
    });
}

// ---------------------------------------------------------------------------
// Storage thread
// ---------------------------------------------------------------------------

/// The storage ticks ([`storage_tasks`]) on a runtime of their own until
/// shutdown, then the store's persist. Storage is the last stage stopped, so
/// the persist sees every write.
fn run_storage_thread(storage: EdgeStorage, shutdown_rx: watch::Receiver<bool>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");
        run_periodic(storage_tasks(&storage), shutdown_rx).await;
        info!("storage thread shutting down");

        // Persist store before closing
        if let Err(e) = storage.store.persist().await {
            error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
}

// ---------------------------------------------------------------------------
// Auto-bootstrap
// ---------------------------------------------------------------------------

/// Extract the mnemonic (path) from a `did:webvh` DID string.
///
/// Re-exported from `did_hosting_common::server::identity`, which needs the same
/// parse to answer "was the DID just published our own?" — the question that
/// gates the rotation trigger. One copy, so the two cannot drift.
use did_hosting_common::server::identity::mnemonic_from_did;

/// How [`run_first_boot_init`] treats a failed step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstBoot {
    /// Log it and go on to the next step; succeed. The standalone edge: it
    /// treats domain seeding as best-effort metadata, so a legacy
    /// single-domain deployment without `bootstrap_domains` boots into the
    /// permissive-skip state (with warnings) rather than refusing to serve.
    Lenient,
    /// Stop at it and return it. The daemon: it owns the control plane and
    /// must have a domain catalogue for the admin write paths to work.
    Strict,
}

/// First-boot multi-domain init, shared by the standalone edge and the
/// daemon so both get the same effective state on first boot. Three steps,
/// in order:
///
/// 1. **Domain catalog seed** (`seed_domains_first_boot`) — populates
///    `KS_DOMAINS` from `[hosting] bootstrap_domains` or the legacy
///    `public_url` host. Without it, the resolve-side safety check
///    (`assert_resolution_allowed`) takes its permissive skip branch
///    on every resolve and emits a per-request warn-log.
/// 2. **Assignment seed** (`seed_assignments_first_boot`) — same tier
///    chain, populates `KS_ASSIGNMENTS`. Matters once a control plane
///    starts driving `replica/domain/assign` / unassign messages.
/// 3. **Migration runner** — `migrations`: the edge runs
///    [`did_hosting_common::server::migrations::registry`] (M-01 fills
///    `DidRecord.domain` for legacy records by parsing the embedded `did_id`
///    host), the daemon
///    [`did_hosting_common::server::migrations::control_plane_registry`],
///    which adds the control plane's derived rows.
///
/// All three are idempotent — subsequent boots short-circuit
/// (existing keyspace entries / migration markers in `meta`) so this
/// is cheap to call on every startup. `mode` says what a failure does.
pub async fn run_first_boot_init(
    store: &Store,
    config: &AppConfig,
    migrations: Vec<Arc<dyn did_hosting_common::server::migrations::Migration>>,
    mode: FirstBoot,
) -> Result<(), AppError> {
    let failed = |step: &str, e: AppError| -> Result<(), AppError> {
        match mode {
            FirstBoot::Lenient => {
                warn!(error = %e, "{step} failed");
                Ok(())
            }
            FirstBoot::Strict => Err(AppError::Internal(format!("{step} failed: {e}"))),
        }
    };

    // 1. Domain catalog
    match did_hosting_common::server::domain::seed_domains_first_boot(
        store,
        &config.hosting.bootstrap_domains,
        config.public_url.as_deref(),
    )
    .await
    {
        Ok(outcome) => info!(
            tier = ?outcome.tier,
            count = outcome.final_count,
            default = ?outcome.default,
            "first-boot domain seed"
        ),
        Err(e) => failed("first-boot domain seed", e)?,
    }

    // 2. Per-server assignments
    let now = did_hosting_common::server::auth::session::now_epoch();
    match did_hosting_common::server::assignment_seed::seed_assignments_first_boot(
        store,
        &config.hosting.bootstrap_domains,
        config.public_url.as_deref(),
        now,
    )
    .await
    {
        Ok(outcome) => info!(
            tier = ?outcome.tier,
            count = outcome.final_count,
            "first-boot assignment seed"
        ),
        Err(e) => failed("first-boot assignment seed", e)?,
    }

    // 3. Storage migrations
    let runner = did_hosting_common::server::migrations::MigrationRunner::new(migrations);
    match runner.run_pending(store).await {
        Ok(summary) => info!(
            applied = ?summary.applied,
            skipped = ?summary.skipped,
            "migration runner complete"
        ),
        Err(e) => failed("migration runner", e)?,
    }
    Ok(())
}

/// Verify DIDs in the store and log their status.
///
/// The server is a read-only edge node — it does not auto-create DIDs.
/// The setup wizard or `bootstrap-did` CLI command creates the server's
/// identity DID. This function only verifies and logs what's present.
///
/// `bin` is the binary the operator runs (`did-hosting-server`,
/// `did-hosting-daemon`); the commands the log suggests are its own.
pub async fn auto_bootstrap_dids(
    bin: &str,
    config: AppConfig,
    _store: &Store,
    dids_ks: &KeyspaceHandle,
    _secrets: &ServerSecrets,
) -> AppConfig {
    // Verify server_did exists in store (if configured)
    if let Some(ref server_did) = config.server_did
        && let Some(mnemonic) = mnemonic_from_did(server_did)
    {
        let exists = dids_ks
            .contains_key(format!("did:{mnemonic}"))
            .await
            .unwrap_or(false);
        if exists {
            info!(path = %mnemonic, "server DID loaded from store");
        } else {
            error!(
                did = %server_did,
                path = %mnemonic,
                "server DID not found in store — DID resolution will fail"
            );
            error!("  To create it, run:  {bin} bootstrap-did --path {mnemonic}");
            error!("  Then update server_did in config.toml with the new DID");
        }
    }

    // How many DIDs the store holds: counted from the keys, without reading
    // a record. Each one is listed only at debug level.
    match dids_ks.prefix_count("did:").await {
        Ok(0) => {
            warn!("no DIDs in store — run `{bin} bootstrap-did` to create one")
        }
        Ok(count) => {
            info!(count, "DIDs in store");
            if tracing::enabled!(Level::DEBUG)
                && let Ok(keys) = dids_ks.prefix_keys_raw("did:").await
            {
                for key in keys {
                    let key = String::from_utf8_lossy(&key);
                    debug!(path = %key.strip_prefix("did:").unwrap_or("?"), "  DID loaded");
                }
            }
        }
        Err(e) => warn!("failed to count DIDs: {e}"),
    }

    config
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

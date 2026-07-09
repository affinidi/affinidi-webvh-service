use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, ListenerConfig, Protocols, RestartPolicy, RetryConfig,
};
use affinidi_tdk::secrets_resolver::ThreadedSecretsResolver;
use axum::routing::get;
use did_hosting_common::server::domain::parse_trusted_cidrs;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS};
use ipnetwork::IpNetwork;

use did_hosting_common::server::auth::extractor::AuthState;
use did_hosting_common::server::didcomm_profile::{build_tdk_profile, wait_for_did_resolution};
use did_hosting_common::server::init;
use tokio_util::sync::CancellationToken;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
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
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub dids_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub signing_key_bytes: Option<[u8; 32]>,
    pub http_client: reqwest::Client,
    pub stats_collector: Option<Arc<stats::StatsCollector>>,
    /// In-memory cache for DID content (did.jsonl). TTL-based eviction on read.
    pub did_cache: Arc<crate::cache::ContentCache>,
    /// Parsed `server.trusted_proxy_cidrs` — peers inside this set
    /// have their `Forwarded` / `X-Forwarded-Host` headers honoured
    /// for request-host detection (multi-domain, T19/T21).
    pub trusted_proxy_cidrs: Arc<Vec<IpNetwork>>,
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
    let sessions_ks = store.keyspace(KS_SESSIONS)?;
    let acl_ks = store.keyspace(KS_ACL)?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    // Integrity check on DID keyspace
    match dids_ks.verify_integrity().await {
        Ok(0) => debug!("store integrity check passed"),
        Ok(n) => warn!(
            corrupted = n,
            "store integrity check found corrupted entries"
        ),
        Err(e) => warn!(error = %e, "store integrity check failed"),
    }

    // First-boot multi-domain init (daemon parity with
    // did-hosting-daemon/src/main.rs:544-622). Three idempotent steps:
    //
    //   1. seed_domains_first_boot — populates KS_DOMAINS from
    //      `[hosting] bootstrap_domains`, falling back to legacy
    //      `public_url` host on upgrade. Without this, the
    //      resolve-side safety check (assert_resolution_allowed) takes
    //      the "permissive skip" branch on every resolve and emits a
    //      warn-log per request — annoying noise on standalone v0.6
    //      → v0.7 upgrades.
    //   2. seed_assignments_first_boot — same tier chain, populates
    //      KS_ASSIGNMENTS so this server knows which domains it
    //      serves (matters once a control plane starts driving
    //      MSG_DOMAIN_ASSIGN / unassign).
    //   3. MigrationRunner::run_pending — runs T13 M-01 which fills
    //      DidRecord.domain for legacy records by parsing the
    //      embedded did_id host. Required for write-side checks
    //      that key on domain once domains are configured.
    //
    // All three are idempotent (markers in `meta` keyspace gate the
    // migration; existing keyspace entries short-circuit the seeds),
    // so re-running on every boot is cheap.
    run_first_boot_init(&store, &config).await;
    // Auto-bootstrap DIDs if public_url is set and they don't exist yet
    let config = auto_bootstrap_dids(config, &store, &dids_ks, &secrets).await;

    // Initialize DIDComm auth infrastructure (requires server_did)
    let (did_resolver, secrets_resolver) =
        init::init_didcomm_auth(config.server_did.as_deref(), &secrets).await;

    // Initialize JWT keys independently — needed by both DIDComm and passkey auth
    let jwt_keys = init::init_jwt_keys(&secrets);

    // Extract raw signing key bytes for pack_signed operations
    let signing_key_bytes = init::decode_multibase_ed25519_key(&secrets.signing_key).ok();

    // Always bind TCP — the server must serve public DID documents even when
    // the management REST API is disabled. The rest_api flag controls whether
    // /api/* routes are included, not whether HTTP is served.
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let std_listener = {
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("server listening addr={addr}");
        listener
    };

    // Gather storage thread inputs before moving config into Arc
    let storage_sessions_ks = sessions_ks.clone();
    let storage_dids_ks = dids_ks.clone();
    let storage_auth_config = config.auth.clone();
    let has_auth = jwt_keys.is_some();

    let upload_body_limit = config.limits.upload_body_limit;
    let stats_config = config.stats.clone();

    // Initialize in-memory stats collector (starts at zero — no disk persistence)
    let stats_collector = {
        let collector = stats::StatsCollector::new();
        let total_dids = storage_dids_ks
            .prefix_iter_raw("did:")
            .await
            .map(|v| v.len())
            .unwrap_or(0) as u64;
        collector.set_total_dids(total_dids);
        info!(total_dids, "stats collector initialized");
        Arc::new(collector)
    };

    let (parsed_cidrs, bad_cidrs) = parse_trusted_cidrs(&config.server.trusted_proxy_cidrs);
    if !bad_cidrs.is_empty() {
        warn!(
            bad_cidrs = ?bad_cidrs,
            "server.trusted_proxy_cidrs contains unparseable entries; ignoring them"
        );
    }

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        dids_ks,
        config: Arc::new(config),
        did_resolver,
        secrets_resolver,
        jwt_keys,
        signing_key_bytes,
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client"),
        stats_collector: Some(stats_collector.clone()),
        did_cache: Arc::new(crate::cache::ContentCache::new(Duration::from_secs(300))),
        trusted_proxy_cidrs: Arc::new(parsed_cidrs),
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

    // Separate shutdown channels for ordered shutdown (DIDComm → REST → Storage)
    let (rest_shutdown_tx, rest_shutdown_rx) = watch::channel(false);
    let (storage_shutdown_tx, storage_shutdown_rx) = watch::channel(false);

    // REST ready signal — DIDComm waits for this before starting
    let (rest_ready_tx, rest_ready_rx) = oneshot::channel::<()>();

    // 1. Spawn HTTP thread first — must be serving before DIDComm starts
    //    (the server's own DID needs to be resolvable for mediator auth)
    let mut rest_shutdown = rest_shutdown_rx.clone();
    let rest_state = state.clone();
    let rest_handle = std::thread::Builder::new()
        .name("webvh-rest".into())
        .spawn(move || {
            run_rest_thread(
                std_listener,
                rest_state,
                upload_body_limit,
                &mut rest_shutdown,
                rest_ready_tx,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn HTTP thread: {e}")))?;

    // 2. Spawn storage thread (independent cleanup, flush, sync)
    let mut storage_shutdown = storage_shutdown_rx.clone();
    let storage_collector = stats_collector.clone();
    let storage_http = state.http_client.clone();
    let storage_control_url = state.config.control_url.clone();
    let storage_server_did = state.config.server_did.clone();
    let storage_stats_config = stats_config;
    let storage_handle = std::thread::Builder::new()
        .name("webvh-storage".into())
        .spawn(move || {
            run_storage_thread(
                StorageThreadParams {
                    store,
                    sessions_ks: storage_sessions_ks,
                    dids_ks: storage_dids_ks,
                    auth_config: storage_auth_config,
                    has_auth,
                    collector: storage_collector,
                    stats_config: storage_stats_config,
                    http: storage_http,
                    control_url: storage_control_url,
                    server_did: storage_server_did,
                },
                &mut storage_shutdown,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // 3. Wait for REST to be serving before starting DIDComm
    //    (the server's own DID needs to be resolvable for mediator auth)
    let _ = rest_ready_rx.await;

    // 4. Start the mediator messaging service (DIDComm and/or TSP) — one
    //    connection for both receiving and sending. TSP-only deployments
    //    (didcomm off, tsp on) must still start it.
    let didcomm_shutdown = CancellationToken::new();
    let didcomm_service = if state.config.features.didcomm || state.config.features.tsp {
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

    // 5. Register with control plane via DIDComm (uses the shared connection)
    if let Some(ref svc) = didcomm_service
        && state.config.control_did.is_some()
    {
        let reg_state = state.clone();
        let reg_svc = svc.clone();
        tokio::spawn(async move {
            control_register::register_via_didcomm(&reg_state, &reg_svc).await;
        });
    }

    // 6. Spawn DIDComm stats sync task (runs on main tokio runtime)
    let stats_sync_shutdown = CancellationToken::new();
    let didcomm_sync_interval = state.config.stats.sync_interval_secs;
    if let (Some(svc), Some(control_did), Some(server_did)) = (
        didcomm_service.as_ref(),
        state.config.control_did.as_ref(),
        state.config.server_did.as_ref(),
    ) && didcomm_sync_interval > 0
    {
        let token = stats_sync_shutdown.clone();
        let svc = svc.clone();
        let control_did = control_did.clone();
        let server_did = server_did.clone();
        let collector = stats_collector.clone();
        tokio::spawn(async move {
            let mut timer =
                tokio::time::interval(Duration::from_secs(didcomm_sync_interval.max(1)));
            timer.tick().await; // skip first tick
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        stats::sync_to_control_didcomm(
                            &svc,
                            &server_did,
                            &control_did,
                            &collector,
                        ).await;
                    }
                    _ = token.cancelled() => break,
                }
            }
        });
    }

    // Wait for shutdown signal
    init::shutdown_signal().await;

    // Ordered shutdown: stats sync → DIDComm → REST → Storage
    let mut any_panic = false;

    stats_sync_shutdown.cancel();
    didcomm_shutdown.cancel();
    if let Some(ref svc) = didcomm_service {
        svc.shutdown().await;
        info!("DIDComm service stopped");
    }

    let _ = rest_shutdown_tx.send(true);
    {
        let handle = rest_handle;
        match tokio::time::timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || handle.join()),
        )
        .await
        {
            Ok(Ok(Ok(()))) => info!("REST thread stopped"),
            Ok(Ok(Err(_panic))) => {
                error!("REST thread panicked");
                any_panic = true;
            }
            Ok(Err(e)) => {
                error!("failed to join REST thread: {e}");
                any_panic = true;
            }
            Err(_) => {
                error!("REST thread shutdown timed out (30s)");
                any_panic = true;
            }
        }
    }

    let _ = storage_shutdown_tx.send(true);
    match tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || storage_handle.join()),
    )
    .await
    {
        Ok(Ok(Ok(()))) => info!("storage thread stopped"),
        Ok(Ok(Err(_panic))) => {
            error!("storage thread panicked");
            any_panic = true;
        }
        Ok(Err(e)) => {
            error!("failed to join storage thread: {e}");
            any_panic = true;
        }
        Err(_) => {
            error!("storage thread shutdown timed out (30s)");
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

pub async fn start_didcomm_service(
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

    // Block until the mediator DID document is resolvable. On a cold start
    // the mediator DID may be hosted by a control plane / did-hosting-server that
    // has not yet published its log, so we retry instead of starting the
    // listener against an unreachable mediator (which surfaces as a cryptic
    // "No Mediator is configured for this Profile" later).
    if let Some(resolver) = state.did_resolver.as_ref() {
        wait_for_did_resolution(mediator_did, "mediator", resolver, &shutdown).await?;
    }

    let profile = build_tdk_profile(
        "server",
        server_did,
        Some(mediator_did),
        secrets,
        state.did_resolver.as_ref(),
    )
    .await?;

    // Transport selection — DIDComm and/or TSP ride the same mediator
    // socket. Inbound TSP frames (sync/domain pushes from the control
    // plane's outbox) are routed to the `ServerTspHandler` when TSP is on.
    // "neither flag set but a mediator is configured" defaults to
    // DIDComm-only for back-compat.
    let didcomm_enabled = state.config.features.didcomm;
    let tsp_enabled = state.config.features.tsp;
    let protocols = match (didcomm_enabled, tsp_enabled) {
        (true, true) => Protocols::BOTH,
        (false, true) => Protocols::TSP_ONLY,
        _ => Protocols::DIDCOMM_ONLY,
    };

    let listener = ListenerConfig {
        id: "server".into(),
        profile,
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        protocols,
        ..Default::default()
    };

    let router = messaging::build_server_router(state.clone())
        .map_err(|e| AppError::Internal(format!("failed to build DIDComm router: {e}")))?;

    let config = DIDCommServiceConfig {
        listeners: vec![listener],
    };

    let svc = if tsp_enabled {
        info!("starting messaging service with DIDComm + TSP on the mediator connection");
        DIDCommService::start_with_tsp(
            config,
            router,
            crate::tsp::ServerTspHandler::new(state.clone()),
            shutdown,
        )
        .await
    } else {
        info!("starting DIDComm service with mediator connection");
        DIDCommService::start(config, router, shutdown).await
    }
    .map_err(|e| AppError::Internal(format!("failed to start messaging service: {e}")))?;

    info!(
        tsp = tsp_enabled,
        "messaging service started for {server_did}"
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
    shutdown_rx: &mut watch::Receiver<bool>,
    ready_tx: oneshot::Sender<()>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to build REST runtime");

    rt.block_on(async {
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .expect("failed to convert std TcpListener to tokio TcpListener");

        // When rest_api is disabled, serve only public DID routes + health.
        // When enabled, serve full management API + public DID routes.
        let base_router = if state.config.features.rest_api {
            info!("HTTP thread started (REST API + public DID serving)");
            routes::router(upload_body_limit)
        } else {
            info!("HTTP thread started (public DID serving only, REST API disabled)");
            routes::router_public_only().fallback(routes::did_public::serve_public)
        };

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
// Storage thread
// ---------------------------------------------------------------------------

/// Parameters for the background storage thread.
struct StorageThreadParams {
    store: Store,
    sessions_ks: KeyspaceHandle,
    dids_ks: KeyspaceHandle,
    auth_config: AuthConfig,
    has_auth: bool,
    collector: Arc<stats::StatsCollector>,
    stats_config: crate::config::StatsConfig,
    http: reqwest::Client,
    control_url: Option<String>,
    server_did: Option<String>,
}

fn run_storage_thread(params: StorageThreadParams, shutdown_rx: &mut watch::Receiver<bool>) {
    let StorageThreadParams {
        store,
        sessions_ks,
        dids_ks,
        auth_config,
        has_auth,
        collector,
        stats_config,
        http,
        control_url,
        server_did,
    } = params;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!(
            sync_interval = stats_config.sync_interval_secs,
            "storage thread started"
        );

        let session_interval = Duration::from_secs(auth_config.session_cleanup_interval);
        let did_ttl_seconds = auth_config.cleanup_ttl_minutes * 60;
        let did_interval = Duration::from_secs(did_ttl_seconds.max(60));
        let sync_enabled = stats_config.sync_interval_secs > 0 && control_url.is_some();
        let sync_interval = Duration::from_secs(stats_config.sync_interval_secs.max(1));

        let mut session_timer = tokio::time::interval(session_interval);
        let mut did_timer = tokio::time::interval(did_interval);
        let mut sync_timer = tokio::time::interval(sync_interval);

        // First tick completes immediately; skip so cleanup doesn't run at startup
        session_timer.tick().await;
        did_timer.tick().await;
        sync_timer.tick().await;

        loop {
            tokio::select! {
                _ = session_timer.tick(), if has_auth => {
                    if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
                        warn!("session cleanup error: {e}");
                    }
                }
                _ = did_timer.tick() => {
                    match cleanup_empty_dids(&dids_ks, did_ttl_seconds).await {
                        Ok(0) => {}
                        Ok(n) => {
                            info!(count = n, "cleaned up empty DID records");
                            // Adjust count for cleaned up records
                            for _ in 0..n {
                                collector.decrement_total_dids();
                            }
                        }
                        Err(e) => warn!("DID cleanup error: {e}"),
                    }
                }
                _ = sync_timer.tick(), if sync_enabled => {
                    if let (Some(url), Some(did)) = (&control_url, &server_did) {
                        stats::sync_to_control(&http, url, did, &collector).await;
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
// Auto-bootstrap
// ---------------------------------------------------------------------------

/// Extract the mnemonic (path) from a did:webvh DID string.
///
/// `did:webvh:{SCID}:{host}:{path:components}` → `path/components`
/// Colons in the path portion are converted back to `/`.
fn mnemonic_from_did(did: &str) -> Option<String> {
    // did:webvh:{SCID}:{host}:{path...}
    let rest = did.strip_prefix("did:webvh:")?;
    let parts: Vec<&str> = rest.splitn(4, ':').collect();
    // parts[0] = SCID, parts[1] = host (possibly with %3A port), parts[2..] = path
    if parts.len() < 3 {
        return None;
    }
    // The host may contain %3A (encoded port), which counts as one segment.
    // After SCID and host, the remaining colon-separated segments form the path.
    // But the host itself may have been split if it didn't contain %3A.
    // Re-parse: skip SCID, skip host (which may contain %3A), rest is path.
    let after_scid = rest.split_once(':')?.1; // "{host}:{path...}"

    // Host is everything up to the first segment that doesn't look like a host
    // Simpler: host is the first segment after SCID (it contains the domain)
    let after_host = after_scid.split_once(':')?.1; // "{path...}"

    let mnemonic = after_host.replace(':', "/");
    Some(mnemonic)
}

/// First-boot multi-domain init for the standalone server.
///
/// Mirrors the daemon's `did-hosting-daemon/src/main.rs:544-622` block
/// so a standalone `did-hosting-server` deployment gets the same
/// effective state on first boot. Three steps, in order:
///
/// 1. **Domain catalog seed** (`seed_domains_first_boot`) — populates
///    `KS_DOMAINS` from `[hosting] bootstrap_domains` or the legacy
///    `public_url` host. Without it, the resolve-side safety check
///    (`assert_resolution_allowed`) takes its permissive skip branch
///    on every resolve and emits a per-request warn-log.
/// 2. **Assignment seed** (`seed_assignments_first_boot`) — same tier
///    chain, populates `KS_ASSIGNMENTS`. Matters once a control plane
///    starts driving `MSG_DOMAIN_ASSIGN` / unassign messages.
/// 3. **Migration runner** (`MigrationRunner::run_pending`) — runs
///    `m01_tag_did_records_with_domain` which fills
///    `DidRecord.domain` for legacy records by parsing the embedded
///    `did_id` host. Required for any write path that keys on
///    `domain` once domains are configured.
///
/// All three are idempotent — subsequent boots short-circuit
/// (existing keyspace entries / migration markers in `meta`) so this
/// is cheap to call on every startup.
///
/// Failures log loudly but do **not** abort startup. The standalone
/// server's design treats domain seeding as best-effort metadata: a
/// legacy single-domain deployment without `bootstrap_domains`
/// configured boots into the permissive-skip state (with warnings)
/// rather than refusing to serve. The daemon's stricter
/// `std::process::exit(1)` is appropriate there because the daemon
/// owns the control plane and *must* have a domain catalog to make
/// admin write paths work; the standalone server has no such
/// guarantee.
pub async fn run_first_boot_init(store: &Store, config: &AppConfig) {
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
        Err(e) => warn!(error = %e, "first-boot domain seed failed"),
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
        Err(e) => warn!(error = %e, "first-boot assignment seed failed"),
    }

    // 3. Storage migrations (T2 runner + T13 M-01)
    let runner = did_hosting_common::server::migrations::MigrationRunner::new(
        did_hosting_common::server::migrations::registry(),
    );
    match runner.run_pending(store).await {
        Ok(summary) => info!(
            applied = ?summary.applied,
            skipped = ?summary.skipped,
            "migration runner complete"
        ),
        Err(e) => warn!(error = %e, "migration runner failed"),
    }
}

/// Verify DIDs in the store and log their status.
///
/// The server is a read-only edge node — it does not auto-create DIDs.
/// The setup wizard or `bootstrap-did` CLI command creates the server's
/// identity DID. This function only verifies and logs what's present.
pub async fn auto_bootstrap_dids(
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
            error!("  To create it, run:  did-hosting-server bootstrap-did --path {mnemonic}");
            error!("  Then update server_did in config.toml with the new DID");
        }
    }

    // Log all DIDs present in the store
    match dids_ks.prefix_iter_raw("did:").await {
        Ok(entries) => {
            let count = entries.len();
            if count == 0 {
                warn!("no DIDs in store — run `did-hosting-server bootstrap-did` to create one");
            } else {
                info!(count, "DIDs in store:");
                for (key, _) in &entries {
                    let mnemonic = String::from_utf8_lossy(key)
                        .strip_prefix("did:")
                        .unwrap_or("?")
                        .to_string();
                    info!(path = %mnemonic, "  DID loaded");
                }
            }
        }
        Err(e) => warn!("failed to list DIDs: {e}"),
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_from_did_simple() {
        let did =
            "did:webvh:QmaErmPvnHUDaaiM4phkDgrK58T49cxgmCUtKon9gwyWtJ:webvh.storm.ws:webvh:server1";
        assert_eq!(mnemonic_from_did(did).unwrap(), "webvh/server1");
    }

    #[test]
    fn mnemonic_from_did_single_path() {
        let did = "did:webvh:QmABC:example.com:my-did";
        assert_eq!(mnemonic_from_did(did).unwrap(), "my-did");
    }

    #[test]
    fn mnemonic_from_did_deep_path() {
        let did = "did:webvh:QmABC:example.com:people:staff:glenn";
        assert_eq!(mnemonic_from_did(did).unwrap(), "people/staff/glenn");
    }

    #[test]
    fn mnemonic_from_did_invalid() {
        assert!(mnemonic_from_did("did:web:example.com").is_none());
        assert!(mnemonic_from_did("not-a-did").is_none());
    }
}

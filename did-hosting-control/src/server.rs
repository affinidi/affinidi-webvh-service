use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_service::{
    DIDCommService, DIDCommServiceConfig, ListenerConfig, Protocols, RestartPolicy, RetryConfig,
};
use affinidi_tdk::secrets_resolver::ThreadedSecretsResolver;
use did_hosting_common::server::auth::extractor::AuthState;
use did_hosting_common::server::didcomm_profile::{
    advertised_protocols, build_tdk_profile_for_identity, reconcile_listener_protocols,
    wait_for_did_resolution,
};
use did_hosting_common::server::identity::{self, ServiceIdentity};
use did_hosting_common::server::init;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
};
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

/// What a cache-eviction hook is told has changed in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheChange<'a> {
    /// One DID's record, log or witness file, by mnemonic.
    Did(&'a str),
    /// A domain entry (created, updated, enabled, disabled or purged).
    Domains,
}

/// A cache-eviction hook: told what changed, so whatever it cached from
/// that is now stale. See `AppState::cache_invalidate`.
pub type CacheInvalidateFn = dyn Fn(CacheChange<'_>) + Send + Sync;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub sessions_ks: KeyspaceHandle,
    pub acl_ks: KeyspaceHandle,
    pub registry_ks: KeyspaceHandle,
    /// Opened with [`Store::keyspace_consistent`]: its reads decide writes.
    pub dids_ks: KeyspaceHandle,
    pub config: Arc<AppConfig>,
    pub did_resolver: Option<DIDCacheClient>,
    pub secrets_resolver: Option<Arc<ThreadedSecretsResolver>>,
    /// The service's own DID identity: every generation of key material still
    /// honoured, and the kids each one answers to.
    ///
    /// `did_resolver` and `secrets_resolver` above are clones taken from this
    /// — both are cheap (the cache client is internally `Arc`'d, the secrets
    /// resolver already an `Arc`). They remain separate fields because most
    /// callers want only one of them. This is the source of truth for *which
    /// kids* those resolvers answer to, and the listener's profile is built
    /// from it, so the two cannot drift apart the way they did when each
    /// resolved the DID document independently.
    pub identity: Option<Arc<ServiceIdentity>>,
    /// Trust Tasks proof verifier — backed by the
    /// `affinidi-data-integrity` crate, sharing the same
    /// [`DIDCacheClient`] as `did_resolver` for verificationMethod
    /// lookups. `None` when `did_resolver` is unconfigured (e.g. a
    /// non-DIDComm deployment); in that case the trust-tasks pipeline
    /// runs in proof-optional mode — a present proof is ignored, a
    /// REQUIRED proof on the spec is not enforced. v0.7.0 ships this
    /// way for backwards compat; v0.8.0 makes the verifier mandatory
    /// for the strict-proof specs (`acl/grant`, `acl/revoke`,
    /// `acl/change-role`).
    /// `TransportBoundVerifier`, not the stock `affinidi::Verifier`: it
    /// enforces the in-band issuer↔`verificationMethod` binding only when an
    /// `issuer` is asserted, and verifies the signature alone when it is
    /// absent. That absent case is the passkey delegation path (the
    /// ephemeral session key signs; the JWT carries the responsible DID),
    /// which the stock verifier rejects. See `TransportBoundVerifier` docs.
    pub trust_tasks_verifier:
        Option<Arc<did_hosting_common::server::trust_tasks::TransportBoundVerifier>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub webauthn: Option<Arc<Webauthn>>,
    pub http_client: reqwest::Client,
    /// DIDComm service for inbound/outbound mediator messaging.
    /// Wrapped in `OnceLock` so cloned states see it once it's initialized
    /// (the service starts after REST + DIDComm router are already cloned).
    pub didcomm_service: Arc<std::sync::OnceLock<DIDCommService>>,
    /// In-memory stats collector — accumulates per-DID deltas from servers,
    /// flushed periodically to the stats keyspace.
    pub stats_collector: Arc<did_hosting_common::server::stats_collector::StatsCollector>,
    /// Stats keyspace for persistent per-DID **aggregate** stats —
    /// `stats:{mnemonic}` rows. Schema is `DidStats` (totals +
    /// last_resolved_at + last_updated_at).
    pub stats_ks: KeyspaceHandle,
    /// Time-series keyspace for 5-minute aggregate buckets —
    /// `ts:{mnemonic}:{bucket_epoch}` rows for per-DID buckets and
    /// `ts:_all:{bucket_epoch}` for server-wide. Schema is
    /// `{r: u64, u: u64}`. Split out from `stats_ks` in v0.7 so a
    /// future `prefix_iter_raw("")` over either keyspace returns
    /// homogeneous-shaped values rather than two different schemas.
    pub timeseries_ks: KeyspaceHandle,
    /// Ed25519 signing key bytes for packing DIDComm responses (REST endpoint).
    ///
    /// SECURITY: this is a raw 32-byte seed. `AppState` deliberately does
    /// NOT derive `Debug` — adding it would format this field via the
    /// default tuple printer and the seed would land in any subsequent
    /// `tracing::*` macro that takes `?state` or `state = ?state`. If a
    /// `Debug` derive is added later, wrap this in a redacting newtype
    /// (or `secrecy::SecretBox`) at the same time.
    pub signing_key_bytes: Option<[u8; 32]>,
    /// Anti-replay cache for inbound DIDComm `(sender, msg.id)` pairs.
    /// Both transports gate through it before dispatch to reject
    /// captured-and-resubmitted envelopes within the freshness window.
    pub replay_cache: Arc<crate::replay::ReplayCache>,
    /// Per-mnemonic write lock. `register_did_atomic` (and any other
    /// read-then-write operation on the same path) holds the lock for
    /// the duration of its read + build + commit window so two
    /// concurrent calls on the same path can't both observe
    /// `existing == None` and both commit.
    pub path_locks: crate::path_locks::PathLocks,
    /// Per-key write lock for Trust Tasks ACL mutations. Separate
    /// from `path_locks` so DID-mnemonic locking and ACL-write locking
    /// don't share a keyspace — the `grant` / `change-role` /
    /// `revoke` handlers acquire a single fixed key
    /// (`ACL_WRITE_LOCK_KEY`) here so concurrent admins serialise
    /// through one queue, closing the race the last-authority guard
    /// would otherwise have.
    pub acl_locks: did_hosting_common::server::path_locks::PathLocks,
    /// Bounded set of live authentication challenges, with per-DID and
    /// global caps. Replaces an O(N) prefix scan in
    /// `routes::auth::challenge`; closes the unauthenticated
    /// challenge-endpoint storage-exhaustion + CPU-amplification
    /// surface (review SM3). Members expire with `challenge_ttl`, so a
    /// slot is never held past the life of its challenge.
    pub pending_challenges: Arc<crate::pending_challenges::PendingChallengeTracker>,
    /// Per-IP rate limiter for the unauthenticated challenge endpoint.
    /// Network-layer defence-in-depth that complements the per-DID +
    /// global counters above. See `crate::rate_limit` for the
    /// trusted-proxy / X-Forwarded-For policy.
    pub ip_rate_limiter: Arc<crate::rate_limit::IpRateLimiter>,
    /// Per-source limiter for passkey invite redemption
    /// (`auth/passkey/enroll/redeem/start`). See
    /// [`crate::rate_limit::SourceRateLimiter`].
    pub redeem_rate_limiter: Arc<crate::rate_limit::SourceRateLimiter>,
    /// Per-address budget for large documents (over the framework's default
    /// 64 KiB) a claimed — not yet verified — known issuer is granted a
    /// raised size limit for. See
    /// [`did_hosting_common::server::trust_tasks::size`].
    pub large_document_budget:
        Arc<did_hosting_common::server::trust_tasks::size::LargeDocumentBudget>,
    /// Wakes the [`crate::outbox`] worker when a new entry lands in
    /// the durable outbound queue. The route handlers call
    /// `outbox::enqueue_and_notify`, which writes to fjall + fires
    /// this notify so delivery happens promptly in the happy path.
    /// On notify-miss the worker still runs on its 30 s tick.
    pub outbox_notify: Arc<tokio::sync::Notify>,
    /// Evicts what resolution cached about a DID or the domains when this
    /// process also serves resolution from the same store — the unified
    /// `did-hosting-daemon`, which wires this to its embedded server's
    /// content cache and gate cache.
    ///
    /// `None` for a standalone control plane: it holds no content cache of
    /// its own, and a registered edge's cache is kept in step independently,
    /// by `webvh/sync/*` invalidating on receipt
    /// (`did-hosting-server::control_register`). Without this hook, a direct
    /// mutation here (register, publish, disable, rollback, delete) would
    /// leave the daemon's embedded server serving a stale or since-deleted
    /// cache entry for up to its TTL — there is no sync round-trip within a
    /// single process to invalidate it the way a standalone edge does. The
    /// daemon also caches each DID's record and the domains (its gate
    /// cache), so a DID disabled or a domain disabled here without this
    /// call would keep resolving.
    pub cache_invalidate: Option<Arc<CacheInvalidateFn>>,
    /// Wallet sign-in with a trigger link (`auth/oob/*`): the open requests
    /// and their limiters. See [`crate::oob`].
    pub oob: Arc<crate::oob::OobRuntime>,
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

    /// Whether `did` holds at least one step-up-only passkey credential —
    /// backs the extractor's TOCTOU close (#190): an `aal2` session whose
    /// `amr` lacks `"passkey"` is only ever downgraded back to `aal1` when
    /// this returns `true`, so the store read only happens on that rare
    /// path, never on every request.
    fn has_step_up_passkey(&self, did: &str) -> impl std::future::Future<Output = bool> + Send {
        let store = self.store.clone();
        let did = did.to_string();
        async move {
            let Ok(ks) = store.keyspace(did_hosting_common::server::store::KS_PASSKEY_STEP_UP)
            else {
                return false;
            };
            did_hosting_common::server::passkey::store::get_passkey_user_by_did(&ks, &did)
                .await
                .ok()
                .flatten()
                .is_some_and(|user| !user.credentials.is_empty())
        }
    }
}

/// Open the configured GeoIP database and named networks (see
/// [`crate::geoip`]). Never fails on the file itself — only if the blocking
/// read task cannot be joined.
pub async fn open_geoip(
    config: &crate::config::GeoIpConfig,
) -> Result<Arc<crate::geoip::GeoIp>, AppError> {
    let path = config.database.clone();
    let networks = config.networks.iter().map(|n| (n.cidr, n.location.clone()));
    tokio::task::spawn_blocking(move || crate::geoip::GeoIp::open(path))
        .await
        .map(|geoip| Arc::new(geoip.with_networks(networks)))
        .map_err(|e| AppError::Internal(format!("GeoIP database load task: {e}")))
}

pub async fn run(config: AppConfig, store: Store, secrets: ServerSecrets) -> Result<(), AppError> {
    // Validate that at least one management interface is enabled
    if !config.features.rest_api && !config.features.didcomm && !config.features.tsp {
        return Err(AppError::Config(
            "at least one of 'rest_api', 'didcomm', or 'tsp' must be enabled in [features]".into(),
        ));
    }

    #[cfg(feature = "ui")]
    if !config.features.rest_api {
        warn!("UI feature is compiled in but rest_api is disabled — UI will not be accessible");
    }

    // Open keyspace handles
    let sessions_ks = store.keyspace(KS_SESSIONS)?;
    let acl_ks = store.keyspace(KS_ACL)?;
    let registry_ks = store.keyspace(KS_REGISTRY)?;
    // Strongly consistent: the control plane's DID reads decide writes
    // (ownership, slot existence, what to push to edges), so a read that
    // missed a just-committed write could hand one owner's slot to another.
    let dids_ks = store.keyspace_consistent(KS_DIDS)?;
    let stats_ks = store.keyspace(KS_STATS)?;
    // Time-series buckets live in their own keyspace from v0.7 — see
    // the `timeseries_ks` field doc on `AppState`.
    let timeseries_ks = store.keyspace(KS_TIMESERIES)?;

    // Load the service's own identity (requires server_did). This resolves the
    // DID document for the *real* verification-method key IDs and seeds the
    // secrets resolver under them, rather than assuming `#key-0` / `#key-1`.
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
    // No unsigned mode: a control plane that cannot sign refuses to start.
    crate::signing::require_signing_identity(identity.as_deref(), config.server_did.as_deref())?;
    let did_resolver = identity.as_ref().map(|i| i.did_resolver.clone());
    let secrets_resolver = identity.as_ref().map(|i| i.secrets_resolver.clone());

    // Initialize JWT keys
    let jwt_keys = init::init_jwt_keys(&secrets);

    // Initialize WebAuthn for passkeys
    let webauthn = config.public_url.as_ref().and_then(|url| {
        match did_hosting_common::server::passkey::build_webauthn(url) {
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
    let storage_auth_config = config.auth.clone();
    let replay_config = config.replay.clone();
    let has_auth = jwt_keys.is_some();

    let stats_dids_ks = dids_ks.clone();
    // Trust Tasks verifier — over the configured DID cache, so `did:web` /
    // `did:webvh` verificationMethod lookups hit the same cache the DIDComm
    // path already populates. Built by the one shared constructor (the daemon
    // builds its control-plane verifier with it too).
    let trust_tasks_verifier =
        did_hosting_common::server::trust_tasks::build_verifier(did_resolver.as_ref());

    let pending_challenges =
        crate::pending_challenges::PendingChallengeTracker::for_auth_config(&config.auth);

    // The local GeoIP database, if configured (base design §12.6). Advisory:
    // a file that cannot be read is a warning, and sign-in locations show as
    // "unknown". Read off the runtime's workers — it can be 100+ MB.
    let geoip = open_geoip(&config.geoip).await?;

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        registry_ks,
        dids_ks,
        config: Arc::new(config),
        did_resolver,
        secrets_resolver,
        identity,
        trust_tasks_verifier,
        jwt_keys,
        webauthn,
        // Disable redirect-following: combined with the proxy's
        // Authorization-header passthrough, an attacker-registered backend
        // URL must not be able to redirect the proxy onto a third-party host
        // and harvest the forwarded JWT.
        http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Fail fast: this client backs the Admin reverse proxy, so a slow or
            // hung (even allow-listed) backend must not pin the handler task and
            // its connection open indefinitely. Matches the edge/daemon clients.
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest client construction must succeed"),
        didcomm_service: Arc::new(std::sync::OnceLock::new()),
        stats_collector: {
            use did_hosting_common::server::stats_collector::{StatsAggregate, StatsCollector};
            let collector = StatsCollector::new();
            // Seed aggregate from stored per-DID stats
            let mut total_resolves = 0u64;
            let mut total_updates = 0u64;
            let mut last_resolved_at: Option<u64> = None;
            let mut last_updated_at: Option<u64> = None;
            if let Ok(raw) = stats_ks.prefix_iter_raw("stats:").await {
                for (_key, value) in raw {
                    if let Ok(s) = serde_json::from_slice::<did_hosting_common::DidStats>(&value) {
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
        timeseries_ks: timeseries_ks.clone(),
        signing_key_bytes: init::decode_multibase_ed25519_key(&secrets.signing_key).ok(),
        replay_cache: Arc::new(crate::replay::ReplayCache::with_config(replay_config)?),
        path_locks: crate::path_locks::PathLocks::new(),
        acl_locks: did_hosting_common::server::path_locks::PathLocks::new(),
        pending_challenges: Arc::new(pending_challenges),
        ip_rate_limiter: Arc::new(crate::rate_limit::IpRateLimiter::new()),
        redeem_rate_limiter: Arc::new(crate::rate_limit::SourceRateLimiter::new()),
        large_document_budget: Arc::new(
            did_hosting_common::server::trust_tasks::size::LargeDocumentBudget::new(),
        ),
        outbox_notify: Arc::new(tokio::sync::Notify::new()),
        // Standalone control plane: no content cache of its own to
        // invalidate. See the field doc.
        cache_invalidate: None,
        oob: Arc::new(crate::oob::OobRuntime::with_geoip(geoip)),
    };

    // Reload challenges issued before a restart, so the caps hold across it.
    state
        .pending_challenges
        .seed_from_sessions_or_warn(&state.sessions_ks)
        .await;

    backfill_service_badges(&state.store).await;

    // Seed registry from static config
    seed_registry(&state).await;

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

    // 2. Spawn storage thread (cleanup + stats flush)
    let mut storage_shutdown = storage_shutdown_rx.clone();
    let storage_stats_ks = state.stats_ks.clone();
    let storage_timeseries_ks = state.timeseries_ks.clone();
    let storage_dids_ks = state.dids_ks.clone();
    let storage_collector = state.stats_collector.clone();
    let storage_handle = std::thread::Builder::new()
        .name("control-storage".into())
        .spawn(move || {
            run_storage_thread(
                store,
                storage_sessions_ks,
                storage_stats_ks,
                storage_timeseries_ks,
                storage_dids_ks,
                storage_auth_config,
                has_auth,
                storage_collector,
                &mut storage_shutdown,
            )
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // Wait for REST to be ready before starting DIDComm
    let _ = rest_ready_rx.await;

    // 2b. Now that we are serving HTTP, resolve our *own* DID for the first time.
    //
    // A service that hosts its own DID cannot resolve it at boot — it is the
    // thing that serves it — so `load_identity` came up on guessed
    // `#key-0`/`#key-1` kids and deliberately persisted nothing. This is the
    // first moment the document is actually fetchable, so it is where generation
    // 0 gets recorded with the kids the document really uses.
    //
    // It must run *before* the DIDComm listener starts, or the listener's profile
    // would be built on the guess.
    if let Err(e) = crate::identity_rotation::reload_now(&state).await {
        warn!("failed to establish the service identity from its DID document: {e}");
    }

    // 3. Start the mediator messaging service (DIDComm and/or TSP) for
    //    inbound + outbound messages. TSP-only deployments (didcomm off,
    //    tsp on) must still start it.
    let didcomm_shutdown = CancellationToken::new();
    if state.config.features.didcomm || state.config.features.tsp {
        match start_didcomm_service(&state, didcomm_shutdown.clone()).await {
            Ok(Some(svc)) => {
                let _ = state.didcomm_service.set(svc);
            }
            Ok(None) => {}
            Err(e) => {
                warn!("failed to start DIDComm service: {e}");
            }
        }
    }

    // 3b. Reconnect to any mediator we rotated *away* from but whose grace
    // period has not elapsed. Peers holding a stale DID document are still
    // delivering there, and a restart part-way through the window must not
    // abandon that queue — which is exactly why the retiring generation (and its
    // old mediator) is persisted. No-op in the common case: a key rotation on the
    // same mediator strands nothing.
    crate::identity_rotation::resume_mediator_drains(&state);

    // 4. Spawn DIDComm health check task (runs on main tokio runtime)
    let health_shutdown = CancellationToken::new();
    let health_token = health_shutdown.clone();
    let health_registry_ks = state.registry_ks.clone();
    let health_didcomm = state.didcomm_service.clone();
    let health_control_did = state.config.server_did.clone();
    let health_interval_secs = state.config.registry.health_check_interval.max(10);
    let health_resolver = state.did_resolver.clone();
    let health_identity = state.identity.clone();
    // Control's own configured mediator, used as the send fallback when a
    // target server's document advertises no transport.
    let health_fallback =
        did_hosting_common::server::didcomm_profile::TransportFallback::from_config(
            state.config.mediator_did.as_deref(),
            state.config.features.tsp,
        );
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(health_interval_secs));
        timer.tick().await; // skip first tick
        loop {
            tokio::select! {
                _ = timer.tick() => {
                    if let Err(e) = run_health_checks(
                        &health_registry_ks,
                        &health_didcomm,
                        health_control_did.as_deref(),
                        health_interval_secs,
                        &health_fallback,
                        health_resolver.as_ref(),
                        health_identity.as_deref(),
                    ).await {
                        warn!("health check error: {e}");
                    }
                }
                _ = health_token.cancelled() => break,
            }
        }
    });

    // 5. Spawn the control-plane purge sweep. Mirrors the server-side
    // sweep but only deletes DomainEntry rows for ripe `disable-grace`
    // pending purges — control has no hosted DIDs to clean up.
    let (purge_shutdown_tx, purge_shutdown_rx) = tokio::sync::watch::channel(false);
    let purge_store = state.store.clone();
    let purge_handle = tokio::spawn(async move {
        crate::purge_sweep::run_purge_sweep_loop(purge_store, purge_shutdown_rx).await;
    });

    // 5b. Spawn the identity sweep. Expires generations whose grace period has
    // elapsed (dropping their key material, so a superseded key stops
    // decrypting), and doubles as the backstop for identity changes that never
    // came through our own publish path — an out-of-band update, or one applied
    // while this process was down.
    let (identity_shutdown_tx, identity_shutdown_rx) = tokio::sync::watch::channel(false);
    let identity_state = state.clone();
    let identity_handle = tokio::spawn(async move {
        crate::identity_rotation::run_identity_sweep_loop(identity_state, identity_shutdown_rx)
            .await;
    });

    // 6. Spawn the durable outbox worker. Drains
    // `crate::outbox::KS_OUTBOUND_QUEUE` per-target FIFO; wakes on
    // `state.outbox_notify` (fired by every enqueue) for the low-
    // latency happy path, falls back to a 30 s tick to retry backed-
    // off entries.
    let (outbox_shutdown_tx, outbox_shutdown_rx) = tokio::sync::watch::channel(false);
    let outbox_state = state.clone();
    let outbox_notify = state.outbox_notify.clone();
    // The GeoIP reloader (step 8) stops on the same signal.
    let geoip_shutdown_rx = outbox_shutdown_rx.clone();
    let outbox_handle = tokio::spawn(async move {
        crate::outbox::run_outbox_loop(outbox_state, outbox_notify, outbox_shutdown_rx).await;
    });

    // 7. Check, in the background, that our own DID lists the services
    // wallet sign-in needs; warn once with the fix if not. Never blocks.
    crate::sign_in_readiness::spawn(&state);

    // 8. A refreshed GeoIP database is picked up without a restart.
    let geoip_reloader = state.oob.geoip().spawn_reloader(geoip_shutdown_rx);

    // Wait for shutdown signal
    init::shutdown_signal().await;

    // Ordered shutdown: health → DIDComm → REST → Storage
    let mut any_panic = false;

    health_shutdown.cancel();
    didcomm_shutdown.cancel();
    let _ = purge_shutdown_tx.send(true);
    let _ = identity_shutdown_tx.send(true);
    let _ = outbox_shutdown_tx.send(true);
    // DIDCommService shutdown is handled by the cancellation token

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

    if let Err(e) = purge_handle.await {
        warn!("purge sweep task didn't shut down cleanly: {e}");
    }

    if let Err(e) = identity_handle.await {
        warn!("identity sweep task didn't shut down cleanly: {e}");
    }

    if let Err(e) = outbox_handle.await {
        warn!("outbox worker didn't shut down cleanly: {e}");
    }

    if let Some(handle) = geoip_reloader
        && let Err(e) = handle.await
    {
        warn!("GeoIP reloader didn't shut down cleanly: {e}");
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

    info!(
        control_did = %identity.did,
        mediator_did = %mediator_did,
        generations = identity.generations().len(),
        "building TDK profile for DIDComm"
    );

    // Block until the mediator DID document is resolvable. On a cold start
    // the mediator DID may be hosted by a did-hosting-server that has not yet
    // published its log, so we retry instead of starting the listener
    // against an unreachable mediator (which surfaces as a cryptic
    // "No Mediator is configured for this Profile" later).
    wait_for_did_resolution(&mediator_did, "mediator", &identity.did_resolver, &shutdown).await?;

    // Carries the key material of every live generation, keyed on the kids the
    // DID document actually resolved to — the same kids the secrets resolver
    // was seeded with.
    let profile = build_tdk_profile_for_identity("control", identity, Some(&mediator_did)).await?;

    info!("TDK profile built, configuring DIDComm listener");

    // Transport selection — DIDComm and/or TSP ride the same mediator
    // socket. Inbound TSP frames are routed to the `WebvhTspHandler` when
    // TSP is on. The four combinations map to the framework's `Protocols`;
    // "neither flag set but a mediator is configured" defaults to
    // DIDComm-only for back-compat.
    //
    // The union across live generations, not just the current one's config
    // flags: a generation retiring out of DIDComm while the current identity
    // is TSP-only still has peers delivering DIDComm to it until it expires,
    // and the single listener has to carry both.
    //
    // Then reconcile against what our own DID document advertises — the document
    // is authoritative for how peers reach us, so the listener must carry every
    // transport it advertises or silently drop (and ack) inbound frames on the
    // ones it doesn't.
    let advertised = advertised_protocols(&identity.did, Some(&identity.did_resolver)).await;
    let transports = reconcile_listener_protocols(identity.protocols(), advertised, &identity.did);
    let tsp_enabled = transports.tsp;
    let protocols = match (transports.didcomm, transports.tsp) {
        (true, true) => Protocols::BOTH,
        (false, true) => Protocols::TSP_ONLY,
        _ => Protocols::DIDCOMM_ONLY,
    };

    let mut listener = ListenerConfig {
        id: "control".into(),
        profile,
        restart_policy: RestartPolicy::Always {
            backoff: RetryConfig::default(),
        },
        auto_delete: true,
        protocols,
        ..Default::default()
    };
    // Persist the control plane's TSP relationships (Rev 3 §7.2.2) across
    // restarts, so it keeps its half of each edge relationship and does not need
    // to re-invite: an edge re-invites on its own connect, and this side answers
    // (`WebvhTspHandler::handle_control`). Without persistence a control restart
    // would drop every edge until each re-handshakes. Only meaningful when TSP is
    // on. In daemon mode this is the only listener, so it covers the daemon too.
    if tsp_enabled {
        listener.relationship_store = Some(
            did_hosting_common::server::tsp_relationship_store::build_relationship_store(
                &state.store,
            )?,
        );
    }

    let router = messaging::build_control_router(state.clone())
        .map_err(|e| AppError::Internal(format!("failed to build DIDComm router: {e}")))?;

    let config = DIDCommServiceConfig {
        listeners: vec![listener],
    };

    let svc = if tsp_enabled {
        info!("starting messaging service with DIDComm + TSP on the mediator connection");
        DIDCommService::start_with_tsp(
            config,
            router,
            crate::tsp::WebvhTspHandler::new(state.clone()),
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
        control_did = %identity.did,
        "messaging service started"
    );
    Ok(Some(svc))
}

// ---------------------------------------------------------------------------
// Service-badge backfill
// ---------------------------------------------------------------------------

/// Populate the per-DID service-badge cache (`DidRecord.services`) for records
/// written before that field existed.
///
/// Runs **only** `M-02`, not the full [`migrations::registry`]. The standalone
/// control plane has never invoked the migration runner, so a store here may
/// never have seen `M-01` either — switching the whole set on as a side effect
/// of adding badges would fill `domain` from the system-default tier on records
/// that have gone their entire life without it. That's a separate decision with
/// its own blast radius. `M-02` writes nothing but `services`, a field read only
/// by the UI, so it is safe to run unattended.
///
/// Idempotent and marker-gated in the `meta` keyspace: one pass over the DID
/// logs on the first boot after upgrade, a no-op on every boot after.
///
/// Failure is non-fatal. The daemon exits when its migrations fail, but missing
/// badges are cosmetic and must not stop the control plane from starting —
/// `publish_did` self-heals each record on its next publish regardless.
pub async fn backfill_service_badges(store: &Store) {
    use did_hosting_common::server::migrations::{M02CacheDidRecordServices, MigrationRunner};

    let runner = MigrationRunner::new(vec![Arc::new(M02CacheDidRecordServices)]);
    match runner.run_pending(store).await {
        Ok(summary) => info!(
            applied = ?summary.applied,
            skipped = ?summary.skipped,
            "service-badge backfill complete"
        ),
        Err(e) => warn!(
            error = %e,
            "service-badge backfill failed; DID badges may be missing until each DID is next published"
        ),
    }
}

// ---------------------------------------------------------------------------
// Registry seeding
// ---------------------------------------------------------------------------

/// Seed the registry with statically configured instances.
pub async fn seed_registry(state: &AppState) {
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
            // Config-seeded instances pre-date T27's capability
            // declaration; assume webvh-only until the instance
            // re-registers and reports its compile-time methods.
            enabled_methods: vec!["webvh".to_string()],
            served_domains: Vec::new(),
            protocol_version: "1.0".to_string(),
            // Config-seeded instances carry no DID (`metadata` is Null).
            // The health-check loop fills these once the instance
            // re-registers over DIDComm and records one.
            advertised_services: None,
            services_checked_at: None,
            trust_task_capable: false,
            sync_batch_capable: false,
            last_inbound_transport: None,
            last_inbound_at: None,
            last_outbound_transport: None,
            last_outbound_at: None,
            last_ack_at: None,
            last_reconcile_at: None,
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
                did_hosting_common::server::security_headers,
            ));

        let _ = ready_tx.send(());

        let mut rx = shutdown_rx.clone();
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
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

#[allow(clippy::too_many_arguments)]
fn run_storage_thread(
    store: Store,
    sessions_ks: KeyspaceHandle,
    stats_ks: KeyspaceHandle,
    timeseries_ks: KeyspaceHandle,
    dids_ks: KeyspaceHandle,
    auth_config: AuthConfig,
    has_auth: bool,
    collector: Arc<did_hosting_common::server::stats_collector::StatsCollector>,
    shutdown_rx: &mut watch::Receiver<bool>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");

        let session_interval = Duration::from_secs(auth_config.session_cleanup_interval);
        let flush_interval = Duration::from_secs(10);

        let mut session_timer = tokio::time::interval(session_interval);
        let mut flush_timer = tokio::time::interval(flush_interval);
        // A flush that overruns its interval is followed by a full interval,
        // not an immediate catch-up flush.
        flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut did_count_timer = tokio::time::interval(
            did_hosting_common::server::stats_collector::DID_COUNT_RECONCILE_INTERVAL,
        );

        // Skip first tick (immediate)
        session_timer.tick().await;
        flush_timer.tick().await;
        did_count_timer.tick().await;

        loop {
            tokio::select! {
                _ = session_timer.tick(), if has_auth => {
                    if let Err(e) = cleanup_expired_sessions(&sessions_ks, auth_config.challenge_ttl).await {
                        warn!("session cleanup error: {e}");
                    }
                }
                _ = flush_timer.tick() => {
                    // Flush accumulated per-DID stats deltas to persistent store
                    if let Err(e) = flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, STATS_FLUSH_MAX_ROWS).await {
                        warn!("stats flush error: {e}");
                    }
                }
                _ = did_count_timer.tick() => {
                    if let Err(e) = did_hosting_common::server::stats_collector::reconcile_total_dids(&collector, &dids_ks).await {
                        warn!("DID count reconcile error: {e}");
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("storage thread shutting down");
                    break;
                }
            }
        }

        // Final flush before shutdown
        flush_remaining_stats(&collector, &stats_ks, &timeseries_ks).await;

        if let Err(e) = store.persist().await {
            error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
}

/// Most rows one periodic stats flush writes, about 20 a second at the
/// 10-second flush interval. Each row is a read and a write, so this bounds
/// the flush's share of the store's capacity and how long it holds the
/// storage task; rows beyond it wait for the next flush, in the order
/// [`stats_flush_order`] gives them.
pub const STATS_FLUSH_MAX_ROWS: usize = 200;

/// Rows a flush writes at once. The rows are independent keys, so writing
/// several together takes the same store capacity in a fraction of the
/// time the storage task would otherwise spend waiting on round trips.
pub const STATS_FLUSH_CONCURRENCY: usize = 8;

/// Oldest time-series bucket a flush still writes. Older buckets are counts
/// the store has refused or the flush could not reach for this long; they
/// are dropped with a warning so a long outage cannot grow the backlog
/// without bound. Per-DID totals are never dropped by age: there is one row
/// per DID.
pub const STATS_BUCKET_MAX_AGE: Duration = Duration::from_secs(3600);

/// How long the shutdown flush may write before giving up, well inside a
/// container's usual 30-second termination grace period so the store is
/// still persisted afterwards.
pub const STATS_SHUTDOWN_FLUSH_DEADLINE: Duration = Duration::from_secs(15);

/// How often a warning about rows dropped at the collector's caps may repeat.
const STATS_DROP_WARN_SECS: u64 = 300;

/// One row a stats flush writes.
enum StatsRow {
    /// A DID's `stats:{mnemonic}` totals.
    Total(did_hosting_common::DidStatsDelta),
    /// A `ts:{mnemonic}:{epoch}` time-series bucket.
    Bucket(did_hosting_common::server::stats_collector::DrainedBucket),
}

/// Flush accumulated stats deltas from the in-memory collector to the store,
/// writing at most `max_rows` rows.
///
/// `stats_ks` receives `stats:{mnemonic}` aggregate rows;
/// `timeseries_ks` receives `ts:{mnemonic}:{bucket}` and
/// `ts:_all:{bucket}` time-series rows. The split came in v0.7 so a
/// future scan over either keyspace returns homogeneous-shaped values.
///
/// Each row is its own read-modify-write, not one transaction over the
/// whole flush: on a metered store a transaction costs twice the write
/// units, and one throttled row would fail every row with it. Rows are
/// written [`STATS_FLUSH_CONCURRENCY`] at a time. The first failed batch
/// ends the flush; failed rows and every row not yet written go back to the
/// collector, as do rows past `max_rows`, so a failed flush loses no counts
/// while the process runs. A write that reports failure is read back first,
/// and counted as written if the store applied it (a timeout after the
/// write landed), so the retry does not count it twice.
pub async fn flush_stats_to_store(
    collector: &did_hosting_common::server::stats_collector::StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    max_rows: usize,
) -> Result<(), AppError> {
    flush_stats_rows(collector, stats_ks, timeseries_ks, max_rows, None).await
}

/// Flush every pending stats row, for shutdown, for at most
/// [`STATS_SHUTDOWN_FLUSH_DEADLINE`]. Rows that cannot be written by then
/// are lost with the process, so that is logged as an error.
pub async fn flush_remaining_stats(
    collector: &did_hosting_common::server::stats_collector::StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
) {
    let deadline = tokio::time::Instant::now() + STATS_SHUTDOWN_FLUSH_DEADLINE;
    let result = flush_stats_rows(
        collector,
        stats_ks,
        timeseries_ks,
        usize::MAX,
        Some(deadline),
    )
    .await;
    let lost = collector.pending_rows();
    match result {
        Err(e) => error!(
            lost,
            "final stats flush failed; unwritten statistics are lost: {e}"
        ),
        Ok(()) if lost > 0 => error!(
            lost,
            "final stats flush ran out of time; unwritten statistics are lost"
        ),
        Ok(()) => {}
    }
}

async fn flush_stats_rows(
    collector: &did_hosting_common::server::stats_collector::StatsCollector,
    stats_ks: &KeyspaceHandle,
    timeseries_ks: &KeyspaceHandle,
    max_rows: usize,
    deadline: Option<tokio::time::Instant>,
) -> Result<(), AppError> {
    if let Some(dropped) = collector.take_dropped(STATS_DROP_WARN_SECS) {
        warn!(
            dropped,
            "stats backlog full; per-DID statistics were dropped (the server-wide totals and series still count them)"
        );
    }

    let mut rows = stats_flush_order(
        collector.drain_for_sync(),
        recent_buckets(collector.drain_buckets()),
    );
    let mut failed = Vec::new();
    let mut failure = None;
    let mut written = 0usize;

    while written < max_rows
        && !rows.is_empty()
        && deadline.is_none_or(|d| tokio::time::Instant::now() < d)
    {
        let n = STATS_FLUSH_CONCURRENCY
            .min(max_rows - written)
            .min(rows.len());
        let mut set = tokio::task::JoinSet::new();
        for row in rows.drain(..n) {
            let stats_ks = stats_ks.clone();
            let timeseries_ks = timeseries_ks.clone();
            set.spawn(async move {
                let result = match &row {
                    StatsRow::Total(d) => write_did_stats(&stats_ks, d).await,
                    StatsRow::Bucket(b) => write_timeseries_bucket(&timeseries_ks, b).await,
                };
                (row, result)
            });
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((_, Ok(()))) => written += 1,
                Ok((row, Err(e))) => {
                    failed.push(row);
                    failure.get_or_insert(e);
                }
                Err(e) => error!("stats row write task failed; its counts are lost: {e}"),
            }
        }
        if failure.is_some() {
            break;
        }
    }

    let deferred = failed.len() + rows.len();
    let mut deltas = Vec::new();
    let mut buckets = Vec::new();
    for row in failed.into_iter().chain(rows) {
        match row {
            StatsRow::Total(d) => deltas.push(d),
            StatsRow::Bucket(b) => buckets.push(b),
        }
    }
    collector.requeue_deltas(deltas);
    collector.requeue_buckets(buckets);

    match failure {
        Some(e) => {
            warn!(
                written,
                deferred, "stats flush stopped; unwritten rows requeued"
            );
            Err(e)
        }
        None => {
            if written > 0 || deferred > 0 {
                debug!(written, deferred, "flushed stats rows to store");
            }
            Ok(())
        }
    }
}

/// The order a flush writes rows in, so a flush budget smaller than the
/// backlog still makes progress on everything: the server-wide series first
/// (one bucket per 5 minutes, and what the dashboard charts), then per-DID
/// totals and per-DID buckets alternately, buckets newest first. Neither
/// kind can starve the other under sustained load.
fn stats_flush_order(
    deltas: Vec<did_hosting_common::DidStatsDelta>,
    buckets: Vec<did_hosting_common::server::stats_collector::DrainedBucket>,
) -> std::collections::VecDeque<StatsRow> {
    use did_hosting_common::server::stats_collector::ALL_SERIES;

    let (all, per_did): (Vec<_>, Vec<_>) =
        buckets.into_iter().partition(|b| b.mnemonic == ALL_SERIES);
    let mut order: std::collections::VecDeque<StatsRow> =
        all.into_iter().map(StatsRow::Bucket).collect();
    let mut deltas = deltas.into_iter();
    let mut per_did = per_did.into_iter();
    loop {
        let d = deltas.next();
        let b = per_did.next();
        if d.is_none() && b.is_none() {
            break;
        }
        order.extend(d.map(StatsRow::Total));
        order.extend(b.map(StatsRow::Bucket));
    }
    order
}

/// Drop drained buckets older than [`STATS_BUCKET_MAX_AGE`] and order the
/// rest newest first.
fn recent_buckets(
    buckets: Vec<did_hosting_common::server::stats_collector::DrainedBucket>,
) -> Vec<did_hosting_common::server::stats_collector::DrainedBucket> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cutoff = now.saturating_sub(STATS_BUCKET_MAX_AGE.as_secs());
    let (mut recent, old): (Vec<_>, Vec<_>) = buckets.into_iter().partition(|b| b.epoch >= cutoff);
    if !old.is_empty() {
        warn!(
            rows = old.len(),
            "dropping time-series buckets that could not be written within the maximum age"
        );
    }
    recent.sort_by_key(|b| std::cmp::Reverse(b.epoch));
    recent
}

/// Write `value` to `key`. If the write reports failure, read the row back:
/// only the storage task writes stats rows, so finding exactly `value`
/// means the store applied the write (a timeout after it landed) and it
/// must not be retried, or the retry would count it twice.
async fn write_stats_row(
    ks: &KeyspaceHandle,
    key: String,
    value: serde_json::Value,
) -> Result<(), AppError> {
    match ks.insert(key.as_str(), &value).await {
        Ok(()) => Ok(()),
        Err(e) => match ks.get::<serde_json::Value>(key.as_str()).await {
            Ok(Some(stored)) if stored == value => {
                debug!(key, "stats write reported failure but was applied");
                Ok(())
            }
            _ => Err(e),
        },
    }
}

/// Add one DID's deltas to its `stats:{mnemonic}` row.
async fn write_did_stats(
    stats_ks: &KeyspaceHandle,
    d: &did_hosting_common::DidStatsDelta,
) -> Result<(), AppError> {
    let key = format!("stats:{}", d.mnemonic);
    let mut stats: did_hosting_common::DidStats =
        stats_ks.get(key.as_str()).await?.unwrap_or_default();
    stats.total_resolves += d.resolve_delta;
    stats.total_updates += d.update_delta;
    stats.last_resolved_at = stats.last_resolved_at.max(d.last_resolved_at);
    stats.last_updated_at = stats.last_updated_at.max(d.last_updated_at);
    let value = serde_json::to_value(&stats).map_err(|e| AppError::Internal(e.to_string()))?;
    write_stats_row(stats_ks, key, value).await
}

/// Add one bucket's counts to its `ts:{mnemonic}:{epoch}` row (`_all` for
/// the server-wide series).
async fn write_timeseries_bucket(
    timeseries_ks: &KeyspaceHandle,
    b: &did_hosting_common::server::stats_collector::DrainedBucket,
) -> Result<(), AppError> {
    let key = format!("ts:{}:{}", b.mnemonic, b.epoch);
    let existing: serde_json::Value = timeseries_ks
        .get(key.as_str())
        .await?
        .unwrap_or(serde_json::json!({"r": 0, "u": 0}));
    let r = existing.get("r").and_then(|v| v.as_u64()).unwrap_or(0) + b.resolves;
    let u = existing.get("u").and_then(|v| v.as_u64()).unwrap_or(0) + b.updates;
    write_stats_row(timeseries_ks, key, serde_json::json!({"r": r, "u": u})).await
}

/// Ping one trust-task-capable instance, letting its DID document choose the
/// transport. Failures are logged, never fatal — an unreachable server simply
/// stops ponging and ages into `Unreachable` on the next sweep.
// One over clippy's 7-arg threshold: the signer joined an already-flat
// parameter list, and a struct would only move the same values around.
#[allow(clippy::too_many_arguments)]
async fn send_health_ping_trust_task(
    svc: &DIDCommService,
    registry_ks: &KeyspaceHandle,
    control_did: &str,
    server_did: &str,
    inst: &registry::ServiceInstance,
    fallback: &did_hosting_common::server::didcomm_profile::TransportFallback,
    did_resolver: Option<&DIDCacheClient>,
    signer: &affinidi_tdk::secrets_resolver::secrets::Secret,
) {
    use did_hosting_common::server::trust_tasks::send::{build_signed_request, send_trust_task};

    // Signed: an edge answers only a ping its control plane signed.
    let doc = match build_signed_request(
        did_hosting_common::didcomm_types::MSG_HEALTH_PING,
        control_did,
        server_did,
        serde_json::json!({}),
        signer,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "health ping: could not build the signed ping");
            return;
        }
    };

    match send_trust_task(
        svc,
        "control",
        control_did,
        server_did,
        &doc,
        fallback,
        did_resolver,
    )
    .await
    {
        Ok(transport) => {
            debug!(
                instance_id = %inst.instance_id,
                server_did,
                ?transport,
                "health ping sent as trust task"
            );
            // The transport that actually carried it — after any TSP->DIDComm
            // fallback — not the one the DID document advertised.
            registry::record_outbound_transport(
                registry_ks,
                &inst.instance_id,
                transport.into(),
                crate::auth::session::now_epoch(),
            )
            .await;
        }
        Err(e) => debug!(
            instance_id = %inst.instance_id,
            server_did,
            error = %e,
            "failed to send health ping (trust task)"
        ),
    }
}

/// Send health pings to all registered instances and evaluate staleness-based
/// status from the last received pong timestamp.
///
/// `identity` is the control plane's own identity, read on every sweep so a
/// rotation is picked up; without it no ping can be signed and none is sent —
/// instances then age into `Unreachable`, which is the honest status for a
/// control plane that cannot prove who it is.
pub async fn run_health_checks(
    registry_ks: &KeyspaceHandle,
    didcomm: &std::sync::OnceLock<DIDCommService>,
    control_did: Option<&str>,
    health_interval_secs: u64,
    fallback: &did_hosting_common::server::didcomm_profile::TransportFallback,
    did_resolver: Option<&DIDCacheClient>,
    identity: Option<&did_hosting_common::server::identity::ServiceIdentity>,
) -> Result<(), AppError> {
    let instances = registry::list_instances(registry_ks).await?;
    let now = crate::auth::session::now_epoch();

    // Send health pings (fire-and-forget — the pong handler updates status).
    // Every ping is a signed `.../server/health/0.1` trust task, and
    // `send_trust_task` picks TSP or DIDComm from the *server's own DID
    // document*.
    let signer = match (identity, control_did) {
        (Some(identity), Some(ctrl_did)) => {
            match did_hosting_common::server::trust_tasks::identity_signing_secret(
                identity, ctrl_did,
            ) {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!(error = %e, "health pings skipped: cannot sign");
                    None
                }
            }
        }
        _ => None,
    };
    if let (Some(svc), Some(ctrl_did), Some(signer)) = (didcomm.get(), control_did, signer.as_ref())
    {
        for inst in &instances {
            let Some(server_did) = inst.did() else {
                continue;
            };
            send_health_ping_trust_task(
                svc,
                registry_ks,
                ctrl_did,
                server_did,
                inst,
                fallback,
                did_resolver,
                signer,
            )
            .await;
        }
    }

    // Evaluate status based on last pong timestamp
    for inst in &instances {
        let new_status = registry::health_status_from_timestamp(inst, now, health_interval_secs);
        if new_status != inst.status {
            info!(
                instance_id = %inst.instance_id,
                old_status = ?inst.status,
                new_status = ?new_status,
                "instance status changed"
            );
            registry::update_instance_status(registry_ks, &inst.instance_id, new_status, now)
                .await?;
        }
    }

    // Refresh the advertised-service badge cache on the same cadence. Runs
    // after the status sweep so a resolve stall can't delay status updates.
    // Errors are per-instance and non-fatal — a failed resolve keeps the
    // previous cache (see `registry::refresh_advertised_services`).
    for inst in &instances {
        if inst.did().is_none() {
            continue;
        }
        if let Err(e) =
            registry::refresh_advertised_services(registry_ks, &inst.instance_id, did_resolver, now)
                .await
        {
            debug!(
                instance_id = %inst.instance_id,
                error = %e,
                "failed to refresh advertised services"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use did_hosting_common::DidStats;
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::stats_collector::StatsCollector;

    use super::*;

    /// A flush whose writes start failing part-way keeps every row it did
    /// not write, and the next flush writes them without counting any
    /// event twice.
    #[tokio::test]
    async fn failed_stats_flush_loses_no_counts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open fjall");
        let allowed = Arc::new(AtomicUsize::new(1));
        let stats_ks = store
            .keyspace("stats")
            .unwrap()
            .failing_writes_after(allowed.clone());
        let timeseries_ks = store
            .keyspace("timeseries")
            .unwrap()
            .failing_writes_after(allowed.clone());

        let collector = StatsCollector::new();
        for mnemonic in ["alice", "bob", "carol"] {
            collector.record_resolve(mnemonic);
        }
        collector.record_resolve("alice");

        flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, usize::MAX)
            .await
            .expect_err("writes fail after the first");

        // Events recorded between the failed flush and the retry merge with
        // the retained rows.
        collector.record_update("bob");
        allowed.store(usize::MAX, Ordering::SeqCst);
        flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, usize::MAX)
            .await
            .expect("retry flushes everything");

        let stats = |m: &str| {
            let ks = stats_ks.clone();
            let key = format!("stats:{m}");
            async move {
                let s: DidStats = ks.get(key.as_str()).await.unwrap().unwrap();
                (s.total_resolves, s.total_updates)
            }
        };
        assert_eq!(stats("alice").await, (2, 0));
        assert_eq!(stats("bob").await, (1, 1));
        assert_eq!(stats("carol").await, (1, 0));

        let rows = timeseries_ks.prefix_iter_raw("ts:_all:").await.unwrap();
        let (r, u) = rows
            .iter()
            .map(|(_, v)| serde_json::from_slice::<serde_json::Value>(v).unwrap())
            .fold((0, 0), |(r, u), v| {
                (r + v["r"].as_u64().unwrap(), u + v["u"].as_u64().unwrap())
            });
        assert_eq!((r, u), (4, 1), "server-wide series counts each event once");
    }

    async fn fjall_keyspaces() -> (tempfile::TempDir, KeyspaceHandle, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open fjall");
        let stats_ks = store.keyspace("stats").unwrap();
        let timeseries_ks = store.keyspace("timeseries").unwrap();
        (dir, stats_ks, timeseries_ks)
    }

    /// Rows past the flush's budget wait for the next flush; the server-wide
    /// series goes first, then per-DID totals and buckets alternately.
    #[tokio::test]
    async fn stats_flush_defers_rows_past_its_budget() {
        let (_dir, stats_ks, timeseries_ks) = fjall_keyspaces().await;
        let collector = StatsCollector::new();
        for mnemonic in ["alice", "bob"] {
            collector.record_resolve(mnemonic);
        }
        // Two totals, two per-DID buckets and one `_all` bucket.
        assert_eq!(collector.pending_rows(), 5);

        flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, 2)
            .await
            .unwrap();
        assert_eq!(collector.pending_rows(), 3, "only the budget is written");
        assert_eq!(
            timeseries_ks
                .prefix_iter_raw("ts:_all:")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(stats_ks.prefix_iter_raw("stats:").await.unwrap().len(), 1);

        flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, 2)
            .await
            .unwrap();
        flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, 2)
            .await
            .unwrap();
        assert_eq!(collector.pending_rows(), 0);
        assert_eq!(timeseries_ks.prefix_iter_raw("ts:").await.unwrap().len(), 3);
    }

    /// A write the store applied but reported as failed is not retried, so
    /// it is not counted twice.
    #[tokio::test]
    async fn an_applied_write_reported_as_failed_is_not_counted_twice() {
        let (_dir, stats_ks, timeseries_ks) = fjall_keyspaces().await;
        let allowed = Arc::new(AtomicUsize::new(0));
        let stats_ks = stats_ks.failing_acks_after(allowed.clone());
        let timeseries_ks = timeseries_ks.failing_acks_after(allowed.clone());

        let collector = StatsCollector::new();
        collector.record_resolve("alice");
        flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, usize::MAX)
            .await
            .expect("every failed write is found applied on read-back");
        assert_eq!(collector.pending_rows(), 0, "nothing is requeued");

        let s: DidStats = stats_ks.get("stats:alice").await.unwrap().unwrap();
        assert_eq!(s.total_resolves, 1);
    }

    /// A flush budget far below the backlog still writes the server-wide
    /// series and per-DID buckets, not only per-DID totals.
    #[tokio::test]
    async fn a_small_budget_does_not_starve_the_timeseries() {
        let (_dir, stats_ks, timeseries_ks) = fjall_keyspaces().await;
        let collector = StatsCollector::new();
        for i in 0..50 {
            collector.record_resolve(&format!("did-{i}"));
        }

        flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, 10)
            .await
            .unwrap();

        let all = timeseries_ks.prefix_iter_raw("ts:_all:").await.unwrap();
        assert_eq!(all.len(), 1, "the server-wide series is written first");
        let per_did_ts = timeseries_ks.prefix_iter_raw("ts:did-").await.unwrap();
        let totals = stats_ks.prefix_iter_raw("stats:").await.unwrap();
        assert_eq!(totals.len() + per_did_ts.len(), 9);
        assert!(!per_did_ts.is_empty() && !totals.is_empty());
    }

    /// A bucket older than the maximum age is dropped, not written or kept.
    #[tokio::test]
    async fn stats_flush_drops_buckets_past_the_maximum_age() {
        use did_hosting_common::server::stats_collector::DrainedBucket;

        let (_dir, stats_ks, timeseries_ks) = fjall_keyspaces().await;
        let collector = StatsCollector::new();
        collector.requeue_buckets(vec![DrainedBucket {
            mnemonic: "alice".into(),
            epoch: 300,
            resolves: 1,
            updates: 0,
        }]);
        collector.record_resolve("bob");

        flush_stats_to_store(&collector, &stats_ks, &timeseries_ks, usize::MAX)
            .await
            .unwrap();

        assert_eq!(collector.pending_rows(), 0);
        assert!(
            timeseries_ks
                .get_raw("ts:alice:300")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(timeseries_ks.prefix_iter_raw("ts:").await.unwrap().len(), 2);
    }
}

//! The control plane's [`AppState`], its HTTP router and the process run loop:
//! opening the store, starting the DIDComm/TSP listener and the background
//! tasks, and serving until shutdown.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_service::{DIDCommService, DIDCommServiceConfig};
use affinidi_tdk::secrets_resolver::ThreadedSecretsResolver;
use did_hosting_common::server::auth::extractor::AuthState;
use did_hosting_common::server::didcomm_profile::{build_own_listener, wait_for_did_resolution};
use did_hosting_common::server::identity::{self, ServiceIdentity};
use did_hosting_common::server::init;
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
};
use did_hosting_common::server::supervise::{
    PeriodicTask, Policy, SHUTDOWN_STAGE_DEADLINE, Stage, Supervisor, retry_with_backoff,
    run_periodic,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use webauthn_rs::prelude::Webauthn;

use crate::auth::jwt::JwtKeys;
use crate::auth::session::cleanup_expired_sessions;
use crate::config::{AppConfig, AuthConfig};
use crate::messaging;
use crate::registry::{self, ServiceStatus};
use crate::routes;
use crate::secret_store::ServerSecrets;
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::store::{KeyspaceHandle, Store};
use tokio::sync::{oneshot, watch};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, info, warn};

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
    /// lookups. `None` when `did_resolver` is unconfigured; every trust-task
    /// path then refuses rather than accept a document unverified
    /// (`messaging::require_verifier`) — proofs are verified on every path.
    ///
    /// `TransportBoundVerifier`, not the stock `affinidi::Verifier`: it
    /// requires an in-band `issuer` and enforces the
    /// issuer↔`verificationMethod` binding. The passkey delegation path (an
    /// ephemeral session key signing for the JWT's subject) is admitted only
    /// by a per-request copy built with `with_session_delegate`, never by
    /// this shared instance. See `TransportBoundVerifier` docs.
    pub trust_tasks_verifier:
        Option<Arc<did_hosting_common::server::trust_tasks::TransportBoundVerifier>>,
    pub jwt_keys: Option<Arc<JwtKeys>>,
    pub webauthn: Option<Arc<Webauthn>>,
    /// Work a request or message hands off to run after it is answered (a
    /// re-registering edge's resync, a sync queued outside a mutation — see
    /// [`crate::server_push`]). Tracked so shutdown waits for it, within its
    /// deadline, before the store is persisted.
    pub background: TaskTracker,
    /// DIDComm service for inbound/outbound mediator messaging.
    /// Wrapped in `OnceLock` so cloned states see it once it's initialized
    /// (the service starts after the HTTP + DIDComm routers are already cloned).
    pub didcomm_service: Arc<std::sync::OnceLock<DIDCommService>>,
    /// In-memory stats collector — accumulates per-DID deltas from servers,
    /// flushed periodically to the stats keyspace.
    pub stats_collector: Arc<did_hosting_common::server::stats_collector::StatsCollector>,
    /// Stats keyspace — `stats:{mnemonic}` rows (a DID's totals plus its
    /// coarse hourly and daily series) and `statspin:{mnemonic}` tier
    /// overrides. See `did_hosting_common::server::stats_tiers` and
    /// `docs/stats-tiers.md`.
    pub stats_ks: KeyspaceHandle,
    /// Time-series keyspace — the fine 5-minute ring
    /// (`t5:{mnemonic}:{slot}`, and `t5:_all:{slot}` server-wide) and the
    /// server-wide coarse series (`c:_all`). See `stats_tiers`.
    pub timeseries_ks: KeyspaceHandle,
    /// Anti-replay cache for inbound DIDComm `(sender, msg.id)` pairs.
    /// Both transports gate through it before dispatch to reject
    /// captured-and-resubmitted envelopes within the freshness window.
    pub replay_cache: Arc<did_hosting_common::server::replay::ReplayCache>,
    /// What signed documents from signers the ACL does not list may
    /// consume: their own replay cache and bounded DID resolution. See
    /// [`crate::unlisted_signers`].
    pub unlisted_signers: Arc<crate::unlisted_signers::UnlistedSigners>,
    /// Per-mnemonic write lock. `register_did_atomic` (and any other
    /// read-then-write operation on the same path) holds the lock for
    /// the duration of its read + build + commit window so two
    /// concurrent calls on the same path can't both observe
    /// `existing == None` and both commit.
    pub path_locks: did_hosting_common::server::path_locks::PathLocks,
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
    /// Who an HTTPS request's client is, from `server.trusted_proxies`: built
    /// once at startup and shared by every handler that charges a client
    /// address.
    pub client_ips: did_hosting_common::server::rate_limit::ClientIps,
    /// Per-IP rate limiter for the unauthenticated challenge endpoint.
    /// Network-layer defence-in-depth that complements the per-DID +
    /// global counters above. See `crate::rate_limit` for the
    /// trusted-proxy / X-Forwarded-For policy.
    pub ip_rate_limiter: Arc<did_hosting_common::server::rate_limit::IpRateLimiter>,
    /// Per-source limiter for opening a passkey login
    /// (`auth/passkey/login/start`). See
    /// [`crate::rate_limit::login_start_limiter`].
    pub login_start_rate_limiter:
        Arc<did_hosting_common::server::rate_limit::KeyedRateLimiter<String>>,
    /// Per-source limiter for passkey invite redemption
    /// (`auth/passkey/enroll/redeem/start`). See
    /// [`crate::rate_limit::redeem_limiter`].
    pub redeem_rate_limiter: Arc<did_hosting_common::server::rate_limit::KeyedRateLimiter<String>>,
    /// Per-source limiter for `did:webs` self-registration (a
    /// `did/register/0.1` from a `did:webs` outside the ACL, verified against
    /// its own key event log). See
    /// [`crate::rate_limit::webs_self_register_limiter`].
    pub webs_self_register_limiter:
        Arc<did_hosting_common::server::rate_limit::KeyedRateLimiter<String>>,
    /// The bucket every `did:webs` self-registration shares, whatever its
    /// source. See [`crate::rate_limit::webs_self_register_global_limiter`].
    pub webs_self_register_global_limiter:
        Arc<did_hosting_common::server::rate_limit::KeyedRateLimiter<String>>,
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
    /// Sweep idle clients out of every rate limiter this state serves (the
    /// challenge, passkey login, redemption, large-document and wallet sign-in
    /// limits) until
    /// `shutdown` fires.
    ///
    /// Call it on a runtime that lives as long as the process serves
    /// requests on *any* transport, not on the HTTP thread's: invite
    /// redemption and the large-document budget are charged over DIDComm and
    /// TSP too, so a sweep tied to the HTTP runtime would stop (or never
    /// start) when the HTTP listener is off. The sweep only touches the limiters'
    /// shared maps, so which runtime runs it does not matter otherwise.
    pub fn spawn_rate_limit_gc(&self, shutdown: &CancellationToken) {
        self.ip_rate_limiter.spawn_gc(shutdown.clone());
        self.login_start_rate_limiter.spawn_gc(shutdown.clone());
        self.redeem_rate_limiter.spawn_gc(shutdown.clone());
        self.webs_self_register_limiter.spawn_gc(shutdown.clone());
        self.webs_self_register_global_limiter
            .spawn_gc(shutdown.clone());
        self.large_document_budget.spawn_gc(shutdown);
        self.oob.spawn_rate_limit_gc(shutdown);
    }

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

    /// Assemble a control plane's state over `store`: the one recipe the
    /// standalone [`run`], the daemon and the tests share, so a field added
    /// here reaches all of them.
    ///
    /// Opens the keyspaces, takes the resolvers and the Trust Task verifier
    /// from `identity`, the JWT keys from `secrets` (none without), WebAuthn
    /// from `config.public_url`, and builds the limiters and caches.
    /// `overrides` supplies what a caller shares with something else in the
    /// same process (the daemon's statistics collector, its cache hook, its
    /// client-address rule).
    ///
    /// Builds state only; it starts nothing. [`startup`] runs the boot steps.
    pub async fn build(
        config: AppConfig,
        store: Store,
        secrets: Option<&ServerSecrets>,
        identity: Option<Arc<ServiceIdentity>>,
        overrides: AppStateOverrides,
    ) -> Result<Self, AppError> {
        let sessions_ks = store.keyspace(KS_SESSIONS)?;
        let acl_ks = store.keyspace(KS_ACL)?;
        let registry_ks = store.keyspace(KS_REGISTRY)?;
        // Strongly consistent: the control plane's DID reads decide writes
        // (ownership, slot existence, what to push to edges), so a read that
        // missed a just-committed write could hand one owner's slot to another.
        let dids_ks = store.keyspace_consistent(KS_DIDS)?;
        let stats_ks = store.keyspace(KS_STATS)?;
        // Time-series rows live in their own keyspace — see the
        // `timeseries_ks` field doc.
        let timeseries_ks = store.keyspace(KS_TIMESERIES)?;

        let did_resolver = identity.as_ref().map(|i| i.did_resolver.clone());
        let secrets_resolver = identity.as_ref().map(|i| i.secrets_resolver.clone());
        // Over the identity's DID cache, so `did:web` / `did:webvh`
        // verificationMethod lookups hit the cache the DIDComm path already
        // populates.
        let trust_tasks_verifier =
            did_hosting_common::server::trust_tasks::build_verifier(did_resolver.as_ref());
        let jwt_keys = secrets.and_then(init::init_jwt_keys);

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

        let stats_collector = match overrides.stats_collector {
            Some(collector) => collector,
            None => {
                use did_hosting_common::server::stats_collector::seed_from_store;
                let collector = StatsCollector::new();
                // The aggregate, the DID count and the per-DID statistics
                // overrides, from the store; then the `[stats]` policy.
                let agg = seed_from_store(&collector, &stats_ks, &dids_ks).await;
                collector.configure_tiers(config.stats);
                info!(
                    total_dids = agg.total_dids,
                    total_resolves = agg.total_resolves,
                    total_updates = agg.total_updates,
                    "stats collector seeded from store"
                );
                Arc::new(collector)
            }
        };
        let client_ips = match overrides.client_ips {
            Some(ips) => ips,
            None => did_hosting_common::server::rate_limit::ClientIps::from_server_config(
                &config.server,
            )?,
        };
        // The local GeoIP database, if configured (base design §12.6).
        // Advisory: a file that cannot be read is a warning, and sign-in
        // locations show as "unknown".
        let geoip = open_geoip(&config.geoip).await?;
        let pending_challenges =
            crate::pending_challenges::PendingChallengeTracker::for_auth_config(&config.auth);
        let replay_cache =
            did_hosting_common::server::replay::ReplayCache::with_config(config.replay.clone())?;

        Ok(Self {
            store,
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
            background: TaskTracker::new(),
            didcomm_service: Arc::new(std::sync::OnceLock::new()),
            stats_collector,
            stats_ks,
            timeseries_ks,
            unlisted_signers: Default::default(),
            replay_cache: Arc::new(replay_cache),
            path_locks: did_hosting_common::server::path_locks::PathLocks::new(),
            acl_locks: did_hosting_common::server::path_locks::PathLocks::new(),
            pending_challenges: Arc::new(pending_challenges),
            client_ips,
            ip_rate_limiter: Arc::new(crate::rate_limit::challenge_limiter()),
            login_start_rate_limiter: Arc::new(crate::rate_limit::login_start_limiter()),
            redeem_rate_limiter: Arc::new(crate::rate_limit::redeem_limiter()),
            webs_self_register_limiter: Arc::new(crate::rate_limit::webs_self_register_limiter()),
            webs_self_register_global_limiter: Arc::new(
                crate::rate_limit::webs_self_register_global_limiter(),
            ),
            large_document_budget: Arc::new(
                did_hosting_common::server::trust_tasks::size::LargeDocumentBudget::new(),
            ),
            outbox_notify: Arc::new(tokio::sync::Notify::new()),
            cache_invalidate: overrides.cache_invalidate,
            oob: Arc::new(crate::oob::OobRuntime::with_geoip(geoip)),
        })
    }
}

/// What [`AppState::build`] takes from its caller instead of making its own.
/// `Default` is a standalone control plane: it makes all of them.
#[derive(Default)]
pub struct AppStateOverrides {
    /// The statistics collector. `None` makes one seeded from the store; the
    /// daemon passes the one its embedded server records resolutions in.
    pub stats_collector: Option<Arc<StatsCollector>>,
    /// The hook clearing what the embedded server cached (the daemon). See
    /// [`AppState::cache_invalidate`].
    pub cache_invalidate: Option<Arc<CacheInvalidateFn>>,
    /// The client-address rule. `None` builds one from `[server]`; the daemon
    /// passes the one every service it embeds shares.
    pub client_ips: Option<did_hosting_common::server::rate_limit::ClientIps>,
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

/// The names of the control plane's background tasks: what its supervisor
/// logs, and what the daemon's skip list and parity test refer to.
pub mod tasks {
    /// Expired sessions and challenges are deleted (storage).
    pub const SESSION_CLEANUP: &str = "session-cleanup";
    /// Statistics deltas are flushed, and the tiered-statistics migration
    /// stepped (storage).
    pub const STATS_FLUSH: &str = "stats-flush";
    /// The hosted-DID count is recounted from the records (storage).
    pub const DID_COUNT_RECONCILE: &str = "did-count-reconcile";
    /// Ripe `disable-grace` domain records are deleted.
    pub const DOMAIN_PURGE_SWEEP: &str = "domain-purge-sweep";
    /// Superseded identity generations past their grace period are dropped.
    pub const IDENTITY_EXPIRY: &str = "identity-expiry";
    /// The service re-resolves its own DID document (a backstop for changes
    /// that did not come through its own publish).
    pub const IDENTITY_RELOAD: &str = "identity-reload";
    /// Registered instances are pinged and their status re-evaluated.
    pub const REGISTRY_HEALTH_CHECK: &str = "registry-health-check";
    /// The GeoIP database is reloaded when its file changes.
    pub const GEOIP_RELOAD: &str = "geoip-reload";
    /// The durable outbound queue is delivered (a worker, not a tick).
    pub const OUTBOX: &str = "outbox";
    /// The periodic tasks of [`super::background_tasks`], run together.
    pub const BACKGROUND: &str = "control-background";

    /// Every storage tick ([`super::storage_tasks`]).
    pub const STORAGE: [&str; 3] = [SESSION_CLEANUP, STATS_FLUSH, DID_COUNT_RECONCILE];
    /// Every background tick ([`super::background_tasks`]).
    pub const PERIODIC: [&str; 5] = [
        DOMAIN_PURGE_SWEEP,
        IDENTITY_EXPIRY,
        IDENTITY_RELOAD,
        REGISTRY_HEALTH_CHECK,
        GEOIP_RELOAD,
    ];
}

/// Boot steps that run once a control plane's state is built, before it
/// serves: shared by the standalone [`run`] and the daemon, so a step added
/// here cannot be missed by one of them.
///
/// - Reload challenges issued before a restart, so the caps hold across it.
/// - The service-badge backfill and the DID index build (`M-02`, `M-03`;
///   marker-gated, so a no-op once applied — the daemon has already run them
///   with the rest of its migrations).
/// - Seed the registry from `[[registry.instances]]`.
/// - Check, in the background, that the service's DID lists the services
///   wallet sign-in needs; warn once with the fix if not. Never blocks.
pub async fn startup(state: &AppState) -> Result<(), AppError> {
    state
        .pending_challenges
        .seed_from_sessions_or_warn(&state.sessions_ks)
        .await;
    backfill_service_badges(&state.store).await;
    index_did_records(&state.store).await?;
    seed_registry(state).await;
    crate::sign_in_readiness::spawn(state);
    Ok(())
}

/// What the control plane's storage ticks work on. Built from a control
/// plane's state ([`ControlStorage::of`]), or by the daemon from its own
/// handles, which it has whether or not the control plane runs.
#[derive(Clone)]
pub struct ControlStorage {
    pub sessions_ks: KeyspaceHandle,
    pub stats_ks: KeyspaceHandle,
    pub timeseries_ks: KeyspaceHandle,
    /// Strongly consistent, as the control plane's.
    pub dids_ks: KeyspaceHandle,
    pub auth: AuthConfig,
    /// Whether there are sessions to clean up (the service signs them).
    pub has_auth: bool,
    pub collector: Arc<StatsCollector>,
    pub stats_flush: crate::config::StatsFlushConfig,
}

impl ControlStorage {
    /// The storage of a control plane's state.
    pub fn of(state: &AppState) -> Self {
        Self {
            sessions_ks: state.sessions_ks.clone(),
            stats_ks: state.stats_ks.clone(),
            timeseries_ks: state.timeseries_ks.clone(),
            dids_ks: state.dids_ks.clone(),
            auth: state.config.auth.clone(),
            has_auth: state.jwt_keys.is_some(),
            collector: state.stats_collector.clone(),
            stats_flush: state.config.stats_flush,
        }
    }

    /// The last flush, at shutdown: every delta still held.
    pub async fn final_flush(&self) {
        flush_remaining_stats(&self.collector, &self.stats_ks, &self.timeseries_ks).await;
    }
}

/// The control plane's storage ticks ([`tasks::STORAGE`]): run on its
/// storage thread, and in the daemon's storage task.
pub fn storage_tasks(storage: &ControlStorage) -> Vec<PeriodicTask> {
    let sessions = {
        let s = storage.clone();
        PeriodicTask::new(
            tasks::SESSION_CLEANUP,
            Duration::from_secs(s.auth.session_cleanup_interval),
            move |_| {
                let s = s.clone();
                async move {
                    if let Err(e) =
                        cleanup_expired_sessions(&s.sessions_ks, s.auth.challenge_ttl).await
                    {
                        warn!("session cleanup error: {e}");
                    }
                }
            },
        )
        .enabled_if(storage.has_auth)
    };

    // The migration to (and clean-up after) the tiered statistics format,
    // stepped a flush's worth at a time after each flush.
    let maintenance = Arc::new(tokio::sync::Mutex::new(
        crate::stats_migration::StatsMaintenance::new(
            storage.stats_ks.clone(),
            storage.timeseries_ks.clone(),
            storage.dids_ks.clone(),
        ),
    ));
    let flush = {
        let s = storage.clone();
        PeriodicTask::new(
            tasks::STATS_FLUSH,
            crate::config::STATS_FLUSH_INTERVAL,
            move |shutdown| {
                let s = s.clone();
                let maintenance = maintenance.clone();
                async move {
                    // One deadline for the tick: the flush, then the migration
                    // in what is left of it, so the tick keeps its interval.
                    let deadline =
                        tokio::time::Instant::now() + crate::config::STATS_FLUSH_INTERVAL;
                    if let Err(e) = flush_stats_paced_until(
                        &s.collector,
                        &s.stats_ks,
                        &s.timeseries_ks,
                        &s.stats_flush,
                        shutdown.clone(),
                        deadline,
                    )
                    .await
                    {
                        warn!("stats flush error: {e}");
                    }
                    if let Err(e) = maintenance
                        .lock()
                        .await
                        .step(&s.collector, &s.stats_flush, shutdown, deadline)
                        .await
                    {
                        warn!("stats migration error: {e}");
                    }
                }
            },
        )
        // A flush that overruns its interval is followed by a full interval,
        // not an immediate catch-up flush.
        .delay_missed()
    };

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

    vec![sessions, flush, recount]
}

/// The control plane's background ticks ([`tasks::PERIODIC`]).
pub fn background_tasks(state: &AppState) -> Vec<PeriodicTask> {
    let purge = {
        let store = state.store.clone();
        PeriodicTask::new(
            tasks::DOMAIN_PURGE_SWEEP,
            crate::purge_sweep::DEFAULT_SWEEP_INTERVAL,
            move |_| {
                let store = store.clone();
                async move {
                    let purged = crate::purge_sweep::run_sweep_once(&store).await;
                    if purged > 0 {
                        info!(count = purged, "control purge sweep tick completed");
                    }
                }
            },
        )
    };

    // Identity expiry is local and cheap, so it runs on the tight interval
    // and retires a superseded key promptly; it also picks up a generation
    // the offline CLI retired out of band.
    let expiry = {
        let state = state.clone();
        PeriodicTask::new(
            tasks::IDENTITY_EXPIRY,
            crate::identity_rotation::SWEEP_INTERVAL,
            move |_| {
                let state = state.clone();
                async move { crate::identity_rotation::expire_due(&state).await }
            },
        )
    };

    // The reload re-resolves our DID document over the network. Only a
    // backstop (the publish hook catches a rotation the instant it happens),
    // so it runs on the slower interval.
    let reload = {
        let state = state.clone();
        PeriodicTask::new(
            tasks::IDENTITY_RELOAD,
            crate::identity_rotation::RELOAD_INTERVAL,
            move |_| {
                let state = state.clone();
                async move {
                    if let Err(e) = crate::identity_rotation::reload_now(&state).await {
                        debug!("identity backstop reload failed: {e}");
                    }
                }
            },
        )
    };

    let health = {
        let state = state.clone();
        let interval_secs = state.config.registry.health_check_interval.max(10);
        PeriodicTask::new(
            tasks::REGISTRY_HEALTH_CHECK,
            Duration::from_secs(interval_secs),
            move |_| {
                let state = state.clone();
                async move {
                    // Control's own configured mediator: the send fallback when
                    // a target's document advertises no transport.
                    let fallback =
                        did_hosting_common::server::didcomm_profile::TransportFallback::from_config(
                            state.config.mediator_did.as_deref(),
                            state.config.features.tsp,
                        );
                    if let Err(e) = run_health_checks(
                        &state.registry_ks,
                        &state.didcomm_service,
                        state.config.server_did.as_deref(),
                        interval_secs,
                        &fallback,
                        // The verifier inbound documents are checked with, so
                        // a pong answered over HTTPS is held to the same
                        // per-DID limits.
                        did_hosting_common::server::trust_tasks::send::Peers::new(
                            state.did_resolver.as_ref(),
                            state.trust_tasks_verifier.as_deref(),
                        ),
                        state.identity.as_deref(),
                    )
                    .await
                    {
                        warn!("health check error: {e}");
                    }
                }
            },
        )
    };

    vec![
        purge,
        expiry,
        reload,
        health,
        state.oob.geoip().reload_task(),
    ]
}

/// Start the control plane's background workers under `sup`, leaving out the
/// periodic tasks `skip` names: shared by the standalone [`run`] (which skips
/// nothing) and the daemon (which skips what CLAUDE.md lists as its
/// deliberate omissions).
///
/// Both restart with backoff if they stop ([`Policy::Restart`]): the outbox's
/// queue is durable and every tick is idempotent, so running again is always
/// safe, and stopping would silently stop replication or identity expiry.
///
/// - [`tasks::OUTBOX`] — the durable outbox worker. Idle until a messaging
///   service is up, then delivers every queued mutation; started before the
///   service, so it cannot miss the first notify.
/// - [`tasks::BACKGROUND`] — [`background_tasks`], minus `skip`.
pub fn spawn_workers(state: &AppState, sup: &mut Supervisor, skip: &'static [&'static str]) {
    let outbox_state = state.clone();
    sup.spawn(Stage::Workers, tasks::OUTBOX, Policy::Restart, move |sd| {
        crate::outbox::run_outbox_loop(
            outbox_state.clone(),
            outbox_state.outbox_notify.clone(),
            sd.watch(),
        )
    });
    let periodic_state = state.clone();
    sup.spawn(
        Stage::Workers,
        tasks::BACKGROUND,
        Policy::Restart,
        move |sd| {
            let tasks = background_tasks(&periodic_state)
                .into_iter()
                .filter(|t| !skip.contains(&t.name))
                .collect();
            run_periodic(tasks, sd.watch())
        },
    );
}

/// Start the messaging service (DIDComm and/or TSP), retrying with backoff
/// while it fails, until it starts or `shutdown` is cancelled. `None` when
/// none is configured (no `server_did` or no mediator) or on shutdown.
pub async fn start_messaging(
    state: &AppState,
    shutdown: CancellationToken,
) -> Option<DIDCommService> {
    retry_with_backoff("the messaging service", &shutdown, || {
        start_didcomm_service(state, shutdown.clone())
    })
    .await
    .flatten()
}

/// Stop what [`run`] (or the daemon) started, in order, and report what
/// failed: the workers (and with them the messaging service, which is
/// awaited); then the HTTP listener; then the hand-offs requests left
/// running ([`AppState::background`]); then storage, whose last flush and
/// persist therefore see every write.
pub async fn shutdown(state: &AppState, mut sup: Supervisor) -> Result<(), AppError> {
    sup.stop_stage(Stage::Workers, SHUTDOWN_STAGE_DEADLINE)
        .await;
    if let Some(svc) = state.didcomm_service.get() {
        match tokio::time::timeout(SHUTDOWN_STAGE_DEADLINE, svc.shutdown()).await {
            Ok(()) => info!("DIDComm service stopped"),
            Err(_) => warn!("DIDComm service did not stop within {SHUTDOWN_STAGE_DEADLINE:?}"),
        }
    }
    sup.stop_stage(Stage::Listeners, SHUTDOWN_STAGE_DEADLINE)
        .await;
    state.background.close();
    if tokio::time::timeout(SHUTDOWN_STAGE_DEADLINE, state.background.wait())
        .await
        .is_err()
    {
        warn!(
            remaining = state.background.len(),
            "background hand-offs did not finish within the shutdown deadline"
        );
    }
    sup.finish(SHUTDOWN_STAGE_DEADLINE)
        .await
        .map_err(|failures| {
            AppError::Internal(format!(
                "{} task(s) failed: {}",
                failures.len(),
                failures
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        })
}

pub async fn run(config: AppConfig, store: Store, secrets: ServerSecrets) -> Result<(), AppError> {
    // Validate that at least one management interface is enabled
    if !config.features.http_listener && !config.features.didcomm && !config.features.tsp {
        return Err(AppError::Config(
            "at least one of 'http_listener', 'didcomm', or 'tsp' must be enabled in [features]"
                .into(),
        ));
    }

    #[cfg(feature = "ui")]
    if !config.features.http_listener {
        warn!(
            "UI feature is compiled in but http_listener is disabled — UI will not be accessible"
        );
    }

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

    // Bind TCP listener on the main thread
    let std_listener = if config.features.http_listener {
        let addr = format!("{}:{}", config.server.host, config.server.port);
        let listener = std::net::TcpListener::bind(&addr).map_err(AppError::Io)?;
        listener.set_nonblocking(true).map_err(AppError::Io)?;
        info!("control plane listening addr={addr}");
        Some(listener)
    } else {
        None
    };

    let state = AppState::build(
        config,
        store,
        Some(&secrets),
        identity,
        AppStateOverrides::default(),
    )
    .await?;
    startup(&state).await?;

    // Log startup configuration
    info!("--- enabled services ---");
    info!(
        "  HTTP listener : {}",
        if state.config.features.http_listener {
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

    let mut sup = Supervisor::new("did-hosting-control");
    let mut signal = std::pin::pin!(init::shutdown_signal());

    // Sweep idle clients out of the rate limiters on this runtime, not the
    // HTTP thread's: invite redemption is charged over DIDComm and TSP too,
    // so the sweep runs whether or not the HTTP listener is on.
    state.spawn_rate_limit_gc(&sup.signal(Stage::Workers).token());

    // 1. The HTTP listener thread. Critical: it owns the listening socket.
    let (rest_ready_tx, rest_ready_rx) = oneshot::channel::<()>();
    if let Some(listener) = std_listener {
        let rest_state = state.clone();
        sup.spawn_thread(Stage::Listeners, "control-rest", move |sd| {
            run_rest_thread(listener, rest_state, sd.watch(), rest_ready_tx)
        })
        .map_err(|e| AppError::Internal(format!("failed to spawn REST thread: {e}")))?;
    } else {
        let _ = rest_ready_tx.send(());
    }

    // 2. The storage thread (cleanup + stats flush, then the last flush and
    //    the persist). Critical: it is what persists the store at shutdown.
    let storage = ControlStorage::of(&state);
    let storage_store = state.store.clone();
    sup.spawn_thread(Stage::Storage, "control-storage", move |sd| {
        run_storage_thread(storage_store, storage, sd.watch())
    })
    .map_err(|e| AppError::Internal(format!("failed to spawn storage thread: {e}")))?;

    // Wait for the HTTP listener to be ready before starting DIDComm
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

    // 3. The workers: the outbox and the periodic sweeps. Shared with the
    //    daemon; started before messaging so the outbox is waiting for it.
    spawn_workers(&state, &mut sup, &[]);

    // 4. The mediator messaging service (DIDComm and/or TSP) for inbound +
    //    outbound messages, retried with backoff while it fails. TSP-only
    //    deployments (didcomm off, tsp on) must still start it.
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

    // 4b. Everything that has to follow the listener — shared with the daemon.
    post_listener_startup(&state);

    // Run until the shutdown signal, or until a critical task stops.
    let outcome = if interrupted {
        Ok(())
    } else {
        sup.run_until(&mut signal).await
    };
    let stopped = shutdown(&state, sup).await;
    if let Err(failure) = outcome {
        return Err(AppError::Internal(format!("shut down because {failure}")));
    }
    stopped?;
    info!("control plane shut down");
    Ok(())
}

// ---------------------------------------------------------------------------
// DIDComm service startup (inbound)
// ---------------------------------------------------------------------------

/// Startup work that must run once the messaging listener is up (or has been
/// skipped because no transport is enabled).
///
/// Shared by the standalone control plane's [`run`] and the daemon's
/// `run_daemon`, so a step added here cannot be missed by one of them.
///
/// - Reconnect to any mediator we rotated *away* from but whose grace period
///   has not elapsed. Peers holding a stale DID document are still delivering
///   there, and a restart part-way through the window must not abandon that
///   queue — which is exactly why the retiring generation (and its old
///   mediator) is persisted. No-op in the common case: a key rotation on the
///   same mediator strands nothing.
pub fn post_listener_startup(state: &AppState) {
    crate::identity_rotation::resume_mediator_drains(state);
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
    //
    // The profile carries the key material of every live generation, keyed on
    // the kids the DID document actually resolved to. With TSP on the listener
    // persists the control plane's TSP relationships (Rev 3 §7.2.2) across
    // restarts, so it keeps its half of each edge relationship and does not
    // need to re-invite: an edge re-invites on its own connect, and this side
    // answers (`WebvhTspHandler::handle_control`). In daemon mode this is the
    // only listener, so it covers the daemon too.
    //
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
    info!("TDK profile built, DIDComm listener configured");

    let router = messaging::build_control_router(state.clone())
        .map_err(|e| AppError::Internal(format!("failed to build DIDComm router: {e}")))?;

    let config = DIDCommServiceConfig {
        listeners: vec![listener],
    };

    // The TSP handler is installed whether or not this listener carries TSP
    // yet. The service holds one handler for its lifetime, and the listener's
    // own `protocols` decide whether TSP frames reach it — so a service started
    // without one could never dispatch TSP, even after an identity rotation
    // rebuilt the listener with TSP on (`rebuild_own_listener`) because the
    // new document advertises `TSPTransport`. A DIDComm-only listener receives
    // no TSP frames, so the idle handler costs nothing.
    let svc = DIDCommService::start_with_tsp(
        config,
        router,
        crate::tsp::WebvhTspHandler::new(state.clone()),
        shutdown,
    )
    .await
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
/// Runs **only** `M-02`, not the full `migrations::registry`. The standalone
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
/// `register_did_atomic` self-heals each record on its next publish regardless.
/// Build the per-owner usage counters and the per-domain DID index from the
/// records ([`did_hosting_common::server::migrations::M03IndexDidRecords`]),
/// once, on the first boot after upgrade.
///
/// Fatal on failure, unlike the badge backfill: the quota checks read the
/// counters, so a control plane serving without them would admit writes over
/// an owner's quota.
pub async fn index_did_records(store: &Store) -> Result<(), AppError> {
    use did_hosting_common::server::migrations::{M03IndexDidRecords, MigrationRunner};

    let summary = MigrationRunner::new(vec![Arc::new(M03IndexDidRecords)])
        .run_pending(store)
        .await?;
    info!(applied = ?summary.applied, "DID index backfill complete");
    Ok(())
}

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
///
/// Each `[[registry.instances]]` entry is kept under a stable id derived from
/// its type and URL ([`registry::seeded_instance_id`]) and upserted: a restart
/// refreshes its label and leaves what the registry has observed about it
/// (status, badges, transports) in place, rather than adding another record.
/// Records an earlier version seeded under a random id for the same entry
/// (no DID, same type and URL) are removed.
pub async fn seed_registry(state: &AppState) {
    let existing = match registry::list_instances(&state.registry_ks).await {
        Ok(existing) => existing,
        Err(e) => {
            warn!(error = %e, "failed to list the registry; not seeding configured instances");
            return;
        }
    };
    for instance_config in &state.config.registry.instances {
        let service_type = instance_config.service_type.clone();

        let instance_id = registry::seeded_instance_id(&service_type, &instance_config.url);
        let label = instance_config.label.clone();
        let url = instance_config.url.clone();
        let seeded = registry::upsert_instance(&state.registry_ks, &instance_id, |current| {
            Some(match current {
                Some(mut known) => {
                    known.label = label;
                    known.url = url;
                    known
                }
                None => registry::ServiceInstance {
                    instance_id: instance_id.clone(),
                    service_type: service_type.clone(),
                    label,
                    url,
                    status: ServiceStatus::Active,
                    last_health_check: None,
                    registered_at: crate::auth::session::now_epoch(),
                    metadata: serde_json::Value::Null,
                    // Config-seeded instances carry no capability
                    // declaration; assume webvh-only until the instance
                    // re-registers and reports its compile-time methods.
                    enabled_methods: vec!["webvh".to_string()],
                    served_domains: Vec::new(),
                    protocol_version: "1.0".to_string(),
                    // Config-seeded instances carry no DID (`metadata` is
                    // Null), so there is no document to read badges from.
                    advertised_services: None,
                    services_checked_at: None,
                    sync_batch_capable: false,
                    last_inbound_transport: None,
                    last_inbound_at: None,
                    last_outbound_transport: None,
                    last_outbound_at: None,
                    last_ack_at: None,
                    last_reconcile_at: None,
                },
            })
        })
        .await;
        match seeded {
            Ok(_) => info!(
                url = %instance_config.url,
                service_type = %instance_config.service_type,
                instance_id = %instance_id,
                "seeded registry instance"
            ),
            Err(e) => {
                warn!(url = %instance_config.url, error = %e, "failed to seed registry instance");
                continue;
            }
        }

        // Duplicates an earlier version seeded on every boot.
        for stale in existing.iter().filter(|i| {
            i.instance_id != instance_id
                && i.did().is_none()
                && i.service_type == service_type
                && i.url.trim_end_matches('/') == instance_config.url.trim_end_matches('/')
        }) {
            match registry::deregister_instance(&state.registry_ks, &stale.instance_id).await {
                Ok(()) => info!(
                    instance_id = %stale.instance_id,
                    url = %stale.url,
                    "removed a duplicate seeded registry instance"
                ),
                Err(e) => warn!(
                    instance_id = %stale.instance_id,
                    error = %e,
                    "failed to remove a duplicate seeded registry instance"
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP listener thread (`POST /api/trust-tasks`, health, sign-in, UI)
// ---------------------------------------------------------------------------

fn run_rest_thread(
    std_listener: std::net::TcpListener,
    state: AppState,
    mut shutdown_rx: watch::Receiver<bool>,
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

        let trusted_proxies = state.config.server.trusted_proxies.clone();
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
            tracing::error!("HTTP server failed: {e}");
        }

        info!("REST thread shutting down");
    });
}

// ---------------------------------------------------------------------------
// Storage thread
// ---------------------------------------------------------------------------

/// The storage ticks ([`storage_tasks`]) on a runtime of their own until
/// shutdown, then the last statistics flush and the store's persist. Storage
/// is the last stage [`shutdown`] stops, so both see every write.
fn run_storage_thread(store: Store, storage: ControlStorage, shutdown_rx: watch::Receiver<bool>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build storage runtime");

    rt.block_on(async {
        info!("storage thread started");
        run_periodic(storage_tasks(&storage), shutdown_rx).await;
        info!("storage thread shutting down");

        storage.final_flush().await;
        if let Err(e) = store.persist().await {
            tracing::error!("failed to persist store on shutdown: {e}");
        } else {
            info!("store persisted");
        }
    });
}

pub use crate::stats_flush::{
    STATS_BUCKET_MAX_AGE, STATS_FLUSH_CONCURRENCY, STATS_SHUTDOWN_FLUSH_DEADLINE,
    flush_remaining_stats, flush_stats_paced, flush_stats_paced_until, flush_stats_to_store,
};

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
    peers: did_hosting_common::server::trust_tasks::send::Peers<'_>,
    signer: &affinidi_tdk::secrets_resolver::secrets::Secret,
) {
    use did_hosting_common::server::trust_tasks::send::{build_signed_request, send_trust_task};

    // `server/health/0.1`: names the instance probed, which is the one the
    // edge registered as. An edge before #449 ignores the payload.
    let ping = match did_hosting_common::server::trust_tasks::infra::health_ping_body(
        &registry::instance_id_for(server_did),
    ) {
        Ok(ping) => ping,
        Err(e) => {
            warn!(error = %e, "health ping: not a server/health/0.1 payload");
            return;
        }
    };
    // Signed: an edge answers only a ping its control plane signed.
    let doc = match build_signed_request(
        did_hosting_common::didcomm_types::MSG_HEALTH_PING,
        control_did,
        server_did,
        ping,
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
        peers,
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
    peers: did_hosting_common::server::trust_tasks::send::Peers<'_>,
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
                peers,
                signer,
            )
            .await;
        }
    }

    // Evaluate status based on last pong timestamp
    // Only a pong records a successful check; the sweep only re-derives the
    // status from the last one, so it can degrade an instance but never
    // revive it.
    for inst in &instances {
        if registry::health_status_from_timestamp(inst, now, health_interval_secs) == inst.status {
            continue;
        }
        if let Some((old_status, new_status)) =
            registry::reevaluate_status(registry_ks, &inst.instance_id, now, health_interval_secs)
                .await?
        {
            info!(
                instance_id = %inst.instance_id,
                ?old_status,
                ?new_status,
                "instance status changed"
            );
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
        if let Err(e) = registry::refresh_advertised_services(
            registry_ks,
            &inst.instance_id,
            peers.did_resolver,
            now,
        )
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
mod seed_registry_tests {
    use super::*;
    use crate::config::InstanceConfig;

    /// A configured instance is one record however often the control plane
    /// starts, under an id derived from its type and URL; what the registry
    /// observed about it survives a restart, and the duplicates an earlier
    /// version left (one random id per boot) are removed.
    #[tokio::test]
    async fn seeding_on_every_boot_keeps_one_record_per_configured_instance() {
        let (mut state, _dir) = crate::control_tasks::harness::state().await;
        let mut config = (*state.config).clone();
        config.registry.instances = vec![InstanceConfig {
            label: Some("edge one".into()),
            service_type: registry::ServiceType::Server,
            url: "https://edge-one.example".into(),
        }];
        state.config = std::sync::Arc::new(config);

        // What an earlier version left behind: a record per boot.
        for n in 0..3 {
            let stale: registry::ServiceInstance = serde_json::from_value(serde_json::json!({
                "instanceId": format!("0000-old-{n}"),
                "serviceType": "server",
                "label": "edge one",
                "url": "https://edge-one.example/",
                "status": "unreachable",
                "registeredAt": 1,
                "metadata": null,
            }))
            .unwrap();
            registry::register_instance(&state.registry_ks, &stale)
                .await
                .unwrap();
        }

        seed_registry(&state).await;
        let id = registry::seeded_instance_id(
            &registry::ServiceType::Server,
            "https://edge-one.example",
        );
        registry::update_instance(&state.registry_ks, &id, |instance| {
            instance.status = ServiceStatus::Degraded;
            instance.last_health_check = Some(42);
            true
        })
        .await
        .unwrap();
        seed_registry(&state).await;
        seed_registry(&state).await;

        let all = registry::list_instances(&state.registry_ks).await.unwrap();
        assert_eq!(all.len(), 1, "{all:?}");
        assert_eq!(all[0].instance_id, id);
        assert_eq!(all[0].label.as_deref(), Some("edge one"));
        assert_eq!(
            all[0].status,
            ServiceStatus::Degraded,
            "a restart keeps what the registry observed"
        );
    }

    /// Concurrent writers to one instance each keep their change: no
    /// read-modify-write loses another's.
    #[tokio::test]
    async fn concurrent_instance_updates_are_not_lost() {
        let (state, _dir) = crate::control_tasks::harness::state().await;
        let edge = "did:example:edge-concurrent";
        let instance: registry::ServiceInstance = serde_json::from_value(serde_json::json!({
            "instanceId": registry::instance_id_for(edge),
            "serviceType": "server",
            "url": "https://edge.example",
            "status": "active",
            "registeredAt": 1,
            "metadata": { "did": edge },
        }))
        .unwrap();
        registry::register_instance(&state.registry_ks, &instance)
            .await
            .unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for n in 0..32u64 {
            let ks = state.registry_ks.clone();
            tasks.spawn(async move {
                registry::update_instance_for_did(&ks, edge, |i| {
                    i.served_domains.push(format!("d{n}.example"));
                    true
                })
                .await
                .unwrap();
            });
        }
        while tasks.join_next().await.is_some() {}
        let stored = registry::get_instance_for_did(&state.registry_ks, edge)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.served_domains.len(), 32);
    }

    /// The sweep degrades an instance whose last pong is stale and keeps
    /// degrading it: a status change is not a successful check, so the next
    /// sweep must not read it as one and revive the instance. Only a pong does.
    #[tokio::test]
    async fn the_health_sweep_never_revives_an_instance_without_a_pong() {
        let (state, _dir) = crate::control_tasks::harness::state().await;
        let edge = "did:example:edge-sweep";
        let interval = 60;
        let now = crate::auth::session::now_epoch();
        let last_pong = now - interval * 3 / 2;
        let instance: registry::ServiceInstance = serde_json::from_value(serde_json::json!({
            "instanceId": registry::instance_id_for(edge),
            "serviceType": "server",
            "url": "https://edge.example",
            "status": "active",
            "lastHealthCheck": last_pong,
            "registeredAt": 1,
            "metadata": { "did": edge },
        }))
        .unwrap();
        registry::register_instance(&state.registry_ks, &instance)
            .await
            .unwrap();

        let didcomm = std::sync::OnceLock::new();
        let fallback = did_hosting_common::server::didcomm_profile::TransportFallback::from_config(
            None, false,
        );
        let sweep = || {
            run_health_checks(
                &state.registry_ks,
                &didcomm,
                None,
                interval,
                &fallback,
                did_hosting_common::server::trust_tasks::send::Peers::new(None, None),
                None,
            )
        };
        let held = || async {
            registry::get_instance(&state.registry_ks, &instance.instance_id)
                .await
                .unwrap()
                .unwrap()
        };

        for sweep_no in 0..3 {
            sweep().await.unwrap();
            let stored = held().await;
            assert_eq!(stored.status, ServiceStatus::Degraded, "sweep {sweep_no}");
            assert_eq!(
                stored.last_health_check,
                Some(last_pong),
                "a sweep records no check"
            );
        }

        // Old enough, it ages on to Unreachable, and stays there.
        registry::update_instance(&state.registry_ks, &instance.instance_id, |i| {
            i.last_health_check = Some(now - interval * 3);
            true
        })
        .await
        .unwrap();
        sweep().await.unwrap();
        sweep().await.unwrap();
        assert_eq!(held().await.status, ServiceStatus::Unreachable);

        // A pong is a successful check: the next sweep keeps it Active.
        registry::update_instance(&state.registry_ks, &instance.instance_id, |i| {
            i.status = ServiceStatus::Active;
            i.last_health_check = Some(now);
            true
        })
        .await
        .unwrap();
        sweep().await.unwrap();
        assert_eq!(held().await.status, ServiceStatus::Active);
    }
}

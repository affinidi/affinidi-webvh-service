//! End-to-end replication smoke test through a **real** mediator
//! (`affinidi-messaging-test-mediator`) and a **real** bound HTTPS listener.
//!
//! Every other trust-task test in this workspace drives the transports
//! in-process: `Via::Tsp`/`Via::Didcomm` call the frame/envelope handler
//! functions directly, and `Via::Https` calls the route handler function
//! directly (`tower::ServiceExt::oneshot` or a bare function call). None of
//! that touches `did_hosting_common::server::trust_tasks::send::send_trust_task`'s
//! actual network code — the DIDComm branches never go near a mediator
//! socket, and the HTTPS branch never opens a TCP connection. This file
//! closes that gap: a control plane and a hosting server (edge), each with a
//! real `did:peer` identity, replicate a domain over
//!
//! 1. **DIDComm through the mediator** — both sides run a real
//!    `DIDCommService` listener (`did_hosting_control`/`did_hosting_server`'s
//!    own `start_didcomm_service`) connected to a spawned
//!    `affinidi-messaging-test-mediator`; the control plane's outbox pushes a
//!    signed document over the wire, the edge's real router applies it and
//!    replies, and the control plane's real router receives that reply and
//!    settles the outbox entry — with no test code standing in for any of
//!    those steps.
//! 2. **HTTPS** — the edge runs a real `axum::serve` on an ephemeral loopback
//!    port, advertising `TrustTaskHTTPS` on its own `did:peer` document; the
//!    control plane's outbox POSTs to it over a real HTTP connection and
//!    verifies the signed reply exactly as `send_over_https` does in
//!    production.
//!
//! Both are run twice: once in **distributed** shape (control plane and edge
//! are two independent identities, each with its own listener) and once in
//! **daemon** shape, mirroring `CLAUDE.md`'s "did-hosting-daemon" section: one
//! identity, one DIDComm listener (owned by the control-plane role), and an
//! embedded server-role `AppState` that never starts a listener of its own.
//! `did-hosting-daemon` is a bin-only crate with no library target, so its
//! `build_control`/`build_server` wiring cannot be called from an external
//! test; this reproduces the one architectural difference CLAUDE.md
//! documents (single shared identity/listener) directly, and still
//! replicates outward to a genuinely separate, remote standalone edge over
//! the real mediator/HTTP — exactly the "daemon *can* host remote service
//! instances" case CLAUDE.md calls out.
//!
//! ## Secrets
//!
//! No `SecretStore`/keyring is opened anywhere in this file: identities are
//! built directly from freshly generated `Secret`s via
//! `ServiceIdentity::for_didcomm_test`/`from_signing_secret`, which hold key
//! material in memory only. There is nothing here for `confirm_plaintext` to
//! gate.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_test_mediator::TestMediator;
use affinidi_tdk::dids::{
    DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use tokio_util::sync::CancellationToken;

use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::{
    self, DomainEntry, DomainScope, DomainStatus, DomainUrlScheme,
};
use did_hosting_common::server::identity::{ProtocolSet, ServiceIdentity};
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES, Store,
};
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// did:peer minting — real, resolvable-with-no-network identities
// ---------------------------------------------------------------------------

/// Mint a `did:peer:2` with a fresh Ed25519 (verification) + X25519
/// (encryption) key pair and a `DIDCommMessaging` service pointing at
/// `mediator`, so it resolves with no network I/O. Also registers the DID
/// with the mediator (`LOCAL`, `ALLOW_ALL`) — a `DIDCommService` connecting
/// with a DID the mediator has never seen (everything minted directly via
/// `DID::generate_did_peer_with_services` rather than
/// `TestMediator{,Handle}::{with_users,add_user}` is, by construction,
/// unknown to it) never completes its handshake and `wait_connected` times
/// out; this is that missing registration step, folded into minting so every
/// caller gets it automatically.
///
/// Returns `(did, signing_secret, ka_secret)` —
/// `generate_did_peer_with_services` returns secrets in the same order as the
/// `keys` list passed in, which is always Verification then Encryption here.
async fn mint_didcomm_peer(
    mediator: &affinidi_messaging_test_mediator::TestMediatorHandle,
) -> (String, Secret, Secret) {
    let (did, secrets) = DID::generate_did_peer_with_services(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        Some(vec![didcomm_service()]),
    )
    .expect("generate did:peer");
    let mut secrets = secrets.into_iter();
    let signing = secrets.next().expect("verification secret");
    let ka = secrets.next().expect("encryption secret");
    mediator
        .register_local_did(&did)
        .await
        .expect("register did:peer with the test mediator (LOCAL, ALLOW_ALL)");
    (did, signing, ka)
}

/// Mint a `did:peer:2` with **only** a verification key — HTTPS carries no
/// encryption, so no key-agreement key is needed. Returns
/// `(did, signing_secret)`.
fn mint_https_peer(base_url: &str) -> (String, Secret) {
    let (did, secrets) = DID::generate_did_peer_with_services(
        vec![(PeerKeyRole::Verification, KeyType::Ed25519)],
        Some(vec![https_service(base_url)]),
    )
    .expect("generate did:peer");
    let signing = secrets.into_iter().next().expect("verification secret");
    (did, signing)
}

/// A `DIDCommMessaging` service with a short placeholder endpoint — the
/// named service type `resolve_transport` (tier 1) recognises, deliberately
/// built ourselves rather than via `TestMediator::add_user` (whose minted
/// peers tag their service `"dm"`, which `resolve_transport` does not
/// match). Building it this way exercises document-advertised routing, not
/// just the config-mediator fallback.
///
/// The endpoint is a placeholder, not `mediator.did()`, on purpose:
/// `resolve_transport` only reads this service's *type* to pick the
/// `Didcomm` binding, and `send_over_didcomm` never reads the endpoint value
/// at all (the real connection target is `identity.mediator_did()` —
/// `ServiceIdentity::for_didcomm_test`'s own parameter — resolved once at
/// listener startup, independent of anything in this document). Embedding
/// the mediator's own `did:peer` here instead would nest one already-long
/// `did:peer` inside another and push the result past `check_acl`'s
/// 512-byte cap on the DIDs it looks up — exactly the failure this
/// placeholder avoids.
fn didcomm_service() -> PeerService {
    PeerService {
        type_: "DIDCommMessaging".into(),
        endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri: "urn:mediator:placeholder".into(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        })),
        id: Some("#vta-didcomm".into()),
    }
}

/// A `TrustTaskHTTPS` service pointing at `base_url` (the Trust-Task base;
/// the request itself goes to `{base_url}/trust-tasks`).
fn https_service(base_url: &str) -> PeerService {
    PeerService {
        type_: "TrustTaskHTTPS".into(),
        endpoint: PeerServiceEndpoint::Uri(base_url.to_string()),
        id: Some("#trust-tasks".into()),
    }
}

// ---------------------------------------------------------------------------
// AppState builders
// ---------------------------------------------------------------------------

/// A `did-hosting-control` `AppState` for `identity`, sharing `did_resolver`
/// so peer resolution (routing + reply verification) is real. Field-for-field
/// copy of `control_tasks::harness::state()` (this crate's own canonical
/// control-plane test fixture), parameterised on identity/resolver instead of
/// a fixed `did:webvh:test:...` + `None`.
async fn control_state(
    identity: Arc<ServiceIdentity>,
    did_resolver: DIDCacheClient,
) -> (did_hosting_control::server::AppState, tempfile::TempDir) {
    use did_hosting_control::config::{AppConfig, RegistryConfig};

    let did = identity.did.clone();
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some(did),
        mediator_did: None,
        public_url: Some("http://control.test".into()),
        did_hosting_url: Some("http://control.test".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        fjall: Default::default(),
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(),
        registry: RegistryConfig::default(),
        trust_tasks: Default::default(),
        hosting: Default::default(),
        identity: Default::default(),
        config_path: PathBuf::new(),
    };
    let state = did_hosting_control::server::AppState {
        store: store.clone(),
        sessions_ks: store.keyspace(KS_SESSIONS).unwrap(),
        acl_ks: store.keyspace(KS_ACL).unwrap(),
        registry_ks: store.keyspace(KS_REGISTRY).unwrap(),
        dids_ks: store.keyspace(KS_DIDS).unwrap(),
        config: Arc::new(config),
        did_resolver: Some(did_resolver.clone()),
        secrets_resolver: None,
        identity: Some(identity),
        trust_tasks_verifier: Some(Arc::new(TransportBoundVerifier::with_did_cache(
            did_resolver,
        ))),
        jwt_keys: Some(Arc::new(
            did_hosting_control::auth::jwt::JwtKeys::from_ed25519_bytes(&[7u8; 32]).unwrap(),
        )),
        webauthn: None,
        http_client: reqwest::Client::new(),
        didcomm_service: Arc::new(OnceLock::new()),
        stats_collector: Arc::new(StatsCollector::new()),
        stats_ks: store.keyspace(KS_STATS).unwrap(),
        timeseries_ks: store.keyspace(KS_TIMESERIES).unwrap(),
        signing_key_bytes: None,
        replay_cache: Arc::new(did_hosting_control::replay::ReplayCache::new()),
        path_locks: did_hosting_control::path_locks::PathLocks::new(),
        acl_locks: did_hosting_common::server::path_locks::PathLocks::new(),
        pending_challenges: Arc::new(
            did_hosting_control::pending_challenges::PendingChallengeTracker::new(),
        ),
        ip_rate_limiter: Arc::new(did_hosting_control::rate_limit::IpRateLimiter::new()),
        pending_confirms: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        outbox_notify: Arc::new(tokio::sync::Notify::new()),
    };
    (state, dir)
}

/// A `did-hosting-server` (edge) `AppState` for `identity`, trusting
/// `control_did` as its one control plane. Field-for-field copy of
/// `edge_trust_tasks.rs`'s `edge_state()`.
async fn edge_state(
    identity: Arc<ServiceIdentity>,
    control_did: &str,
    did_resolver: DIDCacheClient,
) -> (did_hosting_server::server::AppState, tempfile::TempDir) {
    use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};

    let did = identity.did.clone();
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some(did),
        mediator_did: None,
        public_url: Some("https://edge.example.com".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        fjall: Default::default(),
        auth: AuthConfig::default(),
        hosting: did_hosting_common::server::config::HostingConfig::default(),
        secrets: SecretsConfig::default(),
        limits: LimitsConfig::default(),
        stats: StatsConfig::default(),
        control_did: Some(control_did.to_string()),
        vta: VtaConfig::default(),
        identity: Default::default(),
        config_path: PathBuf::new(),
    };
    let state = did_hosting_server::server::AppState {
        store: store.clone(),
        dids_ks: store.keyspace(KS_DIDS).unwrap(),
        config: Arc::new(config),
        did_resolver: Some(did_resolver.clone()),
        trust_tasks_verifier: Some(Arc::new(TransportBoundVerifier::with_did_cache(
            did_resolver,
        ))),
        secrets_resolver: None,
        identity: Some(identity),
        didcomm_service: Arc::new(OnceLock::new()),
        stats_collector: None,
        did_cache: Arc::new(did_hosting_server::cache::ContentCache::new(
            Duration::from_secs(60),
        )),
        trusted_proxy_cidrs: Arc::new(Vec::new()),
    };
    (state, dir)
}

/// Register `edge_did` as a `Role::Service` in `control`'s ACL — the
/// prerequisite for the outbox to have anywhere to enqueue a push, matching
/// what `POST /api/servers` leaves behind for a real registration.
async fn register_edge(control: &did_hosting_control::server::AppState, edge_did: &str) {
    store_acl_entry(
        &control.acl_ks,
        &AclEntry {
            did: edge_did.to_string(),
            role: Role::Service,
            label: Some("edge".into()),
            created_at: 1,
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        },
    )
    .await
    .unwrap();
}

/// A one-off domain entry to replicate.
fn domain_entry(name: &str) -> DomainEntry {
    DomainEntry {
        name: name.into(),
        label: None,
        scheme: DomainUrlScheme::Https,
        status: DomainStatus::Active,
        created_at: 1_700_000_000,
        default_domain: false,
        branding: None,
        witnesses: None,
        watchers: None,
        quota: None,
        well_known_enabled: false,
        disabled_at: None,
        purge_at: None,
    }
}

/// Poll `check` until it returns `true` or `timeout` elapses.
async fn wait_until<Fut>(mut check: impl FnMut() -> Fut, timeout: Duration, what: &str)
where
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Reserve an ephemeral loopback port up front, before the edge's `did:peer`
/// is minted — the DID is content-addressed over its keys *and* services, so
/// the `TrustTaskHTTPS` endpoint has to be known before minting, not after.
/// Returns the Trust-Task base URL (`http://127.0.0.1:{port}/api`) to
/// advertise, and the bound (not yet serving) listener.
async fn reserve_https_port() -> (String, tokio::net::TcpListener) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral loopback port");
    let addr = listener.local_addr().expect("local addr");
    (format!("http://{addr}/api"), listener)
}

/// Serve the edge's production `POST /api/trust-tasks` route
/// (`did_hosting_server::routes::trust_tasks::receive`, unmodified) on
/// `listener`. Returns the task's handle — aborted at test end.
fn serve_https_edge(
    listener: tokio::net::TcpListener,
    state: did_hosting_server::server::AppState,
) -> tokio::task::JoinHandle<()> {
    let app = axum::Router::new()
        .route(
            "/api/trust-tasks",
            axum::routing::post(did_hosting_server::routes::trust_tasks::receive),
        )
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("edge HTTPS server");
    })
}

/// Wait until `svc`'s named listener is connected to the mediator.
async fn wait_connected(
    svc: &affinidi_messaging_didcomm_service::DIDCommService,
    listener_id: &str,
) {
    svc.wait_connected(listener_id, CONNECT_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{listener_id} listener never connected: {e}"));
}

// ---------------------------------------------------------------------------
// Distributed mode — separate control plane and edge, each its own listener
// ---------------------------------------------------------------------------

/// Control plane → edge replication over **DIDComm, through a real
/// mediator**: both sides run a real `DIDCommService`, the outbox's push
/// travels the wire, the edge's real router applies it and replies, and the
/// control plane's real router receives the reply and settles the entry.
#[tokio::test]
async fn distributed_mode_replicates_over_didcomm_through_the_mediator() {
    let mediator = TestMediator::spawn().await.expect("spawn test mediator");
    let shutdown = CancellationToken::new();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("did resolver");

    let (control_did, control_signing, control_ka) = mint_didcomm_peer(&mediator).await;
    let control_identity = ServiceIdentity::for_didcomm_test(
        &control_did,
        control_signing,
        control_ka,
        mediator.did(),
        ProtocolSet {
            didcomm: true,
            tsp: false,
        },
    )
    .await
    .expect("control identity");

    let (edge_did, edge_signing, edge_ka) = mint_didcomm_peer(&mediator).await;
    let edge_identity = ServiceIdentity::for_didcomm_test(
        &edge_did,
        edge_signing,
        edge_ka,
        mediator.did(),
        ProtocolSet {
            didcomm: true,
            tsp: false,
        },
    )
    .await
    .expect("edge identity");

    let (control, _control_dir) = control_state(control_identity, did_resolver.clone()).await;
    let (edge, _edge_dir) = edge_state(edge_identity, &control_did, did_resolver).await;
    register_edge(&control, &edge_did).await;

    let control_svc =
        did_hosting_control::server::start_didcomm_service(&control, shutdown.clone())
            .await
            .expect("start control DIDComm service")
            .expect("control has a mediator — service must start");
    control.didcomm_service.set(control_svc.clone()).ok();
    let edge_svc = did_hosting_server::server::start_didcomm_service(&edge, shutdown.clone())
        .await
        .expect("start edge DIDComm service")
        .expect("edge has a mediator — service must start");
    edge.didcomm_service.set(edge_svc.clone()).ok();

    wait_connected(&control_svc, "control").await;
    wait_connected(&edge_svc, "server").await;

    did_hosting_control::server_push::send_domain_upsert(
        &control,
        &edge_did,
        &domain_entry("edge.example.com"),
    )
    .await
    .expect("queue domain upsert");

    did_hosting_control::outbox::run_tick(&control).await;

    wait_until(
        || async {
            domain::get_domain(&edge.store, "edge.example.com")
                .await
                .unwrap()
                .is_some()
        },
        SETTLE_TIMEOUT,
        "edge applies the domain upsert over DIDComm",
    )
    .await;
    wait_until(
        || async {
            did_hosting_control::outbox::list_pending_for_target(&control.store, &edge_did)
                .await
                .unwrap()
                .is_empty()
        },
        SETTLE_TIMEOUT,
        "control settles the outbox entry once the edge's DIDComm ack arrives",
    )
    .await;

    shutdown.cancel();
    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// Control plane → edge replication over **HTTPS**: the edge runs a real
/// bound `axum::serve` (no DIDComm listener at all on this side), the
/// control's outbox POSTs the signed document over a real HTTP connection,
/// and `send_over_https` verifies the reply is signed by the edge, addressed
/// back to the control plane, and threaded — settling the outbox entry
/// synchronously (see `outbox::run_tick`'s HTTPS self-acknowledge).
#[tokio::test]
async fn distributed_mode_replicates_over_https() {
    let mediator = TestMediator::spawn().await.expect("spawn test mediator");
    let shutdown = CancellationToken::new();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("did resolver");

    // The control plane still needs a real, working DIDComm listener: the
    // outbox no-ops entirely without one (`run_tick` reads
    // `state.didcomm_service.get()`), even though this test's send never
    // touches it — `send_trust_task`'s HTTPS branch ignores its `didcomm`
    // parameter. Proves HTTPS routing wins on its own merits: the edge's
    // document advertises no TSP/DIDComm at all, only `TrustTaskHTTPS`.
    let (control_did, control_signing, control_ka) = mint_didcomm_peer(&mediator).await;
    let control_identity = ServiceIdentity::for_didcomm_test(
        &control_did,
        control_signing,
        control_ka,
        mediator.did(),
        ProtocolSet {
            didcomm: true,
            tsp: false,
        },
    )
    .await
    .expect("control identity");
    let (control, _control_dir) = control_state(control_identity, did_resolver.clone()).await;
    let control_svc =
        did_hosting_control::server::start_didcomm_service(&control, shutdown.clone())
            .await
            .expect("start control DIDComm service")
            .expect("control has a mediator — service must start");
    control.didcomm_service.set(control_svc.clone()).ok();
    wait_connected(&control_svc, "control").await;

    // Reserve the loopback port first: the edge's `did:peer` is
    // content-addressed over its keys *and* services, so the URL has to be
    // known before minting it. The edge's identity is signing-only — HTTPS
    // carries no encryption, and its document advertises `TrustTaskHTTPS`
    // (not `DIDCommMessaging`), so no key-agreement key is exercised.
    let (base_url, listener) = reserve_https_port().await;
    let (edge_did, edge_signing) = mint_https_peer(&base_url);
    let edge_identity = ServiceIdentity::from_signing_secret(&edge_did, edge_signing)
        .await
        .expect("edge identity");
    let (edge, _edge_dir) = edge_state(edge_identity, &control_did, did_resolver).await;
    register_edge(&control, &edge_did).await;
    let https_handle = serve_https_edge(listener, edge.clone());

    did_hosting_control::server_push::send_domain_upsert(
        &control,
        &edge_did,
        &domain_entry("edge.example.com"),
    )
    .await
    .expect("queue domain upsert");

    did_hosting_control::outbox::run_tick(&control).await;

    wait_until(
        || async {
            domain::get_domain(&edge.store, "edge.example.com")
                .await
                .unwrap()
                .is_some()
        },
        SETTLE_TIMEOUT,
        "edge applies the domain upsert over HTTPS",
    )
    .await;
    // No separate wait needed for settlement: `run_tick`'s HTTPS branch
    // self-acknowledges synchronously once `send_trust_task` returns, so by
    // the time the tick above completed the entry is already gone.
    assert!(
        did_hosting_control::outbox::list_pending_for_target(&control.store, &edge_did)
            .await
            .unwrap()
            .is_empty(),
        "the HTTPS round trip already proved delivery; the entry must not be waiting on a \
         separate ack"
    );

    https_handle.abort();
    shutdown.cancel();
    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

// ---------------------------------------------------------------------------
// Daemon mode — one identity, one listener (owned by the control-plane
// role), an embedded server-role AppState that never starts a listener of
// its own — replicating outward to a genuinely separate, remote edge.
//
// See this file's module docs and CLAUDE.md's "did-hosting-daemon" section
// for why the daemon binary itself isn't driven directly here.
// ---------------------------------------------------------------------------

/// Daemon-mode control plane → remote edge replication over **DIDComm,
/// through a real mediator**. One shared identity backs both the
/// control-plane role (a real listener) and an embedded server role (no
/// listener at all — `embedded_server.didcomm_service` stays empty, exactly
/// as CLAUDE.md describes); the remote edge is a fully separate, standalone
/// identity and listener, registered the same way a real remote instance
/// would be.
#[tokio::test]
async fn daemon_mode_replicates_over_didcomm_through_the_mediator() {
    let mediator = TestMediator::spawn().await.expect("spawn test mediator");
    let shutdown = CancellationToken::new();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("did resolver");

    // One identity, shared by both roles — mirrors main.rs's `identity.clone()`
    // passed to both `build_server` and `build_control`.
    let (daemon_did, daemon_signing, daemon_ka) = mint_didcomm_peer(&mediator).await;
    let daemon_identity = ServiceIdentity::for_didcomm_test(
        &daemon_did,
        daemon_signing,
        daemon_ka,
        mediator.did(),
        ProtocolSet {
            didcomm: true,
            tsp: false,
        },
    )
    .await
    .expect("daemon identity");

    let (control, _control_dir) =
        control_state(daemon_identity.clone(), did_resolver.clone()).await;
    // The embedded server role: same identity, same store's DID keyspace
    // shape, but — per CLAUDE.md — no listener of its own in daemon mode.
    let (embedded_server, _embedded_dir) =
        edge_state(daemon_identity, &daemon_did, did_resolver.clone()).await;

    let control_svc =
        did_hosting_control::server::start_didcomm_service(&control, shutdown.clone())
            .await
            .expect("start control DIDComm service")
            .expect("control has a mediator — service must start");
    control.didcomm_service.set(control_svc.clone()).ok();
    wait_connected(&control_svc, "control").await;
    assert!(
        embedded_server.didcomm_service.get().is_none(),
        "the daemon's embedded server role must not start its own listener"
    );

    // The remote edge: a genuinely separate identity and listener, exactly
    // as in the distributed test.
    let (edge_did, edge_signing, edge_ka) = mint_didcomm_peer(&mediator).await;
    let edge_identity = ServiceIdentity::for_didcomm_test(
        &edge_did,
        edge_signing,
        edge_ka,
        mediator.did(),
        ProtocolSet {
            didcomm: true,
            tsp: false,
        },
    )
    .await
    .expect("edge identity");
    let (edge, _edge_dir) = edge_state(edge_identity, &daemon_did, did_resolver).await;
    register_edge(&control, &edge_did).await;
    let edge_svc = did_hosting_server::server::start_didcomm_service(&edge, shutdown.clone())
        .await
        .expect("start edge DIDComm service")
        .expect("edge has a mediator — service must start");
    edge.didcomm_service.set(edge_svc.clone()).ok();
    wait_connected(&edge_svc, "server").await;

    did_hosting_control::server_push::send_domain_upsert(
        &control,
        &edge_did,
        &domain_entry("edge.example.com"),
    )
    .await
    .expect("queue domain upsert");

    did_hosting_control::outbox::run_tick(&control).await;

    wait_until(
        || async {
            domain::get_domain(&edge.store, "edge.example.com")
                .await
                .unwrap()
                .is_some()
        },
        SETTLE_TIMEOUT,
        "the remote edge applies the domain upsert over DIDComm",
    )
    .await;
    wait_until(
        || async {
            did_hosting_control::outbox::list_pending_for_target(&control.store, &edge_did)
                .await
                .unwrap()
                .is_empty()
        },
        SETTLE_TIMEOUT,
        "the daemon's control role settles the outbox entry once the edge's ack arrives",
    )
    .await;

    shutdown.cancel();
    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// Daemon-mode control plane → remote edge replication over **HTTPS**. Same
/// shared-identity/no-embedded-listener shape as the DIDComm daemon test
/// above; the remote edge runs a real bound HTTP server instead of a
/// DIDComm listener.
#[tokio::test]
async fn daemon_mode_replicates_over_https() {
    let mediator = TestMediator::spawn().await.expect("spawn test mediator");
    let shutdown = CancellationToken::new();
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("did resolver");

    let (daemon_did, daemon_signing, daemon_ka) = mint_didcomm_peer(&mediator).await;
    let daemon_identity = ServiceIdentity::for_didcomm_test(
        &daemon_did,
        daemon_signing,
        daemon_ka,
        mediator.did(),
        ProtocolSet {
            didcomm: true,
            tsp: false,
        },
    )
    .await
    .expect("daemon identity");

    let (control, _control_dir) =
        control_state(daemon_identity.clone(), did_resolver.clone()).await;
    let (embedded_server, _embedded_dir) =
        edge_state(daemon_identity, &daemon_did, did_resolver.clone()).await;

    let control_svc =
        did_hosting_control::server::start_didcomm_service(&control, shutdown.clone())
            .await
            .expect("start control DIDComm service")
            .expect("control has a mediator — service must start");
    control.didcomm_service.set(control_svc.clone()).ok();
    wait_connected(&control_svc, "control").await;
    assert!(
        embedded_server.didcomm_service.get().is_none(),
        "the daemon's embedded server role must not start its own listener"
    );

    let (base_url, listener) = reserve_https_port().await;
    let (edge_did, edge_signing) = mint_https_peer(&base_url);
    let edge_identity = ServiceIdentity::from_signing_secret(&edge_did, edge_signing)
        .await
        .expect("edge identity");
    let (edge, _edge_dir) = edge_state(edge_identity, &daemon_did, did_resolver).await;
    register_edge(&control, &edge_did).await;
    let https_handle = serve_https_edge(listener, edge.clone());

    did_hosting_control::server_push::send_domain_upsert(
        &control,
        &edge_did,
        &domain_entry("edge.example.com"),
    )
    .await
    .expect("queue domain upsert");

    did_hosting_control::outbox::run_tick(&control).await;

    wait_until(
        || async {
            domain::get_domain(&edge.store, "edge.example.com")
                .await
                .unwrap()
                .is_some()
        },
        SETTLE_TIMEOUT,
        "the remote edge applies the domain upsert over HTTPS",
    )
    .await;
    assert!(
        did_hosting_control::outbox::list_pending_for_target(&control.store, &edge_did)
            .await
            .unwrap()
            .is_empty(),
        "the HTTPS round trip already proved delivery; the entry must not be waiting on a \
         separate ack"
    );

    https_handle.abort();
    shutdown.cancel();
    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

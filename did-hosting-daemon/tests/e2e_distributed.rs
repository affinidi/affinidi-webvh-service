//! Distributed-mode end-to-end smoke: a standalone control plane, edge,
//! witness and watcher — each a real process-shaped `AppState`, wired
//! together the way `did-hosting-control/tests/mediator_replication_smoke.rs`
//! wires a control plane and an edge: real bound HTTPS listeners, and (for the
//! control plane) a real `DIDCommService` on a real, spawned
//! `affinidi-messaging-test-mediator`.
//!
//! What that file doesn't cover, and this one adds: an **admin** driving the
//! full domain/DID lifecycle as a genuine Trust Task requester, over each of
//! TSP, DIDComm and HTTPS in turn (`support::AdminClient`). One test per
//! transport runs:
//!
//! 1. `domain/create` — a domain, fanned out to the edge's own store.
//! 2. `webvh/witness/key/create` — a witness identity (always over HTTPS; the
//!    witness isn't the transport under test).
//! 3. `did/register` — a did:webvh log naming the watcher, but **not** the
//!    witness — see the comment in `run_lifecycle` on why a witnessed log can
//!    never pass `did/register`'s validation today, a bug this test found.
//! 4. `webvh/witness/sign` proves the witness's own attestation still works,
//!    against a separate, unregistered log built the same way but naming it.
//! 5. the outbox settles: the edge serves `/{mnemonic}/did.jsonl`, and the
//!    watcher mirrors the DID.
//! 6. `did/set-state` (`suspended`) over `via` — the edge refuses resolution.
//! 7. `did/delete` over `via` — the watcher no longer mirrors it.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_test_mediator::TestMediator;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::did_management::{did, domain};

use did_hosting_common::WitnessClient;
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::server::identity::{ProtocolSet, ServiceIdentity};
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES, Store,
};
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;

#[path = "support/mod.rs"]
mod support;
use support::{AdminClient, Via, build_did_log, did_key_signer, mint_https_peer, ok, wait_until};

const EDGE_HOST: &str = "edge-e2e.example";
const WATCHER_URL: &str = "https://watcher-e2e.example";
const SETTLE_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Every long-lived piece of the topology, kept alive for the test's
/// duration.
#[allow(dead_code)] // several fields exist to keep their AppState/task alive, not to be read
struct Topology {
    mediator: affinidi_messaging_test_mediator::TestMediatorHandle,
    shutdown: CancellationToken,
    control: did_hosting_control::server::AppState,
    control_did: String,
    control_https_url: String,
    edge: did_hosting_server::server::AppState,
    edge_did: String,
    edge_base: String,
    witness: webvh_witness::server::AppState,
    witness_did: String,
    witness_url: String,
    watcher: webvh_watcher::server::AppState,
    admin: AdminClient,
    admin_did: String,
    http_tasks: Vec<tokio::task::JoinHandle<()>>,
    _dirs: Vec<tempfile::TempDir>,
}

async fn reserve_port() -> (String, tokio::net::TcpListener) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral loopback port");
    let addr = listener.local_addr().expect("local addr");
    (format!("http://{addr}"), listener)
}

impl Topology {
    async fn build() -> Self {
        // `local_direct_delivery(true, false)`: the admin RPC client's TSP
        // leg (`AdminClient::call`'s `Via::Tsp` branch) is a **Direct** send
        // (`DIDCommService::send_tsp`, via `tsp_ensure_relationship`), which
        // the mediator refuses by default (`e.p.direct_delivery.denied`) —
        // anonymous senders stay off (`allow_anon: false`), since every
        // identity here is already registered with the mediator.
        let mediator = TestMediator::builder()
            .local_direct_delivery(true, false)
            .spawn()
            .await
            .expect("spawn test mediator");
        let shutdown = CancellationToken::new();
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("did resolver");
        let mut http_tasks = Vec::new();
        let mut dirs = Vec::new();

        // Mint the edge's and watcher's identities up front — both are
        // HTTPS-only `did:peer`s content-addressed over their service
        // endpoint, so the port has to be known before minting, and the
        // control plane's config needs the watcher's DID before it is built.
        let (edge_base, edge_listener) = reserve_port().await;
        let (edge_did, edge_signing) = mint_https_peer(&format!("{edge_base}/api"));
        let (watcher_base, watcher_listener) = reserve_port().await;
        let (watcher_did, watcher_signing) = mint_https_peer(&format!("{watcher_base}/api"));

        // ---- control plane: real DIDComm+TSP listener, real HTTPS listener ----
        let (control_did, control_signing, control_ka) =
            support::mint_mediator_peer(&mediator).await;
        let control_identity = ServiceIdentity::for_didcomm_test(
            &control_did,
            control_signing,
            control_ka,
            mediator.did(),
            ProtocolSet {
                didcomm: true,
                tsp: true,
            },
        )
        .await
        .expect("control identity");

        let control_dir = tempfile::tempdir().expect("temp dir");
        let control_store_config = StoreConfig {
            data_dir: PathBuf::from(control_dir.path()),
            ..StoreConfig::default()
        };
        let store = Store::open(&control_store_config)
            .await
            .expect("open control store");
        let control_config = did_hosting_control::config::AppConfig {
            features: FeaturesConfig {
                didcomm: true,
                tsp: true,
                ..FeaturesConfig::default()
            },
            server_did: Some(control_did.clone()),
            mediator_did: Some(mediator.did().to_string()),
            public_url: Some(format!("https://{EDGE_HOST}")),
            did_hosting_url: Some(format!("https://{EDGE_HOST}")),
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: control_store_config,
            fjall: Default::default(),
            auth: AuthConfig::default(),
            secrets: SecretsConfig::default(),
            vta: VtaConfig::default(),
            registry: did_hosting_control::config::RegistryConfig {
                watchers: vec![did_hosting_control::config::WatcherPeer {
                    url: WATCHER_URL.to_string(),
                    did: watcher_did.clone(),
                }],
                ..did_hosting_control::config::RegistryConfig::default()
            },
            trust_tasks: Default::default(),
            hosting: Default::default(),
            identity: Default::default(),
            config_path: PathBuf::new(),
        };
        let control = did_hosting_control::server::AppState {
            store: store.clone(),
            sessions_ks: store.keyspace(KS_SESSIONS).unwrap(),
            acl_ks: store.keyspace(KS_ACL).unwrap(),
            registry_ks: store.keyspace(KS_REGISTRY).unwrap(),
            dids_ks: store.keyspace(KS_DIDS).unwrap(),
            config: Arc::new(control_config),
            did_resolver: Some(did_resolver.clone()),
            secrets_resolver: None,
            identity: Some(control_identity),
            trust_tasks_verifier: Some(Arc::new(TransportBoundVerifier::with_did_cache(
                did_resolver.clone(),
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
            redeem_rate_limiter: Arc::new(did_hosting_control::rate_limit::SourceRateLimiter::new()),
            outbox_notify: Arc::new(tokio::sync::Notify::new()),
        };
        dirs.push(control_dir);

        let control_svc =
            did_hosting_control::server::start_didcomm_service(&control, shutdown.clone())
                .await
                .expect("start control DIDComm service")
                .expect("control has a mediator — service must start");
        control.didcomm_service.set(control_svc.clone()).ok();
        control_svc
            .wait_connected("control", CONNECT_TIMEOUT)
            .await
            .expect("control connects to the mediator");

        let (control_https_url, control_listener) = reserve_port().await;
        let control_router =
            did_hosting_control::routes::router_without_fallback().with_state(control.clone());
        http_tasks.push(tokio::spawn(async move {
            axum::serve(control_listener, control_router.into_make_service())
                .await
                .expect("control HTTPS server");
        }));

        // Register the edge as an active server instance — the prerequisite
        // for `fanout_domain_upsert` (domain/create) and `notify_servers_did`
        // (did/register, witness/publish, set-state, delete) to enqueue
        // anything for it.
        did_hosting_control::registry::register_instance(
            &control.registry_ks,
            &did_hosting_control::registry::ServiceInstance {
                instance_id: "edge-1".into(),
                service_type: did_hosting_control::registry::ServiceType::Server,
                label: Some("e2e edge".into()),
                url: edge_base.clone(),
                status: did_hosting_control::registry::ServiceStatus::Active,
                last_health_check: None,
                registered_at: 1,
                metadata: json!({ "did": edge_did }),
                enabled_methods: vec!["webvh".into()],
                served_domains: Vec::new(),
                protocol_version: "1.0".into(),
                advertised_services: None,
                services_checked_at: None,
                trust_task_capable: true,
                sync_batch_capable: false,
                last_inbound_transport: None,
                last_inbound_at: None,
                last_outbound_transport: None,
                last_outbound_at: None,
                last_ack_at: None,
                last_reconcile_at: None,
            },
        )
        .await
        .expect("register edge instance");

        // ---- edge: HTTPS-only did:peer, full public router ----
        let edge_identity = ServiceIdentity::from_signing_secret(&edge_did, edge_signing)
            .await
            .expect("edge identity");
        let edge_dir = tempfile::tempdir().expect("temp dir");
        let edge_store_config = StoreConfig {
            data_dir: PathBuf::from(edge_dir.path()),
            ..StoreConfig::default()
        };
        let edge_store = Store::open(&edge_store_config)
            .await
            .expect("open edge store");
        let edge_config = did_hosting_server::config::AppConfig {
            features: FeaturesConfig::default(),
            server_did: Some(edge_did.clone()),
            mediator_did: None,
            public_url: Some(format!("https://{EDGE_HOST}")),
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: edge_store_config,
            fjall: Default::default(),
            auth: AuthConfig::default(),
            hosting: did_hosting_common::server::config::HostingConfig::default(),
            secrets: SecretsConfig::default(),
            limits: did_hosting_server::config::LimitsConfig::default(),
            stats: did_hosting_server::config::StatsConfig::default(),
            replication: Default::default(),
            control_did: Some(control_did.clone()),
            vta: VtaConfig::default(),
            identity: Default::default(),
            config_path: PathBuf::new(),
        };
        let edge = did_hosting_server::server::AppState {
            store: edge_store.clone(),
            dids_ks: edge_store.keyspace(KS_DIDS).unwrap(),
            config: Arc::new(edge_config),
            did_resolver: Some(did_resolver.clone()),
            trust_tasks_verifier: Some(Arc::new(TransportBoundVerifier::with_did_cache(
                did_resolver.clone(),
            ))),
            secrets_resolver: None,
            identity: Some(edge_identity),
            didcomm_service: Arc::new(OnceLock::new()),
            stats_collector: None,
            did_cache: Arc::new(did_hosting_server::cache::ContentCache::new(
                Duration::from_secs(60),
            )),
            trusted_proxy_cidrs: Arc::new(Vec::new()),
            replication: Arc::new(did_hosting_server::replication::ReplicationStatus::new(
                did_hosting_common::server::auth::session::now_epoch(),
            )),
            trust_tasks_rate_limiter: Arc::new(
                did_hosting_common::server::rate_limit::IpRateLimiter::new(
                    did_hosting_common::server::rate_limit::TRUST_TASKS_RATE_LIMIT_NAME,
                    did_hosting_common::server::rate_limit::TRUST_TASKS_MAX_PER_WINDOW,
                    did_hosting_common::server::rate_limit::TRUST_TASKS_WINDOW_SECS,
                ),
            ),
            sync_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        dirs.push(edge_dir);
        let edge_router = did_hosting_server::routes::router(1024 * 1024).with_state(edge.clone());
        http_tasks.push(tokio::spawn(async move {
            axum::serve(edge_listener, edge_router.into_make_service())
                .await
                .expect("edge HTTPS server");
        }));

        // ---- witness: did:key, HTTPS only ----
        let (witness_did, witness_key) = did_key_signer(70);
        let (witness_base, witness_listener) = reserve_port().await;
        let witness_dir = tempfile::tempdir().expect("temp dir");
        let witness_store_config = StoreConfig {
            data_dir: PathBuf::from(witness_dir.path()),
            ..StoreConfig::default()
        };
        let witness_store = Store::open(&witness_store_config)
            .await
            .expect("open witness store");
        let witness_config = webvh_witness::config::AppConfig {
            features: FeaturesConfig::default(),
            server_did: Some(witness_did.clone()),
            mediator_did: None,
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: witness_store_config,
            fjall: Default::default(),
            secrets: SecretsConfig::default(),
            vta: VtaConfig::default(),
            identity: Default::default(),
            config_path: PathBuf::new(),
        };
        let witness_identity = ServiceIdentity::from_signing_secret(&witness_did, witness_key)
            .await
            .expect("witness identity");
        let mut witness = webvh_witness::server::AppState::new(
            witness_store,
            witness_config,
            Some(witness_identity),
            Arc::new(webvh_witness::signing::LocalSigner),
        )
        .expect("witness state");
        witness.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_did_cache(
            did_resolver.clone(),
        )));
        dirs.push(witness_dir);
        let witness_router = webvh_witness::routes::router().with_state(witness.clone());
        http_tasks.push(tokio::spawn(async move {
            axum::serve(witness_listener, witness_router.into_make_service())
                .await
                .expect("witness HTTPS server");
        }));

        // ---- watcher: HTTPS-only did:peer, mirrors this control plane ----
        let watcher_identity = ServiceIdentity::from_signing_secret(&watcher_did, watcher_signing)
            .await
            .expect("watcher identity");
        let watcher_dir = tempfile::tempdir().expect("temp dir");
        let watcher_store_config = StoreConfig {
            data_dir: PathBuf::from(watcher_dir.path()),
            ..StoreConfig::default()
        };
        let watcher_store = Store::open(&watcher_store_config)
            .await
            .expect("open watcher store");
        let watcher_config = webvh_watcher::config::AppConfig {
            server_did: Some(watcher_did.clone()),
            store: watcher_store_config,
            sync: webvh_watcher::config::SyncConfig {
                source_dids: vec![control_did.clone()],
            },
            ..webvh_watcher::config::AppConfig::default()
        };
        let mut watcher = webvh_watcher::server::AppState::new(
            watcher_store,
            watcher_config,
            Some(watcher_identity),
        )
        .expect("watcher state");
        watcher.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_did_cache(
            did_resolver.clone(),
        )));
        dirs.push(watcher_dir);
        let watcher_router = webvh_watcher::routes::router().with_state(watcher.clone());
        http_tasks.push(tokio::spawn(async move {
            axum::serve(watcher_listener, watcher_router.into_make_service())
                .await
                .expect("watcher HTTPS server");
        }));

        // ---- admin identity: real did:peer, ACL Admin on control ----
        let admin = AdminClient::start(&mediator, did_resolver.clone()).await;
        let admin_did = admin.did.clone();
        store_acl_entry(
            &control.acl_ks,
            &AclEntry {
                did: admin_did.clone(),
                role: Role::Admin,
                label: Some("e2e admin".into()),
                created_at: 1,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .expect("seed control ACL");

        // The DID's own update-key signer (`did_key_signer(90)`, minted again
        // identically in `run_lifecycle`) also stands as the requester for the
        // witness's HTTPS-only ops (`key/create`, `sign`) — the witness isn't
        // the transport under test, so it needs no `did:peer`/mediator
        // identity of its own; ACL Admin on the witness's own store is enough.
        let (did_signer_did, _) = did_key_signer(90);
        store_acl_entry(
            &witness.acl_ks,
            &AclEntry {
                did: did_signer_did,
                role: Role::Admin,
                label: Some("e2e did signer".into()),
                created_at: 1,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .expect("seed witness ACL");

        Self {
            mediator,
            shutdown,
            control,
            control_did,
            control_https_url,
            edge,
            edge_did,
            edge_base,
            witness,
            witness_did,
            witness_url: witness_base,
            watcher,
            admin,
            admin_did,
            http_tasks,
            _dirs: dirs,
        }
    }

    /// Run every enqueued outbox entry to completion (each target's queue
    /// empty), retrying — delivery races the test's own polling.
    async fn settle_outbox(&self) {
        wait_until(
            || async {
                did_hosting_control::outbox::run_tick(&self.control).await;
                did_hosting_control::outbox::list_targets(&self.control.store)
                    .await
                    .unwrap()
                    .is_empty()
            },
            SETTLE_TIMEOUT,
            "control's outbox drains to the edge and the watcher",
        )
        .await;
    }

    /// `GET {mnemonic}/did.jsonl` from the edge, with the `Host` header the
    /// resolve-side domain-safety check expects (`EDGE_HOST`, not the
    /// loopback address this fixture actually binds).
    async fn get_edge_log(&self, mnemonic: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{}/{mnemonic}/did.jsonl", self.edge_base))
            .header(reqwest::header::HOST, EDGE_HOST)
            .send()
            .await
            .expect("GET the edge")
    }

    async fn teardown(self) {
        for t in self.http_tasks {
            t.abort();
        }
        self.shutdown.cancel();
        self.mediator.shutdown();
        self.mediator.join().await.expect("mediator shutdown");
    }
}

/// The full lifecycle, driven over `via`: create a domain, register a
/// witnessed DID, confirm the edge serves it and the watcher mirrors it,
/// disable it and confirm the edge refuses it, then delete it.
async fn run_lifecycle(via: Via) {
    let topo = Topology::build().await;
    let mnemonic = format!("e2e-{via:?}").to_lowercase();
    let (did_signer_did, did_signer) = did_key_signer(90);

    // 1. domain/create
    let reply = topo
        .admin
        .call(
            via,
            &topo.control_did,
            &topo.control_https_url,
            domain::create::v0_1::Payload::TYPE_URI,
            json!({ "name": EDGE_HOST, "setAsDefault": false }),
        )
        .await;
    ok(&reply, domain::create::v0_1::Payload::TYPE_URI);
    topo.settle_outbox().await;

    // 2. a witness identity (always over HTTPS — the witness isn't the
    // transport under test).
    let witness_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("did resolver");
    let witness_client = WitnessClient::new(
        &topo.witness_url,
        &topo.witness_did,
        &did_signer_did,
        did_signer.clone(),
        witness_resolver,
    );
    let key = witness_client
        .create_key(Some("e2e"))
        .await
        .unwrap_or_else(|e| panic!("witness key/create: {e}"));
    let witness_key_did = key.key.did.to_string();
    let witness_id = key.key.witness_id.to_string();

    // 3. did/register — a webvh log naming the watcher. NOT naming the
    // witness: `didwebvh_rs::DIDWebVHState::validate()` enforces the witness
    // threshold unconditionally, even though
    // `did_hosting_common::did_ops::verify_did_log_proofs` (which `did/register`
    // calls with no witness content, by design — proofs are meant to arrive
    // later via `webvh/witness/publish`) documents them as deferred. A log
    // whose parameters name an active witness therefore can never pass
    // `did/register`'s validation on its own first entry, since no proof can
    // exist yet for a not-yet-published version — a chicken-and-egg refusal
    // (`did-management/did/register:invalidLog`, "Witness proof threshold (1)
    // was not met. Only (0) proofs were validated") this test tripped over
    // while writing it. See the witness-attestation check below, which proves
    // the witness's own signing operation still works correctly in isolation.
    let (jsonl, _version_id) =
        build_did_log(EDGE_HOST, &mnemonic, &did_signer, None, &[WATCHER_URL]).await;
    let reply = topo
        .admin
        .call(
            via,
            &topo.control_did,
            &topo.control_https_url,
            did::register::v0_1::Payload::TYPE_URI,
            json!({
                "path": mnemonic,
                "method": "webvh",
                "didData": jsonl,
                "domain": EDGE_HOST,
            }),
        )
        .await;
    ok(&reply, did::register::v0_1::Payload::TYPE_URI);

    // The witness's own attestation still works: sign a (separate, unregistered)
    // log built the same way but naming the witness, proving `webvh/witness/sign`
    // verifies the log and produces a threshold-meeting proof — the half of the
    // witnessed-DID story that `did/register`'s bug above blocks from ever
    // reaching the control plane.
    let (witnessed_jsonl, witnessed_version_id) = build_did_log(
        EDGE_HOST,
        &format!("{mnemonic}-witnessed"),
        &did_signer,
        Some(&witness_key_did),
        &[],
    )
    .await;
    let signed = witness_client
        .sign(&witness_id, &witnessed_version_id, &witnessed_jsonl)
        .await
        .unwrap_or_else(|e| panic!("witness sign: {e}"));
    assert_eq!(signed.version_id.to_string(), witnessed_version_id);

    // 4. the outbox settles: the edge serves the log, the watcher mirrors it.
    //
    // Each check below drives `run_tick` itself rather than settling the
    // outbox first and polling separately — `notify_servers_did` enqueues
    // from a detached `tokio::spawn`, so a `list_targets().is_empty()` check
    // run immediately after the admin call can observe "nothing queued yet"
    // and falsely conclude the outbox has already settled.
    wait_until(
        || async {
            did_hosting_control::outbox::run_tick(&topo.control).await;
            topo.get_edge_log(&mnemonic).await.status().is_success()
        },
        SETTLE_TIMEOUT,
        "the edge serves the freshly published DID",
    )
    .await;
    let served = topo
        .get_edge_log(&mnemonic)
        .await
        .text()
        .await
        .expect("body");
    assert_eq!(
        served.trim(),
        jsonl.trim(),
        "the edge serves exactly what was registered"
    );
    wait_until(
        || async {
            did_hosting_control::outbox::run_tick(&topo.control).await;
            webvh_watcher::watcher_ops::get_record(&topo.watcher.dids_ks, &mnemonic)
                .await
                .unwrap()
                .is_some()
        },
        SETTLE_TIMEOUT,
        "the watcher mirrors the DID through the outbox",
    )
    .await;
    topo.settle_outbox().await;

    // 5. did/set-state suspended — the edge refuses resolution.
    let reply = topo
        .admin
        .call(
            via,
            &topo.control_did,
            &topo.control_https_url,
            did::set_state::v0_1::Payload::TYPE_URI,
            json!({ "mnemonic": mnemonic, "state": "suspended" }),
        )
        .await;
    ok(&reply, did::set_state::v0_1::Payload::TYPE_URI);
    wait_until(
        || async {
            did_hosting_control::outbox::run_tick(&topo.control).await;
            topo.get_edge_log(&mnemonic).await.status() == reqwest::StatusCode::NOT_FOUND
        },
        SETTLE_TIMEOUT,
        "the edge refuses a disabled DID",
    )
    .await;
    topo.settle_outbox().await;

    // 6. did/delete — the watcher no longer mirrors it.
    let reply = topo
        .admin
        .call(
            via,
            &topo.control_did,
            &topo.control_https_url,
            did::delete::v0_1::Payload::TYPE_URI,
            json!({ "mnemonic": mnemonic }),
        )
        .await;
    ok(&reply, did::delete::v0_1::Payload::TYPE_URI);
    wait_until(
        || async {
            did_hosting_control::outbox::run_tick(&topo.control).await;
            webvh_watcher::watcher_ops::get_record(&topo.watcher.dids_ks, &mnemonic)
                .await
                .unwrap()
                .is_none()
        },
        SETTLE_TIMEOUT,
        "the watcher drops the deleted DID",
    )
    .await;
    topo.settle_outbox().await;

    topo.teardown().await;
}

#[tokio::test]
async fn distributed_lifecycle_over_https() {
    run_lifecycle(Via::Https).await;
}

#[tokio::test]
async fn distributed_lifecycle_over_didcomm() {
    run_lifecycle(Via::Didcomm).await;
}

#[tokio::test]
async fn distributed_lifecycle_over_tsp() {
    run_lifecycle(Via::Tsp).await;
}

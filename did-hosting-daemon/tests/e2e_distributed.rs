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
//! 3. `did/register` — a did:webvh log naming *both* the watcher and the
//!    witness. Registering a witnessed log used to be impossible (its
//!    genesis entry needs a witness proof no one could have produced yet —
//!    a bug this test found); it is registered directly now.
//! 4. `webvh/witness/sign` produces the witness's proof over that same
//!    registered version.
//! 5. `webvh/witness/publish` carries that proof to the control plane, so
//!    the sync this settles below carries a log the edge's own witness-
//!    threshold check accepts.
//! 6. the outbox settles: the edge serves `/{mnemonic}/did.jsonl`, and the
//!    watcher mirrors the DID.
//! 7. `did/set-state` (`suspended`) over `via` — the edge refuses resolution.
//! 8. `did/delete` over `via` — the watcher no longer mirrors it, and a `GET`
//!    against the edge 404s at once (no cache staleness window — a bug this
//!    test also found).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_test_mediator::TestMediator;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use did_hosting_common::tasks::did_management::{did, domain};
use did_hosting_common::tasks::webvh::witness::publish::v0_1 as witness_publish;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use trust_tasks_rs::Payload;

use did_hosting_common::WitnessClient;
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::server::identity::{ProtocolSet, ServiceIdentity};
use did_hosting_common::server::store::{KS_DIDS, Store};
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
    /// The control plane's signing and key-agreement secrets, kept so a test
    /// can stand up a successor identity for the same DID.
    control_secrets: (Secret, Secret),
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
        Self::build_with(ProtocolSet {
            didcomm: true,
            tsp: true,
        })
        .await
    }

    /// [`Self::build`], with the control plane's identity (and its
    /// `features.tsp`) carrying `control_protocols`.
    async fn build_with(control_protocols: ProtocolSet) -> Self {
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

        // The edge and watcher listen on loopback, which a peer-advertised
        // Trust Task endpoint may not name outside tests.
        did_hosting_common::server::trust_tasks::send::allow_loopback_peer_endpoints_for_tests();

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
            control_signing.clone(),
            control_ka.clone(),
            mediator.did(),
            control_protocols,
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
                tsp: control_protocols.tsp,
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
            replay: Default::default(),
            geoip: Default::default(),
            stats_flush: Default::default(),
            stats: Default::default(),
            config_path: PathBuf::new(),
        };
        let mut control = did_hosting_control::server::AppState::build(
            control_config,
            store.clone(),
            None,
            Some(control_identity),
            Default::default(),
        )
        .await
        .unwrap();
        control.did_resolver = Some(did_resolver.clone());
        control.secrets_resolver = None;
        control.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_did_cache(
            did_resolver.clone(),
        )));
        control.jwt_keys = Some(Arc::new(
            did_hosting_control::auth::jwt::JwtKeys::from_ed25519_bytes(&[7u8; 32]).unwrap(),
        ));
        control.webauthn = None;
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
            axum::serve(
                control_listener,
                control_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
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
            replay: Default::default(),
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
            gate_cache: None,
            trusted_proxy_cidrs: Arc::new(Vec::new()),
            replication: Arc::new(did_hosting_server::replication::ReplicationStatus::new(
                did_hosting_common::server::auth::session::now_epoch(),
            )),
            client_ips: Default::default(),
            trust_tasks_rate_limiter: Arc::new(
                did_hosting_common::server::rate_limit::IpRateLimiter::new(
                    did_hosting_common::server::rate_limit::TRUST_TASKS_RATE_LIMIT_NAME,
                    did_hosting_common::server::rate_limit::TRUST_TASKS_MAX_PER_WINDOW,
                    did_hosting_common::server::rate_limit::TRUST_TASKS_WINDOW_SECS,
                ),
            ),
            sync_locks: Default::default(),
            replay_cache: std::sync::Arc::new(
                did_hosting_common::server::replay::ReplayCache::new(),
            ),
        };
        dirs.push(edge_dir);
        let edge_router = did_hosting_server::routes::router(1024 * 1024).with_state(edge.clone());
        http_tasks.push(tokio::spawn(async move {
            axum::serve(
                edge_listener,
                edge_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
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
            replay: Default::default(),
            config_path: PathBuf::new(),
        };
        let witness_identity = ServiceIdentity::from_signing_secret(&witness_did, witness_key)
            .await
            .expect("witness identity");
        let mut witness = webvh_witness::server::AppState::new(
            witness_store,
            witness_config,
            Some(witness_identity),
            Arc::new(
                webvh_witness::witness_keys::WitnessKeys::generate()
                    .expect("witness key-encryption key"),
            ),
        )
        .expect("witness state");
        witness.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_did_cache(
            did_resolver.clone(),
        )));
        dirs.push(witness_dir);
        let witness_router = webvh_witness::routes::router().with_state(witness.clone());
        http_tasks.push(tokio::spawn(async move {
            axum::serve(
                witness_listener,
                witness_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
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
                sources: Vec::new(),
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
            axum::serve(
                watcher_listener,
                watcher_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
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
            control_secrets: (control_signing, control_ka),
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

    // 3. did/register — a webvh log naming *both* the watcher and the
    // witness. Registering the genesis entry of a witnessed DID directly
    // used to be impossible: `didwebvh_rs::DIDWebVHState::validate()`
    // enforces the witness threshold unconditionally, even on an entry that
    // is not published yet and so cannot have a proof — a chicken-and-egg
    // refusal (`did-management/did/register:invalidLog`, "Witness proof
    // threshold (1) was not met. Only (0) proofs were validated") this test
    // tripped over while writing it. Fixed by
    // `did_hosting_common::did_ops::verify_did_log_for_publish`: the
    // threshold is enforced only on entries already published before this
    // call, never on the new tail a register/publish is adding.
    let (jsonl, version_id) = build_did_log(
        EDGE_HOST,
        &mnemonic,
        &did_signer,
        Some(&witness_key_did),
        &[WATCHER_URL],
    )
    .await;
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

    // 4. webvh/witness/sign — the witness signs the version just registered.
    let signed = witness_client
        .sign(&witness_id, &version_id, &jsonl)
        .await
        .unwrap_or_else(|e| panic!("witness sign: {e}"));
    assert_eq!(signed.version_id.to_string(), version_id);

    // 5. webvh/witness/publish — carry that proof to the control plane, so
    // the sync below carries a log the edge's own witness-threshold check
    // (`did_hosting_common::did_ops::verify_did_log_and_witness_proofs`)
    // accepts: the genesis entry now has its threshold-meeting proof on
    // record, before the outbox ever fans it out to the edge.
    let reply = topo
        .admin
        .call(
            via,
            &topo.control_did,
            &topo.control_https_url,
            witness_publish::Payload::TYPE_URI,
            json!({
                "mnemonic": mnemonic,
                "witness": {
                    "versionId": version_id,
                    "witness": witness_key_did,
                    "proof": signed.proof,
                },
            }),
        )
        .await;
    ok(&reply, witness_publish::Payload::TYPE_URI);

    // 6. the outbox settles: the edge serves the log, the watcher mirrors it.
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

/// A control plane that boots with TSP off — its identity is DIDComm-only and
/// its DID document advertises no `TSPTransport`, so its listener carries
/// DIDComm alone — gains TSP when an identity change rebuilds the listener
/// with it on (`rebuild_own_listener`), with no restart: an admin's request
/// over TSP after the rebuild is dispatched and answered. This is the shape of
/// a rotation to a document that starts advertising `TSPTransport`; a service
/// started without a TSP handler could never dispatch it.
#[tokio::test]
async fn control_dispatches_tsp_after_a_rebuild_turns_it_on() {
    let topo = Topology::build_with(ProtocolSet {
        didcomm: true,
        tsp: false,
    })
    .await;
    let svc = topo
        .control
        .didcomm_service
        .get()
        .expect("control messaging service")
        .clone();

    // DIDComm works on the listener the control plane booted with.
    let reply = topo
        .admin
        .call(
            Via::Didcomm,
            &topo.control_did,
            &topo.control_https_url,
            domain::create::v0_1::Payload::TYPE_URI,
            json!({ "name": EDGE_HOST, "setAsDefault": false }),
        )
        .await;
    ok(&reply, domain::create::v0_1::Payload::TYPE_URI);

    // The identity now carries TSP — what a rotation to a TSP-advertising
    // document yields — and the listener is rebuilt on it, as
    // `identity_rotation::rebuild_listener` does.
    let (signing, ka) = topo.control_secrets.clone();
    let rotated = ServiceIdentity::for_didcomm_test(
        &topo.control_did,
        signing,
        ka,
        topo.mediator.did(),
        ProtocolSet {
            didcomm: true,
            tsp: true,
        },
    )
    .await
    .expect("rotated control identity");
    let transports = did_hosting_common::server::didcomm_profile::rebuild_own_listener(
        &svc,
        "control",
        &rotated,
        topo.mediator.did(),
        &topo.control.store,
    )
    .await
    .expect("rebuild the control listener");
    assert!(transports.tsp, "the rebuilt listener carries TSP");
    svc.wait_connected("control", CONNECT_TIMEOUT)
        .await
        .expect("rebuilt control listener reconnects");

    // A TSP request is now dispatched and answered.
    let reply = topo
        .admin
        .call(
            Via::Tsp,
            &topo.control_did,
            &topo.control_https_url,
            domain::list::v0_1::Payload::TYPE_URI,
            json!({}),
        )
        .await;
    ok(&reply, domain::list::v0_1::Payload::TYPE_URI);

    topo.teardown().await;
}

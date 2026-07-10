//! Control-plane infrastructure trust tasks: server registration and health
//! pong, dispatched through `trust_tasks_infra` rather than the legacy `MSG_*`
//! DIDComm routes.
//!
//! These exercise the transport-*agnostic* half of the wiring: the dispatcher
//! takes a `TrustTask<Value>` and a transport-authenticated sender, and knows
//! nothing about whether the document arrived over TSP, a DIDComm envelope, or
//! HTTPS. Getting a real frame onto a real mediator socket needs a live ATM, so
//! the transport bindings themselves are covered by unit tests on the payload
//! shapes (`server/src/tsp.rs`) and the Type-URI pairing
//! (`common/.../trust_tasks/send.rs`).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
};
use did_hosting_control::auth::jwt::JwtKeys;
use did_hosting_control::config::{AppConfig, RegistryConfig};
use did_hosting_control::server::AppState;
use serde_json::{Value, json};

struct Harness {
    state: AppState,
    _dir: tempfile::TempDir,
}

async fn make_harness() -> Harness {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let sessions_ks = store.keyspace(KS_SESSIONS).expect("sessions ks");
    let acl_ks = store.keyspace(KS_ACL).expect("acl ks");
    let registry_ks = store.keyspace(KS_REGISTRY).expect("registry ks");
    let dids_ks = store.keyspace(KS_DIDS).expect("dids ks");
    let stats_ks = store.keyspace(KS_STATS).expect("stats ks");

    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some("did:webvh:test:control.example.com".into()),
        mediator_did: None,
        public_url: Some("http://control.test".into()),
        did_hosting_url: Some("http://control.test".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(),
        registry: RegistryConfig::default(),
        trust_tasks: Default::default(),
        hosting: Default::default(),
        config_path: PathBuf::new(),
    };

    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&[7u8; 32]).expect("jwt keys"));

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        registry_ks,
        dids_ks,
        config: Arc::new(config),
        // Deliberately `None` — see the module note on `/api/config`.
        did_resolver: None,
        secrets_resolver: None,
        trust_tasks_verifier: None,
        jwt_keys: Some(jwt_keys),
        webauthn: None,
        http_client: reqwest::Client::new(),
        didcomm_service: Arc::new(OnceLock::new()),
        stats_collector: Arc::new(StatsCollector::new()),
        stats_ks: stats_ks.clone(),
        timeseries_ks: store.keyspace(KS_TIMESERIES).expect("timeseries ks"),
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

    Harness { state, _dir: dir }
}

async fn add_acl(state: &AppState, did: &str, role: Role) {
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.into(),
            role,
            label: None,
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .expect("store acl");
}

use did_hosting_common::didcomm_types::{
    MSG_HEALTH_PONG, MSG_SERVER_REGISTER, MSG_SERVER_REGISTER_ACK,
};
use did_hosting_common::server::trust_tasks::send::build_request;
use did_hosting_control::registry;
use did_hosting_control::trust_tasks_infra;

const CONTROL_DID: &str = "did:webvh:test:control.example.com";
const SERVER_DID: &str = "did:webvh:QmS:webvh.example.com:server1";

fn register_body(trust_task_capable: bool) -> Value {
    json!({
        "public_url": "https://webvh.example.com/server1",
        "label": "did-hosting-server",
        "enabled_methods": ["webvh"],
        "served_domains": [],
        "protocol_version": "1.0",
        "trust_task_capable": trust_task_capable,
    })
}

fn instance_id_for(did: &str) -> String {
    did.replace(':', "_")
}

/// A `server/register/0.1` trust task registers the instance and answers with
/// the `#response` variant of the *same* Type URI — not a separately-named ack
/// constant. That is what makes the op identical across transports.
#[tokio::test]
async fn register_trust_task_creates_instance_and_acks() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Service).await;

    let doc = build_request(
        MSG_SERVER_REGISTER,
        SERVER_DID,
        CONTROL_DID,
        register_body(true),
    )
    .expect("build register doc");
    let resp = trust_tasks_infra::dispatch(&h.state, SERVER_DID, doc)
        .await
        .expect("register must produce an ack");

    assert_eq!(
        resp["type"], MSG_SERVER_REGISTER_ACK,
        "ack must be the #response variant of the request URI; got {resp}"
    );

    let inst = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .expect("registry read")
        .expect("instance registered");
    assert_eq!(inst.url, "https://webvh.example.com/server1");
    assert!(
        inst.trust_task_capable,
        "a server that registers over a trust task declares itself capable"
    );
}

/// The capability flag is what gates the health loop away from legacy pings.
/// An older server omits it; it must default to `false` so the control plane
/// keeps speaking `MSG_HEALTH_PING` to it and never strands it Unreachable.
#[tokio::test]
async fn register_without_capability_flag_defaults_to_legacy() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Service).await;

    let mut body = register_body(false);
    body.as_object_mut().unwrap().remove("trust_task_capable");

    let doc = build_request(MSG_SERVER_REGISTER, SERVER_DID, CONTROL_DID, body).expect("build");
    trust_tasks_infra::dispatch(&h.state, SERVER_DID, doc)
        .await
        .expect("ack");

    let inst = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert!(!inst.trust_task_capable);
}

/// Registration is ACL-gated exactly as the legacy DIDComm route was: a DID
/// without the `Service` role must not be able to register, because doing so
/// triggers a full DID-log push to the caller.
#[tokio::test]
async fn register_trust_task_requires_service_role() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Owner).await; // wrong role

    let doc = build_request(
        MSG_SERVER_REGISTER,
        SERVER_DID,
        CONTROL_DID,
        register_body(true),
    )
    .expect("build");
    let resp = trust_tasks_infra::dispatch(&h.state, SERVER_DID, doc)
        .await
        .expect("rejection is still a document");

    assert_ne!(
        resp["type"], MSG_SERVER_REGISTER_ACK,
        "must not ack: {resp}"
    );
    assert!(
        registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
            .await
            .unwrap()
            .is_none(),
        "no instance may be created for an unauthorised registrant"
    );
}

/// A pong marks the instance Active and is terminal — it must not produce a
/// reply, or two control planes would ping-pong forever.
#[tokio::test]
async fn health_pong_trust_task_marks_active_and_is_terminal() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Service).await;

    let reg = build_request(
        MSG_SERVER_REGISTER,
        SERVER_DID,
        CONTROL_DID,
        register_body(true),
    )
    .expect("build");
    trust_tasks_infra::dispatch(&h.state, SERVER_DID, reg).await;

    let before = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert!(before.last_health_check.is_none(), "precondition");

    let pong = build_request(
        MSG_HEALTH_PONG,
        SERVER_DID,
        CONTROL_DID,
        json!({ "status": "ok", "version": "0.7.0", "did_count": 3 }),
    )
    .expect("MSG_HEALTH_PONG must parse as a #response TypeUri");

    let resp = trust_tasks_infra::dispatch(&h.state, SERVER_DID, pong).await;
    assert!(resp.is_none(), "a pong is an answer, not a question");

    let after = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert!(after.last_health_check.is_some());
    assert!(matches!(after.status, registry::ServiceStatus::Active));
}

/// The dispatcher must claim only its two ops. `owns` gates `dispatch`, and if
/// it over-claimed it would swallow DID-management tasks bound for the bridge.
#[test]
fn owns_only_register_and_health_pong() {
    use did_hosting_common::didcomm_types::{MSG_HEALTH_PING, MSG_SYNC_UPDATE};

    assert!(trust_tasks_infra::owns(MSG_SERVER_REGISTER));
    assert!(trust_tasks_infra::owns(MSG_HEALTH_PONG));
    // The control plane *sends* these; it must never route them to itself.
    assert!(!trust_tasks_infra::owns(MSG_HEALTH_PING));
    assert!(!trust_tasks_infra::owns(MSG_SERVER_REGISTER_ACK));
    assert!(!trust_tasks_infra::owns(MSG_SYNC_UPDATE));
}

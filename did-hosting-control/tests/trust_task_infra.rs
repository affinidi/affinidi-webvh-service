//! Control-plane infrastructure trust tasks: server registration, health
//! pong, stats sync and acks, dispatched through `messaging::infra`.
//!
//! These exercise the transport-*agnostic* half of the wiring: the dispatcher
//! takes a `TrustTask<Value>` and its proven signer, and knows
//! nothing about whether the document arrived over TSP, a DIDComm envelope, or
//! HTTPS. Getting a real frame onto a real mediator socket needs a live ATM, so
//! the transport bindings themselves are covered by unit tests on the payload
//! shapes (`did-hosting-server/src/tsp.rs`) and the Type-URI pairing
//! (`did-hosting-common/src/server/trust_tasks/send.rs`).

use std::path::PathBuf;
use std::sync::Arc;

use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::Store;
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

    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some("did:webvh:test:control.example.com".into()),
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
        replay: Default::default(),
        geoip: Default::default(),
        stats_flush: Default::default(),
        stats: Default::default(),
        config_path: PathBuf::new(),
    };

    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&[7u8; 32]).expect("jwt keys"));

    // Deliberately no resolver: the dispatcher under test needs none.
    let mut state =
        did_hosting_control::test_support::bare_state(config, store.clone(), None).await;
    state.jwt_keys = Some(jwt_keys);

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
    MSG_HEALTH_PONG, MSG_SERVER_REGISTER, MSG_SERVER_REGISTER_ACK, MSG_STATS_ACK, MSG_STATS_SYNC,
};
use did_hosting_common::server::didcomm_profile::ObservedTransport;
use did_hosting_common::server::trust_tasks::send::build_request;
use did_hosting_control::messaging::infra;
use did_hosting_control::registry;

const CONTROL_DID: &str = "did:webvh:test:control.example.com";
const SERVER_DID: &str = "did:webvh:QmS:webvh.example.com:server1";

/// A `server/register/0.2` payload from [`SERVER_DID`], with this service's
/// hints under `ext`.
fn register_body() -> Value {
    json!({
        "instanceId": instance_id_for(SERVER_DID),
        "did": SERVER_DID,
        "publicUrl": "https://webvh.example.com/server1",
        "label": "did-hosting-server",
        "enabledMethods": ["webvh"],
        "servedDomains": [],
        "protocolVersion": "1.0",
        "ext": {
            (did_hosting_common::didcomm_types::REGISTER_EXT_NAMESPACE): {
            }
        },
    })
}

fn instance_id_for(did: &str) -> String {
    did.replace(':', "_")
}

/// A `server/register/0.2` trust task registers the instance and answers with
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
        register_body(),
    )
    .expect("build register doc");
    let resp = infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Tsp), doc)
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
}

/// The `ext` hints are optional: a register that carries none still registers.
#[tokio::test]
async fn register_without_ext_hints_registers() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Service).await;

    let mut body = register_body();
    body.as_object_mut().unwrap().remove("ext");

    let doc = build_request(MSG_SERVER_REGISTER, SERVER_DID, CONTROL_DID, body).expect("build");
    infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Tsp), doc)
        .await
        .expect("ack");

    let inst = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inst.url, "https://webvh.example.com/server1");
}

/// The payload is `server/register/0.2`, closed: 0.1's snake_case members, or
/// a `did` / `instanceId` that does not name the signer, are refused as
/// malformed and register nothing.
#[tokio::test]
async fn register_refuses_a_payload_that_is_not_0_2_for_the_signer() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Service).await;

    let snake = json!({
        "public_url": "https://webvh.example.com/server1",
        "served_domains": [],
        "trust_task_capable": true,
    });
    let mut other_did = register_body();
    other_did["did"] = json!("did:webvh:QmS:webvh.example.com:server2");
    let mut other_id = register_body();
    other_id["instanceId"] = json!("someone-else");
    for body in [snake, other_did, other_id] {
        let doc = build_request(MSG_SERVER_REGISTER, SERVER_DID, CONTROL_DID, body).expect("build");
        let resp = infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Tsp), doc)
            .await
            .expect("a refusal is still a document");
        assert_eq!(resp["payload"]["code"], "malformedRequest", "{resp}");
    }
    assert!(
        registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
            .await
            .unwrap()
            .is_none()
    );
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
        register_body(),
    )
    .expect("build");
    let resp = infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Tsp), doc)
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
        register_body(),
    )
    .expect("build");
    infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Tsp), reg).await;

    let before = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert!(before.last_health_check.is_none(), "precondition");

    let pong = build_request(
        MSG_HEALTH_PONG,
        SERVER_DID,
        CONTROL_DID,
        did_hosting_common::server::trust_tasks::infra::health_pong_body(
            &instance_id_for(SERVER_DID),
            chrono::Utc::now(),
            "0.7.0",
            3,
        )
        .expect("a health response"),
    )
    .expect("MSG_HEALTH_PONG must parse as a #response TypeUri");

    let resp = infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Didcomm), pong).await;
    assert!(resp.is_none(), "a pong is an answer, not a question");

    let after = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert!(after.last_health_check.is_some());
    assert!(matches!(after.status, registry::ServiceStatus::Active));
}

/// The dispatcher must claim only its own ops. `owns` gates `dispatch`, and if
/// it over-claimed it would swallow DID-management tasks bound for the bridge.
#[test]
fn owns_only_register_health_pong_and_stats_sync() {
    use did_hosting_common::didcomm_types::{MSG_HEALTH_PING, MSG_SYNC_UPDATE};

    assert!(infra::owns(MSG_SERVER_REGISTER));
    assert!(infra::owns(MSG_HEALTH_PONG));
    assert!(infra::owns(MSG_STATS_SYNC));
    // The control plane *sends* these; it must never route them to itself.
    assert!(!infra::owns(MSG_HEALTH_PING));
    assert!(!infra::owns(MSG_SERVER_REGISTER_ACK));
    assert!(!infra::owns(MSG_STATS_ACK));
    assert!(!infra::owns(MSG_SYNC_UPDATE));
}

// Stats sync keys its replay window on a process-wide map, so each test uses
// its own server DID to stay independent of the others running alongside it.

/// A `server/stats-sync/0.1` payload in the pinned shape, as an edge sends it.
fn stats_body(server_did: &str, seq: u64, resolves: u64) -> Value {
    use did_hosting_common::server::trust_tasks::infra;
    infra::stats_sync_body(
        &infra::instance_id_for(server_did),
        seq,
        &[did_hosting_common::DidStatsDelta {
            mnemonic: "alice".into(),
            resolve_delta: resolves,
            update_delta: 0,
            last_resolved_at: Some(now_epoch()),
            last_updated_at: None,
        }],
    )
    .expect("a stats-sync payload")
}

/// The same sync in the shape edges sent before #449, which a control plane
/// still reads for one release.
fn legacy_stats_body(server_did: &str, seq: u64, resolves: u64) -> Value {
    json!({
        "server_did": server_did,
        "seq": seq,
        "did_deltas": [{
            "mnemonic": "alice",
            "resolve_delta": resolves,
            "update_delta": 0,
            "last_resolved_at": now_epoch(),
            "last_updated_at": null,
        }],
    })
}

/// A `server/stats-sync/0.1` trust task — what a server sends when the control
/// plane advertises TSP — records the deltas and answers with the `#response`
/// variant, exactly as the legacy `MSG_STATS_SYNC` DIDComm route does.
#[tokio::test]
async fn stats_sync_trust_task_records_deltas_and_acks() {
    const DID: &str = "did:webvh:QmS:webvh.example.com:stats-accept";
    let h = make_harness().await;
    add_acl(&h.state, DID, Role::Service).await;

    let doc = build_request(MSG_STATS_SYNC, DID, CONTROL_DID, stats_body(DID, 1, 5))
        .expect("MSG_STATS_SYNC must parse as a TypeUri");
    let resp = infra::dispatch(&h.state, DID, Some(ObservedTransport::Tsp), doc)
        .await
        .expect("stats sync must produce an ack");

    assert_eq!(resp["type"], MSG_STATS_ACK, "got {resp}");
    assert_eq!(resp["payload"]["accepted"], 1, "got {resp}");
    assert_eq!(h.state.stats_collector.get_aggregate().total_resolves, 5);

    // A replay of the same sequence is acked but not double-counted.
    let replay =
        build_request(MSG_STATS_SYNC, DID, CONTROL_DID, stats_body(DID, 1, 5)).expect("build");
    let resp = infra::dispatch(&h.state, DID, Some(ObservedTransport::Tsp), replay)
        .await
        .expect("ack");
    assert_eq!(resp["payload"]["accepted"], 0);
    assert_eq!(
        resp["payload"]["ext"]["vnd.affinidi.webvh"]["skipped"],
        "stale_seq"
    );
    assert_eq!(h.state.stats_collector.get_aggregate().total_resolves, 5);

    // An edge not yet upgraded past #449 is still counted (one release).
    let legacy = build_request(
        MSG_STATS_SYNC,
        DID,
        CONTROL_DID,
        legacy_stats_body(DID, 2, 3),
    )
    .expect("build");
    let resp = infra::dispatch(&h.state, DID, Some(ObservedTransport::Tsp), legacy)
        .await
        .expect("ack");
    assert_eq!(resp["type"], MSG_STATS_ACK, "got {resp}");
    assert_eq!(resp["payload"]["accepted"], 1, "got {resp}");
    assert_eq!(h.state.stats_collector.get_aggregate().total_resolves, 8);
}

/// Stats writes are ACL-gated on every transport: an Owner-role
/// DID must not be able to inflate another server's counters.
#[tokio::test]
async fn stats_sync_trust_task_requires_service_role() {
    const DID: &str = "did:webvh:QmS:webvh.example.com:stats-owner";
    let h = make_harness().await;
    add_acl(&h.state, DID, Role::Owner).await;

    let doc =
        build_request(MSG_STATS_SYNC, DID, CONTROL_DID, stats_body(DID, 1, 5)).expect("build");
    let resp = infra::dispatch(&h.state, DID, Some(ObservedTransport::Tsp), doc)
        .await
        .expect("rejection is still a document");

    assert_ne!(resp["type"], MSG_STATS_ACK, "must not ack: {resp}");
    assert_eq!(h.state.stats_collector.get_aggregate().total_resolves, 0);
}

/// `server_did` keys the replay window, so a Service may not report under
/// another server's DID — it could advance that server's sequence and have
/// its genuine deltas skipped as stale. It is bound to the
/// document's proven signer.
#[tokio::test]
async fn stats_sync_rejects_a_foreign_server_did() {
    const DID: &str = "did:webvh:QmS:webvh.example.com:stats-spoofer";
    const VICTIM: &str = "did:webvh:QmS:webvh.example.com:stats-victim";
    let h = make_harness().await;
    add_acl(&h.state, DID, Role::Service).await;

    let doc =
        build_request(MSG_STATS_SYNC, DID, CONTROL_DID, stats_body(VICTIM, 99, 5)).expect("build");
    let resp = infra::dispatch(&h.state, DID, Some(ObservedTransport::Tsp), doc)
        .await
        .expect("rejection is still a document");

    assert_ne!(resp["type"], MSG_STATS_ACK, "must not ack: {resp}");
    assert_eq!(h.state.stats_collector.get_aggregate().total_resolves, 0);
}

/// The registration that *enrols* the instance must itself be observed.
///
/// Recording inbound transport before the dispatch would find no instance to
/// write onto, so the very message that created the server would go unrecorded
/// and the card would read "unknown" until the first pong an interval later.
#[tokio::test]
async fn register_records_the_transport_it_arrived_on() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Service).await;

    let doc = build_request(
        MSG_SERVER_REGISTER,
        SERVER_DID,
        CONTROL_DID,
        register_body(),
    )
    .expect("build");
    infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Tsp), doc)
        .await
        .expect("ack");

    let inst = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inst.last_inbound_transport, Some(ObservedTransport::Tsp));
    assert!(inst.last_inbound_at.is_some());
}

/// A pong arriving over a different transport than the register updates the
/// observation — this is a *last seen*, not a first-seen, value.
#[tokio::test]
async fn pong_updates_observed_inbound_transport() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Service).await;

    let reg = build_request(
        MSG_SERVER_REGISTER,
        SERVER_DID,
        CONTROL_DID,
        register_body(),
    )
    .expect("build");
    infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Didcomm), reg).await;

    let pong = build_request(
        MSG_HEALTH_PONG,
        SERVER_DID,
        CONTROL_DID,
        // The pong edges sent before #449, still read for one release.
        json!({ "status": "ok" }),
    )
    .expect("build");
    infra::dispatch(&h.state, SERVER_DID, Some(ObservedTransport::Tsp), pong).await;

    let inst = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inst.last_inbound_transport, Some(ObservedTransport::Tsp));
}

/// An unrecognised binding records nothing rather than guessing a transport.
#[tokio::test]
async fn unknown_binding_records_no_transport() {
    let h = make_harness().await;
    add_acl(&h.state, SERVER_DID, Role::Service).await;

    let doc = build_request(
        MSG_SERVER_REGISTER,
        SERVER_DID,
        CONTROL_DID,
        register_body(),
    )
    .expect("build");
    infra::dispatch(&h.state, SERVER_DID, None, doc)
        .await
        .expect("ack");

    let inst = registry::get_instance(&h.state.registry_ks, &instance_id_for(SERVER_DID))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inst.last_inbound_transport, None);
}

/// `ObservedTransport::from_binding_uri` maps each binding crate's own exported
/// constant, so a new binding surfaces as `None` instead of being mis-attributed.
#[test]
fn binding_uris_map_to_their_transports() {
    use did_hosting_common::server::trust_tasks::transport::TSP_BINDING_URI;

    assert_eq!(
        ObservedTransport::from_binding_uri(TSP_BINDING_URI),
        Some(ObservedTransport::Tsp)
    );
    assert_eq!(
        ObservedTransport::from_binding_uri(trust_tasks_didcomm::BINDING_URI),
        Some(ObservedTransport::Didcomm)
    );
    assert_eq!(
        ObservedTransport::from_binding_uri("https://example.com/binding/x"),
        None
    );
}

//! The edge's Trust Task listener, driven through each of its three transport
//! entry points — the TSP frame handler, the DIDComm envelope handler and
//! `POST /api/trust-tasks` — with documents signed as the control plane's
//! outbox signs them.
//!
//! Covers the `did-management/replica/domain/*` directives, `webvh/sync/*`,
//! the `stalePurge` freshness rule, and the two refusals every one of these
//! tasks makes: a document that does not verify gets no signed reply, and one
//! that verifies but was signed by a DID other than the configured control
//! plane is answered `notAuthorized`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_messaging_didcomm::Message;
use affinidi_secrets_resolver::secrets::Secret;
use did_hosting_common::did::{DidDocumentOptions, build_did_document};
use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::didcomm_types::*;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::identity::ServiceIdentity;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS, Store};
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use did_hosting_common::server::trust_tasks::send::build_request;
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::server::AppState;
use serde_json::{Value, json};

/// A `did:key` signer, so proofs verify with no I/O.
fn signer(seed: u8) -> (String, Secret) {
    let secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let pk = secret.get_public_keymultibase().unwrap();
    let did = format!("did:key:{pk}");
    let mut s = secret;
    s.id = format!("{did}#{pk}");
    (did, s)
}

fn control() -> (String, Secret) {
    signer(90)
}

fn edge() -> (String, Secret) {
    signer(92)
}

/// A transport a document can arrive on.
#[derive(Debug, Clone, Copy)]
enum Via {
    Tsp,
    Didcomm,
    Https,
}

const VIAS: [Via; 3] = [Via::Tsp, Via::Didcomm, Via::Https];

/// An edge with a signing identity, configured with `control()` as its one
/// control plane.
async fn edge_state() -> (AppState, tempfile::TempDir) {
    let (control_did, _) = control();
    let (edge_did, edge_key) = edge();
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let config = AppConfig {
        features: FeaturesConfig {
            tsp: true,
            ..Default::default()
        },
        server_did: Some(edge_did.clone()),
        mediator_did: None,
        public_url: Some("https://server.example.com".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        auth: AuthConfig::default(),
        hosting: did_hosting_common::server::config::HostingConfig::default(),
        secrets: SecretsConfig::default(),
        limits: LimitsConfig::default(),
        stats: StatsConfig::default(),
        watchers: Vec::new(),
        control_url: None,
        control_did: Some(control_did),
        vta: VtaConfig::default(),
        identity: Default::default(),
        config_path: PathBuf::new(),
    };
    let state = AppState {
        store: store.clone(),
        sessions_ks: store.keyspace(KS_SESSIONS).unwrap(),
        acl_ks: store.keyspace(KS_ACL).unwrap(),
        dids_ks: store.keyspace(KS_DIDS).unwrap(),
        config: Arc::new(config),
        did_resolver: None,
        trust_tasks_verifier: Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
            DidKeyResolver,
        )))),
        secrets_resolver: None,
        identity: Some(
            ServiceIdentity::from_signing_secret(&edge_did, edge_key)
                .await
                .unwrap(),
        ),
        didcomm_service: Arc::new(std::sync::OnceLock::new()),
        jwt_keys: None,
        signing_key_bytes: None,
        http_client: reqwest::Client::new(),
        stats_collector: None,
        did_cache: Arc::new(ContentCache::new(Duration::from_secs(60))),
        trusted_proxy_cidrs: Arc::new(Vec::new()),
    };
    (state, dir)
}

/// A request from `from` to the edge, issued `age` ago, signed by `from`'s
/// key — or left unsigned.
async fn document(
    type_uri: &str,
    from: &(String, Secret),
    payload: Value,
    age: chrono::Duration,
    sign: bool,
) -> Value {
    let mut doc = build_request(type_uri, &from.0, &edge().0, payload).unwrap();
    doc.issued_at = Some(chrono::Utc::now() - age);
    let doc = if sign {
        did_hosting_common::server::trust_tasks::sign_document(&doc, &from.1)
            .await
            .unwrap()
    } else {
        doc
    };
    serde_json::to_value(doc).unwrap()
}

async fn signed(type_uri: &str, from: &(String, Secret), payload: Value) -> Value {
    document(type_uri, from, payload, chrono::Duration::zero(), true).await
}

/// Deliver `doc` to the edge over `via`, reported as coming from `sender`,
/// and return its reply — `None` when it answered nothing.
async fn deliver(state: &AppState, via: Via, sender: &str, doc: Value) -> Option<Value> {
    match via {
        Via::Tsp => did_hosting_server::tsp::run_tsp_trust_task(
            state,
            sender,
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await
        .expect("TSP entry point")
        .map(|frame| serde_json::from_slice(&frame).expect("TSP reply is JSON")),
        Via::Didcomm => {
            let message = Message::build(
                uuid::Uuid::new_v4().to_string(),
                trust_tasks_didcomm::ENVELOPE_TYPE.to_string(),
                doc,
            )
            .finalize();
            did_hosting_server::messaging::run_trust_tasks_envelope(state, Some(sender), &message)
                .await
                .map(|(typ, body)| {
                    assert_eq!(typ, trust_tasks_didcomm::ENVELOPE_TYPE);
                    body
                })
        }
        Via::Https => {
            use axum::response::IntoResponse;
            use http_body_util::BodyExt;
            let response = did_hosting_server::routes::trust_tasks::receive(
                axum::extract::State(state.clone()),
                axum::body::Bytes::from(serde_json::to_vec(&doc).unwrap()),
            )
            .await
            .into_response();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body: Value = serde_json::from_slice(&bytes).expect("HTTPS reply is JSON");
            // An unverified document is answered with an unsigned refusal,
            // which settles nothing — the equivalent of no reply.
            if status == axum::http::StatusCode::FORBIDDEN {
                assert!(body.get("proof").is_none(), "{body}");
                None
            } else {
                assert_eq!(status, axum::http::StatusCode::OK, "{body}");
                Some(body)
            }
        }
    }
}

/// The reply is the task's `#response`, signed by the edge and addressed to
/// the control plane, and its payload validates against its schema.
fn answered(reply: &Value, type_uri: &str) -> Value {
    assert_eq!(reply["type"], format!("{type_uri}#response"), "{reply}");
    signed_by_the_edge(reply);
    conforms(reply);
    reply["payload"].clone()
}

fn signed_by_the_edge(reply: &Value) {
    assert!(reply.get("proof").is_some(), "the reply is signed: {reply}");
    assert_eq!(reply["issuer"], edge().0, "{reply}");
}

fn conforms(reply: &Value) {
    let type_uri = reply["type"].as_str().expect("reply has a type");
    let schema = trust_tasks_rs::schema_index::schema_for(type_uri)
        .unwrap_or_else(|| panic!("no schema is known for {type_uri}"));
    if let Err(e) = trust_tasks_rs::validate::against_schema(schema, &reply["payload"]) {
        panic!("{type_uri} reply does not match its schema: {e:?}\n{reply}");
    }
}

/// The error code of a signed `trust-task-error` reply.
fn refused(reply: &Value) -> String {
    assert!(
        reply["type"]
            .as_str()
            .is_some_and(|t| t.contains("/trust-task-error/")),
        "expected an error, got {reply}"
    );
    signed_by_the_edge(reply);
    reply["payload"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A valid one-entry `did.jsonl` for `mnemonic` on the edge's host.
async fn valid_did_log(mnemonic: &str) -> (String, String) {
    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let pk_mb = secret.get_public_keymultibase().expect("pubkey multibase");
    let mut signing = secret.clone();
    signing.id = format!("did:key:{pk_mb}#{pk_mb}");
    let doc = build_did_document(
        "server.example.com",
        mnemonic,
        &pk_mb,
        &DidDocumentOptions::default(),
    );
    let params = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![pk_mb.clone().into()])),
        ..Default::default()
    };
    let mut state = didwebvh_rs::DIDWebVHState::default();
    state
        .create_log_entry(
            Some((chrono::Utc::now() - chrono::Duration::hours(1)).fixed_offset()),
            &doc,
            &params,
            &signing,
        )
        .await
        .expect("create webvh log entry");
    let log = state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let did_id = did_hosting_common::did_ops::extract_did_id(&log).expect("log has a DID");
    (did_id, log)
}

fn update_body(mnemonic: &str, did_id: &str, log: &str, disabled: bool) -> Value {
    json!({
        "mnemonic": mnemonic,
        "didId": did_id,
        "logContent": log,
        "versionCount": log.lines().filter(|l| !l.trim().is_empty()).count(),
        "disabled": disabled,
    })
}

async fn stored(state: &AppState, mnemonic: &str) -> Option<DidRecord> {
    state.dids_ks.get(did_key(mnemonic)).await.unwrap()
}

fn domain_entry(name: &str, status: &str) -> Value {
    let mut entry = json!({
        "name": name,
        "status": status,
        "createdAt": "2026-06-01T10:00:00Z",
        "ext": { "vnd.affinidi.webvh": { "scheme": "https", "wellKnownEnabled": false } },
    });
    if status == "disabled" {
        entry["disabledAt"] = json!("2026-09-27T09:00:00Z");
        entry["purgeAt"] = json!("2026-10-04T09:00:00Z");
    }
    entry
}

// ---------------------------------------------------------------------------
// Replication, on every transport
// ---------------------------------------------------------------------------

/// Every directive the control plane sends is applied on each transport and
/// answered with its signed, schema-conformant `#response`.
#[tokio::test]
async fn every_directive_is_served_on_every_transport() {
    use did_hosting_common::server::{assignment, domain, pending_purge};

    for via in VIAS {
        let (state, _dir) = edge_state().await;
        let cp = control();

        // replica/domain/upsert
        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_REPLICA_DOMAIN_UPSERT,
                &cp,
                json!({ "entry": domain_entry("tenant.example", "active") }),
            )
            .await,
        )
        .await
        .expect("answered");
        let body = answered(&reply, MSG_REPLICA_DOMAIN_UPSERT);
        assert_eq!(
            body,
            json!({ "name": "tenant.example", "status": "applied" })
        );
        let held = domain::get_domain(&state.store, "tenant.example")
            .await
            .unwrap()
            .expect("the entry is replicated");
        assert!(held.status.is_active(), "{via:?}");

        // replica/domain/assign
        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_REPLICA_DOMAIN_ASSIGN,
                &cp,
                json!({ "domain": "tenant.example" }),
            )
            .await,
        )
        .await
        .expect("answered");
        answered(&reply, MSG_REPLICA_DOMAIN_ASSIGN);
        assert!(
            assignment::get(&state.store, "tenant.example")
                .await
                .unwrap()
                .is_some()
        );

        // webvh/sync/update, then sync/batch, then sync/delete
        let (did_id, log) = valid_did_log("alice").await;
        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_SYNC_UPDATE,
                &cp,
                update_body("alice", &did_id, &log, false),
            )
            .await,
        )
        .await
        .expect("answered");
        assert_eq!(answered(&reply, MSG_SYNC_UPDATE)["status"], "applied");
        assert!(stored(&state, "alice").await.is_some());

        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_SYNC_BATCH,
                &cp,
                json!({ "updates": [update_body("alice", &did_id, &log, true)] }),
            )
            .await,
        )
        .await
        .expect("answered");
        answered(&reply, MSG_SYNC_BATCH);
        assert!(stored(&state, "alice").await.unwrap().disabled, "{via:?}");

        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(MSG_SYNC_DELETE, &cp, json!({ "mnemonic": "alice" })).await,
        )
        .await
        .expect("answered");
        assert_eq!(answered(&reply, MSG_SYNC_DELETE)["status"], "deleted");
        assert!(stored(&state, "alice").await.is_none());

        // replica/domain/unassign: the answer states the schedule in force.
        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_REPLICA_DOMAIN_UNASSIGN,
                &cp,
                json!({ "domain": "tenant.example" }),
            )
            .await,
        )
        .await
        .expect("answered");
        let body = answered(&reply, MSG_REPLICA_DOMAIN_UNASSIGN);
        assert_eq!(body["status"], "scheduled");
        let scheduled = pending_purge::get(&state.store, "tenant.example")
            .await
            .unwrap()
            .expect("a purge is scheduled");
        let purge_at: chrono::DateTime<chrono::Utc> =
            body["purgeAt"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            purge_at.timestamp() as u64,
            scheduled.scheduled_at + scheduled.grace_seconds
        );

        // replica/domain/purge: nothing is assigned any more, so it runs.
        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_REPLICA_DOMAIN_PURGE,
                &cp,
                json!({ "domain": "tenant.example" }),
            )
            .await,
        )
        .await
        .expect("answered");
        let body = answered(&reply, MSG_REPLICA_DOMAIN_PURGE);
        assert_eq!(body["status"], "purged");
        assert!(
            pending_purge::get(&state.store, "tenant.example")
                .await
                .unwrap()
                .is_none(),
            "the immediate purge supersedes the scheduled one"
        );
    }
}

/// A disabled domain record schedules its purge at the carried `purgeAt`;
/// re-enabling it cancels the schedule.
#[tokio::test]
async fn an_upserted_disable_schedules_the_purge_and_an_enable_cancels_it() {
    use did_hosting_common::server::pending_purge;

    let (state, _dir) = edge_state().await;
    let cp = control();
    for (status, scheduled) in [("disabled", true), ("active", false)] {
        let reply = deliver(
            &state,
            Via::Tsp,
            &cp.0,
            signed(
                MSG_REPLICA_DOMAIN_UPSERT,
                &cp,
                json!({ "entry": domain_entry("old.example", status) }),
            )
            .await,
        )
        .await
        .expect("answered");
        answered(&reply, MSG_REPLICA_DOMAIN_UPSERT);
        let purge = pending_purge::get(&state.store, "old.example")
            .await
            .unwrap();
        assert_eq!(purge.is_some(), scheduled, "{status}");
        if let Some(purge) = purge {
            let purge_at: chrono::DateTime<chrono::Utc> = "2026-10-04T09:00:00Z".parse().unwrap();
            assert_eq!(
                purge.scheduled_at + purge.grace_seconds,
                purge_at.timestamp() as u64
            );
        }
    }
}

/// A domain name the control plane did not canonicalise is refused with the
/// declared `nonCanonicalName`, and nothing is stored under either spelling.
#[tokio::test]
async fn an_upsert_with_a_non_canonical_name_is_refused() {
    let (state, _dir) = edge_state().await;
    let cp = control();
    let reply = deliver(
        &state,
        Via::Https,
        &cp.0,
        signed(
            MSG_REPLICA_DOMAIN_UPSERT,
            &cp,
            json!({ "entry": domain_entry("Tenant.Example", "active") }),
        )
        .await,
    )
    .await
    .expect("answered");
    assert_eq!(
        refused(&reply),
        "did-management/replica/domain/upsert:nonCanonicalName"
    );
    assert!(
        did_hosting_common::server::domain::get_domain(&state.store, "tenant.example")
            .await
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// stalePurge
// ---------------------------------------------------------------------------

/// A purge issued before the domain was (re-)assigned here never wipes it:
/// refused with `stalePurge`, on every transport, and the content survives.
/// A purge issued after the assignment runs.
#[tokio::test]
async fn a_purge_issued_before_the_current_assignment_is_refused() {
    for via in VIAS {
        let (state, _dir) = edge_state().await;
        let cp = control();

        // The operator unassigned the domain; the purge was queued then and
        // has waited in the outbox while the operator changed their mind.
        let stale = document(
            MSG_REPLICA_DOMAIN_PURGE,
            &cp,
            json!({ "domain": "server.example.com" }),
            chrono::Duration::seconds(60),
            true,
        )
        .await;

        // Re-assigned, and a DID synced onto it.
        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_REPLICA_DOMAIN_ASSIGN,
                &cp,
                json!({ "domain": "server.example.com" }),
            )
            .await,
        )
        .await
        .expect("answered");
        answered(&reply, MSG_REPLICA_DOMAIN_ASSIGN);
        let (did_id, log) = valid_did_log("kept").await;
        deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_SYNC_UPDATE,
                &cp,
                update_body("kept", &did_id, &log, false),
            )
            .await,
        )
        .await
        .expect("answered");
        assert!(stored(&state, "kept").await.is_some());

        let reply = deliver(&state, via, &cp.0, stale).await.expect("answered");
        assert_eq!(
            refused(&reply),
            "did-management/replica/domain/purge:stalePurge",
            "{via:?}"
        );
        assert_eq!(reply["payload"]["retryable"], false, "{reply}");
        assert!(
            stored(&state, "kept").await.is_some(),
            "nothing was deleted"
        );

        // A purge the control plane issues now is fresh, and runs.
        let reply = deliver(
            &state,
            via,
            &cp.0,
            signed(
                MSG_REPLICA_DOMAIN_PURGE,
                &cp,
                json!({ "domain": "server.example.com" }),
            )
            .await,
        )
        .await
        .expect("answered");
        assert_eq!(answered(&reply, MSG_REPLICA_DOMAIN_PURGE)["removed"], 1);
        assert!(stored(&state, "kept").await.is_none());
    }
}

// ---------------------------------------------------------------------------
// Unsigned and foreign-signer refusals
// ---------------------------------------------------------------------------

/// Every directive, on every transport: an unsigned document from the control
/// plane gets no signed reply, and one signed by any other DID is answered
/// `notAuthorized` — in both cases nothing is applied.
#[tokio::test]
async fn unsigned_and_foreign_signed_directives_are_refused() {
    let (did_id, log) = valid_did_log("mallory").await;
    let directives: Vec<(&str, Value)> = vec![
        (
            MSG_SYNC_UPDATE,
            update_body("mallory", &did_id, &log, false),
        ),
        (
            MSG_SYNC_BATCH,
            json!({ "updates": [update_body("mallory", &did_id, &log, false)] }),
        ),
        (MSG_SYNC_DELETE, json!({ "mnemonic": "mallory" })),
        (
            MSG_REPLICA_DOMAIN_UPSERT,
            json!({ "entry": domain_entry("evil.example", "active") }),
        ),
        (
            MSG_REPLICA_DOMAIN_ASSIGN,
            json!({ "domain": "evil.example" }),
        ),
        (
            MSG_REPLICA_DOMAIN_UNASSIGN,
            json!({ "domain": "evil.example" }),
        ),
        (
            MSG_REPLICA_DOMAIN_PURGE,
            json!({ "domain": "server.example.com" }),
        ),
    ];
    let slug = |type_uri: &str| {
        type_uri
            .trim_start_matches("https://trusttasks.org/spec/")
            .rsplit_once('/')
            .unwrap()
            .0
            .to_string()
    };

    for via in VIAS {
        let (state, _dir) = edge_state().await;
        let cp = control();
        let stranger = signer(66);
        for (type_uri, payload) in &directives {
            let unsigned = document(
                type_uri,
                &cp,
                payload.clone(),
                chrono::Duration::zero(),
                false,
            )
            .await;
            assert!(
                deliver(&state, via, &cp.0, unsigned).await.is_none(),
                "{via:?} {type_uri}: an unsigned directive is not answered"
            );

            let foreign = signed(type_uri, &stranger, payload.clone()).await;
            let reply = deliver(&state, via, &stranger.0, foreign)
                .await
                .unwrap_or_else(|| panic!("{via:?} {type_uri}: a foreign signer is answered"));
            assert_eq!(
                refused(&reply),
                format!("{}:notAuthorized", slug(type_uri)),
                "{via:?} {type_uri}"
            );
            assert_eq!(reply["recipient"], stranger.0, "answered to its signer");
        }
        assert!(stored(&state, "mallory").await.is_none(), "{via:?}");
        assert!(
            did_hosting_common::server::domain::get_domain(&state.store, "evil.example")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            did_hosting_common::server::assignment::get(&state.store, "evil.example")
                .await
                .unwrap()
                .is_none()
        );
    }
}

/// A document from the stranger, reported by the transport as coming from the
/// control plane, does not verify at all: it gets no reply.
#[tokio::test]
async fn a_foreign_document_reported_as_the_control_planes_is_not_answered() {
    let (state, _dir) = edge_state().await;
    let cp = control();
    let stranger = signer(66);
    for via in [Via::Tsp, Via::Didcomm] {
        let doc = signed(
            MSG_REPLICA_DOMAIN_PURGE,
            &stranger,
            json!({ "domain": "server.example.com" }),
        )
        .await;
        assert!(deliver(&state, via, &cp.0, doc).await.is_none(), "{via:?}");
    }
}

/// The other ways a directive fails to verify — addressed to another server,
/// stale, a replay of one already applied — get no reply on any transport,
/// and a reply that is sent is threaded to the directive it answers.
#[tokio::test]
async fn misaddressed_stale_and_replayed_directives_are_not_answered() {
    for via in VIAS {
        let (state, _dir) = edge_state().await;
        let cp = control();
        let payload = json!({ "domain": "kept.example" });

        let mut misaddressed = build_request(
            MSG_REPLICA_DOMAIN_ASSIGN,
            &cp.0,
            &signer(67).0,
            payload.clone(),
        )
        .unwrap();
        misaddressed.issued_at = Some(chrono::Utc::now());
        let misaddressed =
            did_hosting_common::server::trust_tasks::sign_document(&misaddressed, &cp.1)
                .await
                .unwrap();
        assert!(
            deliver(
                &state,
                via,
                &cp.0,
                serde_json::to_value(misaddressed).unwrap()
            )
            .await
            .is_none(),
            "{via:?}: a directive addressed to another server is not answered"
        );

        let stale = document(
            MSG_REPLICA_DOMAIN_ASSIGN,
            &cp,
            payload.clone(),
            chrono::Duration::days(1),
            true,
        )
        .await;
        assert!(
            deliver(&state, via, &cp.0, stale).await.is_none(),
            "{via:?}: a stale directive is not answered"
        );
        assert!(
            did_hosting_common::server::assignment::get(&state.store, "kept.example")
                .await
                .unwrap()
                .is_none(),
            "{via:?}: neither was applied"
        );

        let fresh = signed(MSG_REPLICA_DOMAIN_ASSIGN, &cp, payload.clone()).await;
        let reply = deliver(&state, via, &cp.0, fresh.clone())
            .await
            .expect("answered");
        answered(&reply, MSG_REPLICA_DOMAIN_ASSIGN);
        assert_eq!(reply["threadId"], fresh["id"], "{via:?}: threaded");
        assert_eq!(reply["recipient"], cp.0, "{via:?}");
        assert!(
            deliver(&state, via, &cp.0, fresh).await.is_none(),
            "{via:?}: a replay is not answered"
        );
    }
}

/// A health ping is answered to the control plane only: a stranger's gets no
/// reply at all, not even a refusal.
#[tokio::test]
async fn a_strangers_health_ping_is_not_answered() {
    for via in VIAS {
        let (state, _dir) = edge_state().await;
        let stranger = signer(68);
        let ping = signed(MSG_HEALTH_PING, &stranger, json!({})).await;
        assert!(
            deliver(&state, via, &stranger.0, ping).await.is_none(),
            "{via:?}"
        );
        let ping = signed(MSG_HEALTH_PING, &control(), json!({})).await;
        let reply = deliver(&state, via, &control().0, ping.clone())
            .await
            .unwrap_or_else(|| panic!("{via:?}: the control plane's ping is answered"));
        signed_by_the_edge(&reply);
        assert_eq!(reply["threadId"], ping["id"], "{via:?}");
    }
}

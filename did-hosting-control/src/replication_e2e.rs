//! Distributed mode, end to end and in process: a control plane and a hosting
//! server (edge) wired together through each transport's real entry points.
//!
//! The control plane queues directives exactly as its admin paths do
//! (`server_push`), signs each one at delivery time exactly as the outbox
//! worker does (`outbox::signed_document`), and the document is handed to the
//! edge's TSP frame handler, DIDComm envelope handler or `POST
//! /api/trust-tasks`. The edge's signed reply goes back into the control
//! plane's entry point for the same transport, which settles the outbox entry.
//! Only the mediator hop is left out — both ends of it are the code under
//! test, and the frames that cross it are the ones built here.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_messaging_didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::{Value, json};

use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
use did_hosting_common::didcomm_types::*;
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::identity::ServiceIdentity;
use did_hosting_common::server::store::{KS_DIDS, Store};
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;

use crate::control_tasks::harness::{self, VIAS, Via};
use crate::server::AppState;

/// A control plane and one edge that trust each other.
struct Fleet {
    control: AppState,
    control_did: String,
    edge: did_hosting_server::server::AppState,
    edge_did: String,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

async fn fleet() -> Fleet {
    let (control_did, control_key) = crate::signing::test_util::did_key_signer(&[90; 32]);
    let (edge_did, edge_key) = crate::signing::test_util::did_key_signer(&[92; 32]);

    // The control plane signs as a `did:key`, so the edge verifies it with no
    // resolution I/O.
    let (mut control, control_dir) = harness::state().await;
    let mut config = (*control.config).clone();
    config.server_did = Some(control_did.clone());
    control.config = Arc::new(config);
    control.identity = Some(
        ServiceIdentity::from_signing_secret(&control_did, control_key)
            .await
            .unwrap(),
    );
    // The edge is a registered Service, as `server/register` leaves it.
    store_acl_entry(
        &control.acl_ks,
        &AclEntry {
            did: edge_did.clone(),
            role: Role::Service,
            label: Some("edge".into()),
            created_at: 1,
            max_total_size: None,
            max_did_count: None,
            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .unwrap();

    let (edge, edge_dir) = edge_state(&edge_did, edge_key, &control_did).await;
    Fleet {
        control,
        control_did,
        edge,
        edge_did,
        _dirs: (control_dir, edge_dir),
    }
}

async fn edge_state(
    edge_did: &str,
    edge_key: Secret,
    control_did: &str,
) -> (did_hosting_server::server::AppState, tempfile::TempDir) {
    use did_hosting_common::server::config::{
        AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, VtaConfig,
    };
    use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};

    let dir = tempfile::tempdir().unwrap();
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.unwrap();
    let config = AppConfig {
        features: FeaturesConfig {
            tsp: true,
            ..Default::default()
        },
        server_did: Some(edge_did.into()),
        mediator_did: None,
        public_url: Some("https://edge.example.com".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        auth: AuthConfig::default(),
        hosting: Default::default(),
        secrets: SecretsConfig::default(),
        limits: LimitsConfig::default(),
        replication: Default::default(),
        stats: StatsConfig::default(),
        control_did: Some(control_did.into()),
        vta: VtaConfig::default(),
        identity: Default::default(),
        config_path: PathBuf::new(),
    };
    let state = did_hosting_server::server::AppState {
        store: store.clone(),
        dids_ks: store.keyspace(KS_DIDS).unwrap(),
        config: Arc::new(config),
        did_resolver: None,
        trust_tasks_verifier: Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
            DidKeyResolver,
        )))),
        secrets_resolver: None,
        identity: Some(
            ServiceIdentity::from_signing_secret(edge_did, edge_key)
                .await
                .unwrap(),
        ),
        didcomm_service: Arc::new(std::sync::OnceLock::new()),
        stats_collector: None,
        did_cache: Arc::new(did_hosting_server::cache::ContentCache::new(
            Duration::from_secs(60),
        )),
        trusted_proxy_cidrs: Arc::new(Vec::new()),
        replication: Arc::new(did_hosting_server::replication::ReplicationStatus::new(
            did_hosting_common::server::auth::session::now_epoch(),
        )),
    };
    (state, dir)
}

impl Fleet {
    async fn queued(&self) -> Vec<(String, Value)> {
        crate::outbox::list_pending_for_target(&self.control.store, &self.edge_did)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, e)| (e.msg_type, e.body))
            .collect()
    }

    /// Deliver the head of the edge's outbox over `via` — signed at send time,
    /// recorded as awaiting its ack — and hand the edge's reply back to the
    /// control plane over the same transport. Returns the edge's reply.
    async fn pump(&self, via: Via) -> Value {
        let (key, entry) =
            crate::outbox::list_pending_for_target(&self.control.store, &self.edge_did)
                .await
                .unwrap()
                .into_iter()
                .next()
                .expect("an entry is queued");
        let signer =
            crate::signing::control_signing_secret(&self.control, &self.control_did).unwrap();
        let doc = crate::outbox::signed_document(&self.control_did, &entry, &signer)
            .await
            .unwrap();
        crate::outbox::record_sent(&self.control.store, key, &entry, &doc.id)
            .await
            .unwrap();
        let doc = serde_json::to_value(&doc).unwrap();

        let reply = self.to_edge(via, doc).await.expect("the edge answers");
        self.to_control(via, reply.clone()).await;
        reply
    }

    async fn to_edge(&self, via: Via, doc: Value) -> Option<Value> {
        match via {
            Via::Tsp => did_hosting_server::tsp::run_tsp_trust_task(
                &self.edge,
                &self.control_did,
                &serde_json::to_vec(&doc).unwrap(),
            )
            .await
            .unwrap()
            .map(|frame| serde_json::from_slice(&frame).unwrap()),
            Via::Didcomm => did_hosting_server::messaging::run_trust_tasks_envelope(
                &self.edge,
                Some(&self.control_did),
                &envelope(doc),
            )
            .await
            .map(|(_, body)| body),
            Via::Https => {
                use axum::response::IntoResponse;
                use http_body_util::BodyExt;
                let response = did_hosting_server::routes::trust_tasks::receive(
                    axum::extract::State(self.edge.clone()),
                    axum::body::Bytes::from(serde_json::to_vec(&doc).unwrap()),
                )
                .await
                .into_response();
                let ok = response.status().is_success();
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                ok.then(|| serde_json::from_slice(&bytes).unwrap())
            }
        }
    }

    /// The edge's reply, arriving at the control plane. Acknowledgements are
    /// terminal: nothing is answered.
    async fn to_control(&self, via: Via, reply: Value) {
        match via {
            Via::Tsp => {
                crate::tsp::run_tsp_trust_task(
                    &self.control,
                    &self.edge_did,
                    &serde_json::to_vec(&reply).unwrap(),
                )
                .await
                .unwrap();
            }
            Via::Didcomm => {
                crate::messaging::run_trust_tasks_envelope(
                    &self.control,
                    &self.edge_did,
                    &envelope(reply),
                )
                .await
                .unwrap();
            }
            Via::Https => {
                use axum::response::IntoResponse;
                let _ = crate::routes::trust_tasks::dispatch_trust_task(
                    None,
                    axum::extract::State(self.control.clone()),
                    axum::body::Bytes::from(serde_json::to_vec(&reply).unwrap()),
                )
                .await
                .into_response();
            }
        }
    }
}

fn envelope(doc: Value) -> Message {
    Message::build(
        uuid::Uuid::new_v4().to_string(),
        trust_tasks_didcomm::ENVELOPE_TYPE.to_string(),
        doc,
    )
    .finalize()
}

/// A one-entry `did.jsonl` on the edge's host, published at the control plane.
async fn publish(control: &AppState, mnemonic: &str) -> DidRecord {
    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let mut signing = secret.clone();
    signing.id = format!("did:key:{pk_mb}#{pk_mb}");
    let doc = did_hosting_common::did::build_did_document(
        "edge.example.com",
        mnemonic,
        &pk_mb,
        &did_hosting_common::did::DidDocumentOptions::default(),
    );
    let params = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![pk_mb.clone().into()])),
        ..Default::default()
    };
    let mut webvh = didwebvh_rs::DIDWebVHState::default();
    webvh
        .create_log_entry(
            Some((chrono::Utc::now() - chrono::Duration::hours(1)).fixed_offset()),
            &doc,
            &params,
            &signing,
        )
        .await
        .unwrap();
    let log = webvh
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let mut record = harness::seed_did(control, "did:key:owner", mnemonic).await;
    record.did_id = did_hosting_common::did_ops::extract_did_id(&log);
    record.version_count = 1;
    control
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .unwrap();
    control
        .dids_ks
        .insert_raw(content_log_key(mnemonic), log.into_bytes())
        .await
        .unwrap();
    record
}

async fn queue_sync(fleet: &Fleet, record: &DidRecord) {
    let log = String::from_utf8(
        fleet
            .control
            .dids_ks
            .get_raw(content_log_key(&record.mnemonic))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let body = crate::server_push::sync_update_body(record, log, None).unwrap();
    crate::outbox::enqueue(&fleet.control.store, &fleet.edge_did, MSG_SYNC_UPDATE, body)
        .await
        .unwrap();
}

/// The whole lifecycle, on each transport: a domain is replicated and
/// assigned, a DID is synced onto it, disabled, deleted, the domain unassigned
/// and purged — each directive applied on the edge, answered with a signed
/// `#response`, and settled in the control plane's outbox by that answer.
#[tokio::test]
async fn directives_replicate_and_settle_on_every_transport() {
    use did_hosting_common::server::{assignment, domain, pending_purge};

    for via in VIAS {
        let f = fleet().await;
        let entry = domain::DomainEntry {
            name: "edge.example.com".into(),
            label: None,
            scheme: domain::DomainUrlScheme::Https,
            status: domain::DomainStatus::Active,
            created_at: 1_700_000_000,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        };

        crate::server_push::send_domain_upsert(&f.control, &f.edge_did, &entry)
            .await
            .unwrap();
        let reply = f.pump(via).await;
        assert_eq!(
            reply["type"], MSG_REPLICA_DOMAIN_UPSERT_ACK,
            "{via:?} {reply}"
        );
        assert_eq!(
            domain::get_domain(&f.edge.store, "edge.example.com")
                .await
                .unwrap()
                .as_ref(),
            Some(&entry),
            "{via:?}: the edge holds the control plane's record, host settings included"
        );

        crate::server_push::send_domain_assign(&f.control, &f.edge_did, "edge.example.com")
            .await
            .unwrap();
        let reply = f.pump(via).await;
        assert_eq!(
            reply["type"], MSG_REPLICA_DOMAIN_ASSIGN_ACK,
            "{via:?} {reply}"
        );
        assert!(
            assignment::get(&f.edge.store, "edge.example.com")
                .await
                .unwrap()
                .is_some()
        );

        let mut record = publish(&f.control, "alice").await;
        queue_sync(&f, &record).await;
        let reply = f.pump(via).await;
        assert_eq!(reply["type"], MSG_SYNC_UPDATE_ACK, "{via:?} {reply}");
        let held: DidRecord = f.edge.dids_ks.get(did_key("alice")).await.unwrap().unwrap();
        assert!(!held.disabled);

        // The disabled flag travels with the content.
        record.disabled = true;
        f.control
            .dids_ks
            .insert(did_key("alice"), &record)
            .await
            .unwrap();
        queue_sync(&f, &record).await;
        f.pump(via).await;
        let held: DidRecord = f.edge.dids_ks.get(did_key("alice")).await.unwrap().unwrap();
        assert!(held.disabled, "{via:?}: the disable reached the edge");

        crate::outbox::enqueue(
            &f.control.store,
            &f.edge_did,
            MSG_SYNC_DELETE,
            json!({ "mnemonic": "alice" }),
        )
        .await
        .unwrap();
        let reply = f.pump(via).await;
        assert_eq!(reply["payload"]["status"], "deleted", "{via:?} {reply}");

        crate::server_push::send_domain_unassign(&f.control, &f.edge_did, "edge.example.com")
            .await
            .unwrap();
        let reply = f.pump(via).await;
        assert_eq!(reply["payload"]["status"], "scheduled", "{via:?} {reply}");
        assert!(
            pending_purge::get(&f.edge.store, "edge.example.com")
                .await
                .unwrap()
                .is_some()
        );

        crate::server_push::send_domain_purge(&f.control, &f.edge_did, "edge.example.com")
            .await
            .unwrap();
        let reply = f.pump(via).await;
        assert_eq!(reply["payload"]["status"], "purged", "{via:?} {reply}");

        assert!(
            f.queued().await.is_empty(),
            "{via:?}: every directive was settled by the edge's signed answer"
        );
        let intents = crate::server_push::domain_intents(&f.control, &f.edge_did)
            .await
            .unwrap();
        assert!(
            intents
                .iter()
                .all(|i| i.op == crate::server_push::DomainOp::Assign),
            "{via:?}: the acknowledged unassign and purge are settled: {intents:?}"
        );
    }
}

/// An operator unassigns a domain and orders it purged while the edge is
/// unreachable, then changes their mind and re-assigns it. The re-assign drops
/// the queued purge (which, signed afresh at delivery, would otherwise pass the
/// edge's freshness check); the edge keeps the content.
#[tokio::test]
async fn a_reassign_drops_the_queued_purge() {
    let f = fleet().await;
    let domain = "edge.example.com";
    crate::server_push::send_domain_unassign(&f.control, &f.edge_did, domain)
        .await
        .unwrap();
    crate::server_push::send_domain_purge(&f.control, &f.edge_did, domain)
        .await
        .unwrap();
    crate::server_push::send_domain_assign(&f.control, &f.edge_did, domain)
        .await
        .unwrap();
    let queued: Vec<String> = f.queued().await.into_iter().map(|(t, _)| t).collect();
    assert_eq!(
        queued,
        vec![
            MSG_REPLICA_DOMAIN_UNASSIGN.to_string(),
            MSG_REPLICA_DOMAIN_ASSIGN.to_string()
        ]
    );
}

/// A purge signed before the edge's current assignment — one the control
/// plane had already put on the wire when the operator re-assigned — is
/// refused `stalePurge`; the refusal is signed and final, so it settles the
/// entry instead of being retried.
#[tokio::test]
async fn a_stale_purge_is_refused_and_settled() {
    for via in VIAS {
        let f = fleet().await;
        crate::server_push::send_domain_purge(&f.control, &f.edge_did, "edge.example.com")
            .await
            .unwrap();
        let (key, entry) = crate::outbox::list_pending_for_target(&f.control.store, &f.edge_did)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        // Signed a minute ago, and delayed in transit.
        let signer = crate::signing::control_signing_secret(&f.control, &f.control_did).unwrap();
        let mut doc = did_hosting_common::server::trust_tasks::send::build_request(
            &entry.msg_type,
            &f.control_did,
            &f.edge_did,
            entry.body.clone(),
        )
        .unwrap();
        doc.issued_at = Some(chrono::Utc::now() - chrono::Duration::seconds(60));
        let doc = did_hosting_common::server::trust_tasks::sign_document(&doc, &signer)
            .await
            .unwrap();
        crate::outbox::record_sent(&f.control.store, key, &entry, &doc.id)
            .await
            .unwrap();

        // Meanwhile the edge was assigned the domain.
        did_hosting_common::server::assignment::record_assignment(
            &f.edge.store,
            "edge.example.com",
            &f.control_did,
            did_hosting_common::server::auth::session::now_epoch(),
        )
        .await
        .unwrap();

        let reply = f
            .to_edge(via, serde_json::to_value(&doc).unwrap())
            .await
            .expect("answered");
        assert_eq!(
            reply["payload"]["code"], "did-management/replica/domain/purge:stalePurge",
            "{via:?} {reply}"
        );
        f.to_control(via, reply).await;
        assert!(
            f.queued().await.is_empty(),
            "{via:?}: the signed, final refusal settles the entry"
        );
    }
}

// ---------------------------------------------------------------------------
// The staleness bound
// ---------------------------------------------------------------------------

impl Fleet {
    /// Register the edge as a hosting server, as `server/register` leaves it.
    async fn register_edge(&self) {
        let instance: crate::registry::ServiceInstance = serde_json::from_value(json!({
            "instanceId": self.edge_did.replace(':', "_"),
            "serviceType": "server",
            "url": "https://edge.example.com",
            "status": "active",
            "registeredAt": 1,
            "metadata": { "did": self.edge_did },
        }))
        .unwrap();
        crate::registry::register_instance(&self.control.registry_ks, &instance)
            .await
            .unwrap();
    }

    /// A request from the edge, answered by the control plane over `via`.
    async fn ask_control(
        &self,
        via: Via,
        doc: trust_tasks_rs::TrustTask<Value>,
    ) -> Result<trust_tasks_rs::TrustTask<Value>, String> {
        let doc = serde_json::to_value(&doc).unwrap();
        let reply: Value = match via {
            Via::Tsp => serde_json::from_slice(
                &crate::tsp::run_tsp_trust_task(
                    &self.control,
                    &self.edge_did,
                    &serde_json::to_vec(&doc).unwrap(),
                )
                .await
                .unwrap()
                .expect("answered"),
            )
            .unwrap(),
            Via::Didcomm => {
                crate::messaging::run_trust_tasks_envelope(
                    &self.control,
                    &self.edge_did,
                    &envelope(doc),
                )
                .await
                .unwrap()
                .expect("answered")
                .1
            }
            Via::Https => harness::https(&self.control, None, doc).await,
        };
        serde_json::from_value(reply).map_err(|e| e.to_string())
    }
}

/// A disable whose push was lost is repaired by the edge's next reconcile
/// against `did/list`, on each transport. A publish that was lost leaves the
/// reconcile unclean — the edge re-registers for it — and the control plane
/// records when the edge last reconciled.
#[tokio::test]
async fn reconcile_repairs_a_missed_disable_on_every_transport() {
    for via in VIAS {
        let f = fleet().await;
        f.register_edge().await;
        did_hosting_common::server::assignment::record_assignment(
            &f.edge.store,
            "edge.example.com",
            &f.control_did,
            1,
        )
        .await
        .unwrap();

        let mut record = publish(&f.control, "alice").await;
        queue_sync(&f, &record).await;
        f.pump(via).await;

        // Disabled at the control plane; the push never arrives.
        record.disabled = true;
        f.control
            .dids_ks
            .insert(did_key("alice"), &record)
            .await
            .unwrap();
        let held: DidRecord = f.edge.dids_ks.get(did_key("alice")).await.unwrap().unwrap();
        assert!(!held.disabled, "the edge missed it");

        let report =
            did_hosting_server::replication::reconcile_once(&f.edge, |doc| f.ask_control(via, doc))
                .await
                .unwrap_or_else(|e| panic!("{via:?}: {e}"));
        assert_eq!(report.repaired, vec!["alice".to_string()], "{via:?}");
        assert!(report.is_clean(), "{via:?}: {report:?}");
        let held: DidRecord = f.edge.dids_ks.get(did_key("alice")).await.unwrap().unwrap();
        assert!(held.disabled, "{via:?}: the reconcile repaired the disable");
        assert!(f.edge.replication.last_reconciled_at().is_some());
        let instance =
            crate::registry::get_instance(&f.control.registry_ks, &f.edge_did.replace(':', "_"))
                .await
                .unwrap()
                .unwrap();
        assert!(instance.last_reconcile_at.is_some(), "{via:?}");

        // A publish the edge never received cannot be repaired from a
        // listing: the reconcile is not clean, and the freshness mark stays.
        f.edge.replication.set_last_reconciled_at(1);
        publish(&f.control, "bob").await;
        let report =
            did_hosting_server::replication::reconcile_once(&f.edge, |doc| f.ask_control(via, doc))
                .await
                .unwrap();
        assert_eq!(report.behind, vec!["bob".to_string()], "{via:?}");
        assert!(!report.is_clean());
        assert_eq!(f.edge.replication.last_reconciled_at(), Some(1));
    }
}

/// A DID that is not a registered hosting server — here, one with the Service
/// role but no server registration — sees only its own slots, so the listing
/// is no wider than what the control plane already sends that edge.
#[tokio::test]
async fn only_a_registered_server_is_given_the_full_listing() {
    let f = fleet().await;
    publish(&f.control, "alice").await;
    let request = did_hosting_server::replication::list_request(&f.edge, 0)
        .await
        .unwrap();
    let reply = f.ask_control(Via::Https, request).await.unwrap();
    assert_eq!(reply.payload["total"], 0, "{reply:?}");

    f.register_edge().await;
    let request = did_hosting_server::replication::list_request(&f.edge, 0)
        .await
        .unwrap();
    let reply = f.ask_control(Via::Https, request).await.unwrap();
    assert_eq!(reply.payload["total"], 1, "{reply:?}");
}

/// Per-edge replication lag reaches `server/metrics/0.1`: the queued
/// directives and the age of the oldest.
#[tokio::test]
async fn control_metrics_expose_per_edge_replication_lag() {
    let f = fleet().await;
    f.register_edge().await;
    crate::server_push::send_domain_assign(&f.control, &f.edge_did, "edge.example.com")
        .await
        .unwrap();
    let admin = harness::member(&f.control, 7, Role::Admin).await;
    for via in VIAS {
        let mut doc = harness::request(
            "https://trusttasks.org/spec/did-management/server/metrics/0.1",
            &admin.did,
            json!({}),
        );
        doc["recipient"] = json!(f.control_did);
        let doc = harness::signed(doc, &admin.key).await;
        let reply = harness::send(&f.control, via, &admin, doc).await;
        harness::conforms(&reply);
        let gauges = reply["payload"]["snapshot"]["gauges"].as_array().unwrap();
        let find = |name: &str| {
            gauges
                .iter()
                .find(|g| g["name"] == name && g["labels"]["edge"] == f.edge_did.as_str())
                .unwrap_or_else(|| panic!("{via:?}: no {name} for the edge: {reply}"))
        };
        assert_eq!(
            find("did_hosting_replication_pending")["value"].as_f64(),
            Some(1.0)
        );
        assert!(find("did_hosting_replication_lag_seconds")["value"].is_number());
    }
}

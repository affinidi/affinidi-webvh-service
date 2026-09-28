//! The control plane fanning a DID out to the watchers its log names, in
//! process and on each transport.
//!
//! A publish queues `webvh/sync/update/0.2` in the outbox for each watcher the
//! log's `watchers` parameter names and `registry.watchers` maps to a DID;
//! each entry is signed at delivery exactly as the outbox worker signs it and
//! handed to the watcher's TSP frame handler, DIDComm envelope handler or
//! `POST /api/trust-tasks`. The watcher's signed reply goes back into the
//! control plane's entry point for the same transport and settles the entry —
//! the same delivery and acknowledgement machinery edges use.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_messaging_didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::{Value, json};

use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
use did_hosting_common::didcomm_types::*;
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::identity::ServiceIdentity;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;

use crate::config::WatcherPeer;
use crate::control_tasks::harness::{self, VIAS, Via};
use crate::server::AppState;

const WATCHER_URL: &str = "https://watcher.example.com";

struct Pair {
    control: AppState,
    control_did: String,
    watcher: webvh_watcher::server::AppState,
    watcher_did: String,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

async fn pair() -> Pair {
    let (control_did, control_key) = crate::signing::test_util::did_key_signer(&[90; 32]);
    let (watcher_did, watcher_key) = crate::signing::test_util::did_key_signer(&[93; 32]);

    let (mut control, control_dir) = harness::state().await;
    let mut config = (*control.config).clone();
    config.server_did = Some(control_did.clone());
    // No ACL entry for the watcher: the map is its only standing here.
    config.registry.watchers = vec![WatcherPeer {
        url: format!("{WATCHER_URL}/"),
        did: watcher_did.clone(),
    }];
    control.config = Arc::new(config);
    control.identity = Some(
        ServiceIdentity::from_signing_secret(&control_did, control_key)
            .await
            .unwrap(),
    );

    let dir = tempfile::tempdir().unwrap();
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.unwrap();
    let watcher_config = webvh_watcher::config::AppConfig {
        server_did: Some(watcher_did.clone()),
        store: store_config,
        sync: webvh_watcher::config::SyncConfig {
            source_dids: vec![control_did.clone()],
        },
        ..Default::default()
    };
    let mut watcher = webvh_watcher::server::AppState::new(
        store,
        watcher_config,
        Some(
            ServiceIdentity::from_signing_secret(&watcher_did, watcher_key)
                .await
                .unwrap(),
        ),
    )
    .unwrap();
    watcher.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
        DidKeyResolver,
    ))));

    Pair {
        control,
        control_did,
        watcher,
        watcher_did,
        _dirs: (control_dir, dir),
    }
}

impl Pair {
    async fn queued(&self) -> Vec<(String, Value)> {
        crate::outbox::list_pending_for_target(&self.control.store, &self.watcher_did)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, e)| (e.msg_type, e.body))
            .collect()
    }

    /// Wait for the spawned fan-out to queue `n` entries for the watcher.
    async fn wait_for(&self, n: usize) {
        for _ in 0..200 {
            if self.queued().await.len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("nothing was queued for the watcher");
    }

    /// Deliver the head of the watcher's queue over `via` and hand the reply
    /// back to the control plane on the same transport.
    async fn pump(&self, via: Via) -> Value {
        let (key, entry) =
            crate::outbox::list_pending_for_target(&self.control.store, &self.watcher_did)
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
        let reply = match via {
            Via::Tsp => webvh_watcher::tsp::run_tsp_trust_task(
                &self.watcher,
                &self.control_did,
                &serde_json::to_vec(&doc).unwrap(),
            )
            .await
            .unwrap()
            .map(|frame| serde_json::from_slice(&frame).unwrap()),
            Via::Didcomm => webvh_watcher::messaging::run_trust_tasks_envelope(
                &self.watcher,
                Some(&self.control_did),
                &envelope(doc),
            )
            .await
            .map(|(_, body)| body),
            Via::Https => {
                use axum::response::IntoResponse;
                use http_body_util::BodyExt;
                let response = webvh_watcher::routes::trust_tasks::receive(
                    axum::extract::State(self.watcher.clone()),
                    axum::body::Bytes::from(serde_json::to_vec(&doc).unwrap()),
                )
                .await
                .into_response();
                let ok = response.status().is_success();
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                ok.then(|| serde_json::from_slice(&bytes).unwrap())
            }
        }
        .expect("the watcher answers");

        match via {
            Via::Tsp => {
                crate::tsp::run_tsp_trust_task(
                    &self.control,
                    &self.watcher_did,
                    &serde_json::to_vec(&reply).unwrap(),
                )
                .await
                .unwrap();
            }
            Via::Didcomm => {
                crate::messaging::run_trust_tasks_envelope(
                    &self.control,
                    &self.watcher_did,
                    &envelope(reply.clone()),
                )
                .await
                .unwrap();
            }
            // Over HTTPS the reply *is* the acknowledgement: the outbox worker
            // settles the entry once `send_trust_task` has verified it, as it
            // does for an edge.
            Via::Https => {
                assert!(
                    crate::outbox::acknowledge(
                        &self.control.store,
                        &self.watcher_did,
                        &doc_id(&reply)
                    )
                    .await
                    .unwrap()
                );
            }
        }
        reply
    }
}

fn doc_id(reply: &Value) -> String {
    reply["threadId"].as_str().unwrap().to_string()
}

fn envelope(doc: Value) -> Message {
    Message::build(
        uuid::Uuid::new_v4().to_string(),
        trust_tasks_didcomm::ENVELOPE_TYPE.to_string(),
        doc,
    )
    .finalize()
}

/// A one-entry log for `mnemonic` on `origin.example.com` naming `watchers`,
/// published at the control plane.
async fn publish(control: &AppState, mnemonic: &str, watchers: &[&str]) -> DidRecord {
    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let mut signing = secret.clone();
    signing.id = format!("did:key:{pk_mb}#{pk_mb}");
    let doc = did_hosting_common::did::build_did_document(
        "origin.example.com",
        mnemonic,
        &pk_mb,
        &did_hosting_common::did::DidDocumentOptions::default(),
    );
    let params = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![pk_mb.clone().into()])),
        watchers: Some(Arc::new(watchers.iter().map(|w| w.to_string()).collect())),
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

/// Publish → fan out through the outbox → applied on the watcher → its signed
/// acknowledgement settles the entry; and a delete reaches it the same way.
#[tokio::test]
async fn a_published_did_fans_out_to_the_watchers_its_log_names() {
    for via in VIAS {
        let p = pair().await;
        let record = publish(&p.control, "alice", &[WATCHER_URL]).await;

        crate::server_push::notify_servers_did(&p.control, "alice".into());
        p.wait_for(1).await;
        assert_eq!(p.queued().await[0].0, MSG_SYNC_UPDATE);

        let reply = p.pump(via).await;
        assert_eq!(reply["type"], MSG_SYNC_UPDATE_ACK, "{via:?} {reply}");
        let held = webvh_watcher::watcher_ops::get_record(&p.watcher.dids_ks, "alice")
            .await
            .unwrap()
            .expect("the watcher mirrors the DID");
        assert_eq!(Some(held.did_id), record.did_id);
        assert_eq!(held.source_did, p.control_did);
        assert!(
            p.queued().await.is_empty(),
            "{via:?}: the watcher's signed ack settled the entry"
        );

        crate::server_push::notify_servers_delete(&p.control, "alice".into());
        p.wait_for(1).await;
        let reply = p.pump(via).await;
        assert_eq!(reply["payload"]["status"], "deleted", "{via:?} {reply}");
        assert!(p.queued().await.is_empty(), "{via:?}");
    }
}

/// A log naming no configured watcher queues nothing for any watcher.
#[tokio::test]
async fn an_unconfigured_watcher_is_not_pushed_to() {
    let p = pair().await;
    publish(&p.control, "bob", &["https://other-watcher.example.com"]).await;
    crate::server_push::notify_servers_did(&p.control, "bob".into());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(p.queued().await.is_empty());
    assert!(
        crate::outbox::list_targets(&p.control.store)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A configured watcher's DID may acknowledge a sync, and nothing else: any
/// other request it signs is refused as from a DID with no ACL entry.
#[tokio::test]
async fn a_watcher_may_only_acknowledge() {
    let p = pair().await;
    let (_, watcher_key) = crate::signing::test_util::did_key_signer(&[93; 32]);
    let doc = did_hosting_common::server::trust_tasks::send::build_signed_request(
        "https://trusttasks.org/spec/acl/list/0.1",
        &p.watcher_did,
        &p.control_did,
        json!({}),
        &watcher_key,
    )
    .await
    .unwrap();
    let reply = crate::tsp::run_tsp_trust_task(
        &p.control,
        &p.watcher_did,
        &serde_json::to_vec(&doc).unwrap(),
    )
    .await
    .unwrap()
    .map(|f| serde_json::from_slice::<Value>(&f).unwrap())
    .expect("refused with an error");
    assert_eq!(reply["payload"]["code"], "permissionDenied", "{reply}");
}

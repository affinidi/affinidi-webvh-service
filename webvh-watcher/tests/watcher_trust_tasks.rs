//! The watcher's Trust Task listener, driven through each of its three
//! transport entry points — the TSP frame handler, the DIDComm envelope
//! handler and `POST /api/trust-tasks` — with documents signed as a control
//! plane's outbox signs them.
//!
//! Every sync task (`webvh/sync/update/0.2`, `delete/0.2`, `batch/0.1`) is
//! applied on every transport from a configured source; every one refuses an
//! unsigned document, a foreign signer and a proof of the wrong purpose; the
//! log is verified exactly as an edge verifies it; and a replay is not applied
//! twice.

use std::path::PathBuf;
use std::sync::Arc;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_messaging_didcomm::Message;
use affinidi_secrets_resolver::secrets::Secret;
use did_hosting_common::did::{DidDocumentOptions, build_did_document};
use did_hosting_common::didcomm_types::{MSG_SYNC_BATCH, MSG_SYNC_DELETE, MSG_SYNC_UPDATE};
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::identity::ServiceIdentity;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::trust_tasks::send::build_request;
use did_hosting_common::server::trust_tasks::{TransportBoundVerifier, sign_document};
use serde_json::{Value, json};
use webvh_watcher::config::{AppConfig, SyncConfig};
use webvh_watcher::server::AppState;
use webvh_watcher::watcher_ops;

fn signer(seed: u8) -> (String, Secret) {
    let secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let pk = secret.get_public_keymultibase().unwrap();
    let did = format!("did:key:{pk}");
    let mut s = secret;
    s.id = format!("{did}#{pk}");
    (did, s)
}

fn watcher() -> (String, Secret) {
    signer(80)
}

fn source() -> (String, Secret) {
    signer(81)
}

fn stranger() -> (String, Secret) {
    signer(82)
}

#[derive(Debug, Clone, Copy)]
enum Via {
    Tsp,
    Didcomm,
    Https,
}

const VIAS: [Via; 3] = [Via::Tsp, Via::Didcomm, Via::Https];

/// A watcher with its own signing identity, mirroring `source()` only.
async fn watcher_state() -> (AppState, tempfile::TempDir) {
    let (my_did, my_key) = watcher();
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let config = AppConfig {
        server_did: Some(my_did.clone()),
        store: store_config,
        sync: SyncConfig {
            source_dids: vec![source().0],
        },
        ..AppConfig::default()
    };
    let identity = ServiceIdentity::from_signing_secret(&my_did, my_key)
        .await
        .unwrap();
    let mut state = AppState::new(store, config, Some(identity)).unwrap();
    state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
        DidKeyResolver,
    ))));
    (state, dir)
}

#[derive(Debug, Clone, Copy)]
enum Proof {
    Authentication,
    AssertionMethod,
    None,
}

async fn document(type_uri: &str, from: &(String, Secret), payload: Value, proof: Proof) -> Value {
    let doc = build_request(type_uri, &from.0, &watcher().0, payload).unwrap();
    match proof {
        Proof::Authentication => {
            serde_json::to_value(sign_document(&doc, &from.1).await.unwrap()).unwrap()
        }
        Proof::AssertionMethod => {
            use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
            sign_trust_task(
                &serde_json::to_value(&doc).unwrap(),
                &from.1,
                SignOptions::new()
                    .with_proof_purpose("assertionMethod")
                    .with_cryptosuite(CryptoSuite::EddsaJcs2022),
            )
            .await
            .unwrap()
        }
        Proof::None => serde_json::to_value(doc).unwrap(),
    }
}

async fn signed(type_uri: &str, from: &(String, Secret), payload: Value) -> Value {
    document(type_uri, from, payload, Proof::Authentication).await
}

async fn deliver(state: &AppState, via: Via, sender: &str, doc: Value) -> Option<Value> {
    match via {
        Via::Tsp => webvh_watcher::tsp::run_tsp_trust_task(
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
            webvh_watcher::messaging::run_trust_tasks_envelope(state, Some(sender), &message)
                .await
                .map(|(typ, body)| {
                    assert_eq!(typ, trust_tasks_didcomm::ENVELOPE_TYPE);
                    body
                })
        }
        Via::Https => {
            use axum::response::IntoResponse;
            use http_body_util::BodyExt;
            let response = webvh_watcher::routes::trust_tasks::receive(
                axum::extract::State(state.clone()),
                axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
                axum::http::HeaderMap::new(),
                axum::body::Bytes::from(serde_json::to_vec(&doc).unwrap()),
            )
            .await
            .into_response();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body: Value = serde_json::from_slice(&bytes).expect("HTTPS reply is JSON");
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

fn signed_by_the_watcher(reply: &Value, to: &str) {
    assert!(reply.get("proof").is_some(), "the reply is signed: {reply}");
    assert_eq!(reply["issuer"], watcher().0, "{reply}");
    assert_eq!(reply["recipient"], to, "{reply}");
}

fn answered(reply: &Value, type_uri: &str) -> Value {
    assert_eq!(reply["type"], format!("{type_uri}#response"), "{reply}");
    signed_by_the_watcher(reply, &source().0);
    let schema = trust_tasks_rs::schema_index::schema_for(&format!("{type_uri}#response"))
        .unwrap_or_else(|| panic!("no schema is known for {type_uri}#response"));
    if let Err(e) = trust_tasks_rs::validate::against_schema(schema, &reply["payload"]) {
        panic!("{type_uri} reply does not match its schema: {e:?}\n{reply}");
    }
    reply["payload"].clone()
}

fn refused(reply: &Value, to: &str) -> String {
    assert!(
        reply["type"]
            .as_str()
            .is_some_and(|t| t.contains("/trust-task-error/")),
        "expected an error, got {reply}"
    );
    signed_by_the_watcher(reply, to);
    reply["payload"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A did:webvh log for `mnemonic` on `origin.example.com`: one entry, or two
/// with the second deactivating it.
/// The genesis `versionTime` of every test log: fixed, because the SCID — and
/// so the DID — hashes it. Taken from the wall clock, two `did_log` calls for
/// one identity a second boundary apart produced two different DIDs, and
/// `logs_are_verified_before_they_are_mirrored` failed (intermittently) as
/// `invalidLog` on a log that was valid. In the past, so a later entry (the
/// deactivation, stamped now) is always later.
fn genesis_time() -> chrono::DateTime<chrono::FixedOffset> {
    chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").expect("a fixed instant")
}

async fn did_log(mnemonic: &str, entries: usize) -> (String, String) {
    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let mut signing = secret.clone();
    signing.id = format!("did:key:{pk_mb}#{pk_mb}");
    let doc = build_did_document(
        "origin.example.com",
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
            Some(genesis_time()),
            &doc,
            &params,
            &signing,
        )
        .await
        .expect("create webvh log entry");
    if entries > 1 {
        state.deactivate(&signing).await.expect("deactivate");
    }
    let log = state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let did = did_hosting_common::did_ops::extract_did_id(&log).unwrap();
    (did, log)
}

fn update_body(mnemonic: &str, did: &str, log: &str) -> Value {
    json!({
        "mnemonic": mnemonic,
        "didId": did,
        "logContent": log,
        "versionCount": log.lines().filter(|l| !l.trim().is_empty()).count(),
        "disabled": false,
    })
}

async fn held(state: &AppState, mnemonic: &str) -> Option<watcher_ops::WatcherRecord> {
    watcher_ops::get_record(&state.dids_ks, mnemonic)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Every task, on every transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_sync_task_is_applied_on_every_transport() {
    for via in VIAS {
        let (state, _dir) = watcher_state().await;
        let s = source();
        let (did, log) = did_log("alice", 1).await;

        // sync/update
        let reply = deliver(
            &state,
            via,
            &s.0,
            signed(MSG_SYNC_UPDATE, &s, update_body("alice", &did, &log)).await,
        )
        .await
        .expect("answered");
        assert_eq!(
            answered(&reply, MSG_SYNC_UPDATE),
            json!({ "mnemonic": "alice", "status": "applied" }),
            "{via:?}"
        );
        let record = held(&state, "alice").await.expect("mirrored");
        assert_eq!(record.did_id, did);
        assert_eq!(record.source_did, s.0);

        // The same state again is `unchanged`.
        let reply = deliver(
            &state,
            via,
            &s.0,
            signed(MSG_SYNC_UPDATE, &s, update_body("alice", &did, &log)).await,
        )
        .await
        .expect("answered");
        assert_eq!(answered(&reply, MSG_SYNC_UPDATE)["status"], "unchanged");

        // sync/batch
        let (bob_did, bob_log) = did_log("bob", 1).await;
        let reply = deliver(
            &state,
            via,
            &s.0,
            signed(
                MSG_SYNC_BATCH,
                &s,
                json!({ "updates": [update_body("bob", &bob_did, &bob_log)] }),
            )
            .await,
        )
        .await
        .expect("answered");
        assert_eq!(
            answered(&reply, MSG_SYNC_BATCH)["results"][0],
            json!({ "mnemonic": "bob", "status": "applied" })
        );
        assert!(held(&state, "bob").await.is_some());

        // sync/delete
        let reply = deliver(
            &state,
            via,
            &s.0,
            signed(MSG_SYNC_DELETE, &s, json!({ "mnemonic": "alice" })).await,
        )
        .await
        .expect("answered");
        assert_eq!(
            answered(&reply, MSG_SYNC_DELETE),
            json!({ "mnemonic": "alice", "status": "deleted" })
        );
        assert!(held(&state, "alice").await.is_none());
        let reply = deliver(
            &state,
            via,
            &s.0,
            signed(MSG_SYNC_DELETE, &s, json!({ "mnemonic": "alice" })).await,
        )
        .await
        .expect("answered");
        assert_eq!(answered(&reply, MSG_SYNC_DELETE)["status"], "absent");
    }
}

// ---------------------------------------------------------------------------
// Refusals, for every task on every transport
// ---------------------------------------------------------------------------

async fn payloads() -> Vec<(&'static str, Value)> {
    let (did, log) = did_log("carol", 1).await;
    vec![
        (MSG_SYNC_UPDATE, update_body("carol", &did, &log)),
        (
            MSG_SYNC_BATCH,
            json!({ "updates": [update_body("carol", &did, &log)] }),
        ),
        (MSG_SYNC_DELETE, json!({ "mnemonic": "carol" })),
    ]
}

/// A document that does not verify — unsigned, or signed for the wrong
/// purpose — gets no reply and applies nothing.
#[tokio::test]
async fn unverified_documents_get_no_reply() {
    for via in VIAS {
        let (state, _dir) = watcher_state().await;
        let s = source();
        for (type_uri, payload) in payloads().await {
            for proof in [Proof::None, Proof::AssertionMethod] {
                let doc = document(type_uri, &s, payload.clone(), proof).await;
                assert_eq!(
                    deliver(&state, via, &s.0, doc).await,
                    None,
                    "{via:?} {type_uri} {proof:?}"
                );
            }
        }
        assert!(held(&state, "carol").await.is_none(), "{via:?}");
    }
}

/// The source-DID allowlist: a claimed issuer that is not a configured
/// source is refused before its proof is ever checked — no reply at all,
/// exactly like a document that never verified (the pre-check in
/// `dispatch_inbound_document` compares the claimed issuer against
/// `source_dids` before any DID resolution). Applies nothing, and takes no
/// room in the replay cache — the same document resent is refused again, not
/// dropped as a replay.
#[tokio::test]
async fn only_configured_sources_are_applied() {
    for via in VIAS {
        let (state, _dir) = watcher_state().await;
        let x = stranger();
        for (type_uri, payload) in payloads().await {
            let doc = signed(type_uri, &x, payload).await;
            for _ in 0..2 {
                assert_eq!(
                    deliver(&state, via, &x.0, doc.clone()).await,
                    None,
                    "{via:?} {type_uri}: a claimed issuer outside the source allowlist must not be answered"
                );
            }
        }
        assert!(held(&state, "carol").await.is_none(), "{via:?}");
    }
}

/// With no configured source, nothing is ever applied — and, per the
/// pre-check above, nothing is even resolved: every claimed issuer fails the
/// (empty) allowlist before its proof is checked.
#[tokio::test]
async fn an_empty_allowlist_applies_nothing() {
    let (mut state, _dir) = watcher_state().await;
    let mut config = (*state.config).clone();
    config.sync.source_dids.clear();
    state.config = Arc::new(config);
    let s = source();
    let (did, log) = did_log("dave", 1).await;
    let reply = deliver(
        &state,
        Via::Https,
        &s.0,
        signed(MSG_SYNC_UPDATE, &s, update_body("dave", &did, &log)).await,
    )
    .await;
    assert_eq!(reply, None);
    assert!(held(&state, "dave").await.is_none());
}

#[tokio::test]
async fn a_sender_that_disagrees_with_the_proof_is_not_answered() {
    let (state, _dir) = watcher_state().await;
    let s = source();
    for via in [Via::Tsp, Via::Didcomm] {
        let doc = signed(MSG_SYNC_DELETE, &s, json!({ "mnemonic": "x" })).await;
        assert_eq!(deliver(&state, via, &stranger().0, doc).await, None);
    }
}

#[tokio::test]
async fn a_replay_is_refused() {
    for via in VIAS {
        let (state, _dir) = watcher_state().await;
        let s = source();
        let doc = signed(MSG_SYNC_DELETE, &s, json!({ "mnemonic": "x" })).await;
        assert!(deliver(&state, via, &s.0, doc.clone()).await.is_some());
        assert_eq!(deliver(&state, via, &s.0, doc).await, None, "{via:?}");
    }
}

// ---------------------------------------------------------------------------
// The log is verified as an edge verifies it
// ---------------------------------------------------------------------------

async fn update_refusal(state: &AppState, body: Value) -> String {
    let s = source();
    let reply = deliver(
        state,
        Via::Https,
        &s.0,
        signed(MSG_SYNC_UPDATE, &s, body).await,
    )
    .await
    .expect("answered");
    refused(&reply, &s.0)
}

#[tokio::test]
async fn logs_are_verified_before_they_are_mirrored() {
    let (state, _dir) = watcher_state().await;
    let (did, log) = did_log("erin", 1).await;

    // A tampered log.
    let tampered = log.replacen("origin.example.com", "evil.example.com", 1);
    assert_eq!(
        update_refusal(&state, update_body("erin", &did, &tampered)).await,
        "webvh/sync/update:invalidLog"
    );
    // Filed under another slot.
    assert_eq!(
        update_refusal(&state, update_body("mallory", &did, &log)).await,
        "webvh/sync/update:invalidLog"
    );
    // A versionCount that is not the log's.
    let mut body = update_body("erin", &did, &log);
    body["versionCount"] = json!(2);
    assert_eq!(
        update_refusal(&state, body).await,
        "webvh/sync/update:invalidLog"
    );
    assert!(held(&state, "erin").await.is_none());

    // Once the two-entry (deactivated) log is mirrored, the one-entry log is
    // a history rewrite…
    let (_, deactivated) = did_log("erin", 2).await;
    let s = source();
    let reply = deliver(
        &state,
        Via::Https,
        &s.0,
        signed(MSG_SYNC_UPDATE, &s, update_body("erin", &did, &deactivated)).await,
    )
    .await
    .expect("answered");
    assert_eq!(answered(&reply, MSG_SYNC_UPDATE)["status"], "applied");
    assert_eq!(
        update_refusal(&state, update_body("erin", &did, &log)).await,
        "webvh/sync/update:historyRewrite"
    );

    // …even after a delete: the high-water mark stays.
    deliver(
        &state,
        Via::Https,
        &s.0,
        signed(MSG_SYNC_DELETE, &s, json!({ "mnemonic": "erin" })).await,
    )
    .await
    .expect("answered");
    assert_eq!(
        update_refusal(&state, update_body("erin", &did, &log)).await,
        "webvh/sync/update:historyRewrite"
    );
}

/// 0.1's snake_case members are refused, not ignored.
#[tokio::test]
async fn a_snake_case_payload_is_refused() {
    let (state, _dir) = watcher_state().await;
    let (did, log) = did_log("frank", 1).await;
    let code = update_refusal(
        &state,
        json!({
            "mnemonic": "frank", "did_id": did, "log_content": log,
            "version_count": 1, "disabled": false,
        }),
    )
    .await;
    assert_eq!(code, "malformedRequest");
    assert!(held(&state, "frank").await.is_none());
}

// ---------------------------------------------------------------------------
// One source cannot take over or delete another source's slot
// ---------------------------------------------------------------------------

/// A one-entry did:webvh log for `mnemonic` on `host`.
async fn did_log_on(host: &str, mnemonic: &str) -> (String, String) {
    let secret = Secret::generate_ed25519(None, Some(&[11u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let mut signing = secret.clone();
    signing.id = format!("did:key:{pk_mb}#{pk_mb}");
    let doc = build_did_document(host, mnemonic, &pk_mb, &DidDocumentOptions::default());
    let params = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![pk_mb.clone().into()])),
        ..Default::default()
    };
    let mut state = didwebvh_rs::DIDWebVHState::default();
    state
        .create_log_entry(
            Some(genesis_time()),
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
    let did = did_hosting_common::did_ops::extract_did_id(&log).unwrap();
    (did, log)
}

#[tokio::test]
async fn a_source_cannot_take_over_or_delete_another_sources_slot() {
    let (mut state, _dir) = watcher_state().await;
    let (a, b) = (source(), signer(83));
    let mut config = (*state.config).clone();
    config.sync.source_dids.push(b.0.clone());
    state.config = Arc::new(config);

    let (did_a, log_a) = did_log_on("origin.example.com", "frank").await;
    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(MSG_SYNC_UPDATE, &a, update_body("frank", &did_a, &log_a)).await,
    )
    .await
    .expect("answered");
    answered(&reply, MSG_SYNC_UPDATE);

    // Another source's DID at the same slot is refused.
    let (did_b, log_b) = did_log_on("other.example.com", "frank").await;
    assert_ne!(did_a, did_b);
    let reply = deliver(
        &state,
        Via::Https,
        &b.0,
        signed(MSG_SYNC_UPDATE, &b, update_body("frank", &did_b, &log_b)).await,
    )
    .await
    .expect("answered");
    assert_eq!(refused(&reply, &b.0), "webvh/sync/update:notAuthorized");
    assert_eq!(held(&state, "frank").await.unwrap().did_id, did_a);

    // Its delete leaves the slot alone, and says nothing of it.
    let reply = deliver(
        &state,
        Via::Https,
        &b.0,
        signed(MSG_SYNC_DELETE, &b, json!({ "mnemonic": "frank" })).await,
    )
    .await
    .expect("answered");
    assert_eq!(
        reply["type"],
        format!("{MSG_SYNC_DELETE}#response"),
        "{reply}"
    );
    signed_by_the_watcher(&reply, &b.0);
    assert_eq!(reply["payload"]["status"], "absent");
    assert!(held(&state, "frank").await.is_some());

    // The slot's own source can delete it.
    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(MSG_SYNC_DELETE, &a, json!({ "mnemonic": "frank" })).await,
    )
    .await
    .expect("answered");
    assert_eq!(answered(&reply, MSG_SYNC_DELETE)["status"], "deleted");
    assert!(held(&state, "frank").await.is_none());
}

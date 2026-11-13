//! The witness's Trust Task listener, driven through each of its three
//! transport entry points — the TSP frame handler, the DIDComm envelope
//! handler and `POST /api/trust-tasks` — with documents signed as a requester
//! signs them.
//!
//! Every task (`webvh/witness/key/*`, `webvh/witness/sign`, `acl/*`) is served
//! on every transport; every one of them refuses an unsigned document, a
//! foreign signer and a proof of the wrong purpose; `witness/sign` verifies
//! the log before it signs; and a replayed document is not acted on twice.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use affinidi_data_integrity::DidKeyResolver;
use affinidi_messaging_didcomm::Message;
use affinidi_secrets_resolver::secrets::Secret;
use did_hosting_common::did::{DidDocumentOptions, build_did_document};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::config::{
    FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::server::identity::ServiceIdentity;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::trust_tasks::send::build_request;
use did_hosting_common::server::trust_tasks::{TransportBoundVerifier, sign_document};
use did_hosting_common::tasks::acl::{list as acl_list, show as acl_show};
use did_hosting_common::tasks::webvh::witness::{
    key::{create::v0_1 as key_create, delete::v0_1 as key_delete, list::v0_1 as key_list},
    sign::v0_1 as sign,
};
use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use webvh_witness::config::AppConfig;
use webvh_witness::server::AppState;
use webvh_witness::witness_keys::WitnessKeys;
use webvh_witness::witness_ops;

/// A fresh loopback address, distinct from every other call in this process.
///
/// `receive`'s per-address rate limiter would otherwise treat every HTTPS
/// delivery in a test file that exercises many tasks as one address — a
/// test artifact, not the real-address-per-connection world the limiter
/// defends. Each simulated "connection" here gets its own.
fn fresh_https_addr() -> std::net::SocketAddr {
    static NEXT: AtomicU16 = AtomicU16::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::net::SocketAddr::from(([127, 0, (n >> 8) as u8, n as u8], 0))
}

/// A `did:key` signer, so proofs verify with no I/O.
fn signer(seed: u8) -> (String, Secret) {
    let secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let pk = secret.get_public_keymultibase().unwrap();
    let did = format!("did:key:{pk}");
    let mut s = secret;
    s.id = format!("{did}#{pk}");
    (did, s)
}

fn witness_service() -> (String, Secret) {
    signer(60)
}

fn admin() -> (String, Secret) {
    signer(61)
}

fn owner() -> (String, Secret) {
    signer(62)
}

fn stranger() -> (String, Secret) {
    signer(63)
}

#[derive(Debug, Clone, Copy)]
enum Via {
    Tsp,
    Didcomm,
    Https,
}

const VIAS: [Via; 3] = [Via::Tsp, Via::Didcomm, Via::Https];

/// A witness with a signing identity, `admin()` an Admin and `owner()` an
/// Owner in its ACL.
async fn witness_state() -> (AppState, tempfile::TempDir) {
    let (my_did, my_key) = witness_service();
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some(my_did.clone()),
        mediator_did: None,
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        fjall: Default::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(),
        identity: Default::default(),
        replay: Default::default(),
        config_path: PathBuf::new(),
    };
    let identity = ServiceIdentity::from_signing_secret(&my_did, my_key)
        .await
        .unwrap();
    let mut state = AppState::new(store, config, Some(identity), test_witness_keys(&dir)).unwrap();
    state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
        DidKeyResolver,
    ))));
    for (did, role) in [(admin().0, Role::Admin), (owner().0, Role::Owner)] {
        store_acl_entry(
            &state.acl_ks,
            &AclEntry {
                did,
                role,
                label: None,
                created_at: 1_700_000_000,
                max_total_size: None,
                max_did_count: None,
                domains: DomainScope::All,
            },
        )
        .await
        .unwrap();
    }
    (state, dir)
}

/// A witness key-encryption key for one test witness.
fn test_witness_keys(_dir: &tempfile::TempDir) -> Arc<WitnessKeys> {
    Arc::new(WitnessKeys::generate().expect("key-encryption key"))
}

/// How a test document is signed.
#[derive(Debug, Clone, Copy)]
enum Proof {
    Authentication,
    AssertionMethod,
    None,
}

async fn document(type_uri: &str, from: &(String, Secret), payload: Value, proof: Proof) -> Value {
    let doc = build_request(type_uri, &from.0, &witness_service().0, payload).unwrap();
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

/// Deliver `doc` over `via`, reported as coming from `sender`; `None` when the
/// witness answered nothing.
async fn deliver(state: &AppState, via: Via, sender: &str, doc: Value) -> Option<Value> {
    match via {
        Via::Tsp => webvh_witness::tsp::run_tsp_trust_task(
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
            webvh_witness::messaging::run_trust_tasks_envelope(state, Some(sender), &message)
                .await
                .map(|(typ, body)| {
                    assert_eq!(typ, trust_tasks_didcomm::ENVELOPE_TYPE);
                    body
                })
        }
        Via::Https => {
            use axum::response::IntoResponse;
            use http_body_util::BodyExt;
            let response = webvh_witness::routes::trust_tasks::receive(
                axum::extract::State(state.clone()),
                axum::extract::ConnectInfo(fresh_https_addr()),
                axum::http::HeaderMap::new(),
                axum::body::Body::from(serde_json::to_vec(&doc).unwrap()),
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

fn signed_by_the_witness(reply: &Value, to: &str) {
    assert!(reply.get("proof").is_some(), "the reply is signed: {reply}");
    assert_eq!(reply["issuer"], witness_service().0, "{reply}");
    assert_eq!(reply["recipient"], to, "{reply}");
}

/// The reply is the task's `#response`, signed by the witness, and its payload
/// validates against its schema.
fn answered(reply: &Value, type_uri: &str) -> Value {
    assert_eq!(reply["type"], format!("{type_uri}#response"), "{reply}");
    signed_by_the_witness(reply, &admin().0);
    let schema = did_hosting_common::tasks::payload_schema(&format!("{type_uri}#response"))
        .unwrap_or_else(|| panic!("no schema is known for {type_uri}#response"));
    if let Err(e) = trust_tasks_rs::validate::against_schema(schema, &reply["payload"]) {
        panic!("{type_uri} reply does not match its schema: {e:?}\n{reply}");
    }
    reply["payload"].clone()
}

/// The code of a signed `trust-task-error` reply.
fn refused(reply: &Value, to: &str) -> String {
    assert!(
        reply["type"]
            .as_str()
            .is_some_and(|t| t.contains("/trust-task-error/")),
        "expected an error, got {reply}"
    );
    signed_by_the_witness(reply, to);
    reply["payload"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A did:webvh log whose last entry names `witness` (a `did:key`'s multibase
/// key) as its witness; with `deactivate`, a second entry deactivates it.
async fn witnessed_log(witness: &str, deactivate: bool) -> String {
    use didwebvh_rs::witness::{Witness, Witnesses};
    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let mut signing = secret.clone();
    signing.id = format!("did:key:{pk_mb}#{pk_mb}");
    let doc = build_did_document(
        "server.example.com",
        "alice",
        &pk_mb,
        &DidDocumentOptions::default(),
    );
    let params = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![pk_mb.clone().into()])),
        witness: Some(Arc::new(Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: witness.to_string().into(),
            }],
        })),
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
    if deactivate {
        state.deactivate(&signing).await.expect("deactivate");
    }
    state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// `witnessed_log(witness, true)`, with one more entry appended after the
/// deactivating one. didwebvh-rs itself refuses to *write* such a log (a
/// deactivated DID accepts no further entry, full stop — `create_log_entry`
/// returns `DeactivatedError` regardless of `updateKeys`), so this hand-crafts
/// the successor line by cloning the real deactivating entry's JSON and
/// changing only its `versionId`/`versionTime`. That line is never
/// cryptographically verified: `verify_log_for_witnessing` refuses on sight
/// of the earlier deactivating entry, before reaching this one (see its doc
/// comment), so an unsigned-in-truth successor is exactly what the witness's
/// refusal must not depend on inspecting.
async fn witnessed_log_after_deactivation(witness: &str) -> String {
    let deactivated = witnessed_log(witness, true).await;
    let mut after: Value = serde_json::from_str(deactivated.lines().last().unwrap()).unwrap();
    after["versionId"] = json!("3-QmAfterDeactivation");
    after["versionTime"] =
        json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    format!("{deactivated}\n{}", serde_json::to_string(&after).unwrap())
}

fn last_version_id(log: &str) -> String {
    let last: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    last["versionId"].as_str().unwrap().to_string()
}

/// A witness identity on `state`, and a log that names it.
async fn identity_and_log(state: &AppState) -> (witness_ops::WitnessRecord, String) {
    let record =
        witness_ops::create_witness(&state.witnesses_ks, &state.witness_keys, Some("w".into()))
            .await
            .unwrap();
    let log = witnessed_log(&record.witness_id, false).await;
    (record, log)
}

fn sign_payload(witness_id: &str, log: &str) -> Value {
    json!({
        "witnessId": witness_id,
        "versionId": last_version_id(log),
        "logContent": log,
    })
}

// ---------------------------------------------------------------------------
// Every task, on every transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_task_is_served_on_every_transport() {
    for via in VIAS {
        let (state, _dir) = witness_state().await;
        let a = admin();

        // key/create
        let reply = deliver(
            &state,
            via,
            &a.0,
            signed(
                key_create::Payload::TYPE_URI,
                &a,
                json!({ "label": "EU 1" }),
            )
            .await,
        )
        .await
        .expect("answered");
        let key = answered(&reply, key_create::Payload::TYPE_URI)["key"].clone();
        assert_eq!(key["label"], "EU 1", "{via:?}");
        assert_eq!(key["proofsSigned"], 0);
        assert!(key["did"].as_str().unwrap().starts_with("did:key:"));
        assert!(key.get("privateKeyMultibase").is_none());
        let witness_id = key["witnessId"].as_str().unwrap().to_string();

        // key/list
        let reply = deliver(
            &state,
            via,
            &a.0,
            signed(key_list::Payload::TYPE_URI, &a, json!({})).await,
        )
        .await
        .expect("answered");
        let keys = answered(&reply, key_list::Payload::TYPE_URI)["keys"].clone();
        assert_eq!(keys.as_array().unwrap().len(), 1, "{via:?}");

        // sign — against a log that names the new identity
        let log = witnessed_log(&witness_id, false).await;
        let reply = deliver(
            &state,
            via,
            &a.0,
            signed(sign::Payload::TYPE_URI, &a, sign_payload(&witness_id, &log)).await,
        )
        .await
        .expect("answered");
        let body = answered(&reply, sign::Payload::TYPE_URI);
        assert_eq!(body["versionId"], last_version_id(&log), "{via:?}");
        assert_eq!(body["proof"]["type"], "DataIntegrityProof");
        assert_eq!(
            witness_ops::get_witness(&state.witnesses_ks, &witness_id)
                .await
                .unwrap()
                .unwrap()
                .proofs_signed,
            1
        );

        // acl/list and acl/show
        let reply = deliver(
            &state,
            via,
            &a.0,
            signed(acl_list::v0_3::Payload::TYPE_URI, &a, json!({})).await,
        )
        .await
        .expect("answered");
        assert_eq!(
            reply["type"],
            format!("{}#response", acl_list::v0_3::Payload::TYPE_URI),
            "{via:?}: {reply}"
        );
        signed_by_the_witness(&reply, &a.0);
        let reply = deliver(
            &state,
            via,
            &a.0,
            signed(
                acl_show::v0_2::Payload::TYPE_URI,
                &a,
                json!({ "subject": owner().0 }),
            )
            .await,
        )
        .await
        .expect("answered");
        assert_eq!(
            reply["type"],
            format!("{}#response", acl_show::v0_2::Payload::TYPE_URI),
            "{via:?}: {reply}"
        );

        // key/delete
        let reply = deliver(
            &state,
            via,
            &a.0,
            signed(
                key_delete::Payload::TYPE_URI,
                &a,
                json!({ "witnessId": witness_id }),
            )
            .await,
        )
        .await
        .expect("answered");
        answered(&reply, key_delete::Payload::TYPE_URI);
        assert!(
            witness_ops::get_witness(&state.witnesses_ks, &witness_id)
                .await
                .unwrap()
                .is_none()
        );
        // …and a second delete is `notFound`.
        let reply = deliver(
            &state,
            via,
            &a.0,
            signed(
                key_delete::Payload::TYPE_URI,
                &a,
                json!({ "witnessId": witness_id }),
            )
            .await,
        )
        .await
        .expect("answered");
        assert_eq!(
            refused(&reply, &a.0),
            key_delete::error_codes::NOT_FOUND.code
        );
    }
}

/// The acl write family goes through the same gate: an admin's grant applies.
#[tokio::test]
async fn an_admin_grant_applies_on_every_transport() {
    use did_hosting_common::tasks::acl::grant;
    for via in VIAS {
        let (state, _dir) = witness_state().await;
        let a = admin();
        let subject = signer(70 + via as u8).0;
        let reply = deliver(
            &state,
            via,
            &a.0,
            signed(
                grant::v0_2::Payload::TYPE_URI,
                &a,
                json!({ "entry": {
                    "subject": subject,
                    "role": "owner",
                    "act": { "scope": "all" },
                    "keys": { "scope": "none" },
                    "capabilities": { "scope": "ceiling" },
                } }),
            )
            .await,
        )
        .await
        .expect("answered");
        assert_eq!(
            reply["type"],
            format!("{}#response", grant::v0_2::Payload::TYPE_URI),
            "{via:?}: {reply}"
        );
        signed_by_the_witness(&reply, &a.0);
        assert!(
            did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &subject)
                .await
                .unwrap()
                .is_some()
        );
    }
}

// ---------------------------------------------------------------------------
// Refusals, for every task on every transport
// ---------------------------------------------------------------------------

/// A payload each task would accept from the admin.
async fn payloads(state: &AppState) -> Vec<(&'static str, Value)> {
    let (record, log) = identity_and_log(state).await;
    vec![
        (key_create::Payload::TYPE_URI, json!({})),
        (key_list::Payload::TYPE_URI, json!({})),
        (
            key_delete::Payload::TYPE_URI,
            json!({ "witnessId": record.witness_id }),
        ),
        (
            sign::Payload::TYPE_URI,
            sign_payload(&record.witness_id, &log),
        ),
        (acl_list::v0_3::Payload::TYPE_URI, json!({})),
        (
            acl_show::v0_2::Payload::TYPE_URI,
            json!({ "subject": owner().0 }),
        ),
    ]
}

/// Whether anything changed: the witness identities and their counters.
async fn snapshot(state: &AppState) -> Vec<(String, u64)> {
    let mut v: Vec<_> = witness_ops::list_witnesses(&state.witnesses_ks)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.witness_id, r.proofs_signed))
        .collect();
    v.sort();
    v
}

/// An unsigned document, and one whose proof has the wrong purpose, get no
/// reply at all, on every transport, and change nothing.
#[tokio::test]
async fn unverified_documents_get_no_reply() {
    for via in VIAS {
        let (state, _dir) = witness_state().await;
        let a = admin();
        let tasks = payloads(&state).await;
        let before = snapshot(&state).await;
        for (type_uri, payload) in tasks {
            for proof in [Proof::None, Proof::AssertionMethod] {
                let doc = document(type_uri, &a, payload.clone(), proof).await;
                assert_eq!(
                    deliver(&state, via, &a.0, doc).await,
                    None,
                    "{via:?} {type_uri} {proof:?} must get no reply"
                );
            }
        }
        assert_eq!(snapshot(&state).await, before, "{via:?}: nothing changed");
    }
}

/// A document from a DID the witness would not authorise — a stranger, or,
/// for a witness-admin task, a requester that is on the ACL but not an admin
/// — is refused before its proof is ever checked (the cheap ACL pre-check in
/// `dispatch_inbound_document` looks up the claimed issuer's role, a local
/// store read, ahead of the DID resolution verification would need), so it
/// gets no reply at all and changes nothing.
#[tokio::test]
async fn a_foreign_signer_is_refused() {
    for via in VIAS {
        let (state, _dir) = witness_state().await;
        let tasks = payloads(&state).await;
        let before = snapshot(&state).await;
        for (type_uri, payload) in tasks {
            let s = stranger();
            assert_eq!(
                deliver(
                    &state,
                    via,
                    &s.0,
                    signed(type_uri, &s, payload.clone()).await,
                )
                .await,
                None,
                "{via:?} {type_uri}: a stranger must not be answered"
            );

            if type_uri.contains("/witness/") {
                let o = owner();
                assert_eq!(
                    deliver(&state, via, &o.0, signed(type_uri, &o, payload).await).await,
                    None,
                    "{via:?} {type_uri}: a non-admin owner must not be answered"
                );
            }
        }
        assert_eq!(snapshot(&state).await, before, "{via:?}: nothing changed");
    }
}

/// A document signed by one DID but delivered by a transport that reports
/// another is refused without a reply.
#[tokio::test]
async fn an_issuer_that_disagrees_with_the_transport_is_not_answered() {
    let (state, _dir) = witness_state().await;
    let a = admin();
    for via in [Via::Tsp, Via::Didcomm] {
        let doc = signed(key_list::Payload::TYPE_URI, &a, json!({})).await;
        assert_eq!(deliver(&state, via, &stranger().0, doc).await, None);
    }
}

/// A replayed document is acted on once; the replay gets no reply.
#[tokio::test]
async fn a_replay_is_refused() {
    for via in VIAS {
        let (state, _dir) = witness_state().await;
        let a = admin();
        let doc = signed(key_create::Payload::TYPE_URI, &a, json!({})).await;
        assert!(deliver(&state, via, &a.0, doc.clone()).await.is_some());
        assert_eq!(deliver(&state, via, &a.0, doc).await, None, "{via:?}");
        assert_eq!(snapshot(&state).await.len(), 1, "{via:?}: created once");
    }
}

/// A stranger's documents are refused before anything is recorded — the ACL
/// pre-check drops them with no reply, ahead of the replay cache, which never
/// sees them: the same document, resent, is refused the same way again, not
/// dropped as a replay.
#[tokio::test]
async fn a_strangers_documents_take_no_room_in_the_replay_cache() {
    let (state, _dir) = witness_state().await;
    let s = stranger();
    let doc = signed(key_list::Payload::TYPE_URI, &s, json!({})).await;
    for _ in 0..2 {
        assert_eq!(deliver(&state, Via::Https, &s.0, doc.clone()).await, None);
    }
}

// ---------------------------------------------------------------------------
// witness/sign verifies before it signs
// ---------------------------------------------------------------------------

async fn sign_refusal(state: &AppState, payload: Value) -> String {
    let a = admin();
    let reply = deliver(
        state,
        Via::Https,
        &a.0,
        signed(sign::Payload::TYPE_URI, &a, payload).await,
    )
    .await
    .expect("answered");
    refused(&reply, &a.0)
}

#[tokio::test]
async fn sign_verifies_the_log_before_signing() {
    let (state, _dir) = witness_state().await;
    let (record, log) = identity_and_log(&state).await;

    // A tampered entry does not verify.
    let tampered = log.replacen("server.example.com", "evil.example.com", 1);
    assert_eq!(
        sign_refusal(&state, sign_payload(&record.witness_id, &tampered)).await,
        sign::error_codes::INVALID_LOG.code
    );

    // Not the last entry.
    let mut p = sign_payload(&record.witness_id, &log);
    p["versionId"] = json!("1-QmNotTheLastEntry");
    assert_eq!(
        sign_refusal(&state, p).await,
        sign::error_codes::VERSION_NOT_LAST.code
    );

    // A log that names some other witness.
    let other = witnessed_log(
        &Secret::generate_ed25519(None, Some(&[8u8; 32]))
            .get_public_keymultibase()
            .unwrap(),
        false,
    )
    .await;
    assert_eq!(
        sign_refusal(&state, sign_payload(&record.witness_id, &other)).await,
        sign::error_codes::NOT_LISTED.code
    );

    // An entry *after* the DID's deactivating entry.
    let past_deactivation = witnessed_log_after_deactivation(&record.witness_id).await;
    assert_eq!(
        sign_refusal(&state, sign_payload(&record.witness_id, &past_deactivation)).await,
        sign::error_codes::DEACTIVATED.code
    );

    // An identity the witness does not hold.
    assert_eq!(
        sign_refusal(&state, sign_payload("z6MkNoSuchWitness", &log)).await,
        sign::error_codes::NOT_FOUND.code
    );

    // Nothing was signed on any refused path.
    assert_eq!(
        witness_ops::get_witness(&state.witnesses_ks, &record.witness_id)
            .await
            .unwrap()
            .unwrap()
            .proofs_signed,
        0
    );
}

/// did:webvh does not exempt a DID's deactivating entry from witnessing (see
/// `verify_log_for_witnessing`'s doc comment): a witness signs it exactly as
/// it signs any other entry that is the log's last, is authorised by the
/// DID's update keys, and names this witness identity. Only an entry *after*
/// it is refused (covered by `sign_verifies_the_log_before_signing` above).
#[tokio::test]
async fn sign_witnesses_the_deactivating_entry() {
    let (state, _dir) = witness_state().await;
    let record = witness_ops::create_witness(&state.witnesses_ks, &state.witness_keys, None)
        .await
        .unwrap();
    let deactivated = witnessed_log(&record.witness_id, true).await;

    let a = admin();
    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(
            sign::Payload::TYPE_URI,
            &a,
            sign_payload(&record.witness_id, &deactivated),
        )
        .await,
    )
    .await
    .expect("answered");
    let body = answered(&reply, sign::Payload::TYPE_URI);
    assert_eq!(body["versionId"], last_version_id(&deactivated));
    assert_eq!(body["proof"]["type"], "DataIntegrityProof");
    assert_eq!(
        witness_ops::get_witness(&state.witnesses_ks, &record.witness_id)
            .await
            .unwrap()
            .unwrap()
            .proofs_signed,
        1
    );
}

/// The proof `witness/sign` returns is the witness identity's signature over
/// the entry's versionId: a resolver accepts the log with it.
#[tokio::test]
async fn the_signed_proof_satisfies_the_log() {
    let (state, _dir) = witness_state().await;
    let (record, log) = identity_and_log(&state).await;
    let a = admin();
    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(
            sign::Payload::TYPE_URI,
            &a,
            sign_payload(&record.witness_id, &log),
        )
        .await,
    )
    .await
    .expect("answered");
    let body = answered(&reply, sign::Payload::TYPE_URI);
    let witness_file = json!([{ "versionId": body["versionId"], "proof": [body["proof"]] }]);
    did_hosting_common::did_ops::verify_did_log_and_witness_proofs(
        &log,
        Some(&witness_file.to_string()),
    )
    .expect("the witnessed log verifies");
}

// ---------------------------------------------------------------------------
// witness/sign never witnesses two histories of one DID
// ---------------------------------------------------------------------------

/// A three-entry did:webvh log that names `witness` throughout, as each of
/// its prefixes: `[1 entry, 2 entries, 3 entries]`.
async fn witnessed_chain(witness: &str) -> Vec<String> {
    witnessed_branch(witness, chrono::Utc::now() - chrono::Duration::hours(1), 0).await
}

/// [`witnessed_chain`] from a fixed `base` time, its entries after the first
/// written `branch` minutes later: two branches of one `base` share their
/// first entry (one DID) and diverge from the second (a fork).
async fn witnessed_branch(
    witness: &str,
    base: chrono::DateTime<chrono::Utc>,
    branch: i64,
) -> Vec<String> {
    use didwebvh_rs::witness::{Witness, Witnesses};
    let secret = Secret::generate_ed25519(None, Some(&[9u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let mut signing = secret.clone();
    signing.id = format!("did:key:{pk_mb}#{pk_mb}");
    let doc = build_did_document(
        "server.example.com",
        "bob",
        &pk_mb,
        &DidDocumentOptions::default(),
    );
    let params = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![pk_mb.clone().into()])),
        witness: Some(Arc::new(Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: witness.to_string().into(),
            }],
        })),
        ..Default::default()
    };
    let mut state = didwebvh_rs::DIDWebVHState::default();
    let mut prefixes = Vec::new();
    for i in 0..3i64 {
        let current = match state.log_entries().last() {
            Some(e) => e.get_state().clone(),
            None => doc.clone(),
        };
        let p = if i == 0 {
            params.clone()
        } else {
            didwebvh_rs::parameters::Parameters::default()
        };
        state
            .create_log_entry(
                Some(
                    (base + chrono::Duration::minutes(if i == 0 { 0 } else { i + branch }))
                        .fixed_offset(),
                ),
                &current,
                &p,
                &signing,
            )
            .await
            .expect("create webvh log entry");
        prefixes.push(
            state
                .log_entries()
                .iter()
                .map(|e| serde_json::to_string(&e.log_entry).unwrap())
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    prefixes
}

async fn sign_ok(state: &AppState, witness_id: &str, log: &str) {
    let a = admin();
    let reply = deliver(
        state,
        Via::Https,
        &a.0,
        signed(sign::Payload::TYPE_URI, &a, sign_payload(witness_id, log)).await,
    )
    .await
    .expect("answered");
    answered(&reply, sign::Payload::TYPE_URI);
}

#[tokio::test]
async fn sign_refuses_a_fork_or_a_rollback_of_what_it_witnessed() {
    let (state, _dir) = witness_state().await;
    let record = witness_ops::create_witness(&state.witnesses_ks, &state.witness_keys, None)
        .await
        .unwrap();
    let chain = witnessed_chain(&record.witness_id).await;

    // Extending what it witnessed — and re-witnessing the same entry — is fine.
    sign_ok(&state, &record.witness_id, &chain[1]).await;
    sign_ok(&state, &record.witness_id, &chain[1]).await;
    sign_ok(&state, &record.witness_id, &chain[2]).await;

    // An entry older than one already witnessed is refused.
    assert_eq!(
        sign_refusal(&state, sign_payload(&record.witness_id, &chain[1])).await,
        sign::error_codes::INVALID_LOG.code
    );

    // A log that diverges from the witnessed history is refused.
    let scid = did_hosting_common::did_ops::verify_log_for_witnessing(
        &chain[2],
        &last_version_id(&chain[2]),
        &record.did,
    )
    .unwrap()
    .scid;
    witness_ops::set_witnessed_mark(
        &state.witnesses_ks,
        &record.witness_id,
        &scid,
        &witness_ops::WitnessedMark {
            version_number: 2,
            version_id: "2-QmAnotherHistory".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        sign_refusal(&state, sign_payload(&record.witness_id, &chain[2])).await,
        sign::error_codes::INVALID_LOG.code
    );
    assert_eq!(
        witness_ops::get_witness(&state.witnesses_ks, &record.witness_id)
            .await
            .unwrap()
            .unwrap()
            .proofs_signed,
        3
    );
}

/// Whether a sign request was answered with a proof (`true`) or refused.
async fn try_sign(state: &AppState, witness_id: &str, log: &str) -> bool {
    let a = admin();
    let reply = deliver(
        state,
        Via::Https,
        &a.0,
        signed(sign::Payload::TYPE_URI, &a, sign_payload(witness_id, log)).await,
    )
    .await
    .expect("answered");
    reply["type"] == format!("{}#response", sign::Payload::TYPE_URI)
}

/// Two witness processes sharing one store — each with its own in-process
/// lock — asked at the same moment to witness two forks of one DID: at most
/// one of them signs, whichever order the store sees them in, and a process
/// started afterwards on the same store refuses the other fork too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_sharing_a_store_never_both_witness_a_fork() {
    let (first, _dir) = witness_state().await;
    let base = chrono::Utc::now() - chrono::Duration::hours(1);

    for round in 0..8 {
        // Each round on its own identity, so each starts from one witnessed
        // first entry.
        let record = witness_ops::create_witness(&first.witnesses_ks, &first.witness_keys, None)
            .await
            .unwrap();
        let left = witnessed_branch(&record.witness_id, base, 0).await;
        let right = witnessed_branch(&record.witness_id, base, 7).await;
        // Both branches start from the same first entry: the same versionId.
        // Its proof carries the second it was signed in, so two builds of it
        // can differ there; the right branch takes the left's copy, so the
        // shared entry is byte-identical whatever the clock did.
        let version_id = |log: &str| -> Value {
            serde_json::from_str::<Value>(log.lines().next().unwrap()).unwrap()["versionId"].clone()
        };
        assert_eq!(version_id(&left[0]), version_id(&right[0]), "one DID");
        let right: Vec<String> = right
            .iter()
            .map(|log| {
                std::iter::once(left[0].as_str())
                    .chain(log.lines().skip(1))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .collect();
        assert_eq!(left[0], right[0], "one DID");
        assert_ne!(left[1], right[1], "two histories");
        sign_ok(&first, &record.witness_id, &left[0]).await;

        let mut second = first.clone();
        second.sign_lock = Arc::new(tokio::sync::Mutex::new(()));
        // One process asked for the left fork's second entry, the other for
        // the right fork's third: both extend the shared first entry.
        let (a, b) = tokio::join!(
            try_sign(&first, &record.witness_id, &left[1]),
            try_sign(&second, &record.witness_id, &right[2]),
        );
        assert!(!(a && b), "round {round}: both forks were witnessed");
        assert!(a || b, "round {round}: neither fork was witnessed");

        // A process started later on the same store keeps to the fork
        // already witnessed.
        let mut restarted = first.clone();
        restarted.sign_lock = Arc::new(tokio::sync::Mutex::new(()));
        let (signed, other) = if a {
            (&left[1], &right[2])
        } else {
            (&right[2], &left[1])
        };
        assert!(!try_sign(&restarted, &record.witness_id, other).await);
        assert!(try_sign(&restarted, &record.witness_id, signed).await);
    }
}

// ---------------------------------------------------------------------------
// A `service` entry may request signatures and nothing else
// ---------------------------------------------------------------------------

fn service_caller() -> (String, Secret) {
    signer(64)
}

async fn add_service_entry(state: &AppState) {
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: service_caller().0,
            role: Role::Service,
            label: None,
            created_at: 1_700_000_000,
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        },
    )
    .await
    .unwrap();
}

/// A `service` caller has the witness sign, on every transport.
#[tokio::test]
async fn a_service_entry_may_request_a_signature() {
    for via in VIAS {
        let (state, _dir) = witness_state().await;
        add_service_entry(&state).await;
        let (record, log) = identity_and_log(&state).await;
        let svc = service_caller();
        let reply = deliver(
            &state,
            via,
            &svc.0,
            signed(
                sign::Payload::TYPE_URI,
                &svc,
                sign_payload(&record.witness_id, &log),
            )
            .await,
        )
        .await
        .expect("answered");
        assert_eq!(
            reply["type"],
            format!("{}#response", sign::Payload::TYPE_URI),
            "{via:?}: {reply}"
        );
        signed_by_the_witness(&reply, &svc.0);
        assert!(reply["payload"]["proof"].is_object(), "{reply}");
    }
}

/// A `service` caller cannot create, list or delete witness identities (no
/// reply: refused before its proof is checked), nor grant, revoke another's
/// entry, or change a role (a signed `permissionDenied`). Nothing changes.
#[tokio::test]
async fn a_service_entry_cannot_administer_keys_or_the_acl() {
    use did_hosting_common::tasks::acl::{change_role, grant, revoke};
    for via in VIAS {
        let (state, _dir) = witness_state().await;
        add_service_entry(&state).await;
        let (record, _log) = identity_and_log(&state).await;
        let svc = service_caller();
        let before = snapshot(&state).await;

        for (type_uri, payload) in [
            (key_create::Payload::TYPE_URI, json!({})),
            (key_list::Payload::TYPE_URI, json!({})),
            (
                key_delete::Payload::TYPE_URI,
                json!({ "witnessId": record.witness_id }),
            ),
        ] {
            assert_eq!(
                deliver(&state, via, &svc.0, signed(type_uri, &svc, payload).await).await,
                None,
                "{via:?} {type_uri}: a service entry must not be answered"
            );
        }

        let subject = signer(80 + via as u8).0;
        for (type_uri, payload) in [
            (
                grant::v0_2::Payload::TYPE_URI,
                json!({ "entry": {
                    "subject": subject,
                    "role": "admin",
                    "act": { "scope": "all" },
                    "keys": { "scope": "all" },
                    "capabilities": { "scope": "ceiling" },
                } }),
            ),
            (
                revoke::v0_2::Payload::TYPE_URI,
                json!({
                    "subject": admin().0,
                    "revocation": { "kind": "entry" },
                    "reason": "test",
                }),
            ),
            (
                change_role::v0_2::Payload::TYPE_URI,
                json!({
                    "subject": svc.0,
                    "fromRole": "service",
                    "toRole": "admin",
                    "reason": "test",
                }),
            ),
        ] {
            let reply = deliver(&state, via, &svc.0, signed(type_uri, &svc, payload).await)
                .await
                .unwrap_or_else(|| panic!("{via:?} {type_uri}: refused with a reply"));
            assert_eq!(
                refused(&reply, &svc.0),
                "permissionDenied",
                "{via:?} {type_uri}: {reply}"
            );
        }

        assert_eq!(
            snapshot(&state).await,
            before,
            "{via:?}: no identity changed"
        );
        let acl = |did: String| {
            let ks = state.acl_ks.clone();
            async move {
                did_hosting_common::server::acl::get_acl_entry(&ks, &did)
                    .await
                    .unwrap()
                    .map(|e| e.role)
            }
        };
        assert_eq!(acl(subject).await, None, "{via:?}");
        assert_eq!(acl(admin().0).await, Some(Role::Admin), "{via:?}");
        assert_eq!(acl(svc.0.clone()).await, Some(Role::Service), "{via:?}");
    }
}

/// On a witness a `service` entry states that it may have any key used
/// (`keys: all`), and a grant of one must say so.
#[tokio::test]
async fn a_witness_service_entry_states_every_key() {
    use did_hosting_common::tasks::acl::grant;
    let (state, _dir) = witness_state().await;
    let a = admin();
    let entry = |subject: &str, keys: &str| {
        json!({ "entry": {
            "subject": subject,
            "role": "service",
            "act": { "scope": "all" },
            "keys": { "scope": keys },
            "capabilities": { "scope": "ceiling" },
        } })
    };

    let refused_subject = signer(90).0;
    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(
            grant::v0_2::Payload::TYPE_URI,
            &a,
            entry(&refused_subject, "none"),
        )
        .await,
    )
    .await
    .expect("answered");
    assert_eq!(refused(&reply, &a.0), "taskFailed", "{reply}");
    assert_eq!(
        reply["payload"]["details"]["reason"], "notSupportedByMaintainer",
        "a service entry with no keys is not what the witness holds: {reply}"
    );

    let subject = signer(91).0;
    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(grant::v0_2::Payload::TYPE_URI, &a, entry(&subject, "all")).await,
    )
    .await
    .expect("answered");
    let payload = answered(&reply, grant::v0_2::Payload::TYPE_URI);
    assert_eq!(payload["entry"]["keys"]["scope"], "all", "{payload}");

    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(
            acl_show::v0_2::Payload::TYPE_URI,
            &a,
            json!({ "subject": subject }),
        )
        .await,
    )
    .await
    .expect("answered");
    let payload = answered(&reply, acl_show::v0_2::Payload::TYPE_URI);
    assert_eq!(payload["entry"]["keys"]["scope"], "all", "{payload}");
    assert_eq!(payload["entry"]["role"], "service", "{payload}");
}

/// A grant on a witness stating a key list is refused: the witness holds
/// `all` or `none`, never a list.
#[tokio::test]
async fn a_witness_grant_with_listed_keys_is_refused() {
    use did_hosting_common::tasks::acl::grant;
    let (state, _dir) = witness_state().await;
    let a = admin();
    let subject = signer(92).0;
    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(
            grant::v0_2::Payload::TYPE_URI,
            &a,
            json!({ "entry": {
                "subject": subject,
                "role": "service",
                "act": { "scope": "all" },
                "keys": { "scope": "listed", "keys": ["z6MkSomeWitnessKey"] },
                "capabilities": { "scope": "ceiling" },
            } }),
        )
        .await,
    )
    .await
    .expect("answered");
    assert_eq!(refused(&reply, &a.0), "taskFailed", "{reply}");
    assert!(
        did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &subject)
            .await
            .unwrap()
            .is_none()
    );
}

/// The migration path for an existing caller: an admin moves it from
/// `admin` to `service`, and it can still request signatures but no longer
/// administer the witness.
#[tokio::test]
async fn an_admin_moved_to_service_still_signs_and_no_longer_administers() {
    use did_hosting_common::tasks::acl::change_role;
    let (state, _dir) = witness_state().await;
    let caller = service_caller();
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: caller.0.clone(),
            role: Role::Admin,
            label: None,
            created_at: 1_700_000_000,
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        },
    )
    .await
    .unwrap();
    let a = admin();
    let reply = deliver(
        &state,
        Via::Https,
        &a.0,
        signed(
            change_role::v0_2::Payload::TYPE_URI,
            &a,
            json!({
                "subject": caller.0,
                "fromRole": "admin",
                "toRole": "service",
                "reason": "signatures only",
            }),
        )
        .await,
    )
    .await
    .expect("answered");
    answered(&reply, change_role::v0_2::Payload::TYPE_URI);

    let (record, log) = identity_and_log(&state).await;
    let reply = deliver(
        &state,
        Via::Https,
        &caller.0,
        signed(
            sign::Payload::TYPE_URI,
            &caller,
            sign_payload(&record.witness_id, &log),
        )
        .await,
    )
    .await
    .expect("answered");
    assert_eq!(
        reply["type"],
        format!("{}#response", sign::Payload::TYPE_URI),
        "{reply}"
    );
    assert_eq!(
        deliver(
            &state,
            Via::Https,
            &caller.0,
            signed(
                key_delete::Payload::TYPE_URI,
                &caller,
                json!({ "witnessId": record.witness_id }),
            )
            .await,
        )
        .await,
        None
    );
}

/// A `service` caller may read its own entry but not list the ACL or read
/// another member's entry.
#[tokio::test]
async fn a_service_entry_cannot_read_the_acl() {
    let (state, _dir) = witness_state().await;
    add_service_entry(&state).await;
    let svc = service_caller();
    for (type_uri, payload) in [
        (acl_list::v0_3::Payload::TYPE_URI, json!({})),
        (
            acl_show::v0_2::Payload::TYPE_URI,
            json!({ "subject": admin().0 }),
        ),
    ] {
        let reply = deliver(
            &state,
            Via::Https,
            &svc.0,
            signed(type_uri, &svc, payload).await,
        )
        .await
        .expect("answered");
        assert_eq!(
            refused(&reply, &svc.0),
            "permissionDenied",
            "{type_uri}: {reply}"
        );
    }
    let reply = deliver(
        &state,
        Via::Https,
        &svc.0,
        signed(
            acl_show::v0_2::Payload::TYPE_URI,
            &svc,
            json!({ "subject": svc.0 }),
        )
        .await,
    )
    .await
    .expect("answered");
    assert_eq!(
        reply["type"],
        format!("{}#response", acl_show::v0_2::Payload::TYPE_URI),
        "{reply}"
    );
}

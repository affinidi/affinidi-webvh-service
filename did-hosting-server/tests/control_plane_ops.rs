//! Integration tests for the control-plane → edge operations (sync, domain).
//!
//! Exercises `did_hosting_server::messaging::dispatch_control_plane_op` — the
//! entry both the DIDComm envelope route and the TSP handler call — end to
//! end: signed-document verification (`verify_control_plane`) → the `do_*`
//! core → store mutation, without a mediator. Each refusal the edge must make
//! has a test beside the normal flow it guards.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use affinidi_data_integrity::DidKeyResolver;
use affinidi_secrets_resolver::secrets::Secret;
use did_hosting_common::did::{DidDocumentOptions, build_did_document};
use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::didcomm_types::{
    MSG_DOMAIN_ASSIGN, MSG_DOMAIN_ASSIGN_ACK, MSG_SYNC_BATCH, MSG_SYNC_BATCH_ACK, MSG_SYNC_DELETE,
    MSG_SYNC_UPDATE, MSG_SYNC_UPDATE_ACK,
};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS, Store};
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
use did_hosting_common::server::trust_tasks::send::{build_request, build_signed_request};
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::messaging::{ControlPlaneReply, dispatch_control_plane_op};
use did_hosting_server::server::AppState;
use serde_json::{Value, json};

const SERVER_DID: &str = "did:webvh:test:server.example.com";

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

fn verifier() -> TransportBoundVerifier {
    TransportBoundVerifier::with_resolver(Arc::new(DidKeyResolver))
}

/// Server `AppState` with the control plane configured, so
/// `verify_control_plane` expects documents signed by `control()`.
async fn make_state() -> (AppState, tempfile::TempDir) {
    let (control_did, _) = control();
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
        server_did: Some(SERVER_DID.into()),
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
        trust_tasks_verifier: None,
        secrets_resolver: None,
        identity: None,
        didcomm_service: std::sync::Arc::new(std::sync::OnceLock::new()),
        jwt_keys: None,
        signing_key_bytes: None,
        http_client: reqwest::Client::new(),
        stats_collector: None,
        did_cache: Arc::new(ContentCache::new(Duration::from_secs(60))),
        trusted_proxy_cidrs: Arc::new(Vec::new()),
    };
    (state, dir)
}

/// A first webvh log for `mnemonic`, plus the state to extend it with.
async fn new_log(mnemonic: &str) -> (didwebvh_rs::DIDWebVHState, Secret) {
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
    let mut state = didwebvh_rs::DIDWebVHState::default();
    state
        .create_log_entry(Some(hours_ago(3)), &doc, &params(&signing), &signing)
        .await
        .expect("create webvh log entry");
    (state, signing)
}

/// Each version's `versionTime` must be strictly later than the last, at
/// second resolution — so tests date their entries explicitly rather than
/// racing the clock.
fn hours_ago(hours: i64) -> chrono::DateTime<chrono::FixedOffset> {
    (chrono::Utc::now() - chrono::Duration::hours(hours)).fixed_offset()
}

fn params(signing: &Secret) -> didwebvh_rs::parameters::Parameters {
    didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![
            signing.get_public_keymultibase().unwrap().into(),
        ])),
        ..Default::default()
    }
}

/// Append a new version of the current document, dated `hours` ago.
async fn append(state: &mut didwebvh_rs::DIDWebVHState, signing: &Secret, hours: i64) {
    // The resolved document (SCID filled in), not the genesis template.
    let last = jsonl(state).lines().last().unwrap().to_string();
    let current: Value = serde_json::from_str::<Value>(&last).unwrap()["state"].clone();
    state
        .create_log_entry(Some(hours_ago(hours)), &current, &params(signing), signing)
        .await
        .expect("append webvh log entry");
}

fn jsonl(state: &didwebvh_rs::DIDWebVHState) -> String {
    state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn did_id(log: &str) -> String {
    did_hosting_common::did_ops::extract_did_id(log).expect("log has a DID")
}

/// A valid one-entry `did.jsonl` for `mnemonic`.
async fn valid_did_log(mnemonic: &str) -> (String, String) {
    let (state, _) = new_log(mnemonic).await;
    let log = jsonl(&state);
    (did_id(&log), log)
}

fn update_body(mnemonic: &str, did_id: &str, log_content: &str) -> Value {
    json!({
        "mnemonic": mnemonic,
        "did_id": did_id,
        "log_content": log_content,
        "version_count": log_content.lines().filter(|l| !l.trim().is_empty()).count(),
    })
}

/// A control-plane operation document, signed by `key` (the control plane
/// unless a test says otherwise).
async fn signed_op(
    type_uri: &str,
    key: &(String, Secret),
    payload: Value,
) -> trust_tasks_rs::TrustTask<Value> {
    build_signed_request(type_uri, &key.0, SERVER_DID, payload, &key.1)
        .await
        .expect("signed request")
}

async fn apply(
    state: &AppState,
    doc: trust_tasks_rs::TrustTask<Value>,
) -> trust_tasks_rs::TrustTask<Value> {
    let sender = doc.issuer.clone();
    dispatch_control_plane_op(state, sender.as_deref(), doc, &verifier())
        .await
        .expect("a control-plane op produces a reply")
        .into_document()
}

fn is_error(reply: &trust_tasks_rs::TrustTask<Value>) -> bool {
    reply.type_uri.to_string().contains("/trust-task-error/")
}

async fn stored(state: &AppState, mnemonic: &str) -> Option<DidRecord> {
    state.dids_ks.get(did_key(mnemonic)).await.unwrap()
}

// ---------------------------------------------------------------------------
// Normal flows
// ---------------------------------------------------------------------------

/// A sync-update signed by the control plane is applied and acknowledged.
#[tokio::test]
async fn signed_sync_update_from_control_plane_is_applied() {
    let (state, _dir) = make_state().await;
    let (did_id, log) = valid_did_log("alice").await;

    let reply = apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", &did_id, &log),
        )
        .await,
    )
    .await;
    assert_eq!(reply.type_uri.to_string(), MSG_SYNC_UPDATE_ACK, "{reply:?}");
    assert_eq!(reply.payload["status"], "applied");
    assert_eq!(
        stored(&state, "alice").await.expect("stored").version_count,
        1
    );
}

/// A batch applies every entry; a malformed entry is skipped without
/// stranding the rest.
#[tokio::test]
async fn signed_sync_batch_applies_good_entries_and_skips_bad_ones() {
    let (state, _dir) = make_state().await;
    let (alice_id, alice_log) = valid_did_log("alice").await;
    let (bob_id, bob_log) = valid_did_log("bob").await;
    let payload = json!({ "updates": [
        update_body("alice", &alice_id, &alice_log),
        update_body("bob", &bob_id, &bob_log),
        // Missing `mnemonic` — `apply_sync_update_body` rejects it.
        { "did_id": "did:webvh:x:server.example.com:ghost", "log_content": "{}", "version_count": 1 },
    ]});

    let reply = apply(&state, signed_op(MSG_SYNC_BATCH, &control(), payload).await).await;
    assert_eq!(reply.type_uri.to_string(), MSG_SYNC_BATCH_ACK);
    assert_eq!(reply.payload["applied"], 2);
    assert_eq!(reply.payload["failed"], 1);
    for m in ["alice", "bob"] {
        assert!(
            stored(&state, m).await.is_some(),
            "batched DID {m} landed in the store"
        );
    }
}

/// A log that strictly extends the held one (a new version) is applied.
#[tokio::test]
async fn a_strict_extension_of_the_held_log_is_applied() {
    let (state, _dir) = make_state().await;
    let (mut webvh, key) = new_log("alice").await;
    let v1 = jsonl(&webvh);
    let id = did_id(&v1);
    apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v1)).await,
    )
    .await;

    append(&mut webvh, &key, 1).await;
    let v2 = jsonl(&webvh);
    let reply = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v2)).await,
    )
    .await;
    assert_eq!(reply.type_uri.to_string(), MSG_SYNC_UPDATE_ACK, "{reply:?}");
    assert_eq!(stored(&state, "alice").await.unwrap().version_count, 2);
}

#[tokio::test]
async fn signed_sync_delete_removes_the_did() {
    let (state, _dir) = make_state().await;
    let (did_id, log) = valid_did_log("alice").await;
    apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", &did_id, &log),
        )
        .await,
    )
    .await;

    let reply = apply(
        &state,
        signed_op(MSG_SYNC_DELETE, &control(), json!({ "mnemonic": "alice" })).await,
    )
    .await;
    assert!(!is_error(&reply), "{reply:?}");
    assert!(stored(&state, "alice").await.is_none());
}

#[tokio::test]
async fn signed_domain_assign_is_applied() {
    let (state, _dir) = make_state().await;
    let reply = apply(
        &state,
        signed_op(
            MSG_DOMAIN_ASSIGN,
            &control(),
            json!({ "domain": "tenant.example" }),
        )
        .await,
    )
    .await;
    assert_eq!(
        reply.type_uri.to_string(),
        MSG_DOMAIN_ASSIGN_ACK,
        "{reply:?}"
    );
    assert_eq!(reply.payload["status"], "assigned");
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Unsigned — the shape every control plane used to send — is refused, even
/// though the reported sender is the control plane.
#[tokio::test]
async fn an_unsigned_sync_update_is_refused() {
    let (state, _dir) = make_state().await;
    let (control_did, _) = control();
    let (did_id, log) = valid_did_log("mallory").await;
    let doc = build_request(
        MSG_SYNC_UPDATE,
        &control_did,
        SERVER_DID,
        update_body("mallory", &did_id, &log),
    )
    .unwrap();

    let reply = dispatch_control_plane_op(&state, Some(&control_did), doc, &verifier())
        .await
        .unwrap();
    let ControlPlaneReply::Unverified(reply) = reply else {
        panic!("an unsigned document must not verify: {reply:?}");
    };
    assert!(is_error(&reply));
    assert_eq!(reply.payload["code"], "proofRequired");
    assert!(stored(&state, "mallory").await.is_none(), "nothing applied");
}

/// A document validly signed by someone else, reported as coming from the
/// control plane, is refused: the proof — not the transport — names the peer.
#[tokio::test]
async fn a_document_signed_by_another_peer_is_refused_whatever_the_transport_reports() {
    let (state, _dir) = make_state().await;
    let (control_did, _) = control();
    let attacker = signer(66);
    let (did_id, log) = valid_did_log("mallory").await;
    let doc = signed_op(
        MSG_SYNC_UPDATE,
        &attacker,
        update_body("mallory", &did_id, &log),
    )
    .await;

    let reply = dispatch_control_plane_op(&state, Some(&control_did), doc, &verifier())
        .await
        .unwrap();
    let ControlPlaneReply::Unverified(reply) = reply else {
        panic!("another peer's document must not verify: {reply:?}");
    };
    assert!(is_error(&reply), "{reply:?}");
    assert!(stored(&state, "mallory").await.is_none(), "nothing applied");
}

/// The destructive ops get the same refusal.
#[tokio::test]
async fn an_unauthorised_delete_or_purge_is_refused() {
    let (state, _dir) = make_state().await;
    let (did_id, log) = valid_did_log("alice").await;
    apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", &did_id, &log),
        )
        .await,
    )
    .await;

    let attacker = signer(66);
    let reply = apply(
        &state,
        signed_op(MSG_SYNC_DELETE, &attacker, json!({ "mnemonic": "alice" })).await,
    )
    .await;
    assert!(is_error(&reply));
    assert!(stored(&state, "alice").await.is_some(), "the DID survived");
}

/// A document the control plane signed for a different edge cannot be
/// replayed here.
#[tokio::test]
async fn a_document_addressed_to_another_server_is_refused() {
    let (state, _dir) = make_state().await;
    let (control_did, control_key) = control();
    let (did_id, log) = valid_did_log("alice").await;
    let doc = build_signed_request(
        MSG_SYNC_UPDATE,
        &control_did,
        "did:webvh:test:other-server.example.com",
        update_body("alice", &did_id, &log),
        &control_key,
    )
    .await
    .unwrap();

    let reply = apply(&state, doc).await;
    assert!(is_error(&reply));
    assert!(stored(&state, "alice").await.is_none());
}

/// The same signed document twice: the second delivery is a replay.
#[tokio::test]
async fn a_replayed_document_is_refused() {
    let (state, _dir) = make_state().await;
    let (did_id, log) = valid_did_log("alice").await;
    let doc = signed_op(
        MSG_SYNC_UPDATE,
        &control(),
        update_body("alice", &did_id, &log),
    )
    .await;

    let first = apply(&state, doc.clone()).await;
    assert!(!is_error(&first), "{first:?}");
    let second = apply(&state, doc).await;
    assert!(is_error(&second));
    assert_eq!(second.payload["code"], "idConflict");
}

/// Rolling a DID back to an earlier log — e.g. to before a key rotation — is
/// refused even from the genuine control plane.
#[tokio::test]
async fn a_rollback_to_an_earlier_log_is_refused() {
    let (state, _dir) = make_state().await;
    let (mut webvh, key) = new_log("alice").await;
    let v1 = jsonl(&webvh);
    let id = did_id(&v1);
    append(&mut webvh, &key, 1).await;
    let v2 = jsonl(&webvh);

    apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v2)).await,
    )
    .await;
    let reply = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v1)).await,
    )
    .await;
    assert!(is_error(&reply), "{reply:?}");
    assert_eq!(
        stored(&state, "alice").await.unwrap().version_count,
        2,
        "still at v2"
    );
}

/// Once a DID is deactivated, no further log is accepted for it: not a
/// history that drops the deactivation, and not one that appends past it.
#[tokio::test]
async fn a_deactivated_did_cannot_be_reactivated() {
    let (state, _dir) = make_state().await;
    let (mut webvh, key) = new_log("alice").await;
    let id = did_id(&jsonl(&webvh));
    append(&mut webvh, &key, 1).await;
    let v2 = jsonl(&webvh);
    webvh.deactivate(&key).await.expect("deactivate");
    let deactivated = jsonl(&webvh);
    let reply = apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", &id, &deactivated),
        )
        .await,
    )
    .await;
    assert!(
        !is_error(&reply),
        "the deactivation itself is applied: {reply:?}"
    );

    // Back to the pre-deactivation history.
    let back = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v2)).await,
    )
    .await;
    assert!(is_error(&back), "{back:?}");
    // An entry appended past the deactivation.
    let v2_entry = v2.lines().last().unwrap();
    let past = format!("{deactivated}\n{v2_entry}");
    let forward = apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", &id, &past),
        )
        .await,
    )
    .await;
    assert!(is_error(&forward), "{forward:?}");

    let held = state
        .dids_ks
        .get_raw(did_hosting_common::did_ops::content_log_key("alice"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(held).unwrap(),
        deactivated,
        "the deactivated log is still served"
    );
}

/// A log whose proof chain does not verify is refused, whoever signed the
/// push.
#[tokio::test]
async fn a_log_with_a_broken_chain_is_refused() {
    let (state, _dir) = make_state().await;
    let (did_id, log) = valid_did_log("alice").await;
    let tampered = log.replacen("server.example.com", "evil.example.com", 1);
    let reply = apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", &did_id, &tampered),
        )
        .await,
    )
    .await;
    assert!(is_error(&reply), "{reply:?}");
    assert!(stored(&state, "alice").await.is_none());
}

/// A valid log filed under the wrong DID identifier is refused.
#[tokio::test]
async fn a_log_for_a_different_did_is_refused() {
    let (state, _dir) = make_state().await;
    let (_, log) = valid_did_log("alice").await;
    let reply = apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", "did:webvh:other:server.example.com:alice", &log),
        )
        .await,
    )
    .await;
    assert!(is_error(&reply), "{reply:?}");
}

/// A type that is not a control-plane operation is not handled here.
#[tokio::test]
async fn a_non_control_plane_type_returns_none() {
    let (state, _dir) = make_state().await;
    let doc = signed_op(
        "https://trusttasks.org/spec/did-management/server/health/0.1",
        &control(),
        json!({}),
    )
    .await;
    assert!(
        dispatch_control_plane_op(&state, None, doc, &verifier())
            .await
            .is_none()
    );
}

/// The edge's acks are signed by the edge for the control plane
/// (`proofPurpose: authentication`), so the control plane can attribute them.
#[tokio::test]
async fn acks_are_signed_by_the_edge() {
    use did_hosting_common::server::identity::ServiceIdentity;
    use did_hosting_common::server::trust_tasks::verify_sender_bound;

    let (mut state, _dir) = make_state().await;
    let (edge, edge_key) = signer(91);
    let mut cfg = (*state.config).clone();
    cfg.server_did = Some(edge.clone());
    state.config = Arc::new(cfg);
    state.identity = Some(
        ServiceIdentity::from_signing_secret(&edge, edge_key)
            .await
            .unwrap(),
    );

    let (control_did, control_key) = control();
    let (did_id, log) = valid_did_log("alice").await;
    let doc = build_signed_request(
        MSG_SYNC_UPDATE,
        &control_did,
        &edge,
        update_body("alice", &did_id, &log),
        &control_key,
    )
    .await
    .unwrap();
    let reply = apply(&state, doc).await;
    assert_eq!(reply.type_uri.to_string(), MSG_SYNC_UPDATE_ACK, "{reply:?}");

    let sealed = did_hosting_server::messaging::seal_reply(&state, reply)
        .await
        .expect("sealed");
    let sealed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(sealed).unwrap();
    verify_sender_bound(&sealed, Some(&edge), None, &control_did, &verifier())
        .await
        .expect("the ack is signed by the edge for the control plane");
}

/// Delete, then re-sync an older version of the same DID: refused. The edge's
/// high-water mark for the DID survives the delete, so a re-created DID must
/// extend everything it ever served.
#[tokio::test]
async fn a_rollback_through_delete_and_resync_is_refused() {
    let (state, _dir) = make_state().await;
    let (mut webvh, key) = new_log("alice").await;
    let v1 = jsonl(&webvh);
    let id = did_id(&v1);
    append(&mut webvh, &key, 1).await;
    let v2 = jsonl(&webvh);
    apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v2)).await,
    )
    .await;
    let del = apply(
        &state,
        signed_op(MSG_SYNC_DELETE, &control(), json!({"mnemonic": "alice"})).await,
    )
    .await;
    assert!(!is_error(&del), "{del:?}");

    let back = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v1)).await,
    )
    .await;
    assert!(
        is_error(&back),
        "a pre-rotation log must not come back: {back:?}"
    );
    assert!(
        stored(&state, "alice").await.is_none(),
        "nothing re-created"
    );

    // Re-creating it at (or beyond) the high-water mark is fine.
    let again = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v2)).await,
    )
    .await;
    assert!(!is_error(&again), "{again:?}");
}

/// Delete a deactivated DID, then re-sync its pre-deactivation history:
/// refused. A deactivated DID stays deactivated.
#[tokio::test]
async fn a_deactivated_did_cannot_be_resurrected_through_delete() {
    let (state, _dir) = make_state().await;
    let (mut webvh, key) = new_log("alice").await;
    let id = did_id(&jsonl(&webvh));
    append(&mut webvh, &key, 1).await;
    let v2 = jsonl(&webvh);
    webvh.deactivate(&key).await.expect("deactivate");
    let deactivated = jsonl(&webvh);
    apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", &id, &deactivated),
        )
        .await,
    )
    .await;
    apply(
        &state,
        signed_op(MSG_SYNC_DELETE, &control(), json!({"mnemonic": "alice"})).await,
    )
    .await;

    let back = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v2)).await,
    )
    .await;
    assert!(is_error(&back), "{back:?}");
    assert!(stored(&state, "alice").await.is_none());
}

/// A valid log cannot be filed under a slot it does not resolve at.
#[tokio::test]
async fn a_valid_log_filed_under_another_slot_is_refused() {
    let (state, _dir) = make_state().await;
    let (alice_id, alice_log) = valid_did_log("alice").await;
    let r = apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("bob", &alice_id, &alice_log),
        )
        .await,
    )
    .await;
    assert!(is_error(&r), "{r:?}");
    assert!(stored(&state, "bob").await.is_none());
}

/// ...nor for a host this server does not serve.
#[tokio::test]
async fn a_log_for_a_host_this_server_does_not_serve_is_refused() {
    let (mut state, _dir) = make_state().await;
    let mut cfg = (*state.config).clone();
    cfg.public_url = Some("https://other-host.example".into());
    state.config = Arc::new(cfg);
    let (id, log) = valid_did_log("alice").await;
    let r = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &log)).await,
    )
    .await;
    assert!(is_error(&r), "{r:?}");
}

/// A different DID may take over a slot whose DID was deleted — it is a new
/// identity with its own history — but the old DID still cannot come back
/// rolled back.
#[tokio::test]
async fn a_new_did_may_reuse_a_deleted_slot() {
    let (state, _dir) = make_state().await;
    let (id, log) = valid_did_log("alice").await;
    apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &log)).await,
    )
    .await;
    apply(
        &state,
        signed_op(MSG_SYNC_DELETE, &control(), json!({"mnemonic": "alice"})).await,
    )
    .await;

    // A different key → a different SCID at the same slot.
    let secret = Secret::generate_ed25519(None, Some(&[8u8; 32]));
    let pk_mb = secret.get_public_keymultibase().unwrap();
    let mut signing = secret.clone();
    signing.id = format!("did:key:{pk_mb}#{pk_mb}");
    let doc = build_did_document(
        "server.example.com",
        "alice",
        &pk_mb,
        &DidDocumentOptions::default(),
    );
    let mut other = didwebvh_rs::DIDWebVHState::default();
    other
        .create_log_entry(Some(hours_ago(2)), &doc, &params(&signing), &signing)
        .await
        .unwrap();
    let other_log = jsonl(&other);
    let other_id = did_id(&other_log);
    assert_ne!(other_id, id);
    let r = apply(
        &state,
        signed_op(
            MSG_SYNC_UPDATE,
            &control(),
            update_body("alice", &other_id, &other_log),
        )
        .await,
    )
    .await;
    assert!(!is_error(&r), "{r:?}");
}

/// A document that did not verify as the control plane's gets no reply at all
/// — not a signed refusal (which would settle an op the control plane never
/// sent) and not an unsigned one.
#[tokio::test]
async fn an_unverified_document_gets_no_reply() {
    use did_hosting_common::server::identity::ServiceIdentity;

    let (mut state, _dir) = make_state().await;
    let (edge, edge_key) = signer(92);
    let mut cfg = (*state.config).clone();
    cfg.server_did = Some(edge.clone());
    state.config = Arc::new(cfg);
    state.identity = Some(
        ServiceIdentity::from_signing_secret(&edge, edge_key)
            .await
            .unwrap(),
    );
    state.trust_tasks_verifier = Some(Arc::new(verifier()));
    let (control_did, control_key) = control();
    let attacker = signer(66);
    let (did_id, log) = valid_did_log("mallory").await;

    // Signed by another peer, reported as the control plane.
    let forged = build_signed_request(
        MSG_SYNC_UPDATE,
        &attacker.0,
        &edge,
        update_body("mallory", &did_id, &log),
        &attacker.1,
    )
    .await
    .unwrap();
    assert!(
        did_hosting_server::messaging::dispatch_inbound_document(
            &state,
            Some(&control_did),
            forged
        )
        .await
        .is_none(),
        "a forged op is dropped silently"
    );
    // A ping from a stranger is not answered either.
    let ping = build_signed_request(
        did_hosting_common::didcomm_types::MSG_HEALTH_PING,
        &attacker.0,
        &edge,
        json!({}),
        &attacker.1,
    )
    .await
    .unwrap();
    assert!(
        did_hosting_server::messaging::dispatch_inbound_document(&state, Some(&attacker.0), ping)
            .await
            .is_none(),
        "a stranger's ping is not answered"
    );

    // The genuine control plane's op still gets its signed ack.
    let genuine = build_signed_request(
        MSG_SYNC_UPDATE,
        &control_did,
        &edge,
        update_body("mallory", &did_id, &log),
        &control_key,
    )
    .await
    .unwrap();
    let reply = did_hosting_server::messaging::dispatch_inbound_document(
        &state,
        Some(&control_did),
        genuine,
    )
    .await
    .expect("the control plane's op is answered");
    assert_eq!(reply["type"], MSG_SYNC_UPDATE_ACK);
    assert!(reply.get("proof").is_some(), "{reply}");
}

fn admin() -> did_hosting_server::auth::AuthClaims {
    did_hosting_server::auth::AuthClaims {
        did: "did:key:admin".into(),
        role: did_hosting_server::acl::Role::Admin,
        session_id: String::new(),
        session_pubkey_b58btc: None,
        amr: vec!["did".into()],
        acr: "aal1".into(),
    }
}

/// The edge's own `PUT /api/dids/{mnemonic}` is held to the same history rule
/// as a sync: it cannot roll a DID back, and after a delete it cannot bring
/// back a history older than the one the edge last served.
#[tokio::test]
async fn a_rest_publish_cannot_roll_back_the_served_history() {
    use did_hosting_server::did_ops::{create_did, publish_did};

    let (state, _dir) = make_state().await;
    let (mut webvh, key) = new_log("alice").await;
    let v1 = jsonl(&webvh);
    let id = did_id(&v1);
    append(&mut webvh, &key, 1).await;
    let v2 = jsonl(&webvh);
    append(&mut webvh, &key, 0).await;
    let v3 = jsonl(&webvh);

    let synced = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v2)).await,
    )
    .await;
    assert!(!is_error(&synced), "{synced:?}");

    // Rollback over the held log.
    let err = publish_did(&admin(), &state, "alice", &v1)
        .await
        .err()
        .expect("a rollback is refused");
    assert!(err.to_string().contains("not an extension"), "{err}");

    // Delete, re-create the slot, and try the older history again.
    let del = apply(
        &state,
        signed_op(MSG_SYNC_DELETE, &control(), json!({"mnemonic": "alice"})).await,
    )
    .await;
    assert!(!is_error(&del), "{del:?}");
    create_did(&admin(), &state, Some("alice"))
        .await
        .expect("slot re-created");
    let err = publish_did(&admin(), &state, "alice", &v1)
        .await
        .err()
        .expect("the high-water mark survives the delete");
    assert!(err.to_string().contains("not an extension"), "{err}");

    // A strict extension is fine, and becomes the new high-water mark.
    publish_did(&admin(), &state, "alice", &v3)
        .await
        .expect("an extension is published");
    let back = apply(
        &state,
        signed_op(MSG_SYNC_UPDATE, &control(), update_body("alice", &id, &v2)).await,
    )
    .await;
    assert!(
        is_error(&back),
        "a sync cannot undo the REST publish: {back:?}"
    );
}

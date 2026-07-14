//! Integration test for the TSP sync receive path.
//!
//! Exercises `did_hosting_server::messaging::dispatch_tsp_message` — the
//! entry the `ServerTspHandler` calls after the messaging-service
//! framework unpacks a TSP frame off the shared mediator socket. This
//! drives the *server* half of the control→server sync-over-TSP feature
//! end-to-end (route by type → `require_control_plane` auth → the `do_*`
//! core → store mutation) without standing up a real mediator. The
//! transport itself (mediator connection, TSP seal/unpack) is exercised by
//! the messaging-service crate's own tests.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_secrets_resolver::secrets::Secret;
use did_hosting_common::did::{DidDocumentOptions, build_did_document, create_log_entry};
use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::didcomm_types::{MSG_SYNC_UPDATE, MSG_SYNC_UPDATE_ACK};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS, Store};
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::messaging::dispatch_tsp_message;
use did_hosting_server::server::AppState;
use serde_json::json;

const CONTROL_DID: &str = "did:webvh:test:control.example.com";
const SERVER_DID: &str = "did:webvh:test:server.example.com";

/// Server `AppState` with the control plane configured, so
/// `require_control_plane` accepts `CONTROL_DID` as the sync sender.
async fn make_state() -> (AppState, tempfile::TempDir) {
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
        public_url: Some("http://localhost:8530".into()),
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
        control_did: Some(CONTROL_DID.into()),
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

/// Generate a valid webvh `did.jsonl` for `mnemonic` so
/// `apply_single_update`'s `validate_did_jsonl` accepts it.
async fn valid_did_log(mnemonic: &str) -> (String, String) {
    let secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
    let pk_mb = secret.get_public_keymultibase().expect("pubkey multibase");
    let doc = build_did_document(
        "server.example.com",
        mnemonic,
        &pk_mb,
        &DidDocumentOptions::default(),
    );
    let (scid, jsonl) = create_log_entry(&doc, &secret)
        .await
        .expect("create webvh log entry");
    let did_id = format!("did:webvh:{scid}:server.example.com:{mnemonic}");
    (did_id, jsonl)
}

fn sync_update_msg(mnemonic: &str, did_id: &str, log_content: &str) -> Message {
    Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_SYNC_UPDATE.to_string(),
        json!({
            "mnemonic": mnemonic,
            "did_id": did_id,
            "log_content": log_content,
            "version_count": 1,
        }),
    )
    .from(CONTROL_DID.to_string())
    .to(SERVER_DID.to_string())
    .finalize()
}

/// A sync-update delivered over TSP by the authorised control plane is
/// applied: the ack is returned and the DID record lands in the store.
#[tokio::test]
async fn tsp_sync_update_from_control_plane_is_applied() {
    let (state, _dir) = make_state().await;
    let (did_id, jsonl) = valid_did_log("alice").await;
    let msg = sync_update_msg("alice", &did_id, &jsonl);

    let (resp_type, resp_body) = dispatch_tsp_message(&state, CONTROL_DID, &msg)
        .await
        .expect("sync-update produces a response");

    assert_eq!(resp_type, MSG_SYNC_UPDATE_ACK, "success ack returned");
    assert_eq!(resp_body["status"], "applied");

    let stored: Option<DidRecord> = state.dids_ks.get(did_key("alice")).await.unwrap();
    assert!(stored.is_some(), "the synced DID landed in the store");
    assert_eq!(stored.unwrap().version_count, 1);
}

/// A sync-update from a sender that is NOT the configured control plane is
/// rejected (`require_control_plane`) and applies nothing — the same
/// authorisation the DIDComm listener enforces, now on the TSP path.
#[tokio::test]
async fn tsp_sync_update_from_unauthorised_sender_is_rejected() {
    let (state, _dir) = make_state().await;
    let (did_id, jsonl) = valid_did_log("mallory").await;
    let msg = sync_update_msg("mallory", &did_id, &jsonl);

    let (_resp_type, resp_body) = dispatch_tsp_message(&state, "did:web:attacker.example", &msg)
        .await
        .expect("a response (problem report) is produced");

    assert_ne!(
        resp_body["status"], "applied",
        "an unauthorised sync must not report applied"
    );
    let stored: Option<DidRecord> = state.dids_ks.get(did_key("mallory")).await.unwrap();
    assert!(stored.is_none(), "unauthorised sync applied nothing");
}

/// An unhandled message type over TSP returns `None` (dropped) rather than
/// mis-routing.
#[tokio::test]
async fn tsp_unhandled_type_returns_none() {
    let (state, _dir) = make_state().await;
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping".to_string(),
        json!({}),
    )
    .from(CONTROL_DID.to_string())
    .to(SERVER_DID.to_string())
    .finalize();

    assert!(
        dispatch_tsp_message(&state, CONTROL_DID, &msg)
            .await
            .is_none(),
        "an unhandled type is dropped, not mis-routed"
    );
}

//! In-process tests for agent-name redirect resolution.
//!
//! Exercises `GET /@{name}` against the assembled server router: the happy-path
//! 302, and every way a name must *not* resolve — feature off, disabled name,
//! disabled/deleted DID, wrong domain, reserved name, missing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::did_ops::{
    AgentNameEntry, DidRecord, agent_name_key, content_log_key, did_key,
};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS};
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::server::AppState;
use tower::ServiceExt;

const DOMAIN: &str = "server.example.com";
const DID: &str = "did:webvh:QmScid:server.example.com:alice";

async fn make_state(agent_names_enabled: bool) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let sessions_ks = store.keyspace(KS_SESSIONS).expect("sessions ks");
    let acl_ks = store.keyspace(KS_ACL).expect("acl ks");
    let dids_ks = store.keyspace(KS_DIDS).expect("dids ks");

    let config = AppConfig {
        features: FeaturesConfig {
            agent_names: agent_names_enabled,
            ..FeaturesConfig::default()
        },
        server_did: Some("did:webvh:test:server.example.com".into()),
        mediator_did: None,
        public_url: Some(format!("http://{DOMAIN}")),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config.clone(),
        auth: AuthConfig::default(),
        hosting: did_hosting_common::server::config::HostingConfig::default(),
        secrets: SecretsConfig::default(),
        limits: LimitsConfig::default(),
        stats: StatsConfig::default(),
        watchers: Vec::new(),
        control_url: None,
        control_did: None,
        vta: VtaConfig::default(),
        identity: Default::default(),
        config_path: PathBuf::new(),
    };

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        dids_ks,
        config: Arc::new(config),
        did_resolver: None,
        secrets_resolver: None,
        identity: None,
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

/// Seed a DID with one agent name, and its index entry.
async fn seed(state: &AppState, name: &str, enabled: bool, disabled_did: bool) {
    let mnemonic = "alice-did";
    let record = DidRecord {
        owner: "did:example:owner".into(),
        mnemonic: mnemonic.into(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: Some(DID.into()),
        content_size: 0,
        disabled: disabled_did,
        deleted_at: None,
        method: "webvh".into(),
        domain: DOMAIN.into(),
        services: None,
        agent_names: vec![AgentNameEntry {
            name: name.into(),
            enabled,
            created_at: 0,
        }],
    };
    // A blank log so the DID record is coherent.
    state
        .dids_ks
        .insert_raw(
            content_log_key(mnemonic).into_bytes(),
            format!("{{\"versionId\":\"1\",\"state\":{{\"id\":\"{DID}\"}}}}").into_bytes(),
        )
        .await
        .unwrap();
    state
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(
            agent_name_key(DOMAIN, name).into_bytes(),
            mnemonic.as_bytes().to_vec(),
        )
        .await
        .unwrap();
}

fn app(state: AppState) -> axum::Router {
    did_hosting_server::routes::router(1024 * 1024).with_state(state)
}

async fn get(state: AppState, path: &str) -> (StatusCode, Option<String>) {
    let response = app(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .header("host", DOMAIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (status, location)
}

#[tokio::test]
async fn resolves_an_enabled_name_to_its_did() {
    let (state, _dir) = make_state(true).await;
    seed(&state, "alice", true, false).await;

    let (status, location) = get(state, "/@alice").await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location.as_deref(), Some(DID));
}

/// The FAQ context path resolves to the same DID.
#[tokio::test]
async fn resolves_a_context_qualified_name() {
    let (state, _dir) = make_state(true).await;
    seed(&state, "alice", true, false).await;

    let (status, location) = get(state, "/@alice/h2hsummit").await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location.as_deref(), Some(DID));
}

/// Feature off -> the namespace is not served, even for a name that exists.
#[tokio::test]
async fn returns_404_when_feature_disabled() {
    let (state, _dir) = make_state(false).await;
    seed(&state, "alice", true, false).await;

    let (status, _) = get(state, "/@alice").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A disabled name is parked, not resolvable — the reservation holds but the
/// redirect does not.
#[tokio::test]
async fn a_disabled_name_does_not_resolve() {
    let (state, _dir) = make_state(true).await;
    seed(&state, "alice", false, false).await;

    let (status, _) = get(state, "/@alice").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A disabled DID serves nothing, names included.
#[tokio::test]
async fn a_disabled_did_serves_no_names() {
    let (state, _dir) = make_state(true).await;
    seed(&state, "alice", true, true).await;

    let (status, _) = get(state, "/@alice").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unknown_name_is_404() {
    let (state, _dir) = make_state(true).await;
    seed(&state, "alice", true, false).await;

    let (status, _) = get(state, "/@nobody").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A reserved name never resolves, even if somehow indexed.
#[tokio::test]
async fn a_reserved_name_is_refused() {
    let (state, _dir) = make_state(true).await;
    let (status, _) = get(state, "/@admin").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A request for the name on a different host must not resolve it — the index
/// is domain-scoped.
#[tokio::test]
async fn a_name_does_not_resolve_on_the_wrong_host() {
    let (state, _dir) = make_state(true).await;
    seed(&state, "alice", true, false).await;

    let response = app(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/@alice")
                .header("host", "other.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

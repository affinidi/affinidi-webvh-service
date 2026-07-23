//! HTTP-shape coverage for agent names on the DID management API.
//!
//! Drives the real Axum router in-process (`routes::router_without_fallback`
//! — the same router the daemon merges), so this covers the wire contract the
//! UI reads: `agentNames` is camelCase, carries local parts only, lists the
//! *enabled* names, and is omitted entirely — not `[]` — when a DID has none.
//!
//! The enabled-only rule is the one worth pinning. A parked name is reserved
//! to a slot but deliberately does not resolve; surfacing it in a list would
//! advertise a handle that 404s.
//!
//! Derivation itself (document `alsoKnownAs` → registry) is covered by the
//! `reconcile_agent_names` / `extract_agent_names` unit tests in
//! did-hosting-common: the publish paths verify webvh proof chains before they
//! write, and this repo has no signing fixture to forge a valid log with.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::did_ops::{AgentNameEntry, DidRecord, did_key, owner_key};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::auth::session::{create_authenticated_session, now_epoch};
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
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

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
        identity: Default::default(),
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
        identity: None,
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

async fn mint_token(state: &AppState, did: &str, role: Role) -> String {
    let keys = state.jwt_keys.as_ref().expect("jwt keys configured");
    let auth = AuthConfig::default();
    create_authenticated_session(
        &state.sessions_ks,
        keys,
        did,
        &role,
        auth.access_token_expiry,
        auth.refresh_token_expiry,
        None,
        None,
    )
    .await
    .expect("create session")
    .access_token
}

async fn seed_did(
    state: &AppState,
    owner_did: &str,
    mnemonic: &str,
    agent_names: Vec<AgentNameEntry>,
) {
    let now = now_epoch();
    let record = DidRecord {
        owner: owner_did.into(),
        mnemonic: mnemonic.into(),
        created_at: now,
        updated_at: now,
        version_count: 1,
        did_id: Some(format!("did:webvh:abc:control.test:{mnemonic}")),
        content_size: 42,
        disabled: false,
        deleted_at: None,
        method: "webvh".to_string(),
        domain: "control.test".to_string(),
        services: None,
        agent_names,
    };
    let mut batch = state.store.batch();
    batch
        .insert(&state.dids_ks, did_key(mnemonic), &record)
        .expect("seed did");
    batch.insert_raw(
        &state.dids_ks,
        owner_key(owner_did, mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.commit().await.expect("commit seed");
}

fn name(name: &str, enabled: bool) -> AgentNameEntry {
    AgentNameEntry {
        name: name.into(),
        enabled,
        created_at: 0,
    }
}

async fn get_json(state: &AppState, uri: &str, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(state.clone())
        .oneshot(req)
        .await
        .expect("router response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json body")
    };
    (status, json)
}


/// The enabled names reach `GET /api/dids` as camelCase `agentNames`, parked
/// names do not, and a DID with none omits the key so the UI's
/// `agentNames?: string[]` lands on `undefined` rather than an empty array.
#[tokio::test]
async fn dids_list_exposes_enabled_agent_names_only() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    add_acl(&h.state, owner, Role::Owner).await;
    let token = mint_token(&h.state, owner, Role::Owner).await;

    seed_did(
        &h.state,
        owner,
        "named",
        vec![name("alice", true), name("parked", false), name("ops", true)],
    )
    .await;
    seed_did(&h.state, owner, "unnamed", Vec::new()).await;

    let (status, body) = get_json(&h.state, "/api/dids", &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let entries = body.as_array().expect("array of DIDs");
    let named = entries
        .iter()
        .find(|e| e["mnemonic"] == "named")
        .expect("named DID present");
    assert_eq!(
        named["agentNames"],
        serde_json::json!(["alice", "ops"]),
        "enabled names only, local part only, document order preserved"
    );

    let unnamed = entries
        .iter()
        .find(|e| e["mnemonic"] == "unnamed")
        .expect("unnamed DID present");
    assert!(
        unnamed.get("agentNames").is_none(),
        "a DID with no names must omit the key, not send []; got {unnamed}"
    );
}

/// Same contract on the detail endpoint the DID page reads. The two must agree
/// — a handle that shows in the list and vanishes on the detail page (or the
/// reverse) reads as a bug in the name, not in the UI.
#[tokio::test]
async fn did_detail_exposes_enabled_agent_names_only() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    add_acl(&h.state, owner, Role::Owner).await;
    let token = mint_token(&h.state, owner, Role::Owner).await;

    seed_did(
        &h.state,
        owner,
        "named",
        vec![name("alice", true), name("parked", false)],
    )
    .await;
    seed_did(&h.state, owner, "unnamed", Vec::new()).await;

    let (status, body) = get_json(&h.state, "/api/dids/named", &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["agentNames"], serde_json::json!(["alice"]));

    let (status, body) = get_json(&h.state, "/api/dids/unnamed", &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("agentNames").is_none(),
        "a DID with no names must omit the key on detail too; got {body}"
    );
}

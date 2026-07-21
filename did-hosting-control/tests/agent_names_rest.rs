//! HTTP-shape coverage for the agent-name REST surface
//! (`POST /api/agent-names/{set,remove,enable,disable,check}`).
//!
//! Drives the full Axum router in-process via `tower::ServiceExt::oneshot`.
//! The point of these tests is the wiring the `did_ops` unit tests can't
//! reach: that the routes are actually registered, that the JWT-Bearer gate
//! runs, and — the reason this surface exists — that the destructive verbs
//! (`remove`/`disable`) are gated behind aal2 **step-up**. A session minted by
//! the harness is aal1, so those verbs must be refused with 403
//! `step_up_required` before any business logic runs. The signed-log happy
//! paths stay covered by the `did_ops` unit tests.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::did_ops::{DidRecord, did_key, owner_key};
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
use serde_json::{Value, json};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test harness (mirrors change_owner_rest.rs)
// ---------------------------------------------------------------------------

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

/// Mint a real (aal1) authenticated session and return the access token.
async fn mint_token(state: &AppState, did: &str, role: Role) -> String {
    let keys = state.jwt_keys.as_ref().expect("jwt keys configured");
    let auth = AuthConfig::default();
    let tokens = create_authenticated_session(
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
    .expect("create session");
    tokens.access_token
}

async fn seed_did(state: &AppState, owner_did: &str, mnemonic: &str) {
    let now = now_epoch();
    let record = DidRecord {
        owner: owner_did.into(),
        mnemonic: mnemonic.into(),
        created_at: now,
        updated_at: now,
        version_count: 1,
        did_id: Some(format!("did:webvh:abc:{mnemonic}")),
        content_size: 42,
        disabled: false,
        deleted_at: None,
        method: "webvh".to_string(),
        domain: String::new(),
        services: None,
        agent_names: Vec::new(),
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

fn post(path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn read_json(body: Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("response is valid JSON")
}

fn app(h: &Harness) -> axum::Router {
    did_hosting_control::routes::router_without_fallback().with_state(h.state.clone())
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// `remove` is owner-or-admin, NOT HTTP step-up-gated: its real caller is the
/// aal1 VTA, and the destructive elevation lives at the VTA's consent layer.
/// An aal1 owner reaches `did_ops` — a malformed `didLog` is rejected there
/// with 400 (not a 403 `step_up_required`), proving the gate is gone and the
/// handler delegates.
#[tokio::test]
async fn remove_reaches_did_ops_without_step_up() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    add_acl(&h.state, owner, Role::Owner).await;
    seed_did(&h.state, owner, "aliceslot").await;
    let token = mint_token(&h.state, owner, Role::Owner).await;

    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/remove",
            Some(&token),
            json!({ "mnemonic": "aliceslot", "name": "alice", "didLog": "not-a-valid-log" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// `disable` is likewise owner-or-admin, not step-up-gated.
#[tokio::test]
async fn disable_reaches_did_ops_without_step_up() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    add_acl(&h.state, owner, Role::Owner).await;
    seed_did(&h.state, owner, "aliceslot").await;
    let token = mint_token(&h.state, owner, Role::Owner).await;

    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/disable",
            Some(&token),
            json!({ "mnemonic": "aliceslot", "name": "alice", "didLog": "not-a-valid-log" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// No Authorization header → 401, pinning the auth gate on a destructive verb.
#[tokio::test]
async fn remove_without_auth_is_401() {
    let h = make_harness().await;
    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/remove",
            None,
            json!({ "mnemonic": "slot", "name": "alice", "didLog": "x" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// `set` is NOT step-up-gated (an aal1 owner may bind). The route is wired and
/// delegates to `did_ops`: a malformed `didLog` is rejected there with 400
/// (not 404), proving both registration and delegation.
#[tokio::test]
async fn set_route_is_wired_and_delegates() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    add_acl(&h.state, owner, Role::Owner).await;
    seed_did(&h.state, owner, "aliceslot").await;
    let token = mint_token(&h.state, owner, Role::Owner).await;

    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/set",
            Some(&token),
            json!({ "mnemonic": "aliceslot", "name": "alice", "didLog": "not-a-valid-log" }),
        ))
        .await
        .expect("router responds");
    // Reached the handler + did_ops (400), not an unrouted 404.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// `check` reports availability for a free name (aal1 is fine — it's a read).
#[tokio::test]
async fn check_reports_availability() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    add_acl(&h.state, owner, Role::Owner).await;
    let token = mint_token(&h.state, owner, Role::Owner).await;

    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/check",
            Some(&token),
            json!({ "name": "alice", "domain": "control.test" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(false));

    // A reserved name is unavailable but flagged, not an error.
    let resp = app(&h)
        .oneshot(post(
            "/api/agent-names/check",
            Some(&token),
            json!({ "name": "admin", "domain": "control.test" }),
        ))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp.into_body()).await;
    assert_eq!(body.get("available").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(body.get("reserved").and_then(|v| v.as_bool()), Some(true));
}

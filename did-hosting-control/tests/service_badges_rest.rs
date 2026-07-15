//! HTTP-shape coverage for the DID-document service badges.
//!
//! Drives the real Axum router in-process (`routes::router_without_fallback`
//! — the same router the daemon merges) so this covers what the unit tests
//! can't:
//!
//! - the cached `DidRecord.services` actually reaches the wire as
//!   `services` on `GET /api/dids`, camelCased and omitted when unknown;
//! - a registry instance's `advertisedServices` reaches
//!   `GET /api/services/overview`;
//! - `advertisedServices` is *omitted*, not emptied, when the control
//!   plane's own DID can't be resolved — "unknown" must never render as
//!   "advertises nothing".
//!
//! The harness sets `did_resolver: None` throughout.

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
use did_hosting_control::registry::{self, ServiceInstance, ServiceStatus, ServiceType};
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
    services: Option<Vec<String>>,
) {
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
        domain: "control.test".to_string(),
        services,
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

/// The cached services reach the wire as a camelCase `services` array, and a
/// record whose services are unknown omits the key entirely (so the UI's
/// `services?: string[]` lands on `undefined`, not `[]`).
#[tokio::test]
async fn dids_list_exposes_services_and_omits_unknown() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    add_acl(&h.state, owner, Role::Owner).await;
    let token = mint_token(&h.state, owner, Role::Owner).await;

    seed_did(
        &h.state,
        owner,
        "badged",
        Some(vec![
            "WebVHHosting".into(),
            "TSPTransport".into(),
            "DIDCommMessaging".into(),
        ]),
    )
    .await;
    seed_did(&h.state, owner, "unknown-services", None).await;

    let (status, body) = get_json(&h.state, "/api/dids", &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let entries = body.as_array().expect("array of DIDs");
    let badged = entries
        .iter()
        .find(|e| e["mnemonic"] == "badged")
        .expect("badged DID present");
    assert_eq!(
        badged["services"],
        serde_json::json!(["WebVHHosting", "TSPTransport", "DIDCommMessaging"]),
    );

    let unknown = entries
        .iter()
        .find(|e| e["mnemonic"] == "unknown-services")
        .expect("unknown DID present");
    assert!(
        unknown.get("services").is_none(),
        "unknown services must be omitted, not null or []; got {unknown}"
    );
}

/// A registry instance's cached badges reach the services-overview payload.
#[tokio::test]
async fn services_overview_exposes_instance_advertised_services() {
    let h = make_harness().await;
    let admin = "did:example:admin";
    add_acl(&h.state, admin, Role::Admin).await;
    let token = mint_token(&h.state, admin, Role::Admin).await;

    let instance = ServiceInstance {
        instance_id: "srv-1".into(),
        service_type: ServiceType::Server,
        label: Some("edge".into()),
        url: "http://edge.example".into(),
        status: ServiceStatus::Active,
        last_health_check: None,
        registered_at: now_epoch(),
        metadata: serde_json::json!({ "did": "did:webvh:Q1:edge.example" }),
        enabled_methods: vec!["webvh".into()],
        served_domains: vec![],
        protocol_version: "1.0".into(),
        advertised_services: Some(vec!["WebVHHosting".into(), "TSPTransport".into()]),
        services_checked_at: Some(now_epoch()),
        trust_task_capable: false,
        sync_batch_capable: false,
        last_inbound_transport: None,
        last_inbound_at: None,
        last_outbound_transport: None,
        last_outbound_at: None,
    };
    registry::register_instance(&h.state.registry_ks, &instance)
        .await
        .expect("register instance");

    let (status, body) = get_json(&h.state, "/api/services/overview", &token).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let svc = &body["services"][0];
    assert_eq!(svc["instanceId"], "srv-1");
    assert_eq!(
        svc["advertisedServices"],
        serde_json::json!(["WebVHHosting", "TSPTransport"]),
    );

    // No resolver configured, so the control plane's own advertised services
    // are unknown and the key is omitted — the UI renders "couldn't check".
    assert!(
        body["control"].get("advertisedServices").is_none(),
        "control advertisedServices must be omitted without a resolver"
    );
    // The config-derived flags are still reported, so the UI can show
    // "enabled" even when it can't show "advertised".
    assert!(body["control"].get("didcommEnabled").is_some());
    assert!(body["control"].get("tspEnabled").is_some());
}

/// With no resolver configured, `GET /api/config` omits `advertisedServices`
/// rather than reporting an empty list — "unknown" must not read as "nothing
/// advertised".
///
/// Note on what this does *not* cover: `control_advertised_services` also
/// refuses to build a throwaway `DIDCacheClient` when `did_resolver` is
/// `None`, to keep this user-reachable endpoint off the network. That guard
/// is **not** exercised here — a resolve of the harness's unroutable test DID
/// fails fast, so the response is indistinguishable either way. Verifying it
/// would need the resolver injected behind a trait. The assertion below holds
/// with or without the guard; it pins the wire contract, not the guard.
#[tokio::test]
async fn config_omits_advertised_services_without_a_resolver() {
    let h = make_harness().await;
    let owner = "did:example:owner";
    add_acl(&h.state, owner, Role::Owner).await;
    let token = mint_token(&h.state, owner, Role::Owner).await;

    let (status, body) = get_json(&h.state, "/api/config", &token).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("advertisedServices").is_none(),
        "advertisedServices must be omitted when no resolver is configured"
    );
    assert_eq!(body["controlDid"], "did:webvh:test:control.example.com");
}

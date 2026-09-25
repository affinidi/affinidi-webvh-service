//! The server's only limiter — the canonical handler's per-DID cap on pending
//! auth challenges — answers with the ecosystem 429 contract: status `429`,
//! `x-rate-limit-source: did-host`, a `Retry-After` in seconds, and a JSON body
//! naming the limiter. It used to render as `400`, indistinguishable from a
//! malformed request.
//!
//! DID resolution (`did.jsonl` / `did.json` serving) has no limiter on this
//! service, so there is no resolution-path case to cover.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::auth::jwt::JwtKeys;
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS, Store};
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::server::AppState;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn make_state() -> (AppState, tempfile::TempDir) {
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
        features: FeaturesConfig::default(),
        server_did: Some("did:webvh:test:server.example.com".into()),
        mediator_did: None,
        public_url: Some("http://localhost:8530".into()),
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
        trust_tasks_verifier: None,
        secrets_resolver: None,
        identity: None,
        didcomm_service: Arc::new(std::sync::OnceLock::new()),
        jwt_keys: Some(Arc::new(
            JwtKeys::from_ed25519_bytes(&[7u8; 32]).expect("test jwt keys"),
        )),
        signing_key_bytes: None,
        http_client: reqwest::Client::new(),
        stats_collector: None,
        did_cache: Arc::new(ContentCache::new(Duration::from_secs(60))),
        trusted_proxy_cidrs: Arc::new(Vec::new()),
    };
    (state, dir)
}

fn challenge_request(did: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/auth/challenge")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "did": did })).unwrap(),
        ))
        .unwrap()
}

#[tokio::test]
async fn pending_challenge_cap_answers_429_with_the_contract() {
    let (state, _dir) = make_state().await;
    let did = "did:example:enrolled";
    // The canonical cap counts persisted sessions, and only an enrolled subject
    // persists one — so the subject must hold an ACL entry for the cap to bite.
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.into(),
            role: Role::Owner,
            label: None,
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        },
    )
    .await
    .expect("store acl");
    let auth = state.config.auth.clone();
    let app = did_hosting_server::routes::router_without_fallback(1024 * 1024).with_state(state);

    // vti-common's default `max_pending_challenges_per_did` is 10.
    for i in 0..10 {
        let response = app.clone().oneshot(challenge_request(did)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "challenge {i} under the cap"
        );
    }

    let response = app.oneshot(challenge_request(did)).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["x-rate-limit-source"], "did-host");
    assert_eq!(response.headers()["content-type"], "application/json");
    let expected_retry = auth.pending_challenge_retry_after_secs();
    assert_eq!(
        response.headers()["retry-after"],
        expected_retry.to_string().as_str()
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(body["limiter"], "auth-challenge-pending-per-did");
    assert_eq!(body["retryAfterSecs"], expected_retry);
    assert!(body["message"].as_str().is_some_and(|m| !m.is_empty()));
}

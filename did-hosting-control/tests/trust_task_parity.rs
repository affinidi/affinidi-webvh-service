//! Trust-Task REST parity harness.
//!
//! Asserts the two REST wire shapes — without a `Trust-Task` header
//! and with the matching canonical Trust-Task URL on the header —
//! produce byte-equivalent observable state on a permissive route.
//! The DIDComm-paired auth-challenge endpoint is the representative
//! target because it's the simplest valid POST that exercises the
//! full middleware path.
//!
//! ## Why this scope, post-Phase-3
//!
//! Phase 3 retired the bidirectional `v1_aliases` translation table:
//! did-hosting now accepts canonical Trust-Task spec URIs only — the
//! legacy `affinidi.com/webvh/1.0/*` and `did-hosting/did/*/1.0`
//! namespaces are gone. The historical bijection unit-test for the
//! alias table moved with it. What remains in this harness is the
//! REST-permissive contract: a route declared `permissive` must
//! accept *no header at all* (legacy clients pre-Trust-Task) and the
//! matching canonical URL with byte-identical results, but reject a
//! bogus URL with 415.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use did_hosting_common::did_hosting_tasks::TASK_AUTH_CHALLENGE_0_1;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
};
use did_hosting_common::server::trust_task::HEADER_NAME;
use did_hosting_control::config::{AppConfig, RegistryConfig};
use did_hosting_control::server::AppState;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn make_state() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");

    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some("did:webvh:test:control.example.com".into()),
        mediator_did: None,
        public_url: Some("http://localhost:8532".into()),
        did_hosting_url: Some("http://localhost:8532".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config.clone(),
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(),
        registry: RegistryConfig::default(),
        trust_tasks: Default::default(),
        hosting: Default::default(),
        identity: Default::default(),
        config_path: PathBuf::new(),
    };

    let state = AppState {
        store: store.clone(),
        sessions_ks: store.keyspace(KS_SESSIONS).unwrap(),
        acl_ks: store.keyspace(KS_ACL).unwrap(),
        registry_ks: store.keyspace(KS_REGISTRY).unwrap(),
        dids_ks: store.keyspace(KS_DIDS).unwrap(),
        config: Arc::new(config),
        did_resolver: None,
        secrets_resolver: None,
        identity: None,
        trust_tasks_verifier: None,
        jwt_keys: None,
        webauthn: None,
        http_client: reqwest::Client::new(),
        didcomm_service: Arc::new(OnceLock::new()),
        stats_collector: Arc::new(StatsCollector::new()),
        stats_ks: store.keyspace(KS_STATS).unwrap(),
        timeseries_ks: store.keyspace(KS_TIMESERIES).unwrap(),
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

    (state, dir)
}

/// Send the same request twice — once without the `Trust-Task` header,
/// once with the matching canonical value — and assert that the
/// response (status + body bytes) is identical. The DIDComm-paired
/// auth-challenge endpoint is the representative target because it's
/// the simplest valid POST that exercises the full middleware path.
#[tokio::test]
async fn trust_task_parity_rest_permissive_legacy_vs_canonical() {
    let (state, _dir) = make_state().await;
    let app = did_hosting_control::routes::router_without_fallback().with_state(state);

    let body_json = serde_json::json!({ "did": "did:example:caller" }).to_string();

    // Variant 1: legacy / no Trust-Task header.
    let legacy_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(body_json.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let legacy_status = legacy_resp.status();
    let legacy_body = legacy_resp.into_body().collect().await.unwrap().to_bytes();

    // Variant 2: canonical Trust-Task header.
    let canonical_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/challenge")
                .header("content-type", "application/json")
                .header(
                    HEADER_NAME,
                    HeaderValue::from_str(TASK_AUTH_CHALLENGE_0_1.as_str()).unwrap(),
                )
                .body(Body::from(body_json))
                .unwrap(),
        )
        .await
        .unwrap();
    let canonical_status = canonical_resp.status();
    let canonical_body = canonical_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();

    assert_eq!(
        legacy_status, canonical_status,
        "permissive route must return the same status with and without Trust-Task header"
    );
    assert_eq!(
        legacy_body, canonical_body,
        "permissive route must return byte-identical body with and without Trust-Task header"
    );
}

/// Opting in to the Trust-Task header is binding: a mismatched value
/// returns 415, even on a permissive route. This guards the
/// "permissive on absence, strict on declaration" contract from
/// regressing into "always permissive".
#[tokio::test]
async fn trust_task_parity_rest_mismatched_header_returns_415() {
    let (state, _dir) = make_state().await;
    let app = did_hosting_control::routes::router_without_fallback().with_state(state);

    let body_json = serde_json::json!({ "did": "did:example:caller" }).to_string();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/challenge")
                .header("content-type", "application/json")
                .header(
                    HEADER_NAME,
                    "https://trusttasks.org/did-hosting/auth/refresh/1.0",
                )
                .body(Body::from(body_json))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "mismatched Trust-Task on a permissive route must still 415"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "TrustTaskMismatch");
}

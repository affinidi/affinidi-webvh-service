//! In-process HTTP smoke test for did-hosting-server's assembled router.
//!
//! Builds the same `AppState` shape `did-hosting-daemon` constructs, mounts the
//! full server router with the public-DID fallback, seeds a single DID
//! into the fjall store, and exercises:
//!
//! 1. `GET /<mnemonic>/did.jsonl` returns 200 with the seeded body.
//! 2. The response sets `Cache-Control: public, max-age=...` (proves
//!    public DID resolution opts out of the global `no-store` middleware).
//! 3. `GET /unknown-mnemonic/did.jsonl` returns 404 (proves the
//!    fallback handler runs and the error mapper produces a clean
//!    response shape).
//!
//! This is the smallest end-to-end smoke test that covers the daemon's
//! public DID surface in-process. End-to-end DIDComm flows need a fake
//! mediator and are tracked separately.

use std::path::PathBuf;
use std::sync::Arc;

use did_hosting_common::did_ops::content_log_key;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS};
use did_hosting_common::server::store::Store;
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::server::AppState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::time::Duration;
use tower::ServiceExt; // for `oneshot`

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
        secrets: SecretsConfig::default(),
        limits: LimitsConfig::default(),
        stats: StatsConfig::default(),
        watchers: Vec::new(),
        control_url: None,
        control_did: None,
        vta: VtaConfig::default(),
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
        jwt_keys: None,
        signing_key_bytes: None,
        http_client: reqwest::Client::new(),
        stats_collector: None,
        did_cache: Arc::new(ContentCache::new(Duration::from_secs(60))),
    };
    (state, dir)
}

#[tokio::test]
async fn public_did_resolution_round_trip() {
    let (state, _dir) = make_state().await;

    // Seed a DID log under mnemonic "alice".
    let mnemonic = "alice";
    let body =
        "{\"versionId\":\"1-test\",\"state\":{\"id\":\"did:webvh:test:server.example.com:alice\"}}";
    state
        .dids_ks
        .insert_raw(content_log_key(mnemonic), body.as_bytes().to_vec())
        .await
        .expect("seed did log");

    let app = did_hosting_server::routes::router(1024 * 1024)
        .with_state(state.clone())
        .layer(axum::middleware::from_fn(
            did_hosting_common::server::security_headers,
        ));

    // 1. Hit the seeded mnemonic — 200, content matches, cacheable.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/{mnemonic}/did.jsonl"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let cc = response
        .headers()
        .get("cache-control")
        .expect("cache-control header present")
        .to_str()
        .unwrap();
    assert!(
        cc.contains("public") && cc.contains("max-age"),
        "expected public DID response to be cacheable; got cache-control={cc}",
    );

    // CSP / X-Frame-Options / X-Content-Type-Options are inherited from the
    // global security_headers middleware.
    let headers = response.headers();
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("content-security-policy"));

    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(&bytes[..], body.as_bytes());

    // 2. Hit an unknown mnemonic — 404, no panic, no leaked Cache-Control.
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ghost/did.jsonl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // 404s should fall back to the global no-store default — proves the
    // middleware's "leave existing Cache-Control alone" branch doesn't
    // accidentally inherit the cacheable header onto error responses.
    let cc = response
        .headers()
        .get("cache-control")
        .expect("cache-control header present on 404")
        .to_str()
        .unwrap();
    assert_eq!(cc, "no-store", "404 must not be cached");
}

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

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::{
    DomainEntry, DomainStatus, DomainUrlScheme, create_domain,
};
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS};
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::server::AppState;
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

/// T25: with both `method-webvh` and `method-web` enabled, the
/// per-method dispatchers must not swallow specific routes like
/// `/api/health` or other non-DID paths. The dispatchers' suffix
/// checks (`/did.jsonl`, `/did.json`) only trigger on actual artifact
/// URLs; anything else falls through to the eventual 404 (or the
/// daemon's SPA fallback).
#[tokio::test]
async fn route_ordering_specific_routes_beat_method_dispatchers() {
    let (state, _dir) = make_state().await;

    let app = did_hosting_server::routes::router(1024 * 1024).with_state(state);

    // `/api/services` is a specific authenticated route; without
    // credentials it must reach its handler and return 401, not be
    // swallowed by the catch-all fallback (which would 404). The
    // exact 401 vs 403 doesn't matter — anything non-404 proves the
    // specific route matched first.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/services")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        response.status(),
        StatusCode::NOT_FOUND,
        "/api/services must reach its handler (any non-404 ok), not be swallowed by method dispatchers; got {}",
        response.status()
    );

    // A URL with no DID suffix and no specific route — both
    // dispatchers should `Skip`, and the fallback returns 404.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/some/random/path")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "non-DID, non-API URL must 404 through the fallback"
    );

    // Without a seeded did:web record on `.well-known`, the
    // `/.well-known/did.json` specific route still returns 404 — but
    // it must hit the WEB handler, not be intercepted by the WEBVH
    // dispatcher (which would return 404 for a different reason).
    // Either way, the test just confirms the specific route reaches a
    // handler and doesn't 500.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/did.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.status() == StatusCode::NOT_FOUND || response.status() == StatusCode::OK,
        "/.well-known/did.json must reach the did:web handler, got {}",
        response.status()
    );
}

fn domain(name: &str, status: DomainStatus) -> DomainEntry {
    DomainEntry {
        name: name.into(),
        label: None,
        scheme: DomainUrlScheme::Https,
        status,
        created_at: 0,
        default_domain: false,
        branding: None,
        witnesses: None,
        watchers: None,
        quota: None,
        well_known_enabled: false,
        disabled_at: None,
        purge_at: None,
    }
}

/// T21: a request arriving on a different domain than the DID was
/// issued on must NOT resolve the DID — return 404, not the content.
/// The disabled-domain case must surface as 503.
#[tokio::test]
async fn resolve_side_safety_blocks_cross_domain_and_disabled_domain() {
    let (state, _dir) = make_state().await;

    // Seed a DID issued on domain-a.example.
    let mnemonic = "alice";
    let did_id = "did:webvh:Q1:domain-a.example:alice";
    let body = format!("{{\"versionId\":\"1-test\",\"state\":{{\"id\":\"{did_id}\"}}}}");
    state
        .dids_ks
        .insert_raw(content_log_key(mnemonic), body.as_bytes().to_vec())
        .await
        .expect("seed did log");
    let record = DidRecord {
        owner: "did:example:owner".into(),
        mnemonic: mnemonic.into(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: Some(did_id.into()),
        content_size: body.len() as u64,
        disabled: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: "domain-a.example".into(),
        services: None,
    };
    state
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .expect("seed DidRecord");

    // Two active domains; resolution against either is in-policy on
    // its own DIDs but not on the other's.
    create_domain(
        &state.store,
        &domain("domain-a.example", DomainStatus::Active),
    )
    .await
    .unwrap();
    create_domain(
        &state.store,
        &domain("domain-b.example", DomainStatus::Active),
    )
    .await
    .unwrap();

    let app = did_hosting_server::routes::router(1024 * 1024).with_state(state.clone());

    // Cross-domain: domain-b is configured, but the DID belongs to
    // domain-a — must 404, never serve the body.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/{mnemonic}/did.jsonl"))
                .header("host", "domain-b.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "cross-domain resolve must 404"
    );

    // Same-domain happy path: the DID's home domain serves it.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/{mnemonic}/did.jsonl"))
                .header("host", "domain-a.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(&bytes[..], body.as_bytes());

    // Disable domain-a — same request, same Host, now 503 (not 404).
    did_hosting_common::server::domain::disable_domain(
        &state.store,
        "domain-a.example",
        0,
        86_400,
        "did:example:smoke",
    )
    .await
    .expect("disable domain-a");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/{mnemonic}/did.jsonl"))
                .header("host", "domain-a.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "disabled domain must 503"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body_str = std::str::from_utf8(&bytes).unwrap();
    assert!(
        body_str.contains("disabled") && body_str.contains("domain-a.example"),
        "503 body should carry maintenance info, got: {body_str}"
    );
}

/// Public DID resolution must be reachable from browser-based resolvers on any
/// origin, so the assembled router advertises `Access-Control-Allow-Origin: *`.
#[tokio::test]
async fn public_did_resolution_sets_cors_header() {
    let (state, _dir) = make_state().await;

    let mnemonic = "alice";
    let body =
        "{\"versionId\":\"1-test\",\"state\":{\"id\":\"did:webvh:test:server.example.com:alice\"}}";
    state
        .dids_ks
        .insert_raw(content_log_key(mnemonic), body.as_bytes().to_vec())
        .await
        .expect("seed did log");

    // Assemble the router exactly as `run_rest_thread` does: security headers
    // then the public-resolution CORS layer.
    let app = did_hosting_server::routes::router(1024 * 1024)
        .with_state(state)
        .layer(axum::middleware::from_fn(
            did_hosting_common::server::security_headers,
        ))
        .layer(did_hosting_common::server::public_resolution_cors());

    // A cross-origin browser fetch carries an Origin header.
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/{mnemonic}/did.jsonl"))
                .header("origin", "https://wallet.example.org")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let acao = response
        .headers()
        .get("access-control-allow-origin")
        .expect("access-control-allow-origin header present")
        .to_str()
        .unwrap();
    assert_eq!(acao, "*", "public DID resolution must allow any origin");
}

/// REGRESSION (upgrade scenario): when an operator runs
/// `did-hosting-server` with `features.rest_api = false`, the binary
/// assembles `router_public_only().fallback(did_public::serve_public)`
/// (server.rs:483). A request for `/{mnemonic}/did.jsonl` must still
/// route through `serve_public` -> `resolve_webvh::dispatch` ->
/// `serve_content`, not fall to the default 404. This reproduces the
/// user-reported 404 on an upgraded v0.6 -> v0.7 server.
#[tokio::test]
async fn rest_disabled_router_serves_public_did_via_fallback() {
    let (state, _dir) = make_state().await;

    let mnemonic = "mediator";
    let body = "{\"versionId\":\"1-test\",\"state\":{\"id\":\"did:webvh:Q1:server.example.com:mediator\"}}";
    state
        .dids_ks
        .insert_raw(content_log_key(mnemonic), body.as_bytes().to_vec())
        .await
        .expect("seed did log");

    // Reproduce the EXACT layer/route ordering that run_rest_thread
    // assembles when features.rest_api = false (server.rs:483-503):
    // base + fallback, .with_state, TraceLayer, security_headers,
    // public_resolution_cors, then a trailing .route("/api/health",
    // ...) added AFTER the layers.
    let app = did_hosting_server::routes::router_public_only()
        .fallback(did_hosting_server::routes::did_public::serve_public)
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(
            did_hosting_common::server::security_headers,
        ))
        .layer(did_hosting_common::server::public_resolution_cors())
        // Stand-in health handler; only the route SHAPE matters for
        // reproducing the layering/ordering bug, not the body.
        .route("/api/health", axum::routing::get(|| async { "ok" }));

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/{mnemonic}/did.jsonl"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "REST-disabled router must still serve /{{mnemonic}}/did.jsonl via the fallback"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(&bytes[..], body.as_bytes());
}

/// REGRESSION (v0.6 → v0.7 upgrade parity with the daemon):
/// `run_first_boot_init` must (1) seed `KS_DOMAINS` from
/// `public_url` when `bootstrap_domains` is empty, (2) seed
/// `KS_ASSIGNMENTS` from the same tier chain, and (3) run the M-01
/// migration so legacy `DidRecord` records with `domain == ""` get
/// their host backfilled from the embedded `did_id`.
///
/// Without this wire-up, an upgraded standalone server emits a
/// per-resolve "domains keyspace is empty — skipping resolve-side
/// safety check" warn-log and never enforces the multi-domain
/// host-match safety check.
#[tokio::test]
async fn first_boot_init_seeds_domain_and_backfills_legacy_records() {
    use did_hosting_common::did_ops::did_key;

    let (state, _dir) = make_state().await;

    // Plant a v0.6-shape DidRecord: `domain` empty, `did_id`
    // populated so M-01 can derive the host from it.
    let mnemonic = "mediator";
    let did_id = "did:webvh:Q1:webvh.example.com:mediator";
    let legacy = DidRecord {
        owner: "did:example:owner".into(),
        mnemonic: mnemonic.into(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: Some(did_id.into()),
        content_size: 0,
        disabled: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: String::new(), // legacy state
        services: None,        // legacy state
    };
    state
        .dids_ks
        .insert(did_key(mnemonic), &legacy)
        .await
        .expect("seed legacy DidRecord");

    // Build a config that mirrors what an upgraded standalone server
    // looks like: no bootstrap_domains, only the legacy public_url.
    // The seed should fall through to tier 2 (public_url host).
    let mut config = (*state.config).clone();
    config.public_url = Some("https://webvh.example.com".into());
    config.hosting.bootstrap_domains = Vec::new();

    did_hosting_server::server::run_first_boot_init(&state.store, &config).await;

    // 1. KS_DOMAINS now has one entry for the public_url host.
    let domains = did_hosting_common::server::domain::list_domains(&state.store)
        .await
        .expect("list domains");
    assert_eq!(domains.len(), 1, "exactly one domain seeded");
    assert_eq!(domains[0].name, "webvh.example.com");

    // 2. KS_ASSIGNMENTS has the matching assignment.
    let assignments = did_hosting_common::server::assignment::list(&state.store)
        .await
        .expect("list assignments");
    assert_eq!(assignments.len(), 1, "exactly one assignment seeded");
    assert_eq!(assignments[0].domain, "webvh.example.com");

    // 3. The legacy DidRecord got its `domain` field filled from
    //    the embedded `did_id` host.
    let migrated: DidRecord = state
        .dids_ks
        .get(did_key(mnemonic))
        .await
        .expect("get migrated record")
        .expect("record present");
    assert_eq!(migrated.domain, "webvh.example.com");

    // 4. Idempotent: a second invocation is a no-op (markers in
    //    `meta` keyspace short-circuit the migration; existing
    //    KS_DOMAINS / KS_ASSIGNMENTS rows make the seeds report
    //    AlreadySeeded). Just verify no panic / data drift.
    did_hosting_server::server::run_first_boot_init(&state.store, &config).await;
    let domains = did_hosting_common::server::domain::list_domains(&state.store)
        .await
        .expect("list domains after replay");
    assert_eq!(domains.len(), 1, "second run must be a no-op");
}

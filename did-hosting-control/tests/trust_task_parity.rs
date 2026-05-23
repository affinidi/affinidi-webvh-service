//! Trust-Task parity harness (T9).
//!
//! Asserts that the two wire shapes — legacy (`MSG_*` DIDComm type
//! / no REST `Trust-Task` header) and canonical (Trust-Task URL on
//! either transport) — produce byte-equivalent observable state.
//! The matrix is intentionally narrow: the parity guarantee comes
//! from the `v1_aliases` table + the permissive middleware, and
//! those have their own unit-test coverage; this harness exercises
//! the end-to-end seam where the two wire forms reach the same
//! handler.
//!
//! ## What's checked
//!
//! 1. **v1_aliases bijection.** Every `MSG_*` const canonicalises
//!    to a `TASK_*` URL, and every canonical URL round-trips back
//!    to the same legacy `MSG_*`. Drift in either direction breaks
//!    the dispatcher.
//! 2. **REST permissive parity.** For a representative route, a
//!    request *without* `Trust-Task:` and a request *with* the
//!    matching canonical URL produce identical (status, body)
//!    pairs.
//! 3. **REST mismatch is held to the same standard either way.** A
//!    bogus `Trust-Task:` value still returns 415 on a permissive
//!    route — opting in is binding.
//!
//! End-to-end DIDComm parity (sending a request with legacy `typ`
//! vs the canonical TASK_* value) requires a working mediator
//! fixture and is tracked separately as part of the broader
//! integration suite. The dispatcher's per-arm acceptance of both
//! type strings is already pinned by
//! `did_hosting_common::v1_aliases::tests::to_legacy_round_trips_via_canonical`
//! and by `dispatch_did_op`'s call to `to_legacy` before its
//! `match` arm — see `did-hosting-control/src/messaging.rs`.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use did_hosting_common::did_hosting_tasks::TASK_AUTH_CHALLENGE_1_0;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
};
use did_hosting_common::server::trust_task::HEADER_NAME;
use did_hosting_common::v1_aliases::{canonicalize, to_legacy};
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
        step_up_trusted_vta_did: None,
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
                    HeaderValue::from_str(TASK_AUTH_CHALLENGE_1_0.as_str()).unwrap(),
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

/// v1_aliases bijection: every known MSG_* round-trips through
/// canonicalize → to_legacy → original MSG_*. A drift here means
/// the dispatcher would silently route a canonical request to a
/// different (or no) handler.
#[tokio::test]
async fn trust_task_parity_aliases_round_trip() {
    use did_hosting_common::didcomm_types::*;

    let legacy_messages = [
        MSG_AUTHENTICATE,
        MSG_AUTH_RESPONSE,
        MSG_DID_REQUEST,
        MSG_DID_OFFER,
        MSG_DID_PUBLISH,
        MSG_DID_CONFIRM,
        MSG_DID_REGISTER,
        MSG_DID_REGISTER_CONFIRM,
        MSG_WITNESS_PUBLISH,
        MSG_WITNESS_CONFIRM,
        MSG_INFO_REQUEST,
        MSG_INFO,
        MSG_LIST_REQUEST,
        MSG_LIST,
        MSG_DELETE,
        MSG_DELETE_CONFIRM,
        MSG_DID_CHANGE_OWNER,
        MSG_DID_CHANGE_OWNER_CONFIRM,
        MSG_PROBLEM_REPORT,
        MSG_SERVER_REGISTER,
        MSG_SERVER_REGISTER_ACK,
        MSG_HEALTH_PING,
        MSG_HEALTH_PONG,
        MSG_SYNC_UPDATE,
        MSG_SYNC_UPDATE_ACK,
        MSG_SYNC_DELETE,
        MSG_SYNC_DELETE_ACK,
        MSG_STATS_SYNC,
        MSG_STATS_ACK,
        MSG_DOMAIN_ASSIGN,
        MSG_DOMAIN_UNASSIGN,
        MSG_DOMAIN_PURGE,
    ];

    for legacy in legacy_messages {
        let canonical = canonicalize(legacy)
            .unwrap_or_else(|| panic!("legacy `{legacy}` must canonicalise — missing alias entry"));
        // Canonical must canonicalise to itself.
        assert_eq!(
            canonicalize(canonical),
            Some(canonical),
            "canonical `{canonical}` must be idempotent"
        );
        // Round-trip back via to_legacy.
        let round_trip = to_legacy(canonical)
            .unwrap_or_else(|| panic!("canonical `{canonical}` must round-trip via to_legacy"));
        assert_eq!(
            round_trip, legacy,
            "round-trip drift: {legacy} → {canonical} → {round_trip}"
        );
    }

    // Unknown messages return None from both directions — the
    // dispatcher's "unknown type" arm must remain reachable.
    assert!(canonicalize("https://example.com/unknown/1.0").is_none());
    assert!(to_legacy("https://example.com/unknown/1.0").is_none());
}

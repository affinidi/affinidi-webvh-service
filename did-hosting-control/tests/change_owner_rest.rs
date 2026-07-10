//! HTTP-shape coverage for `PUT /api/owner/{*mnemonic}`.
//!
//! Drives the full Axum router (`routes::router_without_fallback`) in-
//! process via `tower::ServiceExt::oneshot`. This is the smallest test
//! surface that proves:
//!
//! - the route is actually registered (a typo or missing `.route(...)`
//!   call returns 404 here, not just a unit-test failure);
//! - the JWT-Bearer extractor works against the response payload;
//! - status codes from the handler propagate correctly through the
//!   error-mapping layer (200 / 403 / 422);
//! - the response JSON body keys match what the UI's `ChangeOwnerResponse`
//!   interface expects (camelCase `mnemonic`, `owner`, `updatedAt`).
//!
//! Together with `change_owner_integration.rs` (which exercises the
//! ownership-lifecycle business logic with realistic identities) and
//! the in-crate `messaging::tests` (which exercise the DIDComm
//! dispatcher), this gives us defense-in-depth on the change-owner
//! feature: dispatcher contract, REST contract, and end-to-end flow.

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
// Test harness
// ---------------------------------------------------------------------------

struct Harness {
    state: AppState,
    /// Held only to keep the on-disk store alive until the test finishes —
    /// dropping it removes the fjall partition files.
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

/// Mint a real authenticated session for `did` with `role` and return the
/// access token. Goes through the production `create_authenticated_session`
/// helper so the JWT/session row matches what the extractor expects.
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

/// Seed a `DidRecord` and the `owner:` reverse index — same shape as
/// `did_ops::create_did` would produce.
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

        // T12: legacy construction site; T13 migration fills `domain`.
        method: "webvh".to_string(),
        domain: String::new(),
        services: None,
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

fn change_owner_request(mnemonic: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/api/owner/{mnemonic}"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn read_json(body: Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("response is valid JSON")
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// Owner can transfer their DID. Response is 200 OK with the camelCase body
/// the UI expects (`mnemonic`, `owner`, `updatedAt`). Pins the wire shape.
#[tokio::test]
async fn put_owner_returns_200_with_camelcase_body() {
    let h = make_harness().await;
    let owner = "did:example:owner-a";
    let new_owner = "did:example:owner-b";
    add_acl(&h.state, owner, Role::Owner).await;
    add_acl(&h.state, new_owner, Role::Owner).await;
    seed_did(&h.state, owner, "alpha-beta").await;

    let token = mint_token(&h.state, owner, Role::Owner).await;
    let app = did_hosting_control::routes::router_without_fallback().with_state(h.state.clone());

    let response = app
        .oneshot(change_owner_request(
            "alpha-beta",
            &token,
            json!({ "new_owner": new_owner }),
        ))
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json(response.into_body()).await;
    assert_eq!(
        body.get("mnemonic").and_then(|v| v.as_str()),
        Some("alpha-beta")
    );
    assert_eq!(body.get("owner").and_then(|v| v.as_str()), Some(new_owner));
    // camelCase — locked because the UI's `ChangeOwnerResponse` consumes it.
    assert!(
        body.get("updatedAt").is_some(),
        "response should use camelCase 'updatedAt'; got {body}"
    );
    assert!(
        body.get("updated_at").is_none(),
        "response must not leak snake_case 'updated_at'; got {body}"
    );

    // Owner index swapped — verifies the storage side-effect ran.
    let new_idx = h
        .state
        .dids_ks
        .prefix_iter_raw(format!("owner:{new_owner}:"))
        .await
        .unwrap();
    assert_eq!(new_idx.len(), 1);
}

/// A second Owner who doesn't own the record gets 403 Forbidden.
#[tokio::test]
async fn put_owner_returns_403_for_non_owner_caller() {
    let h = make_harness().await;
    let owner = "did:example:owner-a";
    let attacker = "did:example:attacker";
    let target = "did:example:target";
    add_acl(&h.state, owner, Role::Owner).await;
    add_acl(&h.state, attacker, Role::Owner).await;
    add_acl(&h.state, target, Role::Owner).await;
    seed_did(&h.state, owner, "protected").await;

    let token = mint_token(&h.state, attacker, Role::Owner).await;
    let app = did_hosting_control::routes::router_without_fallback().with_state(h.state.clone());

    let response = app
        .oneshot(change_owner_request(
            "protected",
            &token,
            json!({ "new_owner": target }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Original owner index intact — no partial mutation.
    let owner_idx = h
        .state
        .dids_ks
        .prefix_iter_raw(format!("owner:{owner}:"))
        .await
        .unwrap();
    assert_eq!(owner_idx.len(), 1);
}

/// Admin role can transfer any record, regardless of who currently owns it.
#[tokio::test]
async fn put_owner_admin_can_transfer_any_did() {
    let h = make_harness().await;
    let owner = "did:example:owner-a";
    let admin = "did:example:admin";
    let target = "did:example:target";
    add_acl(&h.state, owner, Role::Owner).await;
    add_acl(&h.state, admin, Role::Admin).await;
    add_acl(&h.state, target, Role::Owner).await;
    seed_did(&h.state, owner, "admin-flow").await;

    let token = mint_token(&h.state, admin, Role::Admin).await;
    let app = did_hosting_control::routes::router_without_fallback().with_state(h.state.clone());

    let response = app
        .oneshot(change_owner_request(
            "admin-flow",
            &token,
            json!({ "new_owner": target }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response.into_body()).await;
    assert_eq!(body.get("owner").and_then(|v| v.as_str()), Some(target));
}

/// New owner not in the ACL → 400 BAD_REQUEST (Validation status mapping
/// per `AppError::into_response`). Pinning the status code prevents
/// accidental drift to 500 if the error mapper changes.
#[tokio::test]
async fn put_owner_returns_400_when_new_owner_not_in_acl() {
    let h = make_harness().await;
    let owner = "did:example:owner-a";
    add_acl(&h.state, owner, Role::Owner).await;
    seed_did(&h.state, owner, "needs-acl").await;

    let token = mint_token(&h.state, owner, Role::Owner).await;
    let app = did_hosting_control::routes::router_without_fallback().with_state(h.state.clone());

    let response = app
        .oneshot(change_owner_request(
            "needs-acl",
            &token,
            json!({ "new_owner": "did:example:not-in-acl" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Missing `new_owner` field surfaces from the JSON extractor as a 4xx —
/// pin "any 4xx" rather than a specific code, since axum's behaviour for
/// `Json` deserialization can shift between minor versions.
#[tokio::test]
async fn put_owner_rejects_missing_new_owner_field() {
    let h = make_harness().await;
    let owner = "did:example:owner-a";
    add_acl(&h.state, owner, Role::Owner).await;
    seed_did(&h.state, owner, "missing-field").await;

    let token = mint_token(&h.state, owner, Role::Owner).await;
    let app = did_hosting_control::routes::router_without_fallback().with_state(h.state.clone());

    let response = app
        .oneshot(change_owner_request("missing-field", &token, json!({})))
        .await
        .unwrap();
    assert!(
        response.status().is_client_error(),
        "expected 4xx, got {}",
        response.status()
    );
}

/// No Authorization header → 401. Pins the auth gate so a hypothetical
/// future "skip auth" toggle can't accidentally expose this route.
#[tokio::test]
async fn put_owner_without_auth_returns_401() {
    let h = make_harness().await;
    seed_did(&h.state, "did:example:owner-a", "no-auth").await;

    let app = did_hosting_control::routes::router_without_fallback().with_state(h.state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/owner/no-auth")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "new_owner": "did:example:x" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Unknown mnemonic surfaces as 404. Catches a regression where the route
/// matcher would consume any `*mnemonic` and fall through to a generic
/// success path.
#[tokio::test]
async fn put_owner_returns_404_for_unknown_mnemonic() {
    let h = make_harness().await;
    let owner = "did:example:owner-a";
    let target = "did:example:target";
    add_acl(&h.state, owner, Role::Owner).await;
    add_acl(&h.state, target, Role::Owner).await;

    let token = mint_token(&h.state, owner, Role::Owner).await;
    let app = did_hosting_control::routes::router_without_fallback().with_state(h.state.clone());

    let response = app
        .oneshot(change_owner_request(
            "ghost-token",
            &token,
            json!({ "new_owner": target }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

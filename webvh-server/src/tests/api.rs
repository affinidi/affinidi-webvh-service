use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::jwt::JwtKeys;
use crate::auth::session::{Session, SessionState, now_epoch, store_session};
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LimitsConfig, LogConfig, SecretsConfig, ServerConfig,
    StoreConfig,
};
use crate::routes;
use crate::server::AppState;
use crate::store::Store;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct TestEnv {
    state: AppState,
    jwt_keys: Arc<JwtKeys>,
    _dir: tempfile::TempDir,
}

/// Build a self-contained test environment with temporary storage.
async fn setup() -> TestEnv {
    let dir = tempfile::tempdir().unwrap();
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
    };
    let store = Store::open(&store_config).unwrap();
    let sessions_ks = store.keyspace("sessions").unwrap();
    let acl_ks = store.keyspace("acl").unwrap();
    let dids_ks = store.keyspace("dids").unwrap();
    let stats_ks = store.keyspace("stats").unwrap();

    let mut key_bytes = [0u8; 32];
    rand::fill(&mut key_bytes);
    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&key_bytes).unwrap());

    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: None,
        mediator_did: None,
        public_url: Some("http://localhost:8101".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        limits: LimitsConfig::default(),
        config_path: PathBuf::new(),
    };

    let state = AppState {
        store,
        sessions_ks,
        acl_ks,
        dids_ks,
        stats_ks,
        config: Arc::new(config),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: Some(jwt_keys.clone()),
        webauthn: None,
    };

    TestEnv {
        state,
        jwt_keys,
        _dir: dir,
    }
}

/// Build the axum app router from the test environment.
fn app(env: &TestEnv) -> axum::Router {
    let limit = env.state.config.limits.upload_body_limit;
    routes::router(limit).with_state(env.state.clone())
}

/// Create a JWT bearer token for the given DID and role, and store
/// a matching authenticated session so the auth extractor succeeds.
async fn token_for(env: &TestEnv, did: &str, role: Role) -> String {
    let claims = JwtKeys::new_claims(
        did.to_string(),
        uuid::Uuid::new_v4().to_string(),
        role.to_string(),
        3600,
    );
    let token = env.jwt_keys.encode(&claims).unwrap();

    let session = Session {
        session_id: claims.session_id,
        did: did.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: now_epoch(),
        refresh_token: None,
        refresh_expires_at: None,
    };
    store_session(&env.state.sessions_ks, &session)
        .await
        .unwrap();

    token
}

/// Seed an ACL entry for a DID.
async fn seed_acl(env: &TestEnv, did: &str, role: Role) {
    let entry = AclEntry {
        did: did.to_string(),
        role,
        label: None,
        created_at: now_epoch(),
        max_total_size: None,
        max_did_count: None,
    };
    store_acl_entry(&env.state.acl_ks, &entry).await.unwrap();
}

/// Seed an ACL entry with custom limits.
async fn seed_acl_with_limits(
    env: &TestEnv,
    did: &str,
    role: Role,
    max_did_count: Option<u64>,
    max_total_size: Option<u64>,
) {
    let entry = AclEntry {
        did: did.to_string(),
        role,
        label: None,
        created_at: now_epoch(),
        max_total_size,
        max_did_count,
    };
    store_acl_entry(&env.state.acl_ks, &entry).await.unwrap();
}

/// Create a DID via POST /api/dids and return the mnemonic.
async fn create_did(app: &axum::Router, token: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/dids")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    v["mnemonic"].as_str().unwrap().to_string()
}

/// Generate valid did:webvh JSONL content for upload tests.
fn valid_jsonl() -> String {
    use affinidi_webvh_common::did::{build_did_document, create_log_entry, encode_host};

    let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, None);
    let pk = secret.get_public_keymultibase().unwrap();
    let host = encode_host("http://localhost:8101").unwrap();
    let doc = build_did_document(&host, "test", &pk);
    let (_scid, jsonl) = create_log_entry(&doc, &secret).unwrap();
    jsonl
}

/// Read response body as JSON.
async fn json_body(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ===========================================================================
// Auth & token validation tests
// ===========================================================================

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    let env = setup().await;
    let resp = app(&env)
        .oneshot(
            Request::get("/api/dids")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let env = setup().await;
    let resp = app(&env)
        .oneshot(
            Request::get("/api/dids")
                .header(AUTHORIZATION, "Bearer garbage.token.here")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_returns_401() {
    let env = setup().await;
    seed_acl(&env, "did:key:expired", Role::Owner).await;

    // Create token that expired 10 seconds ago
    let claims = crate::auth::jwt::Claims {
        aud: "WebVH".into(),
        sub: "did:key:expired".into(),
        session_id: "sess-expired".into(),
        role: "owner".into(),
        exp: now_epoch().saturating_sub(10),
    };
    let token = env.jwt_keys.encode(&claims).unwrap();

    let resp = app(&env)
        .oneshot(
            Request::get("/api/dids")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_owner_token_accepted() {
    let env = setup().await;
    let did = "did:key:owner1";
    seed_acl(&env, did, Role::Owner).await;
    let token = token_for(&env, did, Role::Owner).await;

    let resp = app(&env)
        .oneshot(
            Request::get("/api/dids")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn valid_admin_token_accepted() {
    let env = setup().await;
    let did = "did:key:admin1";
    seed_acl(&env, did, Role::Admin).await;
    let token = token_for(&env, did, Role::Admin).await;

    let resp = app(&env)
        .oneshot(
            Request::get("/api/dids")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ===========================================================================
// Role-based access control tests
// ===========================================================================

#[tokio::test]
async fn owner_cannot_access_admin_endpoints() {
    let env = setup().await;
    let did = "did:key:owner-no-admin";
    seed_acl(&env, did, Role::Owner).await;
    let token = token_for(&env, did, Role::Owner).await;

    // GET /api/acl requires AdminAuth
    let resp = app(&env)
        .oneshot(
            Request::get("/api/acl")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_access_admin_endpoints() {
    let env = setup().await;
    let did = "did:key:admin-acl";
    seed_acl(&env, did, Role::Admin).await;
    let token = token_for(&env, did, Role::Admin).await;

    let resp = app(&env)
        .oneshot(
            Request::get("/api/acl")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ===========================================================================
// DID ownership tests
// ===========================================================================

#[tokio::test]
async fn owner_can_create_and_access_own_did() {
    let env = setup().await;
    let did = "did:key:creator";
    seed_acl(&env, did, Role::Owner).await;
    let token = token_for(&env, did, Role::Owner).await;
    let router = app(&env);

    let mnemonic = create_did(&router, &token).await;

    // GET own DID → 200
    let resp = router
        .clone()
        .oneshot(
            Request::get(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn owner_cannot_access_others_did() {
    let env = setup().await;

    // Owner A creates a DID
    let did_a = "did:key:ownerA";
    seed_acl(&env, did_a, Role::Owner).await;
    let token_a = token_for(&env, did_a, Role::Owner).await;
    let router = app(&env);
    let mnemonic = create_did(&router, &token_a).await;

    // Owner B tries to GET it
    let did_b = "did:key:ownerB";
    seed_acl(&env, did_b, Role::Owner).await;
    let token_b = token_for(&env, did_b, Role::Owner).await;

    let resp = router
        .clone()
        .oneshot(
            Request::get(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn owner_cannot_delete_others_did() {
    let env = setup().await;

    let did_a = "did:key:delOwnerA";
    seed_acl(&env, did_a, Role::Owner).await;
    let token_a = token_for(&env, did_a, Role::Owner).await;
    let router = app(&env);
    let mnemonic = create_did(&router, &token_a).await;

    let did_b = "did:key:delOwnerB";
    seed_acl(&env, did_b, Role::Owner).await;
    let token_b = token_for(&env, did_b, Role::Owner).await;

    let resp = router
        .clone()
        .oneshot(
            Request::delete(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn owner_cannot_upload_to_others_did() {
    let env = setup().await;

    let did_a = "did:key:uplOwnerA";
    seed_acl(&env, did_a, Role::Owner).await;
    let token_a = token_for(&env, did_a, Role::Owner).await;
    let router = app(&env);
    let mnemonic = create_did(&router, &token_a).await;

    let did_b = "did:key:uplOwnerB";
    seed_acl(&env, did_b, Role::Owner).await;
    let token_b = token_for(&env, did_b, Role::Owner).await;

    let content = valid_jsonl();
    let resp = router
        .clone()
        .oneshot(
            Request::put(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token_b}"))
                .body(Body::from(content))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_access_any_did() {
    let env = setup().await;

    // Owner creates a DID
    let owner_did = "did:key:anyOwner";
    seed_acl(&env, owner_did, Role::Owner).await;
    let owner_token = token_for(&env, owner_did, Role::Owner).await;
    let router = app(&env);
    let mnemonic = create_did(&router, &owner_token).await;

    // Admin accesses it
    let admin_did = "did:key:anyAdmin";
    seed_acl(&env, admin_did, Role::Admin).await;
    let admin_token = token_for(&env, admin_did, Role::Admin).await;

    let resp = router
        .clone()
        .oneshot(
            Request::get(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_dids_returns_only_own() {
    let env = setup().await;
    let router = app(&env);

    // Owner A creates 2 DIDs
    let did_a = "did:key:listA";
    seed_acl(&env, did_a, Role::Owner).await;
    let token_a = token_for(&env, did_a, Role::Owner).await;
    create_did(&router, &token_a).await;
    create_did(&router, &token_a).await;

    // Owner B creates 1 DID
    let did_b = "did:key:listB";
    seed_acl(&env, did_b, Role::Owner).await;
    let token_b = token_for(&env, did_b, Role::Owner).await;
    create_did(&router, &token_b).await;

    // Owner A sees exactly 2
    let resp = router
        .clone()
        .oneshot(
            Request::get("/api/dids")
                .header(AUTHORIZATION, format!("Bearer {token_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body.as_array().unwrap().len(), 2);

    // Owner B sees exactly 1
    let resp = router
        .clone()
        .oneshot(
            Request::get("/api/dids")
                .header(AUTHORIZATION, format!("Bearer {token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body.as_array().unwrap().len(), 1);
}

// ===========================================================================
// ACL CRUD tests
// ===========================================================================

#[tokio::test]
async fn acl_crud_lifecycle() {
    let env = setup().await;
    let admin_did = "did:key:aclAdmin";
    seed_acl(&env, admin_did, Role::Admin).await;
    let token = token_for(&env, admin_did, Role::Admin).await;
    let router = app(&env);

    // Create entry
    let resp = router
        .clone()
        .oneshot(
            Request::post("/api/acl")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"did":"did:key:newuser","role":"owner","label":"test user"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["did"], "did:key:newuser");
    assert_eq!(body["role"], "owner");

    // List includes it
    let resp = router
        .clone()
        .oneshot(
            Request::get("/api/acl")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let entries = body["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["did"] == "did:key:newuser"));

    // Update limits
    let resp = router
        .clone()
        .oneshot(
            Request::put("/api/acl/did:key:newuser")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"max_did_count":5,"max_total_size":500000}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["max_did_count"], 5);
    assert_eq!(body["max_total_size"], 500000);

    // Delete it
    let resp = router
        .clone()
        .oneshot(
            Request::delete("/api/acl/did:key:newuser")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn acl_create_duplicate_rejected() {
    let env = setup().await;
    let admin_did = "did:key:dupAdmin";
    seed_acl(&env, admin_did, Role::Admin).await;
    let token = token_for(&env, admin_did, Role::Admin).await;
    let router = app(&env);

    let body = r#"{"did":"did:key:dupTarget","role":"owner"}"#;

    // First create → 201
    let resp = router
        .clone()
        .oneshot(
            Request::post("/api/acl")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Second create → 409
    let resp = router
        .clone()
        .oneshot(
            Request::post("/api/acl")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn acl_admin_cannot_delete_self() {
    let env = setup().await;
    let admin_did = "did:key:selfDelAdmin";
    seed_acl(&env, admin_did, Role::Admin).await;
    let token = token_for(&env, admin_did, Role::Admin).await;

    let resp = app(&env)
        .oneshot(
            Request::delete(format!("/api/acl/{admin_did}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ===========================================================================
// Quota enforcement tests
// ===========================================================================

#[tokio::test]
async fn did_count_limit_enforced() {
    let env = setup().await;
    let did = "did:key:quotaCount";
    // Set a limit of 2 DIDs
    seed_acl_with_limits(&env, did, Role::Owner, Some(2), None).await;
    let token = token_for(&env, did, Role::Owner).await;
    let router = app(&env);

    // Create 2 DIDs → success
    create_did(&router, &token).await;
    create_did(&router, &token).await;

    // 3rd create → quota exceeded (403)
    let resp = router
        .clone()
        .oneshot(
            Request::post("/api/dids")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = json_body(resp).await;
    assert!(body["error"].as_str().unwrap().contains("DID count limit"));
}

#[tokio::test]
async fn total_size_limit_enforced() {
    let env = setup().await;
    let did = "did:key:quotaSize";
    let content = valid_jsonl();
    let content_len = content.len() as u64;
    // Set total size limit just below 2x the content size
    let limit = content_len * 2 - 1;
    seed_acl_with_limits(&env, did, Role::Owner, None, Some(limit)).await;
    let token = token_for(&env, did, Role::Owner).await;
    let router = app(&env);

    // Create and upload first DID → success
    let m1 = create_did(&router, &token).await;
    let resp = router
        .clone()
        .oneshot(
            Request::put(format!("/api/dids/{m1}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(content.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Create and upload second DID → quota exceeded
    let m2 = create_did(&router, &token).await;
    let resp = router
        .clone()
        .oneshot(
            Request::put(format!("/api/dids/{m2}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(content))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = json_body(resp).await;
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("total DID document size"));
}

#[tokio::test]
async fn admin_bypasses_did_count_limit() {
    let env = setup().await;
    let did = "did:key:adminBypass";
    // Set admin with a limit of 1 — should be bypassed
    seed_acl_with_limits(&env, did, Role::Admin, Some(1), None).await;
    let token = token_for(&env, did, Role::Admin).await;
    let router = app(&env);

    // Create 3 DIDs — all should succeed for admin
    create_did(&router, &token).await;
    create_did(&router, &token).await;

    let resp = router
        .clone()
        .oneshot(
            Request::post("/api/dids")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn admin_bypasses_total_size_limit() {
    let env = setup().await;
    let did = "did:key:adminSizeBypass";
    let content = valid_jsonl();
    // Set a tiny limit — admin should bypass
    seed_acl_with_limits(&env, did, Role::Admin, None, Some(1)).await;
    let token = token_for(&env, did, Role::Admin).await;
    let router = app(&env);

    let mnemonic = create_did(&router, &token).await;
    let resp = router
        .clone()
        .oneshot(
            Request::put(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(content))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ===========================================================================
// DID upload validation tests
// ===========================================================================

#[tokio::test]
async fn upload_valid_jsonl_accepted() {
    let env = setup().await;
    let did = "did:key:validUpload";
    seed_acl(&env, did, Role::Owner).await;
    let token = token_for(&env, did, Role::Owner).await;
    let router = app(&env);

    let mnemonic = create_did(&router, &token).await;
    let content = valid_jsonl();

    let resp = router
        .clone()
        .oneshot(
            Request::put(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(content))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn upload_invalid_jsonl_rejected() {
    let env = setup().await;
    let did = "did:key:invalidUpload";
    seed_acl(&env, did, Role::Owner).await;
    let token = token_for(&env, did, Role::Owner).await;
    let router = app(&env);

    let mnemonic = create_did(&router, &token).await;

    let resp = router
        .clone()
        .oneshot(
            Request::put(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from("this is not valid jsonl at all"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn upload_empty_body_rejected() {
    let env = setup().await;
    let did = "did:key:emptyUpload";
    seed_acl(&env, did, Role::Owner).await;
    let token = token_for(&env, did, Role::Owner).await;
    let router = app(&env);

    let mnemonic = create_did(&router, &token).await;

    let resp = router
        .clone()
        .oneshot(
            Request::put(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===========================================================================
// Public endpoint tests
// ===========================================================================

#[tokio::test]
async fn health_requires_no_auth() {
    let env = setup().await;
    let resp = app(&env)
        .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn public_did_resolve_after_upload() {
    let env = setup().await;
    let did = "did:key:publicResolve";
    seed_acl(&env, did, Role::Owner).await;
    let token = token_for(&env, did, Role::Owner).await;
    let router = app(&env);

    let mnemonic = create_did(&router, &token).await;
    let content = valid_jsonl();

    // Upload content
    let resp = router
        .clone()
        .oneshot(
            Request::put(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(content.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Resolve publicly (no auth header)
    let resp = router
        .clone()
        .oneshot(
            Request::get(format!("/{mnemonic}/did.jsonl"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes, content.as_bytes());
}

#[tokio::test]
async fn public_did_resolve_not_found_before_upload() {
    let env = setup().await;
    let resp = app(&env)
        .oneshot(
            Request::get("/nonexistent/did.jsonl")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// DID delete and cleanup tests
// ===========================================================================

#[tokio::test]
async fn delete_own_did_succeeds() {
    let env = setup().await;
    let did = "did:key:delOwn";
    seed_acl(&env, did, Role::Owner).await;
    let token = token_for(&env, did, Role::Owner).await;
    let router = app(&env);

    let mnemonic = create_did(&router, &token).await;

    // Delete → 204
    let resp = router
        .clone()
        .oneshot(
            Request::delete(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify it's gone
    let resp = router
        .clone()
        .oneshot(
            Request::get(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_can_delete_any_did() {
    let env = setup().await;
    let router = app(&env);

    // Owner creates a DID
    let owner_did = "did:key:adminDelOwner";
    seed_acl(&env, owner_did, Role::Owner).await;
    let owner_token = token_for(&env, owner_did, Role::Owner).await;
    let mnemonic = create_did(&router, &owner_token).await;

    // Admin deletes it
    let admin_did = "did:key:adminDelAdmin";
    seed_acl(&env, admin_did, Role::Admin).await;
    let admin_token = token_for(&env, admin_did, Role::Admin).await;

    let resp = router
        .clone()
        .oneshot(
            Request::delete(format!("/api/dids/{mnemonic}"))
                .header(AUTHORIZATION, format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

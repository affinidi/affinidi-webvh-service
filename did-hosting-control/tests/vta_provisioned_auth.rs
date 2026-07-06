//! End-to-end coverage for VTA-provisioned trust: the daemon (control
//! plane) trusts the VTA that provisioned it to publish DIDs from the
//! get-go, over the DIDComm-JWS auth dialect the VTA speaks.
//!
//! Two additive pieces are exercised here against the real Axum router
//! (`routes::router_without_fallback`) via `tower::ServiceExt::oneshot`:
//!
//! (A) An ACL entry for the provisioning VTA DID (seeded at setup by
//!     `acl::seed_provisioning_vta_acl`) is what lets the VTA past the
//!     ACL gate on `POST /api/auth/challenge` (the canonical challenge
//!     handler calls `check_acl`), so without it the VTA's very first
//!     request is `403 DID not in ACL`.
//!
//! (B) `POST /api/auth/` now content-negotiates: a DIDComm-v2 JWS
//!     envelope (the `did-hosting-server` contract the VTA sends via
//!     `build_authenticate_message`) is accepted *in addition to* the
//!     SIOPv2 id_token Trust-Task envelope. The daemon unified binary
//!     mounts this control route, so before this change the VTA's
//!     envelope failed with `400 missing field type`.
//!
//! The regression case proves the SIOPv2 id_token dialect on the *same*
//! endpoint still authenticates unchanged — the DIDComm-JWS path is
//! additive, not a replacement.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::message::pack::pack_signed;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use did_hosting_common::server::acl::{Role, seed_provisioning_vta_acl};
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
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// RP DID the authenticate paths bind to (SIOPv2 `aud`; the DIDComm
/// envelope's `to`). Set as the control plane's `server_did`.
const RP_DID: &str = "did:web:control.test";

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
        server_did: Some(RP_DID.into()),
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

    // A real did:key resolver — resolves the test identities offline (no
    // network). Both auth dialects resolve the signer's verifying key
    // through this. A ThreadedSecretsResolver is required by
    // `require_didcomm_auth` but is not consulted on the inbound verify
    // path (signature verification uses the resolved public key).
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("did:key resolver");
    let secrets_resolver = Arc::new(
        affinidi_tdk::secrets_resolver::ThreadedSecretsResolver::new(None)
            .await
            .0,
    );

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        registry_ks,
        dids_ks,
        config: Arc::new(config),
        did_resolver: Some(did_resolver),
        secrets_resolver: Some(secrets_resolver),
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

// ---------------------------------------------------------------------------
// did:key identity helpers
// ---------------------------------------------------------------------------

/// A test Ed25519 identity expressed as a `did:key` (the shape both
/// auth dialects resolve). Mirrors how a VTA / wallet identifies itself.
struct KeyIdentity {
    did: String,
    /// `<did>#<multibase>` — the JWS/SIOP `kid`.
    kid: String,
    signing_key: SigningKey,
    signing_key_bytes: [u8; 32],
}

fn key_identity(seed: [u8; 32]) -> KeyIdentity {
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&pk);
    let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
    let did = format!("did:key:{multibase}");
    let kid = format!("{did}#{multibase}");
    KeyIdentity {
        did,
        kid,
        signing_key: sk,
        signing_key_bytes: seed,
    }
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

fn challenge_request(did: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/auth/challenge")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "did": did })).unwrap(),
        ))
        .unwrap();
    // The challenge handler extracts `ConnectInfo<SocketAddr>` for the
    // per-IP rate limiter; `oneshot` doesn't populate it, so inject a
    // loopback peer address explicitly.
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    req
}

/// Build the DIDComm-v2 JWS authenticate envelope the VTA sends
/// (`build_authenticate_message` equivalent): type
/// `spec/auth/authenticate/0.1`, body `{session_id, challenge}`,
/// `from`/`to` set, JWS-packed with the identity's Ed25519 key.
fn didcomm_authenticate_body(
    id: &KeyIdentity,
    session_id: &str,
    challenge: &str,
    now: u64,
) -> String {
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://trusttasks.org/spec/auth/authenticate/0.1".to_string(),
        json!({ "session_id": session_id, "challenge": challenge }),
    )
    .from(id.did.clone())
    .to(RP_DID.to_string())
    .created_time(now)
    .finalize();

    pack_signed(&msg, &id.kid, &id.signing_key_bytes).expect("pack_signed")
}

/// Build a SIOPv2 id_token Trust-Task envelope (the existing dialect) —
/// used by the regression case to prove that path is unchanged.
fn siop_authenticate_body(id: &KeyIdentity, session_id: &str, challenge: &str, now: u64) -> String {
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": id.kid });
    let payload = json!({
        "iss": id.did,
        "sub": id.did,
        "aud": RP_DID,
        "nonce": challenge,
        "iat": now,
        "exp": now + 300,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = id.signing_key.sign(signing_input.as_bytes());
    let id_token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

    let envelope = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/auth/authenticate/0.1",
        "payload": { "id_token": id_token, "session_id": session_id },
    });
    serde_json::to_string(&envelope).unwrap()
}

fn authenticate_request(body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/auth/")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn read_json(body: Body) -> Value {
    let bytes = body.collect().await.expect("collect body").to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("response is valid JSON")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Drive `POST /api/auth/challenge` for `did` and return
/// `(status, session_id, challenge)`.
async fn do_challenge(state: &AppState, did: &str) -> (StatusCode, String, String) {
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(state.clone())
        .oneshot(challenge_request(did))
        .await
        .unwrap();
    let status = resp.status();
    if status != StatusCode::OK {
        return (status, String::new(), String::new());
    }
    let body = read_json(resp.into_body()).await;
    let session_id = body["sessionId"].as_str().unwrap().to_string();
    let challenge = body["challenge"].as_str().unwrap().to_string();
    (status, session_id, challenge)
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// (A) Without the VTA ACL entry, the VTA's first `POST
/// /api/auth/challenge` is rejected — the canonical challenge handler
/// gates on `check_acl`. This is the `403 DID not in ACL` the operator
/// used to fix by hand; it proves piece (A) is load-bearing.
#[tokio::test]
async fn challenge_rejected_when_vta_not_yet_authorized() {
    let harness = make_harness().await;
    let vta = key_identity([11u8; 32]);

    let (status, _, _) = do_challenge(&harness.state, &vta.did).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "un-authorized VTA DID must be rejected at the challenge gate"
    );
}

/// (A)+(B) End-to-end: after the provisioning ACL seed, the VTA can run
/// its native DIDComm-JWS challenge→authenticate flow and receives an
/// **admin** session — exactly the role that unblocks publishing. This
/// is the whole feature: no manual `add-acl`, no second auth dialect.
#[tokio::test]
async fn provisioning_vta_authenticates_via_didcomm_jws_and_gets_admin_session() {
    let harness = make_harness().await;
    let vta = key_identity([22u8; 32]);

    // (A) Setup-time seed: authorize the provisioning VTA.
    let created = seed_provisioning_vta_acl(&harness.state.acl_ks, &vta.did)
        .await
        .expect("seed vta acl");
    assert!(created, "fresh seed writes the entry");

    // Challenge now passes the ACL gate.
    let (status, session_id, challenge) = do_challenge(&harness.state, &vta.did).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "seeded VTA passes the challenge gate"
    );

    // (B) Authenticate with the DIDComm-JWS envelope the VTA speaks.
    let body = didcomm_authenticate_body(&vta, &session_id, &challenge, now_secs());
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(authenticate_request(body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "daemon must accept the VTA's DIDComm-JWS authenticate envelope"
    );

    let out = read_json(resp.into_body()).await;
    assert_eq!(
        out["session"]["subject"].as_str(),
        Some(vta.did.as_str()),
        "session subject is the VTA DID"
    );
    // The seeded entry is Admin, so the issued session carries the admin
    // role — the role that bypasses the per-DID ownership check on the
    // publish endpoints.
    let access_token = out["tokens"]["accessToken"].as_str().expect("access token");
    let claims = decode_jwt_claims(access_token);
    assert_eq!(
        claims["role"].as_str(),
        Some("admin"),
        "authenticated VTA session must carry admin role (publish-capable)"
    );
}

/// (B) Regression: the SIOPv2 id_token dialect still authenticates on
/// the same endpoint. Proves the DIDComm-JWS acceptance is additive —
/// the wallet/control path is unchanged.
#[tokio::test]
async fn siop_id_token_authenticate_still_works() {
    let harness = make_harness().await;
    let wallet = key_identity([33u8; 32]);

    // Wallet is an Owner (the passkey/SIOP enrolment role).
    seed_owner(&harness.state, &wallet.did).await;

    let (status, session_id, challenge) = do_challenge(&harness.state, &wallet.did).await;
    assert_eq!(status, StatusCode::OK);

    let body = siop_authenticate_body(&wallet, &session_id, &challenge, now_secs());
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(authenticate_request(body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "SIOPv2 id_token path must remain unchanged (additive change)"
    );
    let out = read_json(resp.into_body()).await;
    assert_eq!(
        out["session"]["subject"].as_str(),
        Some(wallet.did.as_str())
    );
}

/// (B) A malformed, non-JWS, non-Trust-Task body still yields the
/// existing `trust-task-error` document (the SIOPv2 parser's malformed
/// path) rather than being misrouted — the content-negotiation only
/// diverts genuine JWS envelopes.
#[tokio::test]
async fn junk_body_still_hits_siop_malformed_path() {
    let harness = make_harness().await;
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(authenticate_request(
            "{\"not\":\"an envelope\"}".to_string(),
        ))
        .await
        .unwrap();
    // The SIOPv2 malformed-envelope path returns a trust-task-error doc
    // with a 4xx status (unchanged behaviour).
    assert!(
        resp.status().is_client_error(),
        "junk body must surface a client error via the unchanged SIOP path, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

async fn seed_owner(state: &AppState, did: &str) {
    use did_hosting_common::server::acl::{AclEntry, store_acl_entry};
    use did_hosting_common::server::auth::session::now_epoch;
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.into(),
            role: Role::Owner,
            label: None,
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .expect("store owner acl");
}

/// Decode a compact JWS payload (no verification — test-only) so we can
/// assert on the minted access-token claims.
fn decode_jwt_claims(token: &str) -> Value {
    let payload_b64 = token.split('.').nth(1).expect("jwt payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).expect("b64url payload");
    serde_json::from_slice(&bytes).expect("jwt payload json")
}

//! The VTA-proxied SIOPv2 sign-in: `POST /api/auth/challenge` (still plain
//! REST — see `routes/mod.rs`) then a proxied `auth/authenticate/0.3` over
//! `POST /api/trust-tasks`, driven against the real Axum router
//! (`routes::router_without_fallback`) via `tower::ServiceExt::oneshot`.
//!
//! Mirrors the did-hosting UI's own client
//! (`wallet-login.ts::authenticateIdTokenBindingSessionKey`): a fresh
//! ephemeral `did:key` is the document's own `issuer` — the *delegate* the
//! proxied form names, whose framework `proof` the control plane verifies
//! exactly as any other authenticate signer — and the persona's SIOPv2
//! `id_token` (signed by the persona's own key) becomes
//! `payload.delegationEvidence` (`kind: "siopIdToken"`), naming
//! `payload.principal` as the persona actually being authenticated. The
//! challenge is requested, unauthenticated, naming the persona directly (the
//! REST endpoint answers any subject — VTI-SES-006/007 — so identity is
//! established only at authenticate time, by the framework proof plus the
//! delegation evidence, never by the challenge request).
//!
//! An ACL entry is what lets a subject obtain a session: the *challenge* is
//! issued to anyone, but only an enrolled persona's evidence redeems into
//! one. The entry `acl::seed_provisioning_vta_acl` writes at setup grants the
//! provisioning VTA an **admin** session.
//!
//! The DIDComm-v2 JWS dialect this used to accept is gone entirely: a peer
//! that signs its own documents signs in with `auth/authenticate` over
//! `POST /api/trust-tasks` — the framework's own proof, not a bespoke JWS.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use affinidi_data_integrity::DidKeyResolver;
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
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
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

/// RP DID the sign-in binds to (the SIOPv2 `aud`). Set as the control plane's `server_did`.
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
        fjall: Default::default(),
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

    // Every reply on `/api/trust-tasks` is a signed Trust Task document
    // (`doc.respond_with`/`reject_with`), so the node needs a signing
    // identity for its own DID — REST replies never needed one.
    let identity = did_hosting_common::server::identity::ServiceIdentity::generated_for(RP_DID)
        .await
        .expect("test identity");

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        registry_ks,
        dids_ks,
        config: Arc::new(config),
        did_resolver: Some(did_resolver),
        secrets_resolver: Some(secrets_resolver),
        identity: Some(identity),
        // `auth/authenticate/0.3` documents now travel over `/api/trust-tasks`
        // (see the module doc), so the outer envelope's framework proof —
        // the *delegate*'s own signature, independent of the SIOP `id_token`
        // inside `delegationEvidence` — needs a verifier configured. A
        // `did:key` resolver is enough: every identity here is one.
        trust_tasks_verifier: Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
            DidKeyResolver,
        )))),
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
        redeem_rate_limiter: Arc::new(did_hosting_control::rate_limit::SourceRateLimiter::new()),
        large_document_budget: Arc::new(
            did_hosting_common::server::trust_tasks::size::LargeDocumentBudget::new(),
        ),
        outbox_notify: Arc::new(tokio::sync::Notify::new()),
        cache_invalidate: None,
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

/// A DIDComm-v2 JWS authenticate envelope — the retired dialect: type
/// `spec/auth/authenticate/0.1`, body `{session_id, challenge}`, addressed to
/// the control plane and JWS-packed with the identity's Ed25519 key. Posted as
/// a raw string body to `/api/trust-tasks`, which expects a plain JSON Trust
/// Task document — a packed JWS is neither, so this is refused before it is
/// ever a candidate for an auth dialect at all.
fn didcomm_authenticate_body(
    id: &KeyIdentity,
    session_id: &str,
    challenge: &str,
    now: u64,
) -> String {
    let mut msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://trusttasks.org/spec/auth/authenticate/0.1".to_string(),
        json!({ "session_id": session_id, "challenge": challenge }),
    )
    .from(id.did.clone())
    .created_time(now)
    .finalize();
    msg.to = Some(vec![RP_DID.to_string()]);

    pack_signed(&msg, &id.kid, &id.signing_key_bytes).expect("pack_signed")
}

/// A SIOPv2 self-issued `id_token`: `iss`/`sub` is `id`, `aud` is the control
/// plane, `nonce` is the challenge this login is redeeming.
fn siop_id_token(id: &KeyIdentity, challenge: &str, now: u64) -> String {
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
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// A `Secret` over the same key material as `id`, for signing the outer
/// Trust Task envelope's framework `proof` (Data Integrity, not the SIOP
/// JWT — the two are independent signatures per `auth/authenticate/0.3`
/// Conformance item 3).
fn secret_for(id: &KeyIdentity) -> affinidi_tdk::secrets_resolver::secrets::Secret {
    let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(
        None,
        Some(&id.signing_key_bytes),
    );
    let mut secret = secret;
    secret.id = id.kid.clone();
    secret
}

/// Sign `doc` (proof-less) with `id`'s key, `proofPurpose: authentication`.
async fn sign_envelope(doc: Value, id: &KeyIdentity) -> Value {
    let typed: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(doc).unwrap();
    let canonical = serde_json::to_value(&typed).unwrap();
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &canonical,
        &secret_for(id),
        affinidi_data_integrity::SignOptions::new().with_proof_purpose("authentication"),
    )
    .await
    .expect("sign");
    let mut out = canonical;
    out["proof"] = serde_json::to_value(&proof).unwrap();
    out
}

/// Build a proxied `auth/authenticate/0.3` document: `delegate` signs as
/// `issuer`, naming `principal` as the persona being authenticated, with a
/// `siopIdToken` naming `principal`'s own SIOPv2 token as delegation
/// evidence — exactly the shape `wallet-login.ts`'s
/// `authenticateIdTokenBindingSessionKey` sends.
async fn proxied_authenticate_body(
    delegate: &KeyIdentity,
    principal: &KeyIdentity,
    session_id: &str,
    challenge: &str,
    now: u64,
    session_key: Option<&str>,
) -> Value {
    let id_token = siop_id_token(principal, challenge, now);
    let mut payload = json!({
        "challenge": challenge,
        "sessionId": session_id,
        "principal": principal.did,
        "delegationEvidence": {
            "kind": "siopIdToken",
            "credential": { "idToken": id_token },
        },
    });
    if let Some(k) = session_key {
        payload["sessionKey"] = json!(k);
    }
    let doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/auth/authenticate/0.3",
        "issuer": delegate.did,
        "recipient": RP_DID,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    sign_envelope(doc, delegate).await
}

fn authenticate_request(body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn junk_authenticate_request(body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/trust-tasks")
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

/// Without the VTA ACL entry, the VTA cannot authenticate. The
/// *challenge* is issued — deliberately, per vti-common's canonical
/// handler (VTI-SES-006/007): a challenge endpoint that refuses an
/// unknown subject and answers a known one is an enumeration oracle,
/// so both subjects get a challenge and only an enrolled one gets a
/// session to redeem it against. The challenge handed to an unenrolled
/// subject is therefore **unusable**, and that is what this pins:
/// `/auth/authenticate` finds no session and refuses.
///
/// (This used to assert `403` at the challenge gate. That gate was
/// removed upstream as the oracle it was; the property it was standing
/// in for — an un-authorized VTA DID gets no session — is asserted
/// here directly, one step later, where it actually holds.)
#[tokio::test]
async fn unauthorized_vta_gets_a_challenge_it_cannot_redeem() {
    let harness = make_harness().await;
    let vta = key_identity([11u8; 32]);
    let delegate = key_identity([111u8; 32]);

    let (status, session_id, challenge) = do_challenge(&harness.state, &vta.did).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the challenge endpoint must not distinguish enrolled from unenrolled \
         subjects — that is the enumeration oracle VTI-SES-006 closes"
    );

    // The redemption is where authority is decided, and there is none.
    let body =
        proxied_authenticate_body(&delegate, &vta, &session_id, &challenge, now_secs(), None).await;
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(authenticate_request(body))
        .await
        .unwrap();
    let status = resp.status();
    let out = read_json(resp.into_body()).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "un-authorized VTA DID must not obtain a session: {out}"
    );
}

/// After the provisioning ACL seed, the VTA's sign-in yields an **admin**
/// session — exactly the role that unblocks publishing, with no manual
/// `add-acl`.
#[tokio::test]
async fn the_provisioning_vta_seed_grants_an_admin_session() {
    let harness = make_harness().await;
    let vta = key_identity([22u8; 32]);
    let delegate = key_identity([122u8; 32]);

    // Setup-time seed: authorize the provisioning VTA.
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

    let body =
        proxied_authenticate_body(&delegate, &vta, &session_id, &challenge, now_secs(), None).await;
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(authenticate_request(body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the seeded VTA must be able to sign in"
    );

    let out = read_json(resp.into_body()).await;
    assert_eq!(
        out["payload"]["session"]["subject"].as_str(),
        Some(vta.did.as_str()),
        "session subject is the VTA persona, not the delegate that signed"
    );
    assert_eq!(
        out["payload"]["session"]["actor"].as_str(),
        Some(delegate.did.as_str()),
        "session actor records the delegate that opened it"
    );
    // The seeded entry is Admin, so the issued session carries the admin
    // role — the role that bypasses the per-DID ownership check on the
    // publish endpoints.
    let access_token = out["payload"]["tokens"]["accessToken"]
        .as_str()
        .expect("access token");
    let claims = decode_jwt_claims(access_token);
    assert_eq!(
        claims["role"].as_str(),
        Some("admin"),
        "authenticated VTA session must carry admin role (publish-capable)"
    );
}

/// A DIDComm-v2 JWS sign-in is not accepted here any more — even from a
/// subject that holds an admin entry and a live challenge.
#[tokio::test]
async fn a_didcomm_jws_sign_in_is_refused() {
    let harness = make_harness().await;
    let vta = key_identity([23u8; 32]);
    seed_provisioning_vta_acl(&harness.state.acl_ks, &vta.did)
        .await
        .expect("seed vta acl");
    let (status, session_id, challenge) = do_challenge(&harness.state, &vta.did).await;
    assert_eq!(status, StatusCode::OK);

    let body = didcomm_authenticate_body(&vta, &session_id, &challenge, now_secs());
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(junk_authenticate_request(body))
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "a JWS envelope must be refused, got {}",
        resp.status()
    );
}

/// The SIOPv2 id_token sign-in, wrapped as a proxied `auth/authenticate/0.3`,
/// authenticates.
#[tokio::test]
async fn siop_id_token_authenticate_works() {
    let harness = make_harness().await;
    let wallet = key_identity([33u8; 32]);
    let delegate = key_identity([133u8; 32]);

    // Wallet is an Owner (the passkey/SIOP enrolment role).
    seed_owner(&harness.state, &wallet.did).await;

    let (status, session_id, challenge) = do_challenge(&harness.state, &wallet.did).await;
    assert_eq!(status, StatusCode::OK);

    let body = proxied_authenticate_body(
        &delegate,
        &wallet,
        &session_id,
        &challenge,
        now_secs(),
        None,
    )
    .await;
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(authenticate_request(body))
        .await
        .unwrap();
    let status = resp.status();
    let out = read_json(resp.into_body()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "SIOPv2 id_token delegation evidence must authenticate the persona: {out}"
    );
    assert_eq!(
        out["payload"]["session"]["subject"].as_str(),
        Some(wallet.did.as_str())
    );
}

/// The wallet proxy login binds the Web UI's session key through this
/// document: a fresh `did:key` is both the document's own `issuer` (the
/// delegate) and, named again as `sessionKey`, the key the control plane
/// binds to the new session — see `wallet-login.ts`. The key must land on
/// the session row, which is what lets it sign the session's later calls in
/// place of the wallet.
#[tokio::test]
async fn siop_id_token_authenticate_binds_a_session_key() {
    let harness = make_harness().await;
    let persona = key_identity([34u8; 32]);
    let delegate = key_identity([35u8; 32]);
    seed_owner(&harness.state, &persona.did).await;

    let (status, session_id, challenge) = do_challenge(&harness.state, &persona.did).await;
    assert_eq!(status, StatusCode::OK);

    let body = proxied_authenticate_body(
        &delegate,
        &persona,
        &session_id,
        &challenge,
        now_secs(),
        Some(&delegate.did),
    )
    .await;
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(authenticate_request(body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let out = read_json(resp.into_body()).await;
    let bound_session = out["payload"]["session"]["id"]
        .as_str()
        .expect("session id");

    let session = did_hosting_common::server::auth::session::get_session(
        &harness.state.sessions_ks,
        bound_session,
    )
    .await
    .expect("read session")
    .expect("session exists");
    assert_eq!(session.did, persona.did);
    assert_eq!(
        session.session_pubkey_b58btc.as_deref(),
        Some(delegate.did.trim_start_matches("did:key:"))
    );
}

/// A `sessionKey` that only *looks* like an Ed25519 `did:key` — the right
/// `z6Mk` prefix over bytes that are not one — is refused, not stored: a
/// bound key whose every later proof fails would leave the producer with a
/// session it believes works. Refused before the challenge is spent, so the
/// same challenge still redeems.
#[tokio::test]
async fn siop_id_token_authenticate_refuses_a_malformed_session_key() {
    let harness = make_harness().await;
    let persona = key_identity([36u8; 32]);
    let delegate = key_identity([37u8; 32]);
    seed_owner(&harness.state, &persona.did).await;

    let (status, session_id, challenge) = do_challenge(&harness.state, &persona.did).await;
    assert_eq!(status, StatusCode::OK);

    let pk = delegate.did.trim_start_matches("did:key:").to_string();
    let truncated = format!("did:key:{}", &pk[..pk.len() - 4]);
    let not_base58 = format!("did:key:z6Mk{}", "0OIl".repeat(10));
    let extended = format!("{}zz", delegate.did);
    for bad in [truncated.as_str(), not_base58.as_str(), extended.as_str()] {
        let body = proxied_authenticate_body(
            &delegate,
            &persona,
            &session_id,
            &challenge,
            now_secs(),
            Some(bad),
        )
        .await;
        let resp = did_hosting_control::routes::router_without_fallback()
            .with_state(harness.state.clone())
            .oneshot(authenticate_request(body))
            .await
            .unwrap();
        assert!(
            resp.status().is_client_error(),
            "{bad}: a malformed session key must be refused, got {}",
            resp.status()
        );
    }

    let body = proxied_authenticate_body(
        &delegate,
        &persona,
        &session_id,
        &challenge,
        now_secs(),
        None,
    )
    .await;
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(authenticate_request(body))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the challenge survives a refused key"
    );
}

/// A malformed body yields a `trust-task-error` document with a 4xx status.
#[tokio::test]
async fn a_junk_body_is_a_malformed_request() {
    let harness = make_harness().await;
    let resp = did_hosting_control::routes::router_without_fallback()
        .with_state(harness.state.clone())
        .oneshot(junk_authenticate_request(
            "{\"not\":\"an envelope\"}".to_string(),
        ))
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "junk body must surface a client error, got {}",
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

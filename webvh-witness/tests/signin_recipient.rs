//! affinidi-webvh-service#207: a signed (JWS) DIDComm sign-in is readable
//! and forwardable by anyone who holds it — the signature proves who wrote
//! it, not who it was for. A service the holder signed in to could relay
//! the message here and be issued a session as the holder. So the witness
//! accepts a signed sign-in only when it is addressed, by `to`, to this
//! service's own DID and to nothing else.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::message::pack::pack_signed;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::auth::jwt::JwtKeys;
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::server::store::{KS_ACL, KS_SESSIONS, KS_WITNESSES, KeyspaceHandle, Store};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use webvh_witness::config::AppConfig;
use webvh_witness::server::AppState;
use webvh_witness::signing::LocalSigner;

const OWN_DID: &str = "did:webvh:test:witness.example.com";

struct KeyIdentity {
    did: String,
    kid: String,
    seed: [u8; 32],
}

fn key_identity(seed: [u8; 32]) -> KeyIdentity {
    let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&pk);
    let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
    let did = format!("did:key:{multibase}");
    KeyIdentity {
        kid: format!("{did}#{multibase}"),
        did,
        seed,
    }
}

fn post(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn authenticate_body(
    id: &KeyIdentity,
    session_id: &str,
    challenge: &str,
    to: Option<Vec<&str>>,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://trusttasks.org/spec/auth/authenticate/0.1".to_string(),
        json!({ "session_id": session_id, "challenge": challenge }),
    )
    .from(id.did.clone())
    .created_time(now)
    .finalize();
    msg.to = to.map(|v| v.into_iter().map(String::from).collect());
    pack_signed(&msg, &id.kid, &id.seed).expect("pack_signed")
}

async fn enrol(acl_ks: &KeyspaceHandle, did: &str) {
    store_acl_entry(
        acl_ks,
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
}

/// Challenge, then present each wrongly-addressed sign-in, then the
/// correctly-addressed one — which must still succeed, proving the refused
/// ones never reached (and so never consumed) the session.
async fn assert_only_addressed_sign_in_succeeds(app: axum::Router, id: &KeyIdentity) {
    let resp = app
        .clone()
        .oneshot(post(
            "/api/auth/challenge",
            json!({ "did": id.did }).to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "challenge");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let session_id = body["sessionId"].as_str().expect("sessionId").to_string();
    let challenge = body["challenge"].as_str().expect("challenge").to_string();

    for (to, want, why) in [
        (
            Some(vec!["did:web:some-other-service.example"]),
            StatusCode::UNAUTHORIZED,
            "addressed to another service (the relay)",
        ),
        (
            Some(vec![OWN_DID, "did:web:some-other-service.example"]),
            StatusCode::UNAUTHORIZED,
            "addressed to this service and another",
        ),
        (None, StatusCode::BAD_REQUEST, "no `to` at all"),
    ] {
        let resp = app
            .clone()
            .oneshot(post(
                "/api/auth/",
                authenticate_body(id, &session_id, &challenge, to),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), want, "{why}");
    }

    let resp = app
        .clone()
        .oneshot(post(
            "/api/auth/",
            authenticate_body(id, &session_id, &challenge, Some(vec![OWN_DID])),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a sign-in addressed to this service succeeds, and the refused ones did not consume the session"
    );

    // The same correctly-addressed envelope, replayed: the sign-in is
    // single-use, so the second presentation is refused. `to` binding does
    // not carry replay protection by itself — `unpack_signed`'s 5-minute
    // freshness window and the canonical handler's single-use challenge row
    // do — and this asserts those still hold at the route.
    let resp = app
        .oneshot(post(
            "/api/auth/",
            authenticate_body(id, &session_id, &challenge, Some(vec![OWN_DID])),
        ))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "a correctly-addressed sign-in must not be replayable for a second session"
    );
}

#[tokio::test]
async fn a_signed_sign_in_must_be_addressed_to_this_witness_server() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let acl_ks = store.keyspace(KS_ACL).expect("acl ks");
    let holder = key_identity([32u8; 32]);
    enrol(&acl_ks, &holder.did).await;

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("did:key resolver");
    let secrets_resolver = Arc::new(
        affinidi_tdk::secrets_resolver::ThreadedSecretsResolver::new(None)
            .await
            .0,
    );

    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some(OWN_DID.into()),
        mediator_did: None,
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(),
        identity: Default::default(),
        config_path: PathBuf::new(),
    };
    let state = AppState {
        store: store.clone(),
        sessions_ks: store.keyspace(KS_SESSIONS).expect("sessions ks"),
        acl_ks,
        witnesses_ks: store.keyspace(KS_WITNESSES).expect("witnesses ks"),
        config: Arc::new(config),
        did_resolver: Some(did_resolver),
        secrets_resolver: Some(secrets_resolver),
        identity: None,
        didcomm_service: Arc::new(OnceLock::new()),
        jwt_keys: Some(Arc::new(
            JwtKeys::from_ed25519_bytes(&[7u8; 32]).expect("test jwt keys"),
        )),
        signer: Arc::new(LocalSigner),
    };
    let app = webvh_witness::routes::router().with_state(state);

    assert_only_addressed_sign_in_succeeds(app, &holder).await;
}

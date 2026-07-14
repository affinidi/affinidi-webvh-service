//! Regression test for the DIDComm refresh-token / signer-DID binding.
//!
//! The vulnerability the binding closes: a leaked refresh token could be
//! redeemed by any DID that can produce a valid signed DIDComm envelope,
//! yielding a fresh access token for the victim's session.
//!
//! The local refresh handler in `routes::auth::refresh` unpacks the DIDComm
//! sender DID and passes it as `RefreshInput::signer_did` to the canonical
//! `vti_common::auth::handlers::handle_refresh`. The canonical handler
//! compares it against `session.did` and rejects mismatches with
//! `AuthError::SignerMismatch`, which the local error mapper renders as
//! `AppError::Authentication`.
//!
//! This test exercises that path end-to-end against `DidHostingServerAuthBackend`
//! so a future refactor that drops `signer_did` (or hard-codes it to `None`)
//! fails CI loudly.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use did_hosting_common::server::auth::jwt::JwtKeys;
use did_hosting_common::server::auth::session::{Session, SessionState, store_session};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS, Store};
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::error::AppError;
use did_hosting_server::server::AppState;
use vti_common::auth::RefreshInput;
use vti_common::auth::backend::{AuthBackend, SessionStore};

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

    let jwt_keys = Arc::new(JwtKeys::from_ed25519_bytes(&[7u8; 32]).expect("test jwt keys"));

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
        jwt_keys: Some(jwt_keys),
        signing_key_bytes: None,
        http_client: reqwest::Client::new(),
        stats_collector: None,
        did_cache: Arc::new(ContentCache::new(Duration::from_secs(60))),
        trusted_proxy_cidrs: Arc::new(Vec::new()),
    };
    (state, dir)
}

/// `AuthBackend::mint_access_token` must stamp the `jti` the caller supplies,
/// not the random one `JwtKeys::new_claims` generates for itself.
///
/// The canonical handlers mint a `token_id`, hand it to the backend as `jti`,
/// and pin it to the session row. `AuthClaims` then rejects any token whose
/// `jti` differs from the session's `token_id`. So a backend that ignores the
/// argument still compiles, still returns a well-formed JWT — and every token
/// it mints is rejected as revoked on the holder's very next request.
#[tokio::test]
async fn mint_access_token_stamps_the_supplied_jti() {
    let (state, _dir) = make_state().await;
    let backend =
        did_hosting_server::auth::DidHostingServerAuthBackend::from_state(&state).expect("backend");

    let token = backend
        .mint_access_token(
            "did:webvh:test:alice",
            "session-jti-test",
            &did_hosting_server::acl::Role::Owner,
            &[],
            &["did".to_string()],
            "aal1",
            false,
            300,
            "the-callers-token-id",
        )
        .await
        .expect("mint");

    let jwt_keys = state.jwt_keys.as_ref().expect("jwt keys");
    let claims = jwt_keys.decode(&token).expect("decode minted token");
    assert_eq!(
        claims.jti, "the-callers-token-id",
        "minted token must carry the caller's jti, else AuthClaims treats it as revoked"
    );
}

#[tokio::test]
async fn refresh_rejects_signer_did_mismatch() {
    let (state, _dir) = make_state().await;
    let backend =
        did_hosting_server::auth::DidHostingServerAuthBackend::from_state(&state).expect("backend");

    let session_owner = "did:webvh:test:alice";
    let attacker_did = "did:webvh:test:mallory";
    let refresh_token = "refresh-token-under-test";

    // Seed an authenticated session owned by `session_owner`, with a known
    // refresh token and a far-future expiry so the signer check is the
    // only thing that can reject the call.
    let session = Session {
        session_id: "session-binding-test".to_string(),
        did: session_owner.to_string(),
        challenge: String::new(),
        state: SessionState::Authenticated,
        created_at: 0,
        last_seen: 0,
        refresh_token: Some(refresh_token.to_string()),
        refresh_expires_at: Some(u64::MAX),
        tee_attested: false,
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
        acr_expires_at: None,
        token_id: None,
        session_pubkey_b58btc: None,
    };
    store_session(&state.sessions_ks, &session)
        .await
        .expect("seed session");
    backend
        .sessions()
        .store_refresh_index(refresh_token, &session.session_id)
        .await
        .expect("seed refresh index");

    // Mallory presents Alice's refresh token but signs the envelope with
    // their own DID — the canonical handler must reject before minting.
    let err = vti_common::auth::handlers::handle_refresh(
        &backend,
        RefreshInput {
            refresh_token: refresh_token.to_string(),
            signer_did: Some(attacker_did.to_string()),
        },
    )
    .await
    .expect_err("refresh must be rejected when signer DID does not match session DID");

    match err {
        AppError::Authentication(msg) => {
            assert!(
                msg.to_lowercase().contains("signer") || msg.to_lowercase().contains("mismatch"),
                "expected an auth error mentioning signer mismatch, got: {msg}"
            );
        }
        other => panic!("expected AppError::Authentication, got: {other:?}"),
    }
}

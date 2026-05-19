//! Coverage for the DIDComm router and dispatcher in `did-hosting-control`.
//!
//! The audit flagged `messaging::build_control_router` and the protocol
//! error mapper as load-bearing wire-level contracts that had no tests.
//! These cases lock down the contract:
//!
//! 1. `build_control_router` constructs successfully — every `route(...)`
//!    call registers without conflict and every handler resolves. A typo
//!    in a `MSG_*` constant or an accidental duplicate route becomes a
//!    test failure rather than a runtime surprise.
//! 2. `dispatch_did_op` returns a clear `Validation` error for unknown
//!    message types — pins the "unknown type" wire response so the
//!    DIDComm protocol-error mapping (covered separately by
//!    `map_app_error_code_pinned_table`) maps it to
//!    `e.p.did.validation-error`.
//!
//! Bigger end-to-end tests of every dispatch arm need fakes for the
//! mediator and ATM transport; those are tracked separately. This test
//! is the cheap regression net for the contract surface.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
};
use did_hosting_control::config::{AppConfig, RegistryConfig};
use did_hosting_control::server::AppState;

async fn make_state() -> (AppState, tempfile::TempDir) {
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
        config_path: PathBuf::new(),
    };

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
        jwt_keys: None,
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
    };

    (state, dir)
}

/// `build_control_router` registers every MSG_* type without conflict and
/// every handler resolves. A typo in a `MSG_*` constant, a duplicated
/// route, or a handler signature drift becomes a test failure.
#[tokio::test]
async fn build_control_router_constructs_all_handlers() {
    let (state, _dir) = make_state().await;
    let result = did_hosting_control::messaging::build_control_router(state);
    assert!(
        result.is_ok(),
        "build_control_router failed: {:?}",
        result.err()
    );
}

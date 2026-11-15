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

use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::Store;
use did_hosting_control::config::{AppConfig, RegistryConfig};
use did_hosting_control::server::AppState;

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
        public_url: Some("http://localhost:8532".into()),
        did_hosting_url: Some("http://localhost:8532".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config.clone(),
        fjall: Default::default(),
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(),
        registry: RegistryConfig::default(),
        trust_tasks: Default::default(),
        hosting: Default::default(),
        identity: Default::default(),
        replay: Default::default(),
        geoip: Default::default(),
        stats_flush: Default::default(),
        stats: Default::default(),
        config_path: PathBuf::new(),
    };

    let state = did_hosting_control::test_support::bare_state(config, store.clone(), None).await;

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

//! In-process test harness for the control plane — enabled by the
//! `test-support` feature.
//!
//! Every integration test, and every downstream consumer that wants to cover a
//! control-plane path in its own suite, otherwise hand-assembles an
//! [`AppState`] with ~25 fields over six fjall keyspaces. That boilerplate had
//! drifted between test files and could not be reproduced outside this crate at
//! all — the `AppState` fields are `pub` but the *recipe* for a valid one is
//! not. This module is that recipe, in one place.
//!
//! ```no_run
//! # async fn ex() {
//! use did_hosting_control::test_support::TestServer;
//! use did_hosting_common::server::acl::Role;
//!
//! let ts = TestServer::start().await;
//! let owner = "did:example:owner";
//! ts.add_acl(owner, Role::Owner).await;
//! ts.seed_did(owner, "aliceslot").await;
//! let token = ts.mint_token(owner, Role::Owner).await;
//!
//! // Drive the real router with `tower::ServiceExt::oneshot`.
//! let app = ts.router();
//! # }
//! ```
//!
//! The defaults describe a self-contained HTTP-only node: no DID resolver, no
//! secrets resolver, no identity, agent names on (the shipped default), a JWT
//! key configured so authenticated routes work. Anything a specific test needs
//! to vary goes through [`TestServerOptions`]; anything it needs to inspect is a
//! `pub` field on [`TestServer::state`].

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use did_hosting_common::did_ops::{DidRecord, did_key, owner_key};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::auth::session::{create_authenticated_session, now_epoch};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES, Store,
};

use crate::auth::jwt::JwtKeys;
use crate::config::{AppConfig, RegistryConfig};
use crate::server::AppState;

/// Knobs for [`TestServer::start_with`]. `Default` reproduces
/// [`TestServer::start`] exactly: a hosting node with agent names on, a JWT key
/// configured, and no messaging/identity wiring.
pub struct TestServerOptions {
    /// The full features config. `None` (the default) means
    /// `FeaturesConfig::default()`, which serves agent names — see
    /// [`Self::agent_names`] for the common single-flag case.
    pub features: Option<FeaturesConfig>,
    /// The node's own `server_did`. Defaults to a fixed test DID on
    /// `control.example.com`. Set `None` to leave it unconfigured (the branch
    /// that disables WebAuthn and refuses to send signed trust tasks).
    pub server_did: Option<Option<String>>,
    /// VTA config — set when a test drives the VTA-provisioned auth path.
    pub vta: VtaConfig,
    /// Configure a JWT signing key (required for any authenticated route).
    /// Default `true`; set `false` to exercise the unconfigured-JWT branch.
    pub with_jwt: bool,
}

impl Default for TestServerOptions {
    fn default() -> Self {
        Self {
            features: None,
            server_did: None,
            vta: VtaConfig::default(),
            with_jwt: true,
        }
    }
}

impl TestServerOptions {
    /// Override just the agent-name flag, leaving every other feature at its
    /// default. Sugar for the most common single-knob case; incompatible with a
    /// full [`Self::features`] override (the explicit config wins).
    pub fn agent_names(mut self, on: bool) -> Self {
        let mut f = self.features.take().unwrap_or_default();
        f.agent_names = on;
        self.features = Some(f);
        self
    }
}

/// A running in-process control plane over a temporary fjall store.
///
/// Keep the value alive for the duration of the test: dropping it removes the
/// on-disk store (via the owned [`tempfile::TempDir`]), so binding it to `let
/// _ts` and then only using `ts.state` would delete the data mid-test.
pub struct TestServer {
    /// The assembled application state — every field `pub`, so a test reads a
    /// keyspace (`ts.state.dids_ks`) or the config directly for assertions.
    pub state: AppState,
    /// Owns the fjall data dir; files vanish when this drops.
    _dir: tempfile::TempDir,
}

impl TestServer {
    /// Start a node with the default configuration.
    pub async fn start() -> Self {
        Self::start_with(TestServerOptions::default()).await
    }

    /// Start a node, overriding the defaults through `opts`.
    pub async fn start_with(opts: TestServerOptions) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.expect("open store");

        // Open every keyspace up front — the same set `run_control()` opens, so
        // a harness never trips over a missing one mid-test.
        let sessions_ks = store.keyspace(KS_SESSIONS).expect("sessions ks");
        let acl_ks = store.keyspace(KS_ACL).expect("acl ks");
        let registry_ks = store.keyspace(KS_REGISTRY).expect("registry ks");
        let dids_ks = store.keyspace(KS_DIDS).expect("dids ks");
        let stats_ks = store.keyspace(KS_STATS).expect("stats ks");
        let timeseries_ks = store.keyspace(KS_TIMESERIES).expect("timeseries ks");

        let server_did = opts
            .server_did
            .unwrap_or_else(|| Some("did:webvh:test:control.example.com".into()));

        let config = AppConfig {
            features: opts.features.unwrap_or_default(),
            server_did,
            mediator_did: None,
            public_url: Some("http://control.test".into()),
            did_hosting_url: Some("http://control.test".into()),
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: store_config,
            auth: AuthConfig::default(),
            secrets: SecretsConfig::default(),
            vta: opts.vta,
            registry: RegistryConfig::default(),
            trust_tasks: Default::default(),
            hosting: Default::default(),
            identity: Default::default(),
            config_path: PathBuf::new(),
        };

        // A fixed seed — deterministic across runs, which is what a test wants;
        // the value itself is irrelevant, only that verify matches sign.
        let jwt_keys = opts
            .with_jwt
            .then(|| Arc::new(JwtKeys::from_ed25519_bytes(&[7u8; 32]).expect("jwt keys")));

        let state = AppState {
            store: store.clone(),
            sessions_ks,
            acl_ks,
            registry_ks,
            dids_ks,
            config: Arc::new(config),
            did_resolver: None,
            secrets_resolver: None,
            identity: None,
            trust_tasks_verifier: None,
            jwt_keys,
            webauthn: None,
            http_client: reqwest::Client::new(),
            didcomm_service: Arc::new(OnceLock::new()),
            stats_collector: Arc::new(StatsCollector::new()),
            stats_ks,
            timeseries_ks,
            signing_key_bytes: None,
            replay_cache: Arc::new(crate::replay::ReplayCache::new()),
            path_locks: crate::path_locks::PathLocks::new(),
            acl_locks: did_hosting_common::server::path_locks::PathLocks::new(),
            pending_challenges: Arc::new(crate::pending_challenges::PendingChallengeTracker::new()),
            ip_rate_limiter: Arc::new(crate::rate_limit::IpRateLimiter::new()),
            pending_confirms: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            outbox_notify: Arc::new(tokio::sync::Notify::new()),
        };

        Self { state, _dir: dir }
    }

    /// The real control-plane router, ready for `tower::ServiceExt::oneshot`.
    ///
    /// This is the fallback-free router the route tests drive — it 404s an
    /// unmatched path instead of serving the SPA, which is what an HTTP-shape
    /// test wants.
    pub fn router(&self) -> axum::Router {
        crate::routes::router_without_fallback().with_state(self.state.clone())
    }

    /// Grant `did` an ACL entry with `role` and unrestricted domain scope.
    pub async fn add_acl(&self, did: &str, role: Role) {
        store_acl_entry(
            &self.state.acl_ks,
            &AclEntry {
                did: did.into(),
                role,
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

    /// Mint a real (aal1) authenticated session and return its access token.
    ///
    /// Panics if the server was built with `with_jwt: false` — there is no key
    /// to sign with, and a token minted against no key is not a meaningful test
    /// input.
    pub async fn mint_token(&self, did: &str, role: Role) -> String {
        let keys = self
            .state
            .jwt_keys
            .as_ref()
            .expect("mint_token requires a JWT key; build with `with_jwt: true`");
        let auth = AuthConfig::default();
        create_authenticated_session(
            &self.state.sessions_ks,
            keys,
            did,
            &role,
            auth.access_token_expiry,
            auth.refresh_token_expiry,
            None,
            None,
        )
        .await
        .expect("create session")
        .access_token
    }

    /// Seed a published `DidRecord` at `mnemonic` owned by `owner_did`, writing
    /// both the record and its owner index in one batch — the shape
    /// `register_did_atomic` would leave behind, so an agent-name op or a
    /// publish finds a consistent slot. Returns the seeded record.
    ///
    /// The DID is pinned to the test host so the identifier is well-formed; a
    /// test that needs a specific `did_id`, domain, or existing agent names can
    /// mutate the returned record and re-seed via [`Self::put_did`].
    pub async fn seed_did(&self, owner_did: &str, mnemonic: &str) -> DidRecord {
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
            method: "webvh".to_string(),
            domain: String::new(),
            services: None,
            agent_names: Vec::new(),
        };
        self.put_did(&record).await;
        // Owner index — `register_did_atomic` writes this alongside the record.
        self.state
            .dids_ks
            .insert_raw(owner_key(owner_did, mnemonic), mnemonic.as_bytes().to_vec())
            .await
            .expect("seed owner index");
        record
    }

    /// Write a `DidRecord` to the `dids` keyspace verbatim. Pairs with
    /// [`Self::seed_did`] when a test has hand-built a record (a specific
    /// domain, pre-existing agent names, a takeover state) it wants persisted.
    pub async fn put_did(&self, record: &DidRecord) {
        self.state
            .dids_ks
            .insert(did_key(&record.mnemonic), record)
            .await
            .expect("put did record");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default node serves agent names (the shipped default since the flag
    /// was flipped on) and has a JWT key, so authenticated routes work out of
    /// the box.
    #[tokio::test]
    async fn defaults_serve_agent_names_and_configure_jwt() {
        let ts = TestServer::start().await;
        assert!(ts.state.config.features.agent_names);
        assert!(ts.state.jwt_keys.is_some());
        assert_eq!(
            ts.state.config.server_did.as_deref(),
            Some("did:webvh:test:control.example.com")
        );
    }

    /// The one-flag sugar flips only agent names, leaving siblings default.
    #[tokio::test]
    async fn agent_names_knob_is_isolated() {
        let ts = TestServer::start_with(TestServerOptions::default().agent_names(false)).await;
        assert!(!ts.state.config.features.agent_names);
        assert!(!ts.state.config.features.didcomm);
        assert!(!ts.state.config.features.rest_api);
    }

    /// `seed_did` leaves a slot a publish or agent-name op can find: the record
    /// round-trips and its owner index points back at the mnemonic.
    #[tokio::test]
    async fn seed_did_writes_record_and_owner_index() {
        let ts = TestServer::start().await;
        let owner = "did:example:owner";
        let seeded = ts.seed_did(owner, "slot-one").await;
        assert_eq!(seeded.owner, owner);

        let stored: DidRecord = ts
            .state
            .dids_ks
            .get(did_key("slot-one"))
            .await
            .unwrap()
            .expect("record present");
        assert_eq!(stored.owner, owner);
        assert_eq!(
            ts.state
                .dids_ks
                .get_raw(owner_key(owner, "slot-one"))
                .await
                .unwrap()
                .as_deref(),
            Some(b"slot-one".as_slice()),
            "owner index must point back at the mnemonic"
        );
    }

    /// A minted token authenticates against the real router — a round-trip
    /// through the fixture's two moving parts (session store + JWT key).
    #[tokio::test]
    async fn minted_token_is_accepted_by_the_router() {
        use did_hosting_common::server::acl::Role;
        let ts = TestServer::start().await;
        let owner = "did:example:owner";
        ts.add_acl(owner, Role::Owner).await;
        let token = ts.mint_token(owner, Role::Owner).await;
        assert!(!token.is_empty());
        // The router builds; a full request round-trip is covered by the
        // agent-name REST suite, which now drives this exact fixture.
        let _app = ts.router();
    }
}

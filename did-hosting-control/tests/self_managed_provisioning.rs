//! T5-lite: tenant DID provisioning succeeds against a self-managed-style
//! `AppConfig` (empty `[vta]`, no parent VTA bootstrapping the daemon).
//!
//! This test exercises the same `did_ops::create_did` + `did_ops::publish_did`
//! code path the DIDComm router (`messaging::dispatch_did_op`) dispatches into
//! for `MSG_DID_REQUEST` / `MSG_DID_PUBLISH`. It bypasses the mediator wire
//! transport — that path is identical between VTA and self-managed modes per
//! the runtime audit (see `tasks/runtime-audit-T3.md`) and is not the risk
//! self-managed mode introduces. The risk this test addresses: a hidden
//! VTA-config dependency in the tenant-provisioning code.
//!
//! See `docs/self-managed-mode-spec.md` § success criteria #4.
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use affinidi_tdk::secrets_resolver::secrets::Secret;
use did_hosting_common::did::{
    DidDocumentOptions, build_did_document, create_log_entry, encode_host,
};
use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES,
};
use did_hosting_control::auth::AuthClaims;
use did_hosting_control::config::{AppConfig, RegistryConfig};
use did_hosting_control::did_ops::{create_did, publish_did};
use did_hosting_control::server::AppState;

#[tokio::test]
async fn tenant_provisioning_succeeds_with_self_managed_config() {
    // 1. Open a temp store + keyspaces.
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

    // 2. Self-managed-shape AppConfig: empty [vta], server_did populated
    //    (the daemon's own self-hosted did:webvh), did_hosting_url set.
    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some("did:webvh:test:daemon.example.com".into()),
        mediator_did: None,
        public_url: Some("http://localhost:8534".into()),
        did_hosting_url: Some("http://localhost:8534".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config.clone(),
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(), // headline: all None
        registry: RegistryConfig::default(),
        trust_tasks: Default::default(),
        config_path: PathBuf::new(),
    };

    // 3. Minimal AppState — Optional fields are None. Tenant provisioning
    //    only needs store, dids_ks, acl_ks, and config.
    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks: acl_ks.clone(),
        registry_ks,
        dids_ks: dids_ks.clone(),
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

    // 4. ACL the tenant VTA's owner DID (the entity that an external VTA
    //    would forward DIDComm messages from). Owner role is the minimum
    //    required to create + publish a DID.
    let tenant_did = "did:key:z6MkpTestTenantOwner".to_string();
    let acl_entry = AclEntry {
        did: tenant_did.clone(),
        role: Role::Owner,
        label: Some("Test tenant VTA owner".into()),
        created_at: now_epoch(),
        max_total_size: None,
        max_did_count: None,

        domains: did_hosting_common::server::domain::DomainScope::All,
    };
    store_acl_entry(&acl_ks, &acl_entry)
        .await
        .expect("store ACL entry");

    let auth = AuthClaims {
        did: tenant_did.clone(),
        role: Role::Owner,
        session_pubkey_b58btc: None,
    };

    // 5. Phase 1 — tenant requests a DID slot (analog to MSG_DID_REQUEST).
    let request = create_did(&auth, &state, Some("tenant/alice"), false)
        .await
        .expect("create_did");
    assert_eq!(request.mnemonic, "tenant/alice");
    assert!(
        request.did_url.contains("tenant/alice/did.jsonl"),
        "did_url should reference the mnemonic, got {}",
        request.did_url
    );

    // 6. Phase 2 — tenant builds a real signed did:webvh log entry locally
    //    and publishes it (analog to MSG_DID_PUBLISH). Using a real entry
    //    so `validate_did_jsonl` accepts it.
    let signing = Secret::generate_ed25519(None, None);
    let signing_pub_mb = signing.get_public_keymultibase().expect("signing pub mb");
    let host = encode_host(state.config.public_url.as_deref().unwrap()).expect("encode host");
    let doc = build_did_document(
        &host,
        &request.mnemonic,
        &signing_pub_mb,
        &DidDocumentOptions::default(),
    );
    let (_scid, jsonl) = create_log_entry(&doc, &signing)
        .await
        .expect("create log entry");

    publish_did(&auth, &state, &request.mnemonic, &jsonl)
        .await
        .expect("publish_did");

    // 7. The tenant's DID record is in the daemon's local store with
    //    a populated did_id and version_count = 1.
    let record: DidRecord = state
        .dids_ks
        .get(did_key(&request.mnemonic))
        .await
        .expect("get record")
        .expect("record exists after publish");
    assert!(
        record.did_id.is_some(),
        "did_id should be populated after publish"
    );
    assert_eq!(record.version_count, 1, "version_count after first publish");
    assert_eq!(record.owner, tenant_did);
    assert!(record.content_size > 0, "content_size should reflect jsonl");

    // 8. Confirm self-managed-shape persisted on the config — no VTA
    //    fields touched along the way.
    assert!(state.config.vta.url.is_none());
    assert!(state.config.vta.did.is_none());
    assert!(state.config.vta.context_id.is_none());
}

//! An in-process control plane that answers signed Trust Task documents on
//! each of its three transports, for the table's tests.
//!
//! Every document goes in through the transport's own entry point — the TSP
//! frame handler, the DIDComm envelope handler, the HTTPS route — and so
//! through the one gate and router they share. Signers are `did:key`s, which
//! the verifier resolves without I/O.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use affinidi_data_integrity::DidKeyResolver;
use affinidi_messaging_didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::{Value, json};

use did_hosting_common::did_ops::{DidRecord, did_key, owner_key};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::{
    KS_ACL, KS_DIDS, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES, Store,
};
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;

use crate::auth::AuthClaims;
use crate::config::{AppConfig, RegistryConfig};
use crate::server::AppState;

/// The control plane's DID in every harness.
pub(crate) const CONTROL: &str = "did:webvh:test:control.example.com";

/// A transport a document can arrive on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    Tsp,
    Didcomm,
    Https,
}

/// Every transport, for tests that must hold on each.
pub(crate) const VIAS: [Via; 3] = [Via::Tsp, Via::Didcomm, Via::Https];

/// A control plane with a signing identity and a verifier over `did:key`.
pub(crate) async fn state() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some(CONTROL.into()),
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
    let state = AppState {
        store: store.clone(),
        sessions_ks: store.keyspace(KS_SESSIONS).unwrap(),
        acl_ks: store.keyspace(KS_ACL).unwrap(),
        registry_ks: store.keyspace(KS_REGISTRY).unwrap(),
        dids_ks: store.keyspace(KS_DIDS).unwrap(),
        config: Arc::new(config),
        did_resolver: None,
        secrets_resolver: None,
        identity: Some(
            did_hosting_common::server::identity::ServiceIdentity::generated_for(CONTROL)
                .await
                .unwrap(),
        ),
        trust_tasks_verifier: Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
            DidKeyResolver,
        )))),
        jwt_keys: Some(Arc::new(
            crate::auth::jwt::JwtKeys::from_ed25519_bytes(&[7u8; 32]).unwrap(),
        )),
        webauthn: Some(Arc::new(
            did_hosting_common::server::passkey::build_webauthn("http://control.test").unwrap(),
        )),
        http_client: reqwest::Client::new(),
        didcomm_service: Arc::new(OnceLock::new()),
        stats_collector: Arc::new(StatsCollector::new()),
        stats_ks: store.keyspace(KS_STATS).unwrap(),
        timeseries_ks: store.keyspace(KS_TIMESERIES).unwrap(),
        signing_key_bytes: None,
        replay_cache: Arc::new(crate::replay::ReplayCache::new()),
        path_locks: crate::path_locks::PathLocks::new(),
        acl_locks: did_hosting_common::server::path_locks::PathLocks::new(),
        pending_challenges: Arc::new(crate::pending_challenges::PendingChallengeTracker::new()),
        ip_rate_limiter: Arc::new(crate::rate_limit::IpRateLimiter::new()),
        redeem_rate_limiter: Arc::new(crate::rate_limit::SourceRateLimiter::new()),
        outbox_notify: Arc::new(tokio::sync::Notify::new()),
    };
    (state, dir)
}

/// A caller: its DID and signing key.
pub(crate) struct Caller {
    pub did: String,
    pub key: Secret,
    pub role: Role,
}

/// A `did:key` caller with an ACL entry of `role`.
pub(crate) async fn member(state: &AppState, seed: u8, role: Role) -> Caller {
    let (did, key) = crate::signing::test_util::did_key_signer(&[seed; 32]);
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.clone(),
            role: role.clone(),
            label: None,
            created_at: 1_700_000_000,
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        },
    )
    .await
    .unwrap();
    Caller { did, key, role }
}

/// A `did:key` caller with no ACL entry.
pub(crate) fn stranger(seed: u8) -> Caller {
    let (did, key) = crate::signing::test_util::did_key_signer(&[seed; 32]);
    Caller {
        did,
        key,
        role: Role::Owner,
    }
}

/// An unsigned request from `issuer` to the control plane.
pub(crate) fn request(type_uri: &str, issuer: &str, payload: Value) -> Value {
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuer": issuer,
        "recipient": CONTROL,
        // Whole seconds, `Z`: the form the typed document re-serialises to, so
        // the signature over this JSON still covers it.
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    })
}

/// `doc` signed by `key` with `proofPurpose: authentication`.
pub(crate) async fn signed(doc: Value, key: &Secret) -> Value {
    crate::signing::test_util::sign_operational(doc, key).await
}

/// `doc` signed by `key` with `proofPurpose: assertionMethod` — the purpose of
/// an approver's decision, and the wrong one for an operational request.
pub(crate) async fn signed_as_assertion(doc: Value, key: &Secret) -> Value {
    use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
    sign_trust_task(
        &doc,
        key,
        SignOptions::new()
            .with_proof_purpose("assertionMethod")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .expect("sign")
}

/// Deliver `doc` from `sender` over `via` and return the reply document.
pub(crate) async fn send(state: &AppState, via: Via, sender: &Caller, doc: Value) -> Value {
    match via {
        Via::Tsp => {
            let out = crate::tsp::run_tsp_trust_task(
                state,
                &sender.did,
                &serde_json::to_vec(&doc).unwrap(),
            )
            .await
            .expect("TSP handler ok")
            .expect("TSP reply");
            // A bare request is answered bare.
            serde_json::from_slice(&out).expect("TSP reply is JSON")
        }
        Via::Didcomm => {
            let message = Message::build(
                uuid::Uuid::new_v4().to_string(),
                trust_tasks_didcomm::ENVELOPE_TYPE.to_string(),
                doc,
            )
            .finalize();
            let (typ, body) =
                crate::messaging::run_trust_tasks_envelope(state, &sender.did, &message)
                    .await
                    .expect("envelope handler ok")
                    .expect("envelope reply");
            assert_eq!(typ, trust_tasks_didcomm::ENVELOPE_TYPE);
            body
        }
        // No bearer session: the document's own proof is the authorisation,
        // as on the other two transports.
        Via::Https => https(state, None, doc).await,
    }
}

/// Deliver `doc` to `POST /api/trust-tasks`, with `bearer` as the session the
/// request presents, and return the reply document.
pub(crate) async fn https(state: &AppState, bearer: Option<AuthClaims>, doc: Value) -> Value {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;

    let response = crate::routes::trust_tasks::dispatch_trust_task(
        bearer,
        axum::extract::State(state.clone()),
        axum::body::Bytes::from(serde_json::to_vec(&doc).unwrap()),
    )
    .await
    .into_response();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("HTTPS reply is JSON")
}

/// Sign `payload` as a `type_uri` request from `caller` — with the proof
/// purpose the task's rule asks for — and deliver it.
pub(crate) async fn call(
    state: &AppState,
    via: Via,
    caller: &Caller,
    type_uri: &str,
    payload: Value,
) -> Value {
    let doc = request(type_uri, &caller.did, payload);
    let doc = if super::proof_rule(type_uri)
        == Some(did_hosting_common::server::trust_tasks::ProofRule::AssertionMethod)
    {
        signed_as_assertion(doc, &caller.key).await
    } else {
        signed(doc, &caller.key).await
    };
    // Boxed: a test chaining many calls would otherwise build one future deep
    // enough to overflow a debug-build test thread's stack.
    Box::pin(send(state, via, caller, doc)).await
}

/// The reply's payload when it is the task's `#response`, else a panic naming
/// what came back.
pub(crate) fn ok(reply: &Value, type_uri: &str) -> Value {
    assert_eq!(
        reply["type"],
        format!("{type_uri}#response"),
        "expected a response, got {reply}"
    );
    reply["payload"].clone()
}

/// The error code of a `trust-task-error` reply, else a panic.
pub(crate) fn code(reply: &Value) -> String {
    assert!(
        reply["type"]
            .as_str()
            .is_some_and(|t| t.starts_with("https://trusttasks.org/spec/trust-task-error/")),
        "expected an error, got {reply}"
    );
    reply["payload"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Assert `reply`'s payload validates against the schema its `type` names.
pub(crate) fn conforms(reply: &Value) {
    let type_uri = reply["type"].as_str().expect("reply has a type");
    let schema = trust_tasks_rs::schema_index::schema_for(type_uri)
        .unwrap_or_else(|| panic!("no schema is known for {type_uri}: {reply}"));
    if let Err(e) = trust_tasks_rs::validate::against_schema(schema, &reply["payload"]) {
        panic!("{type_uri} reply does not match its schema: {e:?}\n{reply}");
    }
}

/// A live session for `caller`, as a login would leave it.
pub(crate) async fn session_for(
    state: &AppState,
    caller: &Caller,
) -> did_hosting_common::server::auth::session::TokenResponse {
    did_hosting_common::server::auth::session::create_authenticated_session(
        &state.sessions_ks,
        state.jwt_keys.as_deref().unwrap(),
        &caller.did,
        &caller.role,
        900,
        3600,
        None,
        None,
    )
    .await
    .unwrap()
}

/// Seed a published record owned by `owner`, with its owner index.
pub(crate) async fn seed_did(state: &AppState, owner: &str, mnemonic: &str) -> DidRecord {
    let record = DidRecord {
        services: None,
        owner: owner.into(),
        mnemonic: mnemonic.into(),
        created_at: 1,
        updated_at: 1,
        version_count: 1,
        did_id: Some(format!("did:webvh:abc:control.test:{mnemonic}")),
        content_size: 42,
        disabled: false,
        deleted_at: None,
        method: "webvh".to_string(),
        domain: String::new(),
        agent_names: Vec::new(),
    };
    state
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(owner_key(owner, mnemonic), mnemonic.as_bytes().to_vec())
        .await
        .unwrap();
    record
}

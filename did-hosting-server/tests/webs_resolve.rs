//! End-to-end `did:webs` resolution through the assembled server router.
//!
//! Seeds a hosted `did:webs` slot — the record plus the published
//! `keri.cesr` — and exercises the surface a resolver actually uses:
//!
//! 1. `GET /{AID}/keri.cesr` returns the key event log verbatim.
//! 2. `GET /{AID}/did.json` returns the document **derived** from it.
//! 3. The derived document matches what an independent resolver
//!    (`affinidi-did-webs`) derives from the same bytes.
//! 4. A did:webs slot's `did.json` is not answered by the did:web
//!    bridge, which shares that suffix.
//! 5. Disabled and unknown slots 404 rather than leaking content.
//!
//! The fixture is the `hyperledger-labs/did-webs-resolver` reference
//! publication, so passing means agreeing with the ecosystem rather
//! than with ourselves. See `did-hosting-common/tests/fixtures/`.

#![cfg(feature = "method-webs")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_SESSIONS};
use did_hosting_server::cache::ContentCache;
use did_hosting_server::config::{AppConfig, LimitsConfig, StatsConfig};
use did_hosting_server::server::AppState;
use tower::ServiceExt;

const KERI: &[u8] = include_bytes!("../../did-hosting-common/tests/fixtures/ENro7uf0.keri.cesr");
const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
const DOMAIN: &str = "did-webs-service%3a7676";

fn did_id() -> String {
    format!("did:webs:{DOMAIN}:{AID}")
}

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
        didcomm_service: Arc::new(std::sync::OnceLock::new()),
        jwt_keys: None,
        signing_key_bytes: None,
        http_client: reqwest::Client::new(),
        stats_collector: None,
        did_cache: Arc::new(ContentCache::new(Duration::from_secs(60))),
        trusted_proxy_cidrs: Arc::new(Vec::new()),
    };
    (state, dir)
}

/// Seed a hosted did:webs slot: the record, and the CESR stream under
/// the same `content:{mnemonic}:log` key every method's log lives at.
async fn seed_webs_did(state: &AppState, disabled: bool) {
    state
        .dids_ks
        .insert_raw(content_log_key(AID), KERI.to_vec())
        .await
        .expect("seed keri.cesr");
    let record = DidRecord {
        owner: "did:example:owner".into(),
        mnemonic: AID.into(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: Some(did_id()),
        content_size: KERI.len() as u64,
        disabled,
        deleted_at: None,
        method: "webs".into(),
        domain: DOMAIN.into(),
        services: Some(Vec::new()),
        agent_names: Vec::new(),
    };
    state
        .dids_ks
        .insert(did_key(AID), &record)
        .await
        .expect("seed record");
}

fn app(state: AppState) -> axum::Router {
    did_hosting_server::routes::router(1024 * 1024)
        .with_state(state)
        .layer(axum::middleware::from_fn(
            did_hosting_common::server::security_headers,
        ))
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Vec<String>, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = ["content-type", "cache-control"]
        .iter()
        .map(|h| {
            response
                .headers()
                .get(*h)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn serves_the_key_event_log_verbatim() {
    let (state, _dir) = make_state().await;
    seed_webs_did(&state, false).await;
    let app = app(state);

    let (status, headers, body) = get(&app, &format!("/{AID}/keri.cesr")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body, KERI,
        "the stream's signatures cover exact bytes; it must not be re-encoded",
    );
    assert_eq!(headers[0], "application/cesr");
    assert!(
        headers[1].contains("public"),
        "a self-verifying log is cacheable; got {}",
        headers[1],
    );
}

#[tokio::test]
async fn serves_a_document_derived_from_the_log() {
    let (state, _dir) = make_state().await;
    seed_webs_did(&state, false).await;
    let app = app(state);

    let (status, headers, body) = get(&app, &format!("/{AID}/did.json")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[0], "application/did+json");

    let doc: serde_json::Value = serde_json::from_slice(&body).expect("did.json is JSON");
    assert_eq!(doc["id"].as_str(), Some(did_id().as_str()));
    assert_eq!(
        doc["verificationMethod"][0]["publicKeyJwk"]["kid"].as_str(),
        Some("DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr"),
        "the published key must be the one the key event log authorised",
    );
}

/// The served document must be what an independent resolver derives
/// from the same artifacts — that is the whole contract of `did:webs`,
/// and a hosting service that served anything else would be publishing
/// a document no resolver would accept.
#[tokio::test]
async fn the_served_document_is_what_a_resolver_derives() {
    let (state, _dir) = make_state().await;
    seed_webs_did(&state, false).await;
    let app = app(state);

    let (_, _, served) = get(&app, &format!("/{AID}/did.json")).await;

    let parsed = affinidi_did_webs::DidWebs::parse(&did_id()).expect("parse");
    let expected = affinidi_did_webs::resolve_from_artifacts(&parsed, KERI, None).expect("resolve");

    let served: serde_json::Value = serde_json::from_slice(&served).unwrap();
    let expected: serde_json::Value = serde_json::to_value(&expected).unwrap();
    assert_eq!(served, expected);
}

/// A resolver that fetches both artifacts cross-checks one against the
/// other. Serving a pair that fails its own check would make every
/// hosted DID unresolvable, so assert the round-trip explicitly.
#[tokio::test]
async fn the_two_served_artifacts_verify_against_each_other() {
    let (state, _dir) = make_state().await;
    seed_webs_did(&state, false).await;
    let app = app(state);

    let (_, _, cesr) = get(&app, &format!("/{AID}/keri.cesr")).await;
    let (_, _, did_json) = get(&app, &format!("/{AID}/did.json")).await;

    let parsed = affinidi_did_webs::DidWebs::parse(&did_id()).expect("parse");
    affinidi_did_webs::resolve_from_artifacts(&parsed, &cesr, Some(&did_json))
        .expect("the published did.json must agree with the published keri.cesr");
}

/// `/did.json` is shared with did:web, whose handler reads a webvh
/// jsonl log. If dispatch order regressed, this slot's document would
/// be looked for in a log that is really a CESR stream — a 404 for a
/// DID that is hosted perfectly well.
#[tokio::test]
async fn the_did_web_bridge_does_not_capture_a_webs_slot() {
    let (state, _dir) = make_state().await;
    seed_webs_did(&state, false).await;
    let app = app(state);

    let (status, headers, _) = get(&app, &format!("/{AID}/did.json")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "did:webs must answer for its own slot before the did:web bridge sees it",
    );
    assert_eq!(headers[0], "application/did+json");
}

#[tokio::test]
async fn a_disabled_slot_serves_neither_artifact() {
    let (state, _dir) = make_state().await;
    seed_webs_did(&state, true).await;
    let app = app(state);

    let (status, _, _) = get(&app, &format!("/{AID}/keri.cesr")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = get(&app, &format!("/{AID}/did.json")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a disabled slot must not fall through to the did:web bridge",
    );
}

#[tokio::test]
async fn an_unknown_slot_404s() {
    let (state, _dir) = make_state().await;
    let app = app(state);

    let (status, _, _) = get(&app, &format!("/{AID}/keri.cesr")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// did:webs has no root form — the AID is always the final path
/// segment — so the well-known surface stays webvh/web only.
///
/// The answer is 400, not 404, and deliberately: `.well-known` is not a
/// slot that happens to be empty, it is a path a did:webs DID can never
/// occupy, so `validate_webs_mnemonic` rejects it outright. That
/// matches how the webvh dispatcher answers a mnemonic its own grammar
/// rejects, and it tells an operator who mis-wired a publish something
/// a 404 would not.
#[tokio::test]
async fn there_is_no_well_known_keri_cesr() {
    let (state, _dir) = make_state().await;
    seed_webs_did(&state, false).await;
    let app = app(state);

    let (status, _, body) = get(&app, "/.well-known/keri.cesr").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_ne!(body, KERI, "no path may serve another slot's log");
}

/// A mnemonic that is not a plausible AID must not reach storage
/// lookup at all.
#[tokio::test]
async fn a_non_aid_mnemonic_is_rejected_before_lookup() {
    let (state, _dir) = make_state().await;
    let app = app(state);

    let (status, _, _) = get(&app, "/not.an.aid/keri.cesr").await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a path that cannot be an AID must never serve a key event log",
    );
}

// ---------------------------------------------------------------------
// Control-plane → edge sync
// ---------------------------------------------------------------------

/// An edge must be able to receive a `did:webs` DID from the control
/// plane and then serve it, or the method only works on a daemon (where
/// both halves share one store) and silently fails in the distributed
/// deployment.
///
/// This also pins the edge's independence: the sync path re-verifies the
/// key event log itself rather than trusting the push, so a compromised
/// control plane cannot make an edge serve a stream that does not
/// verify. Same reasoning as deriving agent names from the signed
/// document instead of from the update.
#[tokio::test]
async fn a_webs_did_syncs_from_the_control_plane_and_then_serves() {
    let (state, _dir) = make_state().await;

    let update = did_hosting_common::DidSyncUpdate {
        mnemonic: AID.to_string(),
        did_id: did_id(),
        log_content: String::from_utf8(KERI.to_vec()).unwrap(),
        witness_content: None,
        version_count: 1,
    };
    did_hosting_server::control_register::apply_single_update(
        &state.dids_ks,
        &state.store,
        &update,
        &state.did_cache,
    )
    .await
    .expect("a verifying did:webs log must sync to an edge");

    // The record has to be tagged `webs`, or `resolve_webs` will not
    // answer for it and the DID is stored but unreachable.
    let record: DidRecord = state
        .dids_ks
        .get(did_key(AID))
        .await
        .unwrap()
        .expect("synced record");
    assert_eq!(record.method, "webs");
    assert_eq!(
        record.domain, "did-webs-service:7676",
        "the edge keeps the domain in its decoded form — the same form every other \
         record uses, so the control plane and its edges agree about the same DID",
    );

    // And it actually serves.
    let app = app(state);
    let (status, _, body) = get(&app, &format!("/{AID}/keri.cesr")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, KERI);

    let (status, _, body) = get(&app, &format!("/{AID}/did.json")).await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["id"].as_str(), Some(did_id().as_str()));
}

#[tokio::test]
async fn an_edge_refuses_a_tampered_webs_log_from_the_control_plane() {
    let (state, _dir) = make_state().await;

    let mut tampered = KERI.to_vec();
    let pos = tampered
        .windows(3)
        .position(|w| w == b"\"s\"")
        .expect("inception has an `s` field");
    tampered[pos + 5] = b'9';

    let update = did_hosting_common::DidSyncUpdate {
        mnemonic: AID.to_string(),
        did_id: did_id(),
        log_content: String::from_utf8(tampered).unwrap(),
        witness_content: None,
        version_count: 1,
    };
    did_hosting_server::control_register::apply_single_update(
        &state.dids_ks,
        &state.store,
        &update,
        &state.did_cache,
    )
    .await
    .expect_err("an edge verifies the key event log itself, push or no push");
}

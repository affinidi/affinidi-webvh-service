//! Boot-time backfill of the per-DID service-badge cache on a standalone
//! control plane (`server::backfill_service_badges`).
//!
//! The control plane has never invoked the migration runner. Adding badges
//! must not become a back door for running every other migration against
//! stores that have never seen them — so this pins both halves of the
//! contract:
//!
//! - `M-02` **does** run: a legacy `services: None` record gets populated;
//! - `M-01` **does not**: the same record's empty `domain` is left alone.
//!
//! Without the second assertion, someone "simplifying" the runner to
//! `migrations::registry()` would silently start rewriting `domain` on every
//! control-plane store, and nothing would fail.

use std::path::PathBuf;

use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::store::{KS_DIDS, Store};
use did_hosting_control::server::backfill_service_badges;

async fn temp_store() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&cfg).await.expect("open store");
    (store, dir)
}

/// A pre-`services` record: `services: None` *and* an empty `domain`, which is
/// exactly the shape `M-01` would want to rewrite.
fn legacy_record(mnemonic: &str) -> DidRecord {
    DidRecord {
        owner: "did:example:owner".into(),
        mnemonic: mnemonic.into(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: Some(format!("did:webvh:Q1:host.example:{mnemonic}")),
        content_size: 0,
        disabled: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: String::new(),
        services: None,
        agent_names: Vec::new(),
    }
}

/// A one-entry log whose document advertises hosting + both transports.
fn log_for(mnemonic: &str) -> String {
    let did = format!("did:webvh:Q1:host.example:{mnemonic}");
    format!(
        r##"{{"versionId":"1-a","state":{{"id":"{did}","service":[{{"id":"{did}#webvh-hosting","type":"WebVHHosting","serviceEndpoint":{{"uri":"https://host.example"}}}},{{"id":"{did}#tsp","type":"TSPTransport","serviceEndpoint":"did:webvh:QmMED:med.example"}},{{"id":"{did}#vta-didcomm","type":"DIDCommMessaging","serviceEndpoint":[{{"accept":["didcomm/v2"],"uri":"did:webvh:QmMED:med.example"}}]}}]}}}}"##
    )
}

async fn seed(store: &Store, mnemonic: &str) {
    let ks = store.keyspace(KS_DIDS).expect("dids ks");
    ks.insert(did_key(mnemonic), &legacy_record(mnemonic))
        .await
        .expect("seed record");
    ks.insert_raw(content_log_key(mnemonic), log_for(mnemonic).into_bytes())
        .await
        .expect("seed log");
}

async fn load(store: &Store, mnemonic: &str) -> DidRecord {
    store
        .keyspace(KS_DIDS)
        .expect("dids ks")
        .get::<DidRecord>(did_key(mnemonic))
        .await
        .expect("read record")
        .expect("record exists")
}

#[tokio::test]
async fn backfill_populates_services_and_leaves_domain_untouched() {
    let (store, _dir) = temp_store().await;
    seed(&store, "legacy").await;

    backfill_service_badges(&store).await;

    let rec = load(&store, "legacy").await;
    assert_eq!(
        rec.services,
        Some(vec![
            "WebVHHosting".to_string(),
            "TSPTransport".to_string(),
            "DIDCommMessaging".to_string(),
        ]),
        "M-02 must populate the badge cache"
    );
    assert_eq!(
        rec.domain, "",
        "M-01 must NOT run here — the control plane's `domain` backfill is a \
         separate decision; swapping this runner for migrations::registry() \
         would silently rewrite every record's domain"
    );
}

/// Marker-gated: a second boot is a no-op, and must not disturb a record whose
/// services changed in between (e.g. via a publish).
#[tokio::test]
async fn backfill_is_idempotent_across_boots() {
    let (store, _dir) = temp_store().await;
    seed(&store, "legacy").await;

    backfill_service_badges(&store).await;
    let after_first = load(&store, "legacy").await.services;

    backfill_service_badges(&store).await;
    let after_second = load(&store, "legacy").await.services;

    assert_eq!(after_first, after_second);
    assert!(after_second.is_some());
}

/// A backfill over an empty store must not fail or panic — the common case for
/// a fresh control plane.
#[tokio::test]
async fn backfill_on_empty_store_is_a_noop() {
    let (store, _dir) = temp_store().await;
    backfill_service_badges(&store).await;
}

//! T53: Migration replay against v0.6.0-shape fixtures.
//!
//! Three fixtures, each rebuilt from scratch per test:
//!
//! 1. **Empty store** — no DIDs, no ACL entries. Migration runs
//!    cleanly (no rows touched) and leaves an applied-marker so
//!    the second run skips.
//! 2. **~10 webvh DIDs** — pre-T12 DidRecord shape (no `domain`
//!    field on the wire). Domain seed populates a system default;
//!    M-01 walks every record and either pulls the host from
//!    `did_id` (tier 1) or falls back to the system default
//!    (tier 2). Post-state: every record has a non-empty domain.
//! 3. **Mixed ACL roles** — Admin + Owner + Service entries.
//!    M-01 doesn't touch the ACL keyspace; the ACL entries
//!    survive unchanged through any number of replays.
//!
//! Each fixture is also replayed a **second** time to confirm
//! idempotency: the runner sees the applied-marker and skips,
//! and a `cargo run migrations` against an already-migrated
//! store is a no-op.

use std::path::PathBuf;
use std::sync::Arc;

use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::domain::{
    DomainEntry, DomainScope, DomainStatus, DomainUrlScheme, create_domain, set_default_domain,
};
use did_hosting_common::server::migrations::m01_tag_did_records_with_domain::M01TagDidRecordsWithDomain;
use did_hosting_common::server::migrations::{Migration, MigrationRunner};
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS};

async fn fresh_store() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&cfg).await.expect("open store");
    (store, dir)
}

fn migrations() -> Vec<Arc<dyn Migration>> {
    vec![Arc::new(M01TagDidRecordsWithDomain)]
}

async fn seed_domain(store: &Store, name: &str, default: bool) {
    create_domain(
        store,
        &DomainEntry {
            name: name.into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Active,
            created_at: 1,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
        },
    )
    .await
    .unwrap();
    if default {
        set_default_domain(store, name).await.unwrap();
    }
}

/// Build a pre-T12 DidRecord — `method` defaults to "webvh" via
/// the `#[serde(default)]` annotation, but `domain` is empty.
fn pre_t12_record(mnemonic: &str, did_id: Option<&str>) -> DidRecord {
    DidRecord {
        owner: format!("did:example:owner-{mnemonic}"),
        mnemonic: mnemonic.into(),
        created_at: 1,
        updated_at: 1,
        version_count: 1,
        did_id: did_id.map(|s| s.into()),
        content_size: 0,
        disabled: false,
        deleted_at: None,
        method: "webvh".into(),
        // Empty domain — what M-01 fills in.
        domain: String::new(),
    }
}

async fn seed_did(store: &Store, rec: &DidRecord) {
    let ks = store.keyspace(KS_DIDS).unwrap();
    ks.insert(did_key(&rec.mnemonic), rec).await.unwrap();
}

/// Fixture 1: completely empty store. Migration runs cleanly,
/// the second run skips via the applied-marker.
#[tokio::test]
async fn fixture_empty_store_runs_cleanly_and_is_idempotent() {
    let (store, _dir) = fresh_store().await;
    let runner = MigrationRunner::new(migrations());

    let summary = runner.run_pending(&store).await.expect("first run");
    assert_eq!(summary.applied.len(), 1, "M-01 applied once");
    assert!(summary.skipped.is_empty());

    let summary2 = runner.run_pending(&store).await.expect("second run");
    assert!(summary2.applied.is_empty(), "second run must not re-apply");
    assert_eq!(summary2.skipped.len(), 1, "applied marker honoured");
}

/// Fixture 2: 10 webvh DIDs with varying `did_id` presence.
/// Tier-1 (host from did_id) and tier-2 (system default) both
/// exercised. Post-migration every record has a non-empty domain.
#[tokio::test]
async fn fixture_ten_webvh_dids_post_migration_state() {
    let (store, _dir) = fresh_store().await;
    seed_domain(&store, "system.example", true).await;

    // 7 records with did_id naming various hosts — tier 1.
    for i in 0..7 {
        let did_id = format!("did:webvh:Q1:tenant-{i}.example:user{i}");
        let rec = pre_t12_record(&format!("user{i}"), Some(&did_id));
        seed_did(&store, &rec).await;
    }
    // 3 records with no did_id — tier 2 (system default).
    for i in 0..3 {
        let rec = pre_t12_record(&format!("legacy{i}"), None);
        seed_did(&store, &rec).await;
    }

    let runner = MigrationRunner::new(migrations());
    let summary = runner.run_pending(&store).await.expect("first run");
    assert_eq!(summary.applied, vec!["m01_tag_did_records_with_domain"]);

    // Inspect every record and confirm domain is set.
    let ks = store.keyspace(KS_DIDS).unwrap();
    let raw = ks.prefix_iter_raw(b"did:".to_vec()).await.unwrap();
    assert_eq!(raw.len(), 10, "all 10 records present");

    for (key, value) in raw {
        let mnemonic = String::from_utf8(key).unwrap();
        let rec: DidRecord = serde_json::from_slice(&value).unwrap();
        assert!(
            !rec.domain.is_empty(),
            "record {mnemonic} should have a domain after M-01"
        );
        if mnemonic.starts_with("did:legacy") {
            // Tier 2 path — system default.
            assert_eq!(rec.domain, "system.example");
        } else {
            // Tier 1 path — derived from did_id.
            let user_n = mnemonic.strip_prefix("did:user").unwrap();
            assert_eq!(rec.domain, format!("tenant-{user_n}.example"));
        }
    }

    // Replay must short-circuit on the marker.
    let summary2 = runner.run_pending(&store).await.expect("second run");
    assert!(summary2.applied.is_empty());
    assert_eq!(summary2.skipped.len(), 1);
}

/// Fixture 3: mixed ACL roles (Admin + Owner + Service). The
/// M-01 migration touches only `KS_DIDS`; the ACL keyspace must
/// survive replays without alteration. Pins that future
/// migrations won't be allowed to silently broaden their scope.
#[tokio::test]
async fn fixture_mixed_acl_survives_migration_unchanged() {
    let (store, _dir) = fresh_store().await;

    let acl_ks = store.keyspace(KS_ACL).unwrap();
    let entries = [
        AclEntry {
            did: "did:example:admin".into(),
            role: Role::Admin,
            label: Some("Operator".into()),
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        },
        AclEntry {
            did: "did:example:owner1".into(),
            role: Role::Owner,
            label: None,
            created_at: now_epoch(),
            max_total_size: Some(1_000_000),
            max_did_count: Some(100),
            domains: DomainScope::AllowedWithDefault {
                domains: vec!["a.example".into(), "b.example".into()],
                default: "a.example".into(),
            },
        },
        AclEntry {
            did: "did:example:service".into(),
            role: Role::Service,
            label: Some("Watcher".into()),
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        },
    ];
    for e in &entries {
        store_acl_entry(&acl_ks, e).await.unwrap();
    }

    // Snapshot ACL byte-for-byte.
    let before = acl_ks
        .prefix_iter_raw(b"".to_vec())
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(before.len(), 3, "all 3 ACL entries seeded");

    // Run migration twice — neither pass should touch ACL.
    let runner = MigrationRunner::new(migrations());
    runner.run_pending(&store).await.expect("first run");
    runner.run_pending(&store).await.expect("second run");

    let after = acl_ks
        .prefix_iter_raw(b"".to_vec())
        .await
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(after.len(), 3, "ACL count unchanged");

    // Compare byte-for-byte. Sort both sides on key so the order
    // mismatch from prefix_iter_raw doesn't false-positive.
    let mut before_sorted = before;
    before_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut after_sorted = after;
    after_sorted.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(
        before_sorted, after_sorted,
        "ACL keyspace must be byte-identical pre/post migration"
    );
}

//! `m01_tag_did_records_with_domain` — fill `DidRecord.domain` for
//! every legacy record that's still carrying the empty-string default
//! from before multi-domain hosting.
//!
//! Per `docs/archive/multi-domain-spec.md` §6.5.
//!
//! ## What gets touched
//!
//! Every entry under the `did:{mnemonic}` prefix in `KS_DIDS` whose
//! `DidRecord.domain` is the empty string. Records with a non-empty
//! `domain` (seeded, or written by a domain-aware write path) are skipped — the
//! migration is idempotent and a partial / interrupted run can be
//! resumed by re-running.
//!
//! ## Where the new `domain` comes from
//!
//! Two-tier rule:
//!
//! 1. If `did_id` is set on the record, parse it via the webvh
//!    `DidMethod` (the canonical method for records that predate multi-method hosting)
//!    and use the extracted host. This is the case for every record
//!    created with the current dispatcher — the host the DID was
//!    issued under is what we want to retain.
//! 2. Fall back to the **system default domain** (the
//!    `meta:default_domain` pointer set by the first-boot domain seed).
//!    Catches edge cases — e.g. a `recreate_did` that hasn't fully
//!    populated `did_id` yet — and lets the daemon serve them
//!    rather than reject every subsequent operation.
//! 3. If no system default is set either, the record is left with
//!    `domain == ""` and an error counter is incremented. The
//!    migration succeeds overall; the affected records show up in
//!    the audit-log count for follow-up by ops. The migration then
//!    reports [`MigrationOutcome::Deferred`], so the runner writes no
//!    applied marker and the next runner invocation retries these
//!    (once a default exists they are tagged and the migration completes).
//!
//! ## Concurrent writers
//!
//! The walk is paged and only selects candidates. Each record is re-read
//! through a consistent handle just before it is written, only `domain` is
//! changed, and the write is a compare-and-swap against the bytes read
//! (`super::patch_did_record_field`) — so a publish committed by another
//! replica during a rolling upgrade is never overwritten with a stale
//! record.
//!
//! Records whose `did_id` parses to a method **other than** `webvh`
//! are caught by the same path — the dispatcher routes by method
//! name, so an older store that happens to contain a `did:web`
//! record still gets the right host.

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::super::domain::{extract_did_host, get_default_domain};
use super::super::store::{KS_DIDS, Store};
use super::{
    DidRecordPages, Migration, MigrationFuture, MigrationOutcome, Patched, patch_did_record_field,
};
use crate::did_ops::DidRecord;

/// Public migration ID. Stable wire identifier — never rename.
pub const ID: &str = "m01_tag_did_records_with_domain";

/// Per-run counters surfaced in the audit log line. Internal — kept
/// distinct from `RunSummary` so this migration's own bookkeeping
/// doesn't leak into the runner's framework-level types.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct M01Counters {
    /// Records whose `domain` field was empty and got filled from
    /// `did_id`'s parsed host.
    pub tagged_from_did_id: u64,
    /// Records whose `did_id` was absent or unparseable; filled from
    /// the system default-domain pointer instead.
    pub tagged_from_default: u64,
    /// Records that already had a non-empty `domain`. Skipped.
    pub already_tagged: u64,
    /// Records where neither `did_id` parsing nor a system default
    /// was available. **Left with `domain == ""`** and counted here
    /// for follow-up. The next runner invocation (after operators
    /// add a default domain) retries these.
    pub deferred_no_default: u64,
    /// Records concurrent writers kept changing while the migration tried
    /// to tag them. Retried by the next runner invocation.
    pub deferred_contended: u64,
}

pub struct M01TagDidRecordsWithDomain;

impl Migration for M01TagDidRecordsWithDomain {
    fn id(&self) -> &'static str {
        ID
    }

    fn description(&self) -> &'static str {
        "fill DidRecord.domain for legacy records (method=webvh era)"
    }

    fn run<'a>(&'a self, store: &'a Store) -> MigrationFuture<'a> {
        Box::pin(async move {
            let mut counters = M01Counters::default();
            let dids = store.keyspace(KS_DIDS)?;
            let consistent = store.keyspace_consistent(KS_DIDS)?;

            // Cache the system default once — it's the same across the
            // whole walk. A `None` here doesn't fail the migration;
            // we just defer the affected records.
            let system_default = get_default_domain(store).await?;

            // The new domain for a record, and which tier supplied it.
            let tag = |record: &DidRecord| -> Option<(String, bool)> {
                if let Some(host) = record
                    .did_id
                    .as_deref()
                    .and_then(|d| extract_did_host(d).ok())
                {
                    return Some((host, true));
                }
                system_default.clone().map(|d| (d, false))
            };

            // Walk every `did:{mnemonic}` key, a page at a time. The scan
            // only selects candidates: each one is re-read just before it is
            // written (see `patch_did_record_field`).
            let mut pages = DidRecordPages::new(&dids);
            while let Some(page) = pages.next_page(ID).await? {
                for (mnemonic, value) in page {
                    let record: DidRecord = match serde_json::from_slice(&value) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(
                                migration_id = ID,
                                mnemonic = %mnemonic,
                                error = %e,
                                "skipping unparseable DidRecord"
                            );
                            continue;
                        }
                    };
                    if !record.domain.is_empty() {
                        counters.already_tagged += 1;
                        continue;
                    }
                    if tag(&record).is_none() {
                        counters.deferred_no_default += 1;
                        debug!(
                            migration_id = ID,
                            mnemonic = %mnemonic,
                            "deferred: no did_id host and no system default"
                        );
                        continue;
                    }
                    let patched =
                        patch_did_record_field(&consistent, &mnemonic, "domain", |fresh| {
                            if !fresh.domain.is_empty() {
                                return None;
                            }
                            tag(fresh).map(|(domain, from_did_id)| {
                                (serde_json::Value::String(domain), from_did_id)
                            })
                        })
                        .await?;
                    if matches!(patched, Patched::Written(_))
                        && let Some((domain, _)) = tag(&record)
                    {
                        // The record now has a domain: index it (M-03 indexes the
                        // rest, but this migration may complete after it).
                        dids.insert_raw(
                            crate::server::did_index::domain_index_key(&domain, &mnemonic),
                            mnemonic.as_bytes().to_vec(),
                        )
                        .await?;
                    }
                    match patched {
                        Patched::Written(true) => counters.tagged_from_did_id += 1,
                        Patched::Written(false) => counters.tagged_from_default += 1,
                        // Tagged (or removed) by a concurrent writer since the
                        // scan.
                        Patched::Unneeded => counters.already_tagged += 1,
                        Patched::Contended => counters.deferred_contended += 1,
                    }
                }
            }

            info!(
                migration_id = ID,
                tagged_from_did_id = counters.tagged_from_did_id,
                tagged_from_default = counters.tagged_from_default,
                already_tagged = counters.already_tagged,
                deferred_no_default = counters.deferred_no_default,
                deferred_contended = counters.deferred_contended,
                "M-01 walk complete"
            );

            // Deferred records keep the migration pending: the runner writes
            // no marker, so the next invocation (after operators add a
            // default domain) retries them.
            Ok(MigrationOutcome::from_deferred(
                counters.deferred_no_default + counters.deferred_contended,
            ))
        })
    }
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::super::MigrationRunner;
    use super::*;
    use crate::did_ops::did_key;
    use crate::server::config::StoreConfig;
    use crate::server::domain::{
        create_domain, set_default_domain,
        types::{DomainEntry, DomainStatus, DomainUrlScheme},
    };
    use crate::server::error::AppError;
    use std::sync::Arc;

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }

    fn legacy_record(mnemonic: &str, did_id: Option<&str>) -> DidRecord {
        DidRecord {
            owner: "did:example:owner".into(),
            mnemonic: mnemonic.into(),
            created_at: 0,
            updated_at: 0,
            version_count: 1,
            did_id: did_id.map(|s| s.to_string()),
            content_size: 0,
            disabled: false,
            disabled_by_admin: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: String::new(), // legacy state
            services: None,
            agent_names: Vec::new(),
        }
    }

    fn already_tagged_record(mnemonic: &str, domain: &str) -> DidRecord {
        DidRecord {
            owner: "did:example:owner".into(),
            mnemonic: mnemonic.into(),
            created_at: 0,
            updated_at: 0,
            version_count: 1,
            did_id: None,
            content_size: 0,
            disabled: false,
            disabled_by_admin: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: domain.into(),
            services: None,
            agent_names: Vec::new(),
        }
    }

    fn entry(name: &str) -> DomainEntry {
        DomainEntry {
            name: name.into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Active,
            created_at: 0,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        }
    }

    async fn run_migration(store: &Store) -> Result<(), AppError> {
        let migrations: Vec<Arc<dyn Migration>> = vec![Arc::new(M01TagDidRecordsWithDomain)];
        MigrationRunner::new(migrations).run_pending(store).await?;
        Ok(())
    }

    async fn get_rec(store: &Store, mnemonic: &str) -> DidRecord {
        let dids = store.keyspace(KS_DIDS).unwrap();
        dids.get::<DidRecord>(did_key(mnemonic))
            .await
            .unwrap()
            .expect("record must exist")
    }

    // ---- tier 1: did_id-derived host ----

    #[tokio::test]
    async fn tags_from_did_id_when_present() {
        let store = fjall_store().await;
        let dids = store.keyspace(KS_DIDS).unwrap();
        let rec = legacy_record("user1", Some("did:webvh:Q1:example.com:user1"));
        dids.insert(did_key("user1"), &rec).await.unwrap();

        run_migration(&store).await.unwrap();

        let after = get_rec(&store, "user1").await;
        assert_eq!(after.domain, "example.com");
    }

    #[tokio::test]
    async fn tags_from_did_id_with_encoded_port() {
        let store = fjall_store().await;
        let dids = store.keyspace(KS_DIDS).unwrap();
        let rec = legacy_record("user1", Some("did:webvh:Q1:example.com%3A8085:user1"));
        dids.insert(did_key("user1"), &rec).await.unwrap();
        run_migration(&store).await.unwrap();
        // `extract_did_host` decodes the `%3A` port separator, so the
        // backfilled `record.domain` is the literal `host:port` form —
        // matching the configured-domain entries the timeseries / filter
        // paths compare against.
        assert_eq!(get_rec(&store, "user1").await.domain, "example.com:8085");
    }

    // ---- tier 2: fall back to system default ----

    #[tokio::test]
    async fn falls_back_to_system_default_when_did_id_absent() {
        let store = fjall_store().await;
        create_domain(&store, &entry("fallback.example"))
            .await
            .unwrap();
        set_default_domain(&store, "fallback.example")
            .await
            .unwrap();

        let dids = store.keyspace(KS_DIDS).unwrap();
        let rec = legacy_record("user1", None);
        dids.insert(did_key("user1"), &rec).await.unwrap();

        run_migration(&store).await.unwrap();

        assert_eq!(get_rec(&store, "user1").await.domain, "fallback.example");
    }

    #[tokio::test]
    async fn falls_back_to_system_default_when_did_id_unparseable() {
        let store = fjall_store().await;
        create_domain(&store, &entry("fallback.example"))
            .await
            .unwrap();
        set_default_domain(&store, "fallback.example")
            .await
            .unwrap();

        let dids = store.keyspace(KS_DIDS).unwrap();
        let rec = legacy_record("user1", Some("garbage-not-a-did"));
        dids.insert(did_key("user1"), &rec).await.unwrap();

        run_migration(&store).await.unwrap();

        assert_eq!(get_rec(&store, "user1").await.domain, "fallback.example");
    }

    // ---- tier 3: deferred ----

    #[tokio::test]
    async fn deferred_when_no_did_id_and_no_default() {
        let store = fjall_store().await;
        let dids = store.keyspace(KS_DIDS).unwrap();
        let rec = legacy_record("user1", None);
        dids.insert(did_key("user1"), &rec).await.unwrap();

        // The run succeeds but defers the record, so it stays pending.
        let summary = MigrationRunner::new(vec![Arc::new(M01TagDidRecordsWithDomain)])
            .run_pending(&store)
            .await
            .unwrap();
        assert_eq!(summary.deferred, vec![ID]);
        assert_eq!(get_rec(&store, "user1").await.domain, "");

        // The next runner invocation, after a default is seeded, catches up
        // and completes.
        create_domain(&store, &entry("late.example")).await.unwrap();
        set_default_domain(&store, "late.example").await.unwrap();
        let summary = MigrationRunner::new(vec![Arc::new(M01TagDidRecordsWithDomain)])
            .run_pending(&store)
            .await
            .unwrap();
        assert_eq!(summary.applied, vec![ID]);
        assert_eq!(get_rec(&store, "user1").await.domain, "late.example");
    }

    // ---- idempotency ----

    #[tokio::test]
    async fn skips_already_tagged_records() {
        let store = fjall_store().await;
        let dids = store.keyspace(KS_DIDS).unwrap();
        dids.insert(
            did_key("already"),
            &already_tagged_record("already", "preset.example"),
        )
        .await
        .unwrap();

        run_migration(&store).await.unwrap();

        assert_eq!(get_rec(&store, "already").await.domain, "preset.example");
    }

    #[tokio::test]
    async fn full_run_is_idempotent() {
        // Mixed bag: tagged-from-did_id, tagged-from-default,
        // already-tagged, deferred (then resolved).
        let store = fjall_store().await;
        create_domain(&store, &entry("sys.example")).await.unwrap();
        set_default_domain(&store, "sys.example").await.unwrap();
        let dids = store.keyspace(KS_DIDS).unwrap();
        dids.insert(
            did_key("a"),
            &legacy_record("a", Some("did:webvh:Q:from-did.example:a")),
        )
        .await
        .unwrap();
        dids.insert(did_key("b"), &legacy_record("b", None))
            .await
            .unwrap();
        dids.insert(did_key("c"), &already_tagged_record("c", "preset.example"))
            .await
            .unwrap();

        run_migration(&store).await.unwrap();
        assert_eq!(get_rec(&store, "a").await.domain, "from-did.example");
        assert_eq!(get_rec(&store, "b").await.domain, "sys.example");
        assert_eq!(get_rec(&store, "c").await.domain, "preset.example");

        // Re-running the migration directly via `Migration::run` (the
        // runner would skip it via the applied-marker) is a no-op.
        M01TagDidRecordsWithDomain.run(&store).await.unwrap();
        assert_eq!(get_rec(&store, "a").await.domain, "from-did.example");
        assert_eq!(get_rec(&store, "b").await.domain, "sys.example");
        assert_eq!(get_rec(&store, "c").await.domain, "preset.example");
    }

    // ---- concurrent writers ----

    /// Only `domain` is written, onto the record as it stands at write time:
    /// a field this binary does not model, and every other field, survive.
    #[tokio::test]
    async fn only_the_domain_field_is_written() {
        let store = fjall_store().await;
        let dids = store.keyspace(KS_DIDS).unwrap();
        let mut value = serde_json::to_value(legacy_record(
            "user1",
            Some("did:webvh:Q1:example.com:user1"),
        ))
        .unwrap();
        value["version_count"] = serde_json::json!(7);
        value["from_a_newer_release"] = serde_json::json!("kept");
        dids.insert_raw(did_key("user1"), serde_json::to_vec(&value).unwrap())
            .await
            .unwrap();

        run_migration(&store).await.unwrap();

        let raw: serde_json::Value =
            serde_json::from_slice(&dids.get_raw(did_key("user1")).await.unwrap().unwrap())
                .unwrap();
        assert_eq!(raw["domain"], "example.com");
        assert_eq!(raw["version_count"], 7);
        assert_eq!(raw["from_a_newer_release"], "kept");
    }

    /// A record changed between the scan and the write is decided on its
    /// fresh state: here a concurrent writer tagged it, so it is left alone.
    #[tokio::test]
    async fn a_record_tagged_since_the_scan_is_not_overwritten() {
        let store = fjall_store().await;
        let consistent = store.keyspace_consistent(KS_DIDS).unwrap();
        let dids = store.keyspace(KS_DIDS).unwrap();
        dids.insert(
            did_key("user1"),
            &legacy_record("user1", Some("did:webvh:Q1:example.com:user1")),
        )
        .await
        .unwrap();
        // The concurrent write lands after the scan.
        dids.insert(
            did_key("user1"),
            &already_tagged_record("user1", "preset.example"),
        )
        .await
        .unwrap();
        let patched =
            super::super::patch_did_record_field(&consistent, "user1", "domain", |fresh| {
                fresh
                    .domain
                    .is_empty()
                    .then(|| (serde_json::json!("example.com"), ()))
            })
            .await
            .unwrap();
        assert_eq!(patched, Patched::Unneeded);
        assert_eq!(get_rec(&store, "user1").await.domain, "preset.example");
    }

    // ---- corrupt-data tolerance ----

    #[tokio::test]
    async fn skips_unparseable_records_without_failing_migration() {
        let store = fjall_store().await;
        create_domain(&store, &entry("sys.example")).await.unwrap();
        set_default_domain(&store, "sys.example").await.unwrap();

        let dids = store.keyspace(KS_DIDS).unwrap();
        // Bad value at a `did:` key — corrupted store. Migration logs
        // and continues; doesn't crash the whole run.
        dids.insert_raw(did_key("bad"), b"not json".to_vec())
            .await
            .unwrap();
        dids.insert(did_key("good"), &legacy_record("good", None))
            .await
            .unwrap();

        run_migration(&store).await.unwrap();
        // The good record was tagged; the bad one was skipped.
        assert_eq!(get_rec(&store, "good").await.domain, "sys.example");
    }
}

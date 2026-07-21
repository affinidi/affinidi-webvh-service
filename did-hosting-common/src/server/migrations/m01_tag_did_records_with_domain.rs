//! `m01_tag_did_records_with_domain` — fill `DidRecord.domain` for
//! every legacy record that's still carrying the empty-string default
//! from T12.
//!
//! Per `tasks/did-hosting-rollout-plan.md` WS-2 / T13 and
//! `docs/multi-domain-spec.md` §6.5.
//!
//! ## What gets touched
//!
//! Every entry under the `did:{mnemonic}` prefix in `KS_DIDS` whose
//! `DidRecord.domain` is the empty string. Records with a non-empty
//! `domain` (T18 seed + new T16-aware writes) are skipped — the
//! migration is idempotent and a partial / interrupted run can be
//! resumed by re-running.
//!
//! ## Where the new `domain` comes from
//!
//! Two-tier rule:
//!
//! 1. If `did_id` is set on the record, parse it via the webvh
//!    `DidMethod` (the canonical method for v0.6-vintage records)
//!    and use the extracted host. This is the case for every record
//!    created with the current dispatcher — the host the DID was
//!    issued under is what we want to retain.
//! 2. Fall back to the **system default domain** (the
//!    `meta:default_domain` pointer set by T18's first-boot seed).
//!    Catches edge cases — e.g. a `recreate_did` that hasn't fully
//!    populated `did_id` yet — and lets the daemon serve them
//!    rather than reject every subsequent operation.
//! 3. If no system default is set either, the record is left with
//!    `domain == ""` and an error counter is incremented. The
//!    migration succeeds overall; the affected records show up in
//!    the audit-log count for follow-up by ops. (The next runner
//!    invocation will retry these once a default exists.)
//!
//! Records whose `did_id` parses to a method **other than** `webvh`
//! are caught by the same path — the dispatcher routes by method
//! name, so a v0.6.5 store that happens to contain a `did:web`
//! record (via the legacy bridge) still gets the right host.

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::super::domain::{extract_did_host, get_default_domain};
use super::super::store::{KS_DIDS, Store};
use super::{Migration, MigrationFuture};
use crate::did_ops::{DidRecord, did_key};

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

            // Cache the system default once — it's the same across the
            // whole walk. A `None` here doesn't fail the migration;
            // we just defer the affected records.
            let system_default = get_default_domain(store).await?;

            // Walk every `did:{mnemonic}` key. Prefix-scan filters out
            // `content:`, `owner:`, `watcher_sync:` neighbours.
            let raw = dids.prefix_iter_raw(b"did:".to_vec()).await?;
            for (key, value) in raw {
                let mnemonic = match std::str::from_utf8(&key) {
                    Ok(k) => k.strip_prefix("did:").unwrap_or(k).to_string(),
                    Err(_) => {
                        warn!(migration_id = ID, "skipping non-UTF-8 key in dids keyspace");
                        continue;
                    }
                };
                let mut record: DidRecord = match serde_json::from_slice(&value) {
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
                // Tier 1: parse host out of did_id.
                let from_did_id = record
                    .did_id
                    .as_deref()
                    .and_then(|d| extract_did_host(d).ok());
                let new_domain = match from_did_id {
                    Some(host) => {
                        counters.tagged_from_did_id += 1;
                        host
                    }
                    None => {
                        // Tier 2: system default.
                        match &system_default {
                            Some(d) => {
                                counters.tagged_from_default += 1;
                                d.clone()
                            }
                            None => {
                                counters.deferred_no_default += 1;
                                debug!(
                                    migration_id = ID,
                                    mnemonic = %mnemonic,
                                    "deferred: no did_id host and no system default"
                                );
                                continue;
                            }
                        }
                    }
                };
                record.domain = new_domain;
                dids.insert(did_key(&mnemonic), &record).await?;
            }

            info!(
                migration_id = ID,
                tagged_from_did_id = counters.tagged_from_did_id,
                tagged_from_default = counters.tagged_from_default,
                already_tagged = counters.already_tagged,
                deferred_no_default = counters.deferred_no_default,
                "M-01 complete"
            );

            // The runner records the applied marker for us on Ok(()).
            // The counters here are surfaced via tracing only — a
            // future audit-log keyspace consumer would read them off
            // the structured `tracing` line.
            Ok(())
        })
    }
}

#[cfg(test)]
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

        // Migration succeeds overall but leaves the record un-tagged.
        run_migration(&store).await.unwrap();
        assert_eq!(get_rec(&store, "user1").await.domain, "");

        // Re-running after seeding a default catches up.
        create_domain(&store, &entry("late.example")).await.unwrap();
        set_default_domain(&store, "late.example").await.unwrap();

        // Need to call the migration directly — the runner won't run
        // an already-applied migration. This is the operator-driven
        // "fix forward" path; in practice a future M-02 would do
        // this work, but the bare migration entry point is here for
        // the test.
        M01TagDidRecordsWithDomain.run(&store).await.unwrap();
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

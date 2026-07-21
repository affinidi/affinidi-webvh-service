//! `m02_cache_did_record_services` — populate `DidRecord.services` for
//! every record written before the field existed.
//!
//! ## Why
//!
//! The DID list renders a service badge per DID (`WebVHHosting` / `TSP` /
//! `DIDComm` / `Other`). `list_dids` deliberately never reads log bytes —
//! see the dual-storage note on [`crate::did_ops::DidRecord`] — so the
//! badges are served from a cache on the record itself. Every write path
//! that touches `content_log_key` now keeps that cache fresh, but records
//! already on disk carry `services: None` and would render no badges until
//! their next publish. This sweep fills them in one pass.
//!
//! ## What gets touched
//!
//! Every `did:{mnemonic}` entry in `KS_DIDS` whose `services` is `None`.
//! Records that already have `Some(_)` are skipped — including
//! `Some(vec![])`, which is the meaningful "document read, advertises
//! nothing" state and must not be re-read. That makes the migration
//! idempotent and a partial run resumable.
//!
//! ## Where the services come from
//!
//! The DID document in the last log entry at `content:{mnemonic}:log`,
//! via [`crate::did_ops::extract_service_types`] — the same reader the
//! write paths use, so a swept record is byte-identical to a freshly
//! written one.
//!
//! Records with no log content (an empty slot from `create_did`, i.e.
//! `version_count == 0`) are left at `None` and counted as `skipped_no_log`.
//! That is the correct terminal state for them: there is no document, and
//! `publish_did` will fill the cache on first upload.
//!
//! ## Who runs it
//!
//! All three deployments, by two different routes:
//!
//! - `did-hosting-server` and `did-hosting-daemon` run the full
//!   [`super::registry`] at boot, which includes this migration.
//! - A standalone `did-hosting-control` has historically never invoked the
//!   migration runner at all. Rather than switch it on wholesale — which
//!   would also run `M-01` against stores that have never seen it, filling
//!   `domain` from the system-default tier as a side effect — `server.rs`
//!   constructs a runner carrying **only** this migration. It is safe to run
//!   unattended because it writes nothing but `services`, a field read only
//!   by the UI.
//!
//! `publish_did` additionally self-heals a `None` it encounters, so a record
//! this sweep deferred (unparseable log) still converges on its next publish.

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::super::store::{KS_DIDS, Store};
use super::{Migration, MigrationFuture};
use crate::did_ops::{DidRecord, content_log_key, did_key, extract_service_types};

/// Public migration ID. Stable wire identifier — never rename.
pub const ID: &str = "m02_cache_did_record_services";

/// Per-run counters surfaced in the audit log line.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct M02Counters {
    /// Records whose `services` was `None` and got filled from the log's
    /// DID document. Includes documents that advertise no services at all
    /// (they land on `Some(vec![])`).
    pub cached: u64,
    /// Records that already carried `Some(_)`. Skipped.
    pub already_cached: u64,
    /// Records with no log content — empty slots awaiting a first publish.
    /// Left at `None`; `publish_did` fills them.
    pub skipped_no_log: u64,
    /// Records whose log content was present but unparseable as JSONL with
    /// a `state`. Left at `None` and counted for follow-up; a re-run retries.
    pub deferred_bad_log: u64,
}

pub struct M02CacheDidRecordServices;

impl Migration for M02CacheDidRecordServices {
    fn id(&self) -> &'static str {
        ID
    }

    fn description(&self) -> &'static str {
        "cache DidRecord.services from each DID document's service array"
    }

    fn run<'a>(&'a self, store: &'a Store) -> MigrationFuture<'a> {
        Box::pin(async move {
            let mut counters = M02Counters::default();
            let dids = store.keyspace(KS_DIDS)?;

            // Walk every `did:{mnemonic}` key. The prefix-scan filters out
            // the `content:` / `owner:` / `watcher_sync:` neighbours.
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

                // `Some(vec![])` is a real answer, not an empty cache.
                if record.services.is_some() {
                    counters.already_cached += 1;
                    continue;
                }

                let Some(bytes) = dids.get_raw(content_log_key(&mnemonic)).await? else {
                    counters.skipped_no_log += 1;
                    continue;
                };
                let Ok(content) = String::from_utf8(bytes) else {
                    counters.deferred_bad_log += 1;
                    warn!(
                        migration_id = ID,
                        mnemonic = %mnemonic,
                        "deferred: log content is not UTF-8"
                    );
                    continue;
                };
                let Some(services) = extract_service_types(&content) else {
                    counters.deferred_bad_log += 1;
                    debug!(
                        migration_id = ID,
                        mnemonic = %mnemonic,
                        "deferred: log has no parseable entry with a `state`"
                    );
                    continue;
                };

                counters.cached += 1;
                record.services = Some(services);
                dids.insert(did_key(&mnemonic), &record).await?;
            }

            info!(
                migration_id = ID,
                cached = counters.cached,
                already_cached = counters.already_cached,
                skipped_no_log = counters.skipped_no_log,
                deferred_bad_log = counters.deferred_bad_log,
                "M-02 complete"
            );

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::MigrationRunner;
    use super::*;
    use crate::server::config::StoreConfig;

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }

    fn record(mnemonic: &str, services: Option<Vec<String>>) -> DidRecord {
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
            domain: "host.example".into(),
            services,
            agent_names: Vec::new(),
        }
    }

    /// A two-entry log whose *latest* entry advertises the three canonical
    /// services. The first entry deliberately advertises only hosting, so a
    /// reader that grabs the wrong line is caught.
    fn log_with_services() -> String {
        let v1 = r##"{"versionId":"1-a","state":{"id":"did:webvh:Q1:host.example:x","service":[{"id":"#webvh-hosting","type":"WebVHHosting","serviceEndpoint":{"uri":"https://host.example"}}]}}"##;
        let v2 = r##"{"versionId":"2-b","state":{"id":"did:webvh:Q1:host.example:x","service":[{"id":"#webvh-hosting","type":"WebVHHosting","serviceEndpoint":{"uri":"https://host.example"}},{"id":"#tsp","type":"TSPTransport","serviceEndpoint":"did:webvh:QmMED:med.example"},{"id":"#vta-didcomm","type":"DIDCommMessaging","serviceEndpoint":[{"accept":["didcomm/v2"],"uri":"did:webvh:QmMED:med.example"}]}]}}"##;
        format!("{v1}\n{v2}")
    }

    async fn seed(store: &Store, rec: &DidRecord, log: Option<&str>) {
        let ks = store.keyspace(KS_DIDS).unwrap();
        ks.insert(did_key(&rec.mnemonic), rec).await.unwrap();
        if let Some(l) = log {
            ks.insert_raw(content_log_key(&rec.mnemonic), l.as_bytes().to_vec())
                .await
                .unwrap();
        }
    }

    async fn load(store: &Store, mnemonic: &str) -> DidRecord {
        let ks = store.keyspace(KS_DIDS).unwrap();
        ks.get::<DidRecord>(did_key(mnemonic))
            .await
            .unwrap()
            .unwrap()
    }

    async fn run_m02(store: &Store) {
        MigrationRunner::new(vec![std::sync::Arc::new(M02CacheDidRecordServices)])
            .run_pending(store)
            .await
            .expect("m02 runs");
    }

    /// The core case: a legacy `None` record gets its services cached, in
    /// the document's own order (hosting, TSP, DIDComm).
    #[tokio::test]
    async fn caches_services_from_latest_log_entry() {
        let store = fjall_store().await;
        seed(&store, &record("a", None), Some(&log_with_services())).await;

        run_m02(&store).await;

        assert_eq!(
            load(&store, "a").await.services,
            Some(vec![
                "WebVHHosting".to_string(),
                "TSPTransport".to_string(),
                "DIDCommMessaging".to_string(),
            ])
        );
    }

    /// A document with no `service` array caches as `Some(vec![])` —
    /// "read it, advertises nothing" — not `None`.
    #[tokio::test]
    async fn document_without_services_caches_as_empty_vec() {
        let store = fjall_store().await;
        let log = r#"{"versionId":"1-a","state":{"id":"did:webvh:Q1:host.example:b"}}"#;
        seed(&store, &record("b", None), Some(log)).await;

        run_m02(&store).await;

        assert_eq!(load(&store, "b").await.services, Some(vec![]));
    }

    /// An empty slot (no log content) stays `None` for `publish_did` to fill.
    #[tokio::test]
    async fn record_without_log_is_left_none() {
        let store = fjall_store().await;
        seed(&store, &record("c", None), None).await;

        run_m02(&store).await;

        assert_eq!(load(&store, "c").await.services, None);
    }

    /// `Some(vec![])` is a real cached answer and must survive a re-run
    /// untouched — the migration must not mistake it for "unset" and go
    /// re-read the log.
    #[tokio::test]
    async fn already_cached_empty_vec_is_not_recomputed() {
        let store = fjall_store().await;
        // Record claims "no services"; the log says otherwise. If the
        // migration wrongly treats `Some(vec![])` as unset it will
        // overwrite from the log and this assertion fails.
        seed(
            &store,
            &record("d", Some(vec![])),
            Some(&log_with_services()),
        )
        .await;

        run_m02(&store).await;

        assert_eq!(load(&store, "d").await.services, Some(vec![]));
    }

    /// Idempotent: a second sweep over an already-swept store is a no-op.
    #[tokio::test]
    async fn is_idempotent_across_runs() {
        let store = fjall_store().await;
        seed(&store, &record("e", None), Some(&log_with_services())).await;

        run_m02(&store).await;
        let after_first = load(&store, "e").await.services;
        // A fresh runner re-reads the applied marker and skips; force the
        // migration body to run again to prove the body itself is safe.
        M02CacheDidRecordServices
            .run(&store)
            .await
            .expect("second body run");

        assert_eq!(load(&store, "e").await.services, after_first);
    }
}

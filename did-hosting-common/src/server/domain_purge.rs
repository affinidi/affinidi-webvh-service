//! Server-side domain DID purge (T30 pass 2).
//!
//! Removes every DID record whose `record.domain == target_domain`
//! from the local store. Used by two callers:
//!
//! 1. The background grace-expired sweep (60s tick) consumes ripe
//!    entries from [`super::pending_purge`] and calls this function
//!    with `reason = "grace-expired"`.
//! 2. The admin "Purge now" Trust Task (`domain/purge/1.0`) bypasses
//!    the grace and calls this function directly with
//!    `reason = "admin-immediate"`.
//!
//! ## Scoping
//!
//! Only DID records tagged with the *exact* `target_domain` are
//! deleted. Records on other domains are untouched. The match is
//! against the `domain` field set by T12's record-shape extension +
//! T13's M-01 migration; records without a `domain` (legacy or
//! unmigrated) are skipped with a warn-log — operators should run
//! the M-01 migration before relying on this function for full
//! coverage.
//!
//! ## What gets deleted per matching DID
//!
//! For each record on the target domain:
//! - `did:<mnemonic>` — the `DidRecord` itself.
//! - `content:<mnemonic>:log` — the did.jsonl bytes.
//! - `content:<mnemonic>:witness` — the witness file (if any).
//! - `owner:<did>:<mnemonic>` — the owner index entry.
//! - `watcher_sync:<mnemonic>` — the watcher-sync cursor (if any).
//!
//! All deletes for one DID are batched into a single atomic write
//! per the existing `Store` API. Cross-DID atomicity is not
//! guaranteed (a crash mid-purge leaves the keyspace partially
//! cleaned), but each individual record is removed cleanly.

use tracing::{info, warn};

use super::error::AppError;
use super::store::{KS_DIDS, Store};
use crate::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, owner_key, watcher_sync_key,
};

/// Summary of a [`purge_domain_dids`] run, returned for audit-log
/// purposes.
#[derive(Debug, PartialEq, Eq)]
pub struct PurgeReport {
    /// Number of DID records whose `domain` matched and were deleted.
    pub deleted: u64,
    /// Number of records skipped because they had no `domain` field
    /// (legacy / pre-M01 state). Operators should run the M-01
    /// migration if this is non-zero on a production deployment.
    pub skipped_no_domain: u64,
    /// Number of records skipped because their `domain` didn't match
    /// the target. The vast majority of records on a multi-domain
    /// server fall here; reported only for total accounting.
    pub skipped_other_domain: u64,
}

/// Delete every DID record on `target_domain` from the local store.
///
/// `reason` is recorded in the audit log but is not persisted with
/// the deletion (the records are gone, after all); it's surfaced via
/// the structured log only.
pub async fn purge_domain_dids(
    store: &Store,
    target_domain: &str,
    reason: &str,
) -> Result<PurgeReport, AppError> {
    let ks = store.keyspace(KS_DIDS)?;
    let raw = ks.prefix_iter_raw(b"did:".to_vec()).await?;

    let mut deleted = 0u64;
    let mut skipped_no_domain = 0u64;
    let mut skipped_other_domain = 0u64;

    for (_key, value) in raw {
        let record: DidRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "skipping malformed DidRecord during domain purge");
                continue;
            }
        };

        if record.domain.is_empty() {
            warn!(
                mnemonic = %record.mnemonic,
                "DidRecord has no domain field — skipping. Run M-01 migration for full coverage."
            );
            skipped_no_domain += 1;
            continue;
        }

        if record.domain != target_domain {
            skipped_other_domain += 1;
            continue;
        }

        // Batch every key for this DID into a single atomic write.
        // Other DIDs remain unaffected by failure on this one.
        let mut batch = store.batch();
        batch.remove(&ks, did_key(&record.mnemonic));
        batch.remove(&ks, content_log_key(&record.mnemonic));
        batch.remove(&ks, content_witness_key(&record.mnemonic));
        batch.remove(&ks, owner_key(&record.owner, &record.mnemonic));
        batch.remove(&ks, watcher_sync_key(&record.mnemonic));
        match batch.commit().await {
            Ok(()) => {
                deleted += 1;
                info!(
                    mnemonic = %record.mnemonic,
                    domain = %target_domain,
                    owner = %record.owner,
                    reason,
                    "DID record purged"
                );
            }
            Err(e) => {
                warn!(
                    mnemonic = %record.mnemonic,
                    error = %e,
                    "DID record purge failed mid-batch — leaving in place"
                );
            }
        }
    }

    info!(
        domain = %target_domain,
        reason,
        deleted,
        skipped_no_domain,
        skipped_other_domain,
        "domain purge complete"
    );

    Ok(PurgeReport {
        deleted,
        skipped_no_domain,
        skipped_other_domain,
    })
}

#[cfg(test)]
mod tests {
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

    fn record(mnemonic: &str, domain: &str) -> DidRecord {
        DidRecord {
            owner: format!("did:example:owner-{mnemonic}"),
            mnemonic: mnemonic.into(),
            created_at: 1,
            updated_at: 1,
            version_count: 1,
            did_id: Some(format!("did:webvh:Q1:{domain}:{mnemonic}")),
            content_size: 0,
            disabled: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: domain.into(),
        }
    }

    async fn seed_record(store: &Store, rec: &DidRecord) {
        let ks = store.keyspace(KS_DIDS).unwrap();
        ks.insert(did_key(&rec.mnemonic), rec).await.unwrap();
        ks.insert_raw(content_log_key(&rec.mnemonic), b"log".to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn purge_deletes_only_target_domain() {
        let store = fjall_store().await;
        seed_record(&store, &record("alice", "a.example")).await;
        seed_record(&store, &record("bob", "a.example")).await;
        seed_record(&store, &record("carol", "b.example")).await;

        let report = purge_domain_dids(&store, "a.example", "admin-immediate")
            .await
            .unwrap();
        assert_eq!(report.deleted, 2);
        assert_eq!(report.skipped_other_domain, 1);
        assert_eq!(report.skipped_no_domain, 0);

        let ks = store.keyspace(KS_DIDS).unwrap();
        assert!(
            ks.get::<DidRecord>(did_key("alice"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(ks.get::<DidRecord>(did_key("bob")).await.unwrap().is_none());
        // Carol on b.example survives.
        assert!(
            ks.get::<DidRecord>(did_key("carol"))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn purge_empty_store_is_noop() {
        let store = fjall_store().await;
        let report = purge_domain_dids(&store, "a.example", "x").await.unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(report.skipped_no_domain, 0);
        assert_eq!(report.skipped_other_domain, 0);
    }

    #[tokio::test]
    async fn purge_skips_legacy_records_without_domain() {
        let store = fjall_store().await;
        let mut legacy = record("legacy", "");
        legacy.domain = String::new();
        seed_record(&store, &legacy).await;
        seed_record(&store, &record("modern", "a.example")).await;

        let report = purge_domain_dids(&store, "a.example", "x").await.unwrap();
        assert_eq!(report.deleted, 1, "modern record deleted");
        assert_eq!(report.skipped_no_domain, 1, "legacy record skipped");
    }
}

//! DID record helpers for the edge.
//!
//! An edge writes DID records only on its control plane's signed directives
//! (`crate::messaging`, `crate::control_register::apply_single_update`); this
//! module keeps the record re-exports those paths share and the periodic
//! cleanup of empty and soft-deleted slots.

use crate::error::AppError;
use crate::store::KeyspaceHandle;
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::path_locks::PathLocks;
use tracing::warn;

// Re-export shared types and helpers from did-hosting-common so existing code
// that imports from `crate::did_ops::*` continues to work.
pub use did_hosting_common::did_ops::{
    DidRecord, LogEntryInfo, LogMetadata, content_log_key, content_witness_key, did_key,
    extract_did_id, extract_did_web_document, extract_log_metadata, extract_service_types,
    owner_key, parse_log_entries, servable_did_log, watcher_sync_key,
};

/// Validate that every line in the JSONL body is a well-formed did:webvh log entry.
pub fn validate_did_jsonl(content: &str) -> Result<(), AppError> {
    did_hosting_common::did_ops::validate_did_jsonl(content).map_err(AppError::Validation)
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Remove DID records that have `version_count == 0` and are older than `ttl_seconds`,
/// or soft-deleted records past the 30-day retention period. Returns how many
/// records were removed.
///
/// `locks` is the per-path lock the service's writers take (the daemon's
/// control plane). Each candidate is re-read and re-checked under its lock
/// before it is deleted, so a slot published into after the scan is kept.
/// Pass `None` where nothing else writes DID records under a path lock.
///
/// A failed delete is logged and skipped rather than ending the pass, so the
/// count returned always matches what was removed.
pub async fn cleanup_empty_dids(
    dids_ks: &KeyspaceHandle,
    ttl_seconds: u64,
    locks: Option<&PathLocks>,
) -> Result<u64, AppError> {
    const SOFT_DELETE_RETENTION: u64 = 30 * 24 * 3600; // 30 days
    let now = now_epoch();
    let should_remove = |record: &DidRecord| {
        // Empty records past TTL
        (record.version_count == 0 && now.saturating_sub(record.created_at) > ttl_seconds)
            // Soft-deleted records past retention
            || record
                .deleted_at
                .is_some_and(|d| now.saturating_sub(d) > SOFT_DELETE_RETENTION)
    };

    let raw = dids_ks.prefix_iter_raw("did:").await?;
    let mut removed = 0u64;

    for (_key, value) in raw {
        let Ok(snapshot) = serde_json::from_slice::<DidRecord>(&value) else {
            continue;
        };
        if !should_remove(&snapshot) {
            continue;
        }
        let mnemonic = snapshot.mnemonic;

        let _guard = match locks {
            Some(locks) => Some(locks.guard(&mnemonic).await),
            None => None,
        };
        // The scan is a snapshot: re-read under the lock and decide again.
        let record = match dids_ks.get::<DidRecord>(did_key(&mnemonic)).await {
            Ok(Some(record)) if should_remove(&record) => record,
            Ok(_) => continue,
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "DID cleanup: re-read failed; skipping");
                continue;
            }
        };

        // One atomic write per DID: a crash part-way can no longer leave
        // a record without its content, or an owner index without its
        // record.
        let mut batch = dids_ks.batch();
        batch.remove(dids_ks, did_key(&record.mnemonic));
        batch.remove(dids_ks, content_log_key(&record.mnemonic));
        batch.remove(dids_ks, content_witness_key(&record.mnemonic));
        batch.remove(dids_ks, owner_key(&record.owner, &record.mnemonic));
        match batch.commit().await {
            Ok(()) => removed += 1,
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "DID cleanup: delete failed; will retry next pass");
            }
        }
    }

    Ok(removed)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- validate_did_jsonl wrapper tests ----

    #[test]
    fn validate_jsonl_empty_string_rejected() {
        let result = validate_did_jsonl("");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "expected 'empty' in: {err}");
    }

    #[test]
    fn validate_jsonl_invalid_json_rejected() {
        let result = validate_did_jsonl("this is not json");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid log entry at line 1"),
            "expected line reference in: {err}"
        );
    }

    #[test]
    fn validate_jsonl_valid_json_but_not_log_entry() {
        let result = validate_did_jsonl(r#"{"hello":"world"}"#);
        assert!(result.is_err());
    }

    async fn make_valid_jsonl() -> String {
        use did_hosting_common::did::{build_did_document, create_log_entry, encode_host};

        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let pk = secret.get_public_keymultibase().unwrap();
        let host = encode_host("http://localhost:3000").unwrap();
        let doc = build_did_document(&host, "test-validate", &pk, &Default::default());
        let (_scid, jsonl) = create_log_entry(&doc, &secret).await.unwrap();
        jsonl
    }

    #[tokio::test]
    async fn validate_jsonl_blank_lines_skipped() {
        let entry = make_valid_jsonl().await;
        let with_blanks = format!("\n{entry}\n\n");
        assert!(validate_did_jsonl(&with_blanks).is_ok());
    }

    #[tokio::test]
    async fn validate_jsonl_valid_single_entry() {
        let entry = make_valid_jsonl().await;
        assert!(validate_did_jsonl(&entry).is_ok());
    }

    #[tokio::test]
    async fn validate_jsonl_second_line_invalid() {
        let entry = make_valid_jsonl().await;
        let content = format!("{entry}\nnot valid json");
        let result = validate_did_jsonl(&content);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("line 2"), "expected 'line 2' in error: {err}");
    }

    /// The cleanup removes only the expired records and reports how many.
    #[tokio::test]
    async fn cleanup_removes_expired_dids() {
        use did_hosting_common::server::config::StoreConfig;
        use did_hosting_common::server::store::{KS_DIDS, Store};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open fjall");
        let ks = store.keyspace(KS_DIDS).unwrap();
        let record = |mnemonic: &str, version_count: u64| DidRecord {
            owner: "did:example:owner".into(),
            mnemonic: mnemonic.into(),
            created_at: 1,
            updated_at: 1,
            version_count,
            did_id: None,
            content_size: 0,
            disabled: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: "example.com".into(),
            services: None,
            agent_names: Vec::new(),
        };
        ks.insert(did_key("empty"), &record("empty", 0))
            .await
            .unwrap();
        ks.insert(did_key("live-a"), &record("live-a", 1))
            .await
            .unwrap();
        ks.insert(did_key("live-b"), &record("live-b", 2))
            .await
            .unwrap();

        let removed = cleanup_empty_dids(&ks, 60, None).await.unwrap();

        assert_eq!(removed, 1);
        assert_eq!(ks.prefix_iter_raw("did:").await.unwrap().len(), 2);
    }

    /// A slot the scan saw as empty but that is published into before the
    /// cleanup takes its lock must be kept: the delete decision is made
    /// again on the record read under the lock.
    #[tokio::test]
    async fn cleanup_keeps_a_slot_published_after_the_scan() {
        use did_hosting_common::server::config::StoreConfig;
        use did_hosting_common::server::store::{KS_DIDS, Store};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open fjall");
        let ks = store.keyspace(KS_DIDS).unwrap();
        let mut record = DidRecord {
            owner: "did:example:owner".into(),
            mnemonic: "slot".into(),
            created_at: 1,
            updated_at: 1,
            version_count: 0,
            did_id: None,
            content_size: 0,
            disabled: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: "example.com".into(),
            services: None,
            agent_names: Vec::new(),
        };
        ks.insert(did_key("slot"), &record).await.unwrap();

        // A publish holds the slot's lock while the cleanup scans.
        let locks = PathLocks::new();
        let publish_guard = locks.guard("slot").await;
        let cleanup = {
            let ks = ks.clone();
            let locks = locks.clone();
            tokio::spawn(async move { cleanup_empty_dids(&ks, 60, Some(&locks)).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!cleanup.is_finished(), "cleanup waits for the slot's lock");

        record.version_count = 1;
        ks.insert(did_key("slot"), &record).await.unwrap();
        drop(publish_guard);

        assert_eq!(cleanup.await.unwrap().unwrap(), 0);
        assert!(
            ks.get::<DidRecord>(did_key("slot"))
                .await
                .unwrap()
                .is_some()
        );
    }
}

//! DID record helpers for the edge.
//!
//! An edge writes DID records only on its control plane's signed directives
//! (`crate::messaging`, `crate::control_register::apply_single_update`); this
//! module keeps the record re-exports those paths share and the periodic
//! cleanup of empty and soft-deleted slots.

use crate::error::AppError;
use crate::store::KeyspaceHandle;
use did_hosting_common::server::auth::session::now_epoch;

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

/// What one cleanup pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    /// DID records removed.
    pub removed: u64,
    /// DID records left after the pass. The pass reads every record, so
    /// callers can take the hosted-DID count from it instead of scanning
    /// again.
    pub remaining: u64,
}

/// Remove DID records that have `version_count == 0` and are older than `ttl_seconds`,
/// or soft-deleted records past the 30-day retention period.
pub async fn cleanup_empty_dids(
    dids_ks: &KeyspaceHandle,
    ttl_seconds: u64,
) -> Result<CleanupReport, AppError> {
    const SOFT_DELETE_RETENTION: u64 = 30 * 24 * 3600; // 30 days
    let now = now_epoch();
    let raw = dids_ks.prefix_iter_raw("did:").await?;
    let scanned = raw.len() as u64;
    let mut removed = 0u64;

    for (_key, value) in raw {
        let record: DidRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let should_remove =
            // Empty records past TTL
            (record.version_count == 0 && now.saturating_sub(record.created_at) > ttl_seconds)
            // Soft-deleted records past retention
            || record.deleted_at.is_some_and(|d| now.saturating_sub(d) > SOFT_DELETE_RETENTION);

        if should_remove {
            // One atomic write per DID: a crash part-way can no longer leave
            // a record without its content, or an owner index without its
            // record.
            let mut batch = dids_ks.batch();
            batch.remove(dids_ks, did_key(&record.mnemonic));
            batch.remove(dids_ks, content_log_key(&record.mnemonic));
            batch.remove(dids_ks, content_witness_key(&record.mnemonic));
            batch.remove(dids_ks, owner_key(&record.owner, &record.mnemonic));
            batch.commit().await?;
            removed += 1;
        }
    }

    Ok(CleanupReport {
        removed,
        remaining: scanned - removed,
    })
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

    /// The cleanup reads every DID record, so the count it reports left
    /// must match what is stored after it removes the expired ones.
    #[tokio::test]
    async fn cleanup_reports_the_dids_left() {
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

        let report = cleanup_empty_dids(&ks, 60).await.unwrap();

        assert_eq!(
            report,
            CleanupReport {
                removed: 1,
                remaining: 2
            }
        );
        assert_eq!(ks.prefix_iter_raw("did:").await.unwrap().len(), 2);
    }
}

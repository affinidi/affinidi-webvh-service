use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// A mirrored DID record on the watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherRecord {
    pub mnemonic: String,
    pub did_id: Option<String>,
    pub source_url: String,
    pub updated_at: u64,
    pub disabled: bool,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

pub fn did_key(mnemonic: &str) -> String {
    format!("did:{mnemonic}")
}

pub fn content_log_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:log")
}

pub fn content_witness_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:witness")
}

// ---------------------------------------------------------------------------
// CRUD operations
// ---------------------------------------------------------------------------

pub async fn store_record(
    ks: &KeyspaceHandle,
    record: &WatcherRecord,
) -> Result<(), AppError> {
    ks.insert(did_key(&record.mnemonic), record).await
}

pub async fn get_record(
    ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<Option<WatcherRecord>, AppError> {
    ks.get(did_key(mnemonic)).await
}

pub async fn delete_record(
    ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(), AppError> {
    ks.remove(did_key(mnemonic)).await?;
    ks.remove(content_log_key(mnemonic)).await?;
    ks.remove(content_witness_key(mnemonic)).await?;
    Ok(())
}

pub async fn list_records(
    ks: &KeyspaceHandle,
) -> Result<Vec<WatcherRecord>, AppError> {
    let entries = ks.prefix_iter_raw("did:").await?;
    let mut records = Vec::new();
    for (_key, value) in entries {
        if let Ok(record) = serde_json::from_slice::<WatcherRecord>(&value) {
            records.push(record);
        }
    }
    Ok(records)
}

//! The watcher's mirror: what it holds for each slot, and the rules a sync
//! must pass before it replaces any of it.
//!
//! A watcher is a replica (`webvh/sync/update/0.2`): it verifies what it
//! mirrors exactly as an edge verifies what it serves, rather than taking its
//! source's word for it. A synced log must
//!
//! - establish exactly the DID the update names, at exactly the slot it names
//!   on that DID's own host;
//! - verify as a did:webvh log, witness proofs included when the log
//!   configures witnesses;
//! - hold exactly `versionCount` entries;
//! - strictly extend the log the watcher holds for the same DID, and the
//!   high-water log it keeps for that DID, which a delete does not clear — so
//!   not even a configured source can roll a DID back or rewrite its history.

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

/// A mirrored DID record on the watcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatcherRecord {
    pub mnemonic: String,
    pub did_id: String,
    /// The source (control plane) whose signed sync last wrote this slot.
    pub source_did: String,
    pub version_count: u64,
    pub updated_at: u64,
    pub disabled: bool,
}

pub fn did_key(mnemonic: &str) -> String {
    format!("did:{mnemonic}")
}

pub fn content_log_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:log")
}

pub fn content_witness_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:witness")
}

/// The furthest log this watcher has ever mirrored for a DID, by SCID. Never
/// removed.
fn high_water_key(scid: &str) -> String {
    format!("hw:id:{scid}")
}

pub async fn get_record(
    ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<Option<WatcherRecord>, AppError> {
    ks.get(did_key(mnemonic)).await
}

pub async fn list_records(ks: &KeyspaceHandle) -> Result<Vec<WatcherRecord>, AppError> {
    let entries = ks.prefix_iter_raw("did:").await?;
    let mut records = Vec::new();
    for (_key, value) in entries {
        if let Ok(record) = serde_json::from_slice::<WatcherRecord>(&value) {
            records.push(record);
        }
    }
    Ok(records)
}

/// One slot's complete state, as a source pushes it.
#[derive(Debug, Clone)]
pub struct SyncEntry {
    pub mnemonic: String,
    pub did_id: String,
    pub log_content: String,
    pub witness_content: Option<String>,
    pub version_count: u64,
    pub disabled: bool,
}

/// Why a sync was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncRefusal {
    /// The log does not verify, or does not establish what the update names
    /// (`invalidLog`).
    InvalidLog(String),
    /// The log does not strictly extend history already mirrored
    /// (`historyRewrite`).
    HistoryRewrite(String),
    /// The DID is held as deactivated (`deactivated`).
    Deactivated(String),
    /// The slot holds a different DID, written by a different source: one
    /// source cannot take over, or delete, another's slot (`notAuthorized`).
    NotOwner(String),
    /// The watcher could not apply it just now (storage): retryable.
    Transient(String),
}

impl From<AppError> for SyncRefusal {
    fn from(e: AppError) -> Self {
        SyncRefusal::Transient(e.to_string())
    }
}

/// What [`apply_sync`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncApplied {
    Applied,
    Unchanged,
}

fn webvh_scid(did_id: &str) -> Option<String> {
    did_id
        .strip_prefix("did:webvh:")?
        .split(':')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Verify `entry` against everything the watcher has mirrored, and apply it
/// as one atomic change. `source_did` is the proven source.
pub async fn apply_sync(
    store: &Store,
    ks: &KeyspaceHandle,
    source_did: &str,
    entry: &SyncEntry,
) -> Result<SyncApplied, SyncRefusal> {
    use did_hosting_common::did_ops::{
        extract_did_id, validate_did_id_matches_request, verify_did_log_and_witness_proofs,
        verify_log_extends,
    };

    did_hosting_common::server::mnemonic::validate_mnemonic(&entry.mnemonic)
        .map_err(|e| SyncRefusal::InvalidLog(format!("mnemonic: {e}")))?;

    let entries = entry
        .log_content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count() as u64;
    if entries != entry.version_count {
        return Err(SyncRefusal::InvalidLog(format!(
            "versionCount is {} but logContent holds {entries} entries",
            entry.version_count
        )));
    }

    // Binding: the log establishes exactly the named DID, and that DID
    // resolves at exactly this slot on its own host.
    match extract_did_id(&entry.log_content) {
        Some(id) if id == entry.did_id => {}
        other => {
            return Err(SyncRefusal::InvalidLog(format!(
                "the update names {} but its log establishes {}",
                entry.did_id,
                other.as_deref().unwrap_or("no DID")
            )));
        }
    }
    let scid = webvh_scid(&entry.did_id).ok_or_else(|| {
        SyncRefusal::InvalidLog(format!("{} is not a did:webvh identifier", entry.did_id))
    })?;
    let host = did_hosting_common::server::domain::safety::extract_did_host(&entry.did_id)
        .map_err(|e| SyncRefusal::InvalidLog(e.to_string()))?;
    validate_did_id_matches_request(&entry.did_id, &entry.mnemonic, &format!("https://{host}"))
        .map_err(SyncRefusal::InvalidLog)?;

    // Chain: every entry's proof, and the witness proofs when witnessed.
    verify_did_log_and_witness_proofs(&entry.log_content, entry.witness_content.as_deref())
        .map_err(SyncRefusal::InvalidLog)?;

    // History: strictly extend every history mirrored for this DID.
    let held: Option<WatcherRecord> = ks.get(did_key(&entry.mnemonic)).await?;
    let held_log = ks
        .get_raw(content_log_key(&entry.mnemonic))
        .await?
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    // A slot is its writer's: another source may extend the same DID there
    // (the history checks below still hold it to that DID's log), but it may
    // not re-point the slot at a different DID.
    if let Some(prev) = held.as_ref()
        && prev.source_did != source_did
        && webvh_scid(&prev.did_id).as_deref() != Some(scid.as_str())
    {
        return Err(SyncRefusal::NotOwner(format!(
            "slot {} mirrors a DID another source syncs",
            entry.mnemonic
        )));
    }
    let same_did_held = held_log.clone().filter(|_| {
        held.as_ref().and_then(|r| webvh_scid(&r.did_id)).as_deref() == Some(scid.as_str())
    });
    let high_water = ks
        .get_raw(high_water_key(&scid))
        .await?
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    for previous in [same_did_held, high_water].into_iter().flatten() {
        verify_log_extends(Some(&previous), &entry.log_content).map_err(|e| {
            if e.contains("deactivated") {
                SyncRefusal::Deactivated(e)
            } else {
                SyncRefusal::HistoryRewrite(e)
            }
        })?;
    }

    // Nothing to write when the watcher already mirrors exactly this state.
    let held_witness = ks
        .get_raw(content_witness_key(&entry.mnemonic))
        .await?
        .map(|w| String::from_utf8_lossy(&w).into_owned());
    if let Some(prev) = held.as_ref()
        && prev.did_id == entry.did_id
        && prev.disabled == entry.disabled
        && held_log.as_deref() == Some(entry.log_content.as_str())
        && held_witness == entry.witness_content
    {
        return Ok(SyncApplied::Unchanged);
    }

    let record = WatcherRecord {
        mnemonic: entry.mnemonic.clone(),
        did_id: entry.did_id.clone(),
        source_did: source_did.to_string(),
        version_count: entry.version_count,
        updated_at: did_hosting_common::server::auth::session::now_epoch(),
        disabled: entry.disabled,
    };
    let mut batch = store.batch();
    batch.insert(ks, did_key(&entry.mnemonic), &record)?;
    batch.insert_raw(
        ks,
        content_log_key(&entry.mnemonic),
        entry.log_content.as_bytes().to_vec(),
    );
    // An absent `witnessContent` means the slot holds no witness proofs.
    match entry.witness_content.as_deref() {
        Some(w) => batch.insert_raw(
            ks,
            content_witness_key(&entry.mnemonic),
            w.as_bytes().to_vec(),
        ),
        None => batch.remove(ks, content_witness_key(&entry.mnemonic)),
    }
    batch.insert_raw(
        ks,
        high_water_key(&scid),
        entry.log_content.as_bytes().to_vec(),
    );
    batch.commit().await?;
    Ok(SyncApplied::Applied)
}

/// Stop mirroring a slot for `source_did`. The high-water mark stays, so a
/// later sync cannot roll the DID back. Returns whether anything was held for
/// that source: a slot another source wrote is left alone, and reported as
/// not held, so a source learns nothing of other sources' slots.
pub async fn delete_record(
    store: &Store,
    ks: &KeyspaceHandle,
    mnemonic: &str,
    source_did: &str,
) -> Result<bool, AppError> {
    let held: Option<WatcherRecord> = ks.get(did_key(mnemonic)).await?;
    if held.is_none_or(|r| r.source_did != source_did) {
        return Ok(false);
    }
    let mut batch = store.batch();
    batch.remove(ks, did_key(mnemonic));
    batch.remove(ks, content_log_key(mnemonic));
    batch.remove(ks, content_witness_key(mnemonic));
    batch.commit().await?;
    Ok(true)
}

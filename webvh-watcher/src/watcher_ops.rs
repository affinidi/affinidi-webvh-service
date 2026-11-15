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
//!
//! A slot belongs to the source that first wrote it ([`WatcherRecord::source_did`])
//! until that source deletes it. No other source may update, disable or delete
//! it, even with the same log. A record stored by an earlier release is bound
//! to the source it names, which is the source that last wrote it.
//!
//! The first sync wins: a configured source that syncs a DID's public log
//! before the DID's own control plane does holds the slot. Two settings bound
//! that. A source configured with `domains` (`[[sync.sources]]`) may sync only
//! DIDs on those hosts. And a slot whose holder is no longer a configured
//! source is released: the next configured source to sync or delete it may,
//! still held to the DID's high-water log.
//!
//! The chain is verified before any lock is taken, on a blocking thread, so
//! syncs of different slots verify in parallel. The read-check-write that
//! follows runs under the slot's lock and then the DID's (per-process
//! [`PathLocks`], slot first, then the SCID's high-water key), so two syncs of
//! one slot or one DID cannot both pass against the same old state. The store
//! offers no conditional write, so two watcher processes on one shared store
//! could both pass the check; run one watcher process per store.
//!
//! ## The high-water mark
//!
//! The furthest log mirrored for a DID is kept as a [`HighWaterMark`] — its
//! entry count, last `versionId`, a SHA-256 over its entries and whether it
//! deactivated the DID — not as a second copy of the log. That is all the
//! history check needs: a successor must hold at least that many entries,
//! the first of which hash to the mark (so it diverges nowhere in the shared
//! history), and must add none once the DID is deactivated. A delete keeps the
//! mark on purpose: it is the tombstone that stops a later sync replaying an
//! older log at a released slot, and at a few hundred bytes it costs nothing
//! to keep. Rows written by an earlier release hold the full log; they are
//! read as their mark and rewritten compact ([`migrate_high_water_marks`]).

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use did_hosting_common::server::path_locks::PathLocks;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::SyncConfig;
use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

/// A mirrored DID record on the watcher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatcherRecord {
    pub mnemonic: String,
    pub did_id: String,
    /// The source (control plane) that holds this slot: the one whose signed
    /// sync first wrote it. It never changes while the slot is held; only
    /// this source can update or delete the slot.
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

/// Prefix of the high-water marks, one per DID SCID.
pub const HIGH_WATER_PREFIX: &str = "hw:id:";

/// The furthest log this watcher has ever mirrored for a DID, by SCID. Never
/// removed: a delete keeps it as the DID's anti-rollback tombstone.
pub fn high_water_key(scid: &str) -> String {
    format!("{HIGH_WATER_PREFIX}{scid}")
}

/// The furthest log mirrored for a DID, without the log itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HighWaterMark {
    /// How many entries the log held.
    pub entries: u64,
    /// The `versionId` of its last entry.
    pub last_version_id: String,
    /// Lowercase hex SHA-256 over its entries (each trimmed, joined by `\n`).
    pub entries_sha256: String,
    /// Whether any of its entries deactivated the DID.
    pub deactivated: bool,
}

/// A log's non-empty entries, trimmed — the unit the history check compares.
fn log_entries(log: &str) -> Vec<&str> {
    log.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

fn entries_digest(entries: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for (i, line) in entries.iter().enumerate() {
        if i > 0 {
            hasher.update(b"\n");
        }
        hasher.update(line.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl HighWaterMark {
    /// The mark of `log`.
    pub fn of(log: &str) -> Self {
        let entries = log_entries(log);
        let parsed = |line: &str| serde_json::from_str::<serde_json::Value>(line).ok();
        let last_version_id = entries
            .last()
            .and_then(|l| parsed(l))
            .and_then(|v| v.get("versionId")?.as_str().map(str::to_string))
            .unwrap_or_default();
        let deactivated = entries.iter().any(|l| {
            parsed(l)
                .and_then(|v| v.get("parameters")?.get("deactivated")?.as_bool())
                .unwrap_or(false)
        });
        Self {
            entries: entries.len() as u64,
            last_version_id,
            entries_sha256: entries_digest(&entries),
            deactivated,
        }
    }

    /// Read a stored mark: the compact form, or the full log an earlier
    /// release stored. Returns the mark and whether the row was the latter.
    pub fn from_stored(raw: &[u8]) -> (Self, bool) {
        match serde_json::from_slice::<Self>(raw) {
            Ok(mark) => (mark, false),
            Err(_) => (Self::of(&String::from_utf8_lossy(raw)), true),
        }
    }

    /// Whether `next` is an acceptable successor of the log this marks — the
    /// same rule as `did_ops::verify_log_extends`, against the mark.
    pub fn admits(&self, next: &str) -> Result<(), did_hosting_common::did_ops::LogExtendError> {
        use did_hosting_common::did_ops::LogExtendError;
        let new = log_entries(next);
        let held = self.entries as usize;
        if new.len() < held || entries_digest(&new[..held]) != self.entries_sha256 {
            return Err(LogExtendError::HistoryRewrite {
                held,
                received: new.len(),
            });
        }
        if self.deactivated && new.len() != held {
            return Err(LogExtendError::Deactivated);
        }
        Ok(())
    }
}

/// Rewrite every high-water row an earlier release stored as a full log into
/// its compact [`HighWaterMark`]. Idempotent; returns how many it rewrote.
pub async fn migrate_high_water_marks(ks: &KeyspaceHandle) -> Result<usize, AppError> {
    let mut rewritten = 0;
    for key in ks.prefix_keys_raw(HIGH_WATER_PREFIX).await? {
        let Some(raw) = ks.get_raw(key.clone()).await? else {
            continue;
        };
        let (mark, legacy) = HighWaterMark::from_stored(&raw);
        if legacy {
            ks.insert(key, &mark).await?;
            rewritten += 1;
        }
    }
    Ok(rewritten)
}

/// The slots held as disabled, in memory, so resolution answers from one
/// store read. Loaded at boot ([`DisabledSlots::load`]) and kept current by
/// [`apply_sync`] and [`delete_record`] — the only writers of a record, in
/// the one watcher process a store has.
///
/// Until it is loaded it is not *tracked*, and resolution reads the record
/// as before: the daemon's embedded, resolution-only watcher reads a store
/// it does not write, so it never loads one.
#[derive(Debug, Clone, Default)]
pub struct DisabledSlots(Arc<DisabledInner>);

#[derive(Debug, Default)]
struct DisabledInner {
    set: RwLock<HashSet<String>>,
    tracked: AtomicBool,
}

impl DisabledSlots {
    /// Whether `mnemonic` is held as disabled, or `None` while the set is
    /// not tracked (read the record instead).
    pub fn is_disabled(&self, mnemonic: &str) -> Option<bool> {
        self.0.tracked.load(Ordering::Acquire).then(|| {
            self.0
                .set
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .contains(mnemonic)
        })
    }

    fn set(&self, mnemonic: &str, disabled: bool) {
        let mut set = self.0.set.write().unwrap_or_else(|p| p.into_inner());
        if disabled {
            set.insert(mnemonic.to_string());
        } else {
            set.remove(mnemonic);
        }
    }

    /// Fill from the stored records, and track from then on. Returns how
    /// many slots are disabled.
    pub async fn load(&self, ks: &KeyspaceHandle) -> Result<usize, AppError> {
        // Only the two members any slot record carries.
        #[derive(Deserialize)]
        struct Slot {
            mnemonic: String,
            #[serde(default)]
            disabled: bool,
        }
        let disabled_of = |rows: &[(Vec<u8>, Vec<u8>)]| -> Vec<String> {
            rows.iter()
                .filter_map(|(_, v)| serde_json::from_slice::<Slot>(v).ok())
                .filter(|s| s.disabled)
                .map(|s| s.mnemonic)
                .collect()
        };
        let mut found = Vec::new();
        let mut cursor = None;
        loop {
            match ks.prefix_page_raw("did:", cursor, 500).await? {
                Some(page) => {
                    found.extend(disabled_of(&page.rows));
                    match page.next {
                        Some(next) => cursor = Some(next),
                        None => break,
                    }
                }
                None => {
                    found.extend(disabled_of(&ks.prefix_iter_raw("did:").await?));
                    break;
                }
            }
        }
        let n = found.len();
        self.0
            .set
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .extend(found);
        self.0.tracked.store(true, Ordering::Release);
        Ok(n)
    }
}

/// What a sync runs against: the store and the watcher's in-process state.
#[derive(Clone, Copy)]
pub struct Mirror<'a> {
    pub store: &'a Store,
    pub ks: &'a KeyspaceHandle,
    pub sync: &'a SyncConfig,
    pub locks: &'a PathLocks,
    pub disabled: &'a DisabledSlots,
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
    /// The slot is held by a different source: one source cannot update,
    /// disable, take over or delete another's slot (`notAuthorized`).
    NotOwner(String),
    /// The store's per-item size limit refuses the log (`taskFailed`). Not
    /// retryable: the same log will be refused every time.
    TooLarge(String),
    /// The watcher could not apply it just now (storage): retryable.
    Transient(String),
}

impl From<AppError> for SyncRefusal {
    fn from(e: AppError) -> Self {
        match e {
            AppError::QuotaExceeded { .. } => SyncRefusal::TooLarge(e.to_string()),
            e => SyncRefusal::Transient(e.to_string()),
        }
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

/// Whether `held` belongs to a source other than `source_did`. A slot whose
/// holder is no longer configured is not held: it is logged and released.
fn held_by_another(
    sync: &SyncConfig,
    held: &WatcherRecord,
    source_did: &str,
    mnemonic: &str,
) -> bool {
    if held.source_did == source_did {
        return false;
    }
    if !sync.is_source(&held.source_did) {
        tracing::warn!(
            mnemonic,
            old_holder = %held.source_did,
            source = %source_did,
            "slot released: its holder is no longer a configured source"
        );
        return false;
    }
    true
}

/// The slot's mirrored log and witness proofs, as stored.
async fn held_content(
    ks: &KeyspaceHandle,
    mnemonic: &str,
) -> Result<(Option<String>, Option<String>), AppError> {
    let log = ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    let witness = ks
        .get_raw(content_witness_key(mnemonic))
        .await?
        .map(|w| String::from_utf8_lossy(&w).into_owned());
    Ok((log, witness))
}

/// Verify the chain of `entry`, on a blocking thread: up to
/// `MAX_LOG_ENTRIES` signature checks must not stall an async worker.
async fn verify_chain(entry: &SyncEntry) -> Result<(), SyncRefusal> {
    let log = entry.log_content.clone();
    let witness = entry.witness_content.clone();
    tokio::task::spawn_blocking(move || {
        did_hosting_common::did_ops::verify_did_log_and_witness_proofs(&log, witness.as_deref())
    })
    .await
    .map_err(|e| SyncRefusal::Transient(format!("verification task failed: {e}")))?
    .map_err(SyncRefusal::InvalidLog)
}

/// Verify `entry` against everything the watcher has mirrored, and apply it
/// as one atomic change. `source_did` is the proven source.
///
/// The chain is verified first, outside any lock. A re-send of exactly the
/// log and witness proofs already mirrored is not re-verified: they were
/// verified when they were stored, and nothing else writes them.
pub async fn apply_sync(
    m: Mirror<'_>,
    source_did: &str,
    entry: &SyncEntry,
) -> Result<SyncApplied, SyncRefusal> {
    use did_hosting_common::did_ops::{
        LogExtendError, extract_did_id, validate_did_id_matches_request, verify_log_extends,
    };
    let Mirror {
        store, ks, sync, ..
    } = m;

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
    if !sync.allows_host(source_did, &host) {
        tracing::warn!(
            mnemonic = %entry.mnemonic,
            %host,
            source = %source_did,
            "sync refused: the DID's host is not among the source's domains"
        );
        return Err(SyncRefusal::NotOwner(format!(
            "this source may not sync DIDs on {host}"
        )));
    }

    // Chain: every entry's proof, and the witness proofs when witnessed —
    // before any lock, unless this is exactly what is already mirrored.
    let is_mirrored = |held: &(Option<String>, Option<String>)| {
        held.0.as_deref() == Some(entry.log_content.as_str()) && held.1 == entry.witness_content
    };
    let mut verified = false;
    if !is_mirrored(&held_content(ks, &entry.mnemonic).await?) {
        verify_chain(entry).await?;
        verified = true;
    }

    // Read-check-write under the slot's lock, then the DID's.
    let _slot = m.locks.guard(&did_key(&entry.mnemonic)).await;
    let _did = m.locks.guard(&high_water_key(&scid)).await;

    let held: Option<WatcherRecord> = ks.get(did_key(&entry.mnemonic)).await?;
    let (held_log, held_witness) = held_content(ks, &entry.mnemonic).await?;
    let mirrored = held_log.as_deref() == Some(entry.log_content.as_str())
        && held_witness == entry.witness_content;
    if !mirrored && !verified {
        // The slot changed between the first read and the lock.
        verify_chain(entry).await?;
    }
    // A slot is its holder's: no other source may write to it, not even to
    // re-send the same log, or to flip `disabled`.
    if let Some(prev) = held.as_ref()
        && held_by_another(sync, prev, source_did, &entry.mnemonic)
    {
        tracing::warn!(
            mnemonic = %entry.mnemonic,
            holder = %prev.source_did,
            source = %source_did,
            "sync refused: the slot is held by another source"
        );
        return Err(SyncRefusal::NotOwner(format!(
            "slot {} is held by another source",
            entry.mnemonic
        )));
    }
    let extend_refusal = |e: LogExtendError| match e {
        LogExtendError::Deactivated => SyncRefusal::Deactivated(e.to_string()),
        LogExtendError::HistoryRewrite { .. } => SyncRefusal::HistoryRewrite(e.to_string()),
    };
    // History: strictly extend every history mirrored for this DID — the log
    // the slot holds (trivially, when it is the same), and the high-water mark.
    let same_did_held = held_log.as_deref().filter(|_| {
        held.as_ref().and_then(|r| webvh_scid(&r.did_id)).as_deref() == Some(scid.as_str())
    });
    if let Some(previous) = same_did_held
        && previous != entry.log_content
    {
        verify_log_extends(Some(previous), &entry.log_content).map_err(extend_refusal)?;
    }
    let high_water = ks.get_raw(high_water_key(&scid)).await?;
    let mut mark_current = false;
    if let Some(raw) = high_water.as_deref() {
        let (mark, legacy) = HighWaterMark::from_stored(raw);
        mark.admits(&entry.log_content).map_err(extend_refusal)?;
        mark_current = !legacy && mark.entries == entry.version_count;
    }

    // Nothing to write when the watcher already mirrors exactly this state
    // for this source. A released slot is rewritten to record its new holder.
    if let Some(prev) = held.as_ref()
        && prev.source_did == source_did
        && prev.did_id == entry.did_id
        && prev.disabled == entry.disabled
        && mirrored
        && mark_current
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
    batch.insert(
        ks,
        high_water_key(&scid),
        &HighWaterMark::of(&entry.log_content),
    )?;
    // Hidden before the commit, shown only after it: resolution never serves
    // a slot the store holds as disabled.
    if entry.disabled {
        m.disabled.set(&entry.mnemonic, true);
    }
    if let Err(e) = batch.commit().await {
        let was_disabled = held.as_ref().is_some_and(|r| r.disabled);
        if entry.disabled && !was_disabled {
            m.disabled.set(&entry.mnemonic, false);
        }
        return Err(e.into());
    }
    if !entry.disabled {
        m.disabled.set(&entry.mnemonic, false);
    }
    Ok(SyncApplied::Applied)
}

/// Stop mirroring a slot for `source_did`. The high-water mark stays, so a
/// later sync cannot roll the DID back, but the slot is released: any
/// configured source may write it next. Returns whether the slot was removed.
/// A slot another configured source holds is left alone and reported as not
/// held; one whose holder is no longer configured is removed.
pub async fn delete_record(
    m: Mirror<'_>,
    mnemonic: &str,
    source_did: &str,
) -> Result<bool, AppError> {
    let Mirror {
        store, ks, sync, ..
    } = m;
    let _slot = m.locks.guard(&did_key(mnemonic)).await;
    let held: Option<WatcherRecord> = ks.get(did_key(mnemonic)).await?;
    match held {
        None => return Ok(false),
        Some(r) if held_by_another(sync, &r, source_did, mnemonic) => {
            tracing::warn!(
                mnemonic,
                holder = %r.source_did,
                source = %source_did,
                "sync delete refused: the slot is held by another source"
            );
            return Ok(false);
        }
        Some(_) => {}
    }
    let mut batch = store.batch();
    batch.remove(ks, did_key(mnemonic));
    batch.remove(ks, content_log_key(mnemonic));
    batch.remove(ks, content_witness_key(mnemonic));
    batch.commit().await?;
    m.disabled.set(mnemonic, false);
    Ok(true)
}

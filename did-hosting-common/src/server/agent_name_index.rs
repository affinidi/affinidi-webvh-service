//! Helpers for the agent-name index (`name:{domain}:{name}`) shared by the
//! paths that delete DIDs: the control plane's `did/delete` and the domain
//! purge.
//!
//! The index key is shared by every slot on a domain, so a write that
//! depends on what the index holds takes the name's own lock
//! ([`lock_key`]) after the slot's lock, and only ever removes entries that
//! still point at its own slot ([`owned_keys`]).

use tokio::sync::OwnedMutexGuard;

use super::domain::safety::extract_did_host;
use super::error::AppError;
use super::path_locks::PathLocks;
use super::store::KeyspaceHandle;
use crate::did_ops::{DidRecord, agent_name_key};

/// The `PathLocks` key for one index key. The `::` prefix keeps it apart
/// from slot paths, which can never carry it.
pub fn lock_key(index_key: &str) -> String {
    format!("::agent-name:{index_key}")
}

/// Take the lock of every index key in `index_keys`, in sorted order.
///
/// Callers hold the slot's lock first; nothing takes a slot lock while
/// holding a name lock, so the order is fixed and cannot deadlock.
pub async fn lock_names(
    locks: &PathLocks,
    index_keys: impl IntoIterator<Item = String>,
) -> Vec<OwnedMutexGuard<()>> {
    let mut keys: Vec<String> = index_keys.into_iter().map(|k| lock_key(&k)).collect();
    keys.sort();
    keys.dedup();
    let mut guards = Vec::with_capacity(keys.len());
    for key in &keys {
        guards.push(locks.guard(key).await);
    }
    guards
}

/// Every index key `record`'s agent names could be filed under: its domain,
/// and its DID's host for a legacy record that carries no domain (or was
/// tagged later).
pub fn index_keys(record: &DidRecord) -> Vec<String> {
    let mut domains = Vec::new();
    if !record.domain.is_empty() {
        domains.push(record.domain.clone());
    }
    if let Some(host) = record
        .did_id
        .as_deref()
        .and_then(|d| extract_did_host(d).ok())
        && !domains.contains(&host)
    {
        domains.push(host);
    }
    let mut keys = Vec::new();
    for domain in &domains {
        for entry in &record.agent_names {
            keys.push(agent_name_key(domain, &entry.name));
        }
    }
    keys
}

/// The subset of [`index_keys`] whose entry points at `record`'s slot.
/// Removing only these never touches another slot's entry.
pub async fn owned_keys(ks: &KeyspaceHandle, record: &DidRecord) -> Result<Vec<String>, AppError> {
    let mut owned = Vec::new();
    for key in index_keys(record) {
        if ks
            .get_raw(key.clone())
            .await?
            .is_some_and(|bytes| bytes == record.mnemonic.as_bytes())
        {
            owned.push(key);
        }
    }
    Ok(owned)
}

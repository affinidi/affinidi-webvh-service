//! Derived rows kept beside each `DidRecord` so the control plane never
//! scans every record to answer a per-owner or per-domain question.
//!
//! - **`usage:{owner}`** — `{count, bytes}`: how many slots `owner` holds and
//!   the sum of their `content_size`. The quota checks read it instead of
//!   walking the owner's slots (`did_ops::owner_usage`).
//! - **`domain:{domain}:{mnemonic}`** — value the mnemonic: the slots hosted
//!   under a domain, in mnemonic order on a key-ordered store. `did/list`'s
//!   domain filter and the per-domain charts walk it instead of every record.
//!
//! Both are staged **in the same batch as the record write** by
//! [`stage_record_change`], given the record before and after the write, so
//! they cannot drift from the records on any single write. Every control-plane
//! path that adds, removes, re-owns, resizes or re-domains a record calls it.
//! The `m03_index_did_records` migration builds both from the records once, for
//! stores written before they existed.
//!
//! The `domain:` and `owner:` prefixes share a hazard: a domain (or DID) may
//! be a string prefix of another (`a.example` and `a.example:8443`), so a
//! prefix walk can return a neighbour's rows. A row is the domain's only when
//! its key is exactly [`domain_index_key`] of the domain and the row's value
//! ([`index_row_mnemonic`] checks it).
//!
//! Counters are read-modify-write. [`stage_record_change`] takes a per-owner
//! lock from the caller's [`PathLocks`] and returns its guard, which the caller
//! holds until the batch commits; it is taken last, after every other lock
//! the write holds, and nothing is locked while it is held, so it adds no lock
//! ordering. The lock is per process, like every other `PathLocks` guard:
//! control-plane replicas writing one owner's slots at once can lose an update
//! to the counter, exactly as they can race the quota check itself.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::AppError;
use super::path_locks::{PathGuard, PathLocks};
use super::store::{KeyspaceHandle, WriteBatch};
use crate::did_ops::DidRecord;

/// Key prefix of the per-domain slot index.
pub const DOMAIN_INDEX_PREFIX: &str = "domain:";
/// Key prefix of the per-owner usage counters.
pub const USAGE_PREFIX: &str = "usage:";

/// The per-domain index row of `mnemonic` under `domain`.
pub fn domain_index_key(domain: &str, mnemonic: &str) -> String {
    format!(
        "{DOMAIN_INDEX_PREFIX}{}:{mnemonic}",
        domain.to_ascii_lowercase()
    )
}

/// The prefix every row of `domain`'s index starts with (and, see the
/// module note, possibly a longer domain's rows too).
pub fn domain_index_prefix(domain: &str) -> String {
    format!("{DOMAIN_INDEX_PREFIX}{}:", domain.to_ascii_lowercase())
}

/// The mnemonic an index row names, when the row belongs to the index
/// `key_of(mnemonic)` builds — `None` for a neighbour's row that only
/// shares the prefix, or a malformed one.
pub fn index_row_mnemonic(
    key: &[u8],
    value: &[u8],
    key_of: impl Fn(&str) -> String,
) -> Option<String> {
    let mnemonic = std::str::from_utf8(value).ok()?;
    (key_of(mnemonic).as_bytes() == key).then(|| mnemonic.to_string())
}

/// The usage counter row of `owner`.
pub fn usage_key(owner: &str) -> String {
    format!("{USAGE_PREFIX}{owner}")
}

/// The domain a record is hosted under, lowercased: its `domain`, or for a
/// record written before that was stored, the host of its DID. `None` for
/// an empty slot of an un-domained install.
pub fn record_domain(record: &DidRecord) -> Option<String> {
    let domain = if record.domain.is_empty() {
        crate::server::domain::extract_did_host(record.did_id.as_deref()?).ok()?
    } else {
        record.domain.clone()
    };
    (!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

/// What one owner's slots add up to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerUsage {
    /// Slots the owner holds.
    pub count: u64,
    /// The sum of their `content_size`.
    pub bytes: u64,
}

/// `owner`'s usage counter; zero when it holds nothing.
pub async fn owner_usage(ks: &KeyspaceHandle, owner: &str) -> Result<OwnerUsage, AppError> {
    Ok(ks.get(usage_key(owner)).await?.unwrap_or_default())
}

/// The lock serialising writes to `owner`'s usage counter.
fn usage_lock_key(owner: &str) -> String {
    format!("::usage:{owner}")
}

/// Stage, into `batch`, the index and counter changes that writing `new`
/// over `old` (either absent: a create or a delete) makes, for the same slot.
///
/// Call it after every other lock the write takes, immediately before the
/// commit, and hold the returned guards until the commit returns (see the
/// module note). `locks` is `None` only where nothing else writes the store
/// (an offline CLI command, a migration at boot).
pub async fn stage_record_change(
    batch: &mut WriteBatch,
    ks: &KeyspaceHandle,
    locks: Option<&PathLocks>,
    old: Option<&DidRecord>,
    new: Option<&DidRecord>,
) -> Result<Vec<PathGuard>, AppError> {
    // The domain index: drop the old row when it moves, write the new one
    // (rewriting an unchanged row heals one a crash lost).
    let old_row = old.and_then(|r| Some(domain_index_key(&record_domain(r)?, &r.mnemonic)));
    let new_row = new.and_then(|r| Some(domain_index_key(&record_domain(r)?, &r.mnemonic)));
    if let Some(old_row) = old_row.as_ref()
        && new_row.as_ref() != Some(old_row)
    {
        batch.remove(ks, old_row.clone());
    }
    if let (Some(row), Some(record)) = (new_row, new) {
        batch.insert_raw(ks, row, record.mnemonic.as_bytes().to_vec());
    }

    // The usage counters: net change per owner.
    let mut deltas: BTreeMap<&str, (i64, i128)> = BTreeMap::new();
    if let Some(r) = old {
        let d = deltas.entry(r.owner.as_str()).or_default();
        d.0 -= 1;
        d.1 -= i128::from(r.content_size);
    }
    if let Some(r) = new {
        let d = deltas.entry(r.owner.as_str()).or_default();
        d.0 += 1;
        d.1 += i128::from(r.content_size);
    }
    deltas.retain(|_, d| *d != (0, 0));

    // Locks in owner order (the map's), so two writes moving a slot between
    // the same two owners take them in the same order.
    let mut guards = Vec::with_capacity(deltas.len());
    if let Some(locks) = locks {
        for owner in deltas.keys() {
            guards.push(locks.guard(&usage_lock_key(owner)).await);
        }
    }
    for (owner, (count, bytes)) in deltas {
        let current = owner_usage(ks, owner).await?;
        let next = OwnerUsage {
            count: apply(current.count, i128::from(count)),
            bytes: apply(current.bytes, bytes),
        };
        if next == OwnerUsage::default() {
            batch.remove(ks, usage_key(owner));
        } else {
            batch.insert(ks, usage_key(owner), &next)?;
        }
    }
    Ok(guards)
}

/// `value + delta`, held within `u64`.
fn apply(value: u64, delta: i128) -> u64 {
    (i128::from(value) + delta).clamp(0, i128::from(u64::MAX)) as u64
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::store::{KS_DIDS, Store};

    async fn store() -> (Store, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::server::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        })
        .await
        .unwrap();
        let ks = store.keyspace(KS_DIDS).unwrap();
        (store, ks, dir)
    }

    fn record(owner: &str, mnemonic: &str, domain: &str, size: u64) -> DidRecord {
        DidRecord {
            owner: owner.into(),
            mnemonic: mnemonic.into(),
            created_at: 0,
            updated_at: 0,
            version_count: 1,
            did_id: None,
            content_size: size,
            disabled: false,
            disabled_by_admin: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: domain.into(),
            services: None,
            agent_names: Vec::new(),
        }
    }

    async fn write(
        store: &Store,
        ks: &KeyspaceHandle,
        locks: &PathLocks,
        old: Option<&DidRecord>,
        new: Option<&DidRecord>,
    ) {
        let mut batch = store.batch();
        let _g = stage_record_change(&mut batch, ks, Some(locks), old, new)
            .await
            .unwrap();
        batch.commit().await.unwrap();
    }

    #[tokio::test]
    async fn counters_follow_create_resize_transfer_and_delete() {
        let (store, ks, _dir) = store().await;
        let locks = PathLocks::new();
        let a = record("did:example:a", "one", "a.example", 10);
        write(&store, &ks, &locks, None, Some(&a)).await;
        let a2 = record("did:example:a", "two", "a.example", 5);
        write(&store, &ks, &locks, None, Some(&a2)).await;
        assert_eq!(
            owner_usage(&ks, "did:example:a").await.unwrap(),
            OwnerUsage {
                count: 2,
                bytes: 15
            }
        );

        // Resize.
        let bigger = record("did:example:a", "one", "a.example", 100);
        write(&store, &ks, &locks, Some(&a), Some(&bigger)).await;
        assert_eq!(
            owner_usage(&ks, "did:example:a").await.unwrap(),
            OwnerUsage {
                count: 2,
                bytes: 105
            }
        );

        // Transfer: one slot moves from a to b.
        let moved = record("did:example:b", "one", "a.example", 100);
        write(&store, &ks, &locks, Some(&bigger), Some(&moved)).await;
        assert_eq!(
            owner_usage(&ks, "did:example:a").await.unwrap(),
            OwnerUsage { count: 1, bytes: 5 }
        );
        assert_eq!(
            owner_usage(&ks, "did:example:b").await.unwrap(),
            OwnerUsage {
                count: 1,
                bytes: 100
            }
        );

        // Delete: the emptied counter row goes.
        write(&store, &ks, &locks, Some(&a2), None).await;
        assert_eq!(
            owner_usage(&ks, "did:example:a").await.unwrap(),
            OwnerUsage::default()
        );
        assert!(
            ks.get_raw(usage_key("did:example:a"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_domain_index_follows_the_record_and_rejects_neighbours() {
        let (store, ks, _dir) = store().await;
        let locks = PathLocks::new();
        let r = record("o", "alice", "A.example", 1);
        write(&store, &ks, &locks, None, Some(&r)).await;
        // A neighbour whose domain the first is a prefix of.
        let n = record("o", "bob", "a.example:8443", 1);
        write(&store, &ks, &locks, None, Some(&n)).await;

        let rows = ks
            .prefix_iter_raw(domain_index_prefix("a.example"))
            .await
            .unwrap();
        let mine: Vec<String> = rows
            .iter()
            .filter_map(|(k, v)| index_row_mnemonic(k, v, |m| domain_index_key("a.example", m)))
            .collect();
        assert_eq!(mine, ["alice"], "the :8443 neighbour is not this domain's");

        // Moving the slot to another domain moves its row.
        let moved = record("o", "alice", "b.example", 1);
        write(&store, &ks, &locks, Some(&r), Some(&moved)).await;
        assert!(
            ks.get_raw(domain_index_key("a.example", "alice"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ks.get_raw(domain_index_key("b.example", "alice"))
                .await
                .unwrap()
                .is_some()
        );
        // Deleting it removes it.
        write(&store, &ks, &locks, Some(&moved), None).await;
        assert!(
            ks.get_raw(domain_index_key("b.example", "alice"))
                .await
                .unwrap()
                .is_none()
        );
    }
}

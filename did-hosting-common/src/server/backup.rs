//! Shared backup / restore machinery.
//!
//! Each binary declares what it owns — which stores, which keyspaces in each,
//! and the configuration to carry — and this module does the dumping and the
//! bulk writing. Keyspace data travels as base64url (no padding) key/value
//! pairs, so any byte string round-trips.
//!
//! Two shapes use it:
//!
//! - the edge's (`did-hosting-server backup`), a fixed set of named
//!   keyspaces in one store, kept for compatibility with existing backups;
//! - [`MultiStoreBackup`], used by the daemon: any number of named stores,
//!   each a map of keyspace name → entries, plus the configuration file
//!   verbatim (never re-serialised through a binary's config type, which
//!   would drop whatever that type does not model).

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

use crate::server::error::AppError;
use crate::server::store::{KeyspaceHandle, RawKvPair, Store};

/// Entries written per restore batch.
pub const BATCH_SIZE: usize = 1000;

/// One key/value pair, base64url-encoded (no padding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvEntry {
    pub key: String,
    pub value: String,
}

/// Encode raw pairs for a backup file.
pub fn encode_pairs(pairs: Vec<RawKvPair>) -> Vec<KvEntry> {
    pairs
        .into_iter()
        .map(|(k, v)| KvEntry {
            key: BASE64.encode(&k),
            value: BASE64.encode(&v),
        })
        .collect()
}

/// Decode one backup entry.
pub fn decode_entry(entry: &KvEntry) -> Result<RawKvPair, AppError> {
    let key = BASE64
        .decode(&entry.key)
        .map_err(|e| AppError::Config(format!("invalid base64url key: {e}")))?;
    let value = BASE64
        .decode(&entry.value)
        .map_err(|e| AppError::Config(format!("invalid base64url value: {e}")))?;
    Ok((key, value))
}

/// Write `pairs` into `ks` in batches of [`BATCH_SIZE`].
///
/// A restore is a bulk load that is safe to re-run, and a chunk of 1,000
/// entries can be over one DynamoDB transaction, so each chunk need not land
/// atomically.
pub async fn write_pairs(
    store: &Store,
    ks: &KeyspaceHandle,
    pairs: Vec<RawKvPair>,
) -> Result<usize, AppError> {
    let count = pairs.len();
    for chunk in pairs.chunks(BATCH_SIZE) {
        let mut batch = store.batch();
        for (key, value) in chunk {
            batch.insert_raw(ks, key.clone(), value.clone());
        }
        batch.commit_in_parts().await?;
    }
    Ok(count)
}

/// Decode `entries` and write them into `ks`.
pub async fn restore_keyspace(
    store: &Store,
    ks: &KeyspaceHandle,
    entries: &[KvEntry],
) -> Result<usize, AppError> {
    let pairs = entries
        .iter()
        .map(decode_entry)
        .collect::<Result<Vec<_>, _>>()?;
    write_pairs(store, ks, pairs).await
}

/// One store's keyspaces, by name.
pub type StoreDump = BTreeMap<String, Vec<KvEntry>>;

/// Dump every keyspace in `keyspaces` from `store`.
pub async fn dump_store(store: &Store, keyspaces: &[&str]) -> Result<StoreDump, AppError> {
    let mut dump = StoreDump::new();
    for name in keyspaces {
        let ks = store.keyspace(name)?;
        dump.insert((*name).to_string(), encode_pairs(ks.iter_all().await?));
    }
    Ok(dump)
}

/// A backup of several named stores and the configuration that names them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiStoreBackup {
    /// Which binary wrote it (e.g. `did-hosting-daemon`); a restore refuses
    /// another binary's backup.
    pub format: String,
    /// The format version.
    pub version: u32,
    pub created_at: String,
    /// The writing binary's version.
    pub binary_version: String,
    /// The configuration file, verbatim.
    pub config: String,
    /// Store name → its keyspaces.
    pub stores: BTreeMap<String, StoreDump>,
}

impl MultiStoreBackup {
    /// Total entries across every store.
    pub fn total_entries(&self) -> usize {
        self.stores
            .values()
            .flat_map(|s| s.values())
            .map(Vec::len)
            .sum()
    }

    /// Check the backup's stores and keyspaces against what the binary
    /// declares (`declared`: store name → the keyspaces it backs up). A store
    /// or keyspace the binary does not know is refused rather than skipped:
    /// data a restore silently drops is data lost.
    pub fn check_declared(&self, declared: &[(&str, &[&str])]) -> Result<(), AppError> {
        for (store, keyspaces) in &self.stores {
            let Some((_, known)) = declared.iter().find(|(name, _)| name == store) else {
                return Err(AppError::Config(format!(
                    "the backup holds a store `{store}` this binary does not have"
                )));
            };
            if let Some(unknown) = keyspaces.keys().find(|k| !known.contains(&k.as_str())) {
                return Err(AppError::Config(format!(
                    "the backup's `{store}` store holds a keyspace `{unknown}` this binary does \
                     not restore"
                )));
            }
        }
        Ok(())
    }
}

/// Write every keyspace of `dump` into `store`, except those in `skip` (which
/// the caller restores itself). Returns the entries written per keyspace.
pub async fn restore_store(
    store: &Store,
    dump: &StoreDump,
    skip: &[&str],
) -> Result<BTreeMap<String, usize>, AppError> {
    let mut counts = BTreeMap::new();
    for (name, entries) in dump {
        if skip.contains(&name.as_str()) {
            continue;
        }
        let ks = store.keyspace(name)?;
        counts.insert(name.clone(), restore_keyspace(store, &ks, entries).await?);
    }
    Ok(counts)
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::config::StoreConfig;

    async fn open(dir: &std::path::Path) -> Store {
        Store::open(&StoreConfig {
            data_dir: dir.to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .unwrap()
    }

    #[test]
    fn entries_round_trip_arbitrary_bytes() {
        let pairs = vec![(vec![0u8, 255, b'!'], vec![b'-', b'_', 1])];
        let encoded = encode_pairs(pairs.clone());
        assert!(!encoded[0].key.contains('='));
        assert_eq!(decode_entry(&encoded[0]).unwrap(), pairs[0]);
    }

    /// A dump restored into an empty store reproduces every keyspace.
    #[tokio::test]
    async fn a_dumped_store_restores_into_an_empty_one() {
        let a = tempfile::tempdir().unwrap();
        let source = open(a.path()).await;
        source
            .keyspace("one")
            .unwrap()
            .insert_raw("k1", b"v1".to_vec())
            .await
            .unwrap();
        source
            .keyspace("two")
            .unwrap()
            .insert_raw("k2", b"v2".to_vec())
            .await
            .unwrap();
        let dump = dump_store(&source, &["one", "two"]).await.unwrap();

        let b = tempfile::tempdir().unwrap();
        let target = open(b.path()).await;
        let counts = restore_store(&target, &dump, &["two"]).await.unwrap();
        assert_eq!(counts.get("one"), Some(&1));
        assert!(!counts.contains_key("two"), "skipped");
        assert_eq!(
            target.keyspace("one").unwrap().get_raw("k1").await.unwrap(),
            Some(b"v1".to_vec())
        );
        assert!(
            target
                .keyspace("two")
                .unwrap()
                .get_raw("k2")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn an_undeclared_store_or_keyspace_is_refused() {
        let mut backup = MultiStoreBackup {
            format: "x".into(),
            version: 1,
            created_at: "now".into(),
            binary_version: "0".into(),
            config: String::new(),
            stores: BTreeMap::new(),
        };
        backup
            .stores
            .insert("main".into(), StoreDump::from([("a".into(), vec![])]));
        assert!(backup.check_declared(&[("main", &["a"])]).is_ok());
        assert!(backup.check_declared(&[("main", &["b"])]).is_err());
        assert!(backup.check_declared(&[("other", &["a"])]).is_err());
    }
}

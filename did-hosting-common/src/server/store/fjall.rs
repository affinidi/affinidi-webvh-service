use std::sync::Arc;

use fjall::{KeyspaceCreateOptions, PersistMode};
use tokio::sync::Mutex;
use tracing::info;

use crate::server::config::{FjallTuning, StoreConfig, human_bytes};
use crate::server::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

// ---------------------------------------------------------------------------
// FjallBackend
// ---------------------------------------------------------------------------

pub struct FjallBackend {
    db: fjall::Database,
}

impl FjallBackend {
    /// [`super::Store::open`] and [`super::Store::open_with`] for the fjall
    /// backend — both funnel here via [`super::create_backend`], the former
    /// with `tuning` at [`FjallTuning::default()`] (fjall's own memory
    /// tuning left at its defaults).
    pub fn open_with(
        config: &StoreConfig,
        tuning: &FjallTuning,
    ) -> Result<Box<dyn StorageBackend>, AppError> {
        Ok(Box::new(Self::open_local(config, tuning)?))
    }

    /// Same logic as [`Self::open_with`], but returns the concrete
    /// `FjallBackend` rather than a boxed `dyn StorageBackend` — the trait
    /// object erases the underlying `fjall::Database`, which tests need
    /// direct access to (e.g. `cache_capacity()`) to assert a configured
    /// value actually took effect, not just that opening didn't panic.
    fn open_local(config: &StoreConfig, tuning: &FjallTuning) -> Result<Self, AppError> {
        // Defense in depth: re-checked here regardless of how `tuning` was
        // built (the config-file deserializer and `apply_fjall_env_overrides`
        // both validate already, but a directly-constructed `FjallTuning` —
        // a test fixture, a future caller — must never reach the asserting
        // `Builder` calls below with a value fjall itself would panic on.
        tuning.validate().map_err(AppError::Config)?;

        std::fs::create_dir_all(&config.data_dir).map_err(AppError::Io)?;

        let mut builder = fjall::Database::builder(&config.data_dir);
        if let Some(bytes) = tuning.block_cache {
            builder = builder.cache_size(bytes);
        }
        if let Some(bytes) = tuning.max_journal {
            builder = builder.max_journaling_size(bytes);
        }
        if let Some(bytes) = tuning.write_buffer {
            // `Builder::max_write_buffer_size` is `#[doc(hidden)]` and
            // `#[deprecated = "todo"]` upstream (fjall 3.1) — it is still
            // the only way to cap the total memtable budget across every
            // keyspace a process opens (see `KeyspaceCreateOptions::
            // max_memtable_size`'s own doc, which points back at it), and
            // it remains fully wired (`WriteBufferManager`, checked on
            // every insert/remove). Re-check this note against fjall's
            // changelog when bumping past 3.1 in case a replacement lands.
            #[allow(deprecated)]
            {
                builder = builder.max_write_buffer_size(Some(bytes));
            }
        }

        info!(
            path = %config.data_dir.display(),
            block_cache = %tuning.block_cache.map(human_bytes).unwrap_or_else(|| "default".to_string()),
            write_buffer = %tuning.write_buffer.map(human_bytes).unwrap_or_else(|| "default".to_string()),
            max_journal = %tuning.max_journal.map(human_bytes).unwrap_or_else(|| "default".to_string()),
            "opening fjall store"
        );

        let db = builder.open().map_err(|e| AppError::Store(e.to_string()))?;

        Ok(Self { db })
    }
}

impl StorageBackend for FjallBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        let ks = self
            .db
            .keyspace(name, KeyspaceCreateOptions::default)
            .map_err(|e| AppError::Store(e.to_string()))?;
        Ok((
            name.to_string(),
            Arc::new(FjallKeyspace {
                keyspace: ks,
                take_lock: Mutex::new(()),
            }),
        ))
    }

    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(FjallBatch {
            db: self.db.clone(),
            batch: self.db.batch(),
        })
    }

    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>> {
        let db = self.db.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || db.persist(PersistMode::SyncAll))
                .await
                .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
                .map_err(|e| AppError::Store(e.to_string()))?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// FjallKeyspace
// ---------------------------------------------------------------------------

struct FjallKeyspace {
    keyspace: fjall::Keyspace,
    /// Per-keyspace mutex held across the get-then-remove of
    /// `take_raw_atomic`. fjall is a single-process embedded store so
    /// process-local mutual exclusion is sufficient — no cross-replica
    /// coordination is required.
    take_lock: Mutex<()>,
}

impl KeyspaceOps for FjallKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        let ks = self.keyspace.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || ks.insert(key, value))
                .await
                .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
                .map_err(|e| AppError::Store(e.to_string()))?;
            Ok(())
        })
    }

    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        let ks = self.keyspace.clone();
        Box::pin(async move {
            let result = tokio::task::spawn_blocking(move || ks.get(key))
                .await
                .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
                .map_err(|e| AppError::Store(e.to_string()))?;
            Ok(result.map(|v| v.to_vec()))
        })
    }

    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        let ks = self.keyspace.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || ks.remove(key))
                .await
                .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
                .map_err(|e| AppError::Store(e.to_string()))?;
            Ok(())
        })
    }

    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        let ks = self.keyspace.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || ks.contains_key(key))
                .await
                .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
                .map_err(|e| AppError::Store(e.to_string()))
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        let ks = self.keyspace.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<Vec<RawKvPair>, AppError> {
                let mut results = Vec::new();
                for guard in ks.prefix(&prefix) {
                    let (key, value) = guard
                        .into_inner()
                        .map_err(|e| AppError::Store(e.to_string()))?;
                    results.push((key.to_vec(), value.to_vec()));
                }
                Ok(results)
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }

    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            // Per-keyspace mutex serialises the get-then-remove so two
            // concurrent callers cannot both observe the value before
            // one of them removes it. fjall is single-process, so
            // process-local mutual exclusion is the correct primitive.
            let _guard = self.take_lock.lock().await;
            let ks = self.keyspace.clone();
            let key2 = key.clone();
            let value = tokio::task::spawn_blocking(move || ks.get(key2))
                .await
                .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
                .map_err(|e| AppError::Store(e.to_string()))?
                .map(|v| v.to_vec());
            if value.is_some() {
                let ks = self.keyspace.clone();
                tokio::task::spawn_blocking(move || ks.remove(key))
                    .await
                    .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
                    .map_err(|e| AppError::Store(e.to_string()))?;
            }
            Ok(value)
        })
    }
}

// ---------------------------------------------------------------------------
// FjallBatch — uses native OwnedWriteBatch directly
// ---------------------------------------------------------------------------

struct FjallBatch {
    db: fjall::Database,
    batch: fjall::OwnedWriteBatch,
}

impl BatchOps for FjallBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        match self.db.keyspace(keyspace, KeyspaceCreateOptions::default) {
            Ok(ks) => self.batch.insert(&ks, key, value),
            Err(e) => tracing::error!(keyspace, error = %e, "batch insert: keyspace lookup failed"),
        }
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        match self.db.keyspace(keyspace, KeyspaceCreateOptions::default) {
            Ok(ks) => self.batch.remove(&ks, key),
            Err(e) => tracing::error!(keyspace, error = %e, "batch remove: keyspace lookup failed"),
        }
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let batch = self.batch;
            tokio::task::spawn_blocking(move || {
                batch.commit().map_err(|e| AppError::Store(e.to_string()))
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::FjallBackend;
    use crate::server::config::{FjallTuning, MIN_MAX_JOURNAL_BYTES, MIN_WRITE_BUFFER_BYTES};
    use std::path::PathBuf;

    async fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let store = Store::open(&config).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn insert_and_get_roundtrip() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace("test").unwrap();
        ks.insert("key1", &"hello").await.unwrap();
        let val: Option<String> = ks.get("key1").await.unwrap();
        assert_eq!(val, Some("hello".to_string()));
    }

    /// Two concurrent `take_raw` calls on the same key must observe exactly
    /// one `Some(_)` and one `None`. This is the contract refresh-token
    /// rotation depends on.
    #[tokio::test]
    async fn take_raw_atomic_serialises_concurrent_claims() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace("test").unwrap();
        ks.insert_raw(b"refresh:abc".to_vec(), b"session-X".to_vec())
            .await
            .unwrap();

        let ks_a = ks.clone();
        let ks_b = ks.clone();
        let (a, b) = tokio::join!(
            tokio::spawn(async move { ks_a.take_raw(b"refresh:abc".to_vec()).await.unwrap() }),
            tokio::spawn(async move { ks_b.take_raw(b"refresh:abc".to_vec()).await.unwrap() }),
        );
        let a = a.unwrap();
        let b = b.unwrap();

        // Exactly one winner: one observed Some, the other None.
        let winners = [a.is_some(), b.is_some()].iter().filter(|x| **x).count();
        assert_eq!(winners, 1, "exactly one concurrent take_raw must win");

        // Key is gone from the store.
        assert!(ks.get_raw(b"refresh:abc".to_vec()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace("test").unwrap();
        let val: Option<String> = ks.get("nonexistent").await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn remove_deletes_key() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace("test").unwrap();
        ks.insert("key1", &"hello").await.unwrap();
        ks.remove("key1").await.unwrap();
        let val: Option<String> = ks.get("key1").await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn contains_key_true_false() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace("test").unwrap();
        assert!(!ks.contains_key("key1").await.unwrap());
        ks.insert("key1", &"hello").await.unwrap();
        assert!(ks.contains_key("key1").await.unwrap());
    }

    #[tokio::test]
    async fn insert_raw_and_get_raw_roundtrip() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace("test").unwrap();
        ks.insert_raw("raw1", b"raw-value".to_vec()).await.unwrap();
        let val = ks.get_raw("raw1").await.unwrap();
        assert_eq!(val, Some(b"raw-value".to_vec()));
    }

    #[tokio::test]
    async fn prefix_iter_raw_filters_correctly() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace("test").unwrap();
        ks.insert_raw("prefix:a", b"1".to_vec()).await.unwrap();
        ks.insert_raw("prefix:b", b"2".to_vec()).await.unwrap();
        ks.insert_raw("other:c", b"3".to_vec()).await.unwrap();
        let results = ks.prefix_iter_raw("prefix:").await.unwrap();
        assert_eq!(results.len(), 2);
        let keys: Vec<String> = results
            .iter()
            .map(|(k, _)| String::from_utf8(k.clone()).unwrap())
            .collect();
        assert!(keys.contains(&"prefix:a".to_string()));
        assert!(keys.contains(&"prefix:b".to_string()));
    }

    // =======================================================================
    // Fjall memory settings (`FjallTuning` / STORAGE_FJALL_*)
    // =======================================================================

    /// `Store::open` — every pre-existing call site — must behave exactly
    /// as it did before `open_with` existed: fjall's own default cache
    /// capacity, no builder method called for write buffer or journal.
    /// `open_local` with `FjallTuning::default()` is exactly what
    /// `Store::open` reaches, via `Store::open_with` and `create_backend`.
    #[test]
    fn open_leaves_fjalls_own_default_cache_capacity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let backend = FjallBackend::open_local(&config, &FjallTuning::default()).expect("open");
        // fjall's own built-in default (see `fjall::db_config::Config::new`).
        assert_eq!(backend.db.cache_capacity(), 32 * 1024 * 1024);
    }

    /// `open_with` given `FjallTuning::default()` is identical to `open` —
    /// the shape [`Store::open`] is defined in terms of.
    #[test]
    fn open_with_default_tuning_matches_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let backend = FjallBackend::open_local(&config, &FjallTuning::default())
            .expect("open_with default tuning");
        assert_eq!(backend.db.cache_capacity(), 32 * 1024 * 1024);
    }

    /// A configured block cache reaches fjall's `Database` unchanged — the
    /// one setting fjall exposes a public getter for, so this is a
    /// concrete, not just "it didn't panic", check that the value actually
    /// took effect. `write_buffer` and `max_journal` are wired through the
    /// identical `if let Some(bytes) = ... { builder = builder.method(bytes) }`
    /// shape in `open_local`, and are exercised below by the
    /// success/refusal boundary tests instead, since fjall does not expose
    /// a getter for either configured maximum.
    #[test]
    fn configured_tuning_opens_and_the_block_cache_takes_effect() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let tuning = FjallTuning {
            block_cache: Some(8 * 1024 * 1024),
            write_buffer: Some(MIN_WRITE_BUFFER_BYTES),
            max_journal: Some(MIN_MAX_JOURNAL_BYTES),
        };
        let backend =
            FjallBackend::open_local(&config, &tuning).expect("open_with configured tuning");
        assert_eq!(backend.db.cache_capacity(), 8 * 1024 * 1024);
    }

    /// A `FjallTuning` built by hand (bypassing the deserializer and
    /// `apply_fjall_env_overrides`, both of which already validate) with a
    /// below-floor value is still refused at `open_with` — the
    /// `tuning.validate()` defense-in-depth check — naming the setting,
    /// not a fjall panic.
    #[test]
    fn open_with_refuses_a_below_floor_setting_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let tuning = FjallTuning {
            block_cache: None,
            write_buffer: None,
            max_journal: Some(1024), // far under the 64 MiB floor
        };
        let Err(err) = FjallBackend::open_with(&config, &tuning) else {
            panic!("a below-floor max_journal must be refused");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("fjall.max_journal"),
            "error must name the setting, got: {msg}"
        );
    }

    /// Zero is refused with the same clear naming, not silently ignored.
    #[test]
    fn open_with_refuses_a_zero_setting_naming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let tuning = FjallTuning {
            block_cache: Some(0),
            write_buffer: None,
            max_journal: None,
        };
        let Err(err) = FjallBackend::open_with(&config, &tuning) else {
            panic!("a zero block_cache must be refused");
        };
        let msg = err.to_string();
        assert!(msg.contains("fjall.block_cache"), "got: {msg}");
        assert!(msg.contains("zero"), "got: {msg}");
    }

    /// `Store::open_with` (the public, async wrapper every real startup path
    /// calls) reaches the same fjall database with the configured tuning.
    #[tokio::test]
    async fn store_open_with_applies_configured_tuning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        };
        let tuning = FjallTuning {
            block_cache: Some(16 * 1024 * 1024),
            write_buffer: None,
            max_journal: None,
        };
        // Only asserts the call succeeds and yields a usable store — the
        // block-cache-takes-effect assertion above already exercises the
        // same code path at the concrete-type level, where fjall's getter
        // is reachable.
        let store = Store::open_with(&config, &tuning)
            .await
            .expect("store opens with configured tuning");
        let ks = store.keyspace("test").unwrap();
        ks.insert("k", &"v").await.unwrap();
        let val: Option<String> = ks.get("k").await.unwrap();
        assert_eq!(val, Some("v".to_string()));
    }
}

use std::sync::Arc;

use fjall::{KeyspaceCreateOptions, PersistMode};
use tracing::info;

use crate::config::StoreConfig;
use crate::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

// ---------------------------------------------------------------------------
// FjallBackend
// ---------------------------------------------------------------------------

pub struct FjallBackend {
    db: fjall::Database,
}

impl FjallBackend {
    pub fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        std::fs::create_dir_all(&config.data_dir).map_err(AppError::Io)?;

        info!(path = %config.data_dir.display(), "opening fjall store");

        let db = fjall::Database::builder(&config.data_dir)
            .open()
            .map_err(|e| AppError::Store(e.to_string()))?;

        Ok(Box::new(Self { db }))
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
            Arc::new(FjallKeyspace { keyspace: ks }),
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
        // Resolve keyspace eagerly and add directly to the native batch.
        // keyspace() with default options is a no-op if the keyspace already exists.
        if let Ok(ks) = self
            .db
            .keyspace(keyspace, KeyspaceCreateOptions::default)
        {
            self.batch.insert(&ks, key, value);
        }
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        if let Ok(ks) = self
            .db
            .keyspace(keyspace, KeyspaceCreateOptions::default)
        {
            self.batch.remove(&ks, key);
        }
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let batch = self.batch;
            tokio::task::spawn_blocking(move || {
                batch
                    .commit()
                    .map_err(|e| AppError::Store(e.to_string()))
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
}

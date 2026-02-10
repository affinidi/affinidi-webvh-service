use crate::config::StoreConfig;
use crate::error::AppError;
use fjall::{KeyspaceCreateOptions, PersistMode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::info;

/// A key-value pair of raw bytes from a prefix scan.
pub type RawKvPair = (Vec<u8>, Vec<u8>);

#[derive(Clone)]
pub struct Store {
    db: fjall::Database,
}

#[derive(Clone)]
pub struct KeyspaceHandle {
    keyspace: fjall::Keyspace,
}

impl Store {
    pub fn open(config: &StoreConfig) -> Result<Self, AppError> {
        std::fs::create_dir_all(&config.data_dir).map_err(AppError::Io)?;

        info!(path = %config.data_dir.display(), "opening store");

        let db = fjall::Database::builder(&config.data_dir).open()?;

        Ok(Self { db })
    }

    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let keyspace = self.db.keyspace(name, KeyspaceCreateOptions::default)?;
        Ok(KeyspaceHandle { keyspace })
    }

    #[allow(dead_code)]
    pub async fn persist(&self) -> Result<(), AppError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.persist(PersistMode::SyncAll))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }
}

impl KeyspaceHandle {
    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let key = key.into();
        let bytes = serde_json::to_vec(value)?;
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.insert(key, bytes))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<V>, AppError> {
            match ks.get(key)? {
                Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.remove(key))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        let key = key.into();
        let value = value.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.insert(key, value))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(())
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        let result = tokio::task::spawn_blocking(move || ks.get(key))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))??;
        Ok(result.map(|v| v.to_vec()))
    }

    pub async fn contains_key(&self, key: impl Into<Vec<u8>>) -> Result<bool, AppError> {
        let key = key.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.contains_key(key))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
            .map_err(AppError::Store)
    }

    /// Iterate all key-value pairs whose key starts with `prefix`.
    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        let prefix = prefix.into();
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<RawKvPair>, AppError> {
            let mut results = Vec::new();
            for guard in ks.prefix(&prefix) {
                let (key, value) = guard.into_inner()?;
                results.push((key.to_vec(), value.to_vec()));
            }
            Ok(results)
        })
        .await
        .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
    }

    /// Returns the approximate number of items in the keyspace.
    #[allow(dead_code)]
    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        let ks = self.keyspace.clone();
        tokio::task::spawn_blocking(move || ks.approximate_len())
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = StoreConfig {
            data_dir: PathBuf::from(dir.path()),
        };
        let store = Store::open(&config).unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn insert_and_get_roundtrip() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert("key1", &"hello").await.unwrap();
        let val: Option<String> = ks.get("key1").await.unwrap();
        assert_eq!(val, Some("hello".to_string()));
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        let val: Option<String> = ks.get("nonexistent").await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn remove_deletes_key() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert("key1", &"hello").await.unwrap();
        ks.remove("key1").await.unwrap();
        let val: Option<String> = ks.get("key1").await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn contains_key_true_false() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        assert!(!ks.contains_key("key1").await.unwrap());
        ks.insert("key1", &"hello").await.unwrap();
        assert!(ks.contains_key("key1").await.unwrap());
    }

    #[tokio::test]
    async fn insert_raw_and_get_raw_roundtrip() {
        let (store, _dir) = temp_store();
        let ks = store.keyspace("test").unwrap();
        ks.insert_raw("raw1", b"raw-value".to_vec()).await.unwrap();
        let val = ks.get_raw("raw1").await.unwrap();
        assert_eq!(val, Some(b"raw-value".to_vec()));
    }

    #[tokio::test]
    async fn prefix_iter_raw_filters_correctly() {
        let (store, _dir) = temp_store();
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

#[cfg(feature = "store-cosmosdb")]
mod cosmosdb;
#[cfg(feature = "store-dynamodb")]
mod dynamodb;
#[cfg(feature = "store-firestore")]
mod firestore;
#[cfg(feature = "store-fjall")]
mod fjall;
#[cfg(feature = "store-redis")]
mod redis;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::StoreConfig;
use crate::error::AppError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A key-value pair of raw bytes from a prefix scan.
pub type RawKvPair = (Vec<u8>, Vec<u8>);

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Per-keyspace CRUD + prefix scan over raw bytes.
pub trait KeyspaceOps: Send + Sync {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>>;
    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>>;
    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>>;
    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>>;
    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>>;
}

/// Atomic multi-key write batch identified by keyspace name.
pub trait BatchOps: Send {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>);
    fn remove(&mut self, keyspace: &str, key: Vec<u8>);
    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>>;
}

/// Factory: create keyspaces, create batches, persist/flush.
pub trait StorageBackend: Send + Sync {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError>;
    fn batch(&self) -> Box<dyn BatchOps>;
    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>>;
}

// ---------------------------------------------------------------------------
// Public wrapper types (same API surface as before)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Store {
    inner: Arc<dyn StorageBackend>,
}

#[derive(Clone)]
pub struct KeyspaceHandle {
    pub(crate) name: String,
    inner: Arc<dyn KeyspaceOps>,
}

/// An atomic write batch that collects operations and commits them in a single call.
pub struct WriteBatch {
    inner: Box<dyn BatchOps>,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

impl Store {
    pub async fn open(config: &StoreConfig) -> Result<Self, AppError> {
        let backend = create_backend(config).await?;
        Ok(Self {
            inner: Arc::from(backend),
        })
    }

    pub fn keyspace(&self, name: &str) -> Result<KeyspaceHandle, AppError> {
        let (ks_name, ops) = self.inner.keyspace(name)?;
        Ok(KeyspaceHandle {
            name: ks_name,
            inner: ops,
        })
    }

    /// Create a new atomic write batch.
    pub fn batch(&self) -> WriteBatch {
        WriteBatch {
            inner: self.inner.batch(),
        }
    }

    #[allow(dead_code)]
    pub async fn persist(&self) -> Result<(), AppError> {
        self.inner.persist().await
    }
}

// ---------------------------------------------------------------------------
// WriteBatch
// ---------------------------------------------------------------------------

impl WriteBatch {
    /// Add a serializable insert to the batch.
    pub fn insert<V: Serialize>(
        &mut self,
        ks: &KeyspaceHandle,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let bytes = serde_json::to_vec(value)?;
        self.inner.insert_raw(&ks.name, key.into(), bytes);
        Ok(())
    }

    /// Add a raw-bytes insert to the batch.
    pub fn insert_raw(
        &mut self,
        ks: &KeyspaceHandle,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) {
        self.inner.insert_raw(&ks.name, key.into(), value.into());
    }

    /// Add a remove to the batch.
    pub fn remove(&mut self, ks: &KeyspaceHandle, key: impl Into<Vec<u8>>) {
        self.inner.remove(&ks.name, key.into());
    }

    /// Commit all batched operations atomically.
    pub async fn commit(self) -> Result<(), AppError> {
        self.inner.commit().await
    }
}

// ---------------------------------------------------------------------------
// KeyspaceHandle
// ---------------------------------------------------------------------------

impl KeyspaceHandle {
    pub async fn insert<V: Serialize>(
        &self,
        key: impl Into<Vec<u8>>,
        value: &V,
    ) -> Result<(), AppError> {
        let bytes = serde_json::to_vec(value)?;
        self.inner.insert_raw(key.into(), bytes).await
    }

    pub async fn get<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        match self.inner.get_raw(key.into()).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Atomically get and remove a key.
    /// Returns the deserialized value if the key existed, or `None`.
    pub async fn take<V: DeserializeOwned + Send + 'static>(
        &self,
        key: impl Into<Vec<u8>>,
    ) -> Result<Option<V>, AppError> {
        let key = key.into();
        match self.inner.get_raw(key.clone()).await? {
            Some(bytes) => {
                self.inner.remove(key).await?;
                Ok(Some(serde_json::from_slice(&bytes)?))
            }
            None => Ok(None),
        }
    }

    pub async fn remove(&self, key: impl Into<Vec<u8>>) -> Result<(), AppError> {
        self.inner.remove(key.into()).await
    }

    pub async fn insert_raw(
        &self,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<(), AppError> {
        self.inner.insert_raw(key.into(), value.into()).await
    }

    pub async fn get_raw(&self, key: impl Into<Vec<u8>>) -> Result<Option<Vec<u8>>, AppError> {
        self.inner.get_raw(key.into()).await
    }

    pub async fn contains_key(&self, key: impl Into<Vec<u8>>) -> Result<bool, AppError> {
        self.inner.contains_key(key.into()).await
    }

    /// Iterate all key-value pairs in the keyspace.
    pub async fn iter_all(&self) -> Result<Vec<RawKvPair>, AppError> {
        self.prefix_iter_raw(b"").await
    }

    /// Iterate all key-value pairs whose key starts with `prefix`.
    pub async fn prefix_iter_raw(
        &self,
        prefix: impl Into<Vec<u8>>,
    ) -> Result<Vec<RawKvPair>, AppError> {
        self.inner.prefix_iter_raw(prefix.into()).await
    }

    /// Returns the approximate number of items in the keyspace.
    #[allow(dead_code)]
    pub async fn approximate_len(&self) -> Result<usize, AppError> {
        Ok(self.prefix_iter_raw(b"").await?.len())
    }
}

// ---------------------------------------------------------------------------
// Backend factory
// ---------------------------------------------------------------------------

#[allow(unused_variables)]
async fn create_backend(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
    #[cfg(feature = "store-fjall")]
    {
        return fjall::FjallBackend::open(config);
    }

    #[cfg(feature = "store-redis")]
    {
        return redis::RedisBackend::open(config).await;
    }

    #[cfg(feature = "store-dynamodb")]
    {
        return dynamodb::DynamoDbBackend::open(config).await;
    }

    #[cfg(feature = "store-firestore")]
    {
        return firestore::FirestoreBackend::open(config).await;
    }

    #[cfg(feature = "store-cosmosdb")]
    {
        return cosmosdb::CosmosDbBackend::open(config).await;
    }

    // build.rs enforces exactly one feature, so this is unreachable
    #[allow(unreachable_code)]
    Err(AppError::Config(
        "no storage backend compiled — enable a store-* feature".into(),
    ))
}

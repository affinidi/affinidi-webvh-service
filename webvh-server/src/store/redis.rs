use std::sync::Arc;

use redis::AsyncCommands;
use tracing::info;

use crate::config::StoreConfig;
use crate::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

// ---------------------------------------------------------------------------
// RedisBackend
// ---------------------------------------------------------------------------

pub struct RedisBackend {
    conn: redis::aio::MultiplexedConnection,
}

impl RedisBackend {
    pub async fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        let url = config
            .redis_url
            .as_deref()
            .unwrap_or("redis://127.0.0.1:6379");

        info!(url, "opening redis store");

        let client = redis::Client::open(url)
            .map_err(|e| AppError::Store(format!("redis connect: {e}")))?;

        // Create a single multiplexed connection (internally pipelining)
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Store(format!("redis connect: {e}")))?;

        // Verify connectivity
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| AppError::Store(format!("redis ping: {e}")))?;

        Ok(Box::new(Self { conn }))
    }
}

impl StorageBackend for RedisBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        Ok((
            name.to_string(),
            Arc::new(RedisKeyspace {
                conn: self.conn.clone(),
                prefix: format!("{name}:"),
            }),
        ))
    }

    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(RedisBatch {
            conn: self.conn.clone(),
            ops: Vec::new(),
        })
    }

    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>> {
        // Redis is durable by default (RDB/AOF); no-op here.
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// RedisKeyspace
// ---------------------------------------------------------------------------

struct RedisKeyspace {
    conn: redis::aio::MultiplexedConnection,
    prefix: String,
}

impl RedisKeyspace {
    fn full_key(&self, key: &[u8]) -> Vec<u8> {
        let mut fk = self.prefix.as_bytes().to_vec();
        fk.extend_from_slice(key);
        fk
    }
}

impl KeyspaceOps for RedisKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            conn.set::<_, _, ()>(fk, value)
                .await
                .map_err(|e| AppError::Store(format!("redis SET: {e}")))?;
            Ok(())
        })
    }

    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            let result: Option<Vec<u8>> = conn
                .get(fk)
                .await
                .map_err(|e| AppError::Store(format!("redis GET: {e}")))?;
            Ok(result)
        })
    }

    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            conn.del::<_, ()>(fk)
                .await
                .map_err(|e| AppError::Store(format!("redis DEL: {e}")))?;
            Ok(())
        })
    }

    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            let exists: bool = conn
                .exists(fk)
                .await
                .map_err(|e| AppError::Store(format!("redis EXISTS: {e}")))?;
            Ok(exists)
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            let mut pattern = self.full_key(&prefix);
            pattern.extend_from_slice(b"*");

            let mut conn = self.conn.clone();

            // Use SCAN to collect matching keys
            let keys: Vec<Vec<u8>> = {
                let mut collected = Vec::new();
                let mut iter: redis::AsyncIter<Vec<u8>> = conn
                    .scan_match(&pattern)
                    .await
                    .map_err(|e| AppError::Store(format!("redis SCAN: {e}")))?;

                while let Some(key) = iter.next_item().await {
                    collected.push(key);
                }
                collected
            };
            // `iter` is dropped here, releasing the borrow on `conn`

            if keys.is_empty() {
                return Ok(Vec::new());
            }

            // MGET all matched keys
            let values: Vec<Option<Vec<u8>>> = conn
                .mget(&keys)
                .await
                .map_err(|e| AppError::Store(format!("redis MGET: {e}")))?;

            let prefix_len = self.prefix.len();
            let results = keys
                .into_iter()
                .zip(values)
                .filter_map(|(k, v)| {
                    v.map(|val| {
                        // Strip the keyspace prefix to return the raw key
                        let raw_key = k[prefix_len..].to_vec();
                        (raw_key, val)
                    })
                })
                .collect();

            Ok(results)
        })
    }
}

// ---------------------------------------------------------------------------
// RedisBatch
// ---------------------------------------------------------------------------

enum RedisBatchOp {
    Insert {
        full_key: Vec<u8>,
        value: Vec<u8>,
    },
    Remove {
        full_key: Vec<u8>,
    },
}

struct RedisBatch {
    conn: redis::aio::MultiplexedConnection,
    ops: Vec<RedisBatchOp>,
}

impl BatchOps for RedisBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        let mut full_key = format!("{keyspace}:").into_bytes();
        full_key.extend_from_slice(&key);
        self.ops.push(RedisBatchOp::Insert { full_key, value });
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        let mut full_key = format!("{keyspace}:").into_bytes();
        full_key.extend_from_slice(&key);
        self.ops.push(RedisBatchOp::Remove { full_key });
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let mut conn = self.conn.clone();

            let mut pipe = redis::pipe();
            pipe.atomic(); // MULTI/EXEC

            for op in &self.ops {
                match op {
                    RedisBatchOp::Insert { full_key, value } => {
                        pipe.set(full_key.as_slice(), value.as_slice());
                    }
                    RedisBatchOp::Remove { full_key } => {
                        pipe.del(full_key.as_slice());
                    }
                }
            }

            pipe.query_async::<()>(&mut conn)
                .await
                .map_err(|e| AppError::Store(format!("redis pipeline: {e}")))?;

            Ok(())
        })
    }
}

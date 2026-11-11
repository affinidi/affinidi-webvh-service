use std::sync::Arc;

use redis::AsyncCommands;
use tracing::info;

use crate::server::config::StoreConfig;
use crate::server::error::AppError;

use super::{BatchOps, BoxFuture, KeyspaceOps, RawKvPair, StorageBackend};

pub struct RedisBackend {
    conn: redis::aio::MultiplexedConnection,
}

impl RedisBackend {
    pub async fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        let url = config
            .redis_url
            .as_deref()
            .unwrap_or("redis://127.0.0.1:6379");

        info!(url = %redacted_url(url), "opening redis store");

        let client =
            redis::Client::open(url).map_err(|e| AppError::Store(format!("redis connect: {e}")))?;

        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::Store(format!("redis connect: {e}")))?;

        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| AppError::Store(format!("redis ping: {e}")))?;

        Ok(Box::new(Self { conn }))
    }
}

/// `url` with any username, password and query removed, for logging.
/// `StoreConfig`'s `Debug` redacts `redis_url` for the same reason: a
/// connection URL can carry credentials (`redis://:password@host`,
/// `rediss://user:pass@host`, or `redis+unix:///path?pass=...`).
fn redacted_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let had_credentials = !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some();
            // Both setters fail only for a URL that cannot carry credentials,
            // which then has none to remove.
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            let mut shown = parsed.to_string();
            if had_credentials {
                shown.push_str(" (credentials redacted)");
            }
            shown
        }
        // Unparseable: whatever it holds is not safe to echo.
        Err(_) => "<unparseable redis url>".to_string(),
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
        Box::pin(async { Ok(()) })
    }
}

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

    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            // Redis 6.2+ provides GETDEL: atomic get-and-remove in a single
            // command, returning the previous value (or nil if absent).
            // Cross-replica safe — exactly one concurrent caller observes
            // a non-nil result for any given key.
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            let result: Option<Vec<u8>> = redis::cmd("GETDEL")
                .arg(fk)
                .query_async(&mut conn)
                .await
                .map_err(|e| AppError::Store(format!("redis GETDEL: {e}")))?;
            Ok(result)
        })
    }

    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        Box::pin(async move {
            // Redis `INCR` is a single atomic command — cross-replica safe
            // by construction, the same guarantee `take_raw_atomic`'s
            // `GETDEL` gives.
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            let next: u64 = conn
                .incr(fk, 1i64)
                .await
                .map_err(|e| AppError::Store(format!("redis INCR: {e}")))?;
            Ok(next)
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            let mut pattern = self.full_key(&prefix);
            pattern.extend_from_slice(b"*");

            let mut conn = self.conn.clone();

            let keys: Vec<Vec<u8>> = {
                let mut collected = Vec::new();
                let mut iter: redis::AsyncIter<Vec<u8>> = conn
                    .scan_match(&pattern)
                    .await
                    .map_err(|e| AppError::Store(format!("redis SCAN: {e}")))?;

                while let Some(key) = iter.next_item().await {
                    collected
                        .push(key.map_err(|e| AppError::Store(format!("redis SCAN iter: {e}")))?);
                }
                collected
            };

            if keys.is_empty() {
                return Ok(Vec::new());
            }

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
                        let raw_key = k[prefix_len..].to_vec();
                        (raw_key, val)
                    })
                })
                .collect();

            Ok(results)
        })
    }
}

enum RedisBatchOp {
    Insert { full_key: Vec<u8>, value: Vec<u8> },
    Remove { full_key: Vec<u8> },
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
            pipe.atomic();

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

#[cfg(test)]
mod tests {
    use super::redacted_url;

    #[test]
    fn redacted_url_drops_credentials() {
        for (input, expected) in [
            ("redis://127.0.0.1:6379", "redis://127.0.0.1:6379"),
            ("redis://127.0.0.1:6379/2", "redis://127.0.0.1:6379/2"),
            (
                "redis://:hunter2@cache.internal:6379/0",
                "redis://cache.internal:6379/0 (credentials redacted)",
            ),
            (
                "rediss://app:hunter2@cache.internal",
                "rediss://cache.internal (credentials redacted)",
            ),
            (
                "redis+unix:///run/redis.sock?db=1&pass=hunter2",
                "redis+unix:///run/redis.sock (credentials redacted)",
            ),
        ] {
            let shown = redacted_url(input);
            assert_eq!(shown, expected);
            assert!(!shown.contains("hunter2"));
            assert!(!shown.contains("app@"));
        }
        assert_eq!(redacted_url("not a url"), "<unparseable redis url>");
    }
}

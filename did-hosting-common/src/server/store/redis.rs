//! Redis backend.
//!
//! A row of keyspace `ks` under `key` is the string `ks:key`. Each keyspace
//! also keeps an index: a sorted set at `__index__:ks` holding every key of
//! the keyspace as a member, all at score 0, so Redis orders them bytewise
//! and `ZRANGEBYLEX` / `ZLEXCOUNT` answer a prefix scan, a page or a count
//! from the keyspace's own keys. Every write changes the value and the index
//! together, in one `MULTI` or one Lua script, so they cannot drift apart.
//!
//! A database written before the index existed is indexed once, at open
//! ([`rebuild_index`]), and marked so it is not walked again.

use std::sync::{Arc, LazyLock};

use redis::AsyncCommands;
use tracing::{info, warn};

use crate::server::config::StoreConfig;
use crate::server::error::AppError;

use super::{
    ALL_KEYSPACES, BatchOps, BoxFuture, KeyspaceOps, PrefixPage, RawKvPair, StorageBackend,
};

/// How many keys one `ZRANGEBYLEX` page or one `MGET` carries.
const CHUNK: usize = 1000;

/// Where keyspace `ks`'s index lives. No row key has this shape: a row is
/// `ks:...` for a keyspace name, and no keyspace is called `__index__`.
fn index_key(keyspace: &str) -> String {
    format!("__index__:{keyspace}")
}

/// Set once every keyspace's index has been built from its rows.
const INDEX_MARKER: &str = "__index_version__";
const INDEX_VERSION: &str = "1";

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

        rebuild_index(&mut conn).await?;

        Ok(Box::new(Self { conn }))
    }
}

/// Index every row of every known keyspace, once per database: a database
/// written before the index existed would otherwise list none of its rows.
///
/// Walks the database with `SCAN` (a key it returns twice is added twice,
/// which `ZADD` makes harmless) and adds each `ks:key` whose `ks` is one of
/// [`ALL_KEYSPACES`] to that keyspace's index, then sets [`INDEX_MARKER`].
/// Replicas opening together may both walk it; each `ZADD` is idempotent.
/// Rows written meanwhile by a replica that predates the index are not
/// indexed: upgrade every replica sharing the database together.
async fn rebuild_index(conn: &mut redis::aio::MultiplexedConnection) -> Result<(), AppError> {
    let marker: Option<String> = conn
        .get(INDEX_MARKER)
        .await
        .map_err(|e| AppError::Store(format!("redis GET: {e}")))?;
    if marker.as_deref() == Some(INDEX_VERSION) {
        return Ok(());
    }
    info!("redis store: indexing existing rows (once)");
    let mut cursor: u64 = 0;
    let mut indexed = 0usize;
    loop {
        let (next, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("COUNT")
            .arg(CHUNK)
            .query_async(conn)
            .await
            .map_err(|e| AppError::Store(format!("redis SCAN: {e}")))?;
        // A batch with no row of a known keyspace queues nothing, and Redis
        // refuses an empty pipeline (#470): skip its round trip.
        if let Some((pipe, queued)) = index_batch(&keys) {
            pipe.query_async::<()>(conn)
                .await
                .map_err(|e| AppError::Store(format!("redis index rebuild: {e}")))?;
            indexed += queued;
        }
        cursor = next;
        if cursor == 0 {
            break;
        }
    }
    conn.set::<_, _, ()>(INDEX_MARKER, INDEX_VERSION)
        .await
        .map_err(|e| AppError::Store(format!("redis SET: {e}")))?;
    info!(indexed, "redis store: index built");
    Ok(())
}

/// The `ZADD`s that index one `SCAN` batch, and how many there are; `None`
/// when the batch holds no row of a known keyspace, so nothing is sent.
fn index_batch(keys: &[Vec<u8>]) -> Option<(redis::Pipeline, usize)> {
    let mut pipe = redis::pipe();
    let mut queued = 0usize;
    for full in keys {
        if let Some((keyspace, key)) = split_row_key(full) {
            pipe.zadd(index_key(keyspace), key, 0).ignore();
            queued += 1;
        }
    }
    (queued > 0).then_some((pipe, queued))
}

/// `ks:key` as `(ks, key)`, for a known keyspace only.
fn split_row_key(full: &[u8]) -> Option<(&'static str, &[u8])> {
    let colon = full.iter().position(|b| *b == b':')?;
    let keyspace = ALL_KEYSPACES
        .iter()
        .find(|ks| ks.as_bytes() == &full[..colon])?;
    Some((keyspace, &full[colon + 1..]))
}

/// `url` with any username, password and query removed, for logging.
/// `StoreConfig`'s `Debug` redacts `redis_url` for the same reason: a
/// connection URL can carry credentials (`redis://:password@host`,
/// `rediss://user:pass@host`, or `redis+unix:///path?pass=...`).
fn redacted_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let query_credentials = parsed.query_pairs().any(|(key, _)| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "pass" | "password" | "user" | "username"
                )
            });
            let had_credentials =
                !parsed.username().is_empty() || parsed.password().is_some() || query_credentials;
            let had_query = parsed.query().is_some();
            // Both setters fail only for a URL that cannot carry credentials,
            // which then has none to remove.
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            let mut shown = parsed.to_string();
            if had_credentials {
                shown.push_str(" (credentials redacted)");
            } else if had_query {
                shown.push_str(" (query omitted)");
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
                index: index_key(name),
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

/// `KEYS[1]`: the row, `KEYS[2]`: its keyspace's index. `ARGV[1]`: the
/// member (the key within the keyspace). `ARGV[2]`: `1` if a current value is
/// expected, `0` if the row must be absent. `ARGV[3]`: the expected value.
/// `ARGV[4]`: the new value. Returns 1 if it wrote, 0 if the row held
/// anything else.
static COMPARE_AND_SWAP: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
local current = redis.call('GET', KEYS[1])
if ARGV[2] == '1' then
  if current ~= ARGV[3] then return 0 end
elseif current then
  return 0
end
redis.call('SET', KEYS[1], ARGV[4])
redis.call('ZADD', KEYS[2], 0, ARGV[1])
return 1
"#,
    )
});

/// `KEYS` and `ARGV[1]` as above. Reads the row and removes it and its index
/// entry in one step; returns the value, or nil if there was none.
static TAKE: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
local current = redis.call('GET', KEYS[1])
if current then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[1])
end
return current
"#,
    )
});

/// `KEYS` and `ARGV[1]` as above. Increments the row and indexes it.
static INCR: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r#"
local next = redis.call('INCR', KEYS[1])
redis.call('ZADD', KEYS[2], 0, ARGV[1])
return next
"#,
    )
});

/// The `ZRANGEBYLEX` bound at or after every key starting with `prefix`.
fn lex_min(prefix: &[u8]) -> Vec<u8> {
    if prefix.is_empty() {
        return b"-".to_vec();
    }
    let mut bound = b"[".to_vec();
    bound.extend_from_slice(prefix);
    bound
}

/// The `ZRANGEBYLEX` bound after every key starting with `prefix`: below the
/// prefix's successor, the shortest string greater than all of them.
fn lex_max(prefix: &[u8]) -> Vec<u8> {
    let mut successor = prefix.to_vec();
    while successor.last() == Some(&0xff) {
        successor.pop();
    }
    match successor.last_mut() {
        None => b"+".to_vec(),
        Some(last) => {
            *last += 1;
            let mut bound = b"(".to_vec();
            bound.extend_from_slice(&successor);
            bound
        }
    }
}

/// The bound just after `key`.
fn lex_after(key: &[u8]) -> Vec<u8> {
    let mut bound = b"(".to_vec();
    bound.extend_from_slice(key);
    bound
}

struct RedisKeyspace {
    conn: redis::aio::MultiplexedConnection,
    /// `{name}:`, which every row key of the keyspace starts with.
    prefix: String,
    /// The keyspace's index ([`index_key`]).
    index: String,
}

impl RedisKeyspace {
    fn full_key(&self, key: &[u8]) -> Vec<u8> {
        let mut fk = self.prefix.as_bytes().to_vec();
        fk.extend_from_slice(key);
        fk
    }

    /// Up to `count` keys of the index between `min` and `max`, in order.
    async fn range(&self, min: &[u8], max: &[u8], count: usize) -> Result<Vec<Vec<u8>>, AppError> {
        let mut conn = self.conn.clone();
        redis::cmd("ZRANGEBYLEX")
            .arg(&self.index)
            .arg(min)
            .arg(max)
            .arg("LIMIT")
            .arg(0)
            .arg(count)
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::Store(format!("redis ZRANGEBYLEX: {e}")))
    }

    /// Every key of the index starting with `prefix`, in order.
    async fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, AppError> {
        let max = lex_max(prefix);
        let mut min = lex_min(prefix);
        let mut keys = Vec::new();
        loop {
            let chunk = self.range(&min, &max, CHUNK).await?;
            let done = chunk.len() < CHUNK;
            if let Some(last) = chunk.last() {
                min = lex_after(last);
            }
            keys.extend(chunk);
            if done {
                return Ok(keys);
            }
        }
    }

    /// The values of `keys`, one `MGET` per [`CHUNK`], paired with their
    /// keys. A key whose row is gone (removed since it was listed) is left
    /// out.
    async fn values(&self, keys: Vec<Vec<u8>>) -> Result<Vec<RawKvPair>, AppError> {
        let mut conn = self.conn.clone();
        let mut rows = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(CHUNK) {
            let full: Vec<Vec<u8>> = chunk.iter().map(|k| self.full_key(k)).collect();
            let values: Vec<Option<Vec<u8>>> = redis::cmd("MGET")
                .arg(&full)
                .query_async(&mut conn)
                .await
                .map_err(|e| AppError::Store(format!("redis MGET: {e}")))?;
            rows.extend(
                chunk
                    .iter()
                    .cloned()
                    .zip(values)
                    .filter_map(|(k, v)| v.map(|v| (k, v))),
            );
        }
        Ok(rows)
    }
}

impl KeyspaceOps for RedisKeyspace {
    fn pages_in_key_order(&self) -> bool {
        true
    }
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            redis::pipe()
                .atomic()
                .set(fk, value)
                .ignore()
                .zadd(&self.index, key, 0)
                .ignore()
                .query_async::<()>(&mut conn)
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
            redis::pipe()
                .atomic()
                .del(fk)
                .ignore()
                .zrem(&self.index, key)
                .ignore()
                .query_async::<()>(&mut conn)
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
            // A Lua script runs atomically on the server, so of any number
            // of replicas taking the same key, one reads it before it is gone.
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            TAKE.key(fk)
                .key(&self.index)
                .arg(key)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| AppError::Store(format!("redis take: {e}")))
        })
    }

    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        Box::pin(async move {
            // `INCR` inside a script: atomic across replicas, and indexed in
            // the same step.
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            INCR.key(fk)
                .key(&self.index)
                .arg(key)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| AppError::Store(format!("redis INCR: {e}")))
        })
    }

    fn compare_and_swap_raw(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            // A Lua script runs atomically on the server: no other command
            // touches the key between its `GET` and its `SET`, so of any
            // number of replicas swapping from the same value, one wins.
            let fk = self.full_key(&key);
            let mut conn = self.conn.clone();
            let (has_expected, expected) = match expected {
                Some(v) => ("1", v),
                None => ("0", Vec::new()),
            };
            let swapped: i64 = COMPARE_AND_SWAP
                .key(fk)
                .key(&self.index)
                .arg(key)
                .arg(has_expected)
                .arg(expected)
                .arg(new)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| AppError::Store(format!("redis compare-and-swap: {e}")))?;
            Ok(swapped == 1)
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            let keys = self.keys(&prefix).await?;
            self.values(keys).await
        })
    }

    fn prefix_page_raw(
        &self,
        prefix: Vec<u8>,
        cursor: Option<Vec<u8>>,
        limit: usize,
    ) -> BoxFuture<'_, Result<Option<PrefixPage>, AppError>> {
        Box::pin(async move {
            // The cursor is the last key of the previous page.
            let min = match cursor {
                Some(after) if after.as_slice() >= prefix.as_slice() => lex_after(&after),
                _ => lex_min(&prefix),
            };
            let limit = limit.max(1);
            let mut keys = self.range(&min, &lex_max(&prefix), limit + 1).await?;
            let more = keys.len() > limit;
            keys.truncate(limit);
            let next = more.then(|| keys.last().cloned()).flatten();
            Ok(Some(PrefixPage {
                rows: self.values(keys).await?,
                next,
                ordered: true,
            }))
        })
    }

    fn prefix_keys_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, AppError>> {
        Box::pin(async move { self.keys(&prefix).await })
    }

    fn prefix_count(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<usize, AppError>> {
        Box::pin(async move {
            let mut conn = self.conn.clone();
            redis::cmd("ZLEXCOUNT")
                .arg(&self.index)
                .arg(lex_min(&prefix))
                .arg(lex_max(&prefix))
                .query_async(&mut conn)
                .await
                .map_err(|e| AppError::Store(format!("redis ZLEXCOUNT: {e}")))
        })
    }
}

enum RedisBatchOp {
    Insert {
        keyspace: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Remove {
        keyspace: String,
        key: Vec<u8>,
    },
}

struct RedisBatch {
    conn: redis::aio::MultiplexedConnection,
    ops: Vec<RedisBatchOp>,
}

fn row_key(keyspace: &str, key: &[u8]) -> Vec<u8> {
    let mut full = format!("{keyspace}:").into_bytes();
    full.extend_from_slice(key);
    full
}

impl BatchOps for RedisBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push(RedisBatchOp::Insert {
            keyspace: keyspace.to_string(),
            key,
            value,
        });
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        self.ops.push(RedisBatchOp::Remove {
            keyspace: keyspace.to_string(),
            key,
        });
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            if self.ops.is_empty() {
                return Ok(());
            }
            let mut conn = self.conn.clone();

            // One `MULTI`: every row and its index entry change together,
            // in order, so a key's last operation decides it.
            let mut pipe = redis::pipe();
            pipe.atomic();
            for op in &self.ops {
                match op {
                    RedisBatchOp::Insert {
                        keyspace,
                        key,
                        value,
                    } => {
                        pipe.set(row_key(keyspace, key), value.as_slice()).ignore();
                        pipe.zadd(index_key(keyspace), key.as_slice(), 0).ignore();
                    }
                    RedisBatchOp::Remove { keyspace, key } => {
                        pipe.del(row_key(keyspace, key)).ignore();
                        pipe.zrem(index_key(keyspace), key.as_slice()).ignore();
                    }
                }
            }

            pipe.query_async::<()>(&mut conn).await.map_err(|e| {
                warn!(error = %e, "redis batch failed");
                AppError::Store(format!("redis pipeline: {e}"))
            })?;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{index_batch, lex_max, lex_min, redacted_url, split_row_key};

    /// A `SCAN` batch with no row of a known keyspace sends nothing: Redis
    /// refuses an empty pipeline, which failed the open (#470).
    #[test]
    fn a_batch_without_known_rows_sends_nothing() {
        let foreign: Vec<Vec<u8>> = vec![
            b"__index_version__".to_vec(),
            b"__index__:dids".to_vec(),
            b"c0123456789ab_roundtrip:x".to_vec(),
        ];
        assert!(index_batch(&[]).is_none());
        assert!(index_batch(&foreign).is_none());
        let mut mixed = foreign;
        mixed.push(b"dids:did:alice".to_vec());
        let (pipe, queued) = index_batch(&mixed).expect("one row to index");
        assert_eq!(queued, 1);
        assert_eq!(pipe.cmd_iter().count(), 1);
    }

    #[test]
    fn lex_bounds_cover_exactly_the_prefix() {
        assert_eq!(lex_min(b""), b"-");
        assert_eq!(lex_max(b""), b"+");
        assert_eq!(lex_min(b"did:"), b"[did:");
        assert_eq!(lex_max(b"did:"), b"(did;");
        assert_eq!(lex_max(&[b'a', 0xff, 0xff]), b"(b");
        assert_eq!(lex_max(&[0xff]), b"+");
    }

    #[test]
    fn only_rows_of_known_keyspaces_are_indexed() {
        assert_eq!(
            split_row_key(b"dids:did:alice"),
            Some(("dids", &b"did:alice"[..]))
        );
        assert_eq!(split_row_key(b"sessions:"), Some(("sessions", &b""[..])));
        assert_eq!(split_row_key(b"__index__:dids"), None);
        assert_eq!(split_row_key(b"__index_version__"), None);
        assert_eq!(split_row_key(b"other_app:x"), None);
        assert_eq!(split_row_key(b"didsx:y"), None);
    }

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
            (
                "redis://127.0.0.1:6379/?protocol=resp3",
                "redis://127.0.0.1:6379/ (query omitted)",
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

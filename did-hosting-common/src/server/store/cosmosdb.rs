//! Azure Cosmos DB backend.
//!
//! **One container, one partition.** Every keyspace lives in one container
//! (`store.cosmosdb_container`, default `kv`, partitioned on `/pk`), every
//! item under the partition key value `kv`. An item's id is the base64url
//! encoding of `keyspace \0 key`. That is what makes a [`BatchOps`] commit
//! atomic: Cosmos DB's transactional batch covers one partition of one
//! container, so a batch spanning keyspaces is still one transactional batch.
//! The cost is that one logical partition holds everything, and Cosmos DB
//! caps a logical partition at 20 GB.
//!
//! Earlier releases kept one container per keyspace. On open, each keyspace
//! still in such a container is copied in once ([`CosmosDbBackend::migrate`]);
//! the old containers are left for the operator to delete.

use std::sync::Arc;

use azure_data_cosmos::clients::{ContainerClient, DatabaseClient};
use azure_data_cosmos::models::ContainerProperties;
use azure_data_cosmos::options::{ItemWriteOptions, Precondition, Region};
use azure_data_cosmos::{
    AccountEndpoint, AccountReference, CosmosClient, FeedScope, Query, RoutingStrategy,
    TransactionalBatch,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use futures::StreamExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::server::config::StoreConfig;
use crate::server::error::{AppError, QuotaKind};

use super::{
    ALL_KEYSPACES, BatchOps, BoxFuture, KeyspaceOps, PrefixPage, RawKvPair, StorageBackend,
};

/// The partition key value used for all items (single-partition design).
const PARTITION_VALUE: &str = "kv";

/// The container every keyspace lives in, unless configured otherwise.
const DEFAULT_CONTAINER: &str = "kv";

/// How many times a conditional (ETag) write is retried under contention
/// before `take_raw_atomic`/`incr_raw` give up with an error. Each retry
/// means another writer won, so this is only reached under a sustained
/// race on one key.
const CONDITIONAL_WRITE_ATTEMPTS: usize = 16;

/// How many times a batch is re-run when an item it deletes vanished
/// between the existence check and the batch (see [`send_batch`]).
const BATCH_ATTEMPTS: usize = 5;

/// Cosmos DB's transactional batch takes at most 100 operations.
const MAX_BATCH_OPS: usize = 100;

/// ... and a request of at most 2 MB. Counted as 2,000,000 bytes of
/// serialized operations, so the bound errs on the side of refusing.
const MAX_BATCH_BYTES: usize = 2_000_000;

/// Cosmos DB's item limit is 2 MB of JSON; counted as 2,000,000 bytes of
/// id, value and [`DOC_OVERHEAD`].
const MAX_DOC_BYTES: usize = 2_000_000;

/// The JSON framing of a [`KvDoc`] (field names, quotes, the partition key)
/// and the system properties Cosmos DB adds.
const DOC_OVERHEAD: usize = 256;

/// The keyspace migration markers ([`CosmosDbBackend::migrate`]) live in
/// this keyspace. No keyspace a caller opens has this name.
const LAYOUT_KEYSPACE: &str = "__layout__";

/// Document model stored in Cosmos DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KvDoc {
    /// Document ID: base64url of `keyspace \0 key` ([`doc_id`]).
    id: String,
    /// Partition key field.
    pk: String,
    /// Base64url-encoded raw value bytes.
    data: String,
}

/// A projection of a [`KvDoc`] to its id.
#[derive(Debug, Deserialize)]
struct IdOnly {
    id: String,
}

/// The id of `key` in `keyspace`: `keyspace \0 key`, base64url. Keyspace
/// names never hold a NUL, so no two (keyspace, key) pairs share an id.
fn doc_id(keyspace: &str, key: &[u8]) -> String {
    BASE64.encode(scoped(keyspace, key))
}

/// `keyspace \0 key`, the bytes [`doc_id`] encodes.
fn scoped(keyspace: &str, key: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(keyspace.len() + 1 + key.len());
    bytes.extend_from_slice(keyspace.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(key);
    bytes
}

/// The id prefix every id starting with `prefix`'s bytes shares.
///
/// base64 turns each 3 bytes into 4 characters, but the character holding a
/// group's last bits also depends on the bytes after it, so only whole
/// 3-byte groups of the prefix encode the same way in every id that starts
/// with it. The rest is left to the exact byte check after decoding.
fn encoded_query_prefix(prefix: &[u8]) -> String {
    BASE64.encode(&prefix[..prefix.len() / 3 * 3])
}

/// Refuse an item Cosmos DB would reject as too large.
fn check_doc_size(doc: &KvDoc) -> Result<(), AppError> {
    super::check_item_size(
        "Cosmos DB",
        doc.id.len() + doc.data.len() + DOC_OVERHEAD,
        MAX_DOC_BYTES,
    )
}

fn value_doc(id: String, value: &[u8]) -> KvDoc {
    KvDoc {
        id,
        pk: PARTITION_VALUE.to_string(),
        data: BASE64.encode(value),
    }
}

fn decode(what: &str, encoded: &str) -> Result<Vec<u8>, AppError> {
    BASE64
        .decode(encoded)
        .map_err(|e| AppError::Store(format!("cosmosdb decode {what}: {e}")))
}

// ---------------------------------------------------------------------------
// CosmosDbBackend
// ---------------------------------------------------------------------------

pub struct CosmosDbBackend {
    container: ContainerClient,
}

/// Parse a Cosmos DB connection string into (endpoint, key).
///
/// Format: `AccountEndpoint=https://xxx.documents.azure.com:443/;AccountKey=xxx`
fn parse_connection_string(conn_str: &str) -> Result<(String, String), AppError> {
    let mut endpoint = None;
    let mut key = None;

    for part in conn_str.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("AccountEndpoint=") {
            endpoint = Some(val.to_string());
        } else if let Some(val) = part.strip_prefix("AccountKey=") {
            key = Some(val.to_string());
        }
    }

    match (endpoint, key) {
        (Some(e), Some(k)) => Ok((e, k)),
        _ => Err(AppError::Config(
            "invalid cosmosdb connection string: expected AccountEndpoint=...;AccountKey=..."
                .into(),
        )),
    }
}

impl CosmosDbBackend {
    pub async fn open(config: &StoreConfig) -> Result<Box<dyn StorageBackend>, AppError> {
        let database = config
            .cosmosdb_database
            .clone()
            .unwrap_or_else(|| "webvh".to_string());
        let container = config
            .cosmosdb_container
            .clone()
            .unwrap_or_else(|| DEFAULT_CONTAINER.to_string());

        let connection_string = config
            .cosmosdb_connection_string
            .as_deref()
            .ok_or_else(|| {
                AppError::Config("store.cosmosdb_connection_string is required".into())
            })?;

        info!(database, container, "opening cosmosdb store");

        let (endpoint_str, account_key) = parse_connection_string(connection_string)?;

        let endpoint: AccountEndpoint = endpoint_str
            .parse()
            .map_err(|e| AppError::Store(format!("cosmosdb endpoint parse: {e}")))?;

        let account = AccountReference::with_authentication_key(
            endpoint,
            azure_core::credentials::Secret::new(account_key),
        );

        // Cosmos DB 0.32 requires explicit routing. Accept any Azure region
        // name (display or normalized form); default to EAST_US when unset.
        let region = config
            .cosmosdb_region
            .as_deref()
            .map(|name| Region::new(name.to_string()))
            .unwrap_or(Region::EAST_US);

        let client = CosmosClient::builder()
            .build(account, RoutingStrategy::ProximityTo(region))
            .await
            .map_err(|e| AppError::Store(format!("cosmosdb build client: {e}")))?;

        Ok(Box::new(
            Self::with_client(&client, &database, &container).await?,
        ))
    }

    /// The backend over `database`/`container`, creating either if missing
    /// and copying in any keyspace still in its own container.
    async fn with_client(
        client: &CosmosClient,
        database: &str,
        container: &str,
    ) -> Result<Self, AppError> {
        let db = client.database_client(database);
        let container = match db.container_client(container, None).await {
            Ok(c) => c,
            Err(e) if is_not_found(&e) => {
                create_container(client, &db, database, container).await?;
                db.container_client(container, None)
                    .await
                    .map_err(|e| AppError::Store(format!("cosmosdb container client: {e}")))?
            }
            Err(e) => return Err(AppError::Store(format!("cosmosdb container client: {e}"))),
        };
        let backend = Self { container };
        backend.migrate(&db).await?;
        Ok(backend)
    }

    /// Copy each keyspace an earlier release kept in a container of its own
    /// into the shared container, once: a marker in [`LAYOUT_KEYSPACE`]
    /// records each keyspace done (or found with no container of its own).
    ///
    /// A copied item never replaces one already in the shared container
    /// (`create`, not `upsert`), so a replica that started on the new layout
    /// first keeps what it wrote. Start one upgraded replica alone, so the
    /// copy is done before any other writes.
    async fn migrate(&self, db: &DatabaseClient) -> Result<(), AppError> {
        for keyspace in ALL_KEYSPACES {
            let marker = doc_id(LAYOUT_KEYSPACE, keyspace.as_bytes());
            if self.read(&marker).await?.is_some() {
                continue;
            }
            let copied = match db.container_client(*keyspace, None).await {
                Ok(legacy) => self.copy_legacy(keyspace, &legacy).await?,
                Err(e) if is_not_found(&e) => 0,
                Err(e) => {
                    return Err(AppError::Store(format!(
                        "cosmosdb migrate {keyspace}: container client: {e}"
                    )));
                }
            };
            if copied > 0 {
                info!(
                    keyspace,
                    copied, "cosmosdb: copied a keyspace from its own container"
                );
            }
            self.container
                .upsert_item(
                    PARTITION_VALUE,
                    &marker,
                    value_doc(marker.clone(), b"migrated"),
                    None,
                )
                .await
                .map_err(|e| AppError::Store(format!("cosmosdb migrate marker: {e}")))?;
        }
        Ok(())
    }

    async fn copy_legacy(
        &self,
        keyspace: &str,
        legacy: &ContainerClient,
    ) -> Result<usize, AppError> {
        let docs: Vec<KvDoc> = query(
            legacy,
            Query::from("SELECT * FROM c WHERE c.pk = @pk")
                .with_parameter("@pk", PARTITION_VALUE)
                .map_err(query_param)?,
        )
        .await?;
        let mut copied = 0;
        for doc in docs {
            let key = decode("legacy key", &doc.id)?;
            let id = doc_id(keyspace, &key);
            let moved = KvDoc {
                id: id.clone(),
                pk: PARTITION_VALUE.to_string(),
                data: doc.data,
            };
            match self
                .container
                .create_item(PARTITION_VALUE, &id, moved, None)
                .await
            {
                Ok(_) => copied += 1,
                Err(e) if e.status().is_conflict() => {}
                Err(e) => return Err(AppError::Store(format!("cosmosdb migrate copy: {e}"))),
            }
        }
        Ok(copied)
    }

    async fn read(&self, id: &str) -> Result<Option<KvDoc>, AppError> {
        match self.container.read_item(PARTITION_VALUE, id, None).await {
            Ok(resp) => resp
                .into_model()
                .map(Some)
                .map_err(|e| AppError::Store(format!("cosmosdb read body: {e}"))),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(AppError::Store(format!("cosmosdb read: {e}"))),
        }
    }
}

/// Create the database (if missing) and the container, partitioned on
/// `/pk`. Someone else creating either meanwhile is fine.
async fn create_container(
    client: &CosmosClient,
    db: &DatabaseClient,
    database: &str,
    container: &str,
) -> Result<(), AppError> {
    match client.create_database(database, None).await {
        Ok(_) => info!(database, "cosmosdb database created"),
        Err(e) if e.status().is_conflict() => {}
        Err(e) => return Err(AppError::Store(format!("cosmosdb create database: {e}"))),
    }
    let properties = ContainerProperties::new(container.to_string(), "/pk".into());
    match db.create_container(properties, None).await {
        Ok(_) => {
            info!(container, "cosmosdb container created");
            Ok(())
        }
        Err(e) if e.status().is_conflict() => Ok(()),
        Err(e) => Err(AppError::Store(format!("cosmosdb create container: {e}"))),
    }
}

fn query_param(e: azure_data_cosmos::CosmosError) -> AppError {
    AppError::Store(format!("cosmosdb query param: {e}"))
}

/// Run `query` in the shared partition and collect every result.
async fn query<T: DeserializeOwned + Send + 'static>(
    container: &ContainerClient,
    query: Query,
) -> Result<Vec<T>, AppError> {
    let mut pager = container
        .query_items::<T>(query, FeedScope::partition(PARTITION_VALUE), None)
        .await
        .map_err(|e| AppError::Store(format!("cosmosdb query: {e}")))?;
    let mut out = Vec::new();
    while let Some(item) = pager.next().await {
        out.push(item.map_err(|e| AppError::Store(format!("cosmosdb query item: {e}")))?);
    }
    Ok(out)
}

impl StorageBackend for CosmosDbBackend {
    fn keyspace(&self, name: &str) -> Result<(String, Arc<dyn KeyspaceOps>), AppError> {
        CosmosDbKeyspace::valid_name(name)?;
        Ok((
            name.to_string(),
            Arc::new(CosmosDbKeyspace {
                container: self.container.clone(),
                keyspace: name.to_string(),
            }),
        ))
    }

    fn batch(&self) -> Box<dyn BatchOps> {
        Box::new(CosmosDbBatch {
            container: self.container.clone(),
            ops: Vec::new(),
        })
    }

    fn persist(&self) -> BoxFuture<'_, Result<(), AppError>> {
        // Cosmos DB is fully managed; no-op.
        Box::pin(async { Ok(()) })
    }

    fn max_item_bytes(&self) -> Option<usize> {
        // The value is stored base64-encoded: 4 characters for 3 bytes.
        Some((MAX_DOC_BYTES - DOC_OVERHEAD) / 4 * 3)
    }
}

// ---------------------------------------------------------------------------
// CosmosDbKeyspace
// ---------------------------------------------------------------------------

struct CosmosDbKeyspace {
    container: ContainerClient,
    keyspace: String,
}

impl CosmosDbKeyspace {
    /// A keyspace name is non-empty and holds no NUL, the byte that ends it
    /// inside an id ([`doc_id`]).
    fn valid_name(name: &str) -> Result<(), AppError> {
        if name.is_empty() || name.contains('\0') {
            return Err(AppError::Store(format!("invalid keyspace name {name:?}")));
        }
        Ok(())
    }

    fn id(&self, key: &[u8]) -> String {
        doc_id(&self.keyspace, key)
    }

    /// The key an id of this keyspace stands for, or `None` for an id of
    /// another keyspace (one sharing the query's encoded prefix).
    fn key_of(&self, id: &str) -> Result<Option<Vec<u8>>, AppError> {
        let bytes = decode("key", id)?;
        let scope = scoped(&self.keyspace, b"");
        Ok(bytes
            .starts_with(&scope)
            .then(|| bytes[scope.len()..].to_vec()))
    }

    /// The id-prefix query for `prefix`: `SELECT {select}` of every item
    /// whose id may stand for a key starting with it.
    fn prefix_query(&self, select: &str, prefix: &[u8], tail: &str) -> Result<Query, AppError> {
        Query::from(format!(
            "SELECT {select} FROM c WHERE c.pk = @pk AND STARTSWITH(c.id, @prefix){tail}"
        ))
        .with_parameter("@pk", PARTITION_VALUE)
        .map_err(query_param)?
        .with_parameter(
            "@prefix",
            encoded_query_prefix(&scoped(&self.keyspace, prefix)),
        )
        .map_err(query_param)
    }

    /// The rows of `docs` whose key starts with `prefix`, decoded.
    fn rows(&self, docs: Vec<KvDoc>, prefix: &[u8]) -> Result<Vec<RawKvPair>, AppError> {
        let mut rows = Vec::new();
        for doc in docs {
            if let Some(key) = self.key_of(&doc.id)?
                && key.starts_with(prefix)
            {
                rows.push((key, decode("value", &doc.data)?));
            }
        }
        Ok(rows)
    }
}

impl KeyspaceOps for CosmosDbKeyspace {
    fn insert_raw(&self, key: Vec<u8>, value: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let id = self.id(&key);
            let doc = value_doc(id.clone(), &value);
            check_doc_size(&doc)?;
            self.container
                .upsert_item(PARTITION_VALUE, &id, doc, None)
                .await
                .map_err(|e| AppError::Store(format!("cosmosdb upsert: {e}")))?;
            Ok(())
        })
    }

    fn get_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        Box::pin(async move {
            let id = self.id(&key);
            match self.container.read_item(PARTITION_VALUE, &id, None).await {
                Ok(resp) => {
                    let doc: KvDoc = resp
                        .into_model()
                        .map_err(|e| AppError::Store(format!("cosmosdb read body: {e}")))?;
                    Ok(Some(decode("value", &doc.data)?))
                }
                Err(e) if is_not_found(&e) => Ok(None),
                Err(e) => Err(AppError::Store(format!("cosmosdb read: {e}"))),
            }
        })
    }

    fn remove(&self, key: Vec<u8>) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let id = self.id(&key);
            match self.container.delete_item(PARTITION_VALUE, &id, None).await {
                Ok(_) => Ok(()),
                Err(e) if is_not_found(&e) => Ok(()),
                Err(e) => Err(AppError::Store(format!("cosmosdb delete: {e}"))),
            }
        })
    }

    fn contains_key(&self, key: Vec<u8>) -> BoxFuture<'_, Result<bool, AppError>> {
        Box::pin(async move {
            let id = self.id(&key);
            match self.container.read_item(PARTITION_VALUE, &id, None).await {
                Ok(_) => Ok(true),
                Err(e) if is_not_found(&e) => Ok(false),
                Err(e) => Err(AppError::Store(format!("cosmosdb read: {e}"))),
            }
        })
    }

    fn take_raw_atomic(&self, key: Vec<u8>) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        // Read the item and its ETag, then delete it `If-Match` that ETag.
        // Cosmos DB deletes a given version of an item exactly once, so of
        // any number of callers — on any replica — racing on the same key,
        // one delete succeeds and returns the value; the rest see 404 (it's
        // gone) or 412 (it changed; re-read) and never return it.
        Box::pin(async move {
            let container = &self.container;
            let id = self.id(&key);
            for _ in 0..CONDITIONAL_WRITE_ATTEMPTS {
                let resp = match container.read_item(PARTITION_VALUE, &id, None).await {
                    Ok(resp) => resp,
                    Err(e) if is_not_found(&e) => return Ok(None),
                    Err(e) => return Err(AppError::Store(format!("cosmosdb read: {e}"))),
                };
                let etag = resp
                    .headers()
                    .etag()
                    .cloned()
                    .ok_or_else(|| AppError::Store("cosmosdb read: no etag".into()))?;
                let doc: KvDoc = resp
                    .into_model()
                    .map_err(|e| AppError::Store(format!("cosmosdb read body: {e}")))?;
                let options =
                    ItemWriteOptions::default().with_precondition(Precondition::if_match(etag));
                match container
                    .delete_item(PARTITION_VALUE, &id, Some(options))
                    .await
                {
                    Ok(_) => return Ok(Some(decode("value", &doc.data)?)),
                    Err(e) if is_not_found(&e) => return Ok(None),
                    Err(e) if e.status().is_precondition_failed() => continue,
                    Err(e) => return Err(AppError::Store(format!("cosmosdb delete: {e}"))),
                }
            }
            Err(AppError::Store("cosmosdb take: too much contention".into()))
        })
    }

    fn incr_raw(&self, key: Vec<u8>) -> BoxFuture<'_, Result<u64, AppError>> {
        // Optimistic concurrency: create the counter (a create 409s if the
        // item already exists), or replace it `If-Match` the ETag just read.
        // A racing writer on another replica makes the write fail (409/412)
        // and this re-reads, so no increment is ever lost.
        Box::pin(async move {
            let container = &self.container;
            let id = self.id(&key);
            let counter_doc = |n: u64| value_doc(id.clone(), &encode_counter(n));
            for _ in 0..CONDITIONAL_WRITE_ATTEMPTS {
                match container.read_item(PARTITION_VALUE, &id, None).await {
                    Err(e) if is_not_found(&e) => {
                        match container
                            .create_item(PARTITION_VALUE, &id, counter_doc(1), None)
                            .await
                        {
                            Ok(_) => return Ok(1),
                            Err(e) if e.status().is_conflict() => continue,
                            Err(e) => return Err(AppError::Store(format!("cosmosdb create: {e}"))),
                        }
                    }
                    Err(e) => return Err(AppError::Store(format!("cosmosdb read: {e}"))),
                    Ok(resp) => {
                        let etag = resp
                            .headers()
                            .etag()
                            .cloned()
                            .ok_or_else(|| AppError::Store("cosmosdb read: no etag".into()))?;
                        let doc: KvDoc = resp
                            .into_model()
                            .map_err(|e| AppError::Store(format!("cosmosdb read body: {e}")))?;
                        let next = BASE64
                            .decode(&doc.data)
                            .map(|bytes| decode_counter(&bytes))
                            .unwrap_or(0)
                            .saturating_add(1);
                        let options = ItemWriteOptions::default()
                            .with_precondition(Precondition::if_match(etag));
                        match container
                            .replace_item(PARTITION_VALUE, &id, counter_doc(next), Some(options))
                            .await
                        {
                            Ok(_) => return Ok(next),
                            Err(e) if e.status().is_precondition_failed() || is_not_found(&e) => {
                                continue;
                            }
                            Err(e) => {
                                return Err(AppError::Store(format!("cosmosdb replace: {e}")));
                            }
                        }
                    }
                }
            }
            Err(AppError::Store("cosmosdb incr: too much contention".into()))
        })
    }

    fn compare_and_swap_raw(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> BoxFuture<'_, Result<bool, AppError>> {
        // Expecting absence: a create, which 409s if the item exists.
        // Expecting a value: read it with its ETag, compare, and replace
        // `If-Match` that ETag, which 412s if any writer on any replica got
        // there first. Either refusal means the key no longer holds what the
        // caller expected.
        Box::pin(async move {
            let container = &self.container;
            let id = self.id(&key);
            let doc = value_doc(id.clone(), &new);
            check_doc_size(&doc)?;
            let Some(expected) = expected else {
                return match container.create_item(PARTITION_VALUE, &id, doc, None).await {
                    Ok(_) => Ok(true),
                    Err(e) if e.status().is_conflict() => Ok(false),
                    Err(e) => Err(AppError::Store(format!("cosmosdb create: {e}"))),
                };
            };
            let resp = match container.read_item(PARTITION_VALUE, &id, None).await {
                Ok(resp) => resp,
                Err(e) if is_not_found(&e) => return Ok(false),
                Err(e) => return Err(AppError::Store(format!("cosmosdb read: {e}"))),
            };
            let etag = resp
                .headers()
                .etag()
                .cloned()
                .ok_or_else(|| AppError::Store("cosmosdb read: no etag".into()))?;
            let current: KvDoc = resp
                .into_model()
                .map_err(|e| AppError::Store(format!("cosmosdb read body: {e}")))?;
            if decode("value", &current.data)? != expected {
                return Ok(false);
            }
            let options =
                ItemWriteOptions::default().with_precondition(Precondition::if_match(etag));
            match container
                .replace_item(PARTITION_VALUE, &id, doc, Some(options))
                .await
            {
                Ok(_) => Ok(true),
                Err(e) if e.status().is_precondition_failed() || is_not_found(&e) => Ok(false),
                Err(e) => Err(AppError::Store(format!("cosmosdb replace: {e}"))),
            }
        })
    }

    fn prefix_iter_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<RawKvPair>, AppError>> {
        Box::pin(async move {
            let docs: Vec<KvDoc> =
                query(&self.container, self.prefix_query("*", &prefix, "")?).await?;
            self.rows(docs, &prefix)
        })
    }

    /// One `SELECT TOP` page in id order, resumed after the cursor (the id
    /// of the last item the previous page evaluated). Ids are base64, whose
    /// order is not key order, so pages are not `ordered`; and an item of
    /// another keyspace sharing the encoded prefix takes a place in a page,
    /// so a page may come back short or empty while more follow.
    fn prefix_page_raw(
        &self,
        prefix: Vec<u8>,
        cursor: Option<Vec<u8>>,
        limit: usize,
    ) -> BoxFuture<'_, Result<Option<PrefixPage>, AppError>> {
        Box::pin(async move {
            let limit = limit.clamp(1, 10_000);
            let after = cursor
                .map(|c| {
                    String::from_utf8(c)
                        .map_err(|_| AppError::Store("cosmosdb page: malformed cursor".into()))
                })
                .transpose()?;
            let mut q = self.prefix_query(
                &format!("TOP {limit} *"),
                &prefix,
                if after.is_some() {
                    " AND c.id > @after ORDER BY c.id"
                } else {
                    " ORDER BY c.id"
                },
            )?;
            if let Some(after) = &after {
                q = q.with_parameter("@after", after).map_err(query_param)?;
            }
            let docs: Vec<KvDoc> = query(&self.container, q).await?;
            let next = (docs.len() == limit)
                .then(|| docs.last().map(|d| d.id.clone().into_bytes()))
                .flatten();
            Ok(Some(PrefixPage {
                rows: self.rows(docs, &prefix)?,
                next,
                ordered: false,
            }))
        })
    }

    /// `SELECT c.id`: the keys without their values.
    fn prefix_keys_raw(&self, prefix: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, AppError>> {
        Box::pin(async move {
            let ids: Vec<IdOnly> =
                query(&self.container, self.prefix_query("c.id", &prefix, "")?).await?;
            let mut keys = Vec::new();
            for IdOnly { id } in ids {
                if let Some(key) = self.key_of(&id)?
                    && key.starts_with(&prefix)
                {
                    keys.push(key);
                }
            }
            Ok(keys)
        })
    }
}

/// A counter as its decimal ASCII representation. Malformed values decode to
/// 0 (defensive: a counter key should never hold anything else).
fn decode_counter(bytes: &[u8]) -> u64 {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn encode_counter(n: u64) -> Vec<u8> {
    n.to_string().into_bytes()
}

/// Check if a Cosmos DB error is a 404 Not Found.
///
/// 0.34 surfaces typed status on `CosmosError` (`status().is_not_found()`
/// checks HTTP 404 with no contradicting sub-status), replacing the prior
/// stringly-typed match on `azure_core::Error`.
fn is_not_found(err: &azure_data_cosmos::CosmosError) -> bool {
    err.status().is_not_found()
}

// ---------------------------------------------------------------------------
// CosmosDbBatch
// ---------------------------------------------------------------------------

enum CosmosDbBatchOp {
    Upsert(KvDoc),
    Delete(String),
}

impl CosmosDbBatchOp {
    fn id(&self) -> &str {
        match self {
            Self::Upsert(doc) => &doc.id,
            Self::Delete(id) => id,
        }
    }

    /// What this operation counts against [`MAX_BATCH_BYTES`].
    fn size(&self) -> usize {
        match self {
            Self::Upsert(doc) => doc.id.len() + doc.data.len() + DOC_OVERHEAD,
            Self::Delete(id) => id.len() + DOC_OVERHEAD,
        }
    }
}

struct CosmosDbBatch {
    container: ContainerClient,
    ops: Vec<CosmosDbBatchOp>,
}

impl BatchOps for CosmosDbBatch {
    fn insert_raw(&mut self, keyspace: &str, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push(CosmosDbBatchOp::Upsert(value_doc(
            doc_id(keyspace, &key),
            &value,
        )));
    }

    fn remove(&mut self, keyspace: &str, key: Vec<u8>) {
        self.ops
            .push(CosmosDbBatchOp::Delete(doc_id(keyspace, &key)));
    }

    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let ops = prepare_ops(self.ops)?;
            if ops.is_empty() {
                return Ok(());
            }
            check_one_batch(&ops)?;
            send_batch(&self.container, &ops).await
        })
    }

    fn commit_in_parts(self: Box<Self>) -> BoxFuture<'static, Result<(), AppError>> {
        Box::pin(async move {
            let ops = prepare_ops(self.ops)?;
            for part in split_batches(&ops) {
                send_batch(&self.container, part).await?;
            }
            Ok(())
        })
    }
}

/// Check every item fits, then keep only the last operation on each item:
/// applied in order, the batch leaves each item as its last operation says,
/// and Cosmos DB fails a delete of an item an earlier operation removed.
fn prepare_ops(ops: Vec<CosmosDbBatchOp>) -> Result<Vec<CosmosDbBatchOp>, AppError> {
    for op in &ops {
        if let CosmosDbBatchOp::Upsert(doc) = op {
            check_doc_size(doc)?;
        }
    }
    let mut last = std::collections::HashMap::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        last.insert(op.id().to_owned(), i);
    }
    Ok(ops
        .into_iter()
        .enumerate()
        .filter(|(i, op)| last.get(op.id()) == Some(i))
        .map(|(_, op)| op)
        .collect())
}

/// Refuse a batch over one transactional batch's bound, before anything is
/// sent, rather than splitting it into batches that could land part-way.
fn check_one_batch(ops: &[CosmosDbBatchOp]) -> Result<(), AppError> {
    let bytes: usize = ops.iter().map(CosmosDbBatchOp::size).sum();
    if ops.len() > MAX_BATCH_OPS || bytes > MAX_BATCH_BYTES {
        warn!(
            writes = ops.len(),
            bytes, "batch refused: over one Cosmos DB transactional batch"
        );
        return Err(AppError::quota(
            QuotaKind::Size,
            format!(
                "a change of {} writes ({bytes} bytes) is over the store's size \
             limit for one atomic write: {MAX_BATCH_OPS} writes and \
             {MAX_BATCH_BYTES} bytes",
                ops.len()
            ),
        ));
    }
    Ok(())
}

/// Split operations into runs that each fit one transactional batch. Every
/// item already fits on its own, so no run is empty.
fn split_batches(ops: &[CosmosDbBatchOp]) -> Vec<&[CosmosDbBatchOp]> {
    let mut parts = Vec::new();
    let (mut start, mut bytes) = (0, 0);
    for (i, op) in ops.iter().enumerate() {
        let size = op.size();
        if i > start && (i - start == MAX_BATCH_OPS || bytes + size > MAX_BATCH_BYTES) {
            parts.push(&ops[start..i]);
            (start, bytes) = (i, 0);
        }
        bytes += size;
    }
    if start < ops.len() {
        parts.push(&ops[start..]);
    }
    parts
}

/// How a transactional batch ended.
enum BatchOutcome {
    Applied,
    /// An item it deleted was not there: nothing was applied.
    DeleteMissed,
}

/// Send `ops` as one transactional batch: applied whole or not at all.
///
/// A batch delete of a missing item fails the whole batch, where a single
/// `remove` of a missing key succeeds; so the deletes are first narrowed to
/// the items that exist. One deleted by someone else between that check and
/// the batch fails it with nothing applied, and it is re-run.
async fn send_batch(container: &ContainerClient, ops: &[CosmosDbBatchOp]) -> Result<(), AppError> {
    for _ in 0..BATCH_ATTEMPTS {
        let mut batch = TransactionalBatch::new(PARTITION_VALUE);
        let mut count = 0;
        for op in ops {
            match op {
                CosmosDbBatchOp::Upsert(doc) => {
                    batch = batch
                        .upsert_item(doc, None)
                        .map_err(|e| AppError::Store(format!("cosmosdb batch upsert: {e}")))?;
                    count += 1;
                }
                CosmosDbBatchOp::Delete(id) => {
                    if exists(container, id).await? {
                        batch = batch.delete_item(id.clone(), None);
                        count += 1;
                    }
                }
            }
        }
        if count == 0 {
            return Ok(());
        }
        match execute(container, batch).await? {
            BatchOutcome::Applied => return Ok(()),
            BatchOutcome::DeleteMissed => continue,
        }
    }
    Err(AppError::Store(
        "cosmosdb batch: items it deletes keep vanishing under it".into(),
    ))
}

async fn exists(container: &ContainerClient, id: &str) -> Result<bool, AppError> {
    match container.read_item(PARTITION_VALUE, id, None).await {
        Ok(_) => Ok(true),
        Err(e) if is_not_found(&e) => Ok(false),
        Err(e) => Err(AppError::Store(format!("cosmosdb read: {e}"))),
    }
}

async fn execute(
    container: &ContainerClient,
    batch: TransactionalBatch,
) -> Result<BatchOutcome, AppError> {
    let response = match container.execute_transactional_batch(batch, None).await {
        Ok(response) => response,
        Err(e) if is_not_found(&e) => return Ok(BatchOutcome::DeleteMissed),
        Err(e) => return Err(AppError::Store(format!("cosmosdb batch: {e}"))),
    };
    let results = response
        .into_model()
        .map_err(|e| AppError::Store(format!("cosmosdb batch response: {e}")))?;
    // A failed batch reports the operation that failed with its own status,
    // and every other one with 424 (failed dependency).
    match results
        .results()
        .iter()
        .find(|r| !r.is_success() && r.status_code() != 424)
    {
        None if results.results().iter().all(|r| r.is_success()) => Ok(BatchOutcome::Applied),
        Some(r) if r.status_code() == 404 => Ok(BatchOutcome::DeleteMissed),
        Some(r) => Err(AppError::Store(format!(
            "cosmosdb batch: an operation failed with {}",
            r.status_code()
        ))),
        None => Err(AppError::Store("cosmosdb batch: not applied".into())),
    }
}

#[cfg(test)]
#[path = "cosmosdb_tests.rs"]
mod tests;

/// The whole backend against the Cosmos DB SDK's in-memory emulator: the
/// conformance suite, and the copy from per-keyspace containers.
#[cfg(all(test, feature = "cosmosdb-emulator"))]
mod emulator_tests {
    use azure_core::http::Url;
    use azure_data_cosmos::CosmosRuntimeBuilder;
    use azure_data_cosmos_driver::in_memory_emulator::{
        InMemoryEmulatorHttpClient, VirtualAccountConfig, VirtualRegion,
    };

    use super::*;
    use crate::server::store::{Store, conformance};

    const GATEWAY_URL: &str = "https://eastus.emulator.local";

    async fn emulated_client() -> CosmosClient {
        let config = VirtualAccountConfig::new(vec![VirtualRegion::new(
            "East US",
            Url::parse(GATEWAY_URL).unwrap(),
        )])
        .unwrap();
        let emulator = Arc::new(InMemoryEmulatorHttpClient::new(config));
        let account = AccountReference::with_authentication_key(
            GATEWAY_URL.parse::<AccountEndpoint>().unwrap(),
            azure_core::credentials::Secret::new("dGVzdGtleQ=="),
        );
        CosmosClient::builder()
            .with_runtime(
                CosmosRuntimeBuilder::from(emulator.runtime_builder())
                    .build()
                    .await
                    .unwrap(),
            )
            .build(account, RoutingStrategy::ProximityTo(Region::EAST_US))
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn conformance_suite() {
        let client = emulated_client().await;
        let backend = CosmosDbBackend::with_client(&client, "webvh", "kv")
            .await
            .unwrap();
        let store = Store::from_backend(Box::new(backend));
        conformance::run(&store, &conformance::namespace()).await;
    }

    /// A keyspace an earlier release kept in a container of its own is
    /// copied into the shared container on open, and only once.
    #[tokio::test]
    async fn keyspaces_in_their_own_containers_are_copied_in_once() {
        let client = emulated_client().await;
        client.create_database("webvh", None).await.unwrap();
        let db = client.database_client("webvh");
        db.create_container(ContainerProperties::new("dids", "/pk".into()), None)
            .await
            .unwrap();
        let legacy = db.container_client("dids", None).await.unwrap();
        for (key, value) in [("did:a", "1"), ("did:b", "2")] {
            let id = BASE64.encode(key);
            legacy
                .upsert_item(
                    PARTITION_VALUE,
                    &id,
                    value_doc(id.clone(), value.as_bytes()),
                    None,
                )
                .await
                .unwrap();
        }
        let backend = CosmosDbBackend::with_client(&client, "webvh", "kv")
            .await
            .unwrap();
        let store = Store::from_backend(Box::new(backend));
        let dids = store.keyspace("dids").unwrap();
        let mut rows = dids.prefix_iter_raw("did:").await.unwrap();
        rows.sort();
        assert_eq!(
            rows,
            vec![
                (b"did:a".to_vec(), b"1".to_vec()),
                (b"did:b".to_vec(), b"2".to_vec())
            ]
        );

        // Marked done: a second open copies nothing back.
        dids.remove("did:a").await.unwrap();
        let again = CosmosDbBackend::with_client(&client, "webvh", "kv")
            .await
            .unwrap();
        let store = Store::from_backend(Box::new(again));
        let dids = store.keyspace("dids").unwrap();
        assert_eq!(dids.get_raw("did:a").await.unwrap(), None);
        assert_eq!(dids.get_raw("did:b").await.unwrap(), Some(b"2".to_vec()));
    }
}

//! Integration tests for the `store-dynamodb-single` backend.
//!
//! These tests exercise the `SingleTableDynamoDbBackend` through the
//! `StorageBackend`, `KeyspaceOps`, and `BatchOps` traits against a local
//! DynamoDB instance (DynamoDB Local or LocalStack).
//!
//! # Running
//!
//! 1. Start DynamoDB Local:
//!
//!    ```bash
//!    docker run -d -p 8000:8000 amazon/dynamodb-local
//!    ```
//!
//! 2. Run the tests:
//!
//!    ```bash
//!    DYNAMODB_SINGLE_TEST_ENDPOINT=http://localhost:8000 \
//!      cargo test -p did-hosting-common \
//!        --features store-dynamodb-single \
//!        --test dynamodb_single_table
//!    ```
//!
//! When `DYNAMODB_SINGLE_TEST_ENDPOINT` is not set the test binary
//! compiles but every test is skipped (prints a message and returns
//! `Ok(())`).

#![cfg(feature = "store-dynamodb-single")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, KeySchemaElement, KeyType, ProvisionedThroughput,
    ScalarAttributeType,
};
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::store::{BatchLimits, Store, chunk_ranges};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Monotonic counter to give every test a unique table name.
static TABLE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Return the DynamoDB Local endpoint URL if configured, or `None`.
fn local_endpoint() -> Option<String> {
    std::env::var("DYNAMODB_SINGLE_TEST_ENDPOINT").ok()
}

/// Build a DynamoDB client pointed at the local endpoint.
async fn local_client(endpoint: &str) -> Client {
    let config = aws_config::from_env()
        .endpoint_url(endpoint)
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await;
    Client::new(&config)
}

/// Create a fresh single-table DynamoDB table with the required `pk`
/// (HASH, String) + `sk` (RANGE, String) schema and return its name.
async fn create_test_table(client: &Client) -> String {
    let id = TABLE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = format!("test_single_{id}_{}", std::process::id());

    client
        .create_table()
        .table_name(&name)
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("pk")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("sk")
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("pk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("sk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(5)
                .write_capacity_units(5)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_or_else(|e| panic!("failed to create test table {name}: {e}"));

    name
}

/// Delete the test table (best-effort cleanup).
async fn delete_test_table(client: &Client, name: &str) {
    let _ = client.delete_table().table_name(name).send().await;
}

/// Open a `Store` backed by single-table DynamoDB pointed at `endpoint`
/// using the given `table_name`.
async fn open_store(endpoint: &str, table_name: &str) -> Store {
    open_store_in(endpoint, table_name, None).await
}

/// [`open_store`] with an optional key namespace.
async fn open_store_in(endpoint: &str, table_name: &str, namespace: Option<&str>) -> Store {
    // AWS_ENDPOINT_URL is respected by aws_config::from_env() inside
    // SingleTableDynamoDbBackend::open, so set it for this process.
    // SAFETY: test-only, single-threaded per test; no concurrent reads
    // of these env vars from other threads at this point.
    unsafe {
        std::env::set_var("AWS_ENDPOINT_URL", endpoint);
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        std::env::set_var("AWS_DEFAULT_REGION", "us-east-1");
    }

    let config = StoreConfig {
        data_dir: PathBuf::from("/tmp"),
        dynamodb_table_name: Some(table_name.to_string()),
        dynamodb_region: Some("us-east-1".to_string()),
        dynamodb_key_namespace: namespace.map(str::to_string),
        ..StoreConfig::default()
    };

    Store::open(&config).await.expect("open single-table store")
}

/// What to do about a missing endpoint: skip locally, fail in CI.
///
/// A suite that silently skips when its endpoint variable is unset reports
/// green having tested nothing (a typo in a CI variable would look like a
/// pass). Locally a skip is convenient; where `CI` is set it is an error.
fn endpoint_or_skip(endpoint: Option<String>, in_ci: bool) -> Result<Option<String>, String> {
    match (endpoint, in_ci) {
        (Some(ep), _) => Ok(Some(ep)),
        (None, false) => Ok(None),
        (None, true) => Err(
            "DYNAMODB_SINGLE_TEST_ENDPOINT is not set but CI is: refusing to skip the \
             single-table DynamoDB suite (that would pass having tested nothing)"
                .to_string(),
        ),
    }
}

/// Macro that skips the test when `DYNAMODB_SINGLE_TEST_ENDPOINT` is not set,
/// avoiding a hard failure on a developer machine without local DynamoDB, and
/// fails instead of skipping when `CI` is set (see [`endpoint_or_skip`]).
macro_rules! require_endpoint {
    () => {
        match endpoint_or_skip(local_endpoint(), std::env::var_os("CI").is_some()) {
            Ok(Some(ep)) => ep,
            Ok(None) => {
                eprintln!(
                    "SKIP: DYNAMODB_SINGLE_TEST_ENDPOINT not set — \
                     skipping single-table DynamoDB test"
                );
                return;
            }
            Err(msg) => panic!("{msg}"),
        }
    };
}

// ---------------------------------------------------------------------------
// Store::open — config validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_fails_without_table_name() {
    let config = StoreConfig {
        data_dir: PathBuf::from("/tmp"),
        dynamodb_table_name: None,
        ..StoreConfig::default()
    };

    // Even if we can't reach DynamoDB, the config check fires first.
    // SAFETY: test-only setup before any concurrent AWS SDK access.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        std::env::set_var("AWS_DEFAULT_REGION", "us-east-1");
    }

    let result = Store::open(&config).await;
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("dynamodb_table_name"),
                "error should mention dynamodb_table_name: {msg}"
            );
        }
        Ok(_) => panic!("expected Config error when dynamodb_table_name is None"),
    }
}

// ---------------------------------------------------------------------------
// KeyspaceOps — insert / get / remove / contains_key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn insert_and_get_round_trip() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    // Insert
    ks.insert_raw("did:alice", b"alice-data".to_vec())
        .await
        .expect("insert");

    // Get
    let val: Option<Vec<u8>> = ks.get_raw("did:alice").await.expect("get");
    assert_eq!(val, Some(b"alice-data".to_vec()));

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn get_missing_key_returns_none() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    let val: Option<Vec<u8>> = ks.get_raw("nonexistent").await.expect("get");
    assert_eq!(val, None);

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn contains_key_true_and_false() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("sessions").expect("keyspace");

    assert!(!ks.contains_key("session:1").await.expect("contains_key"));

    ks.insert_raw("session:1", b"s1".to_vec())
        .await
        .expect("insert");

    assert!(ks.contains_key("session:1").await.expect("contains_key"));

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn remove_deletes_key() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    ks.insert_raw("did:bob", b"bob-data".to_vec())
        .await
        .expect("insert");
    assert!(ks.contains_key("did:bob").await.expect("contains_key"));

    ks.remove("did:bob").await.expect("remove");
    assert!(!ks.contains_key("did:bob").await.expect("contains_key"));

    // Remove on a non-existent key must not error.
    ks.remove("did:ghost").await.expect("remove nonexistent");

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// KeyspaceOps — insert overwrites (upsert semantics)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn insert_overwrites_existing_value() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    ks.insert_raw("did:alice", b"v1".to_vec())
        .await
        .expect("insert v1");
    ks.insert_raw("did:alice", b"v2".to_vec())
        .await
        .expect("insert v2");

    let val: Option<Vec<u8>> = ks.get_raw("did:alice").await.expect("get");
    assert_eq!(val, Some(b"v2".to_vec()));

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// KeyspaceOps — take_raw_atomic (get-and-delete)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn take_raw_returns_value_and_removes() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("sessions").expect("keyspace");

    ks.insert_raw("refresh:tok1", b"session-id-1".to_vec())
        .await
        .expect("insert");

    // First take returns the value.
    let val = ks.take_raw("refresh:tok1").await.expect("take");
    assert_eq!(val, Some(b"session-id-1".to_vec()));

    // Second take returns None — the item was deleted.
    let val = ks.take_raw("refresh:tok1").await.expect("take again");
    assert_eq!(val, None);

    // Key is gone.
    assert!(!ks.contains_key("refresh:tok1").await.expect("contains"));

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn take_raw_on_missing_key_returns_none() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("sessions").expect("keyspace");

    let val = ks.take_raw("refresh:nonexistent").await.expect("take");
    assert_eq!(val, None);

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// KeyspaceOps — incr_raw (atomic counter)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn incr_raw_starts_at_one_and_counts_up() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("sessions").expect("keyspace");

    assert_eq!(ks.incr_raw("lockout:a").await.expect("incr"), 1);
    assert_eq!(ks.incr_raw("lockout:a").await.expect("incr"), 2);
    assert_eq!(ks.incr_raw("lockout:a").await.expect("incr"), 3);

    // Counters are per key.
    assert_eq!(ks.incr_raw("lockout:b").await.expect("incr"), 1);

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn incr_raw_is_scoped_to_its_keyspace() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let one = store.keyspace("sessions").expect("keyspace");
    let two = store.keyspace("acl").expect("keyspace");

    // The same sort key in two keyspaces shares the table but not the counter.
    assert_eq!(one.incr_raw("n").await.expect("incr"), 1);
    assert_eq!(one.incr_raw("n").await.expect("incr"), 2);
    assert_eq!(two.incr_raw("n").await.expect("incr"), 1);

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn incr_raw_concurrent_callers_never_see_the_same_value() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("sessions").expect("keyspace");

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let ks = ks.clone();
        tasks.push(tokio::spawn(async move {
            ks.incr_raw("lockout:race").await.expect("incr")
        }));
    }
    let mut seen = Vec::new();
    for t in tasks {
        seen.push(t.await.expect("join"));
    }
    seen.sort_unstable();
    assert_eq!(seen, (1..=8).collect::<Vec<u64>>());

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// KeyspaceOps — prefix_iter_raw
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prefix_iter_returns_matching_keys() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    // Seed data under two prefixes.
    ks.insert_raw("did:alice", b"a".to_vec())
        .await
        .expect("insert");
    ks.insert_raw("did:bob", b"b".to_vec())
        .await
        .expect("insert");
    ks.insert_raw("owner:carol", b"c".to_vec())
        .await
        .expect("insert");

    // Query "did:" prefix — should return alice and bob, not carol.
    let mut pairs = ks.prefix_iter_raw(b"did:").await.expect("prefix_iter");
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].0, b"did:alice");
    assert_eq!(pairs[0].1, b"a");
    assert_eq!(pairs[1].0, b"did:bob");
    assert_eq!(pairs[1].1, b"b");

    // Query "owner:" prefix — carol only.
    let pairs = ks.prefix_iter_raw(b"owner:").await.expect("prefix_iter");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, b"owner:carol");

    // Empty prefix returns all items in the keyspace.
    let pairs = ks.prefix_iter_raw(b"").await.expect("prefix_iter all");
    assert_eq!(pairs.len(), 3);

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn prefix_iter_returns_empty_for_no_match() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    ks.insert_raw("did:alice", b"a".to_vec())
        .await
        .expect("insert");

    let pairs = ks
        .prefix_iter_raw(b"nonexistent:")
        .await
        .expect("prefix_iter");
    assert!(pairs.is_empty());

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// Keyspace isolation — different keyspaces share a table but not data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keyspaces_are_isolated() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let dids = store.keyspace("dids").expect("dids");
    let sessions = store.keyspace("sessions").expect("sessions");

    // Same key name in both keyspaces.
    dids.insert_raw("k1", b"dids-value".to_vec())
        .await
        .expect("insert dids");
    sessions
        .insert_raw("k1", b"sessions-value".to_vec())
        .await
        .expect("insert sessions");

    // Each keyspace returns its own value.
    let v1: Option<Vec<u8>> = dids.get_raw("k1").await.expect("get dids");
    assert_eq!(v1, Some(b"dids-value".to_vec()));

    let v2: Option<Vec<u8>> = sessions.get_raw("k1").await.expect("get sessions");
    assert_eq!(v2, Some(b"sessions-value".to_vec()));

    // Removing from one keyspace does not affect the other.
    dids.remove("k1").await.expect("remove dids");
    assert!(!dids.contains_key("k1").await.expect("contains dids"));
    assert!(
        sessions
            .contains_key("k1")
            .await
            .expect("contains sessions")
    );

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// BatchOps — transactional multi-key writes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_insert_and_remove() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    // Seed one item we'll remove in the batch.
    ks.insert_raw("did:remove-me", b"old".to_vec())
        .await
        .expect("seed");

    // Build a batch: insert two keys, remove one.
    let mut batch = store.batch();
    batch
        .insert(&ks, "did:batch-a", &serde_json::json!({"name": "a"}))
        .expect("batch insert a");
    batch
        .insert(&ks, "did:batch-b", &serde_json::json!({"name": "b"}))
        .expect("batch insert b");
    batch.remove(&ks, "did:remove-me");
    batch.commit().await.expect("batch commit");

    // Verify inserts.
    let a: Option<serde_json::Value> = ks.get("did:batch-a").await.expect("get a");
    assert_eq!(a, Some(serde_json::json!({"name": "a"})));

    let b: Option<serde_json::Value> = ks.get("did:batch-b").await.expect("get b");
    assert_eq!(b, Some(serde_json::json!({"name": "b"})));

    // Verify removal.
    assert!(!ks.contains_key("did:remove-me").await.expect("contains"));

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn batch_across_keyspaces() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let dids = store.keyspace("dids").expect("dids");
    let sessions = store.keyspace("sessions").expect("sessions");

    let mut batch = store.batch();
    batch.insert_raw(&dids, "did:x", b"dx".to_vec());
    batch.insert_raw(&sessions, "session:y", b"sy".to_vec());
    batch.commit().await.expect("batch commit");

    assert_eq!(
        dids.get_raw("did:x").await.expect("get"),
        Some(b"dx".to_vec())
    );
    assert_eq!(
        sessions.get_raw("session:y").await.expect("get"),
        Some(b"sy".to_vec())
    );

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// persist() is a no-op and must not error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn persist_succeeds() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    store.persist().await.expect("persist no-op");

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// JSON round-trip through the typed KeyspaceHandle API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn typed_insert_and_get_json() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct DidRecord {
        mnemonic: String,
        owner: String,
    }

    let record = DidRecord {
        mnemonic: "alice".to_string(),
        owner: "did:key:z6Mk...".to_string(),
    };

    ks.insert("did:alice", &record).await.expect("insert json");

    let got: Option<DidRecord> = ks.get("did:alice").await.expect("get json");
    assert_eq!(got, Some(record));

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// Large values (> 1 KB) — DynamoDB item limit is 400 KB
// ---------------------------------------------------------------------------

#[tokio::test]
async fn large_value_round_trip() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    // 100 KB of repeated bytes.
    let big_value = vec![0xABu8; 100 * 1024];
    ks.insert_raw("content:bigdid:log", big_value.clone())
        .await
        .expect("insert big");

    let got = ks.get_raw("content:bigdid:log").await.expect("get big");
    assert_eq!(got, Some(big_value));

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// approximate_len / iter_all through KeyspaceHandle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approximate_len_counts_items() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    assert_eq!(ks.approximate_len().await.expect("len"), 0);

    ks.insert_raw("did:a", b"a".to_vec()).await.expect("ins");
    ks.insert_raw("did:b", b"b".to_vec()).await.expect("ins");
    ks.insert_raw("did:c", b"c".to_vec()).await.expect("ins");

    assert_eq!(ks.approximate_len().await.expect("len"), 3);

    ks.remove("did:b").await.expect("remove");
    assert_eq!(ks.approximate_len().await.expect("len"), 2);

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// verify_integrity — smoke test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_integrity_reports_no_corruption_on_valid_json() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    // Insert valid JSON entries.
    ks.insert("did:alice", &serde_json::json!({"state": "active"}))
        .await
        .expect("insert");
    // Raw byte entries under content: prefix are skipped by integrity check.
    ks.insert_raw("content:alice:log", b"raw log data".to_vec())
        .await
        .expect("insert raw");

    let corrupted = ks.verify_integrity().await.expect("verify");
    assert_eq!(corrupted, 0);

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn verify_integrity_detects_corrupted_entry() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    // Insert an entry whose key does not match a skip-prefix but whose
    // value is not valid JSON.
    ks.insert_raw("did:corrupt", b"this is not json".to_vec())
        .await
        .expect("insert");

    let corrupted = ks.verify_integrity().await.expect("verify");
    assert_eq!(corrupted, 1);

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// Multiple keyspaces — prefix_iter scopes within keyspace
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prefix_iter_scoped_to_keyspace() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks_a = store.keyspace("alpha").expect("alpha");
    let ks_b = store.keyspace("beta").expect("beta");

    ks_a.insert_raw("k:1", b"a1".to_vec()).await.expect("ins");
    ks_a.insert_raw("k:2", b"a2".to_vec()).await.expect("ins");
    ks_b.insert_raw("k:1", b"b1".to_vec()).await.expect("ins");

    // prefix_iter on alpha should not see beta's items.
    let pairs = ks_a.prefix_iter_raw(b"k:").await.expect("prefix");
    assert_eq!(pairs.len(), 2);

    let pairs = ks_b.prefix_iter_raw(b"k:").await.expect("prefix");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].1, b"b1");

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// Empty batch commit succeeds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_batch_commit() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let batch = store.batch();
    batch.commit().await.expect("empty batch commit");

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// Batch with > 25 items (DynamoDB TransactWriteItems limit per request is
// 100; verify chunking doesn't break at moderate sizes)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_with_many_items() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("bulk").expect("keyspace");

    let count = 50;
    let mut batch = store.batch();
    for i in 0..count {
        batch.insert_raw(&ks, format!("item:{i:04}"), format!("val-{i}").into_bytes());
    }
    batch.commit().await.expect("batch commit");

    // Verify all items are present.
    let all = ks.prefix_iter_raw(b"item:").await.expect("prefix");
    assert_eq!(all.len(), count);

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// Typed take (JSON deserialize + atomic remove)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn typed_take_returns_deserialized_and_removes() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("sessions").expect("keyspace");

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Session {
        id: String,
        user: String,
    }

    let session = Session {
        id: "s1".to_string(),
        user: "alice".to_string(),
    };

    ks.insert("session:s1", &session).await.expect("insert");

    let taken: Option<Session> = ks.take("session:s1").await.expect("take");
    assert_eq!(taken, Some(session));

    let again: Option<Session> = ks.take("session:s1").await.expect("take again");
    assert_eq!(again, None);

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// iter_all returns all items in a keyspace
// ---------------------------------------------------------------------------

#[tokio::test]
async fn iter_all_returns_everything() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    ks.insert_raw("a", b"1".to_vec()).await.expect("ins");
    ks.insert_raw("b", b"2".to_vec()).await.expect("ins");
    ks.insert_raw("c", b"3".to_vec()).await.expect("ins");

    let all = ks.iter_all().await.expect("iter_all");
    assert_eq!(all.len(), 3);

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// Unicode keys work correctly
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unicode_keys_round_trip() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;

    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    let key = "did:μ:résumé";
    ks.insert_raw(key, b"unicode-value".to_vec())
        .await
        .expect("insert unicode key");

    let val = ks.get_raw(key).await.expect("get unicode key");
    assert_eq!(val, Some(b"unicode-value".to_vec()));

    assert!(ks.contains_key(key).await.expect("contains"));

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// All-keyspace isolation test — proves every keyspace the service uses
// (dids, sessions, acl, stats, ts, witnesses, domains, registry, etc.)
// coexists safely in ONE table without data leaking between them.
// ===========================================================================

#[tokio::test]
async fn all_service_keyspaces_coexist_in_single_table() {
    use did_hosting_common::server::store::{
        KS_ACL, KS_ASSIGNMENTS, KS_DIDS, KS_DOMAINS, KS_META, KS_OUTBOUND_QUEUE, KS_PENDING_PURGES,
        KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES, KS_WITNESSES,
    };

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;

    let keyspaces = vec![
        KS_DIDS,
        KS_SESSIONS,
        KS_ACL,
        KS_STATS,
        KS_TIMESERIES,
        KS_WITNESSES,
        KS_DOMAINS,
        KS_REGISTRY,
        KS_OUTBOUND_QUEUE,
        KS_PENDING_PURGES,
        KS_META,
        KS_ASSIGNMENTS,
    ];

    // Write the same key "test:key" into every keyspace with a different value.
    for ks_name in &keyspaces {
        let ks = store.keyspace(ks_name).expect("open keyspace");
        ks.insert_raw("test:key", ks_name.as_bytes().to_vec())
            .await
            .expect("insert");
    }

    // Read back: each keyspace must return its own value, not another's.
    for ks_name in &keyspaces {
        let ks = store.keyspace(ks_name).expect("open keyspace");
        let val = ks.get_raw("test:key").await.expect("get");
        assert_eq!(
            val,
            Some(ks_name.as_bytes().to_vec()),
            "keyspace {ks_name} returned wrong value — isolation broken"
        );
    }

    // Remove from one keyspace, verify others still have their data.
    let dids = store.keyspace(KS_DIDS).expect("dids");
    dids.remove("test:key").await.expect("remove");
    assert!(!dids.contains_key("test:key").await.expect("contains"));

    for ks_name in keyspaces.iter().skip(1) {
        let ks = store.keyspace(ks_name).expect("open keyspace");
        assert!(
            ks.contains_key("test:key").await.expect("contains"),
            "removing from dids affected {ks_name}"
        );
    }

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// Witness keyspace operations — exercises the exact access patterns
// webvh-witness uses against DynamoDB single-table.
// ===========================================================================

#[tokio::test]
async fn witness_keyspace_operations() {
    use did_hosting_common::server::store::KS_WITNESSES;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_WITNESSES).expect("witnesses keyspace");

    // Witness stores proofs keyed by mnemonic.
    let proof_a = serde_json::json!({
        "mnemonic": "alice",
        "witness_did": "did:web:witness.example.com",
        "timestamp": "2024-01-01T00:00:00Z",
        "proof": "base64-encoded-signature"
    });
    let proof_b = serde_json::json!({
        "mnemonic": "bob",
        "witness_did": "did:web:witness.example.com",
        "timestamp": "2024-01-02T00:00:00Z",
        "proof": "another-signature"
    });

    // Write witness proofs.
    ks.insert("witness:alice", &proof_a).await.expect("insert");
    ks.insert("witness:bob", &proof_b).await.expect("insert");

    // Read back.
    let got: Option<serde_json::Value> = ks.get("witness:alice").await.expect("get");
    assert_eq!(got, Some(proof_a));

    // Prefix query (witness lists all proofs).
    let all = ks.prefix_iter_raw(b"witness:").await.expect("prefix");
    assert_eq!(all.len(), 2);

    // Remove a proof.
    ks.remove("witness:alice").await.expect("remove");
    let all = ks.prefix_iter_raw(b"witness:").await.expect("prefix");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, b"witness:bob");

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// Watcher sync-status operations — exercises the exact access patterns
// webvh-watcher uses against DynamoDB single-table.
// ===========================================================================

#[tokio::test]
async fn watcher_sync_status_operations() {
    use did_hosting_common::server::store::KS_DIDS;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_DIDS).expect("dids keyspace");

    // Watcher stores sync status under "watcher_sync:" prefix in the dids keyspace.
    let sync_a = serde_json::json!({
        "mnemonic": "alice",
        "last_version": 3,
        "last_checked": "2024-01-01T12:00:00Z"
    });
    let sync_b = serde_json::json!({
        "mnemonic": "bob",
        "last_version": 1,
        "last_checked": "2024-01-01T10:00:00Z"
    });

    // Write sync statuses.
    ks.insert("watcher_sync:alice", &sync_a)
        .await
        .expect("insert");
    ks.insert("watcher_sync:bob", &sync_b)
        .await
        .expect("insert");

    // Read back.
    let got: Option<serde_json::Value> = ks.get("watcher_sync:alice").await.expect("get");
    assert_eq!(got, Some(sync_a.clone()));

    // Prefix query (watcher lists all watched DIDs).
    let all = ks.prefix_iter_raw(b"watcher_sync:").await.expect("prefix");
    assert_eq!(all.len(), 2);

    // Update sync status (simulates watcher polling and finding new version).
    let sync_a_updated = serde_json::json!({
        "mnemonic": "alice",
        "last_version": 4,
        "last_checked": "2024-01-01T14:00:00Z"
    });
    ks.insert("watcher_sync:alice", &sync_a_updated)
        .await
        .expect("update");

    let got: Option<serde_json::Value> = ks.get("watcher_sync:alice").await.expect("get");
    assert_eq!(got, Some(sync_a_updated));

    // Watcher sync keys coexist with DID records in the same keyspace.
    ks.insert_raw("did:alice", b"did-record".to_vec())
        .await
        .expect("insert did");

    // Prefix scan for "watcher_sync:" must NOT return DID records.
    let syncs = ks.prefix_iter_raw(b"watcher_sync:").await.expect("prefix");
    assert_eq!(syncs.len(), 2);

    // Prefix scan for "did:" must NOT return watcher sync records.
    let dids = ks.prefix_iter_raw(b"did:").await.expect("prefix");
    assert_eq!(dids.len(), 1);

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// Batch across all keyspaces — simulates daemon bootstrap writing DIDs,
// ACL, and domains in a single transaction.
// ===========================================================================

#[tokio::test]
async fn batch_across_all_keyspaces_simulates_bootstrap() {
    use did_hosting_common::server::store::{KS_ACL, KS_DIDS, KS_DOMAINS};

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;

    let dids = store.keyspace(KS_DIDS).expect("dids");
    let acl = store.keyspace(KS_ACL).expect("acl");
    let domains = store.keyspace(KS_DOMAINS).expect("domains");

    // Simulate daemon bootstrap: write DID record + content + owner + ACL + domain
    // in one batch (exactly what happens at first boot).
    let mut batch = store.batch();

    // DID record.
    batch
        .insert(
            &dids,
            "did:.well-known",
            &serde_json::json!({"did_id": "did:webvh:QmABC:host:.well-known", "owner": "system"}),
        )
        .expect("batch did");

    // DID log content (raw bytes).
    batch.insert_raw(
        &dids,
        "content:.well-known:log",
        b"jsonl-entry-here".to_vec(),
    );

    // Owner reverse index.
    batch.insert_raw(&dids, "owner:system:.well-known", b".well-known".to_vec());

    // ACL entry.
    batch
        .insert(
            &acl,
            "acl:did:key:z6MkAdmin",
            &serde_json::json!({"role": "admin", "max_dids": 100}),
        )
        .expect("batch acl");

    // Domain seed.
    batch
        .insert(
            &domains,
            "domain:example.com",
            &serde_json::json!({"domain": "example.com", "owner": "system"}),
        )
        .expect("batch domain");

    batch.commit().await.expect("bootstrap batch commit");

    // Verify everything landed in the correct keyspace.
    let did_record: Option<serde_json::Value> = dids.get("did:.well-known").await.expect("get");
    assert_eq!(
        did_record.unwrap()["did_id"],
        "did:webvh:QmABC:host:.well-known"
    );

    let content = dids.get_raw("content:.well-known:log").await.expect("get");
    assert_eq!(content, Some(b"jsonl-entry-here".to_vec()));

    let owner = dids.get_raw("owner:system:.well-known").await.expect("get");
    assert_eq!(owner, Some(b".well-known".to_vec()));

    let acl_entry: Option<serde_json::Value> = acl.get("acl:did:key:z6MkAdmin").await.expect("get");
    assert_eq!(acl_entry.unwrap()["role"], "admin");

    let domain: Option<serde_json::Value> = domains.get("domain:example.com").await.expect("get");
    assert_eq!(domain.unwrap()["domain"], "example.com");

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// did-hosting-server access patterns
// ===========================================================================

/// Server: DID record + content log + content witness + owner index
/// are always written/deleted as a batch. This is the core multi-key
/// operation the server uses for every DID create/update/delete.
#[tokio::test]
async fn server_did_batch_write_and_read() {
    use did_hosting_common::server::store::KS_DIDS;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_DIDS).expect("dids");

    // Batch: create DID record + content log + witness content + owner index
    let mut batch = store.batch();
    batch.insert(
        &ks, "did:alice",
        &serde_json::json!({"did_id": "did:webvh:Qm:host:alice", "owner": "did:key:zAdmin", "state": "active"}),
    ).expect("batch did");
    batch.insert_raw(&ks, "content:alice:log", b"jsonl-signed-entry\n".to_vec());
    batch.insert_raw(&ks, "content:alice:witness", b"witness-proof-json".to_vec());
    batch.insert_raw(&ks, "owner:did:key:zAdmin:alice", b"alice".to_vec());
    batch.commit().await.expect("batch commit");

    // Read each key back.
    let did_rec: serde_json::Value = ks.get("did:alice").await.expect("get").expect("exists");
    assert_eq!(did_rec["state"], "active");

    let log = ks
        .get_raw("content:alice:log")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(log, b"jsonl-signed-entry\n");

    let witness = ks
        .get_raw("content:alice:witness")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(witness, b"witness-proof-json");

    let owner = ks
        .get_raw("owner:did:key:zAdmin:alice")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(owner, b"alice");

    // Prefix scan for owner's DIDs.
    let owner_dids = ks
        .prefix_iter_raw(b"owner:did:key:zAdmin:")
        .await
        .expect("prefix");
    assert_eq!(owner_dids.len(), 1);

    // Batch delete (simulates DID removal).
    let mut batch = store.batch();
    batch.remove(&ks, "did:alice");
    batch.remove(&ks, "content:alice:log");
    batch.remove(&ks, "content:alice:witness");
    batch.remove(&ks, "owner:did:key:zAdmin:alice");
    batch.commit().await.expect("batch delete");

    // All gone.
    assert!(!ks.contains_key("did:alice").await.expect("contains"));
    assert!(
        !ks.contains_key("content:alice:log")
            .await
            .expect("contains")
    );

    delete_test_table(&client, &table).await;
}

/// Server: watcher_sync prefix lives inside KS_DIDS alongside did: records.
/// Prefix scan must scope correctly.
#[tokio::test]
async fn server_watcher_sync_coexists_with_did_records() {
    use did_hosting_common::server::store::KS_DIDS;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_DIDS).expect("dids");

    // Mix DID records and watcher_sync records in the same keyspace.
    ks.insert("did:alice", &serde_json::json!({"state": "active"}))
        .await
        .expect("ins");
    ks.insert("did:bob", &serde_json::json!({"state": "active"}))
        .await
        .expect("ins");
    ks.insert("watcher_sync:alice", &serde_json::json!({"version": 3}))
        .await
        .expect("ins");
    ks.insert("watcher_sync:bob", &serde_json::json!({"version": 1}))
        .await
        .expect("ins");
    ks.insert_raw("content:alice:log", b"log".to_vec())
        .await
        .expect("ins");
    ks.insert_raw("owner:system:alice", b"alice".to_vec())
        .await
        .expect("ins");

    // Each prefix scan returns only its own prefix.
    let dids = ks.prefix_iter_raw(b"did:").await.expect("prefix");
    assert_eq!(dids.len(), 2);

    let syncs = ks.prefix_iter_raw(b"watcher_sync:").await.expect("prefix");
    assert_eq!(syncs.len(), 2);

    let contents = ks.prefix_iter_raw(b"content:").await.expect("prefix");
    assert_eq!(contents.len(), 1);

    let owners = ks.prefix_iter_raw(b"owner:").await.expect("prefix");
    assert_eq!(owners.len(), 1);

    delete_test_table(&client, &table).await;
}

/// Server: stats and timeseries keyspaces.
#[tokio::test]
async fn server_stats_and_timeseries() {
    use did_hosting_common::server::store::{KS_STATS, KS_TIMESERIES};

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;

    let stats = store.keyspace(KS_STATS).expect("stats");
    let ts = store.keyspace(KS_TIMESERIES).expect("timeseries");

    // Stats: per-mnemonic counters.
    stats
        .insert(
            "stats:alice",
            &serde_json::json!({"resolves": 42, "updates": 5}),
        )
        .await
        .expect("ins");
    stats
        .insert(
            "stats:bob",
            &serde_json::json!({"resolves": 10, "updates": 1}),
        )
        .await
        .expect("ins");

    // prefix_iter_raw to list all stats (used by stats seeding at startup).
    let all_stats = stats.prefix_iter_raw(b"stats:").await.expect("prefix");
    assert_eq!(all_stats.len(), 2);

    // Timeseries: buckets keyed as ts:<mnemonic>:<epoch>.
    ts.insert("ts:alice:1704067200", &serde_json::json!({"resolves": 10}))
        .await
        .expect("ins");
    ts.insert("ts:alice:1704153600", &serde_json::json!({"resolves": 15}))
        .await
        .expect("ins");
    ts.insert("ts:bob:1704067200", &serde_json::json!({"resolves": 5}))
        .await
        .expect("ins");

    // Scan for one mnemonic's time-series.
    let alice_ts = ts.prefix_iter_raw(b"ts:alice:").await.expect("prefix");
    assert_eq!(alice_ts.len(), 2);

    // Scan across all mnemonics.
    let all_ts = ts.prefix_iter_raw(b"ts:").await.expect("prefix");
    assert_eq!(all_ts.len(), 3);

    delete_test_table(&client, &table).await;
}

/// Server: session + refresh token lifecycle with take_raw_atomic.
#[tokio::test]
async fn server_session_and_refresh_token_lifecycle() {
    use did_hosting_common::server::store::KS_SESSIONS;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_SESSIONS).expect("sessions");

    // Create session + refresh token index.
    let session = serde_json::json!({
        "user_did": "did:key:zAlice",
        "expires_at": 1704153600
    });
    ks.insert("session:s1", &session).await.expect("ins");
    ks.insert_raw("refresh:tok-abc", b"s1".to_vec())
        .await
        .expect("ins");

    // Normal session lookup.
    let s: serde_json::Value = ks.get("session:s1").await.expect("get").expect("exists");
    assert_eq!(s["user_did"], "did:key:zAlice");

    // Refresh token rotation: atomic take (exactly one caller gets the value).
    let taken = ks.take_raw("refresh:tok-abc").await.expect("take");
    assert_eq!(taken, Some(b"s1".to_vec()));

    // Second take returns None (token consumed).
    let taken_again = ks.take_raw("refresh:tok-abc").await.expect("take");
    assert_eq!(taken_again, None);

    // Session cleanup: prefix scan for expired sessions.
    let all_sessions = ks.prefix_iter_raw(b"session:").await.expect("prefix");
    assert_eq!(all_sessions.len(), 1);

    // Remove session.
    ks.remove("session:s1").await.expect("remove");
    let all_sessions = ks.prefix_iter_raw(b"session:").await.expect("prefix");
    assert_eq!(all_sessions.len(), 0);

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// did-hosting-control access patterns
// ===========================================================================

/// Control: ACL CRUD — insert, get, prefix scan, remove.
#[tokio::test]
async fn control_acl_crud() {
    use did_hosting_common::server::store::KS_ACL;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_ACL).expect("acl");

    // Insert ACL entries.
    ks.insert(
        "acl:did:key:zAdmin",
        &serde_json::json!({"role": "admin", "max_dids": 100}),
    )
    .await
    .expect("ins");
    ks.insert(
        "acl:did:key:zOwner",
        &serde_json::json!({"role": "owner", "max_dids": 10}),
    )
    .await
    .expect("ins");
    ks.insert(
        "acl:did:key:zService",
        &serde_json::json!({"role": "service"}),
    )
    .await
    .expect("ins");

    // Get specific ACL.
    let admin: serde_json::Value = ks
        .get("acl:did:key:zAdmin")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(admin["role"], "admin");

    // List all ACLs (prefix scan).
    let all = ks.prefix_iter_raw(b"acl:").await.expect("prefix");
    assert_eq!(all.len(), 3);

    // Revoke (remove).
    ks.remove("acl:did:key:zService").await.expect("remove");
    let all = ks.prefix_iter_raw(b"acl:").await.expect("prefix");
    assert_eq!(all.len(), 2);

    delete_test_table(&client, &table).await;
}

/// Control: registry — service instance management.
#[tokio::test]
async fn control_registry_instance_ops() {
    use did_hosting_common::server::store::KS_REGISTRY;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_REGISTRY).expect("registry");

    // Register service instances.
    ks.insert(
        "instance:srv-1",
        &serde_json::json!({"url": "https://srv1.example.com", "last_seen": 1704067200}),
    )
    .await
    .expect("ins");
    ks.insert(
        "instance:srv-2",
        &serde_json::json!({"url": "https://srv2.example.com", "last_seen": 1704067200}),
    )
    .await
    .expect("ins");

    // List instances.
    let all = ks.prefix_iter_raw(b"instance:").await.expect("prefix");
    assert_eq!(all.len(), 2);

    // Deregister.
    ks.remove("instance:srv-1").await.expect("remove");
    let all = ks.prefix_iter_raw(b"instance:").await.expect("prefix");
    assert_eq!(all.len(), 1);

    delete_test_table(&client, &table).await;
}

/// Control: outbound queue — FIFO ordering via lex-sorted keys.
#[tokio::test]
async fn control_outbound_queue_fifo_order() {
    use did_hosting_common::server::store::KS_OUTBOUND_QUEUE;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_OUTBOUND_QUEUE).expect("outbound");

    // Outbox keys: outbox:<target_did>:<micros>:<uuid> — lex order gives FIFO.
    let target = "did:key:zTarget";
    ks.insert_raw(
        format!("outbox:{}:00000000000001:uuid-a", target),
        b"msg-1".to_vec(),
    )
    .await
    .expect("ins");
    ks.insert_raw(
        format!("outbox:{}:00000000000002:uuid-b", target),
        b"msg-2".to_vec(),
    )
    .await
    .expect("ins");
    ks.insert_raw(
        format!("outbox:{}:00000000000003:uuid-c", target),
        b"msg-3".to_vec(),
    )
    .await
    .expect("ins");

    // Prefix scan for target — results come in lex order (FIFO).
    let prefix = format!("outbox:{}:", target);
    let msgs = ks.prefix_iter_raw(prefix.as_bytes()).await.expect("prefix");
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[0].1, b"msg-1");
    assert_eq!(msgs[1].1, b"msg-2");
    assert_eq!(msgs[2].1, b"msg-3");

    // Consume first message (remove after delivery).
    let first_key = String::from_utf8(msgs[0].0.clone()).unwrap();
    ks.remove(first_key).await.expect("remove");
    let remaining = ks.prefix_iter_raw(prefix.as_bytes()).await.expect("prefix");
    assert_eq!(remaining.len(), 2);

    delete_test_table(&client, &table).await;
}

/// Control: domain and assignment keyspaces.
#[tokio::test]
async fn control_domain_and_assignment_ops() {
    use did_hosting_common::server::store::{KS_ASSIGNMENTS, KS_DOMAINS};

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;

    let domains = store.keyspace(KS_DOMAINS).expect("domains");
    let assignments = store.keyspace(KS_ASSIGNMENTS).expect("assignments");

    // Seed domains.
    domains
        .insert("example.com", &serde_json::json!({"domain": "example.com"}))
        .await
        .expect("ins");
    domains
        .insert("test.org", &serde_json::json!({"domain": "test.org"}))
        .await
        .expect("ins");

    // Seed assignments.
    assignments
        .insert("example.com", &serde_json::json!({"zone": "us-east-1"}))
        .await
        .expect("ins");
    assignments
        .insert("test.org", &serde_json::json!({"zone": "eu-west-1"}))
        .await
        .expect("ins");

    // List all domains.
    let all_domains = domains.prefix_iter_raw(b"").await.expect("prefix");
    assert_eq!(all_domains.len(), 2);

    // List all assignments.
    let all_assign = assignments.prefix_iter_raw(b"").await.expect("prefix");
    assert_eq!(all_assign.len(), 2);

    // Domains and assignments are separate keyspaces — no cross-contamination.
    assert!(
        !domains
            .contains_key("zone:us-east-1")
            .await
            .expect("contains")
    );

    delete_test_table(&client, &table).await;
}

/// Control: pending purges keyspace (soft-delete grace period).
#[tokio::test]
async fn control_pending_purges() {
    use did_hosting_common::server::store::KS_PENDING_PURGES;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_PENDING_PURGES).expect("pending_purges");

    // Queue DIDs for purge after grace period.
    ks.insert(
        "purge:alice:1704153600",
        &serde_json::json!({"mnemonic": "alice", "purge_after": 1704153600}),
    )
    .await
    .expect("ins");
    ks.insert(
        "purge:bob:1704240000",
        &serde_json::json!({"mnemonic": "bob", "purge_after": 1704240000}),
    )
    .await
    .expect("ins");

    // List all pending purges.
    let all = ks.prefix_iter_raw(b"purge:").await.expect("prefix");
    assert_eq!(all.len(), 2);

    // Process one purge.
    ks.remove("purge:alice:1704153600").await.expect("remove");
    let remaining = ks.prefix_iter_raw(b"purge:").await.expect("prefix");
    assert_eq!(remaining.len(), 1);

    delete_test_table(&client, &table).await;
}

/// Control: meta keyspace (migration markers).
#[tokio::test]
async fn control_meta_migration_markers() {
    use did_hosting_common::server::store::KS_META;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_META).expect("meta");

    // Write migration markers (idempotent, checked at startup).
    ks.insert(
        "migration:M-01",
        &serde_json::json!({"applied_at": 1704067200}),
    )
    .await
    .expect("ins");
    ks.insert(
        "migration:M-02",
        &serde_json::json!({"applied_at": 1704153600}),
    )
    .await
    .expect("ins");

    // Check if a migration has been applied.
    assert!(ks.contains_key("migration:M-01").await.expect("contains"));
    assert!(!ks.contains_key("migration:M-99").await.expect("contains"));

    // List all applied migrations.
    let all = ks.prefix_iter_raw(b"migration:").await.expect("prefix");
    assert_eq!(all.len(), 2);

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// webvh-witness access patterns
// (witness_keyspace_operations above covers the main pattern;
//  this adds ACL + session patterns used by the witness crate)
// ===========================================================================

/// Witness: ACL and session access (witness has its own ACL + sessions).
#[tokio::test]
async fn witness_acl_and_session_access() {
    use did_hosting_common::server::store::{KS_ACL, KS_SESSIONS};

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;

    let acl = store.keyspace(KS_ACL).expect("acl");
    let sessions = store.keyspace(KS_SESSIONS).expect("sessions");

    // Witness ACL entry (controls who can request witness proofs).
    acl.insert(
        "acl:did:key:zWitnessUser",
        &serde_json::json!({"role": "owner"}),
    )
    .await
    .expect("ins");

    // Witness session (auth token for witness API).
    sessions
        .insert(
            "session:ws1",
            &serde_json::json!({"user": "did:key:zWitnessUser"}),
        )
        .await
        .expect("ins");
    sessions
        .insert_raw("refresh:witness-tok", b"ws1".to_vec())
        .await
        .expect("ins");

    // Verify reads.
    let acl_entry: serde_json::Value = acl
        .get("acl:did:key:zWitnessUser")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(acl_entry["role"], "owner");

    let sess: serde_json::Value = sessions
        .get("session:ws1")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(sess["user"], "did:key:zWitnessUser");

    // Refresh token take (atomic).
    let tok = sessions
        .take_raw("refresh:witness-tok")
        .await
        .expect("take");
    assert_eq!(tok, Some(b"ws1".to_vec()));

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// webvh-watcher access patterns
// (watcher_sync_status_operations above covers sync status;
//  this adds the DID mirroring pattern: did: + content: in watcher's store)
// ===========================================================================

/// Watcher: mirrors DID records + content from remote server into its local store.
#[tokio::test]
async fn watcher_did_mirror_operations() {
    use did_hosting_common::server::store::KS_DIDS;

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace(KS_DIDS).expect("dids");

    // Watcher receives DID records from remote and inserts them locally.
    ks.insert(
        "did:remote-alice",
        &serde_json::json!({"did_id": "did:webvh:Qm:remote:alice", "state": "active"}),
    )
    .await
    .expect("ins");
    ks.insert_raw("content:remote-alice:log", b"remote-log-data\n".to_vec())
        .await
        .expect("ins");
    ks.insert_raw("content:remote-alice:witness", b"remote-witness".to_vec())
        .await
        .expect("ins");

    // Watcher reads mirrored data for serving.
    let did: serde_json::Value = ks
        .get("did:remote-alice")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(did["state"], "active");

    let log = ks
        .get_raw("content:remote-alice:log")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(log, b"remote-log-data\n");

    let witness = ks
        .get_raw("content:remote-alice:witness")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(witness, b"remote-witness");

    // Watcher updates mirrored data when remote version changes.
    ks.insert_raw("content:remote-alice:log", b"updated-log\n".to_vec())
        .await
        .expect("update");
    let updated = ks
        .get_raw("content:remote-alice:log")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(updated, b"updated-log\n");

    // Watcher removes mirrored data if DID is deactivated upstream.
    ks.remove("did:remote-alice").await.expect("remove");
    ks.remove("content:remote-alice:log").await.expect("remove");
    ks.remove("content:remote-alice:witness")
        .await
        .expect("remove");

    assert!(!ks.contains_key("did:remote-alice").await.expect("contains"));

    delete_test_table(&client, &table).await;
}

// ===========================================================================
// did-hosting-daemon access patterns
// (daemon combines all modules; this tests the cross-module scenario)
// ===========================================================================

/// Daemon: full lifecycle — bootstrap + runtime + cleanup in one table.
#[tokio::test]
async fn daemon_full_lifecycle_single_table() {
    use did_hosting_common::server::store::{
        KS_ACL, KS_DIDS, KS_DOMAINS, KS_META, KS_SESSIONS, KS_STATS, KS_TIMESERIES, KS_WITNESSES,
    };

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;

    let dids = store.keyspace(KS_DIDS).expect("dids");
    let acl = store.keyspace(KS_ACL).expect("acl");
    let domains = store.keyspace(KS_DOMAINS).expect("domains");
    let meta = store.keyspace(KS_META).expect("meta");
    let sessions = store.keyspace(KS_SESSIONS).expect("sessions");
    let stats = store.keyspace(KS_STATS).expect("stats");
    let ts = store.keyspace(KS_TIMESERIES).expect("ts");
    let witnesses = store.keyspace(KS_WITNESSES).expect("witnesses");

    // === Phase 1: Bootstrap (server + control) ===
    let mut batch = store.batch();
    // Server: root DID.
    batch
        .insert(
            &dids,
            "did:.well-known",
            &serde_json::json!({"did_id": "did:webvh:Qm:host:.well-known", "owner": "system"}),
        )
        .expect("b");
    batch.insert_raw(
        &dids,
        "content:.well-known:log",
        b"bootstrap-log\n".to_vec(),
    );
    batch.insert_raw(&dids, "owner:system:.well-known", b".well-known".to_vec());
    // Control: admin ACL.
    batch
        .insert(
            &acl,
            "acl:did:key:zAdmin",
            &serde_json::json!({"role": "admin"}),
        )
        .expect("b");
    // Control: domain seed.
    batch
        .insert(
            &domains,
            "example.com",
            &serde_json::json!({"domain": "example.com"}),
        )
        .expect("b");
    // Daemon: migration marker.
    batch
        .insert(&meta, "migration:M-01", &serde_json::json!({"done": true}))
        .expect("b");
    batch.commit().await.expect("bootstrap batch");

    // === Phase 2: Runtime — user resolves DID (server reads) ===
    let did_rec: serde_json::Value = dids
        .get("did:.well-known")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(did_rec["owner"], "system");
    let log = dids
        .get_raw("content:.well-known:log")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(log, b"bootstrap-log\n");

    // === Phase 3: Runtime — stats flush (daemon background task) ===
    stats
        .insert("stats:.well-known", &serde_json::json!({"resolves": 42}))
        .await
        .expect("ins");
    ts.insert(
        "ts:.well-known:1704067200",
        &serde_json::json!({"resolves": 42}),
    )
    .await
    .expect("ins");

    // === Phase 4: Runtime — witness attestation ===
    witnesses
        .insert(
            "witness:.well-known:v1",
            &serde_json::json!({"proof": "sig"}),
        )
        .await
        .expect("ins");
    let proof: serde_json::Value = witnesses
        .get("witness:.well-known:v1")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(proof["proof"], "sig");

    // === Phase 5: Runtime — user creates session (server/control auth) ===
    sessions
        .insert("session:s1", &serde_json::json!({"user": "did:key:zAdmin"}))
        .await
        .expect("ins");
    sessions
        .insert_raw("refresh:tok1", b"s1".to_vec())
        .await
        .expect("ins");
    // Verify session was stored.
    assert!(sessions.contains_key("session:s1").await.expect("c"));

    // === Phase 6: Cleanup (daemon background task) ===
    // Session cleanup.
    sessions.remove("session:s1").await.expect("rm");
    // Verify session is gone immediately after remove.
    assert!(!sessions.contains_key("session:s1").await.expect("c"));

    // Stats already written, just verify.
    let s: serde_json::Value = stats
        .get("stats:.well-known")
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(s["resolves"], 42);

    // === Verify: all keyspaces independently intact ===
    assert!(dids.contains_key("did:.well-known").await.expect("c"));
    assert!(acl.contains_key("acl:did:key:zAdmin").await.expect("c"));
    assert!(domains.contains_key("example.com").await.expect("c"));
    assert!(meta.contains_key("migration:M-01").await.expect("c"));
    assert!(
        witnesses
            .contains_key("witness:.well-known:v1")
            .await
            .expect("c")
    );

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// On-table contract (format freeze)
//
// The item shape is what a live deployment already stores, so it is a frozen
// contract: a change here is a data migration. These tests read the raw item
// through the AWS SDK (not through the backend) and write rows in today's
// shape for the backend to read, so neither direction can drift unnoticed.
// ---------------------------------------------------------------------------

/// Read one raw item (strongly consistent) as `(attribute name, value)` pairs.
async fn raw_item(
    client: &Client,
    table: &str,
    pk: &str,
    sk: &str,
) -> Option<std::collections::BTreeMap<String, AttributeValue>> {
    client
        .get_item()
        .table_name(table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S(sk.to_string()))
        .consistent_read(true)
        .send()
        .await
        .expect("raw get_item")
        .item
        .map(|m| m.into_iter().collect())
}

/// Write one raw item exactly as a deployment already running this backend
/// would have written it.
async fn put_raw_item(
    client: &Client,
    table: &str,
    pk: &str,
    sk: &str,
    attrs: &[(&str, AttributeValue)],
) {
    let mut req = client
        .put_item()
        .table_name(table)
        .item("pk", AttributeValue::S(pk.to_string()))
        .item("sk", AttributeValue::S(sk.to_string()));
    for (name, value) in attrs {
        req = req.item(*name, value.clone());
    }
    req.send().await.expect("raw put_item");
}

#[tokio::test]
async fn value_item_shape_is_pk_sk_val() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    ks.insert_raw("did:alice", b"payload".to_vec())
        .await
        .expect("insert");

    let item = raw_item(&client, &table, "dids", "did:alice")
        .await
        .expect("item exists under pk=keyspace, sk=key");
    assert_eq!(item.len(), 3, "exactly pk, sk, val: {item:?}");
    assert_eq!(item["pk"], AttributeValue::S("dids".into()));
    assert_eq!(item["sk"], AttributeValue::S("did:alice".into()));
    assert_eq!(
        item["val"],
        AttributeValue::B(Blob::new(b"payload".to_vec()))
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn batch_item_shape_matches_single_insert() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    let mut batch = store.batch();
    batch.insert_raw(&ks, "did:bob", b"b".to_vec());
    batch.commit().await.expect("commit");

    let item = raw_item(&client, &table, "dids", "did:bob")
        .await
        .expect("item");
    assert_eq!(item.len(), 3, "exactly pk, sk, val: {item:?}");
    assert_eq!(item["val"], AttributeValue::B(Blob::new(b"b".to_vec())));

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn counter_item_shape_is_pk_sk_cnt_without_val() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("meta").expect("keyspace");

    assert_eq!(ks.incr_raw("lockout:x").await.expect("incr"), 1);
    assert_eq!(ks.incr_raw("lockout:x").await.expect("incr"), 2);

    let item = raw_item(&client, &table, "meta", "lockout:x")
        .await
        .expect("item");
    assert_eq!(item.len(), 3, "exactly pk, sk, cnt: {item:?}");
    assert_eq!(item["cnt"], AttributeValue::N("2".into()));
    assert!(
        !item.contains_key("val"),
        "a counter item has no val: {item:?}"
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn rows_written_in_todays_shape_are_readable() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("dids").expect("keyspace");

    // A value row, an empty-value row, and a counter-only row, written the way
    // an already-deployed instance wrote them.
    put_raw_item(
        &client,
        &table,
        "dids",
        "did:legacy",
        &[("val", AttributeValue::B(Blob::new(b"old".to_vec())))],
    )
    .await;
    put_raw_item(
        &client,
        &table,
        "dids",
        "did:empty",
        &[("val", AttributeValue::B(Blob::new(Vec::new())))],
    )
    .await;
    put_raw_item(
        &client,
        &table,
        "dids",
        "lockout:old",
        &[("cnt", AttributeValue::N("5".into()))],
    )
    .await;

    assert_eq!(
        ks.get_raw("did:legacy").await.expect("get"),
        Some(b"old".to_vec())
    );
    assert_eq!(
        ks.get_raw("did:empty").await.expect("get"),
        Some(Vec::new())
    );
    assert!(ks.contains_key("did:legacy").await.expect("contains"));

    // A counter-only row is present but has no value; listings skip it.
    assert!(ks.contains_key("lockout:old").await.expect("contains"));
    assert_eq!(ks.get_raw("lockout:old").await.expect("get"), None);
    let listed: Vec<String> = ks
        .iter_all()
        .await
        .expect("iter")
        .into_iter()
        .map(|(k, _)| String::from_utf8(k).expect("utf8"))
        .collect();
    assert_eq!(
        listed,
        vec!["did:empty".to_string(), "did:legacy".to_string()]
    );

    // The counter continues from its stored value.
    assert_eq!(ks.incr_raw("lockout:old").await.expect("incr"), 6);

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// BatchOps — one batch is one atomic transaction, or it is refused
//
// DynamoDB's TransactWriteItems holds at most 100 operations and 4 MB, and a
// batch that needed several would not be atomic. The backend refuses it before
// writing anything, with a client-safe validation error, and never writes a
// key it had to alter to make it fit a string column.
// ---------------------------------------------------------------------------

/// Count the items stored under `keyspace` (strongly consistent).
async fn count_in(store: &Store, keyspace: &str) -> usize {
    store
        .keyspace(keyspace)
        .expect("keyspace")
        .iter_all()
        .await
        .expect("iter_all")
        .len()
}

#[tokio::test]
async fn batch_with_a_non_utf8_key_is_refused_and_writes_nothing() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("bulk").expect("keyspace");

    let mut batch = store.batch();
    batch.insert_raw(&ks, "ok:1", b"valid".to_vec());
    batch.insert_raw(&ks, vec![0xff, 0xfe], b"bad key".to_vec());
    let err = batch
        .commit()
        .await
        .expect_err("a non-UTF-8 key must be refused");
    assert!(
        matches!(err, AppError::Validation(_)),
        "client-safe error: {err:?}"
    );

    // Neither the bad key (under a replacement character) nor the valid op landed.
    assert_eq!(count_in(&store, "bulk").await, 0, "all-or-nothing");

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn batch_with_a_non_utf8_remove_is_refused_and_writes_nothing() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("bulk").expect("keyspace");
    ks.insert_raw("keep:me", b"v".to_vec()).await.expect("seed");

    let mut batch = store.batch();
    batch.remove(&ks, "keep:me");
    batch.remove(&ks, vec![0xc3, 0x28]);
    assert!(batch.commit().await.is_err());
    assert!(
        ks.contains_key("keep:me").await.expect("contains"),
        "valid remove must not apply"
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn batch_of_exactly_100_ops_commits() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("bulk").expect("keyspace");

    let mut batch = store.batch();
    for i in 0..100 {
        batch.insert_raw(&ks, format!("item:{i:03}"), b"v".to_vec());
    }
    batch.commit().await.expect("100 ops fit one transaction");
    assert_eq!(count_in(&store, "bulk").await, 100);

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn batch_of_101_ops_is_refused_and_writes_nothing() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("bulk").expect("keyspace");

    let mut batch = store.batch();
    for i in 0..101 {
        batch.insert_raw(&ks, format!("item:{i:03}"), b"v".to_vec());
    }
    let err = batch
        .commit()
        .await
        .expect_err("101 ops cannot be one transaction");
    assert!(
        matches!(err, AppError::Validation(_)),
        "client-safe error: {err:?}"
    );
    assert_eq!(count_in(&store, "bulk").await, 0, "no partial write");

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn batch_over_4_mib_is_refused_and_writes_nothing() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("bulk").expect("keyspace");

    // 14 x 300 KB = 4.2 MB: each item is under DynamoDB's 400 KB item limit,
    // the transaction is not.
    let mut batch = store.batch();
    for i in 0..14 {
        batch.insert_raw(&ks, format!("big:{i:02}"), vec![0u8; 300 * 1024]);
    }
    let err = batch
        .commit()
        .await
        .expect_err("over 4 MiB cannot be one transaction");
    assert!(
        matches!(err, AppError::Validation(_)),
        "client-safe error: {err:?}"
    );
    assert_eq!(count_in(&store, "bulk").await, 0, "no partial write");

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn batch_touching_one_key_twice_is_refused_with_a_clear_error() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("bulk").expect("keyspace");

    let mut batch = store.batch();
    batch.insert_raw(&ks, "dup", b"one".to_vec());
    batch.remove(&ks, "dup");
    let err = batch
        .commit()
        .await
        .expect_err("the same key twice is ambiguous");
    match err {
        AppError::Validation(msg) => assert!(msg.contains("same key"), "message: {msg}"),
        other => panic!("expected a validation error, got {other:?}"),
    }
    assert_eq!(count_in(&store, "bulk").await, 0);

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn batch_limits_report_the_transaction_ceiling() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;

    assert_eq!(
        store.batch_limits(),
        Some(BatchLimits {
            max_ops: 100,
            // 4 MiB less, per operation (x 100), the attribute names (7 bytes)
            // and the longest namespace plus its separator (33 bytes).
            max_bytes: 4 * 1024 * 1024 - 100 * (7 + 33),
        })
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn bulk_write_chunked_to_the_limits_commits_every_entry() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("bulk").expect("keyspace");

    // 250 small entries (more than two transactions by count) plus 30 large
    // ones (several transactions by bytes), as a restore would write them.
    let mut entries: Vec<(String, Vec<u8>)> = (0..250)
        .map(|i| (format!("small:{i:03}"), vec![1u8; 10]))
        .collect();
    entries.extend((0..30).map(|i| (format!("large:{i:02}"), vec![2u8; 300_000])));
    let sizes: Vec<usize> = entries
        .iter()
        .map(|(k, v)| ks.name.len() + k.len() + v.len())
        .collect();

    let chunks = chunk_ranges(store.batch_limits(), 1000, &sizes);
    assert!(chunks.len() > 3, "the input needs several transactions");
    for range in chunks {
        let mut batch = store.batch();
        for (key, value) in &entries[range] {
            batch.insert_raw(&ks, key.clone(), value.clone());
        }
        batch
            .commit()
            .await
            .expect("each planned chunk is one valid transaction");
    }

    assert_eq!(
        count_in(&store, "bulk").await,
        entries.len(),
        "nothing dropped"
    );

    delete_test_table(&client, &table).await;
}

// ---------------------------------------------------------------------------
// Key namespace: several stores on one table without sharing rows
//
// The daemon runs a main store and a witness store, and both use keyspaces
// named `acl` and `witnesses`. On one table, without a namespace, they would be
// the same rows (a revoke through the witness would edit the control plane's
// ACL). A namespace is part of the partition key; unset it is not.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn namespaced_rows_use_namespace_hash_keyspace_as_the_partition_key() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store_in(&endpoint, &table, Some("witness")).await;
    let ks = store.keyspace("acl").expect("keyspace");

    ks.insert_raw("acl:did:x", b"v".to_vec())
        .await
        .expect("insert");

    let item = raw_item(&client, &table, "witness#acl", "acl:did:x")
        .await
        .expect("stored under pk = namespace#keyspace");
    assert_eq!(item["pk"], AttributeValue::S("witness#acl".into()));
    assert_eq!(
        item["sk"],
        AttributeValue::S("acl:did:x".into()),
        "the key is not prefixed"
    );
    assert!(
        raw_item(&client, &table, "acl", "acl:did:x")
            .await
            .is_none(),
        "nothing under the bare keyspace"
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn a_namespaced_store_and_an_unnamespaced_store_share_a_table_without_sharing_rows() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    // The deployed shape: the main store keeps bare keyspaces (existing rows
    // stay addressable); the witness store gets a namespace.
    let main = open_store_in(&endpoint, &table, None).await;
    let witness = open_store_in(&endpoint, &table, Some("witness")).await;
    let main_acl = main.keyspace("acl").expect("keyspace");
    let witness_acl = witness.keyspace("acl").expect("keyspace");

    main_acl
        .insert_raw("acl:did:admin", b"admin".to_vec())
        .await
        .expect("seed");

    // The witness cannot see the control plane's ACL...
    assert_eq!(
        witness_acl.get_raw("acl:did:admin").await.expect("get"),
        None
    );
    assert!(
        !witness_acl
            .contains_key("acl:did:admin")
            .await
            .expect("contains")
    );
    assert!(witness_acl.iter_all().await.expect("iter").is_empty());

    // ...so a revoke on the witness side does not remove it from the main one.
    witness_acl
        .insert_raw("acl:did:admin", b"witness-copy".to_vec())
        .await
        .expect("insert");
    witness_acl
        .remove("acl:did:admin")
        .await
        .expect("revoke on the witness");
    assert_eq!(
        main_acl.get_raw("acl:did:admin").await.expect("get"),
        Some(b"admin".to_vec()),
        "the control plane's ACL entry is untouched"
    );

    // Atomic take and counters are isolated too.
    main_acl
        .insert_raw("tok", b"main".to_vec())
        .await
        .expect("insert");
    assert_eq!(witness_acl.take_raw("tok").await.expect("take"), None);
    assert_eq!(
        main_acl.take_raw("tok").await.expect("take"),
        Some(b"main".to_vec())
    );
    assert_eq!(main_acl.incr_raw("n").await.expect("incr"), 1);
    assert_eq!(
        witness_acl.incr_raw("n").await.expect("incr"),
        1,
        "independent counters"
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn namespaces_are_isolated_in_prefix_listings_and_batches() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let a = open_store_in(&endpoint, &table, Some("a")).await;
    let b = open_store_in(&endpoint, &table, Some("b")).await;
    let a_ks = a.keyspace("dids").expect("keyspace");
    let b_ks = b.keyspace("dids").expect("keyspace");

    let mut batch = a.batch();
    batch.insert_raw(&a_ks, "did:1", b"a1".to_vec());
    batch.insert_raw(&a_ks, "did:2", b"a2".to_vec());
    batch.commit().await.expect("commit a");
    b_ks.insert_raw("did:1", b"b1".to_vec())
        .await
        .expect("insert b");

    assert_eq!(a_ks.prefix_iter_raw("did:").await.expect("iter").len(), 2);
    assert_eq!(b_ks.prefix_iter_raw("did:").await.expect("iter").len(), 1);
    assert_eq!(
        b_ks.get_raw("did:1").await.expect("get"),
        Some(b"b1".to_vec())
    );
    assert_eq!(
        a_ks.get_raw("did:1").await.expect("get"),
        Some(b"a1".to_vec())
    );

    let mut batch = a.batch();
    batch.remove(&a_ks, "did:1");
    batch.commit().await.expect("remove in a");
    assert_eq!(
        b_ks.get_raw("did:1").await.expect("get"),
        Some(b"b1".to_vec()),
        "b untouched"
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn a_namespaced_store_does_not_see_existing_unnamespaced_rows() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    put_raw_item(
        &client,
        &table,
        "witnesses",
        "witness:w1",
        &[("val", AttributeValue::B(Blob::new(b"key".to_vec())))],
    )
    .await;

    let witness = open_store_in(&endpoint, &table, Some("witness")).await;
    let ks = witness.keyspace("witnesses").expect("keyspace");
    assert!(
        ks.iter_all().await.expect("iter").is_empty(),
        "starts from empty namespaced keyspaces"
    );

    // The legacy row is still there for a store without a namespace.
    let legacy = open_store_in(&endpoint, &table, None).await;
    assert_eq!(
        legacy
            .keyspace("witnesses")
            .expect("keyspace")
            .get_raw("witness:w1")
            .await
            .expect("get"),
        Some(b"key".to_vec())
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn a_keyspace_name_with_a_hash_is_refused() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    // "witness#acl" as a bare keyspace would be the same partition as keyspace
    // "acl" in namespace "witness".
    for namespace in [None, Some("witness")] {
        let store = open_store_in(&endpoint, &table, namespace).await;
        assert!(
            store.keyspace("witness#acl").is_err(),
            "namespace {namespace:?}"
        );
    }
    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn open_refuses_an_invalid_namespace_before_touching_dynamodb() {
    // No endpoint needed: validation fires before any AWS call.
    for bad in ["", "a#b", "has space", "caf\u{e9}", &"x".repeat(33)] {
        let config = StoreConfig {
            data_dir: PathBuf::from("/tmp"),
            dynamodb_table_name: Some("t".into()),
            dynamodb_key_namespace: Some(bad.to_string()),
            ..StoreConfig::default()
        };
        match Store::open(&config).await {
            Err(e) => assert!(
                format!("{e}").contains("dynamodb_key_namespace"),
                "error should name the field for {bad:?}: {e}"
            ),
            Ok(_) => panic!("namespace {bad:?} must be refused"),
        }
    }
}

// ---------------------------------------------------------------------------
// Startup probe: a misconfigured table fails at open, not on the first request
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_fails_clearly_when_the_table_does_not_exist() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let missing = format!("no_such_table_{}", std::process::id());
    // Make sure it really is absent.
    delete_test_table(&client, &missing).await;

    // `open_store_in` expects success, so open directly.
    unsafe {
        std::env::set_var("AWS_ENDPOINT_URL", &endpoint);
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }
    let config = StoreConfig {
        data_dir: PathBuf::from("/tmp"),
        dynamodb_table_name: Some(missing.clone()),
        dynamodb_region: Some("us-east-1".into()),
        ..StoreConfig::default()
    };
    match Store::open(&config).await {
        Err(AppError::Config(msg)) => {
            assert!(msg.contains(&missing), "names the table: {msg}");
            assert!(
                msg.contains("pk") && msg.contains("sk"),
                "says what the table needs: {msg}"
            );
        }
        Err(other) => panic!("expected a Config error, got {other:?}"),
        Ok(_) => panic!("a missing table must fail at open"),
    }
}

#[tokio::test]
async fn open_fails_clearly_when_the_table_has_the_wrong_key_schema() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    // A table keyed only by `id`, as someone might provision by mistake.
    let name = format!("wrong_schema_{}", std::process::id());
    delete_test_table(&client, &name).await;
    client
        .create_table()
        .table_name(&name)
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("id")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("id")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(1)
                .write_capacity_units(1)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create wrong-schema table");

    unsafe {
        std::env::set_var("AWS_ENDPOINT_URL", &endpoint);
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }
    let config = StoreConfig {
        data_dir: PathBuf::from("/tmp"),
        dynamodb_table_name: Some(name.clone()),
        dynamodb_region: Some("us-east-1".into()),
        ..StoreConfig::default()
    };
    let result = Store::open(&config).await;
    delete_test_table(&client, &name).await;
    match result {
        Err(AppError::Config(msg)) => assert!(msg.contains("key schema"), "{msg}"),
        Err(other) => panic!("expected a Config error, got {other:?}"),
        Ok(_) => panic!("a table with the wrong key schema must fail at open"),
    }
}

#[tokio::test]
async fn open_fails_clearly_when_the_key_roles_are_reversed() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    // Both attributes are the right names and types, but `sk` is the partition
    // key and `pk` the sort key. A `GetItem` names both and succeeds; only a
    // `Query` on `pk` shows the roles are wrong.
    let name = format!("reversed_roles_{}", std::process::id());
    delete_test_table(&client, &name).await;
    client
        .create_table()
        .table_name(&name)
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("sk")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("pk")
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("pk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("sk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(1)
                .write_capacity_units(1)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create reversed-roles table");

    unsafe {
        std::env::set_var("AWS_ENDPOINT_URL", &endpoint);
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }
    let config = StoreConfig {
        data_dir: PathBuf::from("/tmp"),
        dynamodb_table_name: Some(name.clone()),
        dynamodb_region: Some("us-east-1".into()),
        ..StoreConfig::default()
    };
    let result = Store::open(&config).await;
    delete_test_table(&client, &name).await;
    match result {
        Err(AppError::Config(msg)) => assert!(msg.contains("key schema"), "{msg}"),
        Err(other) => panic!("expected a Config error, got {other:?}"),
        Ok(_) => panic!("a table with reversed key roles must fail at open"),
    }
}

#[tokio::test]
async fn open_refuses_a_blank_table_name() {
    for blank in ["", "   "] {
        let config = StoreConfig {
            data_dir: PathBuf::from("/tmp"),
            dynamodb_table_name: Some(blank.to_string()),
            ..StoreConfig::default()
        };
        match Store::open(&config).await {
            Err(e) => assert!(
                format!("{e}").contains("dynamodb_table_name"),
                "{blank:?}: {e}"
            ),
            Ok(_) => panic!("table name {blank:?} must be refused"),
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoint policy: skip locally, fail in CI
// ---------------------------------------------------------------------------

#[test]
fn a_missing_endpoint_skips_locally_but_fails_in_ci() {
    assert_eq!(endpoint_or_skip(None, false), Ok(None));
    assert!(
        endpoint_or_skip(None, true).is_err(),
        "must not pass having tested nothing"
    );
    assert_eq!(
        endpoint_or_skip(Some("http://localhost:8000".into()), true),
        Ok(Some("http://localhost:8000".into()))
    );
    assert_eq!(
        endpoint_or_skip(Some("http://localhost:8000".into()), false),
        Ok(Some("http://localhost:8000".into()))
    );
}

// ---------------------------------------------------------------------------
// Prefix listing across Query pages, atomic take under contention, counters
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prefix_listing_follows_query_pages() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("big").expect("keyspace");

    // 30 x 100 KB = 3 MB across the prefix. A single Query returns at most
    // 1 MB, so listing it takes at least three pages. (Written one at a time:
    // a 3 MB write is more than one batch can hold.)
    for i in 0..30 {
        ks.insert_raw(format!("page:{i:02}"), vec![i as u8; 100 * 1024])
            .await
            .expect("insert");
    }
    ks.insert_raw("other:1", b"not in the prefix".to_vec())
        .await
        .expect("insert");

    let listed = ks.prefix_iter_raw("page:").await.expect("prefix");
    assert_eq!(listed.len(), 30, "every page of results is followed");
    let keys: Vec<_> = listed
        .iter()
        .map(|(k, _)| String::from_utf8(k.clone()).expect("utf8"))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "results stay in sort-key order across pages");
    assert!(
        listed.iter().all(|(_, v)| v.len() == 100 * 1024),
        "values intact"
    );

    assert_eq!(ks.iter_all().await.expect("iter").len(), 31);

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn concurrent_take_has_exactly_one_winner() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("sessions").expect("keyspace");
    ks.insert_raw("refresh:tok", b"session-1".to_vec())
        .await
        .expect("insert");

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let ks = ks.clone();
        tasks.push(tokio::spawn(async move {
            ks.take_raw("refresh:tok").await.expect("take")
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.expect("join") == Some(b"session-1".to_vec()) {
            winners += 1;
        }
    }
    assert_eq!(
        winners, 1,
        "a single-use token must be consumed exactly once"
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn a_counter_restarts_after_it_is_removed() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("meta").expect("keyspace");

    assert_eq!(ks.incr_raw("lockout:x").await.expect("incr"), 1);
    assert_eq!(ks.incr_raw("lockout:x").await.expect("incr"), 2);
    ks.remove("lockout:x").await.expect("remove");
    assert!(!ks.contains_key("lockout:x").await.expect("contains"));
    assert_eq!(
        ks.incr_raw("lockout:x").await.expect("incr"),
        1,
        "starts again from one"
    );

    delete_test_table(&client, &table).await;
}

#[tokio::test]
async fn writing_a_value_over_a_counter_replaces_the_item() {
    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;
    let ks = store.keyspace("meta").expect("keyspace");

    // A key is either a value or a counter. Writing a value replaces the whole
    // item, so the counter is gone and the value is readable.
    assert_eq!(ks.incr_raw("k").await.expect("incr"), 1);
    ks.insert_raw("k", b"now a value".to_vec())
        .await
        .expect("insert");
    assert_eq!(
        ks.get_raw("k").await.expect("get"),
        Some(b"now a value".to_vec())
    );
    let item = raw_item(&client, &table, "meta", "k").await.expect("item");
    assert!(
        !item.contains_key("cnt"),
        "the counter attribute is replaced: {item:?}"
    );

    delete_test_table(&client, &table).await;
}

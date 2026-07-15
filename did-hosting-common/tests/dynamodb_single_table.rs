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
use aws_sdk_dynamodb::types::{
    AttributeDefinition, KeySchemaElement, KeyType, ProvisionedThroughput, ScalarAttributeType,
};
use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::store::Store;

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
        ..StoreConfig::default()
    };

    Store::open(&config).await.expect("open single-table store")
}

/// Macro that skips the test when `DYNAMODB_SINGLE_TEST_ENDPOINT` is
/// not set, avoiding a hard failure in environments without local
/// DynamoDB.
macro_rules! require_endpoint {
    () => {
        match local_endpoint() {
            Some(ep) => ep,
            None => {
                eprintln!(
                    "SKIP: DYNAMODB_SINGLE_TEST_ENDPOINT not set — \
                     skipping single-table DynamoDB test"
                );
                return;
            }
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
    assert!(sessions
        .contains_key("k1")
        .await
        .expect("contains sessions"));

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

    let got = ks
        .get_raw("content:bigdid:log")
        .await
        .expect("get big");
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

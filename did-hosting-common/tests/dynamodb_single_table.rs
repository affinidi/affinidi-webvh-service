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
        KS_ACL, KS_ASSIGNMENTS, KS_DIDS, KS_DOMAINS, KS_META, KS_OUTBOUND_QUEUE,
        KS_PENDING_PURGES, KS_REGISTRY, KS_SESSIONS, KS_STATS, KS_TIMESERIES, KS_WITNESSES,
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
    ks.insert("watcher_sync:alice", &sync_a).await.expect("insert");
    ks.insert("watcher_sync:bob", &sync_b).await.expect("insert");

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
    batch.insert(
        &dids,
        "did:.well-known",
        &serde_json::json!({"did_id": "did:webvh:QmABC:host:.well-known", "owner": "system"}),
    ).expect("batch did");

    // DID log content (raw bytes).
    batch.insert_raw(&dids, "content:.well-known:log", b"jsonl-entry-here".to_vec());

    // Owner reverse index.
    batch.insert_raw(&dids, "owner:system:.well-known", b".well-known".to_vec());

    // ACL entry.
    batch.insert(
        &acl,
        "acl:did:key:z6MkAdmin",
        &serde_json::json!({"role": "admin", "max_dids": 100}),
    ).expect("batch acl");

    // Domain seed.
    batch.insert(
        &domains,
        "domain:example.com",
        &serde_json::json!({"domain": "example.com", "owner": "system"}),
    ).expect("batch domain");

    batch.commit().await.expect("bootstrap batch commit");

    // Verify everything landed in the correct keyspace.
    let did_record: Option<serde_json::Value> = dids.get("did:.well-known").await.expect("get");
    assert_eq!(did_record.unwrap()["did_id"], "did:webvh:QmABC:host:.well-known");

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

    let log = ks.get_raw("content:alice:log").await.expect("get").expect("exists");
    assert_eq!(log, b"jsonl-signed-entry\n");

    let witness = ks.get_raw("content:alice:witness").await.expect("get").expect("exists");
    assert_eq!(witness, b"witness-proof-json");

    let owner = ks.get_raw("owner:did:key:zAdmin:alice").await.expect("get").expect("exists");
    assert_eq!(owner, b"alice");

    // Prefix scan for owner's DIDs.
    let owner_dids = ks.prefix_iter_raw(b"owner:did:key:zAdmin:").await.expect("prefix");
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
    assert!(!ks.contains_key("content:alice:log").await.expect("contains"));

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
    ks.insert("did:alice", &serde_json::json!({"state": "active"})).await.expect("ins");
    ks.insert("did:bob", &serde_json::json!({"state": "active"})).await.expect("ins");
    ks.insert("watcher_sync:alice", &serde_json::json!({"version": 3})).await.expect("ins");
    ks.insert("watcher_sync:bob", &serde_json::json!({"version": 1})).await.expect("ins");
    ks.insert_raw("content:alice:log", b"log".to_vec()).await.expect("ins");
    ks.insert_raw("owner:system:alice", b"alice".to_vec()).await.expect("ins");

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
    stats.insert("stats:alice", &serde_json::json!({"resolves": 42, "updates": 5})).await.expect("ins");
    stats.insert("stats:bob", &serde_json::json!({"resolves": 10, "updates": 1})).await.expect("ins");

    // prefix_iter_raw to list all stats (used by stats seeding at startup).
    let all_stats = stats.prefix_iter_raw(b"stats:").await.expect("prefix");
    assert_eq!(all_stats.len(), 2);

    // Timeseries: buckets keyed as ts:<mnemonic>:<epoch>.
    ts.insert("ts:alice:1704067200", &serde_json::json!({"resolves": 10})).await.expect("ins");
    ts.insert("ts:alice:1704153600", &serde_json::json!({"resolves": 15})).await.expect("ins");
    ts.insert("ts:bob:1704067200", &serde_json::json!({"resolves": 5})).await.expect("ins");

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
    ks.insert_raw("refresh:tok-abc", b"s1".to_vec()).await.expect("ins");

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
    ks.insert("acl:did:key:zAdmin", &serde_json::json!({"role": "admin", "max_dids": 100})).await.expect("ins");
    ks.insert("acl:did:key:zOwner", &serde_json::json!({"role": "owner", "max_dids": 10})).await.expect("ins");
    ks.insert("acl:did:key:zService", &serde_json::json!({"role": "service"})).await.expect("ins");

    // Get specific ACL.
    let admin: serde_json::Value = ks.get("acl:did:key:zAdmin").await.expect("get").expect("exists");
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
    ks.insert("instance:srv-1", &serde_json::json!({"url": "https://srv1.example.com", "last_seen": 1704067200})).await.expect("ins");
    ks.insert("instance:srv-2", &serde_json::json!({"url": "https://srv2.example.com", "last_seen": 1704067200})).await.expect("ins");

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
    ).await.expect("ins");
    ks.insert_raw(
        format!("outbox:{}:00000000000002:uuid-b", target),
        b"msg-2".to_vec(),
    ).await.expect("ins");
    ks.insert_raw(
        format!("outbox:{}:00000000000003:uuid-c", target),
        b"msg-3".to_vec(),
    ).await.expect("ins");

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
    use did_hosting_common::server::store::{KS_DOMAINS, KS_ASSIGNMENTS};

    let endpoint = require_endpoint!();
    let client = local_client(&endpoint).await;
    let table = create_test_table(&client).await;
    let store = open_store(&endpoint, &table).await;

    let domains = store.keyspace(KS_DOMAINS).expect("domains");
    let assignments = store.keyspace(KS_ASSIGNMENTS).expect("assignments");

    // Seed domains.
    domains.insert("example.com", &serde_json::json!({"domain": "example.com"})).await.expect("ins");
    domains.insert("test.org", &serde_json::json!({"domain": "test.org"})).await.expect("ins");

    // Seed assignments.
    assignments.insert("example.com", &serde_json::json!({"zone": "us-east-1"})).await.expect("ins");
    assignments.insert("test.org", &serde_json::json!({"zone": "eu-west-1"})).await.expect("ins");

    // List all domains.
    let all_domains = domains.prefix_iter_raw(b"").await.expect("prefix");
    assert_eq!(all_domains.len(), 2);

    // List all assignments.
    let all_assign = assignments.prefix_iter_raw(b"").await.expect("prefix");
    assert_eq!(all_assign.len(), 2);

    // Domains and assignments are separate keyspaces — no cross-contamination.
    assert!(!domains.contains_key("zone:us-east-1").await.expect("contains"));

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
    ks.insert("purge:alice:1704153600", &serde_json::json!({"mnemonic": "alice", "purge_after": 1704153600})).await.expect("ins");
    ks.insert("purge:bob:1704240000", &serde_json::json!({"mnemonic": "bob", "purge_after": 1704240000})).await.expect("ins");

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
    ks.insert("migration:M-01", &serde_json::json!({"applied_at": 1704067200})).await.expect("ins");
    ks.insert("migration:M-02", &serde_json::json!({"applied_at": 1704153600})).await.expect("ins");

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
    acl.insert("acl:did:key:zWitnessUser", &serde_json::json!({"role": "owner"})).await.expect("ins");

    // Witness session (auth token for witness API).
    sessions.insert("session:ws1", &serde_json::json!({"user": "did:key:zWitnessUser"})).await.expect("ins");
    sessions.insert_raw("refresh:witness-tok", b"ws1".to_vec()).await.expect("ins");

    // Verify reads.
    let acl_entry: serde_json::Value = acl.get("acl:did:key:zWitnessUser").await.expect("get").expect("exists");
    assert_eq!(acl_entry["role"], "owner");

    let sess: serde_json::Value = sessions.get("session:ws1").await.expect("get").expect("exists");
    assert_eq!(sess["user"], "did:key:zWitnessUser");

    // Refresh token take (atomic).
    let tok = sessions.take_raw("refresh:witness-tok").await.expect("take");
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
    ks.insert("did:remote-alice", &serde_json::json!({"did_id": "did:webvh:Qm:remote:alice", "state": "active"})).await.expect("ins");
    ks.insert_raw("content:remote-alice:log", b"remote-log-data\n".to_vec()).await.expect("ins");
    ks.insert_raw("content:remote-alice:witness", b"remote-witness".to_vec()).await.expect("ins");

    // Watcher reads mirrored data for serving.
    let did: serde_json::Value = ks.get("did:remote-alice").await.expect("get").expect("exists");
    assert_eq!(did["state"], "active");

    let log = ks.get_raw("content:remote-alice:log").await.expect("get").expect("exists");
    assert_eq!(log, b"remote-log-data\n");

    let witness = ks.get_raw("content:remote-alice:witness").await.expect("get").expect("exists");
    assert_eq!(witness, b"remote-witness");

    // Watcher updates mirrored data when remote version changes.
    ks.insert_raw("content:remote-alice:log", b"updated-log\n".to_vec()).await.expect("update");
    let updated = ks.get_raw("content:remote-alice:log").await.expect("get").expect("exists");
    assert_eq!(updated, b"updated-log\n");

    // Watcher removes mirrored data if DID is deactivated upstream.
    ks.remove("did:remote-alice").await.expect("remove");
    ks.remove("content:remote-alice:log").await.expect("remove");
    ks.remove("content:remote-alice:witness").await.expect("remove");

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
    batch.insert(&dids, "did:.well-known", &serde_json::json!({"did_id": "did:webvh:Qm:host:.well-known", "owner": "system"})).expect("b");
    batch.insert_raw(&dids, "content:.well-known:log", b"bootstrap-log\n".to_vec());
    batch.insert_raw(&dids, "owner:system:.well-known", b".well-known".to_vec());
    // Control: admin ACL.
    batch.insert(&acl, "acl:did:key:zAdmin", &serde_json::json!({"role": "admin"})).expect("b");
    // Control: domain seed.
    batch.insert(&domains, "example.com", &serde_json::json!({"domain": "example.com"})).expect("b");
    // Daemon: migration marker.
    batch.insert(&meta, "migration:M-01", &serde_json::json!({"done": true})).expect("b");
    batch.commit().await.expect("bootstrap batch");

    // === Phase 2: Runtime — user resolves DID (server reads) ===
    let did_rec: serde_json::Value = dids.get("did:.well-known").await.expect("get").expect("exists");
    assert_eq!(did_rec["owner"], "system");
    let log = dids.get_raw("content:.well-known:log").await.expect("get").expect("exists");
    assert_eq!(log, b"bootstrap-log\n");

    // === Phase 3: Runtime — stats flush (daemon background task) ===
    stats.insert("stats:.well-known", &serde_json::json!({"resolves": 42})).await.expect("ins");
    ts.insert("ts:.well-known:1704067200", &serde_json::json!({"resolves": 42})).await.expect("ins");

    // === Phase 4: Runtime — witness attestation ===
    witnesses.insert("witness:.well-known:v1", &serde_json::json!({"proof": "sig"})).await.expect("ins");
    let proof: serde_json::Value = witnesses.get("witness:.well-known:v1").await.expect("get").expect("exists");
    assert_eq!(proof["proof"], "sig");

    // === Phase 5: Runtime — user creates session (server/control auth) ===
    sessions.insert("session:s1", &serde_json::json!({"user": "did:key:zAdmin"})).await.expect("ins");
    sessions.insert_raw("refresh:tok1", b"s1".to_vec()).await.expect("ins");

    // === Phase 6: Cleanup (daemon background task) ===
    // Session cleanup.
    sessions.remove("session:s1").await.expect("rm");
    // Stats already written, just verify.
    let s: serde_json::Value = stats.get("stats:.well-known").await.expect("get").expect("exists");
    assert_eq!(s["resolves"], 42);

    // === Verify: all keyspaces independently intact ===
    assert!(dids.contains_key("did:.well-known").await.expect("c"));
    assert!(acl.contains_key("acl:did:key:zAdmin").await.expect("c"));
    assert!(domains.contains_key("example.com").await.expect("c"));
    assert!(meta.contains_key("migration:M-01").await.expect("c"));
    assert!(witnesses.contains_key("witness:.well-known:v1").await.expect("c"));
    assert!(!sessions.contains_key("session:s1").await.expect("c")); // cleaned up

    delete_test_table(&client, &table).await;
}

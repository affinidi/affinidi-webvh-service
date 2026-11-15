//! The shared store conformance suite (`server::store::conformance`) against
//! a real Redis, DynamoDB, Firestore or Cosmos DB, whichever backend this
//! build enables. (fjall runs the same suite in its unit tests.)
//!
//! Opt-in: each test prints a skip line and passes unless its environment
//! variable points it at a server or an emulator. Every run opens its
//! keyspaces under a fresh namespace, so runs can share one.
//!
//! ```sh
//! # Redis
//! docker run --rm -d -p 6379:6379 redis:7
//! WEBVH_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test -p did-hosting-common \
//!   --no-default-features --features server-core,store-redis,test-support \
//!   --test store_conformance
//!
//! # DynamoDB Local (any credentials and region do)
//! docker run --rm -d -p 8000:8000 amazon/dynamodb-local
//! WEBVH_TEST_DYNAMODB=1 AWS_ENDPOINT_URL=http://127.0.0.1:8000 \
//!   AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
//!   cargo test -p did-hosting-common --no-default-features \
//!   --features server-core,store-dynamodb,test-support --test store_conformance
//!
//! # Firestore emulator
//! gcloud emulators firestore start --host-port=127.0.0.1:8080
//! FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 WEBVH_TEST_FIRESTORE_PROJECT=demo-webvh \
//!   cargo test -p did-hosting-common --no-default-features \
//!   --features server-core,store-firestore,test-support --test store_conformance
//!
//! # Cosmos DB emulator
//! WEBVH_TEST_COSMOSDB_CONNECTION_STRING='AccountEndpoint=...;AccountKey=...' \
//!   cargo test -p did-hosting-common --no-default-features \
//!   --features server-core,store-cosmosdb,test-support --test store_conformance
//! ```

#![cfg(all(
    feature = "test-support",
    any(
        feature = "store-redis",
        feature = "store-dynamodb",
        feature = "store-firestore",
        feature = "store-cosmosdb"
    )
))]

use did_hosting_common::server::config::StoreConfig;
use did_hosting_common::server::store::{Store, conformance};

/// The store under test, or `None` (skip) when the environment names none.
fn configured() -> Option<StoreConfig> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let mut config = StoreConfig::default();
    #[cfg(feature = "store-redis")]
    {
        config.redis_url = Some(var("WEBVH_TEST_REDIS_URL")?);
    }
    #[cfg(feature = "store-dynamodb")]
    {
        var("WEBVH_TEST_DYNAMODB")?;
        config.dynamodb_table_prefix = Some("conformance".into());
        config.dynamodb_region = var("AWS_REGION").or(Some("us-east-1".into()));
    }
    #[cfg(feature = "store-firestore")]
    {
        config.firestore_project = Some(var("WEBVH_TEST_FIRESTORE_PROJECT")?);
    }
    #[cfg(feature = "store-cosmosdb")]
    {
        config.cosmosdb_connection_string = Some(var("WEBVH_TEST_COSMOSDB_CONNECTION_STRING")?);
        config.cosmosdb_database = Some("conformance".into());
    }
    Some(config)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backend_meets_the_store_contract() {
    let Some(config) = configured() else {
        eprintln!("skipping: no store configured for this backend (see the module docs)");
        return;
    };
    let store = Store::open(&config).await.expect("open the store");
    let ns = conformance::namespace();
    eprintln!("store conformance under namespace {ns}");
    conformance::run(&store, &ns).await;
}

/// A database written before the Redis index existed still lists its rows:
/// opening the store indexes them, once.
#[cfg(feature = "store-redis")]
#[tokio::test]
async fn redis_indexes_rows_written_before_the_index() {
    use redis::AsyncCommands;

    let Some(config) = configured() else {
        eprintln!("skipping: WEBVH_TEST_REDIS_URL is not set");
        return;
    };
    let client = redis::Client::open(config.redis_url.clone().unwrap()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let ns = conformance::namespace();
    // A row as the previous release wrote it: the value, no index entry.
    let legacy = format!("dids:{ns}:legacy");
    let _: () = conn.set(&legacy, "old").await.unwrap();
    let _: () = conn.del("__index_version__").await.unwrap();

    let store = Store::open(&config).await.unwrap();
    let ks = store.keyspace("dids").unwrap();
    let prefix = format!("{ns}:");
    assert_eq!(
        ks.prefix_iter_raw(prefix.clone()).await.unwrap(),
        vec![(format!("{ns}:legacy").into_bytes(), b"old".to_vec())]
    );
    assert_eq!(ks.prefix_count(prefix.clone()).await.unwrap(), 1);
    let marker: Option<String> = conn.get("__index_version__").await.unwrap();
    assert_eq!(marker.as_deref(), Some("1"), "indexed once, then marked");

    ks.remove(format!("{ns}:legacy")).await.unwrap();
    assert_eq!(ks.prefix_count(prefix).await.unwrap(), 0);
}

/// A database none of whose rows belongs to a known keyspace (another app's
/// keys, or only other namespaces') still opens: no `SCAN` batch has
/// anything to index, and an empty pipeline must not be sent (#470).
#[cfg(feature = "store-redis")]
#[tokio::test]
async fn redis_opens_a_database_with_no_rows_to_index() {
    use redis::AsyncCommands;

    let Some(mut config) = configured() else {
        eprintln!("skipping: WEBVH_TEST_REDIS_URL is not set");
        return;
    };
    // A database of its own (15), so what is in it is known exactly.
    let mut url = url::Url::parse(config.redis_url.as_deref().unwrap()).unwrap();
    url.set_path("/15");
    config.redis_url = Some(url.to_string());
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
    for n in 0..3 {
        let _: () = conn.set(format!("other_app:{n}"), "x").await.unwrap();
    }

    let store = Store::open(&config)
        .await
        .expect("a database with nothing to index opens");
    let marker: Option<String> = conn.get("__index_version__").await.unwrap();
    assert_eq!(marker.as_deref(), Some("1"));
    let dids = store.keyspace("dids").unwrap();
    assert_eq!(dids.prefix_count("").await.unwrap(), 0);
    let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();
}

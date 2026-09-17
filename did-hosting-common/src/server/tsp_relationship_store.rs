//! Durable TSP relationship store — the backend for Rev 3 §7.2.2 persistence.
//!
//! A node gates inbound TSP application traffic on holding a relationship with
//! the sender (§7.2.2). The messaging SDK's default relationship store is
//! in-memory, so a restart wipes every relationship and the node then silently
//! drops each peer's traffic — the peers still hold the relationship the
//! restarted node forgot — until a re-handshake. Persisting the store across
//! restarts is what closes that window (design note `tsp-relationship-recovery`,
//! D1).
//!
//! ## What this crate supplies, and what it does not
//!
//! The SDK's [`PersistentRelationshipStore`] already owns *all* of the
//! relationship semantics: record encoding, the per-facet key layout
//! (`state`/`digests`/`reply-path`/`capability`), and the defaults. A consumer
//! supplies only a durable **byte** backend — the three-method
//! [`RelationshipKv`] (`get`/`put`/`delete`). This module is exactly that
//! backend, over one of webvh's storage keyspaces.
//!
//! It is **backend-agnostic on purpose**: it goes through [`KeyspaceHandle`]'s
//! raw byte ops rather than any one engine, so it persists on every
//! `StorageBackend` webvh supports (fjall, DynamoDB, Firestore, CosmosDB, …),
//! not just the fjall default. The keys are opaque bytes minted by the SDK, so
//! this layer never interprets them.
//!
//! ## Wiring (pending facade support)
//!
//! [`build_relationship_store`] returns the `Arc<dyn RelationshipStore>` to hand
//! to the messaging service so it injects it into the per-listener ATM. That
//! injection point (`ListenerConfig::with_relationship_store`) lands in
//! `affinidi-messaging-didcomm-service` 0.11.0; until then this builder has no
//! call site and is exercised only by its test. See `docs/tsp-transport.md`.

use std::sync::Arc;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::tsp::{
    PersistentRelationshipStore, RelationshipKv, RelationshipStore,
};
use async_trait::async_trait;

use crate::server::error::AppError;
use crate::server::store::{KS_TSP_RELATIONSHIPS, KeyspaceHandle, Store};

/// A [`RelationshipKv`] byte backend over a webvh storage keyspace.
///
/// Holds a [`KeyspaceHandle`] (an `Arc<dyn KeyspaceOps>` inside), so it is cheap
/// to construct and works against whatever backend the node is configured with.
pub struct KeyspaceRelationshipKv {
    ks: KeyspaceHandle,
}

impl KeyspaceRelationshipKv {
    pub fn new(ks: KeyspaceHandle) -> Self {
        Self { ks }
    }
}

/// The SDK's byte backend reports failures as [`ATMError`]; webvh's keyspace
/// reports [`AppError`]. Fold one into the other, tagging the origin so a
/// store-level failure is legible in the messaging service's logs.
fn to_atm(e: AppError) -> ATMError {
    ATMError::SDKError(format!("tsp relationship store: {e}"))
}

#[async_trait]
impl RelationshipKv for KeyspaceRelationshipKv {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError> {
        self.ks.get_raw(key.to_vec()).await.map_err(to_atm)
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ATMError> {
        self.ks
            .insert_raw(key.to_vec(), value.to_vec())
            .await
            .map_err(to_atm)
    }

    async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
        self.ks.remove(key.to_vec()).await.map_err(to_atm)
    }
}

/// Build the durable TSP relationship store to inject into the messaging
/// service (facade 0.11.0's `ListenerConfig::with_relationship_store`).
///
/// Opens the [`KS_TSP_RELATIONSHIPS`] keyspace and wraps it in the SDK's
/// [`PersistentRelationshipStore`], which owns record encoding and per-facet
/// keying; this crate supplies only the raw byte backend
/// ([`KeyspaceRelationshipKv`]). Do **not** implement [`RelationshipStore`]
/// directly — the persistent wrapper already does, and re-deriving its key
/// layout here would risk divergence from the SDK.
pub fn build_relationship_store(store: &Store) -> Result<Arc<dyn RelationshipStore>, AppError> {
    let ks = store.keyspace(KS_TSP_RELATIONSHIPS)?;
    let kv = KeyspaceRelationshipKv::new(ks);
    Ok(Arc::new(PersistentRelationshipStore::new(kv)))
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::config::StoreConfig;

    /// The durability contract of the byte backend: a value written under a key
    /// reads back byte-for-byte, an absent key yields `None`, and a delete
    /// removes it — the three properties `PersistentRelationshipStore` relies on
    /// to survive a restart. Exercised directly against a real (fjall) keyspace
    /// so the round-trip goes through the actual `KeyspaceOps` impl, not a mock.
    #[tokio::test]
    async fn byte_backend_round_trips_through_a_real_keyspace() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store_config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.expect("open store");
        let kv = KeyspaceRelationshipKv::new(
            store.keyspace(KS_TSP_RELATIONSHIPS).expect("open keyspace"),
        );

        let key = b"tsp-rel/v1/\x01peer".as_slice();
        let value = b"opaque-sdk-encoded-record".as_slice();

        assert_eq!(kv.get(key).await.expect("get absent"), None);
        kv.put(key, value).await.expect("put");
        assert_eq!(
            kv.get(key).await.expect("get present").as_deref(),
            Some(value),
            "a stored value must read back byte-for-byte"
        );
        kv.delete(key).await.expect("delete");
        assert_eq!(
            kv.get(key).await.expect("get after delete"),
            None,
            "a deleted key must be absent"
        );
        // Deleting an absent key is not an error (RelationshipKv contract).
        kv.delete(key).await.expect("delete absent is a no-op");

        // And the builder wires keyspace -> byte backend -> PersistentRelationshipStore
        // end to end without panicking.
        let _store: Arc<dyn RelationshipStore> =
            build_relationship_store(&store).expect("build relationship store");
    }
}

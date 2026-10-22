//! Durable did:scid version floors for the identities this service authorises
//! (VTI-KEY-162).
//!
//! A did:scid identity is its bare DID; the `?src=` it is presented with is the
//! presenter's choice. did:webvh verification already stops a host the log
//! never named from serving it, but a portable log that has moved still names
//! its former host in its early entries, so whoever holds that host later can
//! serve the pre-move log — with keys its controller has since rotated away —
//! under the same did:scid. The resolver refuses a log older than one it has
//! verified, and checks an unknown source against the known ones; this module
//! makes what it has verified survive a restart for every did:scid that holds
//! authority here.
//!
//! **Which identities.** An identity is *authorised* when it has an ACL entry
//! (`acl:<did>` in [`KS_ACL`]), owns a hosted DID (`owner:<did>:` in
//! [`KS_DIDS`]), or was named by the process itself through
//! [`ScidFloorKeeper::authorise`] (an edge server's control plane DID). A
//! did:scid that merely presented itself is not persisted: anyone can mint one,
//! so persisting them would let a stranger grow the store.
//!
//! **When.** The resolver's listener hands each changed record to a bounded
//! channel, drained by one writer task, which persists it if the identity is
//! authorised and the record differs from what is stored. The listener never
//! blocks: a full channel drops the event, and a periodic sweep of the
//! resolver's records catches it, along with an identity whose record was
//! verified before it was granted authority.
//!
//! **Removal.** Revoking an ACL entry or transferring a DID leaves the stored
//! record. It confers nothing on its own — authorisation is decided by the ACL
//! and ownership records — and keeping it means a later re-grant starts from
//! the floor already verified rather than from nothing.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::network_resolvers::ScidSourceRecord;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::error::AppError;
use super::store::{KS_ACL, KS_DIDS, KS_SCID_FLOORS, KeyspaceHandle, Store};

/// Key prefix of a persisted floor in [`KS_SCID_FLOORS`].
pub const FLOOR_PREFIX: &str = "scid_floor:";

/// How many changed records may wait for the writer before new ones are
/// dropped (and left to the next sweep).
const CHANNEL_CAPACITY: usize = 256;

/// How often the writer sweeps the resolver's records.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

fn floor_key(did: &str) -> String {
    format!("{FLOOR_PREFIX}{}", crate::scid::identity(did))
}

/// Every persisted floor.
pub async fn load_floors(ks: &KeyspaceHandle) -> Result<Vec<ScidSourceRecord>, AppError> {
    let mut out = Vec::new();
    for (key, value) in ks.prefix_iter_raw(FLOOR_PREFIX).await? {
        match serde_json::from_slice::<ScidSourceRecord>(&value) {
            Ok(record) => out.push(record),
            Err(e) => warn!(
                key = %String::from_utf8_lossy(&key),
                "skipping an unreadable did:scid floor: {e}"
            ),
        }
    }
    Ok(out)
}

/// Persists `record` under its identity's bare DID, unless the stored one is
/// identical. Returns whether it wrote.
pub async fn store_floor(ks: &KeyspaceHandle, record: &ScidSourceRecord) -> Result<bool, AppError> {
    let record = ScidSourceRecord {
        did: crate::scid::identity(&record.did),
        ..record.clone()
    };
    let key = floor_key(&record.did);
    if ks.get::<ScidSourceRecord>(key.clone()).await? == Some(record.clone()) {
        return Ok(false);
    }
    ks.insert(key, &record).await?;
    Ok(true)
}

/// Keeps the floors of authorised did:scid identities in the store, for one
/// resolver.
pub struct ScidFloorKeeper {
    floors: KeyspaceHandle,
    acl: KeyspaceHandle,
    dids: KeyspaceHandle,
    /// Bare DIDs the process authorises outside the ACL (e.g. a control plane).
    named: Mutex<HashSet<String>>,
}

impl ScidFloorKeeper {
    /// Seeds `resolver` with every persisted floor, then keeps the floors of
    /// authorised identities current. Call before the service accepts
    /// requests, so the first resolution of an authorised did:scid already
    /// knows its floor.
    pub async fn install(
        resolver: &DIDCacheClient,
        store: &Store,
    ) -> Result<Arc<ScidFloorKeeper>, AppError> {
        let keeper = Arc::new(ScidFloorKeeper {
            floors: store.keyspace(KS_SCID_FLOORS)?,
            acl: store.keyspace(KS_ACL)?,
            dids: store.keyspace(KS_DIDS)?,
            named: Mutex::new(HashSet::new()),
        });

        let book = resolver.scid_sources();
        let persisted = load_floors(&keeper.floors).await?;
        let seeded = persisted.iter().filter(|r| book.seed(r)).count();
        if seeded > 0 {
            info!(seeded, "did:scid floors seeded from the store");
        }

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        book.set_listener(Arc::new(move |record: &ScidSourceRecord| {
            if tx.try_send(record.clone()).is_err() {
                debug!(did = %record.did, "did:scid floor event dropped; the sweep will catch it");
            }
        }));
        tokio::spawn(keeper.clone().run(rx, resolver.clone()));
        Ok(keeper)
    }

    /// Treats `did` as authorised here although it has no ACL entry or
    /// ownership record — for an identity the process trusts by configuration.
    pub fn authorise(&self, did: &str) {
        if did.starts_with("did:scid:")
            && let Ok(mut named) = self.named.lock()
        {
            named.insert(crate::scid::identity(did));
        }
    }

    /// Whether the bare did:scid `did` holds authority here.
    pub async fn is_authorised(&self, did: &str) -> Result<bool, AppError> {
        let did = crate::scid::identity(did);
        if self.named.lock().map(|n| n.contains(&did)).unwrap_or(false) {
            return Ok(true);
        }
        if self.acl.contains_key(format!("acl:{did}")).await? {
            return Ok(true);
        }
        Ok(!self
            .dids
            .prefix_iter_raw(format!("owner:{did}:"))
            .await?
            .is_empty())
    }

    /// Persists `record` if its identity is authorised. Returns whether it
    /// wrote.
    pub async fn persist(&self, record: &ScidSourceRecord) -> Result<bool, AppError> {
        if !self.is_authorised(&record.did).await? {
            return Ok(false);
        }
        store_floor(&self.floors, record).await
    }

    async fn persist_logged(&self, record: &ScidSourceRecord) {
        match self.persist(record).await {
            Ok(true) => debug!(did = %record.did, "did:scid floor persisted"),
            Ok(false) => {}
            Err(e) => warn!(did = %record.did, "failed to persist a did:scid floor: {e}"),
        }
    }

    async fn run(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<ScidSourceRecord>,
        resolver: DIDCacheClient,
    ) {
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
        sweep.tick().await;
        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Some(record) => self.persist_logged(&record).await,
                    None => return,
                },
                _ = sweep.tick() => {
                    for record in resolver.scid_sources().records() {
                        self.persist_logged(&record).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::acl::{AclEntry, Role, store_acl_entry};
    use crate::server::config::StoreConfig;
    use crate::server::domain::DomainScope;

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_did_resolver_cache_sdk::network_resolvers::ScidVersion;

    const DID: &str = "did:scid:vh:1:QmScid";

    fn record(did: &str, number: u32) -> ScidSourceRecord {
        ScidSourceRecord {
            did: did.to_string(),
            sources: vec!["dids.example.org/alice".to_string()],
            version: Some(ScidVersion {
                number,
                id: format!("{number}-Qm"),
            }),
        }
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache")
    }

    fn acl_entry(did: &str) -> AclEntry {
        AclEntry {
            did: did.to_string(),
            role: Role::Owner,
            label: None,
            created_at: 0,
            max_total_size: None,
            max_did_count: None,
            domains: DomainScope::All,
        }
    }

    #[tokio::test]
    async fn a_persisted_floor_seeds_a_fresh_resolver() {
        let store = fjall_store().await;
        store_floor(&store.keyspace(KS_SCID_FLOORS).unwrap(), &record(DID, 7))
            .await
            .unwrap();

        let fresh = resolver().await;
        ScidFloorKeeper::install(&fresh, &store).await.unwrap();

        let seeded = fresh.scid_sources().record(DID).expect("seeded");
        assert_eq!(seeded.version.map(|v| v.number), Some(7));
    }

    #[tokio::test]
    async fn an_authorised_identity_is_persisted_and_a_stranger_is_not() {
        let store = fjall_store().await;
        let r = resolver().await;
        let keeper = ScidFloorKeeper::install(&r, &store).await.unwrap();
        store_acl_entry(&store.keyspace(KS_ACL).unwrap(), &acl_entry(DID))
            .await
            .unwrap();

        // Presented with its locator; the ACL entry is keyed on the bare DID.
        assert!(
            keeper
                .persist(&record(&format!("{DID}?src=dids.example.org/alice"), 3))
                .await
                .unwrap()
        );
        assert!(
            !keeper.persist(&record(DID, 3)).await.unwrap(),
            "unchanged → no write"
        );
        assert!(
            keeper.persist(&record(DID, 4)).await.unwrap(),
            "changed → written"
        );
        assert!(
            !keeper
                .persist(&record("did:scid:vh:1:QmStranger", 1))
                .await
                .unwrap()
        );

        let stored = load_floors(&store.keyspace(KS_SCID_FLOORS).unwrap())
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].version.as_ref().map(|v| v.number), Some(4));
    }

    #[tokio::test]
    async fn an_owner_and_a_named_identity_are_authorised() {
        let store = fjall_store().await;
        let r = resolver().await;
        let keeper = ScidFloorKeeper::install(&r, &store).await.unwrap();

        assert!(!keeper.is_authorised(DID).await.unwrap());
        store
            .keyspace(KS_DIDS)
            .unwrap()
            .insert_raw(crate::did_ops::owner_key(DID, "alice"), b"alice".to_vec())
            .await
            .unwrap();
        assert!(keeper.is_authorised(DID).await.unwrap());

        let control = "did:scid:vh:1:QmControl";
        assert!(!keeper.is_authorised(control).await.unwrap());
        keeper.authorise(&format!("{control}?src=control.example.org"));
        assert!(keeper.is_authorised(control).await.unwrap());
    }

    #[tokio::test]
    async fn a_listener_event_for_an_authorised_identity_reaches_the_store() {
        let store = fjall_store().await;
        let r = resolver().await;
        ScidFloorKeeper::install(&r, &store).await.unwrap();
        store_acl_entry(&store.keyspace(KS_ACL).unwrap(), &acl_entry(DID))
            .await
            .unwrap();

        // `add_source` changes the record, so the listener fires.
        assert!(
            r.scid_sources()
                .add_source(&format!("{DID}?src=dids.example.org/alice"))
        );

        let floors = store.keyspace(KS_SCID_FLOORS).unwrap();
        let mut stored = Vec::new();
        for _ in 0..50 {
            stored = load_floors(&floors).await.unwrap();
            if !stored.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            stored.len(),
            1,
            "the writer persisted the authorised identity"
        );
        assert_eq!(stored[0].did, DID);
    }
}

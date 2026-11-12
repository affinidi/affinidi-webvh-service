//! Where a witness identity's signing key lives: the configured secret store.
//!
//! A witness identity has two halves. Its public metadata (`witness_id`, DID,
//! label, counters) and its witnessed marks are records in the data store
//! (`KS_WITNESSES`). Its Ed25519 private key is held in the service's secret
//! store, in the same envelope as the service's own keys
//! ([`StoredSecrets::witness_keys`](did_hosting_common::server::secret_store::StoredSecrets)),
//! so it has the protection the operator chose for those: OS keyring, a cloud
//! secret manager, Vault or a Kubernetes `Secret`. Reading the data store, or
//! a backup or snapshot of it, yields no signing key.
//!
//! Releases before this one kept the private key inside the data-store record
//! (`private_key_multibase`). [`migrate_record_keys`] moves such keys into the
//! secret store when the witness starts; see its docs.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::Value;
use tracing::{info, warn};

use crate::error::AppError;
use crate::secret_store::SecretStore;
use crate::store::{KeyspaceHandle, Store};

/// The member the data-store record held the private key in, before keys
/// moved to the secret store.
pub const LEGACY_KEY_MEMBER: &str = "private_key_multibase";

/// Record rewrites per batch during migration: well inside every backend's
/// transaction bound (DynamoDB's is 100 writes).
const MIGRATION_BATCH: usize = 50;

/// The witness's signing keys, read from the secret store and cached in
/// memory.
///
/// The cache is filled on first use and refilled on a miss, so a key added by
/// another process sharing the secret store (a `create-witness` command run
/// against a remote backend) is found without a restart.
pub struct WitnessKeys {
    store: Box<dyn SecretStore>,
    cache: RwLock<HashMap<String, String>>,
}

impl WitnessKeys {
    pub fn new(store: Box<dyn SecretStore>) -> Self {
        Self {
            store,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// The private key (multibase) of `witness_id`, or `None` when the secret
    /// store holds none for it.
    pub async fn private_key(&self, witness_id: &str) -> Result<Option<String>, AppError> {
        if let Some(k) = self.cached(witness_id) {
            return Ok(Some(k));
        }
        let all = self.store.get_witness_keys().await?;
        let found = all.get(witness_id).cloned();
        *self.cache.write().unwrap_or_else(|p| p.into_inner()) = all.into_iter().collect();
        Ok(found)
    }

    /// Every witness id the secret store holds a key for.
    pub async fn held_ids(&self) -> Result<Vec<String>, AppError> {
        Ok(self
            .store
            .get_witness_keys()
            .await?
            .into_keys()
            .collect::<Vec<_>>())
    }

    /// Hold `keys` (witness id → private key) in the secret store: one write.
    pub async fn put(&self, keys: BTreeMap<String, String>) -> Result<(), AppError> {
        self.store.put_witness_keys(&keys).await?;
        self.cache
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .extend(keys);
        Ok(())
    }

    /// Drop `witness_id`'s key from the secret store.
    pub async fn remove(&self, witness_id: &str) -> Result<(), AppError> {
        self.cache
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(witness_id);
        self.store.remove_witness_key(witness_id).await
    }

    fn cached(&self, witness_id: &str) -> Option<String> {
        self.cache
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(witness_id)
            .cloned()
    }
}

/// Rebuild `witness_id`'s signing secret from its multibase private key,
/// refusing a key whose public half is not `witness_id`.
pub fn signing_secret(did: &str, witness_id: &str, private_key: &str) -> Result<Secret, AppError> {
    let kid = format!("{did}#{witness_id}");
    let secret = Secret::from_multibase(private_key, Some(&kid)).map_err(|e| {
        AppError::Internal(format!(
            "the signing key held for witness {witness_id} cannot be read: {e}"
        ))
    })?;
    let public = secret.get_public_keymultibase().map_err(|e| {
        AppError::Internal(format!(
            "the signing key held for witness {witness_id} has no public key: {e}"
        ))
    })?;
    if public != witness_id {
        return Err(AppError::Internal(format!(
            "the signing key held for witness {witness_id} belongs to another identity"
        )));
    }
    Ok(secret)
}

/// What [`migrate_record_keys`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Identities whose key moved from the data store to the secret store.
    pub moved: Vec<String>,
    /// Identities with no key in either store: they cannot sign.
    pub missing: Vec<String>,
}

/// Move every private key still held in a data-store witness record into the
/// secret store, then strip it from the record.
///
/// Runs at startup, before the witness serves anything. Per identity:
///
/// 1. The record's key must belong to the record (its public half is the
///    `witness_id`), else startup is refused: a key that signs for nobody is
///    not something to carry forward silently.
/// 2. If the secret store already holds a key for that id it must be the same
///    one, else startup is refused, naming the identity, for the operator to
///    resolve: neither copy is chosen for them.
/// 3. All keys to move are written to the secret store in one write, read back
///    and compared, and only then are the records rewritten without them (in
///    batches the data store's transaction bound allows).
///
/// A crash at any point leaves every key in at least one of the two stores,
/// and the next start finishes the move: step 2 finds the copy already made.
///
/// Why move rather than refuse to start: the plaintext copy is already in the
/// data store, and every day it stays there it is in each new backup and
/// snapshot. Moving it at once, verified and idempotent, does not change any
/// key — no DID's witness list needs updating — and needs no operator step.
/// Earlier copies in backups, snapshots or the backend's own history are not
/// reached by this; see the CHANGELOG for what an operator may want to do.
///
/// No key material is logged; only witness ids.
pub async fn migrate_record_keys(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    keys: &WitnessKeys,
) -> Result<MigrationReport, AppError> {
    let held = keys.store.get_witness_keys().await?;
    let mut to_move: BTreeMap<String, String> = BTreeMap::new();
    let mut rewrites: Vec<(Vec<u8>, Value)> = Vec::new();
    let mut report = MigrationReport::default();

    for (key, value) in witnesses_ks.prefix_iter_raw("witness:").await? {
        let mut record: Value = serde_json::from_slice(&value)?;
        let witness_id = record
            .get("witness_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let legacy = record
            .as_object_mut()
            .and_then(|o| o.remove(LEGACY_KEY_MEMBER));
        let Some(legacy) = legacy else {
            if !held.contains_key(&witness_id) {
                report.missing.push(witness_id);
            }
            continue;
        };
        let private = legacy.as_str().unwrap_or_default();
        let did = record
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or_default();
        signing_secret(did, &witness_id, private).map_err(|e| {
            AppError::Internal(format!(
                "witness signing-key migration: {e}. Startup is refused; the record is \
                 unchanged."
            ))
        })?;
        match held.get(&witness_id) {
            Some(existing) if existing == private => {}
            Some(_) => {
                return Err(AppError::Internal(format!(
                    "witness signing-key migration: the secret store already holds a different \
                     key for witness {witness_id} than its data-store record. Startup is \
                     refused; nothing was changed. Keep the key whose public half is \
                     {witness_id} and remove the other before starting again."
                )));
            }
            None => {
                to_move.insert(witness_id.clone(), private.to_string());
            }
        }
        report.moved.push(witness_id);
        rewrites.push((key, record));
    }

    if rewrites.is_empty() {
        return Ok(report);
    }

    if !to_move.is_empty() {
        keys.put(to_move.clone()).await?;
        let now_held = keys.store.get_witness_keys().await?;
        if let Some(id) = to_move
            .iter()
            .find(|(id, k)| now_held.get(*id) != Some(*k))
            .map(|(id, _)| id)
        {
            return Err(AppError::Internal(format!(
                "witness signing-key migration: the key written for witness {id} did not read \
                 back from the secret store. Startup is refused; the data-store records still \
                 hold their keys."
            )));
        }
    }

    for chunk in rewrites.chunks(MIGRATION_BATCH) {
        let mut batch = store.batch();
        for (key, record) in chunk {
            batch.insert_raw(witnesses_ks, key.clone(), serde_json::to_vec(record)?);
        }
        batch.commit().await?;
    }
    store.persist().await?;

    info!(
        count = report.moved.len(),
        witness_ids = ?report.moved,
        "moved witness signing keys from the data store to the secret store"
    );
    Ok(report)
}

/// [`migrate_record_keys`], then a warning for each identity no store holds a
/// key for. What the witness (standalone or embedded) runs before serving.
pub async fn prepare(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    keys: &Arc<WitnessKeys>,
) -> Result<(), AppError> {
    let report = migrate_record_keys(store, witnesses_ks, keys).await?;
    if !report.missing.is_empty() {
        warn!(
            witness_ids = ?report.missing,
            "these witness identities have no signing key in the secret store and cannot sign; \
             restore the secret store they were created with, or delete them"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::tests::temp_keys;
    use serde_json::json;

    async fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = did_hosting_common::server::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        (Store::open(&config).await.unwrap(), dir)
    }

    /// A record as releases before this one wrote it: key material inside.
    async fn legacy_record(ks: &KeyspaceHandle) -> (String, String) {
        let secret = Secret::generate_ed25519(None, None);
        let private = secret.get_private_keymultibase().unwrap();
        let public = secret.get_public_keymultibase().unwrap();
        let record = json!({
            "witness_id": public,
            "did": format!("did:key:{public}"),
            "vta_key_id": null,
            "private_key_multibase": private,
            "public_key_multibase": public,
            "label": "old",
            "created_at": 1_700_000_000u64,
            "proofs_signed": 7u64,
        });
        ks.insert_raw(
            format!("witness:{public}"),
            serde_json::to_vec(&record).unwrap(),
        )
        .await
        .unwrap();
        (public, private)
    }

    async fn raw(ks: &KeyspaceHandle, id: &str) -> String {
        String::from_utf8(ks.get_raw(format!("witness:{id}")).await.unwrap().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn keys_in_records_move_to_the_secret_store_and_still_sign() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let (keys, _kdir) = temp_keys();
        let (a, a_key) = legacy_record(&ks).await;
        let (b, b_key) = legacy_record(&ks).await;
        let fresh = crate::witness_ops::create_witness(&ks, &keys, None)
            .await
            .unwrap();

        let report = migrate_record_keys(&store, &ks, &keys).await.unwrap();
        let mut moved = report.moved.clone();
        moved.sort();
        let mut expect = vec![a.clone(), b.clone()];
        expect.sort();
        assert_eq!(moved, expect);
        assert!(report.missing.is_empty());

        for (id, key) in [(&a, &a_key), (&b, &b_key)] {
            let text = raw(&ks, id).await;
            assert!(!text.contains(key.as_str()), "{text}");
            assert!(!text.contains(LEGACY_KEY_MEMBER), "{text}");
            assert_eq!(keys.private_key(id).await.unwrap().as_ref(), Some(key));
            // Everything else in the record is kept.
            let record = crate::witness_ops::get_witness(&ks, id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.proofs_signed, 7);
            assert_eq!(record.label.as_deref(), Some("old"));
        }

        // The moved identity signs with the key it always had.
        let record = crate::witness_ops::get_witness(&ks, &a)
            .await
            .unwrap()
            .unwrap();
        use crate::signing::WitnessSigner;
        let proof = crate::signing::LocalSigner::new(keys.clone())
            .sign_proof(&record, "1-Qm")
            .await
            .unwrap();
        assert!(proof.verification_method.ends_with(&a));

        // A second start has nothing to move.
        let again = migrate_record_keys(&store, &ks, &keys).await.unwrap();
        assert_eq!(again, MigrationReport::default());
        assert!(keys.private_key(&fresh.witness_id).await.unwrap().is_some());
    }

    /// A crash after the secret-store write but before the records were
    /// rewritten: the next start finds the same key already held and finishes.
    #[tokio::test]
    async fn an_interrupted_move_is_finished_on_the_next_start() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let (keys, _kdir) = temp_keys();
        let (a, a_key) = legacy_record(&ks).await;
        keys.put(BTreeMap::from([(a.clone(), a_key.clone())]))
            .await
            .unwrap();

        let report = migrate_record_keys(&store, &ks, &keys).await.unwrap();
        assert_eq!(report.moved, vec![a.clone()]);
        assert!(!raw(&ks, &a).await.contains(&a_key));
    }

    #[tokio::test]
    async fn a_different_key_already_held_refuses_startup_and_changes_nothing() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let (keys, _kdir) = temp_keys();
        let (a, a_key) = legacy_record(&ks).await;
        let other = Secret::generate_ed25519(None, None)
            .get_private_keymultibase()
            .unwrap();
        keys.put(BTreeMap::from([(a.clone(), other.clone())]))
            .await
            .unwrap();

        let err = migrate_record_keys(&store, &ks, &keys).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(&a), "{msg}");
        assert!(!msg.contains(&a_key) && !msg.contains(&other), "{msg}");
        assert!(raw(&ks, &a).await.contains(&a_key));
        assert_eq!(keys.private_key(&a).await.unwrap(), Some(other));
    }

    #[tokio::test]
    async fn a_record_key_that_is_not_the_identitys_refuses_startup() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let (keys, _kdir) = temp_keys();
        let (a, _) = legacy_record(&ks).await;
        let mut record: Value = serde_json::from_str(&raw(&ks, &a).await).unwrap();
        let foreign = Secret::generate_ed25519(None, None)
            .get_private_keymultibase()
            .unwrap();
        record[LEGACY_KEY_MEMBER] = json!(foreign);
        ks.insert_raw(format!("witness:{a}"), serde_json::to_vec(&record).unwrap())
            .await
            .unwrap();

        let err = migrate_record_keys(&store, &ks, &keys).await.unwrap_err();
        assert!(!err.to_string().contains(&foreign));
        assert!(keys.held_ids().await.unwrap().is_empty());
        assert!(raw(&ks, &a).await.contains(&foreign));
    }

    #[tokio::test]
    async fn an_identity_with_no_key_anywhere_is_reported() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let (keys, _kdir) = temp_keys();
        let record = crate::witness_ops::create_witness(&ks, &keys, None)
            .await
            .unwrap();
        keys.remove(&record.witness_id).await.unwrap();
        let report = migrate_record_keys(&store, &ks, &keys).await.unwrap();
        assert_eq!(report.missing, vec![record.witness_id]);
        assert!(report.moved.is_empty());
    }
}

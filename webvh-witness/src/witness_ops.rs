use std::collections::BTreeMap;

use affinidi_data_integrity::DataIntegrityProof;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::signing::WitnessSigner;
use crate::store::{KeyspaceHandle, Store};
use crate::witness_keys::WitnessKeys;

/// A witness identity managed by this service: its public metadata. The
/// identity's private key is held in the secret store, never in this record
/// (see [`crate::witness_keys`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRecord {
    /// Multibase-encoded public key (z6Mk...) — used as the primary identifier.
    pub witness_id: String,
    /// The did:key DID for this witness.
    pub did: String,
    /// Optional VTA key reference for remote signing.
    pub vta_key_id: Option<String>,
    /// Multibase-encoded Ed25519 public key.
    pub public_key_multibase: String,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Number of proofs signed by this witness.
    pub proofs_signed: u64,
}

/// Create a new witness identity: its private key goes to the secret store
/// (`keys`), then its record to the data store.
///
/// Key first: a failure or crash between the two leaves at most a key with no
/// record, which signs nothing (signing starts from the record). The other
/// order could leave a listed identity that cannot sign. If the record write
/// fails, the key is removed again.
pub async fn create_witness(
    witnesses_ks: &KeyspaceHandle,
    keys: &WitnessKeys,
    label: Option<String>,
) -> Result<WitnessRecord, AppError> {
    let secret = Secret::generate_ed25519(None, None);

    let public_key_multibase = secret
        .get_public_keymultibase()
        .map_err(|e| AppError::Internal(format!("failed to get public key multibase: {e}")))?;

    let private_key_multibase = secret
        .get_private_keymultibase()
        .map_err(|e| AppError::Internal(format!("failed to get private key multibase: {e}")))?;

    let did = format!("did:key:{public_key_multibase}");

    let now = did_hosting_common::server::auth::session::now_epoch();

    let record = WitnessRecord {
        witness_id: public_key_multibase.clone(),
        did,
        vta_key_id: None,
        public_key_multibase,
        label,
        created_at: now,
        proofs_signed: 0,
    };

    keys.put(BTreeMap::from([(
        record.witness_id.clone(),
        private_key_multibase,
    )]))
    .await?;
    if let Err(e) = store_witness(witnesses_ks, &record).await {
        if let Err(cleanup) = keys.remove(&record.witness_id).await {
            tracing::warn!(
                witness_id = %record.witness_id,
                error = %cleanup,
                "witness record not stored, and its key could not be removed from the secret store"
            );
        }
        return Err(e);
    }

    Ok(record)
}

/// Store a witness record.
async fn store_witness(
    witnesses_ks: &KeyspaceHandle,
    record: &WitnessRecord,
) -> Result<(), AppError> {
    let key = format!("witness:{}", record.witness_id);
    witnesses_ks.insert(key, record).await?;
    Ok(())
}

/// Get a witness record by its ID (multibase public key).
pub async fn get_witness(
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
) -> Result<Option<WitnessRecord>, AppError> {
    let key = format!("witness:{witness_id}");
    witnesses_ks.get::<WitnessRecord>(key).await
}

/// List all witness records.
pub async fn list_witnesses(witnesses_ks: &KeyspaceHandle) -> Result<Vec<WitnessRecord>, AppError> {
    let entries = witnesses_ks.prefix_iter_raw("witness:").await?;
    let mut records = Vec::new();
    for (_key, value) in entries {
        let record: WitnessRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    Ok(records)
}

/// Delete a witness record by its ID, with every witnessed mark it holds, and
/// then its private key from the secret store.
///
/// The record and its marks are one atomic write, so a crash mid-delete
/// cannot leave orphaned marks behind a deleted identity. The key goes after
/// them: an identity with no record signs nothing, so a key left behind by a
/// failure there is inert. That failure is still returned, so the caller
/// knows the key is still held.
pub async fn delete_witness(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    keys: &WitnessKeys,
    witness_id: &str,
) -> Result<(), AppError> {
    delete_witness_record(store, witnesses_ks, witness_id).await?;
    keys.remove(witness_id).await
}

async fn delete_witness_record(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
) -> Result<(), AppError> {
    let mut batch = store.batch();
    batch.remove(witnesses_ks, format!("witness:{witness_id}"));
    // The identity's key is gone, so what it witnessed can never be extended.
    for (key, _) in witnesses_ks
        .prefix_iter_raw(format!("witnessed:{witness_id}:"))
        .await?
    {
        batch.remove(witnesses_ks, key);
    }
    batch.commit().await
}

/// Sign a witness proof for a given version ID, and record it.
///
/// The record — the identity's `proofs_signed` counter and, when `advance`
/// names a DID, the furthest-witnessed mark for it — is one atomic write,
/// made durable with [`Store::persist`] (an fsync) **before** the proof is
/// returned. The mark is the witness's anti-equivocation memory: were a
/// proof released while its mark was still only in the OS page cache, a
/// power loss would forget it, and the witness would then sign a fork of a
/// history it had already vouched for. A proof whose record cannot be made
/// durable is never returned.
///
/// The caller holds `sign_lock` across its extends-the-mark check and this
/// call, so the check, the signature and the record are one step.
pub async fn sign_witness_proof(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    signer: &dyn WitnessSigner,
    witness_id: &str,
    version_id: &str,
    advance: Option<(&str, &WitnessedMark)>,
) -> Result<(String, DataIntegrityProof), AppError> {
    // Validate version_id format: <number>-<hash>
    if !is_valid_version_id(version_id) {
        return Err(AppError::Validation(format!(
            "invalid version_id format: '{version_id}' (expected '<number>-<hash>')"
        )));
    }

    let witness = get_witness(witnesses_ks, witness_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("witness not found: {witness_id}")))?;

    let proof = signer.sign_proof(&witness, version_id).await?;

    let mut updated = witness;
    updated.proofs_signed += 1;
    let mut batch = store.batch();
    batch.insert(
        witnesses_ks,
        format!("witness:{}", updated.witness_id),
        &updated,
    )?;
    if let Some((scid, mark)) = advance {
        batch.insert(witnesses_ks, witnessed_key(witness_id, scid), mark)?;
    }
    batch.commit().await?;
    store.persist().await?;

    Ok((version_id.to_string(), proof))
}

/// The furthest entry a witness identity has witnessed for one DID: what a
/// later request must extend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WitnessedMark {
    pub version_number: u64,
    pub version_id: String,
}

fn witnessed_key(witness_id: &str, scid: &str) -> String {
    format!("witnessed:{witness_id}:{scid}")
}

/// The furthest entry `witness_id` has witnessed for the DID `scid`.
pub async fn get_witnessed_mark(
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
    scid: &str,
) -> Result<Option<WitnessedMark>, AppError> {
    witnesses_ks.get(witnessed_key(witness_id, scid)).await
}

/// Record that `witness_id` has witnessed `mark` for the DID `scid`.
pub async fn set_witnessed_mark(
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
    scid: &str,
    mark: &WitnessedMark,
) -> Result<(), AppError> {
    witnesses_ks
        .insert(witnessed_key(witness_id, scid), mark)
        .await
}

/// Validate that a version_id matches the expected format: `<number>-<hash>`.
fn is_valid_version_id(version_id: &str) -> bool {
    let Some((num_part, hash_part)) = version_id.split_once('-') else {
        return false;
    };
    if num_part.is_empty() || hash_part.is_empty() {
        return false;
    }
    num_part.chars().all(|c| c.is_ascii_digit()) && hash_part.chars().all(|c| !c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_version_ids() {
        assert!(is_valid_version_id("1-QmTest123"));
        assert!(is_valid_version_id(
            "2-QmaFkyeG4Rksig3tjyn2qQu3eCVeoAZ5txLT4RwyLZZ6ur"
        ));
        assert!(is_valid_version_id("42-abc"));
    }

    #[test]
    fn test_invalid_version_ids() {
        assert!(!is_valid_version_id(""));
        assert!(!is_valid_version_id("no-number"));
        assert!(!is_valid_version_id("1-"));
        assert!(!is_valid_version_id("-hash"));
        assert!(!is_valid_version_id("nohyphen"));
    }

    async fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = did_hosting_common::server::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        (Store::open(&config).await.unwrap(), dir)
    }

    /// The counter and the witnessed mark are one write. Read the counter
    /// first, then the mark: if each proof's record is atomic, the mark
    /// read afterwards is never behind the count read before it. Two
    /// separate writes expose "counted, but the mark not yet advanced" —
    /// the state a crash (or, before the record was fsynced, a power loss)
    /// would freeze while the proof was already out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_signed_proof_is_never_recorded_without_its_mark() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let (keys, _keys_dir) = crate::signing::tests::temp_keys();
        let record = create_witness(&ks, &keys, None).await.unwrap();
        let witness_id = record.witness_id.clone();

        let done = Arc::new(AtomicBool::new(false));
        let mut observers = Vec::new();
        for _ in 0..4 {
            let (ks, done, witness_id) = (ks.clone(), done.clone(), witness_id.clone());
            observers.push(tokio::spawn(async move {
                while !done.load(Ordering::Acquire) {
                    let counted = get_witness(&ks, &witness_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .proofs_signed;
                    let marked = get_witnessed_mark(&ks, &witness_id, "scid")
                        .await
                        .unwrap()
                        .map_or(0, |m| m.version_number);
                    if marked < counted {
                        return Some(format!("{counted} proofs counted, mark at {marked}"));
                    }
                    tokio::task::yield_now().await;
                }
                None
            }));
        }
        for n in 1..=150u64 {
            let version_id = format!("{n}-QmHash{n}");
            let mark = WitnessedMark {
                version_number: n,
                version_id: version_id.clone(),
            };
            sign_witness_proof(
                &store,
                &ks,
                &crate::signing::LocalSigner::new(keys.clone()),
                &witness_id,
                &version_id,
                Some(("scid", &mark)),
            )
            .await
            .unwrap();
        }
        done.store(true, Ordering::Release);
        for o in observers {
            if let Some(v) = o.await.unwrap() {
                panic!("witness record not atomic: {v}");
            }
        }
        assert_eq!(
            get_witnessed_mark(&ks, &witness_id, "scid").await.unwrap(),
            Some(WitnessedMark {
                version_number: 150,
                version_id: "150-QmHash150".into()
            })
        );
    }

    /// Deleting an identity takes its marks with it.
    #[tokio::test]
    async fn delete_witness_removes_its_marks() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let (keys, _keys_dir) = crate::signing::tests::temp_keys();
        let record = create_witness(&ks, &keys, None).await.unwrap();
        let other = create_witness(&ks, &keys, None).await.unwrap();
        let mark = WitnessedMark {
            version_number: 1,
            version_id: "1-Qm".into(),
        };
        for scid in ["a", "b"] {
            set_witnessed_mark(&ks, &record.witness_id, scid, &mark)
                .await
                .unwrap();
        }
        set_witnessed_mark(&ks, &other.witness_id, "a", &mark)
            .await
            .unwrap();

        delete_witness(&store, &ks, &keys, &record.witness_id)
            .await
            .unwrap();
        // The key went with the record; the other identity's stays.
        assert_eq!(keys.private_key(&record.witness_id).await.unwrap(), None);
        assert!(keys.private_key(&other.witness_id).await.unwrap().is_some());

        assert!(
            get_witness(&ks, &record.witness_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get_witnessed_mark(&ks, &record.witness_id, "a")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get_witnessed_mark(&ks, &record.witness_id, "b")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            get_witnessed_mark(&ks, &other.witness_id, "a")
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A new identity's private key is in the secret store, and nothing in
    /// its data-store record is key material.
    #[tokio::test]
    async fn a_created_identity_keeps_its_private_key_out_of_the_data_store() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let (keys, _keys_dir) = crate::signing::tests::temp_keys();
        let record = create_witness(&ks, &keys, Some("w".into())).await.unwrap();

        let private = keys
            .private_key(&record.witness_id)
            .await
            .unwrap()
            .expect("key held in the secret store");
        crate::witness_keys::signing_secret(&record.did, &record.witness_id, &private).unwrap();

        let raw = ks
            .get_raw(format!("witness:{}", record.witness_id))
            .await
            .unwrap()
            .expect("record stored");
        let text = String::from_utf8(raw).unwrap();
        assert!(!text.contains(&private), "{text}");
        assert!(
            !text.contains(crate::witness_keys::LEGACY_KEY_MEMBER),
            "{text}"
        );
    }
}

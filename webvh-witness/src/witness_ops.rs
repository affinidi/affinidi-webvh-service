use affinidi_data_integrity::DataIntegrityProof;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::signing::WitnessSigner;
use crate::store::{KeyspaceHandle, Store};

/// A witness identity managed by this service.
#[derive(Clone, Serialize, Deserialize)]
pub struct WitnessRecord {
    /// Multibase-encoded public key (z6Mk...) — used as the primary identifier.
    pub witness_id: String,
    /// The did:key DID for this witness.
    pub did: String,
    /// Optional VTA key reference for remote signing.
    pub vta_key_id: Option<String>,
    /// Multibase-encoded Ed25519 private key.
    pub private_key_multibase: String,
    /// Multibase-encoded Ed25519 public key.
    pub public_key_multibase: String,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Number of proofs signed by this witness.
    pub proofs_signed: u64,
}

// `Debug` redacts `private_key_multibase` so that a careless
// `tracing::debug!(?record)` does not leak the witness's signing key.
impl std::fmt::Debug for WitnessRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessRecord")
            .field("witness_id", &self.witness_id)
            .field("did", &self.did)
            .field("vta_key_id", &self.vta_key_id)
            .field("private_key_multibase", &"<redacted>")
            .field("public_key_multibase", &self.public_key_multibase)
            .field("label", &self.label)
            .field("created_at", &self.created_at)
            .field("proofs_signed", &self.proofs_signed)
            .finish()
    }
}

/// Create a new witness identity and store it.
pub async fn create_witness(
    witnesses_ks: &KeyspaceHandle,
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
        private_key_multibase,
        public_key_multibase,
        label,
        created_at: now,
        proofs_signed: 0,
    };

    store_witness(witnesses_ks, &record).await?;

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

/// Delete a witness record by its ID, with every witnessed mark it holds.
///
/// One atomic write: the record and its marks go together, so a crash
/// mid-delete cannot leave orphaned marks behind a deleted identity.
pub async fn delete_witness(
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
        let record = create_witness(&ks, None).await.unwrap();
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
                &crate::signing::LocalSigner,
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
        let record = create_witness(&ks, None).await.unwrap();
        let other = create_witness(&ks, None).await.unwrap();
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

        delete_witness(&store, &ks, &record.witness_id)
            .await
            .unwrap();

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
}

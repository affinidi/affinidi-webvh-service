use affinidi_data_integrity::DataIntegrityProof;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::signing::WitnessSigner;
use crate::store::{KeyspaceHandle, Store};
use crate::witness_keys::WitnessKeys;

/// A witness identity managed by this service. Its private key is held only
/// sealed to the witness key-encryption key (see [`crate::witness_keys`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRecord {
    /// Multibase-encoded public key (z6Mk...) — used as the primary identifier.
    pub witness_id: String,
    /// The did:key DID for this witness.
    pub did: String,
    /// Optional VTA key reference for remote signing.
    pub vta_key_id: Option<String>,
    /// The Ed25519 private key, HPKE-sealed to the witness key-encryption key
    /// (multibase). Empty on a record from before keys were sealed, until the
    /// witness's startup migration seals it.
    #[serde(default)]
    pub sealed_private_key: String,
    /// Multibase-encoded Ed25519 public key.
    pub public_key_multibase: String,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Unix timestamp of creation.
    pub created_at: u64,
    /// Number of proofs signed by this witness.
    pub proofs_signed: u64,
}

/// Create a new witness identity and store it: one record, its private key
/// sealed to the witness key-encryption key held by `keys`.
pub async fn create_witness(
    witnesses_ks: &KeyspaceHandle,
    keys: &WitnessKeys,
    label: Option<String>,
) -> Result<WitnessRecord, AppError> {
    let secret = Secret::generate_ed25519(None, None);

    let public_key_multibase = secret
        .get_public_keymultibase()
        .map_err(|e| AppError::Internal(format!("failed to get public key multibase: {e}")))?;

    let sealed_private_key = keys.seal(
        &public_key_multibase,
        &secret
            .get_private_keymultibase()
            .map_err(|e| AppError::Internal(format!("failed to encode the private key: {e}")))?,
    )?;

    let did = format!("did:key:{public_key_multibase}");

    let now = did_hosting_common::server::auth::session::now_epoch();

    let record = WitnessRecord {
        witness_id: public_key_multibase.clone(),
        did,
        vta_key_id: None,
        sealed_private_key,
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
/// One atomic write: the record (and the sealed key in it) and its marks go
/// together, so a crash mid-delete cannot leave orphaned marks behind a
/// deleted identity.
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

/// How many times the identity's `proofs_signed` counter is re-read and
/// swapped when another process updates the record at the same moment.
const COUNTER_ATTEMPTS: usize = 8;

/// Sign a witness proof for a given version ID, and count it.
///
/// The caller has already advanced — durably — the identity's mark for the
/// DID ([`advance_witnessed_mark`]), or found it already at this entry: a
/// proof is never signed for an entry the mark does not hold.
///
/// The counter is swapped over the record it was read from, so a process
/// sharing the store that rewrites or deletes the record at the same moment
/// is neither overwritten nor undone.
pub async fn sign_witness_proof(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    signer: &dyn WitnessSigner,
    witness_id: &str,
    version_id: &str,
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

    let key = format!("witness:{witness_id}");
    let mut counted = false;
    for _ in 0..COUNTER_ATTEMPTS {
        let Some(stored) = witnesses_ks.get_raw(key.as_str()).await? else {
            // Deleted meanwhile: nothing left to count on.
            counted = true;
            break;
        };
        let mut updated: WitnessRecord = serde_json::from_slice(&stored)?;
        updated.proofs_signed += 1;
        if witnesses_ks
            .compare_and_swap_raw(key.as_str(), Some(stored), serde_json::to_vec(&updated)?)
            .await?
        {
            counted = true;
            break;
        }
    }
    if counted {
        store.persist().await?;
    } else {
        tracing::warn!(
            witness_id,
            "witness proof signed but not counted: the record kept changing"
        );
    }

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

/// A mark as read from the store, with the exact bytes it was read as, so
/// [`advance_witnessed_mark`] can move it only from that state.
#[derive(Debug, Clone, Default)]
pub struct HeldMark {
    /// The mark, or `None` if this identity has witnessed nothing for the DID.
    pub mark: Option<WitnessedMark>,
    stored: Option<Vec<u8>>,
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
    Ok(read_witnessed_mark(witnesses_ks, witness_id, scid)
        .await?
        .mark)
}

/// [`get_witnessed_mark`], kept with the bytes it was read as.
pub async fn read_witnessed_mark(
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
    scid: &str,
) -> Result<HeldMark, AppError> {
    let stored = witnesses_ks
        .get_raw(witnessed_key(witness_id, scid))
        .await?;
    let mark = stored.as_deref().map(serde_json::from_slice).transpose()?;
    Ok(HeldMark { mark, stored })
}

/// Move `witness_id`'s mark for the DID `scid` from `from` to `to`, only if
/// the store still holds `from`, and make it durable ([`Store::persist`], an
/// fsync on the embedded store) before returning `true`.
///
/// The mark is the witness's anti-equivocation memory, and the store — not
/// this process — decides the swap: of two witness processes sharing a store
/// that each checked a request against the same mark, at most one moves it.
/// The other gets `false`, and must read the mark again and re-check before
/// it may sign. A restarted process reads the mark the last one left.
///
/// Advance the mark **before** signing: a proof released while its mark
/// could still be lost (another process's swap, or a power loss before the
/// fsync) would let the witness sign a fork of a history it had already
/// vouched for.
pub async fn advance_witnessed_mark(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
    scid: &str,
    from: &HeldMark,
    to: &WitnessedMark,
) -> Result<bool, AppError> {
    let swapped = witnesses_ks
        .compare_and_swap_raw(
            witnessed_key(witness_id, scid),
            from.stored.clone(),
            serde_json::to_vec(to)?,
        )
        .await?;
    if swapped {
        store.persist().await?;
    }
    Ok(swapped)
}

/// Record that `witness_id` has witnessed `mark` for the DID `scid`,
/// whatever it held before. For tests and repair only: signing moves the
/// mark with [`advance_witnessed_mark`].
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

    /// The mark moves before the proof is signed and counted. Read the
    /// counter first, then the mark: the mark read afterwards is never
    /// behind the count read before it. The other order would expose
    /// "counted, but the mark not yet advanced", the state a crash would
    /// freeze while the proof was already out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_signed_proof_is_never_recorded_without_its_mark() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let keys = std::sync::Arc::new(WitnessKeys::generate().unwrap());
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
            let held = read_witnessed_mark(&ks, &witness_id, "scid").await.unwrap();
            assert!(
                advance_witnessed_mark(&store, &ks, &witness_id, "scid", &held, &mark)
                    .await
                    .unwrap()
            );
            sign_witness_proof(
                &store,
                &ks,
                &crate::signing::LocalSigner::new(keys.clone()),
                &witness_id,
                &version_id,
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

    /// The mark moves only from the state it was read in: a second process
    /// that read the same mark before the first one moved it cannot move it
    /// again, and must re-read.
    #[tokio::test]
    async fn a_mark_moves_only_from_the_state_it_was_read_in() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let first = WitnessedMark {
            version_number: 1,
            version_id: "1-QmOne".into(),
        };
        let left = WitnessedMark {
            version_number: 2,
            version_id: "2-QmLeft".into(),
        };
        let right = WitnessedMark {
            version_number: 3,
            version_id: "3-QmRight".into(),
        };

        let none = read_witnessed_mark(&ks, "w", "scid").await.unwrap();
        assert!(none.mark.is_none());
        assert!(
            advance_witnessed_mark(&store, &ks, "w", "scid", &none, &first)
                .await
                .unwrap()
        );
        // A stale "nothing witnessed yet" cannot overwrite it.
        assert!(
            !advance_witnessed_mark(&store, &ks, "w", "scid", &none, &left)
                .await
                .unwrap()
        );

        // Two readers of the same mark: one moves it, the other is refused.
        let a = read_witnessed_mark(&ks, "w", "scid").await.unwrap();
        let b = read_witnessed_mark(&ks, "w", "scid").await.unwrap();
        assert_eq!(a.mark.as_ref(), Some(&first));
        assert!(
            advance_witnessed_mark(&store, &ks, "w", "scid", &a, &left)
                .await
                .unwrap()
        );
        assert!(
            !advance_witnessed_mark(&store, &ks, "w", "scid", &b, &right)
                .await
                .unwrap()
        );
        assert_eq!(
            get_witnessed_mark(&ks, "w", "scid").await.unwrap(),
            Some(left)
        );
    }

    /// Deleting an identity takes its marks with it.
    #[tokio::test]
    async fn delete_witness_removes_its_marks() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let keys = WitnessKeys::generate().unwrap();
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

    /// A new identity's private key is in its record only sealed, and opens
    /// to the identity's own key.
    #[tokio::test]
    async fn a_created_identity_keeps_its_private_key_sealed() {
        let (store, _dir) = temp_store().await;
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let keys = WitnessKeys::generate().unwrap();
        let record = create_witness(&ks, &keys, Some("w".into())).await.unwrap();

        let secret = keys
            .open(&record.did, &record.witness_id, &record.sealed_private_key)
            .unwrap();
        let private = secret.get_private_keymultibase().unwrap();

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

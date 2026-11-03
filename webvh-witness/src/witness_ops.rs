use affinidi_data_integrity::DataIntegrityProof;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::signing::WitnessSigner;
use crate::store::{KeyspaceHandle, Store};
use did_hosting_common::server::store::{BatchLimits, chunk_ranges};

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

/// Marks that a deletion is under way for an identity whose record is already
/// gone: its witnessed marks still have to go. See [`delete_witness`].
const DELETING_PREFIX: &str = "deleting:";

fn deleting_key(witness_id: &str) -> String {
    format!("{DELETING_PREFIX}{witness_id}")
}

fn witnessed_prefix(witness_id: &str) -> String {
    format!("witnessed:{witness_id}:")
}

/// Delete a witness record by its ID, with every witnessed mark it holds.
///
/// Normally one atomic write: the record and its marks go together, so a crash
/// mid-delete cannot leave orphaned marks behind a deleted identity.
///
/// An identity that has witnessed more DIDs than one atomic write can hold on
/// the backend (100 operations on DynamoDB single table) cannot be removed that
/// way, and a split batch is not atomic. So the identity goes first, in one
/// atomic write that also leaves a `deleting:{id}` marker, and its marks are then
/// removed in batches the backend accepts, the last of which clears the marker.
/// Once the first write commits the identity can sign nothing more, so what is
/// left is only cleanup; [`finish_pending_deletions`] resumes it if this call is
/// interrupted.
pub async fn delete_witness(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
) -> Result<(), AppError> {
    let record_key = format!("witness:{witness_id}");
    // The identity's key is gone, so what it witnessed can never be extended.
    let marks = witnesses_ks
        .prefix_iter_raw(witnessed_prefix(witness_id))
        .await?;

    let sizes: Vec<usize> = std::iter::once(record_key.len())
        .chain(marks.iter().map(|(key, _)| key.len()))
        .map(|key_len| witnesses_ks.name.len() + key_len)
        .collect();
    if chunk_ranges(store.batch_limits(), usize::MAX, &sizes).len() <= 1 {
        let mut batch = store.batch();
        batch.remove(witnesses_ks, record_key);
        for (key, _) in marks {
            batch.remove(witnesses_ks, key);
        }
        return batch.commit().await;
    }

    // Too much for one atomic write: the identity and the marker, atomically,
    // then the marks.
    let mut batch = store.batch();
    batch.remove(witnesses_ks, record_key);
    batch.insert_raw(witnesses_ks, deleting_key(witness_id), b"1".to_vec());
    batch.commit().await?;
    clear_marks(store, witnesses_ks, witness_id).await
}

/// Remove an identity's witnessed marks in batches the backend accepts, then its
/// `deleting:` marker. The marker goes in the last batch, so it outlives every
/// mark; each batch leaves room for it. Safe to run again after an interruption:
/// it removes whatever is left.
async fn clear_marks(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
) -> Result<(), AppError> {
    let marker = deleting_key(witness_id);
    let marks = witnesses_ks
        .prefix_iter_raw(witnessed_prefix(witness_id))
        .await?;
    let sizes: Vec<usize> = marks
        .iter()
        .map(|(key, _)| witnesses_ks.name.len() + key.len())
        .collect();
    let marker_size = witnesses_ks.name.len() + marker.len();
    let room_for_marker = store.batch_limits().map(|l| BatchLimits {
        max_ops: l.max_ops.saturating_sub(1).max(1),
        max_bytes: l.max_bytes.saturating_sub(marker_size),
    });

    let ranges = chunk_ranges(room_for_marker, usize::MAX, &sizes);
    let last = ranges.len().saturating_sub(1);
    let mut marks = marks.into_iter();
    for (i, range) in ranges.iter().enumerate() {
        let mut batch = store.batch();
        for (key, _) in marks.by_ref().take(range.len()) {
            batch.remove(witnesses_ks, key);
        }
        if i == last {
            batch.remove(witnesses_ks, marker.clone());
        }
        batch.commit().await?;
    }
    if ranges.is_empty() {
        witnesses_ks.remove(marker).await?;
    }
    Ok(())
}

/// Finish the deletions an earlier run began and did not complete: for every
/// `deleting:` marker, remove the identity's remaining marks and the marker.
/// Returns how many deletions it finished. Run at startup.
pub async fn finish_pending_deletions(
    store: &Store,
    witnesses_ks: &KeyspaceHandle,
) -> Result<usize, AppError> {
    let mut finished = 0;
    for (key, _) in witnesses_ks.prefix_iter_raw(DELETING_PREFIX).await? {
        let key = String::from_utf8_lossy(&key).into_owned();
        let Some(witness_id) = key.strip_prefix(DELETING_PREFIX) else {
            continue;
        };
        clear_marks(store, witnesses_ks, witness_id).await?;
        finished += 1;
    }
    Ok(finished)
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
    // -- a store with a batch ceiling --------------------------------------

    use did_hosting_common::server::store::bounded_memory::BoundedMemory;

    async fn identity_with_marks(ks: &KeyspaceHandle, marks: usize) -> WitnessRecord {
        let record = create_witness(ks, None).await.unwrap();
        let mark = WitnessedMark {
            version_number: 1,
            version_id: "1-Qm".into(),
        };
        for i in 0..marks {
            set_witnessed_mark(ks, &record.witness_id, &format!("scid{i:03}"), &mark)
                .await
                .unwrap();
        }
        record
    }

    async fn marks_left(ks: &KeyspaceHandle, witness_id: &str) -> usize {
        ks.prefix_iter_raw(witnessed_prefix(witness_id))
            .await
            .unwrap()
            .len()
    }

    /// Past 100 marks one batch cannot hold the record and every mark, so the
    /// delete must not need one: the identity goes, then its marks, in batches
    /// the backend takes.
    #[tokio::test]
    async fn an_identity_with_more_marks_than_one_batch_holds_can_be_deleted() {
        let backend = BoundedMemory::new(10);
        let store = backend.store();
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let record = identity_with_marks(&ks, 25).await;
        let other = identity_with_marks(&ks, 3).await;

        delete_witness(&store, &ks, &record.witness_id)
            .await
            .expect("a 25-mark identity is deletable on a 10-operation store");

        assert!(
            get_witness(&ks, &record.witness_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(marks_left(&ks, &record.witness_id).await, 0);
        assert!(
            ks.prefix_iter_raw(DELETING_PREFIX)
                .await
                .unwrap()
                .is_empty(),
            "the marker is cleared"
        );
        assert_eq!(
            marks_left(&ks, &other.witness_id).await,
            3,
            "another identity's marks stay"
        );
        assert!(get_witness(&ks, &other.witness_id).await.unwrap().is_some());
        let sizes = backend.committed_batch_sizes();
        assert!(sizes.iter().all(|n| *n <= 10), "{sizes:?}");
    }

    /// The common case is unchanged: when the record and its marks fit, they are
    /// removed in one atomic write.
    #[tokio::test]
    async fn an_identity_that_fits_one_batch_is_still_deleted_in_one_atomic_write() {
        let backend = BoundedMemory::new(10);
        let store = backend.store();
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let record = identity_with_marks(&ks, 9).await; // record + 9 marks = 10
        let before = backend.committed_batch_sizes().len();

        delete_witness(&store, &ks, &record.witness_id)
            .await
            .unwrap();

        assert_eq!(
            backend.committed_batch_sizes()[before..].to_vec(),
            vec![10],
            "one batch holding the record and all nine marks"
        );
        assert_eq!(marks_left(&ks, &record.witness_id).await, 0);
    }

    /// One mark more than fits flips to the bounded path.
    #[tokio::test]
    async fn one_mark_over_the_batch_limit_takes_the_bounded_path() {
        let backend = BoundedMemory::new(10);
        let store = backend.store();
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let record = identity_with_marks(&ks, 10).await; // record + 10 marks = 11
        let before = backend.committed_batch_sizes().len();

        delete_witness(&store, &ks, &record.witness_id)
            .await
            .unwrap();

        let sizes = backend.committed_batch_sizes()[before..].to_vec();
        assert!(
            sizes.len() > 1 && sizes.iter().all(|n| *n <= 10),
            "{sizes:?}"
        );
        assert_eq!(marks_left(&ks, &record.witness_id).await, 0);
    }

    /// An interrupted cleanup leaves an identity that is already gone, with only
    /// its marks and marker to finish: it cannot sign, is not listed, and the
    /// startup sweep completes the delete.
    #[tokio::test]
    async fn an_interrupted_delete_leaves_no_identity_and_is_finished_by_the_sweep() {
        // The marks are seeded with plain inserts, which are not batches, so
        // commit 0 is the delete's marker write, commit 1 clears a batch of
        // marks, and commit 2 fails.
        let store = BoundedMemory::new(10).fail_commit(2).store();
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        let record = identity_with_marks(&ks, 25).await;
        let bystander = identity_with_marks(&ks, 4).await;

        let err = delete_witness(&store, &ks, &record.witness_id)
            .await
            .expect_err("the third commit fails");

        assert!(matches!(err, AppError::Internal(_)), "{err:?}");
        assert!(
            get_witness(&ks, &record.witness_id)
                .await
                .unwrap()
                .is_none()
        );
        let listed: Vec<_> = list_witnesses(&ks)
            .await
            .unwrap()
            .into_iter()
            .map(|w| w.witness_id)
            .collect();
        assert_eq!(listed, vec![bystander.witness_id.clone()]);
        assert!(marks_left(&ks, &record.witness_id).await > 0);
        assert_eq!(
            ks.prefix_iter_raw(DELETING_PREFIX).await.unwrap().len(),
            1,
            "the marker says a delete is unfinished"
        );

        let finished = finish_pending_deletions(&store, &ks).await.unwrap();

        assert_eq!(finished, 1);
        assert_eq!(marks_left(&ks, &record.witness_id).await, 0);
        assert!(
            ks.prefix_iter_raw(DELETING_PREFIX)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(marks_left(&ks, &bystander.witness_id).await, 4);
        assert!(
            get_witness(&ks, &bystander.witness_id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn the_startup_sweep_with_nothing_pending_writes_nothing() {
        let backend = BoundedMemory::new(10);
        let store = backend.store();
        let ks = store.keyspace(crate::store::KS_WITNESSES).unwrap();
        identity_with_marks(&ks, 3).await;

        assert_eq!(finish_pending_deletions(&store, &ks).await.unwrap(), 0);
        assert!(backend.committed_batch_sizes().is_empty());
    }
}

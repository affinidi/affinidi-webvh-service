use affinidi_data_integrity::DataIntegrityProof;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::signing::WitnessSigner;
use crate::store::KeyspaceHandle;

/// A witness identity managed by this service.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    let now = crate::auth::session::now_epoch();

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
pub async fn list_witnesses(
    witnesses_ks: &KeyspaceHandle,
) -> Result<Vec<WitnessRecord>, AppError> {
    let entries = witnesses_ks.prefix_iter_raw("witness:").await?;
    let mut records = Vec::new();
    for (_key, value) in entries {
        let record: WitnessRecord = serde_json::from_slice(&value)?;
        records.push(record);
    }
    Ok(records)
}

/// Delete a witness record by its ID.
pub async fn delete_witness(
    witnesses_ks: &KeyspaceHandle,
    witness_id: &str,
) -> Result<(), AppError> {
    let key = format!("witness:{witness_id}");
    witnesses_ks.remove(key).await?;
    Ok(())
}

/// Sign a witness proof for a given version ID.
pub async fn sign_witness_proof(
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

    let proof = signer.sign_proof(&witness, version_id)?;

    // Increment proof counter
    let mut updated = witness;
    updated.proofs_signed += 1;
    store_witness(witnesses_ks, &updated).await?;

    Ok((version_id.to_string(), proof))
}

/// Validate that a version_id matches the expected format: `<number>-<hash>`.
fn is_valid_version_id(version_id: &str) -> bool {
    let Some((num_part, hash_part)) = version_id.split_once('-') else {
        return false;
    };
    if num_part.is_empty() || hash_part.is_empty() {
        return false;
    }
    num_part.chars().all(|c| c.is_ascii_digit())
        && hash_part.chars().all(|c| !c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_version_ids() {
        assert!(is_valid_version_id("1-QmTest123"));
        assert!(is_valid_version_id("2-QmaFkyeG4Rksig3tjyn2qQu3eCVeoAZ5txLT4RwyLZZ6ur"));
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
}

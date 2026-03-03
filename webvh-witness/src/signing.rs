use affinidi_data_integrity::DataIntegrityProof;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::json;

use crate::error::AppError;
use crate::witness_ops::WitnessRecord;

/// Trait for witness proof signing. Enables both local and remote (VTA) signing.
pub trait WitnessSigner: Send + Sync {
    fn sign_proof(
        &self,
        witness: &WitnessRecord,
        version_id: &str,
    ) -> Result<DataIntegrityProof, AppError>;
}

/// Signs witness proofs locally using the stored Ed25519 private key.
pub struct LocalSigner;

impl WitnessSigner for LocalSigner {
    fn sign_proof(
        &self,
        witness: &WitnessRecord,
        version_id: &str,
    ) -> Result<DataIntegrityProof, AppError> {
        // Reconstruct the Secret from stored multibase private key.
        // The KID must be the full verification method DID URL:
        //   did:key:z6Mk...#z6Mk...
        let kid = format!("{}#{}", witness.did, witness.witness_id);
        let secret = Secret::from_multibase(&witness.private_key_multibase, Some(&kid))
            .map_err(|e| AppError::Internal(format!("failed to reconstruct signing key: {e}")))?;

        // Sign the canonical {"versionId": "..."} document
        let proof = DataIntegrityProof::sign_jcs_data(
            &json!({"versionId": version_id}),
            None,
            &secret,
            None,
        )
        .map_err(|e| AppError::Internal(format!("failed to sign proof: {e}")))?;

        Ok(proof)
    }
}

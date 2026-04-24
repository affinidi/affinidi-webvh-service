use std::future::Future;
use std::pin::Pin;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::json;

use crate::error::AppError;
use crate::witness_ops::WitnessRecord;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for witness proof signing. Enables both local and remote (VTA) signing.
pub trait WitnessSigner: Send + Sync {
    fn sign_proof<'a>(
        &'a self,
        witness: &'a WitnessRecord,
        version_id: &'a str,
    ) -> BoxFuture<'a, Result<DataIntegrityProof, AppError>>;
}

/// Signs witness proofs locally using the stored Ed25519 private key.
pub struct LocalSigner;

impl WitnessSigner for LocalSigner {
    fn sign_proof<'a>(
        &'a self,
        witness: &'a WitnessRecord,
        version_id: &'a str,
    ) -> BoxFuture<'a, Result<DataIntegrityProof, AppError>> {
        Box::pin(async move {
            // Reconstruct the Secret from stored multibase private key.
            // The KID must be the full verification method DID URL:
            //   did:key:z6Mk...#z6Mk...
            let kid = format!("{}#{}", witness.did, witness.witness_id);
            let secret = Secret::from_multibase(&witness.private_key_multibase, Some(&kid))
                .map_err(|e| {
                    AppError::Internal(format!("failed to reconstruct signing key: {e}"))
                })?;

            // Sign the canonical {"versionId": "..."} document via the
            // 0.6 API (async, Signer-based, SignOptions for cryptosuite/
            // proof_purpose overrides). Secret impls Signer directly.
            let proof = DataIntegrityProof::sign(
                &json!({"versionId": version_id}),
                &secret,
                SignOptions::new(),
            )
            .await
            .map_err(|e| AppError::Internal(format!("failed to sign proof: {e}")))?;

            Ok(proof)
        })
    }
}

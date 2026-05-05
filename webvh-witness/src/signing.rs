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

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    fn make_witness() -> WitnessRecord {
        // Generate a real Ed25519 secret so the data-integrity sign step can
        // produce a verifiable proof. Pass the secret through multibase to
        // exercise `Secret::from_multibase` exactly the way the production
        // path does.
        let secret = Secret::generate_ed25519(None, None);
        let private_key_multibase = secret.get_private_keymultibase().unwrap();
        let public_key_multibase = secret.get_public_keymultibase().unwrap();
        WitnessRecord {
            witness_id: public_key_multibase.clone(),
            did: format!("did:key:{public_key_multibase}"),
            vta_key_id: None,
            private_key_multibase,
            public_key_multibase,
            label: Some("test-witness".into()),
            created_at: 0,
            proofs_signed: 0,
        }
    }

    #[tokio::test]
    async fn local_signer_produces_signed_proof() {
        let signer = LocalSigner;
        let witness = make_witness();
        let proof = signer
            .sign_proof(&witness, "1-test-version")
            .await
            .expect("sign_proof should succeed for a freshly-minted key");
        // Smoke-test the proof shape without re-implementing the data-integrity
        // verifier here — the field set is contract surface for downstream
        // resolvers.
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(json["type"], "DataIntegrityProof");
        assert!(json["proofValue"].is_string());
        assert!(json["verificationMethod"].is_string());
    }

    #[tokio::test]
    async fn local_signer_proof_changes_with_version_id() {
        // Different version_ids must yield different signatures — same secret,
        // different message. Catches a regression where the canonical input is
        // accidentally constant.
        let signer = LocalSigner;
        let witness = make_witness();
        let proof_a = signer.sign_proof(&witness, "1-aaa").await.unwrap();
        let proof_b = signer.sign_proof(&witness, "2-bbb").await.unwrap();
        let json_a = serde_json::to_value(&proof_a).unwrap();
        let json_b = serde_json::to_value(&proof_b).unwrap();
        assert_ne!(json_a["proofValue"], json_b["proofValue"]);
    }

    #[tokio::test]
    async fn local_signer_rejects_witness_with_bad_private_key() {
        let signer = LocalSigner;
        let mut witness = make_witness();
        witness.private_key_multibase = "z6MkBOGUS".into();
        let err = signer
            .sign_proof(&witness, "1-version")
            .await
            .expect_err("invalid multibase key must error");
        assert!(matches!(err, AppError::Internal(_)));
    }
}

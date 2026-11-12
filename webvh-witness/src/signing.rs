use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use serde_json::json;

use crate::error::AppError;
use crate::witness_keys::WitnessKeys;
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

/// Signs witness proofs locally: opens the identity's sealed key from its
/// record with the witness key-encryption key ([`WitnessKeys`]), in memory.
/// No secret-store read happens here.
pub struct LocalSigner {
    keys: Arc<WitnessKeys>,
}

impl LocalSigner {
    pub fn new(keys: Arc<WitnessKeys>) -> Self {
        Self { keys }
    }
}

impl WitnessSigner for LocalSigner {
    fn sign_proof<'a>(
        &'a self,
        witness: &'a WitnessRecord,
        version_id: &'a str,
    ) -> BoxFuture<'a, Result<DataIntegrityProof, AppError>> {
        Box::pin(async move {
            if witness.sealed_private_key.is_empty() {
                return Err(AppError::Internal(format!(
                    "witness {} has no sealed signing key",
                    witness.witness_id
                )));
            }
            // The KID is the full verification method DID URL
            // (did:key:z6Mk...#z6Mk...), and the key must be the one the
            // identity's id names.
            let secret = self.keys.open(
                &witness.did,
                &witness.witness_id,
                &witness.sealed_private_key,
            )?;

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

    fn make_witness(keys: &WitnessKeys) -> WitnessRecord {
        let secret = Secret::generate_ed25519(None, None);
        let public_key_multibase = secret.get_public_keymultibase().unwrap();
        let sealed_private_key = keys
            .seal(
                &public_key_multibase,
                &secret.get_private_keymultibase().unwrap(),
            )
            .unwrap();
        WitnessRecord {
            witness_id: public_key_multibase.clone(),
            did: format!("did:key:{public_key_multibase}"),
            vta_key_id: None,
            sealed_private_key,
            public_key_multibase,
            label: Some("test-witness".into()),
            created_at: 0,
            proofs_signed: 0,
        }
    }

    fn signer() -> (LocalSigner, Arc<WitnessKeys>) {
        let keys = Arc::new(WitnessKeys::generate().unwrap());
        (LocalSigner::new(keys.clone()), keys)
    }

    #[tokio::test]
    async fn local_signer_produces_signed_proof() {
        let (signer, keys) = signer();
        let witness = make_witness(&keys);
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
        let (signer, keys) = signer();
        let witness = make_witness(&keys);
        let proof_a = signer.sign_proof(&witness, "1-aaa").await.unwrap();
        let proof_b = signer.sign_proof(&witness, "2-bbb").await.unwrap();
        let json_a = serde_json::to_value(&proof_a).unwrap();
        let json_b = serde_json::to_value(&proof_b).unwrap();
        assert_ne!(json_a["proofValue"], json_b["proofValue"]);
    }

    #[tokio::test]
    async fn local_signer_refuses_a_witness_it_cannot_open() {
        let (signer, keys) = signer();
        let mut witness = make_witness(&keys);
        witness.sealed_private_key = String::new();
        assert!(matches!(
            signer.sign_proof(&witness, "1-version").await,
            Err(AppError::Internal(_))
        ));
        // Sealed to another key-encryption key.
        let witness = make_witness(&WitnessKeys::generate().unwrap());
        assert!(matches!(
            signer.sign_proof(&witness, "1-version").await,
            Err(AppError::Internal(_))
        ));
        let mut witness = make_witness(&keys);
        witness.sealed_private_key = "z6MkBOGUS".into();
        assert!(matches!(
            signer.sign_proof(&witness, "1-version").await,
            Err(AppError::Internal(_))
        ));
    }
}

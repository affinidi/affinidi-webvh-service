use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use serde_json::json;

use crate::error::AppError;
use crate::witness_keys::{WitnessKeys, signing_secret};
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

/// Signs witness proofs locally, with the identity's Ed25519 private key read
/// from the secret store ([`WitnessKeys`]).
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
            let private_key = self
                .keys
                .private_key(&witness.witness_id)
                .await?
                .ok_or_else(|| {
                    AppError::Internal(format!(
                        "the secret store holds no signing key for witness {}",
                        witness.witness_id
                    ))
                })?;
            // The KID must be the full verification method DID URL:
            //   did:key:z6Mk...#z6Mk...
            // and the key must be the one the identity's id names.
            let secret = signing_secret(&witness.did, &witness.witness_id, &private_key)?;

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
pub(crate) mod tests {
    use super::*;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use std::collections::BTreeMap;

    /// Witness keys over a plaintext secret store in a temp dir (CI has no
    /// keyring).
    pub(crate) fn temp_keys() -> (Arc<WitnessKeys>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let secrets = crate::config::SecretsConfig {
            backend: Some(crate::secret_store::SecretBackend::Plaintext),
            confirm_plaintext: true,
            ..Default::default()
        };
        let store = did_hosting_common::server::secret_store::create_secret_store(
            &secrets,
            &dir.path().join("w.toml"),
        )
        .unwrap();
        (Arc::new(WitnessKeys::new(store)), dir)
    }

    /// A witness whose key is held in `keys`, as `create_witness` leaves it.
    async fn make_witness(keys: &WitnessKeys) -> WitnessRecord {
        let secret = Secret::generate_ed25519(None, None);
        let private_key_multibase = secret.get_private_keymultibase().unwrap();
        let public_key_multibase = secret.get_public_keymultibase().unwrap();
        keys.put(BTreeMap::from([(
            public_key_multibase.clone(),
            private_key_multibase,
        )]))
        .await
        .unwrap();
        WitnessRecord {
            witness_id: public_key_multibase.clone(),
            did: format!("did:key:{public_key_multibase}"),
            vta_key_id: None,
            public_key_multibase,
            label: Some("test-witness".into()),
            created_at: 0,
            proofs_signed: 0,
        }
    }

    #[tokio::test]
    async fn local_signer_produces_signed_proof() {
        let (keys, _dir) = temp_keys();
        let signer = LocalSigner::new(keys.clone());
        let witness = make_witness(&keys).await;
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
        let (keys, _dir) = temp_keys();
        let signer = LocalSigner::new(keys.clone());
        let witness = make_witness(&keys).await;
        let proof_a = signer.sign_proof(&witness, "1-aaa").await.unwrap();
        let proof_b = signer.sign_proof(&witness, "2-bbb").await.unwrap();
        let json_a = serde_json::to_value(&proof_a).unwrap();
        let json_b = serde_json::to_value(&proof_b).unwrap();
        assert_ne!(json_a["proofValue"], json_b["proofValue"]);
    }

    #[tokio::test]
    async fn local_signer_refuses_a_witness_with_no_held_key() {
        let (keys, _dir) = temp_keys();
        let signer = LocalSigner::new(keys.clone());
        let witness = make_witness(&keys).await;
        keys.remove(&witness.witness_id).await.unwrap();
        let err = signer
            .sign_proof(&witness, "1-version")
            .await
            .expect_err("no key, no proof");
        assert!(matches!(err, AppError::Internal(_)));
    }

    #[tokio::test]
    async fn local_signer_refuses_a_key_that_is_not_the_identitys() {
        let (keys, _dir) = temp_keys();
        let signer = LocalSigner::new(keys.clone());
        let witness = make_witness(&keys).await;
        let other = Secret::generate_ed25519(None, None)
            .get_private_keymultibase()
            .unwrap();
        keys.put(BTreeMap::from([(witness.witness_id.clone(), other)]))
            .await
            .unwrap();
        let err = signer
            .sign_proof(&witness, "1-version")
            .await
            .expect_err("a key for another identity must not sign");
        assert!(
            err.to_string().contains("belongs to another identity"),
            "{err}"
        );

        keys.put(BTreeMap::from([(
            witness.witness_id.clone(),
            "z6MkBOGUS".into(),
        )]))
        .await
        .unwrap();
        assert!(matches!(
            signer.sign_proof(&witness, "1-version").await,
            Err(AppError::Internal(_))
        ));
    }
}

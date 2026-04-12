//! VTA secret cache backed by the service's existing secret store.
//!
//! Stores the encoded [`DidSecretsBundle`] in a parallel entry alongside the
//! service's main secrets. This allows the VTA startup flow to persist fresh
//! keys for offline fallback without changing the `ServerSecrets` format.

use super::secret_store::SecretStore;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::integration::SecretCache;

/// Wraps an existing [`SecretStore`] to implement [`SecretCache`].
///
/// The bundle is stored as a serialized string inside a `ServerSecrets`
/// struct where the `vta_credential` field carries the encoded bundle.
/// This reuses the same backend (keyring, AWS, GCP, plaintext) without
/// requiring a separate storage entry.
///
/// The main `ServerSecrets` (with signing_key, jwt_signing_key, etc.)
/// is stored under the normal key. The VTA cache bundle piggybacks on
/// a separate `ServerSecrets` instance stored via a wrapper store that
/// uses a "-vta-cache" suffix.
///
/// For simplicity, we store the encoded bundle by updating the existing
/// `ServerSecrets.vta_credential` field — the setup wizard already stores
/// the VTA credential there, and on VTA refresh we replace it with the
/// encoded secrets bundle. This works because:
/// 1. The credential is only needed for re-auth (which uses the config)
/// 2. The bundle is what we need for offline fallback
pub struct WebvhSecretCache<'a> {
    store: &'a dyn SecretStore,
}

impl<'a> WebvhSecretCache<'a> {
    pub fn new(store: &'a dyn SecretStore) -> Self {
        Self { store }
    }
}

impl SecretCache for WebvhSecretCache<'_> {
    async fn store(
        &self,
        bundle: &DidSecretsBundle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let encoded = bundle
            .encode()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Failed to encode secrets bundle: {e}").into()
            })?;

        // Load existing secrets so we preserve signing_key, jwt_signing_key, etc.
        let mut secrets = match self.store.get().await {
            Ok(Some(s)) => s,
            Ok(None) => {
                // No secrets yet — this shouldn't happen at runtime, but handle gracefully
                tracing::debug!("No existing secrets to update — skipping VTA cache store");
                return Ok(());
            }
            Err(e) => {
                return Err(
                    format!("Failed to load existing secrets for cache update: {e}").into(),
                );
            }
        };

        // Store the encoded bundle in the vta_credential field
        secrets.vta_credential = Some(encoded);

        // Also update the individual key fields from the bundle
        for entry in &bundle.secrets {
            match entry.key_type {
                vta_sdk::keys::KeyType::Ed25519 => {
                    secrets.signing_key = entry.private_key_multibase.clone();
                }
                vta_sdk::keys::KeyType::X25519 => {
                    secrets.key_agreement_key = entry.private_key_multibase.clone();
                }
                _ => {}
            }
        }

        self.store.set(&secrets).await.map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Failed to save updated secrets: {e}").into()
            },
        )?;

        tracing::debug!("Cached VTA secrets bundle to secret store");
        Ok(())
    }

    async fn load(
        &self,
    ) -> Result<Option<DidSecretsBundle>, Box<dyn std::error::Error + Send + Sync>> {
        let secrets = match self.store.get().await {
            Ok(Some(s)) => s,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(format!("Failed to load secrets from store: {e}").into());
            }
        };

        match secrets.vta_credential {
            Some(ref encoded) if !encoded.is_empty() => {
                match DidSecretsBundle::decode(encoded) {
                    Ok(bundle) => {
                        tracing::debug!("Loaded {} cached secret(s)", bundle.secrets.len());
                        Ok(Some(bundle))
                    }
                    Err(_) => {
                        // vta_credential might contain the original credential string
                        // (from setup), not an encoded bundle — that's not a cached bundle
                        tracing::debug!(
                            "vta_credential is not an encoded secrets bundle (may be original credential)"
                        );
                        Ok(None)
                    }
                }
            }
            _ => Ok(None),
        }
    }
}

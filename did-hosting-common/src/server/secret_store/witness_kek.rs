//! The witness key-encryption key: its own secret-store entry.
//!
//! A witness seals each identity's signing key to this key and keeps the
//! sealed key in the identity's data-store record (`webvh_witness::
//! witness_keys`). The key-encryption key is written once and then only read,
//! so it lives in an entry of its own, beside the service envelope rather
//! than inside it:
//!
//! - no release, older or newer, rewrites it as a side effect of writing the
//!   envelope (rotation, expiry sweep, setup), so it cannot be dropped by a
//!   writer that does not know it;
//! - there is no read-modify-write on it, so writers in different processes
//!   cannot lose each other's changes.
//!
//! The entry is named after the envelope's, per backend; see
//! [`witness_kek_location`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use affinidi_secrets_resolver::secrets::Secret;
use vti_secrets::SeedStore;
use vti_secrets::seed_store::PlaintextSeedStore;

use super::{
    SecretBackend, from_vti, keyring_store_for, plaintext_path_named, resolve_backend,
    to_vti_config,
};
use crate::server::config::SecretsConfig;
use crate::server::error::AppError;

/// Suffix of the key-encryption key's entry name on the named backends.
const NAME_SUFFIX: &str = "-witness-kek";
/// The keyring entry (`user`) under `secrets.keyring_service`.
const KEYRING_USER: &str = "witness_key_encryption_key";

/// Bound on one read or write of the key-encryption key's entry. The cloud and
/// Vault backends are network calls; none of them is made on a request path,
/// but startup and the CLI must not hang on one.
pub const WITNESS_KEK_TIMEOUT: Duration = Duration::from_secs(15);

/// Where the key-encryption key is kept for `secrets`: a description an
/// operator can act on (the entry to grant access to, back up or restore).
pub fn witness_kek_location(secrets: &SecretsConfig, config_path: &Path) -> String {
    let named = |n: &Option<String>| format!("{}{NAME_SUFFIX}", n.as_deref().unwrap_or(""));
    match resolve_backend(secrets) {
        SecretBackend::Keyring => format!(
            "OS keyring service \"{}\", account \"{KEYRING_USER}\"",
            secrets.keyring_service
        ),
        SecretBackend::Aws => format!("AWS secret \"{}\"", named(&secrets.aws_secret_name)),
        SecretBackend::Gcp => format!("GCP secret \"{}\"", named(&secrets.gcp_secret_name)),
        SecretBackend::Azure => format!(
            "Azure Key Vault secret \"{}\"",
            named(&secrets.azure_secret_name)
        ),
        SecretBackend::Vault => format!("Vault path \"{}\"", named(&secrets.vault_secret_path)),
        SecretBackend::Kubernetes => {
            format!("Kubernetes Secret \"{}\"", named(&secrets.k8s_secret_name))
        }
        SecretBackend::Plaintext => format!("file {}", kek_plaintext_path(config_path).display()),
        _ => "an unsupported backend".into(),
    }
}

fn kek_plaintext_path(config_path: &Path) -> PathBuf {
    plaintext_path_named(config_path, "witness-kek")
}

/// The witness key-encryption key's entry.
pub struct WitnessKekStore {
    inner: Box<dyn SeedStore>,
    location: String,
}

/// Build the store for the witness key-encryption key on the backend
/// `secrets` selects, in an entry of its own (see [`witness_kek_location`]).
/// Fails closed exactly as [`super::create_secret_store`] does.
pub fn create_witness_kek_store(
    secrets: &SecretsConfig,
    config_path: &Path,
) -> Result<WitnessKekStore, AppError> {
    let mut vti = to_vti_config(secrets)?;
    let suffix = |n: &mut Option<String>| {
        if let Some(n) = n.as_mut() {
            n.push_str(NAME_SUFFIX);
        }
    };
    let inner: Box<dyn SeedStore> = match resolve_backend(secrets) {
        SecretBackend::Keyring => keyring_store_for(&vti, KEYRING_USER)?,
        SecretBackend::Plaintext => {
            let path = kek_plaintext_path(config_path);
            let dir = path.parent().unwrap_or_else(|| Path::new("."));
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("config.witness-kek.plaintext");
            Box::new(PlaintextSeedStore::with_filename(dir, name))
        }
        _ => {
            suffix(&mut vti.aws_secret_name);
            suffix(&mut vti.gcp_secret_name);
            suffix(&mut vti.azure_secret_name);
            suffix(&mut vti.vault_secret_path);
            suffix(&mut vti.k8s_secret_name);
            vti_secrets::create_seed_store(&vti, Path::new(".")).map_err(from_vti)?
        }
    };
    Ok(WitnessKekStore {
        inner,
        location: witness_kek_location(secrets, config_path),
    })
}

impl WitnessKekStore {
    /// Where the key is kept, for messages to the operator.
    pub fn location(&self) -> &str {
        &self.location
    }

    /// The key-encryption key (an X25519 secret), or `None` if none is held.
    pub async fn get(&self) -> Result<Option<Secret>, AppError> {
        let bytes = tokio::time::timeout(WITNESS_KEK_TIMEOUT, self.inner.get())
            .await
            .map_err(|_| self.timed_out("read"))?
            .map_err(from_vti)?;
        let Some(mut bytes) = bytes else {
            return Ok(None);
        };
        let parsed = std::str::from_utf8(&bytes)
            .map_err(|_| self.malformed())
            .and_then(|s| Secret::from_multibase(s.trim(), None).map_err(|_| self.malformed()));
        bytes.iter_mut().for_each(|b| *b = 0);
        parsed.map(Some)
    }

    /// Store `kek` (an X25519 secret).
    pub async fn set(&self, kek: &Secret) -> Result<(), AppError> {
        let encoded = kek
            .get_private_keymultibase()
            .map_err(|e| AppError::SecretStore(format!("cannot encode the key: {e}")))?;
        let mut bytes = encoded.into_bytes();
        let result = tokio::time::timeout(WITNESS_KEK_TIMEOUT, self.inner.set(&bytes))
            .await
            .map_err(|_| self.timed_out("write"))
            .and_then(|r| r.map_err(from_vti));
        bytes.iter_mut().for_each(|b| *b = 0);
        result
    }

    fn timed_out(&self, what: &str) -> AppError {
        AppError::SecretStore(format!(
            "the witness key-encryption key ({}) did not {what} within {}s",
            self.location,
            WITNESS_KEK_TIMEOUT.as_secs()
        ))
    }

    fn malformed(&self) -> AppError {
        AppError::SecretStore(format!(
            "the witness key-encryption key ({}) is not a multibase-encoded key",
            self.location
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plaintext() -> SecretsConfig {
        SecretsConfig {
            backend: Some(SecretBackend::Plaintext),
            confirm_plaintext: true,
            ..SecretsConfig::default()
        }
    }

    /// The key has its own entry: writing it leaves the envelope alone, and
    /// writing the envelope (as any release does on rotation) leaves it alone.
    #[tokio::test]
    async fn the_key_encryption_key_has_an_entry_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("w.toml");
        let kek_store = create_witness_kek_store(&plaintext(), &config).unwrap();
        assert!(kek_store.get().await.unwrap().is_none());

        let kek = Secret::generate_x25519(None, None).unwrap();
        kek_store.set(&kek).await.unwrap();

        let envelope = super::super::create_secret_store(&plaintext(), &config).unwrap();
        assert!(envelope.get().await.unwrap().is_none());
        envelope
            .set(&super::super::ServerSecrets {
                signing_key: "z6Mk".into(),
                key_agreement_key: "z6LS".into(),
                jwt_signing_key: "z6Mk".into(),
                vta_credential: None,
                retired: Vec::new(),
            })
            .await
            .unwrap();

        let read = kek_store.get().await.unwrap().expect("held");
        assert_eq!(read.get_public_bytes(), kek.get_public_bytes());
        assert_ne!(
            kek_plaintext_path(&config),
            super::super::plaintext_path(&config)
        );
    }

    #[test]
    fn each_backend_names_a_separate_entry() {
        let p = Path::new("/etc/w/config.toml");
        let aws = SecretsConfig {
            aws_secret_name: Some("webvh/witness".into()),
            ..SecretsConfig::default()
        };
        assert_eq!(
            witness_kek_location(&aws, p),
            "AWS secret \"webvh/witness-witness-kek\""
        );
        let k8s = SecretsConfig {
            k8s_secret_name: Some("witness".into()),
            ..SecretsConfig::default()
        };
        assert_eq!(
            witness_kek_location(&k8s, p),
            "Kubernetes Secret \"witness-witness-kek\""
        );
        assert!(witness_kek_location(&SecretsConfig::default(), p).contains(KEYRING_USER));
        assert!(witness_kek_location(&plaintext(), p).ends_with("config.witness-kek.plaintext"));
    }
}

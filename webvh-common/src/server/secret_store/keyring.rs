use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

use crate::server::error::AppError;
use tracing::debug;

use super::ServerSecrets;

/// Suffix appended to the keyring entry's `user` field for the
/// offline-bootstrap ephemeral seed. Keeps it in a separate keyring
/// entry from the long-lived `ServerSecrets` blob so the two have
/// independent lifecycles.
const BOOTSTRAP_SEED_USER_SUFFIX: &str = "::bootstrap_seed";

/// Set once the default credential store registration has succeeded. Failures
/// are *not* cached — a transient init error (e.g. dbus not yet up at boot)
/// is allowed to retry on the next `try_new` call rather than poisoning the
/// process for the rest of its lifetime. Successful registration is sticky:
/// subsequent calls observe the `OnceLock` and skip the work.
static REGISTERED: OnceLock<()> = OnceLock::new();

fn ensure_default_store() -> Result<(), AppError> {
    if REGISTERED.get().is_some() {
        return Ok(());
    }
    register_default_store().map_err(|e| {
        AppError::SecretStore(format!(
            "keyring default store could not be registered on this platform: {e}. \
             Either install the native credential store (macOS Keychain, Windows Credential Manager, \
             or a Secret Service implementation on Linux), or pick a different secret backend \
             (aws-secrets / gcp-secrets / azure-secrets / plaintext for testing)."
        ))
    })?;
    // Race-safe: if two threads both reach this point, `set` succeeds for
    // exactly one of them and the other observes a no-op `Err` (already set).
    let _ = REGISTERED.set(());
    Ok(())
}

#[cfg(target_os = "macos")]
fn register_default_store() -> Result<(), keyring_core::Error> {
    use apple_native_keyring_store::keychain::Store;
    keyring_core::set_default_store(Store::new()?);
    Ok(())
}

#[cfg(target_os = "windows")]
fn register_default_store() -> Result<(), keyring_core::Error> {
    use windows_native_keyring_store::store::Store;
    keyring_core::set_default_store(Store::new()?);
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn register_default_store() -> Result<(), keyring_core::Error> {
    use dbus_secret_service_keyring_store::store::Store;
    keyring_core::set_default_store(Store::new()?);
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
fn register_default_store() -> Result<(), keyring_core::Error> {
    Err(keyring_core::Error::NotSupportedByStore(
        "no native keyring backend available for this platform".to_string(),
    ))
}

pub struct KeyringSecretStore {
    service: String,
    user: String,
}

impl KeyringSecretStore {
    /// Initialise the keyring secret store and register the platform default
    /// credential store on first call. Returns an error (rather than panicking
    /// or silently degrading) when the backend is unavailable, so that the
    /// failure surfaces clearly at process startup instead of as a
    /// "secrets not found" misdirection later. This is the only constructor —
    /// callers must handle the `Err` arm rather than panicking via `.unwrap()`.
    pub fn try_new(service: impl Into<String>, user: impl Into<String>) -> Result<Self, AppError> {
        ensure_default_store()?;
        Ok(Self {
            service: service.into(),
            user: user.into(),
        })
    }

    fn bootstrap_seed_user(&self) -> String {
        format!("{}{BOOTSTRAP_SEED_USER_SUFFIX}", self.user)
    }
}

impl super::SecretStore for KeyringSecretStore {
    fn get(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ServerSecrets>, AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.user.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring_core::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                match entry.get_password() {
                    Ok(json_str) => {
                        let secrets: ServerSecrets =
                            serde_json::from_str(&json_str).map_err(|e| {
                                AppError::SecretStore(format!(
                                    "failed to deserialize secrets from keyring: {e}"
                                ))
                            })?;
                        debug!("secrets loaded from keyring");
                        Ok(Some(secrets))
                    }
                    Err(keyring_core::Error::NoEntry) => {
                        debug!("no secrets found in keyring");
                        Ok(None)
                    }
                    Err(e) => Err(AppError::SecretStore(format!(
                        "failed to read secrets from keyring: {e}"
                    ))),
                }
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }

    fn set(
        &self,
        secrets: &ServerSecrets,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.user.clone();
        let json_str = match serde_json::to_string(secrets) {
            Ok(s) => s,
            Err(e) => {
                return Box::pin(async move {
                    Err(AppError::Internal(format!("secrets serialization: {e}")))
                });
            }
        };
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring_core::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                entry.set_password(&json_str).map_err(|e| {
                    AppError::SecretStore(format!("failed to store secrets in keyring: {e}"))
                })?;
                debug!("secrets stored in keyring");
                Ok(())
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }

    fn get_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<[u8; 32]>, AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.bootstrap_seed_user();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring_core::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                match entry.get_password() {
                    Ok(b64) => {
                        use base64::Engine;
                        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
                        let bytes = B64.decode(b64.as_bytes()).map_err(|e| {
                            AppError::SecretStore(format!(
                                "failed to base64-decode bootstrap seed: {e}"
                            ))
                        })?;
                        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                            AppError::SecretStore(format!(
                                "bootstrap seed in keyring has {} bytes, expected 32",
                                bytes.len()
                            ))
                        })?;
                        debug!("bootstrap seed loaded from keyring");
                        Ok(Some(seed))
                    }
                    Err(keyring_core::Error::NoEntry) => Ok(None),
                    Err(e) => Err(AppError::SecretStore(format!(
                        "failed to read bootstrap seed from keyring: {e}"
                    ))),
                }
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }

    fn set_bootstrap_seed(
        &self,
        seed: &[u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.bootstrap_seed_user();
        let seed_owned = *seed;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                use base64::Engine;
                use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
                let b64 = B64.encode(seed_owned);
                let entry = keyring_core::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                entry.set_password(&b64).map_err(|e| {
                    AppError::SecretStore(format!("failed to store bootstrap seed in keyring: {e}"))
                })?;
                debug!("bootstrap seed stored in keyring");
                Ok(())
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }

    fn clear_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let service = self.service.clone();
        let user = self.bootstrap_seed_user();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let entry = keyring_core::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                match entry.delete_credential() {
                    Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
                    Err(e) => Err(AppError::SecretStore(format!(
                        "failed to clear bootstrap seed from keyring: {e}"
                    ))),
                }
            })
            .await
            .map_err(|e| AppError::Internal(format!("blocking task panicked: {e}")))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::secret_store::SecretStore;

    /// Round-trip ServerSecrets through the OS keychain. Skipped if the host
    /// keychain is not reachable (CI containers without a Secret Service
    /// implementation will hit this branch and exit clean rather than fail).
    #[tokio::test]
    async fn keyring_round_trip_when_backend_available() {
        let service = format!("affinidi-webvh-test-{}", uuid::Uuid::new_v4());
        let user = "round_trip";
        let store = match KeyringSecretStore::try_new(&service, user) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping keyring test — backend unavailable: {e}");
                return;
            }
        };

        let secrets = ServerSecrets {
            signing_key: "z6Mksigning_test".into(),
            key_agreement_key: "z6LSagreement_test".into(),
            jwt_signing_key: "z6Mkjwt_test".into(),
            vta_credential: Some("test-vta-blob".into()),
        };

        // Probe the backend with a write+delete; if the OS denies access in
        // this environment (sandboxed CI, no D-Bus session, etc.) we still
        // skip the round-trip rather than failing.
        if store.set(&secrets).await.is_err() {
            eprintln!("skipping keyring test — backend refused write");
            return;
        }

        let loaded = store.get().await.unwrap().expect("secrets present");
        assert_eq!(loaded.signing_key, secrets.signing_key);
        assert_eq!(loaded.key_agreement_key, secrets.key_agreement_key);
        assert_eq!(loaded.jwt_signing_key, secrets.jwt_signing_key);
        assert_eq!(loaded.vta_credential, secrets.vta_credential);

        // Bootstrap-seed lives in a separate entry under the same service.
        let seed = [7u8; 32];
        store.set_bootstrap_seed(&seed).await.unwrap();
        let read = store.get_bootstrap_seed().await.unwrap().unwrap();
        assert_eq!(read, seed);

        // Clean up the entries we just wrote so the test doesn't leave
        // long-lived items in the operator's keyring.
        store.clear_bootstrap_seed().await.unwrap();

        let entry = keyring_core::Entry::new(&service, user).unwrap();
        let _ = entry.delete_credential();
    }
}

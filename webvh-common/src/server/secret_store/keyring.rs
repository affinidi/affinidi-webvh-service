use std::future::Future;
use std::pin::Pin;

use crate::server::error::AppError;
use tracing::debug;

use super::ServerSecrets;

/// Suffix appended to the keyring entry's `user` field for the
/// offline-bootstrap ephemeral seed. Keeps it in a separate keyring
/// entry from the long-lived `ServerSecrets` blob so the two have
/// independent lifecycles.
const BOOTSTRAP_SEED_USER_SUFFIX: &str = "::bootstrap_seed";

pub struct KeyringSecretStore {
    service: String,
    user: String,
}

impl KeyringSecretStore {
    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
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
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
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
                    Err(keyring::Error::NoEntry) => {
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
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
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
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
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
                    Err(keyring::Error::NoEntry) => Ok(None),
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
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
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
                let entry = keyring::Entry::new(&service, &user).map_err(|e| {
                    AppError::SecretStore(format!("failed to create keyring entry: {e}"))
                })?;
                match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
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

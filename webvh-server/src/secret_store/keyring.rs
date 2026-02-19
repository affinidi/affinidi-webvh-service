use std::future::Future;
use std::pin::Pin;

use crate::error::AppError;
use tracing::debug;

use super::ServerSecrets;

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
        let json_str = serde_json::to_string(secrets).expect("ServerSecrets serialization");
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
}

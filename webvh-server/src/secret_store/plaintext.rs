use std::path::PathBuf;

use crate::config::PlaintextSecrets;
use crate::error::AppError;

use super::{BoxFuture, SecretStore, ServerSecrets};

/// Secret store backend that reads/writes secrets as plaintext in the config file.
///
/// **WARNING**: This is insecure — secrets are stored unencrypted on disk.
/// Only use for testing and development. For production, compile with a secure
/// backend: `keyring`, `aws-secrets`, or `gcp-secrets`.
pub struct PlaintextSecretStore {
    secrets: Option<ServerSecrets>,
    config_path: PathBuf,
}

impl PlaintextSecretStore {
    pub fn new(plaintext: Option<&PlaintextSecrets>, config_path: PathBuf) -> Self {
        Self {
            secrets: plaintext.map(|p| ServerSecrets {
                signing_key: p.signing_key.clone(),
                key_agreement_key: p.key_agreement_key.clone(),
                jwt_signing_key: p.jwt_signing_key.clone(),
            }),
            config_path,
        }
    }
}

impl SecretStore for PlaintextSecretStore {
    fn get(&self) -> BoxFuture<'_, Result<Option<ServerSecrets>, AppError>> {
        let secrets = self.secrets.clone();
        Box::pin(async move { Ok(secrets) })
    }

    fn set(&self, secrets: &ServerSecrets) -> BoxFuture<'_, Result<(), AppError>> {
        let secrets = secrets.clone();
        let config_path = self.config_path.clone();
        Box::pin(async move {
            // Read the existing config file
            let contents = tokio::fs::read_to_string(&config_path)
                .await
                .map_err(|e| {
                    AppError::Config(format!(
                        "failed to read config file {}: {e}",
                        config_path.display()
                    ))
                })?;

            let mut doc: toml::Value = contents.parse().map_err(|e| {
                AppError::Config(format!(
                    "failed to parse config file {}: {e}",
                    config_path.display()
                ))
            })?;

            // Build the plaintext secrets value
            let plaintext = PlaintextSecrets {
                signing_key: secrets.signing_key,
                key_agreement_key: secrets.key_agreement_key,
                jwt_signing_key: secrets.jwt_signing_key,
            };

            let plaintext_value = toml::Value::try_from(&plaintext).map_err(|e| {
                AppError::Config(format!("failed to serialize plaintext secrets: {e}"))
            })?;

            // Insert into [secrets.plaintext]
            let root = doc
                .as_table_mut()
                .ok_or_else(|| AppError::Config("config root is not a table".into()))?;

            let secrets_table = root
                .entry("secrets")
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut()
                .ok_or_else(|| AppError::Config("[secrets] is not a table".into()))?;

            secrets_table.insert("plaintext".to_string(), plaintext_value);

            // Write back
            let output = toml::to_string_pretty(&doc).map_err(|e| {
                AppError::Config(format!("failed to serialize config: {e}"))
            })?;

            tokio::fs::write(&config_path, output).await.map_err(|e| {
                AppError::Config(format!(
                    "failed to write config file {}: {e}",
                    config_path.display()
                ))
            })?;

            Ok(())
        })
    }
}

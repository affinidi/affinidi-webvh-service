use std::path::PathBuf;

use crate::server::config::PlaintextSecrets;
use crate::server::error::AppError;
use tracing::warn;

use super::{BoxFuture, SecretStore, ServerSecrets};

/// Secret store backend that reads/writes secrets as plaintext in the config file.
///
/// **WARNING**: This is insecure — secrets are stored unencrypted on disk.
/// Only use for testing and development. For production, compile with a secure
/// backend: `keyring`, `aws-secrets`, or `gcp-secrets`.
pub struct PlaintextSecretStore {
    secrets: Option<ServerSecrets>,
    /// Initial seed value lifted from `[secrets.plaintext_bootstrap_seed]`
    /// at construction. Phase 2 reads it via `get_bootstrap_seed`; later
    /// `clear_bootstrap_seed` rewrites the config.toml without the field.
    bootstrap_seed_b64: Option<String>,
    config_path: PathBuf,
}

impl PlaintextSecretStore {
    pub fn new(
        plaintext: Option<&PlaintextSecrets>,
        bootstrap_seed_b64: Option<String>,
        config_path: PathBuf,
    ) -> Self {
        warn!(
            "plaintext secret store is insecure — use keyring, aws-secrets, or gcp-secrets in production"
        );
        Self {
            secrets: plaintext.map(|p| ServerSecrets {
                signing_key: p.signing_key.clone(),
                key_agreement_key: p.key_agreement_key.clone(),
                jwt_signing_key: p.jwt_signing_key.clone(),
                vta_credential: None,
            }),
            bootstrap_seed_b64,
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
            let contents = tokio::fs::read_to_string(&config_path).await.map_err(|e| {
                AppError::Config(format!(
                    "failed to read config file {}: {e}",
                    config_path.display()
                ))
            })?;

            let mut doc: toml::Value = toml::from_str(&contents).map_err(|e| {
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
            let output = toml::to_string_pretty(&doc)
                .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;

            tokio::fs::write(&config_path, output).await.map_err(|e| {
                AppError::Config(format!(
                    "failed to write config file {}: {e}",
                    config_path.display()
                ))
            })?;

            Ok(())
        })
    }

    fn get_bootstrap_seed(&self) -> super::BoxFuture<'_, Result<Option<[u8; 32]>, AppError>> {
        let b64 = self.bootstrap_seed_b64.clone();
        Box::pin(async move {
            let Some(b64) = b64 else { return Ok(None) };
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
            let bytes = B64.decode(b64.as_bytes()).map_err(|e| {
                AppError::SecretStore(format!(
                    "failed to base64-decode plaintext bootstrap seed: {e}"
                ))
            })?;
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                AppError::SecretStore(format!(
                    "plaintext bootstrap seed has {} bytes, expected 32",
                    bytes.len()
                ))
            })?;
            Ok(Some(seed))
        })
    }

    fn set_bootstrap_seed(&self, seed: &[u8; 32]) -> super::BoxFuture<'_, Result<(), AppError>> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        let b64 = B64.encode(seed);
        let config_path = self.config_path.clone();
        Box::pin(async move { write_plaintext_seed_field(&config_path, Some(&b64)).await })
    }

    fn clear_bootstrap_seed(&self) -> super::BoxFuture<'_, Result<(), AppError>> {
        let config_path = self.config_path.clone();
        Box::pin(async move { write_plaintext_seed_field(&config_path, None).await })
    }
}

/// Rewrite `[secrets].plaintext_bootstrap_seed` in `config_path`
/// to `value` (or remove the field when `None`). Preserves all other
/// config fields. Tolerates a missing config file at phase 1 of the
/// offline-bootstrap wizard — the file is created with just the
/// `[secrets]` table; phase 2's `finalize_*_setup` later overwrites
/// it with the full config.
async fn write_plaintext_seed_field(
    config_path: &std::path::Path,
    value: Option<&str>,
) -> Result<(), AppError> {
    let contents = match tokio::fs::read_to_string(config_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(AppError::Config(format!(
                "failed to read config file {}: {e}",
                config_path.display()
            )));
        }
    };
    let mut doc: toml::Value = if contents.is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(&contents).map_err(|e| {
            AppError::Config(format!(
                "failed to parse config file {}: {e}",
                config_path.display()
            ))
        })?
    };
    let root = doc
        .as_table_mut()
        .ok_or_else(|| AppError::Config("config root is not a table".into()))?;
    let secrets_table = root
        .entry("secrets")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| AppError::Config("[secrets] is not a table".into()))?;
    match value {
        Some(b64) => {
            secrets_table.insert(
                "plaintext_bootstrap_seed".to_string(),
                toml::Value::String(b64.to_string()),
            );
        }
        None => {
            secrets_table.remove("plaintext_bootstrap_seed");
        }
    }
    let output = toml::to_string_pretty(&doc)
        .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
    if let Some(parent) = config_path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            AppError::Config(format!(
                "failed to create config dir {}: {e}",
                parent.display()
            ))
        })?;
    }
    tokio::fs::write(config_path, output).await.map_err(|e| {
        AppError::Config(format!(
            "failed to write config file {}: {e}",
            config_path.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secrets() -> ServerSecrets {
        ServerSecrets {
            signing_key: "z6Mktest_signing".into(),
            key_agreement_key: "z6LStest_agreement".into(),
            jwt_signing_key: "z6Mktest_jwt".into(),
            vta_credential: None,
        }
    }

    fn sample_plaintext() -> PlaintextSecrets {
        PlaintextSecrets {
            signing_key: "z6Mktest_signing".into(),
            key_agreement_key: "z6LStest_agreement".into(),
            jwt_signing_key: "z6Mktest_jwt".into(),
        }
    }

    #[tokio::test]
    async fn get_returns_none_when_no_plaintext_configured() {
        let store = PlaintextSecretStore::new(None, None, PathBuf::from("nonexistent.toml"));
        let result = store.get().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_returns_secrets_when_plaintext_configured() {
        let pt = sample_plaintext();
        let store = PlaintextSecretStore::new(Some(&pt), None, PathBuf::from("unused.toml"));
        let result = store.get().await.unwrap().expect("should have secrets");
        assert_eq!(result.signing_key, "z6Mktest_signing");
        assert_eq!(result.key_agreement_key, "z6LStest_agreement");
        assert_eq!(result.jwt_signing_key, "z6Mktest_jwt");
    }

    #[tokio::test]
    async fn set_writes_plaintext_section_to_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        // Write a minimal config file
        tokio::fs::write(&config_path, "[server]\nhost = \"0.0.0.0\"\n")
            .await
            .unwrap();

        let store = PlaintextSecretStore::new(None, None, config_path.clone());
        store.set(&sample_secrets()).await.unwrap();

        // Read back and verify [secrets.plaintext] was added
        let contents = tokio::fs::read_to_string(&config_path).await.unwrap();
        let doc: toml::Value = toml::from_str(&contents).unwrap();

        let plaintext = doc["secrets"]["plaintext"].as_table().unwrap();
        assert_eq!(
            plaintext["signing_key"].as_str().unwrap(),
            "z6Mktest_signing"
        );
        assert_eq!(
            plaintext["key_agreement_key"].as_str().unwrap(),
            "z6LStest_agreement"
        );
        assert_eq!(
            plaintext["jwt_signing_key"].as_str().unwrap(),
            "z6Mktest_jwt"
        );
    }

    #[tokio::test]
    async fn set_preserves_existing_config_fields() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        let initial = r#"
[server]
host = "127.0.0.1"
port = 9000

[secrets]
keyring_service = "my-service"
"#;
        tokio::fs::write(&config_path, initial).await.unwrap();

        let store = PlaintextSecretStore::new(None, None, config_path.clone());
        store.set(&sample_secrets()).await.unwrap();

        let contents = tokio::fs::read_to_string(&config_path).await.unwrap();
        let doc: toml::Value = toml::from_str(&contents).unwrap();

        // Original fields preserved
        assert_eq!(doc["server"]["host"].as_str().unwrap(), "127.0.0.1");
        assert_eq!(doc["server"]["port"].as_integer().unwrap(), 9000);
        assert_eq!(
            doc["secrets"]["keyring_service"].as_str().unwrap(),
            "my-service"
        );

        // Plaintext secrets added
        assert!(doc["secrets"]["plaintext"].is_table());
    }

    #[tokio::test]
    async fn set_then_reload_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        // Write a minimal valid AppConfig
        let initial = r#"
[features]
didcomm = false
rest_api = true
"#;
        tokio::fs::write(&config_path, initial).await.unwrap();

        // Store secrets via set()
        let store = PlaintextSecretStore::new(None, None, config_path.clone());
        store.set(&sample_secrets()).await.unwrap();

        // Read the file back and parse the plaintext section
        let contents = tokio::fs::read_to_string(&config_path).await.unwrap();
        let doc: toml::Value = toml::from_str(&contents).unwrap();
        let pt_value = &doc["secrets"]["plaintext"];
        let reloaded: PlaintextSecrets = pt_value
            .clone()
            .try_into()
            .expect("should deserialize PlaintextSecrets");

        // Create a new store from the reloaded data and verify get() works
        let store2 = PlaintextSecretStore::new(Some(&reloaded), None, config_path);
        let result = store2.get().await.unwrap().expect("should have secrets");
        assert_eq!(result.signing_key, "z6Mktest_signing");
        assert_eq!(result.key_agreement_key, "z6LStest_agreement");
        assert_eq!(result.jwt_signing_key, "z6Mktest_jwt");
    }

    #[tokio::test]
    async fn set_errors_on_missing_config_file() {
        let store =
            PlaintextSecretStore::new(None, None, PathBuf::from("/nonexistent/path/config.toml"));
        let result = store.set(&sample_secrets()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bootstrap_seed_set_get_clear_roundtrip_via_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        tokio::fs::write(&config_path, "[server]\nhost = \"0.0.0.0\"\n")
            .await
            .unwrap();

        // Phase 1 perspective: store is built fresh (no preloaded seed).
        let store = PlaintextSecretStore::new(None, None, config_path.clone());
        let seed = [42u8; 32];
        store.set_bootstrap_seed(&seed).await.unwrap();

        // Re-construct to mimic phase 2 reading from disk after a
        // restart — load the b64 from `[secrets].plaintext_bootstrap_seed`.
        let contents = tokio::fs::read_to_string(&config_path).await.unwrap();
        let doc: toml::Value = toml::from_str(&contents).unwrap();
        let b64 = doc["secrets"]["plaintext_bootstrap_seed"]
            .as_str()
            .unwrap()
            .to_string();

        let phase2 = PlaintextSecretStore::new(None, Some(b64), config_path.clone());
        let read = phase2.get_bootstrap_seed().await.unwrap().unwrap();
        assert_eq!(read, seed);

        // Clear removes the field from the config.toml.
        phase2.clear_bootstrap_seed().await.unwrap();
        let contents = tokio::fs::read_to_string(&config_path).await.unwrap();
        let doc: toml::Value = toml::from_str(&contents).unwrap();
        assert!(doc["secrets"].get("plaintext_bootstrap_seed").is_none());
    }

    #[tokio::test]
    async fn bootstrap_seed_get_returns_none_when_unset() {
        let store = PlaintextSecretStore::new(None, None, PathBuf::from("nonexistent.toml"));
        assert!(store.get_bootstrap_seed().await.unwrap().is_none());
    }
}

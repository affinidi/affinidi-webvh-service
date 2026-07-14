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
///
/// Both bootstrap-seed reads and writes go through the on-disk config file
/// — there is no in-memory cache of the seed. Earlier revisions cached the
/// seed at construction, which made phase 2 of the offline-bootstrap
/// wizard fail: phase 1 wrote the seed to disk but the `SecretsConfig`
/// snapshot the wizard saved into `setup-offline-state.toml` still had
/// `plaintext_bootstrap_seed = None`, so phase 2 reconstructed the store
/// against a stale snapshot and reported "bootstrap seed missing from
/// secret store — phase 1 may not have run".
pub struct PlaintextSecretStore {
    secrets: Option<ServerSecrets>,
    config_path: PathBuf,
}

impl PlaintextSecretStore {
    pub fn new(plaintext: Option<&PlaintextSecrets>, config_path: PathBuf) -> Self {
        warn!(
            "plaintext secret store is insecure — use keyring, aws-secrets, or gcp-secrets in production"
        );
        Self {
            secrets: plaintext.map(|p| ServerSecrets {
                signing_key: p.signing_key.clone(),
                key_agreement_key: p.key_agreement_key.clone(),
                jwt_signing_key: p.jwt_signing_key.clone(),
                vta_credential: p.vta_credential.clone(),
                retired: p.retired.clone(),
            }),
            config_path,
        }
    }
}

impl SecretStore for PlaintextSecretStore {
    /// Read the secrets, preferring the **file** over the construction-time
    /// snapshot.
    ///
    /// The snapshot comes from the `AppConfig` a caller happened to be holding,
    /// which goes stale the moment anything writes new key material — and the
    /// thing that writes it (`import-secrets`) runs in a *different process*.
    /// A running service reloading its identity would otherwise read the keys it
    /// booted with, fail to match them against the freshly-published DID
    /// document, and refuse the rotation with a message blaming the operator for
    /// an ordering mistake they did not make.
    ///
    /// This mirrors `get_bootstrap_seed`, which already re-reads the file for
    /// exactly this reason (the offline-wizard staleness bug). The file is the
    /// source of truth in plaintext mode; the snapshot is only a fallback for
    /// callers constructed without a readable config path.
    fn get(&self) -> BoxFuture<'_, Result<Option<ServerSecrets>, AppError>> {
        let snapshot = self.secrets.clone();
        let config_path = self.config_path.clone();
        Box::pin(async move {
            match read_plaintext_secrets(&config_path).await {
                Ok(Some(from_file)) => Ok(Some(from_file)),
                // No `[secrets.plaintext]` on disk, or the file is unreadable —
                // fall back rather than pretending the service has no secrets.
                Ok(None) => Ok(snapshot),
                Err(e) => {
                    warn!(
                        "failed to re-read plaintext secrets from config ({e}) — using the snapshot"
                    );
                    Ok(snapshot)
                }
            }
        })
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

            // Build the plaintext secrets value (preserving vta_credential and
            // the retired key material — dropping the latter here would lose
            // the outgoing key on the very write that installs its
            // replacement, which is the one write that must not lose it).
            let plaintext = PlaintextSecrets {
                signing_key: secrets.signing_key,
                key_agreement_key: secrets.key_agreement_key,
                jwt_signing_key: secrets.jwt_signing_key,
                vta_credential: secrets.vta_credential,
                retired: secrets.retired,
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
        // Always re-read the config file. The wizard's phase-1/phase-2
        // split serialises a `SecretsConfig` snapshot before writing the
        // seed, so any in-memory cache here would be stale by phase 2.
        // The on-disk file is the source of truth for plaintext mode.
        let config_path = self.config_path.clone();
        Box::pin(async move { read_plaintext_seed_field(&config_path).await })
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

/// Read `[secrets.plaintext]` from `config_path`.
///
/// Returns `Ok(None)` when the file is missing or carries no plaintext secrets —
/// the caller then falls back to its construction-time snapshot.
async fn read_plaintext_secrets(
    config_path: &std::path::Path,
) -> Result<Option<ServerSecrets>, AppError> {
    let contents = match tokio::fs::read_to_string(config_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AppError::Config(format!(
                "failed to read config file {}: {e}",
                config_path.display()
            )));
        }
    };

    let doc: toml::Value = toml::from_str(&contents).map_err(|e| {
        AppError::Config(format!(
            "failed to parse config file {}: {e}",
            config_path.display()
        ))
    })?;

    let Some(value) = doc.get("secrets").and_then(|s| s.get("plaintext")) else {
        return Ok(None);
    };

    let plaintext: PlaintextSecrets = value
        .clone()
        .try_into()
        .map_err(|e| AppError::Config(format!("failed to parse [secrets.plaintext]: {e}")))?;

    Ok(Some(ServerSecrets {
        signing_key: plaintext.signing_key,
        key_agreement_key: plaintext.key_agreement_key,
        jwt_signing_key: plaintext.jwt_signing_key,
        vta_credential: plaintext.vta_credential,
        retired: plaintext.retired,
    }))
}

/// Read `[secrets].plaintext_bootstrap_seed` from `config_path`. Returns
/// `None` when the file is missing (e.g. phase 1 hasn't run yet) or the
/// field is absent. Errors only on malformed TOML or seed bytes.
///
/// This is the read counterpart to [`write_plaintext_seed_field`]: the
/// pair forms the round-trip `set` / `get` for the bootstrap seed in
/// plaintext mode. Reading directly from disk (rather than caching at
/// construction) is what closes the offline-wizard staleness bug —
/// phase 1's `set_bootstrap_seed` writes to the same file phase 2's
/// `get_bootstrap_seed` will read from, regardless of what
/// `SecretsConfig` snapshot the wizard happened to serialise.
async fn read_plaintext_seed_field(
    config_path: &std::path::Path,
) -> Result<Option<[u8; 32]>, AppError> {
    let contents = match tokio::fs::read_to_string(config_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AppError::Config(format!(
                "failed to read config file {}: {e}",
                config_path.display()
            )));
        }
    };
    let doc: toml::Value = toml::from_str(&contents).map_err(|e| {
        AppError::Config(format!(
            "failed to parse config file {}: {e}",
            config_path.display()
        ))
    })?;
    let Some(b64) = doc
        .get("secrets")
        .and_then(|s| s.get("plaintext_bootstrap_seed"))
        .and_then(|v| v.as_str())
    else {
        return Ok(None);
    };
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
            retired: Vec::new(),
        }
    }

    fn sample_plaintext() -> PlaintextSecrets {
        PlaintextSecrets {
            signing_key: "z6Mktest_signing".into(),
            key_agreement_key: "z6LStest_agreement".into(),
            jwt_signing_key: "z6Mktest_jwt".into(),
            vta_credential: None,
            retired: Vec::new(),
        }
    }

    #[tokio::test]
    async fn get_returns_none_when_no_plaintext_configured() {
        let store = PlaintextSecretStore::new(None, PathBuf::from("nonexistent.toml"));
        let result = store.get().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn set_preserves_retired_key_material() {
        // A rotation writes the outgoing key into `retired` in the *same* call
        // that installs its replacement — there is no compare-and-swap, so this
        // is the one write that must not lose it. An earlier draft of this
        // backend rebuilt `PlaintextSecrets` with `retired: Vec::new()`, which
        // silently dropped the old private key on exactly that write and left a
        // restart mid-rotation unable to decrypt traffic still addressed to it.
        use crate::server::secret_store::RetiredKeys;

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        tokio::fs::write(&config_path, "[server]\nport = 8080\n")
            .await
            .expect("seed config");

        let store = PlaintextSecretStore::new(None, config_path.clone());

        let mut secrets = sample_secrets();
        secrets.retired = vec![RetiredKeys {
            ka_kid: "did:webvh:example:alpha#z6LSold".into(),
            key_agreement_key: "z6LSold_private".into(),
            signing_kid: "did:webvh:example:alpha#z6Mkold".into(),
            signing_key: "z6Mkold_private".into(),
        }];

        store.set(&secrets).await.expect("write secrets");

        // Re-read through the config file, as a fresh boot would.
        let contents = tokio::fs::read_to_string(&config_path)
            .await
            .expect("read config");
        let parsed: toml::Value = toml::from_str(&contents).expect("parse config");
        let plaintext: PlaintextSecrets = parsed["secrets"]["plaintext"]
            .clone()
            .try_into()
            .expect("plaintext secrets present");

        assert_eq!(
            plaintext.retired.len(),
            1,
            "retired key material must survive the write that installs its replacement"
        );
        assert_eq!(
            plaintext.retired[0].ka_kid,
            "did:webvh:example:alpha#z6LSold"
        );
        assert_eq!(plaintext.retired[0].key_agreement_key, "z6LSold_private");
    }

    #[tokio::test]
    async fn get_returns_secrets_when_plaintext_configured() {
        let pt = sample_plaintext();
        let store = PlaintextSecretStore::new(Some(&pt), PathBuf::from("unused.toml"));
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

        let store = PlaintextSecretStore::new(None, config_path.clone());
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

        let store = PlaintextSecretStore::new(None, config_path.clone());
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
        let store = PlaintextSecretStore::new(None, config_path.clone());
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
        let store2 = PlaintextSecretStore::new(Some(&reloaded), config_path);
        let result = store2.get().await.unwrap().expect("should have secrets");
        assert_eq!(result.signing_key, "z6Mktest_signing");
        assert_eq!(result.key_agreement_key, "z6LStest_agreement");
        assert_eq!(result.jwt_signing_key, "z6Mktest_jwt");
    }

    #[tokio::test]
    async fn set_errors_on_missing_config_file() {
        let store = PlaintextSecretStore::new(None, PathBuf::from("/nonexistent/path/config.toml"));
        let result = store.set(&sample_secrets()).await;
        assert!(result.is_err());
    }

    /// Regression for the offline-bootstrap wizard bug. Phase 1 writes the
    /// seed to disk and serialises a `SecretsConfig` snapshot into
    /// `setup-offline-state.toml` — but the snapshot was captured *before*
    /// the seed was written, so phase 2 reconstructs the store with no
    /// in-memory seed. Earlier revisions cached the seed at construction
    /// and would report "bootstrap seed missing from secret store —
    /// phase 1 may not have run" here. The store must read the seed
    /// directly from the config file.
    #[tokio::test]
    async fn bootstrap_seed_set_get_clear_roundtrip_via_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        tokio::fs::write(&config_path, "[server]\nhost = \"0.0.0.0\"\n")
            .await
            .unwrap();

        // Phase 1: write the seed.
        let phase1 = PlaintextSecretStore::new(None, config_path.clone());
        let seed = [42u8; 32];
        phase1.set_bootstrap_seed(&seed).await.unwrap();

        // Phase 2: a fresh store, *without* a preloaded seed — exactly
        // what `create_secret_store` constructs after deserialising
        // `state.secrets` from `setup-offline-state.toml`. Must still
        // surface the seed.
        let phase2 = PlaintextSecretStore::new(None, config_path.clone());
        let read = phase2
            .get_bootstrap_seed()
            .await
            .unwrap()
            .expect("phase 2 must read the seed phase 1 wrote, even with a stale snapshot");
        assert_eq!(read, seed);

        // Clear removes the field from the config.toml.
        phase2.clear_bootstrap_seed().await.unwrap();
        let contents = tokio::fs::read_to_string(&config_path).await.unwrap();
        let doc: toml::Value = toml::from_str(&contents).unwrap();
        assert!(doc["secrets"].get("plaintext_bootstrap_seed").is_none());

        // After clearing, get returns None on the same store — the file
        // is the source of truth.
        assert!(phase2.get_bootstrap_seed().await.unwrap().is_none());
    }

    /// Same regression, but driven through `create_secret_store` — the
    /// public entry point both wizards and runtime callers go through.
    /// Mimics the wizard's exact flow: serialise `SecretsConfig` after
    /// phase 1, deserialise in phase 2, then look up the seed.
    #[tokio::test]
    #[cfg(not(feature = "keyring"))]
    async fn create_secret_store_bootstrap_seed_survives_wizard_serialisation() {
        use crate::server::config::SecretsConfig;
        use crate::server::secret_store::create_secret_store;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        tokio::fs::write(&config_path, "[server]\nhost = \"0.0.0.0\"\n")
            .await
            .unwrap();

        // Phase 1: wizard captures the SecretsConfig (no seed yet) and
        // then writes the seed via the freshly-built store.
        let secrets = SecretsConfig::default();
        let phase1 = create_secret_store(&secrets, &config_path).unwrap();
        let seed = [7u8; 32];
        phase1.set_bootstrap_seed(&seed).await.unwrap();

        // Phase 1 then serialises `secrets` into `setup-offline-state.toml`
        // — the snapshot is stale (still has plaintext_bootstrap_seed: None).
        let state_toml = toml::to_string_pretty(&secrets).unwrap();
        let snapshot: SecretsConfig = toml::from_str(&state_toml).unwrap();
        assert!(
            snapshot.plaintext_bootstrap_seed.is_none(),
            "snapshot is stale by design — fix must not depend on it being populated"
        );

        // Phase 2: rebuild the store from the stale snapshot and the
        // same config_path. Must still find the seed phase 1 wrote.
        let phase2 = create_secret_store(&snapshot, &config_path).unwrap();
        let read = phase2
            .get_bootstrap_seed()
            .await
            .unwrap()
            .expect("phase 2 must read the seed regardless of SecretsConfig staleness");
        assert_eq!(read, seed);
    }

    /// Malformed seed bytes surface as `SecretStore` errors, not silent
    /// `None`. Operator-edited config files with hand-typed seeds need a
    /// loud failure so the typo is fixable, not silently retried as
    /// "phase 1 didn't run".
    #[tokio::test]
    async fn bootstrap_seed_get_errors_on_malformed_seed() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        // Valid base64url-no-pad, but only 3 bytes — not 32.
        tokio::fs::write(
            &config_path,
            "[secrets]\nplaintext_bootstrap_seed = \"AAAA\"\n",
        )
        .await
        .unwrap();
        let store = PlaintextSecretStore::new(None, config_path);
        let err = store.get_bootstrap_seed().await.unwrap_err();
        assert!(
            matches!(err, AppError::SecretStore(_)),
            "expected SecretStore, got {err:?}"
        );
    }

    #[tokio::test]
    async fn set_persists_vta_credential_and_round_trips_via_get() {
        // Regression: PlaintextSecretStore::set used to drop secrets.vta_credential.
        // After 0.6.0, the credential must round-trip through the on-disk config.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        tokio::fs::write(&config_path, "[server]\nhost = \"0.0.0.0\"\n")
            .await
            .unwrap();

        let store = PlaintextSecretStore::new(None, config_path.clone());
        let mut s = sample_secrets();
        s.vta_credential = Some("opaque-vta-credential-blob".into());
        store.set(&s).await.unwrap();

        // Verify the credential is on disk.
        let contents = tokio::fs::read_to_string(&config_path).await.unwrap();
        let doc: toml::Value = toml::from_str(&contents).unwrap();
        let pt_value = &doc["secrets"]["plaintext"];
        let reloaded: PlaintextSecrets = pt_value.clone().try_into().unwrap();
        assert_eq!(
            reloaded.vta_credential.as_deref(),
            Some("opaque-vta-credential-blob")
        );

        // Verify a fresh store loads it back via get().
        let store2 = PlaintextSecretStore::new(Some(&reloaded), config_path);
        let read = store2.get().await.unwrap().expect("secrets present");
        assert_eq!(
            read.vta_credential.as_deref(),
            Some("opaque-vta-credential-blob")
        );
    }

    #[tokio::test]
    async fn bootstrap_seed_get_returns_none_when_unset() {
        let store = PlaintextSecretStore::new(None, PathBuf::from("nonexistent.toml"));
        assert!(store.get_bootstrap_seed().await.unwrap().is_none());
    }
}

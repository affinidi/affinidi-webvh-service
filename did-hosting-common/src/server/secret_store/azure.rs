use std::future::Future;
use std::pin::Pin;

use azure_core::http::StatusCode;
use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{
    SecretClient,
    models::{SecretClientGetSecretOptions, SetSecretParameters},
};
use tracing::debug;

use crate::server::error::AppError;

use super::{ServerSecrets, StoredSecrets};

/// Legacy suffix used by 0.6.0–0.6.1 deployments to store the
/// offline-bootstrap ephemeral seed in a sibling Key Vault secret. The
/// current envelope-based design keeps the seed inside the same secret
/// as `ServerSecrets`. Filtering siblings out of [`list_secret_names`]
/// keeps the wizard tidy when stragglers exist.
const LEGACY_BOOTSTRAP_SEED_SUFFIX: &str = "-bootstrap-seed";

/// Secret store backed by Azure Key Vault.
///
/// A single Key Vault secret holds a JSON [`StoredSecrets`] envelope
/// containing both the long-lived [`ServerSecrets`] and the optional
/// offline-bootstrap ephemeral seed, so a single RBAC grant covers
/// both. Auth is resolved via `DeveloperToolsCredential`, which chains
/// through the standard Azure credential sources (environment vars,
/// managed identity, az CLI, VS Code).
pub struct AzureKeyVaultStore {
    vault_url: String,
    secret_name: String,
}

impl AzureKeyVaultStore {
    pub fn new(vault_url: String, secret_name: String) -> Self {
        Self {
            vault_url,
            secret_name,
        }
    }

    fn client(&self) -> Result<SecretClient, AppError> {
        let credential = DeveloperToolsCredential::new(None).map_err(|e| {
            AppError::SecretStore(format!(
                "failed to obtain Azure credential (DeveloperToolsCredential): {e}"
            ))
        })?;
        SecretClient::new(&self.vault_url, credential, None)
            .map_err(|e| AppError::SecretStore(format!("Azure Key Vault client error: {e}")))
    }

    /// Read the current envelope. Returns `None` when the secret does
    /// not yet exist. Legacy bare-`ServerSecrets` blobs migrate
    /// transparently on the next write.
    async fn read_envelope(
        &self,
        client: &SecretClient,
    ) -> Result<Option<StoredSecrets>, AppError> {
        let result = client
            .get_secret(&self.secret_name, None::<SecretClientGetSecretOptions<'_>>)
            .await;

        match result {
            Ok(response) => {
                let secret = response.into_model().map_err(|e| {
                    AppError::SecretStore(format!(
                        "failed to deserialize Azure secret response: {e}"
                    ))
                })?;
                let value = secret.value.ok_or_else(|| {
                    AppError::SecretStore(
                        "Azure Key Vault secret exists but has no string value".into(),
                    )
                })?;
                let env = StoredSecrets::parse(value.trim()).map_err(|e| {
                    AppError::SecretStore(format!(
                        "failed to deserialize secrets from Azure Key Vault: {e}"
                    ))
                })?;
                Ok(Some(env))
            }
            Err(e) => {
                if is_not_found(&e) {
                    Ok(None)
                } else {
                    Err(AppError::SecretStore(format!(
                        "failed to read secrets from Azure Key Vault: {e}"
                    )))
                }
            }
        }
    }

    /// Persist the envelope by writing a new version of the secret.
    /// Key Vault's `set_secret` creates the secret on first write and
    /// adds a new version on subsequent writes.
    async fn write_envelope(
        &self,
        client: &SecretClient,
        env: &StoredSecrets,
    ) -> Result<(), AppError> {
        let json_str = env
            .to_json()
            .map_err(|e| AppError::Internal(format!("envelope serialization for Azure: {e}")))?;

        let body = SetSecretParameters {
            value: Some(json_str),
            ..Default::default()
        };
        let request = body.try_into().map_err(|e| {
            AppError::SecretStore(format!(
                "failed to encode SetSecretParameters for Azure: {e}"
            ))
        })?;

        client
            .set_secret(&self.secret_name, request, None)
            .await
            .map_err(|e| {
                AppError::SecretStore(format!("failed to store secrets in Azure Key Vault: {e}"))
            })?;
        Ok(())
    }
}

fn is_not_found(err: &azure_core::Error) -> bool {
    matches!(err.http_status(), Some(StatusCode::NotFound))
}

impl super::SecretStore for AzureKeyVaultStore {
    fn get(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ServerSecrets>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client()?;
            let env = self.read_envelope(&client).await?;
            let secrets = env.and_then(|e| e.secrets);
            if secrets.is_some() {
                debug!(secret = %self.secret_name, "secrets loaded from Azure Key Vault");
            }
            Ok(secrets)
        })
    }

    fn set(
        &self,
        secrets: &ServerSecrets,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let secrets = secrets.clone();
        Box::pin(async move {
            let client = self.client()?;
            // Read-modify-write so a concurrently-stored bootstrap seed
            // (phase 1 of offline-bootstrap) survives this write.
            let mut env = self.read_envelope(&client).await?.unwrap_or_default();
            env.secrets = Some(secrets);
            self.write_envelope(&client, &env).await?;
            debug!(secret = %self.secret_name, "secrets stored in Azure Key Vault");
            Ok(())
        })
    }

    fn get_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<[u8; 32]>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client()?;
            let env = self.read_envelope(&client).await?;
            match env.and_then(|e| e.bootstrap_seed) {
                Some(b64) => {
                    let seed = StoredSecrets::decode_seed(&b64)?;
                    debug!(secret = %self.secret_name, "bootstrap seed loaded from Azure");
                    Ok(Some(seed))
                }
                None => Ok(None),
            }
        })
    }

    fn set_bootstrap_seed(
        &self,
        seed: &[u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let seed_owned = *seed;
        Box::pin(async move {
            let client = self.client()?;
            let mut env = self.read_envelope(&client).await?.unwrap_or_default();
            env.bootstrap_seed = Some(StoredSecrets::encode_seed(&seed_owned));
            self.write_envelope(&client, &env).await?;
            debug!(secret = %self.secret_name, "bootstrap seed stored in Azure");
            Ok(())
        })
    }

    fn clear_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client()?;
            let Some(mut env) = self.read_envelope(&client).await? else {
                return Ok(());
            };
            if env.bootstrap_seed.is_none() {
                return Ok(());
            }
            env.bootstrap_seed = None;
            self.write_envelope(&client, &env).await?;
            debug!(secret = %self.secret_name, "bootstrap seed cleared from Azure");
            Ok(())
        })
    }
}

/// List all secret names in the configured Key Vault.
///
/// Filters out legacy `*-bootstrap-seed` companion entries (see
/// [`LEGACY_BOOTSTRAP_SEED_SUFFIX`]).
pub async fn list_secret_names(vault_url: &str) -> Result<Vec<String>, AppError> {
    use azure_security_keyvault_secrets::ResourceExt;
    use futures::TryStreamExt;

    let credential = DeveloperToolsCredential::new(None).map_err(|e| {
        AppError::SecretStore(format!(
            "failed to obtain Azure credential (DeveloperToolsCredential): {e}"
        ))
    })?;
    let client = SecretClient::new(vault_url, credential, None)
        .map_err(|e| AppError::SecretStore(format!("Azure Key Vault client error: {e}")))?;

    let mut names = Vec::new();
    let mut pager = client
        .list_secret_properties(None)
        .map_err(|e| AppError::SecretStore(format!("Azure list_secret_properties: {e}")))?;
    while let Some(props) = pager
        .try_next()
        .await
        .map_err(|e| AppError::SecretStore(format!("Azure list_secret_properties: {e}")))?
    {
        let id = props
            .resource_id()
            .map_err(|e| AppError::SecretStore(format!("Azure secret resource_id: {e}")))?;
        if id.name.ends_with(LEGACY_BOOTSTRAP_SEED_SUFFIX) {
            continue;
        }
        names.push(id.name);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

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

use super::ServerSecrets;

/// Suffix appended to the configured secret name for the
/// offline-bootstrap ephemeral seed. Stored as a separate Key Vault
/// secret so its lifecycle (created at phase 1, deleted at phase 2)
/// is independent of the long-lived `ServerSecrets` blob.
const BOOTSTRAP_SEED_SUFFIX: &str = "-bootstrap-seed";

/// Secret store backed by Azure Key Vault.
///
/// Stores a JSON-serialized `ServerSecrets` struct as the secret value.
/// Auth is resolved via `DeveloperToolsCredential`, which chains through
/// the standard Azure credential sources (environment vars, managed
/// identity, az CLI, VS Code).
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

    fn bootstrap_seed_secret_name(&self) -> String {
        format!("{}{BOOTSTRAP_SEED_SUFFIX}", self.secret_name)
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
                    let secrets: ServerSecrets =
                        serde_json::from_str(value.trim()).map_err(|e| {
                            AppError::SecretStore(format!(
                                "failed to deserialize secrets from Azure Key Vault: {e}"
                            ))
                        })?;
                    debug!(secret = %self.secret_name, "secrets loaded from Azure Key Vault");
                    Ok(Some(secrets))
                }
                Err(e) => {
                    if is_not_found(&e) {
                        debug!(secret = %self.secret_name, "secret not found in Azure Key Vault");
                        Ok(None)
                    } else {
                        Err(AppError::SecretStore(format!(
                            "failed to read secrets from Azure Key Vault: {e}"
                        )))
                    }
                }
            }
        })
    }

    fn set(
        &self,
        secrets: &ServerSecrets,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let json_str = serde_json::to_string(secrets)
            .map_err(|e| AppError::Internal(format!("secrets serialization: {e}")));
        Box::pin(async move {
            let json_str = json_str?;
            let client = self.client()?;

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
                    AppError::SecretStore(format!(
                        "failed to store secrets in Azure Key Vault: {e}"
                    ))
                })?;
            debug!(secret = %self.secret_name, "secrets stored in Azure Key Vault");
            Ok(())
        })
    }

    fn get_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<[u8; 32]>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client()?;
            let secret_id = self.bootstrap_seed_secret_name();
            let result = client
                .get_secret(&secret_id, None::<SecretClientGetSecretOptions<'_>>)
                .await;

            match result {
                Ok(response) => {
                    use base64::Engine;
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
                    let secret = response.into_model().map_err(|e| {
                        AppError::SecretStore(format!(
                            "failed to deserialize Azure bootstrap-seed response: {e}"
                        ))
                    })?;
                    let b64 = secret.value.ok_or_else(|| {
                        AppError::SecretStore(
                            "Azure bootstrap-seed secret exists but has no string value".into(),
                        )
                    })?;
                    let bytes = B64.decode(b64.trim().as_bytes()).map_err(|e| {
                        AppError::SecretStore(format!(
                            "failed to base64-decode bootstrap seed from Azure: {e}"
                        ))
                    })?;
                    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        AppError::SecretStore(format!(
                            "Azure bootstrap seed has {} bytes, expected 32",
                            bytes.len()
                        ))
                    })?;
                    debug!(secret = %secret_id, "bootstrap seed loaded from Azure");
                    Ok(Some(seed))
                }
                Err(e) => {
                    if is_not_found(&e) {
                        Ok(None)
                    } else {
                        Err(AppError::SecretStore(format!(
                            "failed to read bootstrap seed from Azure Key Vault: {e}"
                        )))
                    }
                }
            }
        })
    }

    fn set_bootstrap_seed(
        &self,
        seed: &[u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let seed_owned = *seed;
        Box::pin(async move {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
            let b64 = B64.encode(seed_owned);
            let client = self.client()?;
            let secret_id = self.bootstrap_seed_secret_name();

            let body = SetSecretParameters {
                value: Some(b64),
                ..Default::default()
            };
            let request = body.try_into().map_err(|e| {
                AppError::SecretStore(format!(
                    "failed to encode bootstrap-seed SetSecretParameters for Azure: {e}"
                ))
            })?;

            client
                .set_secret(&secret_id, request, None)
                .await
                .map_err(|e| {
                    AppError::SecretStore(format!(
                        "failed to store bootstrap seed in Azure Key Vault: {e}"
                    ))
                })?;
            debug!(secret = %secret_id, "bootstrap seed stored in Azure");
            Ok(())
        })
    }

    fn clear_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client()?;
            let secret_id = self.bootstrap_seed_secret_name();
            // Key Vault delete_secret is a soft-delete (90-day retention by
            // default at the vault level). For a one-shot ephemeral seed
            // that's acceptable — the next phase-1 will overwrite via
            // set_secret on the same name and supersede the soft-deleted
            // version.
            let result = client.delete_secret(&secret_id, None).await;
            match result {
                Ok(_) => {
                    debug!(secret = %secret_id, "bootstrap seed cleared from Azure");
                    Ok(())
                }
                Err(e) => {
                    if is_not_found(&e) {
                        Ok(())
                    } else {
                        Err(AppError::SecretStore(format!(
                            "failed to clear bootstrap seed from Azure Key Vault: {e}"
                        )))
                    }
                }
            }
        })
    }
}

/// List all secret names in the configured Key Vault.
///
/// Filters out `*-bootstrap-seed` companion entries — those are
/// internal pairings of a `ServerSecrets` blob, not standalone
/// candidates the operator should pick from the wizard.
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
        if id.name.ends_with(BOOTSTRAP_SEED_SUFFIX) {
            continue;
        }
        names.push(id.name);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

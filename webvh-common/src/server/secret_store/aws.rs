use std::future::Future;
use std::pin::Pin;

use crate::server::error::AppError;
use tracing::debug;

use super::ServerSecrets;

/// List secret names visible in AWS Secrets Manager for the configured region.
///
/// Filters out `*-bootstrap-seed` companion entries — those are paired
/// with a `ServerSecrets` blob, not standalone candidates the operator
/// should pick from the wizard.
pub async fn list_secret_names(region: Option<&str>) -> Result<Vec<String>, AppError> {
    let mut config_loader = aws_config::from_env();
    if let Some(region) = region {
        config_loader = config_loader.region(aws_config::Region::new(region.to_string()));
    }
    let sdk_config = config_loader.load().await;
    let client = aws_sdk_secretsmanager::Client::new(&sdk_config);

    let mut names = Vec::new();
    let mut next_token: Option<String> = None;
    loop {
        let mut req = client.list_secrets();
        if let Some(t) = next_token.as_ref() {
            req = req.next_token(t);
        }
        let out = req
            .send()
            .await
            .map_err(|e| format_aws_error("AWS list_secrets", e.into_service_error()))?;
        for entry in out.secret_list() {
            if let Some(name) = entry.name()
                && !name.ends_with(BOOTSTRAP_SEED_SUFFIX)
            {
                names.push(name.to_string());
            }
        }
        match out.next_token() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// Format an AWS SDK service error with its full source chain for troubleshooting.
fn format_aws_error<E: std::error::Error>(context: &str, err: E) -> AppError {
    let mut msg = format!("{context}: {err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        msg.push_str(&format!("\n  caused by: {cause}"));
        source = cause.source();
    }
    AppError::SecretStore(msg)
}

/// Suffix appended to the configured secret name for the
/// offline-bootstrap ephemeral seed. The seed is stored in a separate
/// AWS Secrets Manager secret so its lifecycle (created at phase 1,
/// deleted at phase 2) is independent of the long-lived
/// `ServerSecrets` blob.
const BOOTSTRAP_SEED_SUFFIX: &str = "-bootstrap-seed";

/// Secret store backed by AWS Secrets Manager.
///
/// Stores a JSON-serialized `ServerSecrets` struct as the secret string.
/// AWS credentials are resolved from the environment (IAM role, env vars, etc.)
/// via the default credential provider chain.
pub struct AwsSecretStore {
    secret_name: String,
    region: Option<String>,
}

impl AwsSecretStore {
    pub fn new(secret_name: String, region: Option<String>) -> Self {
        Self {
            secret_name,
            region,
        }
    }

    fn bootstrap_seed_secret_name(&self) -> String {
        format!("{}{BOOTSTRAP_SEED_SUFFIX}", self.secret_name)
    }

    async fn client(&self) -> Result<aws_sdk_secretsmanager::Client, AppError> {
        let mut config_loader = aws_config::from_env();
        if let Some(ref region) = self.region {
            config_loader = config_loader.region(aws_config::Region::new(region.clone()));
        }
        let sdk_config = config_loader.load().await;
        Ok(aws_sdk_secretsmanager::Client::new(&sdk_config))
    }
}

impl super::SecretStore for AwsSecretStore {
    fn get(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ServerSecrets>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let result = client
                .get_secret_value()
                .secret_id(&self.secret_name)
                .send()
                .await;

            match result {
                Ok(output) => {
                    let json_str = output.secret_string().ok_or_else(|| {
                        AppError::SecretStore("AWS secret exists but has no string value".into())
                    })?;
                    let secrets: ServerSecrets = serde_json::from_str(json_str).map_err(|e| {
                        AppError::SecretStore(format!(
                            "failed to deserialize secrets from AWS: {e}"
                        ))
                    })?;
                    debug!(secret_name = %self.secret_name, "secrets loaded from AWS Secrets Manager");
                    Ok(Some(secrets))
                }
                Err(e) => {
                    let service_error = e.into_service_error();
                    if service_error.is_resource_not_found_exception() {
                        debug!(secret_name = %self.secret_name, "secret not found in AWS Secrets Manager");
                        Ok(None)
                    } else {
                        Err(format_aws_error(
                            "failed to read secrets from AWS Secrets Manager",
                            service_error,
                        ))
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
            let client = self.client().await?;

            // Try to update the existing secret first
            let result = client
                .put_secret_value()
                .secret_id(&self.secret_name)
                .secret_string(&json_str)
                .send()
                .await;

            match result {
                Ok(_) => {
                    debug!(secret_name = %self.secret_name, "secrets stored in AWS Secrets Manager");
                    Ok(())
                }
                Err(e) => {
                    let service_error = e.into_service_error();
                    if service_error.is_resource_not_found_exception() {
                        // Secret doesn't exist yet, create it
                        client
                            .create_secret()
                            .name(&self.secret_name)
                            .secret_string(&json_str)
                            .send()
                            .await
                            .map_err(|e| {
                                format_aws_error(
                                    "failed to create secret in AWS Secrets Manager",
                                    e.into_service_error(),
                                )
                            })?;
                        debug!(secret_name = %self.secret_name, "secrets created in AWS Secrets Manager");
                        Ok(())
                    } else {
                        Err(format_aws_error(
                            "failed to store secrets in AWS Secrets Manager",
                            service_error,
                        ))
                    }
                }
            }
        })
    }

    fn get_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<[u8; 32]>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let secret_id = self.bootstrap_seed_secret_name();
            match client.get_secret_value().secret_id(&secret_id).send().await {
                Ok(output) => {
                    use base64::Engine;
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
                    let b64 = output.secret_string().ok_or_else(|| {
                        AppError::SecretStore(
                            "AWS bootstrap-seed secret exists but has no string value".into(),
                        )
                    })?;
                    let bytes = B64.decode(b64.as_bytes()).map_err(|e| {
                        AppError::SecretStore(format!(
                            "failed to base64-decode bootstrap seed from AWS: {e}"
                        ))
                    })?;
                    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        AppError::SecretStore(format!(
                            "AWS bootstrap seed has {} bytes, expected 32",
                            bytes.len()
                        ))
                    })?;
                    debug!(secret_name = %secret_id, "bootstrap seed loaded from AWS");
                    Ok(Some(seed))
                }
                Err(e) => {
                    let service_error = e.into_service_error();
                    if service_error.is_resource_not_found_exception() {
                        Ok(None)
                    } else {
                        Err(format_aws_error(
                            "failed to read bootstrap seed from AWS Secrets Manager",
                            service_error,
                        ))
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
            let client = self.client().await?;
            let secret_id = self.bootstrap_seed_secret_name();

            let result = client
                .put_secret_value()
                .secret_id(&secret_id)
                .secret_string(&b64)
                .send()
                .await;

            match result {
                Ok(_) => {
                    debug!(secret_name = %secret_id, "bootstrap seed stored in AWS");
                    Ok(())
                }
                Err(e) => {
                    let service_error = e.into_service_error();
                    if service_error.is_resource_not_found_exception() {
                        client
                            .create_secret()
                            .name(&secret_id)
                            .secret_string(&b64)
                            .send()
                            .await
                            .map_err(|e| {
                                format_aws_error(
                                    "failed to create bootstrap-seed secret in AWS",
                                    e.into_service_error(),
                                )
                            })?;
                        debug!(secret_name = %secret_id, "bootstrap seed created in AWS");
                        Ok(())
                    } else {
                        Err(format_aws_error(
                            "failed to store bootstrap seed in AWS Secrets Manager",
                            service_error,
                        ))
                    }
                }
            }
        })
    }

    fn clear_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let secret_id = self.bootstrap_seed_secret_name();
            // `force_delete_without_recovery` skips the 7-day recovery
            // window — appropriate for a setup-time ephemeral secret.
            let result = client
                .delete_secret()
                .secret_id(&secret_id)
                .force_delete_without_recovery(true)
                .send()
                .await;
            match result {
                Ok(_) => {
                    debug!(secret_name = %secret_id, "bootstrap seed cleared from AWS");
                    Ok(())
                }
                Err(e) => {
                    let service_error = e.into_service_error();
                    if service_error.is_resource_not_found_exception() {
                        Ok(())
                    } else {
                        Err(format_aws_error(
                            "failed to clear bootstrap seed from AWS Secrets Manager",
                            service_error,
                        ))
                    }
                }
            }
        })
    }
}

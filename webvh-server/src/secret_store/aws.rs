use std::future::Future;
use std::pin::Pin;

use crate::error::AppError;
use tracing::debug;

use super::ServerSecrets;

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
                        AppError::SecretStore(
                            "AWS secret exists but has no string value".into(),
                        )
                    })?;
                    let secrets: ServerSecrets =
                        serde_json::from_str(json_str).map_err(|e| {
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
        let json_str = serde_json::to_string(secrets).expect("ServerSecrets serialization");
        Box::pin(async move {
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
}

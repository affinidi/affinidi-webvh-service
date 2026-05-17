use std::future::Future;
use std::pin::Pin;

use crate::server::error::AppError;
use tracing::debug;

use super::{ServerSecrets, StoredSecrets};

/// Legacy suffix used by 0.6.0–0.6.1 deployments to store the
/// offline-bootstrap ephemeral seed in a sibling secret. The current
/// envelope-based design keeps the seed inside the same secret as
/// `ServerSecrets`, so siblings are no longer created — but stragglers
/// from older runs may still exist and are filtered out of
/// [`list_secret_names`] for a tidier wizard UX.
const LEGACY_BOOTSTRAP_SEED_SUFFIX: &str = "-bootstrap-seed";

/// List secret names visible in AWS Secrets Manager for the configured region.
///
/// Filters out legacy `*-bootstrap-seed` companion entries (see
/// [`LEGACY_BOOTSTRAP_SEED_SUFFIX`]) so the wizard doesn't show stale
/// ephemeral siblings as pickable candidates.
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
                && !name.ends_with(LEGACY_BOOTSTRAP_SEED_SUFFIX)
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

/// Secret store backed by AWS Secrets Manager.
///
/// A single secret holds a JSON [`StoredSecrets`] envelope containing
/// both the long-lived [`ServerSecrets`] and the optional
/// offline-bootstrap ephemeral seed, so a single IAM grant covers both.
/// AWS credentials are resolved from the environment (IAM role, env
/// vars, etc.) via the default credential provider chain.
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

    /// Read the current envelope. Returns `None` when the secret does
    /// not yet exist. Legacy bare-`ServerSecrets` blobs from pre-envelope
    /// deployments parse transparently and migrate on the next write.
    async fn read_envelope(
        &self,
        client: &aws_sdk_secretsmanager::Client,
    ) -> Result<Option<StoredSecrets>, AppError> {
        match client
            .get_secret_value()
            .secret_id(&self.secret_name)
            .send()
            .await
        {
            Ok(output) => {
                let json_str = output.secret_string().ok_or_else(|| {
                    AppError::SecretStore("AWS secret exists but has no string value".into())
                })?;
                let env = StoredSecrets::parse(json_str).map_err(|e| {
                    AppError::SecretStore(format!("failed to deserialize secrets from AWS: {e}"))
                })?;
                Ok(Some(env))
            }
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_resource_not_found_exception() {
                    Ok(None)
                } else {
                    Err(format_aws_error(
                        "failed to read secrets from AWS Secrets Manager",
                        service_error,
                    ))
                }
            }
        }
    }

    /// Persist the envelope. Creates the secret on first write,
    /// otherwise overwrites the existing value.
    async fn write_envelope(
        &self,
        client: &aws_sdk_secretsmanager::Client,
        env: &StoredSecrets,
    ) -> Result<(), AppError> {
        let json_str = env
            .to_json()
            .map_err(|e| AppError::Internal(format!("envelope serialization for AWS: {e}")))?;

        let result = client
            .put_secret_value()
            .secret_id(&self.secret_name)
            .secret_string(&json_str)
            .send()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_resource_not_found_exception() {
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
                    Ok(())
                } else {
                    Err(format_aws_error(
                        "failed to store secrets in AWS Secrets Manager",
                        service_error,
                    ))
                }
            }
        }
    }
}

impl super::SecretStore for AwsSecretStore {
    fn get(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ServerSecrets>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let env = self.read_envelope(&client).await?;
            let secrets = env.and_then(|e| e.secrets);
            if secrets.is_some() {
                debug!(secret_name = %self.secret_name, "secrets loaded from AWS Secrets Manager");
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
            let client = self.client().await?;
            // Read-modify-write so a concurrently-stored bootstrap seed
            // (phase 1 of offline-bootstrap) survives this write.
            let mut env = self.read_envelope(&client).await?.unwrap_or_default();
            env.secrets = Some(secrets);
            self.write_envelope(&client, &env).await?;
            debug!(secret_name = %self.secret_name, "secrets stored in AWS Secrets Manager");
            Ok(())
        })
    }

    fn get_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<[u8; 32]>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let env = self.read_envelope(&client).await?;
            match env.and_then(|e| e.bootstrap_seed) {
                Some(b64) => {
                    let seed = StoredSecrets::decode_seed(&b64)?;
                    debug!(secret_name = %self.secret_name, "bootstrap seed loaded from AWS");
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
            let client = self.client().await?;
            let mut env = self.read_envelope(&client).await?.unwrap_or_default();
            env.bootstrap_seed = Some(StoredSecrets::encode_seed(&seed_owned));
            self.write_envelope(&client, &env).await?;
            debug!(secret_name = %self.secret_name, "bootstrap seed stored in AWS");
            Ok(())
        })
    }

    fn clear_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            // No envelope yet → nothing to clear.
            let Some(mut env) = self.read_envelope(&client).await? else {
                return Ok(());
            };
            if env.bootstrap_seed.is_none() {
                return Ok(());
            }
            env.bootstrap_seed = None;
            self.write_envelope(&client, &env).await?;
            debug!(secret_name = %self.secret_name, "bootstrap seed cleared from AWS");
            Ok(())
        })
    }
}

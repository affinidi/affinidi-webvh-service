#[cfg(feature = "aws-secrets")]
mod aws;
#[cfg(feature = "gcp-secrets")]
mod gcp;
#[cfg(feature = "keyring")]
mod keyring;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSecretStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSecretStore;
#[cfg(feature = "keyring")]
pub use keyring::KeyringSecretStore;

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::error::AppError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Server secret key material stored in the secret store.
///
/// All keys are stored as multibase-encoded private keys (Base58BTC with
/// multicodec type prefix), matching the format used by `Secret::from_multibase()`
/// and `Secret::get_private_keymultibase()` in the affinidi-secrets-resolver.
///
/// This encoding is self-describing: the multicodec prefix identifies the key
/// type (Ed25519, X25519, etc.), so a `Secret` can be reconstructed directly
/// via `Secret::from_multibase(key, kid)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSecrets {
    /// Ed25519 private key for server DID signing (multibase-encoded).
    pub signing_key: String,
    /// X25519 private key for DIDComm key agreement (multibase-encoded).
    pub key_agreement_key: String,
    /// Ed25519 private key for JWT token signing (multibase-encoded).
    pub jwt_signing_key: String,
}

pub trait SecretStore: Send + Sync {
    fn get(&self) -> BoxFuture<'_, Result<Option<ServerSecrets>, AppError>>;
    fn set(&self, secrets: &ServerSecrets) -> BoxFuture<'_, Result<(), AppError>>;
}

/// Create a secret store backend based on compiled features and configuration.
///
/// Priority:
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `secrets.aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `secrets.gcp_secret_name` set)
/// 3. OS keyring (if `keyring` compiled — the default)
#[allow(unused_variables)]
pub fn create_secret_store(config: &AppConfig) -> Result<Box<dyn SecretStore>, AppError> {
    #[cfg(feature = "aws-secrets")]
    if config.secrets.aws_secret_name.is_some() {
        let store = AwsSecretStore::new(
            config.secrets.aws_secret_name.clone().unwrap(),
            config.secrets.aws_region.clone(),
        );
        return Ok(Box::new(store));
    }

    #[cfg(feature = "gcp-secrets")]
    if config.secrets.gcp_secret_name.is_some() {
        let project = config.secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSecretStore::new(project, config.secrets.gcp_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "keyring")]
    {
        let store =
            KeyringSecretStore::new(&config.secrets.keyring_service, "server_secrets");
        return Ok(Box::new(store));
    }

    #[allow(unreachable_code)]
    Err(AppError::Config(
        "no secret store backend available — compile with at least one of: keyring, aws-secrets, gcp-secrets".into(),
    ))
}

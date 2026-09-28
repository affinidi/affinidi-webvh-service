//! The watcher's secrets — its DID's keys, and the credential for its VTA
//! context — through the shared secret-store backends.

pub use did_hosting_common::server::secret_store::*;

use crate::config::AppConfig;
use crate::error::AppError;

/// Create a secret store backend based on the application configuration.
pub fn create_secret_store(config: &AppConfig) -> Result<Box<dyn SecretStore>, AppError> {
    did_hosting_common::server::secret_store::create_secret_store(
        &config.secrets,
        &config.config_path,
    )
}

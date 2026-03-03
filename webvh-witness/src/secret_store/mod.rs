// Re-export from webvh-common shared server infrastructure
pub use affinidi_webvh_common::server::secret_store::*;

use crate::config::AppConfig;
use crate::error::AppError;

/// Create a secret store backend based on the application configuration.
///
/// This is a thin wrapper that delegates to `webvh-common`'s implementation
/// with the appropriate config fields.
pub fn create_secret_store(config: &AppConfig) -> Result<Box<dyn SecretStore>, AppError> {
    affinidi_webvh_common::server::secret_store::create_secret_store(
        &config.secrets,
        &config.config_path,
    )
}

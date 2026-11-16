//! Startup helpers: loading the JWT signing keys and waiting for a shutdown
//! signal.

use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use tracing::{debug, info, warn};

use super::auth::jwt::JwtKeys;
use super::error::AppError;
use super::secret_store::ServerSecrets;

/// Decode a multibase-encoded Ed25519 private key into raw 32-byte form.
pub fn decode_multibase_ed25519_key(multibase_key: &str) -> Result<[u8; 32], AppError> {
    let secret = Secret::from_multibase(multibase_key, None)
        .map_err(|e| AppError::Config(format!("invalid multibase key: {e}")))?;

    let bytes = secret.get_private_bytes();
    bytes
        .try_into()
        .map_err(|_| AppError::Config("key must be exactly 32 bytes".into()))
}

/// Load JWT signing keys from the server secrets.
///
/// Returns `None` (with a warning) if the key cannot be decoded or constructed.
pub fn init_jwt_keys(secrets: &ServerSecrets) -> Option<Arc<JwtKeys>> {
    match decode_multibase_ed25519_key(&secrets.jwt_signing_key) {
        Ok(key_bytes) => match JwtKeys::from_ed25519_bytes(&zeroize::Zeroizing::new(key_bytes)) {
            Ok(keys) => {
                debug!("JWT signing key loaded");
                Some(Arc::new(keys))
            }
            Err(e) => {
                warn!("failed to construct JWT keys: {e} — auth endpoints will not work");
                None
            }
        },
        Err(e) => {
            warn!("failed to load JWT signing key: {e} — auth endpoints will not work");
            None
        }
    }
}

/// Wait for a shutdown signal (Ctrl-C / SIGTERM).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received SIGINT"),
        () = terminate => info!("received SIGTERM"),
    }
}

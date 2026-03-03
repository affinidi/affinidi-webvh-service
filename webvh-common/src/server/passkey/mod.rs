pub mod routes;
pub mod store;

use std::sync::Arc;

use url::Url;
use webauthn_rs::prelude::*;

use crate::server::auth::extractor::AuthState;
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

/// Trait that application states must implement to support passkey extractors.
///
/// Extends `AuthState` (which provides JWT keys + sessions keyspace) with
/// WebAuthn and ACL access needed by passkey enrollment and login routes.
pub trait PasskeyState: AuthState {
    fn webauthn(&self) -> Option<&Arc<Webauthn>>;
    fn acl_ks(&self) -> &KeyspaceHandle;
    fn access_token_expiry(&self) -> u64;
    fn refresh_token_expiry(&self) -> u64;
}

/// Build a `Webauthn` instance from the server's `public_url` configuration.
///
/// The relying party ID is the hostname from the URL and the origin is the
/// full scheme+host (e.g. `https://example.com`).
pub fn build_webauthn(public_url: &str) -> Result<Webauthn, AppError> {
    let url = Url::parse(public_url)
        .map_err(|e| AppError::Config(format!("invalid public_url '{public_url}': {e}")))?;

    let rp_id = url
        .domain()
        .ok_or_else(|| AppError::Config("public_url has no domain".into()))?
        .to_string();

    let builder = WebauthnBuilder::new(&rp_id, &url)
        .map_err(|e| AppError::Config(format!("failed to build WebauthnBuilder: {e}")))?;

    let webauthn = builder
        .rp_name("WebVH Server")
        .build()
        .map_err(|e| AppError::Config(format!("failed to build Webauthn: {e}")))?;

    Ok(webauthn)
}

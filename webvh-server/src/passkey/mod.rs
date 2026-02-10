pub mod store;

use url::Url;
use webauthn_rs::prelude::*;

use crate::error::AppError;

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

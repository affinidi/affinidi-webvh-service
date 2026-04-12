pub mod acl;
pub mod auth;
pub mod config;
pub mod didcomm_profile;
pub mod didcomm_unpack;
pub mod error;
pub mod health;
pub mod init;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod mnemonic;
#[cfg(feature = "passkey")]
pub mod passkey;
pub mod secret_store;
pub mod stats_collector;
pub mod store;
pub mod vta_setup;

/// Axum middleware that sets security response headers on every response.
pub async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    resp
}

pub mod acl;
pub mod assignment;
pub mod auth;
pub mod cli_acl;
pub mod config;
pub mod didcomm_profile;
pub mod didcomm_unpack;
pub mod domain;
pub mod error;
pub mod health;
pub mod init;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod migrations;
pub mod mnemonic;
pub mod operator_messages;
#[cfg(feature = "passkey")]
pub mod passkey;
pub mod problem_report;
pub mod secret_store;
#[cfg(feature = "setup-wizard")]
pub mod setup_prompts;
pub mod setup_recipe;
pub mod stats_collector;
pub mod store;
pub mod trust_task;
pub mod vta_setup;

/// Axum middleware that sets security response headers on every response.
///
/// The defaults are conservative for an admin/management UI hosted on the
/// control plane. Reverse-proxy operators can override these by stripping and
/// re-injecting headers if the deployment needs to differ (e.g. CSP for an
/// embedded iframe widget). See `docs/bootstrap_startup.md` for the policy.
///
/// Headers set:
/// - `X-Content-Type-Options: nosniff` — block MIME sniffing.
/// - `X-Frame-Options: DENY` — block framing/clickjacking. Mirrored by CSP
///   `frame-ancestors 'none'` for browsers that prefer the modern directive.
/// - `Content-Security-Policy: default-src 'self'; ...` — restrict resource
///   loads to same-origin. Allows inline styles (the React/Expo bundle pulls
///   styles from `<style>` tags); inline scripts are *not* allowed.
/// - `Referrer-Policy: no-referrer` — prevent the enrollment URL (which can
///   contain a single-use invite token in its query string) from leaking via
///   the `Referer` header on outbound link clicks.
/// - `Strict-Transport-Security: max-age=31536000` — pin TLS for one year on
///   any caller that has reached us over HTTPS. Browsers ignore this header
///   when delivered over plaintext HTTP, so it is harmless on plain-HTTP
///   deployments.
/// - `Cache-Control: no-store` — applied only when the handler hasn't set its
///   own `Cache-Control`. Public DID-resolution endpoints set
///   `Cache-Control: public, max-age=…` explicitly so CDNs and browsers can
///   cache them; admin/API responses fall through to `no-store`.
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
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             connect-src 'self'; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'",
        ),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=31536000"),
    );
    // Default to `no-store` for API / UI responses. Public DID-resolution
    // handlers set `Cache-Control: public, max-age=…` explicitly so this
    // middleware leaves their value untouched — DID logs are content-
    // addressed and cacheable.
    if !headers.contains_key(axum::http::header::CACHE_CONTROL) {
        headers.insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
    }
    resp
}

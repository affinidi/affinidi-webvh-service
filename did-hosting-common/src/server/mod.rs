pub mod acl;
pub mod assignment;
pub mod assignment_seed;
pub mod auth;
pub mod cli_acl;
pub mod cli_identity;
pub mod config;
pub mod didcomm_profile;
pub mod didcomm_unpack;
pub mod domain;
pub mod domain_purge;
pub mod error;
pub mod health;
pub mod identity;
pub mod identity_drain;
pub mod init;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod migrations;
pub mod mnemonic;
pub mod operator_messages;
#[cfg(feature = "passkey")]
pub mod passkey;
pub mod path_locks;
pub mod pending_purge;
pub mod problem_report;
pub mod secret_store;
#[cfg(feature = "setup-wizard")]
pub mod setup_prompts;
pub mod setup_recipe;
pub mod stats_collector;
pub mod store;
pub mod trust_task;
/// New trust-tasks framework integration (SPEC.md 0.1). Gated behind
/// `server-core` because the dispatcher only runs on the server side;
/// the client crate (no trust-tasks admin surface yet) doesn't compile
/// it in.
#[cfg(feature = "server-core")]
pub mod trust_tasks;
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

/// CORS layer for public DID resolution.
///
/// DID documents (`did.jsonl`, `/.well-known/did.json`) are public,
/// content-addressed, unauthenticated data. Browser-based resolvers and
/// wallets fetch them cross-origin, so we advertise `Access-Control-Allow-Origin: *`
/// to let any page read the response. Resolution is read-only, so only the
/// safe methods are allowed.
///
/// This is deliberately permissive but safe: credentials are never reflected
/// (wildcard origin forbids `Access-Control-Allow-Credentials: true`), and the
/// management API authenticates with bearer JWTs rather than cookies — so a
/// wildcard origin grants a cross-origin page nothing it could not already
/// fetch server-to-server, while still blocking it from reading authenticated
/// responses it has no token for.
pub fn public_resolution_cors() -> tower_http::cors::CorsLayer {
    use axum::http::Method;
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::HEAD, Method::OPTIONS])
        .allow_headers(tower_http::cors::Any)
}

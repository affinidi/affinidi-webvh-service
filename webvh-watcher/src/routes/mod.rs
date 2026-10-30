mod did_public;
pub mod health;
pub mod trust_tasks;

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use did_hosting_common::server::rate_limit::{ResolveRateLimiter, limit_resolution};

use crate::server::AppState;

/// The largest Trust Task document the watcher reads. A `sync/batch` carries
/// up to 512 KiB of logs (the control plane's cap), a `sync/update` a whole
/// log; this leaves room for the envelope.
pub const TRUST_TASKS_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Public DID serving only: the mirrored logs and witness proofs.
pub fn router_public_only() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/did.jsonl",
            get(did_public::serve_root_did_log),
        )
        .route(
            "/.well-known/did-witness.json",
            get(did_public::serve_root_witness),
        )
        .fallback(did_public::serve_public)
}

/// The watcher's HTTP surface: public resolution, and the HTTPS binding of
/// its Trust Task listener, `POST /api/trust-tasks`. There is no sync REST
/// API — a source pushes signed `webvh/sync/*` documents, the same on every
/// transport.
pub fn router() -> Router<AppState> {
    router_with_resolve_limit(Arc::new(ResolveRateLimiter::disabled()))
}

/// [`router_public_only`] with `resolve_limit` on every resolution route.
pub fn router_public_only_with_resolve_limit(
    resolve_limit: Arc<ResolveRateLimiter>,
) -> Router<AppState> {
    router_public_only().layer(axum::middleware::from_fn_with_state(
        resolve_limit,
        limit_resolution,
    ))
}

/// [`router`] with `resolve_limit` on resolution; the Trust Task listener
/// keeps its own limiter.
pub fn router_with_resolve_limit(resolve_limit: Arc<ResolveRateLimiter>) -> Router<AppState> {
    with_trust_task_listener(router_public_only_with_resolve_limit(resolve_limit))
}

/// `public` plus `POST /api/trust-tasks`.
fn with_trust_task_listener(public: Router<AppState>) -> Router<AppState> {
    public
        .route(
            "/api/trust-tasks",
            post(trust_tasks::receive).layer(DefaultBodyLimit::max(TRUST_TASKS_BODY_LIMIT_BYTES)),
        )
        // `receive`'s rate limiter reads `ConnectInfo<SocketAddr>`, supplied
        // per real connection in production by
        // `into_make_service_with_connect_info`. There is deliberately no
        // `MockConnectInfo` layer here: production must never silently fall
        // back to a shared address, so a router driven directly (`.oneshot()`
        // in tests) with no real connection behind it has to supply its own
        // mock, or `receive`'s extractor fails the request closed with a 500.
        // This layer only logs that case; it never masks it.
        .layer(axum::middleware::from_fn(
            trust_tasks::log_missing_connect_info,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_hosting_common::server::config::{ServerConfig, StoreConfig};
    use did_hosting_common::server::store::Store;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The status line's code for `method path` against `addr`.
    async fn status(addr: std::net::SocketAddr, method: &str, path: &str) -> u16 {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "{method} {path} HTTP/1.1\r\nHost: watcher.example\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status line in {response:?}"))
    }

    /// The watcher's served router counts its `.well-known` routes and its
    /// DID-serving fallback against one per-address budget, and not its
    /// Trust Task listener.
    #[tokio::test]
    async fn resolution_shares_one_budget_and_trust_tasks_are_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.unwrap();
        let mut server = ServerConfig::default();
        server.resolve_rate_limit.max_per_window = Some(2);
        server.resolve_rate_limit.window_secs = 60;
        let config = crate::config::AppConfig {
            store: store_config,
            server: server.clone(),
            ..crate::config::AppConfig::default()
        };
        let state = AppState::new(store, config, None).unwrap();
        let app =
            router_with_resolve_limit(Arc::new(ResolveRateLimiter::new(&server))).with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        assert_ne!(status(addr, "GET", "/.well-known/did.jsonl").await, 429);
        assert_ne!(status(addr, "GET", "/alice/did.jsonl").await, 429);
        assert_eq!(status(addr, "GET", "/alice/did.jsonl").await, 429);
        assert_eq!(status(addr, "GET", "/.well-known/did.jsonl").await, 429);
        assert_ne!(
            status(addr, "POST", "/api/trust-tasks").await,
            429,
            "the Trust Task listener has its own limiter"
        );
    }
}

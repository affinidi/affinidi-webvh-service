pub mod health;
pub mod trust_tasks;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::post;

use crate::server::AppState;

/// The largest Trust Task document the witness reads. A `witness/sign`
/// carries a whole `did.jsonl`; this leaves room for the envelope.
pub const TRUST_TASKS_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// The witness's HTTP surface: the HTTPS binding of its Trust Task listener,
/// `POST /api/trust-tasks`. There is no REST management API — every operation
/// is a Trust Task, the same on every transport. (`/api/health` is added by
/// the caller, outside the security-header layer.)
pub fn router() -> Router<AppState> {
    Router::new()
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
    use crate::config::{
        AppConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
    };
    use crate::store::Store;

    async fn limits_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        let store = Store::open(&store_config).await.unwrap();
        let config = AppConfig {
            features: FeaturesConfig::default(),
            server_did: None,
            mediator_did: None,
            server: ServerConfig::default(),
            log: LogConfig::default(),
            store: store_config,
            fjall: Default::default(),
            secrets: SecretsConfig::default(),
            vta: VtaConfig::default(),
            identity: Default::default(),
            replay: Default::default(),
            config_path: Default::default(),
        };
        let state = AppState::new(
            store,
            config,
            None,
            std::sync::Arc::new(crate::signing::LocalSigner),
        )
        .unwrap();
        (state, dir)
    }

    /// What a request on a fresh connection to `addr` is answered with, read
    /// within five seconds: the status code.
    async fn answer(addr: std::net::SocketAddr, request: &[u8]) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("answered without the rest of the body")
            .unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);
        head.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status line in {head:?}"))
    }

    /// Serve `state`'s Trust Task listener as production does, on the bounded
    /// listener.
    async fn serve_trust_tasks(state: AppState) -> std::net::SocketAddr {
        let app = router().with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                did_hosting_common::server::listener::bounded(listener),
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        addr
    }

    /// A body that declares 1000 bytes and sends none.
    const BODY_NEVER_SENT: &[u8] = b"POST /api/trust-tasks HTTP/1.1\r\nHost: x\r\n\
        Content-Type: application/json\r\nContent-Length: 1000\r\n\r\n";

    /// An address over its limit is refused before its body is read: the
    /// refusal comes back although the body never arrives.
    #[tokio::test]
    async fn an_address_over_its_limit_is_refused_before_its_body_is_read() {
        let (mut state, _dir) = limits_state().await;
        state.trust_tasks_rate_limiter = std::sync::Arc::new(
            did_hosting_common::server::rate_limit::IpRateLimiter::new("test", 1, 60),
        );
        let addr = serve_trust_tasks(state).await;
        // Spend the address's one request.
        assert_eq!(
            answer(
                addr,
                b"POST /api/trust-tasks HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"
            )
            .await,
            400
        );
        assert_eq!(answer(addr, BODY_NEVER_SENT).await, 429);
    }

    /// An admitted request whose body stops arriving is answered `408` at
    /// the body timeout.
    #[tokio::test]
    async fn a_body_that_stops_arriving_is_answered_at_the_timeout() {
        let (mut state, _dir) = limits_state().await;
        state.body_read_timeout = std::time::Duration::from_millis(200);
        let addr = serve_trust_tasks(state).await;
        assert_eq!(answer(addr, BODY_NEVER_SENT).await, 408);
    }

    /// A body declared over the limit is refused `413` without being read.
    #[tokio::test]
    async fn a_body_over_the_limit_is_refused_unread() {
        let (state, _dir) = limits_state().await;
        let addr = serve_trust_tasks(state).await;
        let request = format!(
            "POST /api/trust-tasks HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            TRUST_TASKS_BODY_LIMIT_BYTES + 1
        );
        assert_eq!(answer(addr, request.as_bytes()).await, 413);
    }
}

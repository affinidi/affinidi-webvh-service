//! Shared outbound HTTP client construction.
//!
//! Every inter-service client (`WitnessClient`,
//! `ControlClient`, `WebVHClient`) talks to a peer over the network, so each
//! must fail fast rather than hang a task forever on a peer that accepts the
//! connection and then never responds, and must not silently follow a 3xx to an
//! unintended host (which would also carry any bearer token along). Building
//! them all through one helper keeps that policy in a single place.

use std::time::Duration;

/// Total per-request timeout (connect + send + receive). A peer that stalls
/// past this fails the request instead of pinning the caller's task.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect timeout — a peer that accepts a socket but never completes the
/// handshake is abandoned quickly.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A `reqwest::Client` with request + connect timeouts and redirects refused.
///
/// Redirects are refused (`Policy::none()`) so a compromised or misconfigured
/// endpoint cannot 3xx-bounce the request — and any `Authorization` header on
/// it — to a host the caller did not choose. The runtime server/control clients
/// already build this way; the shared clients now match.
///
/// If the client cannot be built (the TLS backend or the platform certificate
/// verifier failed to initialise), the error is returned. There is no
/// fallback client: one without these settings would drop both guarantees.
pub fn outbound_client() -> reqwest::Result<reqwest::Client> {
    build_outbound(reqwest::Client::builder())
}

/// Apply the outbound policy to `builder` and build it.
fn build_outbound(builder: reqwest::ClientBuilder) -> reqwest::Result<reqwest::Client> {
    build_outbound_with(builder, REQUEST_TIMEOUT, CONNECT_TIMEOUT)
}

/// [`build_outbound`] with the timeouts given.
fn build_outbound_with(
    builder: reqwest::ClientBuilder,
    request_timeout: Duration,
    connect_timeout: Duration,
) -> reqwest::Result<reqwest::Client> {
    builder
        .timeout(request_timeout)
        .connect_timeout(connect_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A builder that cannot be built is reported, not replaced by a client
    /// without the timeouts and redirect policy.
    #[test]
    fn a_client_that_cannot_be_built_is_an_error() {
        let failing = reqwest::Client::builder().tls_backend_preconfigured(());
        assert!(build_outbound(failing).is_err());
    }

    #[test]
    fn the_timeouts_are_finite() {
        assert!(CONNECT_TIMEOUT <= REQUEST_TIMEOUT);
        assert!(REQUEST_TIMEOUT <= Duration::from_secs(60));
    }

    /// The total timeout is applied: a peer that accepts the connection and
    /// never answers fails the request.
    #[tokio::test]
    async fn a_peer_that_never_answers_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let client = build_outbound_with(
            reqwest::Client::builder(),
            Duration::from_millis(300),
            Duration::from_millis(300),
        )
        .expect("the client builds");
        let started = std::time::Instant::now();
        let err = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect_err("no reply");
        assert!(err.is_timeout(), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
        server.abort();
    }

    /// A 3xx is returned to the caller, not followed.
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let reply = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{addr}/elsewhere\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            }
        });
        let resp = outbound_client()
            .expect("the client builds")
            .get(format!("http://{addr}/start"))
            .send()
            .await
            .expect("a reply");
        assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
        assert_eq!(
            resp.headers()["location"],
            format!("http://{addr}/elsewhere").as_str()
        );
        server.abort();
    }
}

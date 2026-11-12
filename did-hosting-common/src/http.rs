//! Shared outbound HTTP client construction.
//!
//! Every inter-service client (`WitnessClient`,
//! `ControlClient`, `WebVHClient`) talks to a peer over the network, so each
//! must fail fast rather than hang a task forever on a peer that accepts the
//! connection and then never responds, and must not silently follow a 3xx to an
//! unintended host (which would also carry any bearer token along). Building
//! them all through one helper keeps that policy in a single place.
//!
//! Two clients, each built once per process: [`outbound_client`] for URLs the
//! operator configured, and [`peer_endpoint_client`] for a URL a peer's DID
//! document advertises, which is held to an egress policy as well.

use std::sync::OnceLock;
use std::time::Duration;

use affinidi_net_guard::{
    EgressError, EgressPolicy, GuardedClient, GuardedClientBuilder, RedirectMode, Scheme, VettedUrl,
};

/// Total per-request timeout (connect + send + receive). A peer that stalls
/// past this fails the request instead of pinning the caller's task.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect timeout — a peer that accepts a socket but never completes the
/// handshake is abandoned quickly.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A `reqwest::Client` with request + connect timeouts and redirects refused,
/// built once per process and shared (a clone shares the connection pool).
///
/// For URLs this node's operator chose (a configured control plane, witness
/// or hosting URL). A URL taken from a peer's DID document goes through
/// [`peer_endpoint_client`] instead.
///
/// Redirects are refused (`Policy::none()`) so a compromised or misconfigured
/// endpoint cannot 3xx-bounce the request — and any `Authorization` header on
/// it — to a host the caller did not choose. The runtime server/control clients
/// already build this way; the shared clients now match.
///
/// If the client cannot be built (the TLS backend or the platform certificate
/// verifier failed to initialise), the error is returned and nothing is
/// cached, so a later call tries again. There is no fallback client: one
/// without these settings would drop both guarantees.
pub fn outbound_client() -> reqwest::Result<reqwest::Client> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let client = build_outbound(reqwest::Client::builder())?;
    Ok(CLIENT.get_or_init(|| client).clone())
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

/// Most bytes read from a reply to a request sent to a peer-advertised
/// endpoint. A Trust Task reply is one small signed JSON document.
pub(crate) const PEER_MAX_BODY: usize = 1024 * 1024;

/// What a URL taken from a peer's DID document (its `TrustTaskHTTPS`
/// endpoint) may reach: `https` only, globally routable addresses only, no
/// special-use names (`localhost`, `*.internal`, single-label names, ...), no
/// userinfo. The same rule applies to what the name resolves to, at connect
/// time, through the client [`peer_endpoint_client`] builds.
///
/// `loopback` additionally admits loopback hosts, and plain `http` to them.
/// Only tests can ask for it ([`allow_loopback_peer_endpoints`]).
fn peer_endpoint_policy(loopback: bool) -> EgressPolicy {
    let policy = EgressPolicy::public_internet();
    #[cfg(feature = "test-support")]
    if loopback {
        return policy
            .with_schemes(&[Scheme::Https, Scheme::Http])
            .with_dev_loopback(
                affinidi_net_guard::DevLoopback::acknowledge_ssrf_protection_disabled_for_loopback(
                ),
            );
    }
    #[cfg(not(feature = "test-support"))]
    let _ = loopback;
    policy.with_schemes(&[Scheme::Https])
}

#[cfg(feature = "test-support")]
static LOOPBACK_PEERS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Let this process reach a peer's advertised Trust Task endpoint on
/// loopback (plain `http` included), for tests whose peers listen on
/// `127.0.0.1`. Process-wide and one-way. Test builds only.
#[cfg(feature = "test-support")]
pub(crate) fn allow_loopback_peer_endpoints() {
    LOOPBACK_PEERS.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn loopback_peers() -> bool {
    #[cfg(feature = "test-support")]
    {
        LOOPBACK_PEERS.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(feature = "test-support"))]
    {
        false
    }
}

/// Why a peer would refuse `url` as this node's advertised Trust Task
/// endpoint, under the policy release builds apply (no test opt-in), or
/// `None` when it would be accepted. For setup and self-checks: a node
/// advertising an endpoint other nodes will not send to is unreachable over
/// HTTPS.
pub(crate) fn peer_endpoint_refusal(url: &str) -> Option<String> {
    peer_endpoint_policy(false)
        .vet(url)
        .err()
        .map(|e| e.to_string())
}

/// Check a URL taken from a peer's DID document against the peer endpoint
/// policy (scheme, userinfo, literal address class, special-use names). The
/// resolved addresses are checked when [`peer_endpoint_client`] connects.
pub(crate) fn vet_peer_endpoint(url: &str) -> Result<VettedUrl, EgressError> {
    peer_endpoint_policy(loopback_peers()).vet(url)
}

/// The client for a URL taken from a peer's DID document, built once per
/// process and shared: [`peer_endpoint_policy`] enforced on the URL and on
/// every address its name resolves to, the same finite timeouts as
/// [`outbound_client`], redirects refused, no proxy, and replies capped at
/// [`PEER_MAX_BODY`] by `read_body_capped`.
///
/// If the client cannot be built, the send fails.
pub(crate) fn peer_endpoint_client() -> Result<GuardedClient, EgressError> {
    static PUBLIC: OnceLock<GuardedClient> = OnceLock::new();
    #[cfg(feature = "test-support")]
    static LOOPBACK: OnceLock<GuardedClient> = OnceLock::new();

    let loopback = loopback_peers();
    #[cfg(feature = "test-support")]
    let cell = if loopback { &LOOPBACK } else { &PUBLIC };
    #[cfg(not(feature = "test-support"))]
    let cell = &PUBLIC;

    if let Some(client) = cell.get() {
        return Ok(client.clone());
    }
    let client = build_peer_endpoint_client(peer_endpoint_policy(loopback))?;
    Ok(cell.get_or_init(|| client).clone())
}

fn build_peer_endpoint_client(policy: EgressPolicy) -> Result<GuardedClient, EgressError> {
    GuardedClientBuilder::new(policy)
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirects(RedirectMode::None)
        .max_body(PEER_MAX_BODY)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn peer_endpoints_must_be_public_https() {
        let policy = peer_endpoint_policy(false);
        assert!(policy.vet("https://edge.example.com/api").is_ok());
        for refused in [
            "http://edge.example.com/api",
            "http://127.0.0.1:8534/api",
            "https://127.0.0.1:8534/api",
            "http://localhost:8534/api",
            "https://localhost/api",
            "https://[::1]/api",
            "https://10.1.2.3/api",
            "https://192.168.1.10/api",
            "https://172.16.0.1/api",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.0.1/api",
            "https://[fd00::1]/api",
            "https://[::ffff:10.0.0.1]/api",
            "https://metadata/api",
            "https://edge.internal/api",
            "https://user@edge.example.com/api",
        ] {
            assert!(policy.vet(refused).is_err(), "{refused} must be refused");
        }
    }

    /// Only an explicit test opt-in reaches loopback, and even then only
    /// loopback: private ranges stay refused.
    #[cfg(feature = "test-support")]
    #[test]
    fn the_loopback_opt_in_admits_loopback_only() {
        let policy = peer_endpoint_policy(true);
        assert!(policy.vet("http://127.0.0.1:8534/api").is_ok());
        assert!(policy.vet("https://edge.example.com/api").is_ok());
        assert!(policy.vet("https://10.1.2.3/api").is_err());
        assert!(policy.vet("http://edge.example.com/api").is_err());
    }

    #[test]
    fn the_shared_clients_build() {
        outbound_client().expect("outbound client");
        let client = peer_endpoint_client().expect("peer endpoint client");
        assert_eq!(client.max_body(), PEER_MAX_BODY);
    }

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

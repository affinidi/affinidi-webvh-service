//! This workspace's rate limits, built on `affinidi-rate-limit`: the per-address
//! limit on each Trust Task listener (below), wallet sign-in's and the control
//! plane's limits, and the limit on public DID resolution
//! ([`ResolveRateLimiter`], `[server.resolve_rate_limit]`, off by default; an
//! IPv6 client counts by its /64).
//!
//! `POST /api/trust-tasks` is reachable by anyone who can resolve a service's
//! DID document and reach its HTTPS binding — it carries its own proof, so
//! there is no session or bearer to gate on before that proof is checked.
//! Checking that proof means resolving the claimed issuer's DID, which is an
//! outbound fetch: without a limiter, one address can force unbounded
//! resolver work (and outbound network traffic) by posting documents that
//! claim a fresh issuer on every request.
//!
//! # Who the client is
//!
//! Behind a reverse proxy / load balancer / CDN, the TCP peer is the proxy,
//! not the client. `server.trusted_proxies` opts in to reading
//! `X-Forwarded-For` from the peers it names; [`resolve_client_ip`] applies
//! the crate's rule (`ClientIpExtractor`), the same one the mediator and the
//! DID resolver cache use. A chain from a trusted proxy that cannot be
//! attributed is refused with `400` rather than charged to the proxy.
//!
//! Configuring `trusted_proxies` with the wrong value is a foot-gun: trust too
//! much and an attacker can spoof XFF to bypass the limit; trust too little
//! and legitimate proxied requests all hit one limit. Operators should list
//! their actual reverse proxies there and nothing else — and never a layer-4
//! (TCP) forwarder, which passes the client's own header through untouched.
//!
//! # Limits
//!
//! Each limit is stated as requests per window, and is a token bucket: a
//! client may spend its whole allowance at once and regains one request every
//! `window / max`. A refusal's `Retry-After` is the time to the next request.
//! Every limiter's memory is bounded by the crate; [`KeyedRateLimiter::spawn_gc`]
//! sweeps idle clients out of it.

use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use affinidi_rate_limit::{
    ClientIpExtractor, IpNet, KeyedRateLimiterState, RateLimitLayer, RateLimiterState,
    TooManyRequests,
};
use axum::http::HeaderMap;
use ipnetwork::IpNetwork;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::config::ServerConfig;
use super::error::{AppError, RATE_LIMIT_SOURCE};

/// The `limiter` name every Trust Task listener's per-address limiter uses
/// (the edge server, the witness, the watcher): a stable, shared string so a
/// client's `x-rate-limit-source`/`limiter` handling doesn't need to special-
/// case which service answered.
pub const TRUST_TASKS_RATE_LIMIT_NAME: &str = "trust-tasks-per-address";

/// Maximum `POST /api/trust-tasks` requests one address may make per
/// [`TRUST_TASKS_WINDOW_SECS`] before refusal — generous enough for a busy
/// control plane's own retries and acknowledgements, tight enough to bound an
/// attacker's DID-resolution throughput to a trickle.
pub const TRUST_TASKS_MAX_PER_WINDOW: u64 = 10;

/// Window, in seconds, for the Trust Task listener limiter.
pub const TRUST_TASKS_WINDOW_SECS: u64 = 60;

/// The `limiter` name of the per-address limit on public DID resolution.
pub const RESOLVE_RATE_LIMIT_NAME: &str = "resolve-per-address";

/// The prefix an IPv6 client is counted by on resolution: the block one host
/// is normally given, so rotating addresses inside it does not escape the
/// limit.
const RESOLVE_IPV6_PREFIX: u8 = 64;

/// A named limit of `max_per_window` requests per `window_secs` for each key
/// (a client address, an authenticated source, or `()` for one budget shared
/// by everyone), refusing with [`AppError::RateLimited`].
#[derive(Clone, Debug)]
pub struct KeyedRateLimiter<K: Hash + Eq + Clone> {
    state: KeyedRateLimiterState<K>,
    limiter: &'static str,
    max_per_window: u64,
    window_secs: u64,
}

/// A [`KeyedRateLimiter`] per client address.
pub type IpRateLimiter = KeyedRateLimiter<IpAddr>;

impl<K: Hash + Eq + Clone> KeyedRateLimiter<K> {
    /// `max_per_window` requests per `window_secs` for each key, refusals
    /// naming `limiter`. A limit above `u32::MAX` is held at `u32::MAX`,
    /// which no client reaches in a window.
    pub fn new(limiter: &'static str, max_per_window: u64, window_secs: u64) -> Self {
        let state = KeyedRateLimiterState::per_window(
            u32::try_from(max_per_window).unwrap_or(u32::MAX),
            Duration::from_secs(window_secs),
        )
        .with_source(RATE_LIMIT_SOURCE)
        .with_limiter_name(limiter);
        Self {
            state,
            limiter,
            max_per_window,
            window_secs,
        }
    }

    /// Charge one request to `key`, or refuse it with
    /// [`AppError::RateLimited`] (`429` with `Retry-After`).
    pub fn try_consume(&self, key: K) -> Result<(), AppError> {
        self.state
            .charge(key)
            .map_err(
                |TooManyRequests { retry_after_secs }| AppError::RateLimited {
                    limiter: self.limiter,
                    message: format!(
                        "rate limit exceeded ({} requests per {}s); try again later",
                        self.max_per_window, self.window_secs
                    ),
                    retry_after_secs,
                },
            )
    }

    /// Whether a refusal of `key` is its first in its window, recording it,
    /// so a caller logs once per window rather than once per request.
    pub fn first_refusal_in_window(&self, key: &K) -> bool {
        self.state.first_refusal_in_window(key)
    }
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> KeyedRateLimiter<K> {
    /// Sweep clients whose budget has refilled out of the limiter's memory
    /// every minute until `shutdown` fires. Must run on a Tokio runtime.
    pub fn spawn_gc(&self, shutdown: CancellationToken) {
        self.state.spawn_gc(shutdown);
    }
}

/// The per-client-address limit on public DID resolution
/// (`[server.resolve_rate_limit]`), shared by the edge server, the watcher and
/// the daemon. Lets everything through when no limit is configured.
///
/// Clones share one budget: every route a limiter's [`layer`](Self::layer)
/// wraps counts against the same client allowance.
#[derive(Clone, Debug)]
pub struct ResolveRateLimiter {
    state: RateLimiterState,
    layer: RateLimitLayer,
}

impl ResolveRateLimiter {
    /// The limiter `server.resolve_rate_limit` describes, attributing
    /// requests through `server.trusted_proxies`. Warns when a limit is set
    /// with no trusted proxies: behind a load balancer every client would
    /// then share one budget.
    ///
    /// # Errors
    ///
    /// [`AppError::Config`] for a trusted proxy range covering every address,
    /// which configuration loading already refuses.
    pub fn new(server: &ServerConfig) -> Result<Self, AppError> {
        let config = &server.resolve_rate_limit;
        let Some(max) = config.max_per_window else {
            return Ok(Self::disabled());
        };
        if server.trusted_proxies.is_empty() {
            warn!(
                "server.resolve_rate_limit is on with no server.trusted_proxies: it counts \
                 the TCP peer, so behind a load balancer every client shares one budget"
            );
        }
        info!(
            max_per_window = max,
            window_secs = config.window_secs,
            "resolution rate limit on"
        );
        let state = RateLimiterState::per_window(
            u32::try_from(max).unwrap_or(u32::MAX),
            Duration::from_secs(config.window_secs),
        )
        .with_source(RATE_LIMIT_SOURCE)
        .with_limiter_name(RESOLVE_RATE_LIMIT_NAME);
        // A clone of the handlers' shared extractor, so a proxy's invalid
        // chain is logged once a minute whichever path met it.
        let clients = (*shared_client_ip_extractor(&server.trusted_proxies)?)
            .clone()
            .ipv6_prefix(RESOLVE_IPV6_PREFIX)
            .expect("64 is a valid IPv6 prefix length");
        let layer = RateLimitLayer::new(state.clone()).client_ip_extractor(clients);
        Ok(Self { state, layer })
    }

    /// A limiter that lets everything through.
    pub fn disabled() -> Self {
        let state = RateLimiterState::disabled();
        Self {
            layer: RateLimitLayer::new(state.clone()),
            state,
        }
    }

    /// The layer applying this limit to the routes it wraps. It refuses a
    /// client over the limit with `429` and `Retry-After`, a request without a
    /// peer address with `403` (production serves with
    /// `into_make_service_with_connect_info`, so that is a wiring fault), and
    /// an unattributable `X-Forwarded-For` from a trusted proxy with `400`.
    pub fn layer(&self) -> RateLimitLayer {
        self.layer.clone()
    }

    /// Sweep clients whose budget has refilled out of the limiter's memory
    /// every minute until `shutdown` fires. A no-op when disabled. Must run on
    /// a Tokio runtime.
    pub fn spawn_gc(&self, shutdown: CancellationToken) {
        self.state.spawn_gc(shutdown);
    }
}

/// The crate's client-address rule for `trusted_proxies`.
///
/// # Errors
///
/// [`AppError::Config`] for a range covering every address.
pub fn client_ip_extractor(trusted_proxies: &[IpNetwork]) -> Result<ClientIpExtractor, AppError> {
    let ranges = trusted_proxies
        .iter()
        .map(|network| {
            IpNet::new(network.network(), network.prefix())
                .expect("an IpNetwork's prefix is valid for its address family")
        })
        .collect();
    ClientIpExtractor::trusted_proxies(ranges)
        .map_err(|e| AppError::Config(format!("server.trusted_proxies: {e}")))
}

/// The client address of a request from `peer` carrying `headers`: `peer`
/// unless it is one of `trusted_proxies`, in which case the client its
/// `X-Forwarded-For` names. IPv4-mapped addresses are unwrapped.
///
/// # Errors
///
/// [`AppError::Validation`] (`400`) for a chain from a trusted proxy that
/// cannot be attributed: a malformed entry where the proxies wrote, more than
/// 64 entries, or a header that is not visible ASCII. Charging it to the
/// proxy instead would hand the sender a second budget and hide a misbehaving
/// proxy.
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNetwork],
) -> Result<IpAddr, AppError> {
    shared_client_ip_extractor(trusted_proxies)?
        .client_ip(peer, headers)
        .map_err(|e| AppError::Validation(e.to_string()))
}

/// Admit one request from `peer` to a Trust Task listener, charged to its
/// client address: the client address, or the refusal to send (`400` for an
/// unreadable chain from a trusted proxy, `429` past the limit). A client's
/// first refusal in each window is logged.
pub fn admit_trust_task(
    limiter: &IpRateLimiter,
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNetwork],
) -> Result<IpAddr, AppError> {
    let client_ip = resolve_client_ip(peer, headers, trusted_proxies)?;
    limiter.try_consume(client_ip).inspect_err(|_| {
        if limiter.first_refusal_in_window(&client_ip) {
            warn!(ip = %client_ip, "trust-tasks client over the rate limit; refusing it until its budget refills");
        }
    })?;
    Ok(client_ip)
}

/// The extractor for `trusted_proxies`, built once per distinct list and
/// reused, so every handler shares its once-a-minute log of a proxy's invalid
/// chain (and the request path skips rebuilding it). A process has one or two
/// lists (the daemon's services share theirs), so the cache stays tiny.
fn shared_client_ip_extractor(
    trusted_proxies: &[IpNetwork],
) -> Result<Arc<ClientIpExtractor>, AppError> {
    static EXTRACTORS: Mutex<Vec<(Vec<IpNetwork>, Arc<ClientIpExtractor>)>> =
        Mutex::new(Vec::new());
    let mut extractors = EXTRACTORS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, extractor)) = extractors
        .iter()
        .find(|(proxies, _)| proxies.as_slice() == trusted_proxies)
    {
        return Ok(extractor.clone());
    }
    let extractor = Arc::new(client_ip_extractor(trusted_proxies)?);
    extractors.push((trusted_proxies.to_vec(), extractor.clone()));
    Ok(extractor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn nets(list: &[&str]) -> Vec<IpNetwork> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn xff(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append("x-forwarded-for", line.parse().unwrap());
        }
        headers
    }

    // --- KeyedRateLimiter ---

    /// Past its limit a key is refused with this service's 429: the limit
    /// named, `Retry-After` set; another key is unaffected.
    #[tokio::test]
    async fn a_limiter_refuses_one_key_past_its_limit_with_its_name() {
        let limiter = IpRateLimiter::new("test-limiter", 2, 60);
        let client = ip("203.0.113.1");
        limiter.try_consume(client).unwrap();
        limiter.try_consume(client).unwrap();
        let refusal = limiter.try_consume(client).unwrap_err();
        assert!(matches!(
            refusal,
            AppError::RateLimited {
                limiter: "test-limiter",
                retry_after_secs: 30,
                ..
            }
        ));
        let response = refusal.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["x-rate-limit-source"], "did-host");
        assert_eq!(response.headers()["retry-after"], "30");
        limiter.try_consume(ip("203.0.113.2")).unwrap();
    }

    /// The Trust Task listener's limit is its documented allowance per
    /// address, and refuses the next request.
    #[test]
    fn the_trust_task_listener_limit_is_its_documented_allowance() {
        let limiter = IpRateLimiter::new(
            TRUST_TASKS_RATE_LIMIT_NAME,
            TRUST_TASKS_MAX_PER_WINDOW,
            TRUST_TASKS_WINDOW_SECS,
        );
        let client = ip("203.0.113.1");
        for _ in 0..TRUST_TASKS_MAX_PER_WINDOW {
            limiter.try_consume(client).unwrap();
        }
        assert!(matches!(
            limiter.try_consume(client),
            Err(AppError::RateLimited {
                limiter: TRUST_TASKS_RATE_LIMIT_NAME,
                ..
            })
        ));
    }

    /// One extractor per trusted-proxy list, so handlers share its log of a
    /// proxy's invalid chain.
    #[test]
    fn handlers_share_one_extractor_per_proxy_list() {
        let trusted = nets(&["10.0.0.0/8"]);
        let first = shared_client_ip_extractor(&trusted).unwrap();
        let again = shared_client_ip_extractor(&trusted).unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        let other = shared_client_ip_extractor(&nets(&["172.16.0.0/12"])).unwrap();
        assert!(!Arc::ptr_eq(&first, &other));
    }

    /// A limit on what a source proves, and one budget for everyone.
    #[test]
    fn limits_key_on_sources_and_on_nothing() {
        let per_source = KeyedRateLimiter::<String>::new("per-source", 1, 60);
        per_source.try_consume("vid:did:example:a".into()).unwrap();
        assert!(per_source.try_consume("vid:did:example:a".into()).is_err());
        per_source.try_consume("ip:203.0.113.1".into()).unwrap();

        let global = KeyedRateLimiter::<()>::new("global", 1, 60);
        global.try_consume(()).unwrap();
        assert!(global.try_consume(()).is_err());
    }

    #[test]
    fn a_refusal_is_reported_once_per_window() {
        let limiter = IpRateLimiter::new("test-limiter", 1, 60);
        let client = ip("203.0.113.1");
        assert!(limiter.first_refusal_in_window(&client));
        assert!(!limiter.first_refusal_in_window(&client));
    }

    // --- resolve_client_ip ---

    #[test]
    fn resolve_no_trusted_proxies_returns_peer() {
        let peer = ip("203.0.113.1");
        assert_eq!(
            resolve_client_ip(peer, &xff(&["198.51.100.1"]), &[]).unwrap(),
            peer
        );
    }

    /// Behind trusted proxies, the first untrusted hop from the right: never
    /// what a client wrote further left, and never what an untrusted peer
    /// claims.
    #[test]
    fn resolve_names_the_client_behind_trusted_proxies() {
        let trusted = nets(&["10.20.0.0/16", "172.16.0.0/12"]);
        assert_eq!(
            resolve_client_ip(
                ip("10.20.3.4"),
                &xff(&["1.1.1.1, 198.51.100.7, 172.16.9.9, 10.20.1.1"]),
                &trusted
            )
            .unwrap(),
            ip("198.51.100.7")
        );
        assert_eq!(
            resolve_client_ip(ip("10.21.0.1"), &xff(&["198.51.100.7"]), &trusted).unwrap(),
            ip("10.21.0.1")
        );
        assert_eq!(
            resolve_client_ip(ip("::ffff:10.20.0.1"), &xff(&["198.51.100.7"]), &trusted).unwrap(),
            ip("198.51.100.7"),
            "an IPv4-mapped proxy matches its IPv4 range"
        );
    }

    /// A chain a trusted proxy sent that cannot be attributed is a 400, not
    /// the proxy's address.
    #[test]
    fn resolve_refuses_an_unattributable_chain_from_a_trusted_proxy() {
        let trusted = nets(&["10.0.0.0/8"]);
        let refusal =
            resolve_client_ip(ip("10.0.0.1"), &xff(&["not-an-ip"]), &trusted).unwrap_err();
        assert_eq!(refusal.into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), &HeaderMap::new(), &trusted).unwrap(),
            ip("10.0.0.1"),
            "no header is the peer"
        );
    }

    // --- ResolveRateLimiter ---

    fn resolve_limiter(
        max_per_window: Option<u64>,
        trusted_proxies: &[&str],
    ) -> ResolveRateLimiter {
        let mut server = ServerConfig::default();
        server.resolve_rate_limit.max_per_window = max_per_window;
        server.trusted_proxies = nets(trusted_proxies);
        ResolveRateLimiter::new(&server).unwrap()
    }

    fn app(limiter: &ResolveRateLimiter) -> axum::Router {
        axum::Router::new()
            .route("/alice/did.jsonl", get(|| async { "ok" }))
            .layer(limiter.layer())
    }

    fn request(peer: &str, xff: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri("/alice/did.jsonl");
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip(peer), 443)));
        request
    }

    async fn status(app: &axum::Router, request: Request<Body>) -> StatusCode {
        app.clone().oneshot(request).await.unwrap().status()
    }

    /// Unset, the limit lets everything through, even a request with no peer
    /// address.
    #[tokio::test]
    async fn resolve_limit_off_by_default() {
        let app = app(&resolve_limiter(None, &[]));
        for _ in 0..100 {
            assert_eq!(
                status(&app, request("10.0.0.1", None)).await,
                StatusCode::OK
            );
        }
        let bare = Request::builder()
            .uri("/alice/did.jsonl")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&app, bare).await, StatusCode::OK);
    }

    /// Past the limit one address gets this service's attributed 429; another
    /// address is unaffected.
    #[tokio::test]
    async fn resolve_limit_refuses_one_address_past_the_limit() {
        let app = app(&resolve_limiter(Some(3), &[]));
        for _ in 0..3 {
            assert_eq!(
                status(&app, request("10.0.0.1", None)).await,
                StatusCode::OK
            );
        }
        let refused = app
            .clone()
            .oneshot(request("10.0.0.1", None))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(refused.headers()["x-rate-limit-source"], "did-host");
        assert!(refused.headers().contains_key("retry-after"));
        let body = axum::body::to_bytes(refused.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["limiter"], RESOLVE_RATE_LIMIT_NAME);
        assert_eq!(
            status(&app, request("10.0.0.2", None)).await,
            StatusCode::OK
        );
    }

    /// Behind a trusted proxy the limit follows the client in
    /// `X-Forwarded-For`, not the proxy; an untrusted peer's header is
    /// ignored.
    #[tokio::test]
    async fn resolve_limit_keys_on_the_forwarded_client_behind_a_trusted_proxy() {
        let app = app(&resolve_limiter(Some(1), &["10.0.0.9"]));
        let proxied = |client| request("10.0.0.9", Some(client));
        assert_eq!(status(&app, proxied("203.0.113.1")).await, StatusCode::OK);
        assert_eq!(status(&app, proxied("203.0.113.2")).await, StatusCode::OK);
        assert_eq!(
            status(&app, proxied("203.0.113.1")).await,
            StatusCode::TOO_MANY_REQUESTS
        );

        let direct = |client| request("198.51.100.7", Some(client));
        assert_eq!(status(&app, direct("203.0.113.3")).await, StatusCode::OK);
        assert_eq!(
            status(&app, direct("203.0.113.4")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "an untrusted peer is limited on its own address"
        );
    }

    /// An IPv6 client is counted by its /64.
    #[tokio::test]
    async fn resolve_limit_counts_an_ipv6_client_by_its_64() {
        let app = app(&resolve_limiter(Some(2), &[]));
        assert_eq!(
            status(&app, request("2001:db8:1:2::1", None)).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&app, request("2001:db8:1:2::2", None)).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&app, request("2001:db8:1:2::3", None)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&app, request("2001:db8:1:3::1", None)).await,
            StatusCode::OK
        );
    }

    /// With a limit set, a request without a peer address is refused rather
    /// than let through unlimited.
    #[tokio::test]
    async fn resolve_limit_refuses_a_request_without_a_peer_address() {
        let app = app(&resolve_limiter(Some(100), &[]));
        let bare = Request::builder()
            .uri("/alice/did.jsonl")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&app, bare).await, StatusCode::FORBIDDEN);
    }

    /// Every route behind one limiter's layers shares one budget.
    #[tokio::test]
    async fn resolve_layers_from_one_limiter_share_a_budget() {
        let limiter = resolve_limiter(Some(1), &[]);
        let first = app(&limiter);
        let second = app(&limiter);
        assert_eq!(
            status(&first, request("10.0.0.1", None)).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&second, request("10.0.0.1", None)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}

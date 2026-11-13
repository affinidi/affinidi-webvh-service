//! This workspace's rate limits, built on `affinidi-rate-limit`: the per-address
//! limit on each Trust Task listener (below), wallet sign-in's and the control
//! plane's limits, and the limit on public DID resolution
//! ([`ResolveRateLimiter`], `[server.resolve_rate_limit]`, off by default).
//!
//! Every per-address limit counts an IPv6 client by its network, not its full
//! address: `server.client_ipv6_prefix` (default
//! [`DEFAULT_CLIENT_IPV6_PREFIX`], the block one host is normally given), so
//! rotating addresses inside that block draws on one allowance
//! ([`ClientIps::key_of`]). IPv4 clients count by their address.
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
//! `X-Forwarded-For` from the peers it names; [`ClientIps`], built once from it
//! and held in each service's state, applies the crate's rule
//! (`ClientIpExtractor`), the same one the mediator and the DID resolver cache
//! use. A chain from a trusted proxy that cannot be attributed is refused with
//! `400` (`invalid_forwarded_for`, the same body on every path) rather than
//! charged to the proxy.
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

use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use affinidi_rate_limit::{
    ClientIpExtractor, InvalidForwardedFor, IpNet, KeyedRateLimiterState, RateLimitLayer,
    RateLimiterState, TooManyRequests,
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

/// The prefix an IPv6 client is counted by when `server.client_ipv6_prefix`
/// is not set: the block one host is normally given, so rotating addresses
/// inside it does not draw on a fresh allowance.
pub const DEFAULT_CLIENT_IPV6_PREFIX: u8 = 64;

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

impl<K: Hash + Eq + Clone + fmt::Debug> KeyedRateLimiter<K> {
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

    /// Track at most `max_tracked_keys` keys at once rather than the crate's
    /// default; a new key past that is refused. Set while building.
    pub fn with_max_tracked_keys(mut self, max_tracked_keys: usize) -> Self {
        self.state = self.state.with_max_tracked_keys(max_tracked_keys);
        self
    }

    /// The name this limiter's refusals carry.
    pub fn name(&self) -> &'static str {
        self.limiter
    }

    /// Charge one request to `key`, or refuse it with
    /// [`AppError::RateLimited`] (`429` with `Retry-After`). A key's first
    /// refusal in each window is logged, naming the limiter, so a flood
    /// costs one log line a window rather than one a request.
    pub fn try_consume(&self, key: K) -> Result<(), AppError> {
        let Err(TooManyRequests { retry_after_secs }) = self.state.charge(key.clone()) else {
            return Ok(());
        };
        if self.state.first_refusal_in_window(&key) {
            warn!(
                limiter = self.limiter,
                client = ?key,
                "client over the rate limit; refusing it until its budget refills"
            );
        }
        Err(AppError::RateLimited {
            limiter: self.limiter,
            message: format!(
                "rate limit exceeded ({} requests per {}s); try again later",
                self.max_per_window, self.window_secs
            ),
            retry_after_secs,
        })
    }
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> KeyedRateLimiter<K> {
    /// Sweep clients whose budget has refilled out of the limiter's memory
    /// every minute until `shutdown` fires. Must run on a Tokio runtime.
    pub fn spawn_gc(&self, shutdown: CancellationToken) {
        self.state.spawn_gc(shutdown);
    }
}

impl IpRateLimiter {
    /// Admit one request from `peer` carrying `headers`, charged to its client
    /// address's key ([`ClientIps::key_of`]: an IPv6 client's network). Returns
    /// the client address ([`ClientIps::client_ip`]), or the refusal to send — [`AppError::InvalidForwardedFor`] (`400`, the same body the
    /// resolution limit sends) for an unreadable chain from a trusted proxy,
    /// [`AppError::RateLimited`] (`429`) past the limit.
    pub fn admit(
        &self,
        clients: &ClientIps,
        peer: IpAddr,
        headers: &HeaderMap,
    ) -> Result<IpAddr, AppError> {
        let client_ip = clients
            .client_ip(peer, headers)
            .map_err(|InvalidForwardedFor| AppError::InvalidForwardedFor {
                limiter: self.limiter,
            })?;
        self.try_consume(clients.key_of(client_ip))?;
        Ok(client_ip)
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
    /// requests through `clients` (the service's own, built from the same
    /// `server.trusted_proxies`). Warns when a limit is set with no trusted
    /// proxies: behind a load balancer every client would then share one
    /// budget.
    pub fn new(server: &ServerConfig, clients: &ClientIps) -> Self {
        let config = &server.resolve_rate_limit;
        let Some(max) = config.max_per_window else {
            return Self::disabled();
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
        // A clone of the handlers' extractor, so a proxy's invalid chain is
        // logged once a minute whichever path met it. It carries the
        // service's IPv6 prefix, so the layer counts a client as the
        // handlers' limits do.
        let clients = (*clients.extractor).clone();
        let layer = RateLimitLayer::new(state.clone()).client_ip_extractor(clients);
        Self { state, layer }
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

/// Who the client is: the crate's client-address rule for
/// `server.trusted_proxies`, built once from configuration and held in each
/// service's state. Clones share one extractor, so a proxy's invalid chain is
/// logged once a minute whichever path met it.
///
/// It also says what a per-address limit counts a client as
/// ([`Self::key_of`]): an IPv6 client by its network of the configured prefix.
///
/// The default trusts no proxy (every request is its TCP peer) and counts an
/// IPv6 client by its [`DEFAULT_CLIENT_IPV6_PREFIX`] network.
#[derive(Clone, Debug)]
pub struct ClientIps {
    extractor: Arc<ClientIpExtractor>,
    ipv6_prefix: u8,
}

impl Default for ClientIps {
    fn default() -> Self {
        Self {
            extractor: Arc::new(
                ClientIpExtractor::default()
                    .ipv6_prefix(DEFAULT_CLIENT_IPV6_PREFIX)
                    .expect("64 is a valid IPv6 prefix length"),
            ),
            ipv6_prefix: DEFAULT_CLIENT_IPV6_PREFIX,
        }
    }
}

impl ClientIps {
    /// The rule for `trusted_proxies`, counting an IPv6 client by its
    /// [`DEFAULT_CLIENT_IPV6_PREFIX`] network.
    ///
    /// # Errors
    ///
    /// [`AppError::Config`] for a range covering every address, which
    /// configuration loading already refuses.
    pub fn new(trusted_proxies: &[IpNetwork]) -> Result<Self, AppError> {
        Self::with_ipv6_prefix(trusted_proxies, DEFAULT_CLIENT_IPV6_PREFIX)
    }

    /// The rule a service's `[server]` section describes:
    /// `trusted_proxies` and `client_ipv6_prefix`.
    ///
    /// # Errors
    ///
    /// [`AppError::Config`] for a `trusted_proxies` range covering every
    /// address, or a `client_ipv6_prefix` outside 1 to 128.
    pub fn from_server_config(server: &ServerConfig) -> Result<Self, AppError> {
        Self::with_ipv6_prefix(&server.trusted_proxies, server.client_ipv6_prefix)
    }

    /// The rule for `trusted_proxies`, counting an IPv6 client by its network
    /// of `ipv6_prefix` bits.
    ///
    /// # Errors
    ///
    /// [`AppError::Config`] for a range covering every address, or a prefix
    /// outside 1 to 128 (0 would count every IPv6 client as one).
    pub fn with_ipv6_prefix(
        trusted_proxies: &[IpNetwork],
        ipv6_prefix: u8,
    ) -> Result<Self, AppError> {
        let ranges = trusted_proxies
            .iter()
            .map(|network| {
                IpNet::new(network.network(), network.prefix())
                    .expect("an IpNetwork's prefix is valid for its address family")
            })
            .collect();
        let extractor = ClientIpExtractor::trusted_proxies(ranges)
            .map_err(|e| AppError::Config(format!("server.trusted_proxies: {e}")))?
            .ipv6_prefix(ipv6_prefix)
            .map_err(|e| AppError::Config(format!("server.client_ipv6_prefix: {e}")))?;
        Ok(Self {
            extractor: Arc::new(extractor),
            ipv6_prefix,
        })
    }

    /// What a per-address limit counts `client` (a [`Self::client_ip`]) as:
    /// an IPv6 address's network of the configured prefix, so one host
    /// cannot draw a fresh allowance from each address in its block; an IPv4
    /// address as itself.
    pub fn key_of(&self, client: IpAddr) -> IpAddr {
        match client {
            IpAddr::V6(address) => ipnetwork::Ipv6Network::new(address, self.ipv6_prefix)
                .map_or(client, |network| IpAddr::V6(network.network())),
            IpAddr::V4(_) => client,
        }
    }

    /// The client address of a request from `peer` carrying `headers`:
    /// `peer` unless it is a trusted proxy, in which case the client its
    /// `X-Forwarded-For` names. IPv4-mapped addresses are unwrapped.
    ///
    /// # Errors
    ///
    /// [`InvalidForwardedFor`] for a chain from a trusted proxy that cannot
    /// be attributed: a malformed entry where the proxies wrote, more than 64
    /// entries, or a header that is not visible ASCII. Charging it to the
    /// proxy instead would hand the sender a second budget and hide a
    /// misbehaving proxy.
    pub fn client_ip(
        &self,
        peer: IpAddr,
        headers: &HeaderMap,
    ) -> Result<IpAddr, InvalidForwardedFor> {
        self.extractor.client_ip(peer, headers)
    }
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

    /// Clones of one [`ClientIps`] share its extractor, so the handlers and
    /// the resolution layer share its log of a proxy's invalid chain.
    #[test]
    fn clones_of_client_ips_share_one_extractor() {
        let clients = ClientIps::new(&nets(&["10.0.0.0/8"])).unwrap();
        assert!(Arc::ptr_eq(&clients.extractor, &clients.clone().extractor));
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

    /// A key's first refusal in a window is recorded (and logged) once.
    #[test]
    fn a_refusal_is_reported_once_per_window() {
        let limiter = IpRateLimiter::new("test-limiter", 1, 60);
        let client = ip("203.0.113.1");
        limiter.try_consume(client).unwrap();
        assert!(limiter.try_consume(client).is_err());
        assert!(
            !limiter.state.first_refusal_in_window(&client),
            "try_consume already recorded this window's refusal"
        );
    }

    // --- ClientIps ---

    fn resolve_client_ip(
        peer: IpAddr,
        headers: &HeaderMap,
        trusted_proxies: &[IpNetwork],
    ) -> Result<IpAddr, InvalidForwardedFor> {
        ClientIps::new(trusted_proxies)
            .unwrap()
            .client_ip(peer, headers)
    }

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

    /// A chain a trusted proxy sent that cannot be attributed is refused,
    /// not charged to the proxy's address.
    #[test]
    fn resolve_refuses_an_unattributable_chain_from_a_trusted_proxy() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), &xff(&["not-an-ip"]), &trusted),
            Err(InvalidForwardedFor)
        );
        assert_eq!(
            resolve_client_ip(ip("10.0.0.1"), &HeaderMap::new(), &trusted).unwrap(),
            ip("10.0.0.1"),
            "no header is the peer"
        );
    }

    /// A handler's refusal of an unattributable chain is the same `400` the
    /// resolution layer sends: `invalid_forwarded_for`, naming the limiter,
    /// attributed to this service.
    #[tokio::test]
    async fn admit_refuses_an_unattributable_chain_as_the_layer_does() {
        let limiter = IpRateLimiter::new("test-limiter", 10, 60);
        let clients = ClientIps::new(&nets(&["10.0.0.0/8"])).unwrap();
        let refusal = limiter
            .admit(&clients, ip("10.0.0.1"), &xff(&["not-an-ip"]))
            .unwrap_err();
        let response = refusal.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["x-rate-limit-source"], "did-host");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "error": affinidi_rate_limit::INVALID_FORWARDED_FOR_ERROR,
                "limiter": "test-limiter",
                "message": "Invalid X-Forwarded-For header; request rejected.",
            })
        );
        assert_eq!(
            limiter
                .admit(&clients, ip("10.0.0.1"), &xff(&["198.51.100.7"]))
                .unwrap(),
            ip("198.51.100.7")
        );
    }

    /// A per-address limit counts an IPv6 client by its /64 by default: a
    /// host stepping through the addresses of its block shares one allowance,
    /// while the next /64 and an IPv4 client have their own. The address
    /// handed back is still the client's own.
    #[test]
    fn admit_counts_an_ipv6_client_by_its_network() {
        let limiter = IpRateLimiter::new("test-limiter", 2, 60);
        let clients = ClientIps::new(&[]).unwrap();
        let headers = HeaderMap::new();
        assert_eq!(
            limiter
                .admit(&clients, ip("2001:db8:1:1::1"), &headers)
                .unwrap(),
            ip("2001:db8:1:1::1")
        );
        limiter
            .admit(&clients, ip("2001:db8:1:1:ffff::2"), &headers)
            .unwrap();
        assert!(matches!(
            limiter.admit(&clients, ip("2001:db8:1:1:abcd::3"), &headers),
            Err(AppError::RateLimited { .. })
        ));
        limiter
            .admit(&clients, ip("2001:db8:1:2::1"), &headers)
            .unwrap();
        limiter
            .admit(&clients, ip("203.0.113.1"), &headers)
            .unwrap();
        limiter
            .admit(&clients, ip("203.0.113.2"), &headers)
            .unwrap();
    }

    /// The prefix is configurable, IPv4 is never masked, and a prefix that
    /// would count every IPv6 client as one, or is not a prefix at all, is
    /// refused at startup.
    #[test]
    fn the_ipv6_prefix_is_configurable_and_validated() {
        let mut server = ServerConfig::default();
        assert_eq!(server.client_ipv6_prefix, DEFAULT_CLIENT_IPV6_PREFIX);
        assert_eq!(
            ClientIps::default().key_of(ip("2001:db8:1:1:2:3:4:5")),
            ip("2001:db8:1:1::")
        );
        server.client_ipv6_prefix = 48;
        let clients = ClientIps::from_server_config(&server).unwrap();
        assert_eq!(
            clients.key_of(ip("2001:db8:1:1:2:3:4:5")),
            ip("2001:db8:1::")
        );
        assert_eq!(clients.key_of(ip("203.0.113.9")), ip("203.0.113.9"));
        server.client_ipv6_prefix = 128;
        assert_eq!(
            ClientIps::from_server_config(&server)
                .unwrap()
                .key_of(ip("2001:db8::5")),
            ip("2001:db8::5")
        );
        for refused in [0, 129] {
            server.client_ipv6_prefix = refused;
            assert!(
                matches!(
                    ClientIps::from_server_config(&server),
                    Err(AppError::Config(_))
                ),
                "prefix {refused} should be refused"
            );
        }
    }

    /// The resolution layer counts an IPv6 client by the service's
    /// configured network, as the handlers' limits do.
    #[tokio::test]
    async fn the_resolution_layer_uses_the_configured_ipv6_prefix() {
        let mut server = ServerConfig::default();
        server.resolve_rate_limit.max_per_window = Some(1);
        server.client_ipv6_prefix = 48;
        let limiter =
            ResolveRateLimiter::new(&server, &ClientIps::from_server_config(&server).unwrap());
        let app = app(&limiter);
        assert_eq!(
            status(&app, request("2001:db8:1:1::1", None)).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&app, request("2001:db8:1:2::1", None)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&app, request("2001:db8:2::1", None)).await,
            StatusCode::OK
        );
    }

    /// The resolution layer's own refusal of the same chain, for comparison
    /// with the handlers' above.
    #[tokio::test]
    async fn the_resolution_layer_refuses_an_unattributable_chain_with_the_same_body() {
        let app = app(&resolve_limiter(Some(10), &["10.0.0.0/8"]));
        let response = app
            .oneshot(request("10.0.0.1", Some("not-an-ip")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["x-rate-limit-source"], "did-host");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["error"],
            affinidi_rate_limit::INVALID_FORWARDED_FOR_ERROR
        );
        assert_eq!(body["limiter"], RESOLVE_RATE_LIMIT_NAME);
    }

    // --- ResolveRateLimiter ---

    fn resolve_limiter(
        max_per_window: Option<u64>,
        trusted_proxies: &[&str],
    ) -> ResolveRateLimiter {
        let mut server = ServerConfig::default();
        server.resolve_rate_limit.max_per_window = max_per_window;
        server.trusted_proxies = nets(trusted_proxies);
        ResolveRateLimiter::new(&server, &ClientIps::new(&server.trusted_proxies).unwrap())
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

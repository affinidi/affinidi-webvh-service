//! Per-address rate limiter for an unauthenticated Trust Task listener.
//!
//! `POST /api/trust-tasks` is reachable by anyone who can resolve a service's
//! DID document and reach its HTTPS binding — it carries its own proof, so
//! there is no session or bearer to gate on before that proof is checked.
//! Checking that proof means resolving the claimed issuer's DID, which is an
//! outbound fetch: without a limiter, one address can force unbounded
//! resolver work (and outbound network traffic) by posting documents that
//! claim a fresh issuer on every request. This module adds the same
//! per-address defence the control plane's `/api/auth/challenge` uses
//! (`did-hosting-control::rate_limit`), generalised so the edge server, the
//! witness and the watcher can each configure their own limiter name and
//! thresholds.
//!
//! # IP-attribution policy
//!
//! Identical to the control plane's: behind a reverse proxy / load balancer /
//! CDN, the TCP peer is the proxy itself, not the real client. The
//! `trusted_proxies` config opts in to parsing `X-Forwarded-For`:
//!
//! - Empty `trusted_proxies` (default): always use the direct TCP peer.
//!   Safe when running on the open internet without a proxy.
//! - Non-empty `trusted_proxies` (addresses or CIDR ranges): when the TCP
//!   peer is one of them, walk `X-Forwarded-For` from the right, skip each
//!   entry that is itself a trusted proxy, and use the first one that isn't.
//!
//! The header is a chain that every conforming proxy *appends* to, so only
//! its right-hand end is trustworthy: whatever the client wrote sits further
//! left and is never reached. Every uncertainty — a malformed entry, an
//! over-long chain, a chain trusted end to end — resolves to the peer, the
//! one value nobody can spoof. This is the VTC's rule
//! (`vti-common::rate_limit::TrustedProxyKeyExtractor`).
//!
//! Configuring `trusted_proxies` with the wrong value is a foot-gun: trust too
//! much and an attacker can spoof XFF to bypass the limit; trust too little
//! and legitimate proxied requests all hit one limit. Operators should list
//! their actual reverse proxies there and nothing else — and never a layer-4
//! (TCP) forwarder, which passes the client's own header through untouched.
//!
//! # Algorithm
//!
//! Per-address fixed-window counter, refreshed every `window_secs`. Each
//! `try_consume(addr)` increments and refuses past `max_per_window`. The
//! window resets lazily on the next call after expiry — no separate sweep
//! task required. Per-address HashMap entries persist across the whole
//! process lifetime; under sustained novel-address flood the map grows until
//! eviction kicks in.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnetwork::IpNetwork;
use tracing::{error, info, warn};

use super::auth::session::now_epoch;
use super::config::ServerConfig;
use super::error::AppError;

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

/// Fixed-window length, in seconds, for the Trust Task listener limiter.
pub const TRUST_TASKS_WINDOW_SECS: u64 = 60;

/// Hard cap on tracked-address HashMap size. Once reached, addresses whose
/// window has ended are dropped; if that leaves more than
/// [`EVICTION_LOW_WATER`], the entire map is cleared in a single pass — drastic but the alternative is unbounded memory
/// growth under sustained novel-address flood. Operators who don't want this
/// behaviour should put the listener behind a CDN or deploy a real DDoS
/// mitigation.
pub const MAX_TRACKED_ADDRESSES: usize = 10_000;

/// Most addresses an eviction at [`MAX_TRACKED_ADDRESSES`] may keep. Leaving
/// a quarter of the map free means the next eviction scan waits for that
/// many new addresses, rather than running on every request of a flood that
/// keeps the map full of live addresses.
pub const EVICTION_LOW_WATER: usize = MAX_TRACKED_ADDRESSES * 3 / 4;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Number of consume attempts in the current window.
    count: u64,
    /// The epoch second of the window start.
    window_start: u64,
    /// Whether an attempt has been refused in the current window.
    refused: bool,
}

/// A refused [`IpRateLimiter::try_consume_reporting`] attempt.
#[derive(Debug)]
pub struct Refused {
    /// The refusal, an [`AppError::RateLimited`].
    pub error: AppError,
    /// Whether this is the address's first refusal in its window, so a
    /// caller can log once per window rather than once per request.
    pub first_in_window: bool,
}

/// Per-IP fixed-window rate limiter for an inbound listener, parameterised by
/// a stable `limiter` name (surfaced in the 429 body) and its own
/// `max_per_window` / `window_secs`.
#[derive(Debug)]
pub struct IpRateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    limiter: &'static str,
    max_per_window: u64,
    window_secs: u64,
}

impl IpRateLimiter {
    pub fn new(limiter: &'static str, max_per_window: u64, window_secs: u64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            limiter,
            max_per_window,
            window_secs,
        }
    }

    /// Attempt to consume one slot for `ip`. Returns `Err` once the address
    /// has made `max_per_window` attempts within the current `window_secs`
    /// window.
    pub fn try_consume(&self, ip: IpAddr, now: u64) -> Result<(), AppError> {
        self.try_consume_reporting(ip, now).map_err(|r| r.error)
    }

    /// [`Self::try_consume`], also reporting whether a refusal is the
    /// address's first in its window.
    pub fn try_consume_reporting(&self, ip: IpAddr, now: u64) -> Result<(), Refused> {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // At the cap, drop addresses whose window has ended; if too many are
        // still live, clear the map entirely. Documented in the module docs.
        if buckets.len() >= MAX_TRACKED_ADDRESSES {
            buckets.retain(|_, b| now.saturating_sub(b.window_start) < self.window_secs);
            if buckets.len() > EVICTION_LOW_WATER {
                buckets.clear();
            }
        }

        let entry = buckets.entry(ip).or_insert(Bucket {
            count: 0,
            window_start: now,
            refused: false,
        });

        // Reset on window boundary. Lazy — no sweep task.
        if now.saturating_sub(entry.window_start) >= self.window_secs {
            entry.count = 0;
            entry.window_start = now;
            entry.refused = false;
        }

        if entry.count >= self.max_per_window {
            // The window resets lazily at `window_start + window_secs`, so
            // the time left in it is exactly when the next attempt can
            // succeed.
            let retry_after_secs = (entry.window_start + self.window_secs).saturating_sub(now);
            let first_in_window = !entry.refused;
            entry.refused = true;
            return Err(Refused {
                error: AppError::RateLimited {
                    limiter: self.limiter,
                    message: format!(
                        "rate limit exceeded ({} requests per {}s); try again later",
                        self.max_per_window, self.window_secs
                    ),
                    retry_after_secs,
                },
                first_in_window,
            });
        }
        entry.count += 1;
        Ok(())
    }

    #[cfg(test)]
    pub fn count(&self, ip: IpAddr) -> u64 {
        let buckets = self.buckets.lock().unwrap();
        buckets.get(&ip).map(|b| b.count).unwrap_or(0)
    }
}

/// The `limiter` name of the per-address limit on public DID resolution.
pub const RESOLVE_RATE_LIMIT_NAME: &str = "resolve-per-address";

/// The per-client-address limit on public DID resolution
/// (`[server.resolve_rate_limit]`), shared by the edge server, the watcher and
/// the daemon. Does nothing when no limit is configured.
///
/// An IPv6 client is counted by its /64, the block one host is normally
/// given, so rotating addresses inside it does not escape the limit.
pub struct ResolveRateLimiter {
    limiter: Option<IpRateLimiter>,
    trusted_proxies: Vec<IpNetwork>,
}

impl ResolveRateLimiter {
    /// The limiter `server.resolve_rate_limit` describes, attributing
    /// requests through `server.trusted_proxies`. Warns when a limit is set
    /// with no trusted proxies: behind a load balancer every client would
    /// then share one budget.
    pub fn new(server: &ServerConfig) -> Self {
        let config = &server.resolve_rate_limit;
        let trusted_proxies = server.trusted_proxies.clone();
        if let Some(max) = config.max_per_window {
            if trusted_proxies.is_empty() {
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
        }
        Self {
            limiter: config
                .max_per_window
                .map(|max| IpRateLimiter::new(RESOLVE_RATE_LIMIT_NAME, max, config.window_secs)),
            trusted_proxies,
        }
    }

    /// A limiter that lets everything through.
    pub fn disabled() -> Self {
        Self {
            limiter: None,
            trusted_proxies: Vec::new(),
        }
    }

    /// Count `request` against its client address, or refuse it
    /// ([`AppError::RateLimited`]: `429` with `Retry-After`) once the address
    /// is over the limit.
    ///
    /// With a limit set, a request without a peer address (`ConnectInfo`) is
    /// refused (`500`) rather than let through: production serves with
    /// `into_make_service_with_connect_info`, so a missing peer is a wiring
    /// fault, and passing it would leave resolution unlimited.
    pub fn check(&self, request: &Request) -> Result<(), AppError> {
        let Some(limiter) = &self.limiter else {
            return Ok(());
        };
        let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() else {
            error!("resolution rate limit is on but the request has no peer address");
            return Err(AppError::Internal(
                "resolution rate limit: no peer address".into(),
            ));
        };
        let client = client_key(resolve_client_ip(
            peer.ip(),
            request.headers(),
            &self.trusted_proxies,
        ));
        limiter
            .try_consume_reporting(client, now_epoch())
            .map_err(|refused| {
                if refused.first_in_window {
                    warn!(%client, "client over the resolution rate limit; refusing it until its window ends");
                }
                refused.error
            })
    }
}

/// The address a client is counted under: an IPv4 address as is, an IPv6
/// address by its /64 (an IPv4-mapped one as its IPv4 address).
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        },
    }
}

/// Middleware applying a [`ResolveRateLimiter`] to the routes it wraps.
pub async fn limit_resolution(
    State(limiter): State<Arc<ResolveRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    if let Err(refusal) = limiter.check(&request) {
        return refusal.into_response();
    }
    next.run(request).await
}

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Upper bound on entries considered across all `X-Forwarded-For` headers.
/// A real chain is two or three hops; a longer one is a misconfiguration or
/// a probe, and falls back to the peer (fail-closed, not a truncation).
const MAX_FORWARDED_ENTRIES: usize = 64;

/// Resolve the client IP from the TCP peer and its `X-Forwarded-For` headers.
///
/// - `peer` not in `trusted_proxies` (always the case when it is empty) →
///   `peer`: the request isn't coming from a configured proxy, so its
///   header is untrusted.
/// - Otherwise walk every `X-Forwarded-For` entry (all header lines, in
///   order) right to left and return the first that is not itself a trusted
///   proxy.
/// - `peer` on any uncertainty: no header, a malformed or non-ASCII entry
///   reached before a client, more than [`MAX_FORWARDED_ENTRIES`] entries,
///   or a chain that is trusted the whole way down.
///
/// Entries may be `addr`, `addr:port`, `[v6]` or `[v6]:port`; IPv4-mapped
/// IPv6 addresses are unwrapped so they match IPv4 ranges.
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNetwork],
) -> IpAddr {
    let peer = peer.to_canonical();
    let trusted = |ip: IpAddr| trusted_proxies.iter().any(|net| net.contains(ip));
    if !trusted(peer) {
        return peer;
    }
    client_from_chain(headers, trusted).unwrap_or(peer)
}

/// The rightmost `X-Forwarded-For` entry that isn't a trusted proxy, or
/// `None` to fall back to the peer.
fn client_from_chain(headers: &HeaderMap, trusted: impl Fn(IpAddr) -> bool) -> Option<IpAddr> {
    // Multiple header lines concatenate in order, so collect before walking:
    // the rightmost entry of the last line is the newest hop.
    let mut entries: Vec<&str> = Vec::new();
    for value in headers.get_all(X_FORWARDED_FOR) {
        let value = value.to_str().ok()?;
        // Empty entries (a trailing comma) are dropped, not malformed: they
        // can only sit left of the entry the proxy appended.
        for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            if entries.len() == MAX_FORWARDED_ENTRIES {
                return None;
            }
            entries.push(entry);
        }
    }
    for entry in entries.iter().rev() {
        let ip = parse_forwarded_ip(entry)?;
        if !trusted(ip) {
            return Some(ip);
        }
    }
    None
}

/// One `X-Forwarded-For` entry: a bare address, `addr:port`, or
/// `[v6]` / `[v6]:port`, canonicalised.
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return Some(addr.ip().to_canonical());
    }
    let bracketed = entry.strip_prefix('[')?.strip_suffix(']')?;
    bracketed.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const LIMITER: &str = "test-limiter";
    const MAX_PER_WINDOW: u64 = 10;
    const WINDOW_SECS: u64 = 60;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn limiter() -> IpRateLimiter {
        IpRateLimiter::new(LIMITER, MAX_PER_WINDOW, WINDOW_SECS)
    }

    // --- IpRateLimiter ---

    #[test]
    fn allows_under_cap() {
        let l = limiter();
        let p = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(p, 1000).unwrap();
        }
        assert_eq!(l.count(p), MAX_PER_WINDOW);
    }

    /// The 11th request from one address, within the window, is refused.
    #[test]
    fn the_eleventh_request_from_one_address_is_refused() {
        let l = limiter();
        let p = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(p, 1000).unwrap();
        }
        let err = l.try_consume(p, 1000).unwrap_err();
        assert!(matches!(
            err,
            AppError::RateLimited {
                limiter: LIMITER,
                retry_after_secs: WINDOW_SECS,
                ..
            }
        ));
    }

    #[test]
    fn window_resets_after_expiry() {
        let l = limiter();
        let p = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(p, 1000).unwrap();
        }
        assert!(l.try_consume(p, 1000).is_err());
        l.try_consume(p, 1000 + WINDOW_SECS).unwrap();
        assert_eq!(l.count(p), 1);
    }

    #[test]
    fn distinct_ips_independent() {
        let l = limiter();
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(a, 1000).unwrap();
        }
        assert!(l.try_consume(a, 1000).is_err());
        l.try_consume(b, 1000).unwrap();
    }

    // --- resolve_client_ip ---

    fn nets(list: &[&str]) -> Vec<IpNetwork> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn xff(lines: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for l in lines {
            h.append("x-forwarded-for", l.parse().unwrap());
        }
        h
    }

    #[test]
    fn resolve_no_trusted_proxies_returns_peer() {
        let peer = ip("203.0.113.1");
        assert_eq!(resolve_client_ip(peer, &xff(&["198.51.100.1"]), &[]), peer);
    }

    #[test]
    fn resolve_trusted_peer_picks_xff_client() {
        let peer = ip("10.0.0.1");
        let trusted = nets(&["10.0.0.1"]);
        assert_eq!(
            resolve_client_ip(peer, &xff(&["198.51.100.1"]), &trusted),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn resolve_attacker_spoof_ignored() {
        let peer = ip("203.0.113.99");
        let trusted = nets(&["10.0.0.1"]);
        assert_eq!(
            resolve_client_ip(peer, &xff(&["198.51.100.5, 10.0.0.1"]), &trusted),
            peer
        );
    }

    /// A CIDR trusts every proxy in it, and a chain of them is skipped.
    #[test]
    fn resolve_trusted_range_skips_each_proxy_hop() {
        let peer = ip("10.20.3.4");
        let trusted = nets(&["10.20.0.0/16", "172.16.0.0/12"]);
        assert_eq!(
            resolve_client_ip(
                peer,
                &xff(&["1.1.1.1, 198.51.100.7, 172.16.9.9, 10.20.1.1"]),
                &trusted
            ),
            ip("198.51.100.7"),
            "the client the proxies appended, not what it wrote further left"
        );
        // A peer outside the range is not a proxy.
        assert_eq!(
            resolve_client_ip(ip("10.21.0.1"), &xff(&["198.51.100.7"]), &trusted),
            ip("10.21.0.1")
        );
    }

    /// Several header lines are one chain, in order.
    #[test]
    fn resolve_reads_every_header_line() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(
                ip("10.0.0.1"),
                &xff(&["1.1.1.1", "198.51.100.7, 10.0.0.2"]),
                &trusted
            ),
            ip("198.51.100.7")
        );
    }

    /// Ports, brackets and IPv4-mapped addresses all parse; the mapped peer
    /// matches an IPv4 range.
    #[test]
    fn resolve_accepts_forwarded_entry_forms() {
        let trusted = nets(&["10.0.0.0/8"]);
        let peer = ip("::ffff:10.0.0.1");
        for (entry, want) in [
            ("198.51.100.7:4711", "198.51.100.7"),
            ("[2001:db8::7]", "2001:db8::7"),
            ("[2001:db8::7]:443", "2001:db8::7"),
            ("::ffff:198.51.100.7", "198.51.100.7"),
        ] {
            assert_eq!(
                resolve_client_ip(peer, &xff(&[entry]), &trusted),
                ip(want),
                "{entry}"
            );
        }
    }

    /// Every uncertainty is the peer.
    #[test]
    fn resolve_falls_back_to_the_peer() {
        let peer = ip("10.0.0.1");
        let trusted = nets(&["10.0.0.0/8"]);
        // No header.
        assert_eq!(resolve_client_ip(peer, &HeaderMap::new(), &trusted), peer);
        // A malformed entry reached before any client.
        assert_eq!(
            resolve_client_ip(peer, &xff(&["198.51.100.7, not-an-ip"]), &trusted),
            peer
        );
        // Trusted end to end (the old rule returned the leftmost entry).
        assert_eq!(
            resolve_client_ip(peer, &xff(&["10.9.9.9, 10.0.0.2"]), &trusted),
            peer
        );
        // An absurdly long chain.
        let long = vec!["198.51.100.7"; MAX_FORWARDED_ENTRIES + 1].join(", ");
        assert_eq!(resolve_client_ip(peer, &xff(&[&long]), &trusted), peer);
        // A trailing comma is not malformed.
        assert_eq!(
            resolve_client_ip(peer, &xff(&["198.51.100.7,"]), &trusted),
            ip("198.51.100.7")
        );
    }

    fn resolve_limiter(
        max_per_window: Option<u64>,
        trusted_proxies: &[&str],
    ) -> ResolveRateLimiter {
        let mut server = ServerConfig::default();
        server.resolve_rate_limit.max_per_window = max_per_window;
        server.trusted_proxies = nets(trusted_proxies);
        ResolveRateLimiter::new(&server)
    }

    fn resolve_request(peer: &str, xff: Option<&str>) -> Request {
        let mut builder = Request::builder().uri("/alice/did.jsonl");
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut request = builder.body(axum::body::Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip(peer), 443)));
        request
    }

    /// Unset, the limit lets everything through, even a request with no
    /// peer address.
    #[test]
    fn resolve_limit_off_by_default() {
        let limiter = resolve_limiter(None, &[]);
        for _ in 0..1_000 {
            limiter.check(&resolve_request("10.0.0.1", None)).unwrap();
        }
        let bare = Request::builder().body(axum::body::Body::empty()).unwrap();
        limiter.check(&bare).unwrap();
    }

    /// Past the limit one address gets 429 with Retry-After; another address
    /// is unaffected.
    #[test]
    fn resolve_limit_refuses_one_address_past_the_limit() {
        let limiter = resolve_limiter(Some(3), &[]);
        for _ in 0..3 {
            limiter.check(&resolve_request("10.0.0.1", None)).unwrap();
        }
        let refusal = limiter
            .check(&resolve_request("10.0.0.1", None))
            .unwrap_err()
            .into_response();
        assert_eq!(refusal.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert!(
            refusal
                .headers()
                .contains_key(axum::http::header::RETRY_AFTER)
        );
        limiter.check(&resolve_request("10.0.0.2", None)).unwrap();
    }

    /// Behind a trusted proxy the limit follows the client in
    /// `X-Forwarded-For`, not the proxy; an untrusted peer's header is
    /// ignored.
    #[test]
    fn resolve_limit_keys_on_the_forwarded_client_behind_a_trusted_proxy() {
        let limiter = resolve_limiter(Some(1), &["10.0.0.9"]);
        limiter
            .check(&resolve_request("10.0.0.9", Some("203.0.113.1")))
            .unwrap();
        limiter
            .check(&resolve_request("10.0.0.9", Some("203.0.113.2")))
            .unwrap();
        assert!(
            limiter
                .check(&resolve_request("10.0.0.9", Some("203.0.113.1")))
                .is_err()
        );

        limiter
            .check(&resolve_request("198.51.100.7", Some("203.0.113.3")))
            .unwrap();
        assert!(
            limiter
                .check(&resolve_request("198.51.100.7", Some("203.0.113.4")))
                .is_err(),
            "an untrusted peer is limited on its own address"
        );
    }

    /// With a limit set, a request without a peer address is refused rather
    /// than let through unlimited.
    #[test]
    fn resolve_limit_refuses_a_request_without_a_peer_address() {
        let limiter = resolve_limiter(Some(100), &[]);
        let bare = Request::builder().body(axum::body::Body::empty()).unwrap();
        let refusal = limiter.check(&bare).unwrap_err().into_response();
        assert_eq!(
            refusal.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// An IPv6 client is counted by its /64, an IPv4-mapped one by its IPv4
    /// address.
    #[test]
    fn resolve_limit_counts_an_ipv6_client_by_its_64() {
        assert_eq!(client_key(ip("2001:db8:1:2:aaaa::1")), ip("2001:db8:1:2::"));
        assert_eq!(client_key(ip("::ffff:203.0.113.5")), ip("203.0.113.5"));
        assert_eq!(client_key(ip("203.0.113.5")), ip("203.0.113.5"));

        let limiter = resolve_limiter(Some(2), &[]);
        limiter
            .check(&resolve_request("2001:db8:1:2::1", None))
            .unwrap();
        limiter
            .check(&resolve_request("2001:db8:1:2::2", None))
            .unwrap();
        assert!(
            limiter
                .check(&resolve_request("2001:db8:1:2::3", None))
                .is_err()
        );
        limiter
            .check(&resolve_request("2001:db8:1:3::1", None))
            .unwrap();
    }

    /// Only the first refusal in an address's window is reported as first,
    /// so callers can log once per window.
    #[test]
    fn only_the_first_refusal_in_a_window_is_first() {
        let l = IpRateLimiter::new(LIMITER, 1, WINDOW_SECS);
        let p = ip("203.0.113.1");
        l.try_consume_reporting(p, 1000).unwrap();
        assert!(
            l.try_consume_reporting(p, 1000)
                .unwrap_err()
                .first_in_window
        );
        assert!(
            !l.try_consume_reporting(p, 1001)
                .unwrap_err()
                .first_in_window
        );
        l.try_consume_reporting(p, 1000 + WINDOW_SECS).unwrap();
        assert!(
            l.try_consume_reporting(p, 1000 + WINDOW_SECS)
                .unwrap_err()
                .first_in_window,
            "a new window reports again"
        );
    }

    /// At the address cap, addresses whose window has ended are dropped and
    /// live counts kept; the map is cleared only when too many are live.
    #[test]
    fn at_the_cap_expired_addresses_go_first() {
        let l = IpRateLimiter::new(LIMITER, 1, WINDOW_SECS);
        let live = ip("203.0.113.1");
        l.try_consume(live, 2000).unwrap();
        for i in 0..(MAX_TRACKED_ADDRESSES - 1) as u32 {
            l.try_consume(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), 1000)
                .unwrap();
        }
        l.try_consume(ip("198.51.100.1"), 2000).unwrap();
        assert!(
            l.try_consume(live, 2000).is_err(),
            "the live address keeps its count"
        );
    }

    /// A flood that keeps the map full of live addresses clears it, so the
    /// next eviction waits for the map to refill rather than scanning on
    /// every request.
    #[test]
    fn at_the_cap_mostly_live_addresses_clear_the_map() {
        let l = IpRateLimiter::new(LIMITER, 1, WINDOW_SECS);
        for i in 0..MAX_TRACKED_ADDRESSES as u32 {
            l.try_consume(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), 1000)
                .unwrap();
        }
        l.try_consume(ip("198.51.100.1"), 1000).unwrap();
        assert_eq!(l.buckets.lock().unwrap().len(), 1);
    }
}

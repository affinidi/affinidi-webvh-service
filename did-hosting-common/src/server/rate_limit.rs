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
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use axum::http::{HeaderMap, HeaderName};
use ipnetwork::IpNetwork;

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

/// Hard cap on tracked-address HashMap size. Once exceeded, the entire map is
/// cleared in a single pass — drastic but the alternative is unbounded memory
/// growth under sustained novel-address flood. Operators who don't want this
/// behaviour should put the listener behind a CDN or deploy a real DDoS
/// mitigation.
pub const MAX_TRACKED_ADDRESSES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Number of consume attempts in the current window.
    count: u64,
    /// The epoch second of the window start.
    window_start: u64,
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
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Drastic eviction: if the map has grown past the cap, clear it
        // entirely. Documented in the module docs.
        if buckets.len() >= MAX_TRACKED_ADDRESSES {
            buckets.clear();
        }

        let entry = buckets.entry(ip).or_insert(Bucket {
            count: 0,
            window_start: now,
        });

        // Reset on window boundary. Lazy — no sweep task.
        if now.saturating_sub(entry.window_start) >= self.window_secs {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= self.max_per_window {
            // The window resets lazily at `window_start + window_secs`, so
            // the time left in it is exactly when the next attempt can
            // succeed.
            let retry_after_secs = (entry.window_start + self.window_secs).saturating_sub(now);
            return Err(AppError::RateLimited {
                limiter: self.limiter,
                message: format!(
                    "rate limit exceeded ({} requests per {}s); try again later",
                    self.max_per_window, self.window_secs
                ),
                retry_after_secs,
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
}

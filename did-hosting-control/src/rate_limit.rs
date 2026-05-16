//! Per-IP rate limiter for unauthenticated endpoints.
//!
//! `POST /api/auth/challenge` is the only unauthenticated request-shape
//! exposed by the control plane (everything else requires Bearer
//! token, ACL membership, or signed DIDComm). The per-DID and global
//! `PendingChallengeTracker` caps already bound the total session
//! population; this module adds the matching defence at the network
//! layer — an attacker burning through DIDs from a single IP shouldn't
//! be able to issue thousands of challenges per second even though
//! each individual challenge fits within the per-DID/global counters'
//! steady state.
//!
//! # IP-attribution policy
//!
//! Behind a reverse proxy / load balancer / CDN, the TCP peer is the
//! proxy itself, not the real client — every legitimate request would
//! attribute to one IP. The `trusted_proxies` config opts in to
//! parsing `X-Forwarded-For`:
//!
//! - Empty `trusted_proxies` (default): always use the direct TCP peer.
//!   Safe when running on the open internet without a proxy.
//! - Non-empty `trusted_proxies`: walk `X-Forwarded-For` from the
//!   right, skip any entry that's in `trusted_proxies`, and use the
//!   first non-trusted entry as the client IP. If every XFF entry is
//!   trusted (shouldn't happen in practice — there's always a public
//!   client at the head), fall back to the leftmost.
//!
//! Configuring `trusted_proxies` with the wrong value is a foot-gun:
//! trust too much and an attacker can spoof XFF to bypass the limit;
//! trust too little and legitimate proxied requests all hit one
//! limit. Operators should put their actual reverse-proxy IPs there
//! and nothing else.
//!
//! # Algorithm
//!
//! Per-IP fixed-window counter, refreshed every `WINDOW_SECS`. Each
//! `try_consume(ip)` increments and refuses past `MAX_PER_WINDOW`. The
//! window resets lazily on the next call after expiry — no separate
//! sweep task required. Per-IP HashMap entries persist across the
//! whole process lifetime; under sustained novel-IP flood the map
//! grows until eviction kicks in.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use crate::error::AppError;

/// Maximum challenges per IP per window before rejection. Sized to be
/// generous for legitimate users (a typical browser flow does <10
/// challenge requests in a minute) while bounding an attacker's
/// effective throughput by orders of magnitude.
pub const MAX_PER_WINDOW: u64 = 30;

/// Fixed-window length in seconds. 60s gives the counter a 1 minute
/// reset; combined with `MAX_PER_WINDOW = 30` that's ~0.5 challenges
/// per second steady-state per IP.
pub const WINDOW_SECS: u64 = 60;

/// Hard cap on tracked-IP HashMap size. Once exceeded, the entire
/// map is cleared in a single pass — drastic but the alternative is
/// unbounded memory growth under sustained novel-IP flood. Operators
/// who don't want this behaviour should put the control plane behind
/// a CDN or deploy a real DDoS mitigation.
pub const MAX_TRACKED_IPS: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Number of consume attempts in the current window.
    count: u64,
    /// `now_epoch()` of the window start.
    window_start: u64,
}

/// Per-IP rate limiter for the challenge endpoint.
#[derive(Debug, Default)]
pub struct IpRateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl IpRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempt to consume one slot for `ip`. Returns `Err` once the
    /// IP has issued `MAX_PER_WINDOW` challenges within the current
    /// `WINDOW_SECS` window.
    pub fn try_consume(&self, ip: IpAddr, now: u64) -> Result<(), AppError> {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Drastic eviction: if the map has grown past the cap, clear
        // it entirely. Documented in the module doc.
        if buckets.len() >= MAX_TRACKED_IPS {
            buckets.clear();
        }

        let entry = buckets.entry(ip).or_insert(Bucket {
            count: 0,
            window_start: now,
        });

        // Reset on window boundary. Lazy — no sweep task.
        if now.saturating_sub(entry.window_start) >= WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= MAX_PER_WINDOW {
            return Err(AppError::Validation(format!(
                "IP rate limit exceeded ({MAX_PER_WINDOW} requests per {WINDOW_SECS}s); try again later",
            )));
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

/// Resolve the client IP from a TCP peer + `X-Forwarded-For` header.
///
/// Behaviour:
/// - `trusted_proxies` empty → always return `peer`.
/// - `peer` not in `trusted_proxies` → return `peer` (the request
///   isn't coming from a configured proxy, so XFF is untrusted).
/// - `peer` in `trusted_proxies` and `xff` provided → walk the XFF
///   list right-to-left, skipping any IP that's also in
///   `trusted_proxies`, and return the first non-trusted entry. If
///   every entry is trusted, return the leftmost (best-effort).
/// - `peer` in `trusted_proxies` but no XFF → return `peer`.
///
/// Malformed XFF entries are silently skipped; if all entries fail to
/// parse, return `peer`.
pub fn resolve_client_ip(peer: IpAddr, xff: Option<&str>, trusted_proxies: &[String]) -> IpAddr {
    if trusted_proxies.is_empty() {
        return peer;
    }

    let trusted: Vec<IpAddr> = trusted_proxies
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    if !trusted.contains(&peer) {
        return peer;
    }

    let Some(xff) = xff else {
        return peer;
    };

    // Parse all XFF entries (left-to-right) into IpAddrs, skipping
    // unparseable ones. Empty-after-filter falls through to peer.
    let parsed: Vec<IpAddr> = xff
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();

    if parsed.is_empty() {
        return peer;
    }

    // Walk right-to-left, returning the first non-trusted IP.
    for candidate in parsed.iter().rev() {
        if !trusted.contains(candidate) {
            return *candidate;
        }
    }

    // Every entry is trusted — fall back to the leftmost (the
    // documented "original client" position).
    parsed[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // --- IpRateLimiter ---

    #[test]
    fn allows_under_cap() {
        let l = IpRateLimiter::new();
        let p = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(p, 1000).unwrap();
        }
        assert_eq!(l.count(p), MAX_PER_WINDOW);
    }

    #[test]
    fn rejects_over_cap() {
        let l = IpRateLimiter::new();
        let p = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(p, 1000).unwrap();
        }
        let err = l.try_consume(p, 1000).unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("rate limit")));
    }

    /// Window rolls over: after `WINDOW_SECS` elapsed, a fresh round
    /// of `MAX_PER_WINDOW` requests is allowed. Pinning this catches
    /// a regression where the lazy-reset is moved from
    /// `try_consume` to a sweep task that doesn't run in tests.
    #[test]
    fn window_resets_after_expiry() {
        let l = IpRateLimiter::new();
        let p = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // Fill the first window.
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(p, 1000).unwrap();
        }
        // Inside the window — rejected.
        assert!(l.try_consume(p, 1000).is_err());
        // After WINDOW_SECS — accepted.
        l.try_consume(p, 1000 + WINDOW_SECS).unwrap();
        assert_eq!(l.count(p), 1);
    }

    /// Distinct IPs share no state — one IP being rate-limited
    /// doesn't affect another.
    #[test]
    fn distinct_ips_independent() {
        let l = IpRateLimiter::new();
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(a, 1000).unwrap();
        }
        // a is full, b is fresh.
        assert!(l.try_consume(a, 1000).is_err());
        l.try_consume(b, 1000).unwrap();
    }

    // --- resolve_client_ip ---

    #[test]
    fn resolve_no_trusted_proxies_returns_peer() {
        let peer = ip("203.0.113.1");
        // Even with XFF set, with no trusted_proxies the header is ignored.
        assert_eq!(resolve_client_ip(peer, Some("198.51.100.1"), &[]), peer);
    }

    #[test]
    fn resolve_peer_not_in_trusted_returns_peer() {
        let peer = ip("203.0.113.1");
        let trusted = vec!["10.0.0.1".to_string()];
        assert_eq!(
            resolve_client_ip(peer, Some("198.51.100.1"), &trusted),
            peer
        );
    }

    #[test]
    fn resolve_trusted_peer_picks_xff_client() {
        let peer = ip("10.0.0.1");
        let trusted = vec!["10.0.0.1".to_string()];
        // Single client, single trusted proxy.
        assert_eq!(
            resolve_client_ip(peer, Some("198.51.100.1"), &trusted),
            ip("198.51.100.1")
        );
    }

    /// Walk past the trusted-proxy chain to find the original client.
    /// `XFF: client, proxy1, proxy2` → the rightmost entry is the
    /// closest proxy. With proxy1 and proxy2 both trusted, the
    /// original client is the leftmost.
    #[test]
    fn resolve_walks_past_trusted_chain() {
        let peer = ip("10.0.0.2");
        let trusted = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
        assert_eq!(
            resolve_client_ip(peer, Some("198.51.100.1, 10.0.0.1, 10.0.0.2"), &trusted,),
            ip("198.51.100.1")
        );
    }

    /// XFF spoofing: an attacker whose request actually originates
    /// from a non-trusted host injects fake XFF entries trying to
    /// impersonate another IP. With the actual peer not in trusted,
    /// XFF is ignored entirely.
    #[test]
    fn resolve_attacker_spoof_ignored() {
        let peer = ip("203.0.113.99"); // attacker's real IP
        let trusted = vec!["10.0.0.1".to_string()];
        // Attacker tries to claim they came through a trusted proxy.
        assert_eq!(
            resolve_client_ip(peer, Some("198.51.100.5, 10.0.0.1"), &trusted,),
            peer
        );
    }

    #[test]
    fn resolve_malformed_xff_falls_back_to_peer() {
        let peer = ip("10.0.0.1");
        let trusted = vec!["10.0.0.1".to_string()];
        assert_eq!(resolve_client_ip(peer, Some("not-an-ip"), &trusted), peer);
    }

    #[test]
    fn resolve_no_xff_returns_peer() {
        let peer = ip("10.0.0.1");
        let trusted = vec!["10.0.0.1".to_string()];
        assert_eq!(resolve_client_ip(peer, None, &trusted), peer);
    }
}

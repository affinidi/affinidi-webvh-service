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
//! - Non-empty `trusted_proxies`: walk `X-Forwarded-For` from the right, skip
//!   any entry that's in `trusted_proxies`, and use the first non-trusted
//!   entry as the client IP. If every XFF entry is trusted (shouldn't happen
//!   in practice — there's always a public client at the head), fall back to
//!   the leftmost.
//!
//! Configuring `trusted_proxies` with the wrong value is a foot-gun: trust too
//! much and an attacker can spoof XFF to bypass the limit; trust too little
//! and legitimate proxied requests all hit one limit. Operators should put
//! their actual reverse-proxy IPs there and nothing else.
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
use std::net::IpAddr;
use std::sync::Mutex;

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

/// Resolve the client IP from a TCP peer + `X-Forwarded-For` header.
///
/// Behaviour:
/// - `trusted_proxies` empty → always return `peer`.
/// - `peer` not in `trusted_proxies` → return `peer` (the request isn't
///   coming from a configured proxy, so XFF is untrusted).
/// - `peer` in `trusted_proxies` and `xff` provided → walk the XFF list
///   right-to-left, skipping any IP that's also in `trusted_proxies`, and
///   return the first non-trusted entry. If every entry is trusted, return
///   the leftmost (best-effort).
/// - `peer` in `trusted_proxies` but no XFF → return `peer`.
///
/// Malformed XFF entries are silently skipped; if all entries fail to parse,
/// return `peer`.
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

    // Every entry is trusted — fall back to the leftmost (the documented
    // "original client" position).
    parsed[0]
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

    #[test]
    fn resolve_no_trusted_proxies_returns_peer() {
        let peer = ip("203.0.113.1");
        assert_eq!(resolve_client_ip(peer, Some("198.51.100.1"), &[]), peer);
    }

    #[test]
    fn resolve_trusted_peer_picks_xff_client() {
        let peer = ip("10.0.0.1");
        let trusted = vec!["10.0.0.1".to_string()];
        assert_eq!(
            resolve_client_ip(peer, Some("198.51.100.1"), &trusted),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn resolve_attacker_spoof_ignored() {
        let peer = ip("203.0.113.99");
        let trusted = vec!["10.0.0.1".to_string()];
        assert_eq!(
            resolve_client_ip(peer, Some("198.51.100.5, 10.0.0.1"), &trusted),
            peer
        );
    }
}

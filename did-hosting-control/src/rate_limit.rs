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
//! - Non-empty `trusted_proxies` (addresses or CIDR ranges): walk
//!   `X-Forwarded-For` from the right, skip each trusted proxy, and use
//!   the first entry that isn't one; on any doubt, the TCP peer.
//!
//! The rule is shared with every other service —
//! [`did_hosting_common::server::rate_limit::resolve_client_ip`], re-exported
//! here — and documented there, foot-guns included.
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

/// The `limiter` this refusal names in its 429 body.
pub const LIMITER_NAME: &str = "auth-challenge-per-ip";

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
            // The window resets lazily at `window_start + WINDOW_SECS`, so the
            // time left in it is exactly when the next attempt can succeed.
            let retry_after_secs = (entry.window_start + WINDOW_SECS).saturating_sub(now);
            return Err(AppError::RateLimited {
                limiter: LIMITER_NAME,
                message: format!(
                    "IP rate limit exceeded ({MAX_PER_WINDOW} requests per {WINDOW_SECS}s); try again later",
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

/// Redemption attempts one source may make per [`WINDOW_SECS`]: an invite's
/// claim code is Argon2-hashed on every attempt, so this bounds both guessing
/// across invites and the hashing a single source can make the service do.
pub const REDEEM_MAX_PER_WINDOW: u64 = 10;

/// The `limiter` a refused redemption names.
pub const REDEEM_LIMITER_NAME: &str = "passkey-redeem-per-source";

/// Per-source limiter for `auth/passkey/enroll/redeem/start`
/// (Conformance item 2: "Rate-limit this task per source as well").
///
/// A source is what the transport can vouch for: the client IP on HTTPS
/// (`ip:…`), the authenticated sender on TSP and DIDComm (`vid:…`). The
/// per-invite wrong-code limit is the real guard on a claim code (and, unlike
/// this limiter, holds across replicas — its counter lives in the shared
/// store behind an atomic increment; see
/// `did_hosting_common::server::passkey::invite`). This one keeps a single
/// source from spraying invites or burning CPU.
///
/// **Per-process, by design.** Unlike the wrong-code counter, this limiter's
/// buckets are an in-memory `HashMap` — nothing here is shared across
/// replicas. A source spread across N replicas behind a load balancer gets
/// effectively `N * REDEEM_MAX_PER_WINDOW` attempts per window, not
/// `REDEEM_MAX_PER_WINDOW`. That's an accepted tradeoff: this limiter sheds
/// load and guessing pressure, it isn't the security boundary (the per-invite
/// wrong-code lockout is), so making it cross-replica would trade a store
/// round trip on every redemption attempt for a guarantee this limiter
/// doesn't need to make.
#[derive(Debug, Default)]
pub struct SourceRateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl SourceRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume one attempt for `source`, or refuse once it has made
    /// [`REDEEM_MAX_PER_WINDOW`] in the current window.
    pub fn try_consume(&self, source: &str, now: u64) -> Result<(), AppError> {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if buckets.len() >= MAX_TRACKED_IPS {
            buckets.clear();
        }
        let entry = buckets.entry(source.to_string()).or_insert(Bucket {
            count: 0,
            window_start: now,
        });
        if now.saturating_sub(entry.window_start) >= WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }
        if entry.count >= REDEEM_MAX_PER_WINDOW {
            return Err(AppError::RateLimited {
                limiter: REDEEM_LIMITER_NAME,
                message: format!(
                    "too many invite redemptions ({REDEEM_MAX_PER_WINDOW} per {WINDOW_SECS}s); try again later"
                ),
                retry_after_secs: (entry.window_start + WINDOW_SECS).saturating_sub(now),
            });
        }
        entry.count += 1;
        Ok(())
    }
}

/// Resolve the client IP from the TCP peer and `X-Forwarded-For` — the one
/// shared rule every service applies; see its docs.
pub use did_hosting_common::server::rate_limit::resolve_client_ip;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
        assert!(matches!(
            err,
            AppError::RateLimited {
                limiter: LIMITER_NAME,
                retry_after_secs: WINDOW_SECS,
                ..
            }
        ));
    }

    /// The retry hint is the time left in the current window, not the whole
    /// window: a refusal 45s into a 60s window says 15.
    #[test]
    fn retry_after_is_the_remainder_of_the_window() {
        let l = IpRateLimiter::new();
        let p = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..MAX_PER_WINDOW {
            l.try_consume(p, 1000).unwrap();
        }
        let err = l.try_consume(p, 1045).unwrap_err();
        assert!(matches!(
            err,
            AppError::RateLimited {
                retry_after_secs: 15,
                ..
            }
        ));
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
}

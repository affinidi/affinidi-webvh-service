//! The control plane's own rate limits: per client address on
//! `POST /api/auth/challenge`, and per source on invite redemption.
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
//! Both are [`KeyedRateLimiter`]s: token buckets stated as requests per
//! window, with the client-address rule
//! ([`did_hosting_common::server::rate_limit::resolve_client_ip`], re-exported
//! here) and its foot-guns documented in that module.

use std::net::IpAddr;

use did_hosting_common::server::rate_limit::KeyedRateLimiter;
use tokio_util::sync::CancellationToken;

use crate::error::AppError;

/// Challenges per IP per window before rejection. Sized to be generous for
/// legitimate users (a typical browser flow does <10 challenge requests in a
/// minute) while bounding an attacker's effective throughput by orders of
/// magnitude.
pub const MAX_PER_WINDOW: u64 = 30;

/// Window length in seconds: with [`MAX_PER_WINDOW`], one challenge every
/// two seconds per IP once the allowance is spent.
pub const WINDOW_SECS: u64 = 60;

/// The `limiter` this refusal names in its 429 body.
pub const LIMITER_NAME: &str = "auth-challenge-per-ip";

/// Per-IP rate limiter for the challenge endpoint.
#[derive(Debug)]
pub struct IpRateLimiter(KeyedRateLimiter<IpAddr>);

impl Default for IpRateLimiter {
    fn default() -> Self {
        Self(KeyedRateLimiter::new(
            LIMITER_NAME,
            MAX_PER_WINDOW,
            WINDOW_SECS,
        ))
    }
}

impl IpRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge one challenge to `ip`, or refuse once it has spent its
    /// [`MAX_PER_WINDOW`].
    pub fn try_consume(&self, ip: IpAddr) -> Result<(), AppError> {
        self.0.try_consume(ip)
    }

    /// Whether a refusal of `ip` is its first in its window, so the caller
    /// logs once per window.
    pub fn first_refusal_in_window(&self, ip: &IpAddr) -> bool {
        self.0.first_refusal_in_window(ip)
    }

    /// Sweep idle clients out of memory until `shutdown` fires.
    pub fn spawn_gc(&self, shutdown: CancellationToken) {
        self.0.spawn_gc(shutdown);
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
/// **Per-process, by design.** This limiter's buckets are in memory, not
/// shared across replicas. A source spread across N replicas behind a load
/// balancer gets effectively `N * REDEEM_MAX_PER_WINDOW` attempts per window,
/// not `REDEEM_MAX_PER_WINDOW`. That's an accepted tradeoff: this limiter
/// sheds load and guessing pressure, it isn't the security boundary (the
/// per-invite wrong-code lockout is), so making it cross-replica would trade a
/// store round trip on every redemption attempt for a guarantee this limiter
/// doesn't need to make.
#[derive(Debug)]
pub struct SourceRateLimiter(KeyedRateLimiter<String>);

impl Default for SourceRateLimiter {
    fn default() -> Self {
        Self(KeyedRateLimiter::new(
            REDEEM_LIMITER_NAME,
            REDEEM_MAX_PER_WINDOW,
            WINDOW_SECS,
        ))
    }
}

impl SourceRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume one attempt for `source`, or refuse once it has spent its
    /// [`REDEEM_MAX_PER_WINDOW`].
    pub fn try_consume(&self, source: &str) -> Result<(), AppError> {
        self.0.try_consume(source.to_owned())
    }

    /// Whether a refusal of `source` is its first in its window, so the
    /// caller logs once per window.
    pub fn first_refusal_in_window(&self, source: &str) -> bool {
        self.0.first_refusal_in_window(&source.to_owned())
    }

    /// Sweep idle sources out of memory until `shutdown` fires.
    pub fn spawn_gc(&self, shutdown: CancellationToken) {
        self.0.spawn_gc(shutdown);
    }
}

/// Resolve the client IP from the TCP peer and `X-Forwarded-For` — the one
/// shared rule every service applies; see its docs.
pub use did_hosting_common::server::rate_limit::resolve_client_ip;

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The challenge limit is the documented allowance, refused with its own
    /// name, and per address.
    #[test]
    fn the_challenge_limit_refuses_past_its_allowance_by_name() {
        let limiter = IpRateLimiter::new();
        let client = ip("203.0.113.1");
        for _ in 0..MAX_PER_WINDOW {
            limiter.try_consume(client).unwrap();
        }
        assert!(matches!(
            limiter.try_consume(client),
            Err(AppError::RateLimited {
                limiter: LIMITER_NAME,
                ..
            })
        ));
        limiter.try_consume(ip("203.0.113.2")).unwrap();
    }

    /// Redemption is limited per source, whichever transport vouched for it.
    #[test]
    fn redemption_is_limited_per_source() {
        let limiter = SourceRateLimiter::new();
        for _ in 0..REDEEM_MAX_PER_WINDOW {
            limiter.try_consume("ip:203.0.113.1").unwrap();
        }
        assert!(matches!(
            limiter.try_consume("ip:203.0.113.1"),
            Err(AppError::RateLimited {
                limiter: REDEEM_LIMITER_NAME,
                ..
            })
        ));
        limiter.try_consume("vid:did:example:alice").unwrap();
    }
}

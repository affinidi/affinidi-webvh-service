//! The control plane's own rate limits: per client address on
//! `POST /api/auth/challenge`, and per source on opening a passkey login and
//! on invite redemption.
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
//! Both are plain [`KeyedRateLimiter`]s from the common module — token
//! buckets stated as requests per window, which log a client's first refusal
//! in each window — built by [`challenge_limiter`] and [`redeem_limiter`].
//! Client addresses come from the service's
//! [`ClientIps`](did_hosting_common::server::rate_limit::ClientIps), whose
//! rule and foot-guns are documented in that module.

use did_hosting_common::server::rate_limit::{IpRateLimiter, KeyedRateLimiter};

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

/// The per-IP limiter for `POST /api/auth/challenge`.
pub fn challenge_limiter() -> IpRateLimiter {
    IpRateLimiter::new(LIMITER_NAME, MAX_PER_WINDOW, WINDOW_SECS)
}

/// Redemption attempts one source may make per [`WINDOW_SECS`]: an invite's
/// claim code is Argon2-hashed on every attempt, so this bounds both guessing
/// across invites and the hashing a single source can make the service do.
pub const REDEEM_MAX_PER_WINDOW: u64 = 10;

/// The `limiter` a refused redemption names.
pub const REDEEM_LIMITER_NAME: &str = "passkey-redeem-per-source";

/// The per-source limiter for `auth/passkey/enroll/redeem/start`
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
pub fn redeem_limiter() -> KeyedRateLimiter<String> {
    KeyedRateLimiter::new(REDEEM_LIMITER_NAME, REDEEM_MAX_PER_WINDOW, WINDOW_SECS)
}

/// Passkey login ceremonies one source may open per [`WINDOW_SECS`]. Opening
/// one is unauthenticated and stores a row until it is finished or swept, so
/// this bounds how many a single source can leave behind; a person signing in
/// opens one per attempt.
pub const LOGIN_START_MAX_PER_WINDOW: u64 = 30;

/// The `limiter` a refused login start names.
pub const LOGIN_START_LIMITER_NAME: &str = "passkey-login-start-per-source";

/// The per-source limiter for `auth/passkey/login/start` (the task declares
/// `rateLimited` for "the issuer's login-start budget"). A source is what the
/// transport vouches for, as for [`redeem_limiter`]: the client IP on HTTPS
/// (`ip:…`), the authenticated sender on TSP and DIDComm (`vid:…`).
/// Per-process, for the reason [`redeem_limiter`] gives.
pub fn login_start_limiter() -> KeyedRateLimiter<String> {
    KeyedRateLimiter::new(
        LOGIN_START_LIMITER_NAME,
        LOGIN_START_MAX_PER_WINDOW,
        WINDOW_SECS,
    )
}

/// Self-registration attempts one source may make per [`WINDOW_SECS`].
///
/// A `did:webs` outside the ACL that registers itself makes the service
/// verify the key event log it submits — every event's SAID, signature and
/// pre-rotation commitment — before anything proves who sent it, which is
/// work a stranger can ask for. A node registers its identifier once, and
/// again only to retry; this bounds what a single source can make the
/// service verify.
pub const WEBS_SELF_REGISTER_MAX_PER_WINDOW: u64 = 10;

/// The `limiter` a refused self-registration names.
pub const WEBS_SELF_REGISTER_LIMITER_NAME: &str = "webs-self-register-per-source";

/// The per-source limiter for `did:webs` self-registration
/// (`crate::webs_self_register`). A source is what the transport vouches
/// for, as for [`redeem_limiter`]: the client IP on HTTPS (`ip:…`), the
/// authenticated sender on TSP and DIDComm (`vid:…`). Per-process, for the
/// reason [`redeem_limiter`] gives.
pub fn webs_self_register_limiter() -> KeyedRateLimiter<String> {
    KeyedRateLimiter::new(
        WEBS_SELF_REGISTER_LIMITER_NAME,
        WEBS_SELF_REGISTER_MAX_PER_WINDOW,
        WINDOW_SECS,
    )
}

/// Self-registration attempts every source together may make per
/// [`WINDOW_SECS`]. The per-source limit cannot bound the whole on TSP and
/// DIDComm, where a source is its sender and a sender can mint a new
/// `did:key` for each attempt; this bucket does, at a rate no deployment's
/// own first boots come near.
pub const WEBS_SELF_REGISTER_GLOBAL_MAX_PER_WINDOW: u64 = 30;

/// The `limiter` a self-registration refused by the shared bucket names.
pub const WEBS_SELF_REGISTER_GLOBAL_LIMITER_NAME: &str = "webs-self-register-global";

/// The one key of [`webs_self_register_global_limiter`].
pub const WEBS_SELF_REGISTER_GLOBAL_KEY: &str = "all";

/// The limiter every `did:webs` self-registration shares, whatever its
/// source, keyed on [`WEBS_SELF_REGISTER_GLOBAL_KEY`]. Per-process, for the
/// reason [`redeem_limiter`] gives.
pub fn webs_self_register_global_limiter() -> KeyedRateLimiter<String> {
    KeyedRateLimiter::new(
        WEBS_SELF_REGISTER_GLOBAL_LIMITER_NAME,
        WEBS_SELF_REGISTER_GLOBAL_MAX_PER_WINDOW,
        WINDOW_SECS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The challenge limit is the documented allowance, refused with its own
    /// name, and per address.
    #[test]
    fn the_challenge_limit_refuses_past_its_allowance_by_name() {
        let limiter = challenge_limiter();
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

    /// Self-registration shares one bucket across every source, so senders
    /// minted fresh for each attempt are bounded together.
    #[test]
    fn self_registration_shares_one_bucket_across_sources() {
        let limiter = webs_self_register_global_limiter();
        for _ in 0..WEBS_SELF_REGISTER_GLOBAL_MAX_PER_WINDOW {
            limiter
                .try_consume(WEBS_SELF_REGISTER_GLOBAL_KEY.into())
                .unwrap();
        }
        assert!(matches!(
            limiter.try_consume(WEBS_SELF_REGISTER_GLOBAL_KEY.into()),
            Err(AppError::RateLimited {
                limiter: WEBS_SELF_REGISTER_GLOBAL_LIMITER_NAME,
                ..
            })
        ));
    }

    /// Redemption is limited per source, whichever transport vouched for it.
    #[test]
    fn redemption_is_limited_per_source() {
        let limiter = redeem_limiter();
        for _ in 0..REDEEM_MAX_PER_WINDOW {
            limiter.try_consume("ip:203.0.113.1".into()).unwrap();
        }
        assert!(matches!(
            limiter.try_consume("ip:203.0.113.1".into()),
            Err(AppError::RateLimited {
                limiter: REDEEM_LIMITER_NAME,
                ..
            })
        ));
        limiter.try_consume("vid:did:example:alice".into()).unwrap();
    }
}

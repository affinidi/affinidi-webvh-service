//! `[auth]`: token lifetimes, session and challenge bounds.

use crate::server::error::AppError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry: u64,
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry: u64,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl: u64,
    #[serde(default = "default_session_cleanup_interval")]
    pub session_cleanup_interval: u64,
    /// How long an admin session may go without user activity before it may
    /// no longer be renewed, in seconds.
    ///
    /// Distinct from [`Self::access_token_expiry`], which is how often a live
    /// session rotates its token. The console renews on a timer, so if the
    /// two were the same clock a tab left open would hold its session for as
    /// long as the browser ran. This is the value that decides when an
    /// operator who walked away is signed out; it is measured against
    /// `Session::last_seen`, which only real requests advance.
    #[serde(default = "default_admin_idle_timeout")]
    pub admin_idle_timeout: u64,
    #[serde(default = "default_passkey_enrollment_ttl")]
    pub passkey_enrollment_ttl: u64,
    /// How long a passkey invite's claim-code check may wait for a free
    /// hashing slot, in milliseconds, before it is refused as `unavailable`
    /// with a retry time. The checks share a small fixed number of slots
    /// because each takes a large, fixed amount of memory; this bounds how
    /// long a burst of redemption attempts can hold the others up.
    #[serde(default = "default_claim_code_hash_wait_ms")]
    pub claim_code_hash_wait_ms: u64,
    /// How long (in minutes) to keep empty DID records before auto-cleanup.
    #[serde(default = "default_cleanup_ttl_minutes")]
    pub cleanup_ttl_minutes: u64,
    /// Global cap on concurrently-live pending auth challenges across all DIDs
    /// (did-hosting-control's in-memory `PendingChallengeTracker`).
    /// Defence-in-depth bound on the unauthenticated
    /// `POST /api/auth/challenge` surface: an attacker sweeping many distinct
    /// DIDs cannot accumulate more than this many live challenges before
    /// issuance fails closed. Mirrors
    /// `did_hosting_control::pending_challenges::MAX_GLOBAL_PENDING`, the
    /// compiled-in default; the two are pinned equal by a unit test in that
    /// crate. Operators on unusually large or small deployments can tune it.
    #[serde(default = "default_max_global_pending_challenges")]
    pub max_global_pending_challenges: usize,
    /// Per-DID cap on concurrently-live pending auth challenges (the sibling
    /// of `max_global_pending_challenges`). Bounds a single-DID flood. Mirrors
    /// `did_hosting_control::routes::auth::MAX_PENDING_CHALLENGES_PER_DID`, the
    /// compiled-in default; also pinned equal by a unit test in that crate.
    #[serde(default = "default_max_pending_challenges_per_did")]
    pub max_pending_challenges_per_did: usize,
    /// The absolute ceiling on a session's life, in seconds from
    /// authentication (`auth/authenticate/0.3`'s `Session.issuedAt`).
    /// No `auth/refresh/0.2` may advance `Session.expiresAt` — nor, in this
    /// implementation, the underlying refresh-token deadline — past
    /// `issuedAt + absolute_session_lifetime`; a session that has already
    /// reached it refuses refresh outright
    /// (`auth/refresh:sessionLifetimeExceeded`) rather than silently
    /// returning a token with a shrunk window. This is the backstop for a
    /// refresh token (and, where bound, a session key) that stays quietly
    /// compromised: however long undetected, neither can keep a session
    /// alive past this instant — only a fresh `auth/authenticate` can.
    #[serde(default = "default_absolute_session_lifetime")]
    pub absolute_session_lifetime: u64,
}

/// 15 minutes of inactivity.
///
/// Longer than the 900s access-token lifetime it sits beside, deliberately:
/// before this existed an admin was signed out 15 minutes after logging in
/// whether or not they were working, because nothing renewed the token. The
/// same number now bounds idleness rather than wall-clock.
fn default_admin_idle_timeout() -> u64 {
    900
}

fn default_access_token_expiry() -> u64 {
    900
}

fn default_refresh_token_expiry() -> u64 {
    86400
}

fn default_challenge_ttl() -> u64 {
    30
}

fn default_session_cleanup_interval() -> u64 {
    600
}

fn default_passkey_enrollment_ttl() -> u64 {
    86400
}

/// Upper bound on [`AuthConfig::claim_code_hash_wait_ms`]: one minute.
pub const MAX_CLAIM_CODE_HASH_WAIT_MS: u64 = 60_000;

fn default_claim_code_hash_wait_ms() -> u64 {
    5000
}

fn default_cleanup_ttl_minutes() -> u64 {
    60
}

/// Default global pending-challenge cap. Must equal
/// `did_hosting_control::pending_challenges::MAX_GLOBAL_PENDING` (pinned by a
/// unit test in that crate — the constant lives there because the tracker
/// does, and did-hosting-common sits below did-hosting-control in the graph).
fn default_max_global_pending_challenges() -> usize {
    10_000
}

/// Default per-DID pending-challenge cap. Must equal
/// `did_hosting_control::routes::auth::MAX_PENDING_CHALLENGES_PER_DID`.
fn default_max_pending_challenges_per_did() -> usize {
    10
}

/// 30 days. Generous enough that a normally-active session never notices
/// it, tight enough that a compromise nobody caught still ends on its own.
fn default_absolute_session_lifetime() -> u64 {
    30 * 24 * 60 * 60
}

impl AuthConfig {
    /// [`Self::claim_code_hash_wait_ms`] as a duration.
    pub fn claim_code_hash_wait(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.claim_code_hash_wait_ms)
    }

    /// Validate configuration values are within acceptable ranges.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.challenge_ttl < 10 {
            return Err(AppError::Config(
                "challenge_ttl must be at least 10 seconds".into(),
            ));
        }
        if self.session_cleanup_interval < 10 {
            return Err(AppError::Config(
                "session_cleanup_interval must be at least 10 seconds".into(),
            ));
        }
        // A timeout shorter than a minute signs an operator out between
        // keystrokes; it is a misconfiguration, not a strict policy.
        if self.admin_idle_timeout < 60 {
            return Err(AppError::Config(
                "admin_idle_timeout must be at least 60 seconds".into(),
            ));
        }
        // The wait exists to bound how long a burst of redemption attempts
        // holds the others up; a wait of minutes no longer does that.
        if self.claim_code_hash_wait_ms > MAX_CLAIM_CODE_HASH_WAIT_MS {
            return Err(AppError::Config(format!(
                "claim_code_hash_wait_ms must be at most {MAX_CLAIM_CODE_HASH_WAIT_MS}"
            )));
        }
        if self.access_token_expiry < 30 {
            return Err(AppError::Config(
                "access_token_expiry must be at least 30 seconds".into(),
            ));
        }
        // A zero cap fails every challenge closed — bounded, but it takes
        // authentication down rather than protecting it, so refuse it at load.
        if self.max_global_pending_challenges == 0 {
            return Err(AppError::Config(
                "max_global_pending_challenges must be at least 1".into(),
            ));
        }
        if self.max_pending_challenges_per_did == 0 {
            return Err(AppError::Config(
                "max_pending_challenges_per_did must be at least 1".into(),
            ));
        }
        // Shorter than a single refresh cycle, the ceiling would refuse the
        // very first refresh a normal session attempts.
        if self.absolute_session_lifetime < self.refresh_token_expiry {
            return Err(AppError::Config(
                "absolute_session_lifetime must be at least refresh_token_expiry".into(),
            ));
        }
        Ok(())
    }

    /// `Retry-After` for a refusal on the canonical handler's pending-challenge
    /// cap (did-hosting-server, webvh-witness). That cap counts `ChallengeSent`
    /// rows in the store, so a slot frees when its challenge authenticates, or
    /// when the challenge has expired (`challenge_ttl`) and the session sweep
    /// has then run (every `session_cleanup_interval`): their sum bounds the
    /// wait. did-hosting-control does not use this — its in-memory tracker
    /// frees a slot at `challenge_ttl` and computes the exact hint.
    pub fn pending_challenge_retry_after_secs(&self) -> u64 {
        self.challenge_ttl
            .saturating_add(self.session_cleanup_interval)
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry: default_access_token_expiry(),
            refresh_token_expiry: default_refresh_token_expiry(),
            challenge_ttl: default_challenge_ttl(),
            session_cleanup_interval: default_session_cleanup_interval(),
            admin_idle_timeout: default_admin_idle_timeout(),
            passkey_enrollment_ttl: default_passkey_enrollment_ttl(),
            claim_code_hash_wait_ms: default_claim_code_hash_wait_ms(),
            cleanup_ttl_minutes: default_cleanup_ttl_minutes(),
            max_global_pending_challenges: default_max_global_pending_challenges(),
            max_pending_challenges_per_did: default_max_pending_challenges_per_did(),
            absolute_session_lifetime: default_absolute_session_lifetime(),
        }
    }
}

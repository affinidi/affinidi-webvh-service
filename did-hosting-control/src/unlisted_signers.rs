//! Signed documents from signers the ACL does not list.
//!
//! A few tasks take a proof from a signer this service has no standing
//! relationship with: the `Optional` rows (capability discovery,
//! `server/info`, the `auth/*` family, passkey login start and invite
//! redemption) and the `SessionKey` row (a browser's fresh `did:key`). Such a
//! signer costs nothing to create, so what it can make the service do is
//! bounded here, apart from what ACL members can.
//!
//! ## Replay records ([`ReplayPartition`])
//!
//! - **Open reads are not recorded at all**, whoever signs them: `server/info`,
//!   capability discovery and an `auth/oob/*` version this service does not
//!   serve. They change nothing and disclose only public data, so a resend
//!   does nothing a fresh document could not.
//! - **ACL members** (and the configured watchers the gate admits) are
//!   recorded in the shared cache (`AppState::replay_cache`), and only they
//!   are.
//! - **Sign-in rows** (the `auth/*` family, passkey login and invite
//!   redemption) from a signer the ACL does not list are recorded in
//!   [`UnlistedSigners::sign_in`]: a delegate, a browser's session key, a
//!   first login. Each source may add at most [`SIGN_IN_PER_SOURCE`] records
//!   per [`SIGN_IN_WINDOW_SECS`] (the client address on HTTPS, the
//!   transport's sender otherwise), on top of the cache's own per-signer
//!   bound.
//! - **Anything else** from an unlisted signer (a `did:webs`
//!   self-registration) goes into [`UnlistedSigners::other`].
//!
//! Every cache refuses rather than forgets at its bounds. A document already
//! recorded in any of them is refused as a replay whichever one it would go
//! to now (a signer's ACL entry can change inside the freshness window).
//!
//! ## DID resolution
//!
//! Verifying a proof by a DID that is not a `did:key` means resolving that DID
//! over the network. For an unlisted signer that happens only after the
//! key-free checks pass ([`precheck_sender_bound`]), at most
//! [`RESOLUTION_CONCURRENCY`] at a time and [`RESOLUTIONS_PER_WINDOW`] per
//! [`RESOLUTION_WINDOW_SECS`] across all such signers, each bounded by
//! [`RESOLUTION_TIMEOUT`], and without the forced re-resolution retry a known
//! peer gets after a key rotation
//! ([`TransportBoundVerifier::without_forced_refresh`]). Past a bound the
//! document is refused as `unavailable` (retryable). A `did:key` is decoded
//! locally and is subject to none of these limits but the timeout.
//!
//! One exception: the delegate of a proxied `auth/authenticate` whose
//! principal is an ACL member, and whose delegation evidence that principal
//! signed verifies, is verified like a member
//! (`crate::trust_tasks_auth::vouched_delegate`).
//!
//! All of this is per process, like the service's other limiters.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use trust_tasks_rs::{RejectReason, TrustTask};

use did_hosting_common::server::config::ReplayConfig;
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::rate_limit::KeyedRateLimiter;
use did_hosting_common::server::replay::ReplayCache;
use did_hosting_common::server::trust_tasks::verifier::controller_did;
use did_hosting_common::server::trust_tasks::{
    BoundError, TransportBoundVerifier, precheck_sender_bound, unreachable_error,
    verify_sender_bound,
};

/// Records the sign-in cache holds across all signers (about 3 MB).
pub const SIGN_IN_MAX_ENTRIES: usize = 100_000;

/// Records the sign-in cache holds for any one signer.
pub const SIGN_IN_MAX_ENTRIES_PER_SIGNER: usize = 1_000;

/// Records one source may add to the sign-in cache per
/// [`SIGN_IN_WINDOW_SECS`].
pub const SIGN_IN_PER_SOURCE: u64 = 120;

/// The window [`SIGN_IN_PER_SOURCE`] is counted over.
pub const SIGN_IN_WINDOW_SECS: u64 = 60;

/// The `limiter` a sign-in refused by its source's quota names.
pub const SIGN_IN_LIMITER_NAME: &str = "unlisted-sign-in-per-source";

/// Records the cache for other unlisted signers holds across all of them.
pub const OTHER_MAX_ENTRIES: usize = 10_000;

/// Records that cache holds for any one signer.
pub const OTHER_MAX_ENTRIES_PER_SIGNER: usize = 1_000;

/// Network DID resolutions for unlisted signers in flight at once.
pub const RESOLUTION_CONCURRENCY: usize = 16;

/// Network DID resolutions for unlisted signers per
/// [`RESOLUTION_WINDOW_SECS`], across all of them.
pub const RESOLUTIONS_PER_WINDOW: u64 = 300;

/// The window [`RESOLUTIONS_PER_WINDOW`] is counted over.
pub const RESOLUTION_WINDOW_SECS: u64 = 60;

/// The longest an unlisted signer's proof verification (or a delegation
/// evidence check) may take.
pub const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);

/// The `limiter` a refused resolution names.
pub const RESOLUTION_LIMITER_NAME: &str = "unlisted-signer-resolution";

/// How long a caller turned away because every resolution slot is in use
/// is told to wait.
const BUSY_RETRY_AFTER_SECS: i64 = 5;

/// The one key of the shared resolution bucket.
const RESOLUTION_KEY: &str = "all";

/// Where a signed document's `(signer, id)` record goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayPartition {
    /// Not recorded: an open read.
    None,
    /// `AppState::replay_cache`: ACL members and admitted watchers.
    Shared,
    /// [`UnlistedSigners::sign_in`].
    SignIn,
    /// [`UnlistedSigners::other`].
    Other,
}

/// What the control plane spends on signers the ACL does not list. See the
/// module docs.
pub struct UnlistedSigners {
    /// Records for sign-in rows from unlisted signers.
    pub sign_in: ReplayCache,
    /// Records for anything else from unlisted signers.
    pub other: ReplayCache,
    sign_in_sources: KeyedRateLimiter<String>,
    resolutions: Arc<Semaphore>,
    resolution_rate: KeyedRateLimiter<String>,
    timeout: Duration,
}

impl Default for UnlistedSigners {
    fn default() -> Self {
        Self::with_limits(
            RESOLUTION_CONCURRENCY,
            RESOLUTIONS_PER_WINDOW,
            RESOLUTION_TIMEOUT,
        )
    }
}

impl UnlistedSigners {
    /// The default replay bounds, with these resolution bounds.
    pub fn with_limits(concurrency: usize, per_window: u64, timeout: Duration) -> Self {
        let cache = |max_entries, max_entries_per_signer| {
            ReplayCache::with_config(ReplayConfig {
                max_entries,
                max_entries_per_signer,
            })
            .expect("the unlisted-signer replay bounds are valid")
        };
        Self {
            sign_in: cache(SIGN_IN_MAX_ENTRIES, SIGN_IN_MAX_ENTRIES_PER_SIGNER),
            other: cache(OTHER_MAX_ENTRIES, OTHER_MAX_ENTRIES_PER_SIGNER),
            sign_in_sources: KeyedRateLimiter::new(
                SIGN_IN_LIMITER_NAME,
                SIGN_IN_PER_SOURCE,
                SIGN_IN_WINDOW_SECS,
            ),
            resolutions: Arc::new(Semaphore::new(concurrency)),
            resolution_rate: KeyedRateLimiter::new(
                RESOLUTION_LIMITER_NAME,
                per_window,
                RESOLUTION_WINDOW_SECS,
            ),
            timeout,
        }
    }

    /// The cache `partition` names, `shared` being the members' one.
    pub fn cache<'a>(
        &'a self,
        partition: ReplayPartition,
        shared: &'a ReplayCache,
    ) -> Option<&'a ReplayCache> {
        match partition {
            ReplayPartition::None => None,
            ReplayPartition::Shared => Some(shared),
            ReplayPartition::SignIn => Some(&self.sign_in),
            ReplayPartition::Other => Some(&self.other),
        }
    }

    /// Every cache, `shared` included.
    pub fn all<'a>(&'a self, shared: &'a ReplayCache) -> [&'a ReplayCache; 3] {
        [shared, &self.sign_in, &self.other]
    }

    /// Charge `source` for one sign-in record, or the refusal when its quota
    /// is spent.
    pub fn charge_sign_in(&self, source: String) -> Result<(), RejectReason> {
        match self.sign_in_sources.try_consume(source) {
            Err(AppError::RateLimited {
                retry_after_secs, ..
            }) => Err(unavailable_for(retry_after_secs as i64)),
            _ => Ok(()),
        }
    }

    /// The bound on a delegation evidence check
    /// (`crate::trust_tasks_auth`).
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// [`verify_sender_bound`] for a signer the ACL does not list, under the
    /// bounds in the module docs. `Err(Ok(reason))` is a refusal before any
    /// proof work (over a bound); `Err(Err(e))` is the verification's own
    /// failure, a timeout reported as an unreachable signer (retryable).
    pub async fn verify<P>(
        &self,
        doc: &TrustTask<P>,
        sender: &str,
        my_vid: &str,
        verifier: &TransportBoundVerifier,
    ) -> Result<String, Result<RejectReason, BoundError>>
    where
        P: Serialize + Send + Sync,
    {
        precheck_sender_bound(doc, None, Some(sender), my_vid, chrono::Utc::now()).map_err(Err)?;
        let resolves = doc
            .proof
            .as_ref()
            .is_some_and(|p| !controller_did(&p.verification_method).starts_with("did:key:"));
        let _permit = if resolves {
            Some(self.admit_resolution().map_err(Ok)?)
        } else {
            None
        };
        let verifier = verifier.without_forced_refresh();
        match tokio::time::timeout(
            self.timeout,
            verify_sender_bound(doc, None, Some(sender), my_vid, &verifier),
        )
        .await
        {
            Ok(bound) => bound.map_err(Err),
            Err(_) => Err(Err(BoundError::Proof(unreachable_error(format!(
                "verification did not complete within {}s",
                self.timeout.as_secs_f32()
            ))))),
        }
    }

    /// A resolution slot, or the refusal when none is free or the shared
    /// rate is spent.
    fn admit_resolution(&self) -> Result<OwnedSemaphorePermit, RejectReason> {
        let Ok(permit) = self.resolutions.clone().try_acquire_owned() else {
            return Err(unavailable_for(BUSY_RETRY_AFTER_SECS));
        };
        if let Err(AppError::RateLimited {
            retry_after_secs, ..
        }) = self.resolution_rate.try_consume(RESOLUTION_KEY.to_string())
        {
            return Err(unavailable_for(retry_after_secs as i64));
        }
        Ok(permit)
    }

    /// The same limits, with each source's [`SIGN_IN_PER_SOURCE`] sign-in
    /// records counted over `window_secs` rather than
    /// [`SIGN_IN_WINDOW_SECS`]. The quota is a token bucket that gives a
    /// source a record back every `window / SIGN_IN_PER_SOURCE` (half a
    /// second by default), so a test that spends the whole quota through the
    /// full request path would otherwise see a record returned whenever it
    /// runs slower than that.
    #[cfg(test)]
    pub(crate) fn with_sign_in_window(mut self, window_secs: u64) -> Self {
        self.sign_in_sources =
            KeyedRateLimiter::new(SIGN_IN_LIMITER_NAME, SIGN_IN_PER_SOURCE, window_secs);
        self
    }

    /// Hold every resolution slot, as if that many resolutions were in
    /// flight.
    #[cfg(test)]
    pub(crate) fn occupy_all(&self) -> OwnedSemaphorePermit {
        let n = self.resolutions.available_permits() as u32;
        self.resolutions
            .clone()
            .try_acquire_many_owned(n)
            .expect("free slots")
    }
}

fn unavailable_for(secs: i64) -> RejectReason {
    RejectReason::Unavailable {
        retry_after: Some(chrono::Utc::now() + chrono::Duration::seconds(secs)),
    }
}

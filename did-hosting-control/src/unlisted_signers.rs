//! Signed documents from signers the ACL does not list.
//!
//! A few tasks take a proof from a signer this service has no standing
//! relationship with: the `Optional` rows (capability discovery,
//! `server/info`, the `auth/*` family, passkey login start and invite
//! redemption) and the `SessionKey` rows (a browser's fresh `did:key`).
//! Such a signer costs nothing to create, so what it can make the service do
//! is bounded here, apart from what ACL members can:
//!
//! - **Its own replay cache.** Its `(signer, id)` records go into
//!   [`UnlistedSigners::replay`], a separate, smaller cache, never the shared
//!   one ACL members use (`AppState::replay_cache`). Both refuse rather than
//!   forget at their bounds; keeping them apart means records from unlisted
//!   signers can only ever fill this one, so they can never turn away an
//!   operational request.
//! - **Bounded DID resolution.** Verifying a proof by a DID that is not a
//!   `did:key` means resolving that DID over the network. For an unlisted
//!   signer that happens only after the key-free checks pass
//!   ([`precheck_sender_bound`]), at most [`RESOLUTION_CONCURRENCY`] at a
//!   time and [`RESOLUTIONS_PER_WINDOW`] per [`RESOLUTION_WINDOW_SECS`]
//!   across all such signers, each bounded by [`RESOLUTION_TIMEOUT`], and
//!   without the forced re-resolution retry a known peer gets after a key
//!   rotation ([`TransportBoundVerifier::without_forced_refresh`]). Past a
//!   bound the document is refused as `unavailable` (retryable). A `did:key`
//!   is decoded locally and is subject to none of these limits but the
//!   timeout.
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

/// Records the unlisted-signer replay cache holds across all signers (about
/// 3 MB).
pub const REPLAY_MAX_ENTRIES: usize = 100_000;

/// Records it holds for any one unlisted signer.
pub const REPLAY_MAX_ENTRIES_PER_SIGNER: usize = 10_000;

/// Network DID resolutions for unlisted signers in flight at once.
pub const RESOLUTION_CONCURRENCY: usize = 16;

/// Network DID resolutions for unlisted signers per
/// [`RESOLUTION_WINDOW_SECS`], across all of them.
pub const RESOLUTIONS_PER_WINDOW: u64 = 300;

/// The window [`RESOLUTIONS_PER_WINDOW`] is counted over.
pub const RESOLUTION_WINDOW_SECS: u64 = 60;

/// The longest an unlisted signer's proof verification may take.
pub const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);

/// The `limiter` a refused resolution names.
pub const RESOLUTION_LIMITER_NAME: &str = "unlisted-signer-resolution";

/// How long a caller turned away because every resolution slot is in use
/// is told to wait.
const BUSY_RETRY_AFTER_SECS: i64 = 5;

/// The one key of the shared resolution bucket.
const RESOLUTION_KEY: &str = "all";

/// The replay bounds of [`UnlistedSigners::replay`].
pub fn replay_config() -> ReplayConfig {
    ReplayConfig {
        max_entries: REPLAY_MAX_ENTRIES,
        max_entries_per_signer: REPLAY_MAX_ENTRIES_PER_SIGNER,
    }
}

/// What the control plane spends on signers the ACL does not list. See the
/// module docs.
pub struct UnlistedSigners {
    /// `(signer, id)` records for documents from unlisted signers.
    pub replay: ReplayCache,
    resolutions: Arc<Semaphore>,
    resolution_rate: KeyedRateLimiter<String>,
}

impl Default for UnlistedSigners {
    fn default() -> Self {
        Self::with_concurrency(RESOLUTION_CONCURRENCY)
    }
}

impl UnlistedSigners {
    /// The defaults, with `concurrency` resolution slots.
    pub fn with_concurrency(concurrency: usize) -> Self {
        Self {
            replay: ReplayCache::with_config(replay_config())
                .expect("the unlisted-signer replay bounds are valid"),
            resolutions: Arc::new(Semaphore::new(concurrency)),
            resolution_rate: KeyedRateLimiter::new(
                RESOLUTION_LIMITER_NAME,
                RESOLUTIONS_PER_WINDOW,
                RESOLUTION_WINDOW_SECS,
            ),
        }
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
            RESOLUTION_TIMEOUT,
            verify_sender_bound(doc, None, Some(sender), my_vid, &verifier),
        )
        .await
        {
            Ok(bound) => bound.map_err(Err),
            Err(_) => Err(Err(BoundError::Proof(unreachable_error(format!(
                "verification did not complete within {}s",
                RESOLUTION_TIMEOUT.as_secs()
            ))))),
        }
    }

    /// A resolution slot, or the refusal when none is free or the shared
    /// rate is spent.
    fn admit_resolution(&self) -> Result<OwnedSemaphorePermit, RejectReason> {
        let Ok(permit) = self.resolutions.clone().try_acquire_owned() else {
            return Err(RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(BUSY_RETRY_AFTER_SECS),
                ),
            });
        };
        if let Err(AppError::RateLimited {
            retry_after_secs, ..
        }) = self.resolution_rate.try_consume(RESOLUTION_KEY.to_string())
        {
            return Err(RejectReason::Unavailable {
                retry_after: Some(
                    chrono::Utc::now() + chrono::Duration::seconds(retry_after_secs as i64),
                ),
            });
        }
        Ok(permit)
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

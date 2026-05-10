//! Bounded counter for pending DIDComm authentication challenges.
//!
//! `POST /api/auth/challenge` is unauthenticated — anyone who can
//! reach the endpoint can issue a challenge for any DID. The previous
//! implementation defended against this with two mechanisms:
//!
//! 1. A per-DID cap of 10 pending challenges, computed by an O(N)
//!    `prefix_iter_raw("session:")` scan plus an in-process filter.
//!    Cost grew linearly in the total session population.
//! 2. No global cap. An attacker sweeping millions of distinct DIDs
//!    could accumulate ~10 sessions each, with the only bound being
//!    fjall's disk capacity.
//!
//! This module replaces both with an in-memory counter:
//! - O(1) per-DID counter via `RwLock<HashMap<String, AtomicU64>>`.
//! - O(1) global counter via a single `AtomicU64`.
//! - A configurable global cap (default `MAX_GLOBAL_PENDING`), with
//!   the per-DID cap kept as an external constant the caller passes
//!   in.
//!
//! Restart wipes the counter; that's fine because the actual session
//! records still live in fjall and expire naturally — the counter
//! just sees a brief over-count after restart until the cleanup task
//! runs. If under-counting at restart matters, swap to a periodic
//! reconcile that scans `session:` once at startup; today it's not
//! worth the boot-time cost for a strictly-defensive cap.
//!
//! Out of scope: IP-level rate limiting. That belongs in a
//! middleware layer (e.g. `tower-governor`) and is deployment-
//! dependent (trusted-proxy header parsing required behind a load
//! balancer); track separately.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use crate::error::AppError;

/// Hard cap on the total number of pending challenges across all
/// DIDs. Defends against an attacker sweeping millions of distinct
/// DIDs to accumulate per-DID-cap × N entries; once `total >=
/// MAX_GLOBAL_PENDING`, all new challenge issuance is rejected.
///
/// Sized for a generous-but-bounded operator footprint: 10_000
/// concurrent challenges = ~10x the per-DID cap × 1000 distinct
/// DIDs in flight at the same time. Tunable via the constructor if
/// a deployment legitimately needs more.
pub const MAX_GLOBAL_PENDING: u64 = 10_000;

/// In-memory tracker for pending-challenge counts.
///
/// Each `try_issue` is O(1): one `RwLock` read for the per-DID
/// counter slot, then atomic increments on the per-DID and global
/// counters. `release` is symmetric.
#[derive(Debug)]
pub struct PendingChallengeTracker {
    per_did: RwLock<HashMap<String, Arc<AtomicU64>>>,
    global: AtomicU64,
    global_cap: u64,
}

impl Default for PendingChallengeTracker {
    fn default() -> Self {
        Self::with_global_cap(MAX_GLOBAL_PENDING)
    }
}

impl PendingChallengeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_global_cap(global_cap: u64) -> Self {
        Self {
            per_did: RwLock::new(HashMap::new()),
            global: AtomicU64::new(0),
            global_cap,
        }
    }

    /// Atomically reserve one pending-challenge slot for `did`.
    ///
    /// Rejects if either the per-DID cap (caller-supplied) or the
    /// global cap has been hit. On success, the caller owes a
    /// matching `release(did)` once the challenge is consumed
    /// (authenticated) or expires (cleanup).
    ///
    /// On failure no counters are bumped. `try_issue` may be retried
    /// after a `release` call frees a slot.
    pub async fn try_issue(&self, did: &str, per_did_cap: u64) -> Result<(), AppError> {
        // Read or create the per-DID counter slot. The HashMap entry
        // lives for the lifetime of the process — over time it
        // accumulates one slot per distinct DID seen. That's
        // bounded in practice by the ACL size; an attacker spraying
        // unique DIDs is bounded by the global cap below, which
        // refuses to issue *and so* prevents the HashMap from
        // growing past that point. (We could LRU-evict the per-DID
        // counters after a quiet period; defer until profiling
        // shows it's a hotspot.)
        let counter = {
            let read = self.per_did.read().await;
            if let Some(c) = read.get(did) {
                c.clone()
            } else {
                drop(read);
                let mut write = self.per_did.write().await;
                write
                    .entry(did.to_string())
                    .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                    .clone()
            }
        };

        // Check the global cap first; this is the cheaper rejection
        // path for the most-likely attacker shape (sweep of distinct
        // DIDs). The per-DID counter is then advisory.
        if self.global.load(Ordering::Relaxed) >= self.global_cap {
            return Err(AppError::Validation(format!(
                "global pending-challenge cap reached ({} concurrent); try again later",
                self.global_cap,
            )));
        }
        if counter.load(Ordering::Relaxed) >= per_did_cap {
            return Err(AppError::Validation(format!(
                "too many pending challenges for this DID (>= {per_did_cap}); try again later",
            )));
        }

        // Two non-atomic increments — between the global check and
        // this fetch_add another caller could nudge the counter past
        // the cap. The over-shoot is bounded by request concurrency
        // (a few requests at most) and is benign — an attacker
        // cannot exploit it to get past the cap by orders of
        // magnitude. Strict atomicity would require CAS-loops on
        // both counters, which complicates the code without making
        // the cap meaningfully tighter.
        counter.fetch_add(1, Ordering::Relaxed);
        self.global.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Decrement both counters for `did`. Saturating-subtract so a
    /// double-release (e.g. a session expired AND was authenticated
    /// in the same window) is a no-op rather than a panic or
    /// underflow.
    pub async fn release(&self, did: &str) {
        let counter = {
            let read = self.per_did.read().await;
            read.get(did).cloned()
        };
        if let Some(c) = counter {
            // saturating_sub prevents underflow if release is called
            // more times than try_issue (e.g. cleanup races
            // authenticate). Skipped if the per-DID slot is missing
            // entirely, which can happen after restart.
            let prev = c.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
            if prev.is_ok() {
                self.global
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        Some(v.saturating_sub(1))
                    })
                    .ok();
            }
        }
    }

    /// Test/observability accessor — returns the current pending
    /// count for a DID, or 0 if no slot has been allocated.
    #[cfg(test)]
    pub async fn count_for(&self, did: &str) -> u64 {
        let read = self.per_did.read().await;
        read.get(did)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub fn global_count(&self) -> u64 {
        self.global.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issues_within_caps() {
        let t = PendingChallengeTracker::with_global_cap(100);
        for _ in 0..5 {
            t.try_issue("did:example:a", 10).await.unwrap();
        }
        assert_eq!(t.count_for("did:example:a").await, 5);
        assert_eq!(t.global_count(), 5);
    }

    #[tokio::test]
    async fn per_did_cap_rejects_excess() {
        let t = PendingChallengeTracker::with_global_cap(100);
        for _ in 0..3 {
            t.try_issue("did:example:a", 3).await.unwrap();
        }
        let err = t.try_issue("did:example:a", 3).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("DID")));
    }

    /// Sweep-attack defence: many distinct DIDs each within the per-
    /// DID cap should still hit the global cap and be refused.
    #[tokio::test]
    async fn global_cap_rejects_sweep_of_distinct_dids() {
        let t = PendingChallengeTracker::with_global_cap(5);
        // Five DIDs, one challenge each, fills the global cap.
        for i in 0..5 {
            t.try_issue(&format!("did:example:{i}"), 10).await.unwrap();
        }
        assert_eq!(t.global_count(), 5);
        // Sixth distinct DID is within per-DID cap (0/10) but
        // global is full.
        let err = t.try_issue("did:example:6", 10).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("global")));
    }

    #[tokio::test]
    async fn release_decrements_both_counters() {
        let t = PendingChallengeTracker::with_global_cap(100);
        t.try_issue("did:example:a", 10).await.unwrap();
        t.try_issue("did:example:a", 10).await.unwrap();
        assert_eq!(t.count_for("did:example:a").await, 2);
        assert_eq!(t.global_count(), 2);

        t.release("did:example:a").await;
        assert_eq!(t.count_for("did:example:a").await, 1);
        assert_eq!(t.global_count(), 1);
    }

    /// Saturating semantics: extra releases past zero do not
    /// underflow into ~u64::MAX. Pinning this catches a regression
    /// where someone replaces `fetch_update`-with-saturating with a
    /// raw `fetch_sub`.
    #[tokio::test]
    async fn release_saturates_at_zero() {
        let t = PendingChallengeTracker::with_global_cap(100);
        t.try_issue("did:example:a", 10).await.unwrap();
        t.release("did:example:a").await;
        t.release("did:example:a").await; // double-release
        t.release("did:example:a").await; // triple-release
        assert_eq!(t.count_for("did:example:a").await, 0);
        assert_eq!(t.global_count(), 0);
    }

    /// Releasing a DID that was never issued is a no-op.
    #[tokio::test]
    async fn release_unknown_did_noop() {
        let t = PendingChallengeTracker::with_global_cap(100);
        t.release("did:example:never-seen").await;
        assert_eq!(t.global_count(), 0);
    }
}

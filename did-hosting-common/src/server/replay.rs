//! Anti-replay cache for inbound signed messages and Trust Task documents.
//!
//! Signed input is checked for freshness (`issuedAt` inside
//! [`FRESHNESS_WINDOW_SECS`](super::didcomm_unpack::FRESHNESS_WINDOW_SECS), at most
//! [`FUTURE_SKEW_SECS`](super::didcomm_unpack::FUTURE_SKEW_SECS) ahead). That alone
//! doesn't prevent replay: a captured signed document can be re-submitted
//! within the window and still verify, re-triggering a state-changing
//! operation (a DID delete, an owner change, an edge sync or domain purge).
//!
//! This module keeps an in-memory `(signer, id)` record for
//! [`REPLAY_WINDOW_SECS`], so any pair the freshness gate would still accept
//! is still remembered. Callers insert only after the signer has been
//! authorised and verified, so an unauthenticated flood cannot occupy it.
//!
//! # Bounds: refuse, never evict
//!
//! Evicting old records to make room would let a flood push a genuine record
//! out and then replay it. So at its bounds the cache **refuses** new records
//! ([`ReplayError::Full`]) — the request is turned away as temporarily
//! unavailable, and is safe to retry — rather than forgetting anything. Two
//! bounds apply: a global one ([`MAX_ENTRIES`]) and one per signer
//! ([`MAX_ENTRIES_PER_SIGNER`]), so one (authorised) signer cannot exhaust the
//! space for everyone else.
//!
//! Expiry is O(1) amortised: records are kept in insertion order (insert time
//! is monotonic), so expired ones are popped from the front.
//!
//! Restart wipes the cache. The window bounds how long a document captured
//! before a restart can be replayed after it; memory-only is intentional.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use super::auth::session::now_epoch;
use super::didcomm_unpack::REPLAY_WINDOW_SECS;

use super::error::AppError;

/// Global cap on remembered `(signer, id)` pairs.
pub const MAX_ENTRIES: usize = 50_000;

/// Cap on remembered pairs for any one signer.
pub const MAX_ENTRIES_PER_SIGNER: usize = 5_000;

/// Why a record was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The `(signer, id)` pair was already accepted inside the window.
    Duplicate,
    /// The cache is at a bound; the request is refused (retryable).
    Full,
}

impl From<ReplayError> for AppError {
    fn from(e: ReplayError) -> Self {
        match e {
            ReplayError::Duplicate => {
                AppError::Validation("duplicate message id (replay-detected)".into())
            }
            ReplayError::Full => AppError::Internal(
                "replay cache is full; refusing new signed requests until records expire".into(),
            ),
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    seen: HashMap<(String, String), u64>,
    order: VecDeque<(u64, (String, String))>,
    per_signer: HashMap<String, usize>,
}

impl Inner {
    fn expire(&mut self, now: u64) {
        while let Some((at, _)) = self.order.front() {
            if now.saturating_sub(*at) <= REPLAY_WINDOW_SECS {
                break;
            }
            let (_, key) = self.order.pop_front().expect("front exists");
            self.seen.remove(&key);
            if let Some(n) = self.per_signer.get_mut(&key.0) {
                *n -= 1;
                if *n == 0 {
                    self.per_signer.remove(&key.0);
                }
            }
        }
    }
}

/// `(signer, id)` records with insert-time epochs. A single `Mutex`: every
/// access is short and non-async.
#[derive(Debug, Default)]
pub struct ReplayCache {
    inner: Mutex<Inner>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `(signer, id)`, or refuse it as a replay or because the cache is
    /// at a bound.
    pub fn check(&self, signer: &str, id: &str) -> Result<(), ReplayError> {
        self.check_at(signer, id, now_epoch())
    }

    fn check_at(&self, signer: &str, id: &str, now: u64) -> Result<(), ReplayError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.expire(now);
        let key = (signer.to_string(), id.to_string());
        if inner.seen.contains_key(&key) {
            return Err(ReplayError::Duplicate);
        }
        if inner.seen.len() >= MAX_ENTRIES
            || inner.per_signer.get(signer).copied().unwrap_or(0) >= MAX_ENTRIES_PER_SIGNER
        {
            return Err(ReplayError::Full);
        }
        inner.seen.insert(key.clone(), now);
        inner.order.push_back((now, key));
        *inner.per_signer.entry(signer.to_string()).or_default() += 1;
        Ok(())
    }

    /// [`Self::check`] with the error as an [`AppError`].
    pub fn check_and_insert(&self, signer: &str, id: &str) -> Result<(), AppError> {
        self.check(signer, id).map_err(AppError::from)
    }

    /// Number of records currently held.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .seen
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_insert_succeeds_and_duplicate_is_refused() {
        let cache = ReplayCache::new();
        cache.check("did:example:a", "msg-1").unwrap();
        assert_eq!(
            cache.check("did:example:a", "msg-1"),
            Err(ReplayError::Duplicate)
        );
        let err = cache
            .check_and_insert("did:example:a", "msg-1")
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("replay-detected")));
    }

    #[test]
    fn distinct_signer_or_id_accepted() {
        let cache = ReplayCache::new();
        cache.check("did:example:a", "msg-1").unwrap();
        cache.check("did:example:a", "msg-2").unwrap();
        cache.check("did:example:b", "msg-1").unwrap();
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn a_record_expires_after_the_window() {
        let cache = ReplayCache::new();
        cache.check_at("did:example:a", "msg-1", 1_000).unwrap();
        assert_eq!(
            cache.check_at("did:example:a", "msg-1", 1_000 + REPLAY_WINDOW_SECS),
            Err(ReplayError::Duplicate),
            "still inside the window"
        );
        cache
            .check_at("did:example:a", "msg-1", 1_001 + REPLAY_WINDOW_SECS)
            .expect("expired, so accepted again");
        assert_eq!(cache.len(), 1);
    }

    /// At a bound the cache refuses rather than forgets: a remembered record is
    /// never pushed out by new ones, so it can never be replayed.
    #[test]
    fn a_full_signer_is_refused_and_nothing_is_forgotten() {
        let cache = ReplayCache::new();
        for i in 0..MAX_ENTRIES_PER_SIGNER {
            cache.check_at("did:flood", &i.to_string(), 1_000).unwrap();
        }
        assert_eq!(
            cache.check_at("did:flood", "one-more", 1_000),
            Err(ReplayError::Full)
        );
        assert_eq!(
            cache.check_at("did:flood", "0", 1_000),
            Err(ReplayError::Duplicate),
            "the oldest record is still remembered"
        );
        // Another signer is unaffected by one signer's flood.
        cache.check_at("did:other", "x", 1_000).unwrap();
    }

    #[test]
    fn the_global_bound_refuses_new_records() {
        let cache = ReplayCache::new();
        for i in 0..MAX_ENTRIES {
            let signer = format!("did:s{}", i % 100);
            cache.check_at(&signer, &i.to_string(), 1_000).unwrap();
        }
        assert_eq!(
            cache.check_at("did:fresh", "x", 1_000),
            Err(ReplayError::Full)
        );
    }
}

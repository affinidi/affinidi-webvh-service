//! Anti-replay cache for inbound signed messages and Trust Task documents.
//!
//! Signed input is checked for freshness (`issuedAt` inside
//! [`FRESHNESS_WINDOW_SECS`], at most [`FUTURE_SKEW_SECS`] ahead). That alone
//! doesn't prevent replay: a captured signed document can be re-submitted
//! within the window and still verify, re-triggering a state-changing
//! operation (a DID delete, an owner change, an edge sync or domain purge).
//!
//! This module remembers every accepted `(signer, id)` pair for as long as
//! the freshness gate would still accept its document. Callers insert only
//! after the signer has been authorised and verified, so an unauthenticated
//! flood cannot occupy it.
//!
//! # Compact records, filed by `issuedAt`
//!
//! A record is a 128-bit keyed hash of `(signer, id)`, not the strings, so it
//! costs about [`BYTES_PER_RECORD`] bytes whatever the lengths of the DID and
//! id. The hash keys are random per process, so no one can choose ids that
//! collide; a collision would only refuse a genuine request as a duplicate,
//! which is safe and retryable.
//!
//! Records are filed in one-minute buckets by the document's signed
//! `issuedAt`. A replay carries the same signed `issuedAt`, so it always
//! lands in the bucket holding the original. Once a bucket's minute is older
//! than the freshness window (plus [`CLOCK_MARGIN_SECS`]), the freshness gate
//! refuses every document it could hold, so the whole bucket is dropped at
//! once. A document whose `issuedAt` is outside that window is refused here
//! too ([`ReplayError::Stale`]), so the cache never depends on the gate.
//!
//! # Bounds: refuse, never evict
//!
//! Evicting old records to make room would let a flood push a genuine record
//! out and then replay it. So at its bounds the cache **refuses** new records
//! ([`ReplayError::Full`]) — the request is turned away as temporarily
//! unavailable, and is safe to retry — rather than forgetting anything. Two
//! bounds apply, both set by [`ReplayConfig`]: a global one and one per
//! signer, so one (authorised) signer cannot exhaust the space for everyone
//! else. The last [`RESERVE_PERCENT`]% of the global bound is kept for
//! signers holding fewer than [`SMALL_SIGNER_RECORDS`] records, so several
//! busy signers together cannot lock a quiet one out either.
//!
//! Restart wipes the cache. The window bounds how long a document captured
//! before a restart can be replayed after it; memory-only is intentional.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::BuildHasher;
use std::sync::Mutex;

use chrono::{DateTime, Utc};

use super::auth::session::now_epoch;
use super::config::ReplayConfig;
use super::didcomm_unpack::{FRESHNESS_WINDOW_SECS, FUTURE_SKEW_SECS};
use super::error::AppError;

/// Default cap on remembered `(signer, id)` pairs ([`ReplayConfig::max_entries`]):
/// about 32 MB.
pub const MAX_ENTRIES: usize = 1_000_000;

/// Default cap on remembered pairs for any one signer
/// ([`ReplayConfig::max_entries_per_signer`]): about 600 signed requests a
/// second, sustained, since a record is held for up to 7 minutes.
pub const MAX_ENTRIES_PER_SIGNER: usize = 250_000;

/// Approximate memory per record, including hash-table overhead.
pub const BYTES_PER_RECORD: usize = 32;

/// Share of the global bound kept for signers with few records.
pub const RESERVE_PERCENT: usize = 10;

/// A signer holding fewer records than this may use the reserve.
pub const SMALL_SIGNER_RECORDS: usize = 100;

/// Slack on the freshness window, for the time between the freshness gate
/// and this cache (a DID resolution can take seconds) and for clock steps.
pub const CLOCK_MARGIN_SECS: u64 = 60;

/// Width of a bucket, in seconds of `issuedAt`.
const BUCKET_SECS: u64 = 60;

/// What a caller refused with [`ReplayError::Full`] is told to wait: the
/// cache drops its oldest minute of records once a bucket width. A hint, not
/// a promise: if that minute held few records, or (for the per-signer
/// bound) none of this signer's, a retry can be refused again.
pub const FULL_RETRY_AFTER_SECS: u64 = BUCKET_SECS;

/// Why a record was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The `(signer, id)` pair was already accepted inside the window.
    Duplicate,
    /// The cache is at a bound; the request is refused (retryable).
    Full,
    /// The document's `issuedAt` is missing or outside the window the cache
    /// remembers, so it could not be remembered for long enough.
    Stale,
}

impl ReplayError {
    /// The Trust Task rejection for this refusal.
    pub fn reject_reason(&self) -> trust_tasks_rs::RejectReason {
        use trust_tasks_rs::RejectReason;
        match self {
            ReplayError::Duplicate => RejectReason::IdConflict,
            ReplayError::Full => RejectReason::Unavailable {
                retry_after: Some(super::error::retry_at(FULL_RETRY_AFTER_SECS)),
            },
            ReplayError::Stale => RejectReason::Stale {
                detail: trust_tasks_rs::freshness::StaleReason::OlderThanWindow,
            },
        }
    }
}

impl From<ReplayError> for AppError {
    fn from(e: ReplayError) -> Self {
        match e {
            ReplayError::Duplicate => {
                AppError::Validation("duplicate message id (replay-detected)".into())
            }
            ReplayError::Full => AppError::RateLimited {
                limiter: super::error::LIMITER_REPLAY_CACHE,
                message: "too many signed requests in flight; retry later".into(),
                retry_after_secs: FULL_RETRY_AFTER_SECS,
            },
            ReplayError::Stale => {
                AppError::Validation("issuedAt is missing or outside the replay window".into())
            }
        }
    }
}

/// The records whose `issuedAt` falls in one minute.
#[derive(Debug, Default)]
struct Bucket {
    records: HashSet<u128>,
    /// Records in this bucket per signer hash, to release on expiry.
    per_signer: HashMap<u64, usize>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Buckets by `issuedAt / BUCKET_SECS`.
    buckets: BTreeMap<u64, Bucket>,
    /// Records held per signer hash, across all buckets.
    per_signer: HashMap<u64, usize>,
    total: usize,
}

impl Inner {
    /// Drop every bucket whose newest `issuedAt` is older than the window.
    fn expire(&mut self, now: u64) {
        let oldest = oldest_accepted(now) / BUCKET_SECS;
        while let Some(entry) = self.buckets.first_entry() {
            if *entry.key() >= oldest {
                break;
            }
            let bucket = entry.remove();
            self.total -= bucket.records.len();
            for (signer, n) in bucket.per_signer {
                if let Some(held) = self.per_signer.get_mut(&signer) {
                    *held -= n;
                    if *held == 0 {
                        self.per_signer.remove(&signer);
                    }
                }
            }
        }
    }
}

/// The oldest `issuedAt` the cache accepts at `now`.
fn oldest_accepted(now: u64) -> u64 {
    now.saturating_sub(FRESHNESS_WINDOW_SECS + CLOCK_MARGIN_SECS)
}

/// `(signer, id)` records filed by `issuedAt`. A single `Mutex`: every
/// access is short and non-async.
#[derive(Debug)]
pub struct ReplayCache {
    inner: Mutex<Inner>,
    limits: ReplayConfig,
    /// Two independent random keys: a 128-bit record hash, and the first
    /// alone as the signer hash.
    keys: (RandomState, RandomState),
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            limits: ReplayConfig::default(),
            keys: (RandomState::new(), RandomState::new()),
        }
    }
}

impl ReplayCache {
    /// A cache with the default bounds ([`ReplayConfig::default`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache with the configured bounds, which must be valid
    /// ([`ReplayConfig::validate`]): a zero bound would refuse every signed
    /// request.
    pub fn with_config(limits: ReplayConfig) -> Result<Self, AppError> {
        limits.validate()?;
        Ok(Self {
            limits,
            ..Self::default()
        })
    }

    /// Forget a record [`Self::check`] accepted, so the same document can be
    /// sent again: for a document refused as `unavailable` after it was
    /// recorded, which did not run. A refused document can be resent as a
    /// retry (the VTA's contract for a refusal under load), and without this
    /// the resend would be refused as a replay. Only ever for a document whose
    /// task committed nothing; a record already gone is left alone.
    pub fn release(&self, signer: &str, id: &str, issued_at: Option<DateTime<Utc>>) {
        let Some(issued_at) = issued_at.map(|t| t.timestamp()) else {
            return;
        };
        let Ok(issued_at) = u64::try_from(issued_at) else {
            return;
        };
        let signer_hash = self.keys.0.hash_one(signer);
        let record = (u128::from(self.keys.0.hash_one((signer, id))) << 64)
            | u128::from(self.keys.1.hash_one((signer, id)));
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let slot = issued_at / BUCKET_SECS;
        let Some(bucket) = inner.buckets.get_mut(&slot) else {
            return;
        };
        if !bucket.records.remove(&record) {
            return;
        }
        if let Some(n) = bucket.per_signer.get_mut(&signer_hash) {
            *n -= 1;
            if *n == 0 {
                bucket.per_signer.remove(&signer_hash);
            }
        }
        if let Some(held) = inner.per_signer.get_mut(&signer_hash) {
            *held -= 1;
            if *held == 0 {
                inner.per_signer.remove(&signer_hash);
            }
        }
        inner.total -= 1;
    }

    /// Record `(signer, id)` for the document issued at `issued_at`, or refuse
    /// it as a replay, as outside the window, or because the cache is at a
    /// bound.
    pub fn check(
        &self,
        signer: &str,
        id: &str,
        issued_at: Option<DateTime<Utc>>,
    ) -> Result<(), ReplayError> {
        let issued_at = issued_at.ok_or(ReplayError::Stale)?.timestamp();
        let issued_at = u64::try_from(issued_at).map_err(|_| ReplayError::Stale)?;
        self.check_at(signer, id, issued_at, now_epoch())
    }

    fn check_at(
        &self,
        signer: &str,
        id: &str,
        issued_at: u64,
        now: u64,
    ) -> Result<(), ReplayError> {
        if issued_at < oldest_accepted(now)
            || issued_at > now + FUTURE_SKEW_SECS + CLOCK_MARGIN_SECS
        {
            return Err(ReplayError::Stale);
        }
        let signer_hash = self.keys.0.hash_one(signer);
        let record = (u128::from(self.keys.0.hash_one((signer, id))) << 64)
            | u128::from(self.keys.1.hash_one((signer, id)));

        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.expire(now);
        let slot = issued_at / BUCKET_SECS;
        if inner
            .buckets
            .get(&slot)
            .is_some_and(|b| b.records.contains(&record))
        {
            return Err(ReplayError::Duplicate);
        }
        let held = inner.per_signer.get(&signer_hash).copied().unwrap_or(0);
        let reserve = self.limits.max_entries * RESERVE_PERCENT / 100;
        let shared = self.limits.max_entries - reserve;
        if inner.total >= self.limits.max_entries
            || held >= self.limits.max_entries_per_signer
            || (inner.total >= shared && held >= SMALL_SIGNER_RECORDS)
        {
            return Err(ReplayError::Full);
        }
        let bucket = inner.buckets.entry(slot).or_default();
        bucket.records.insert(record);
        *bucket.per_signer.entry(signer_hash).or_default() += 1;
        *inner.per_signer.entry(signer_hash).or_default() += 1;
        inner.total += 1;
        Ok(())
    }

    /// [`Self::check`] with the error as an [`AppError`].
    pub fn check_and_insert(
        &self,
        signer: &str,
        id: &str,
        issued_at: Option<DateTime<Utc>>,
    ) -> Result<(), AppError> {
        self.check(signer, id, issued_at).map_err(AppError::from)
    }

    /// Number of records currently held.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).total
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn first_insert_succeeds_and_duplicate_is_refused() {
        let cache = ReplayCache::new();
        let now = Some(Utc::now());
        cache.check("did:example:a", "msg-1", now).unwrap();
        assert_eq!(
            cache.check("did:example:a", "msg-1", now),
            Err(ReplayError::Duplicate)
        );
        let err = cache
            .check_and_insert("did:example:a", "msg-1", now)
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("replay-detected")));
    }

    #[test]
    fn distinct_signer_or_id_accepted() {
        let cache = ReplayCache::new();
        cache.check_at("did:example:a", "msg-1", NOW, NOW).unwrap();
        cache.check_at("did:example:a", "msg-2", NOW, NOW).unwrap();
        cache.check_at("did:example:b", "msg-1", NOW, NOW).unwrap();
        // The signer/id boundary is part of the hash: these differ.
        cache.check_at("did:example:a", "bmsg-1", NOW, NOW).unwrap();
        cache.check_at("did:example:ab", "msg-1", NOW, NOW).unwrap();
        assert_eq!(cache.len(), 5);
    }

    /// A record is remembered for as long as its `issuedAt` is inside the
    /// window, then its bucket is dropped and the cache refuses the document
    /// as stale instead.
    #[test]
    fn a_record_is_kept_while_its_issued_at_is_in_the_window() {
        let cache = ReplayCache::new();
        cache.check_at("did:example:a", "msg-1", NOW, NOW).unwrap();
        let last = NOW + FRESHNESS_WINDOW_SECS + CLOCK_MARGIN_SECS;
        assert_eq!(
            cache.check_at("did:example:a", "msg-1", NOW, last),
            Err(ReplayError::Duplicate),
            "still inside the window"
        );
        assert_eq!(
            cache.check_at("did:example:a", "msg-1", NOW, last + BUCKET_SECS),
            Err(ReplayError::Stale),
            "out of the window: refused as stale, not accepted again"
        );
        cache
            .check_at(
                "did:example:a",
                "msg-2",
                last + BUCKET_SECS,
                last + BUCKET_SECS,
            )
            .unwrap();
        assert_eq!(cache.len(), 1, "the expired bucket was dropped");
    }

    #[test]
    fn an_issued_at_outside_the_window_is_stale() {
        let cache = ReplayCache::new();
        let too_old = NOW - FRESHNESS_WINDOW_SECS - CLOCK_MARGIN_SECS - 1;
        let too_new = NOW + FUTURE_SKEW_SECS + CLOCK_MARGIN_SECS + 1;
        for t in [too_old, too_new] {
            assert_eq!(
                cache.check_at("did:example:a", "m", t, NOW),
                Err(ReplayError::Stale)
            );
        }
        assert_eq!(
            cache.check("did:example:a", "m", None),
            Err(ReplayError::Stale)
        );
        assert!(cache.is_empty());
    }

    /// At a bound the cache refuses rather than forgets: a remembered record is
    /// never pushed out by new ones, so it can never be replayed.
    #[test]
    fn a_full_signer_is_refused_and_nothing_is_forgotten() {
        let cache = ReplayCache::with_config(ReplayConfig {
            max_entries: 10_000,
            max_entries_per_signer: 500,
        })
        .unwrap();
        for i in 0..500 {
            cache
                .check_at("did:flood", &i.to_string(), NOW, NOW)
                .unwrap();
        }
        assert_eq!(
            cache.check_at("did:flood", "one-more", NOW, NOW),
            Err(ReplayError::Full)
        );
        assert_eq!(
            cache.check_at("did:flood", "0", NOW, NOW),
            Err(ReplayError::Duplicate),
            "the oldest record is still remembered"
        );
        // Another signer is unaffected by one signer's flood.
        cache.check_at("did:other", "x", NOW, NOW).unwrap();
    }

    /// Busy signers fill the shared part of the pool; a quiet signer still
    /// gets in through the reserve, and the hard bound still holds.
    #[test]
    fn the_reserve_keeps_room_for_quiet_signers() {
        let cache = ReplayCache::with_config(ReplayConfig {
            max_entries: 1_000,
            max_entries_per_signer: 450,
        })
        .unwrap();
        for (signer, n) in [("did:busy-1", 450), ("did:busy-2", 400)] {
            for i in 0..n {
                cache.check_at(signer, &i.to_string(), NOW, NOW).unwrap();
            }
        }
        // 850 held; the shared part is 900 (1,000 less a 10% reserve). A new
        // signer may continue into the reserve until it is no longer small.
        let mut busy3 = 0;
        while cache
            .check_at("did:busy-3", &busy3.to_string(), NOW, NOW)
            .is_ok()
        {
            busy3 += 1;
        }
        assert_eq!(busy3, SMALL_SIGNER_RECORDS);
        assert_eq!(cache.len(), 950);
        // A busy signer under its own bound is held to the shared part...
        assert_eq!(
            cache.check_at("did:busy-2", "more", NOW, NOW),
            Err(ReplayError::Full)
        );
        // ...while a quiet one still gets in.
        cache.check_at("did:quiet", "x", NOW, NOW).unwrap();
    }

    #[test]
    fn the_global_bound_refuses_new_records() {
        let cache = ReplayCache::with_config(ReplayConfig {
            max_entries: 1_000,
            max_entries_per_signer: 1_000,
        })
        .unwrap();
        for i in 0..1_000 {
            let signer = format!("did:s{}", i % 100);
            // Ten records each: every signer stays small, so all of the
            // reserve is usable too.
            cache.check_at(&signer, &i.to_string(), NOW, NOW).unwrap();
        }
        assert_eq!(
            cache.check_at("did:fresh", "x", NOW, NOW),
            Err(ReplayError::Full)
        );
    }

    #[test]
    fn configured_bounds_replace_the_defaults() {
        let cache = ReplayCache::with_config(ReplayConfig {
            max_entries: 3,
            max_entries_per_signer: 2,
        })
        .unwrap();
        cache.check_at("did:a", "1", NOW, NOW).unwrap();
        cache.check_at("did:a", "2", NOW, NOW).unwrap();
        assert_eq!(
            cache.check_at("did:a", "3", NOW, NOW),
            Err(ReplayError::Full)
        );
        cache.check_at("did:b", "1", NOW, NOW).unwrap();
        assert_eq!(
            cache.check_at("did:c", "1", NOW, NOW),
            Err(ReplayError::Full)
        );
    }

    #[test]
    fn an_invalid_config_is_refused() {
        let zero = ReplayConfig {
            max_entries: 0,
            max_entries_per_signer: 0,
        };
        assert!(ReplayCache::with_config(zero).is_err());
    }

    /// Records are a fixed size whatever the DID and id lengths.
    #[test]
    fn records_are_compact() {
        let cache = ReplayCache::new();
        let long_did = format!(
            "did:webvh:{}:example.com:{}",
            "Q".repeat(46),
            "path/".repeat(20)
        );
        for i in 0..10_000 {
            cache
                .check_at(&long_did, &format!("urn:uuid:{i:032}"), NOW, NOW)
                .unwrap();
        }
        let inner = cache.inner.lock().unwrap();
        let bucket = inner.buckets.values().next().unwrap();
        assert!(
            bucket.records.capacity() * std::mem::size_of::<u128>() < 10_000 * BYTES_PER_RECORD
        );
    }

    #[test]
    fn a_full_cache_tells_the_caller_when_to_retry() {
        let trust_tasks_rs::RejectReason::Unavailable {
            retry_after: Some(at),
        } = ReplayError::Full.reject_reason()
        else {
            panic!("a full cache must be unavailable with a retry time");
        };
        assert!(at > Utc::now());
        assert_eq!(
            AppError::from(ReplayError::Full).retry_after_secs(),
            Some(FULL_RETRY_AFTER_SECS)
        );
    }

    #[test]
    fn a_released_record_can_be_sent_again_and_only_once() {
        let cache = ReplayCache::new();
        let at = Some(Utc::now());
        assert_eq!(cache.check("did:example:a", "urn:1", at), Ok(()));
        assert_eq!(
            cache.check("did:example:a", "urn:1", at),
            Err(ReplayError::Duplicate)
        );
        cache.release("did:example:a", "urn:1", at);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.check("did:example:a", "urn:1", at), Ok(()));
        assert_eq!(
            cache.check("did:example:a", "urn:1", at),
            Err(ReplayError::Duplicate)
        );
        // Releasing what was never recorded changes nothing.
        cache.release("did:example:b", "urn:1", at);
        assert_eq!(cache.len(), 1);
    }
}

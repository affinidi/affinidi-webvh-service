//! Anti-replay cache for inbound DIDComm messages.
//!
//! Both DIDComm transports — the framework router and the HTTP-signed
//! `POST /api/didcomm` endpoint — verify message freshness via
//! `created_time` ± a 5-minute window in `did-hosting-common::server::didcomm_unpack`.
//! That alone doesn't prevent replay: a captured signed envelope can be
//! re-submitted within the freshness window and will pass the freshness
//! check (the signature is still valid, the `created_time` still in
//! range), letting an attacker re-trigger state-changing operations
//! (`MSG_DELETE`, `MSG_DID_CHANGE_OWNER`, `MSG_DID_PUBLISH`).
//!
//! This module adds an in-memory `(sender, msg.id)` cache keyed by
//! `(String, String)`. Both transports call `check_and_insert` after
//! sender verification but before dispatch; replays surface as
//! `e.p.did.replay-detected`. TTL = the freshness window
//! (`FRESHNESS_WINDOW_SECS`), so any pair that's still in the cache is
//! one that the freshness gate would still accept.
//!
//! # Sizing
//!
//! At 100 msg/s sustained throughput × 300 s window = ~30k entries.
//! `MAX_ENTRIES` caps the map at 50k — when the cap is hit, the oldest
//! 5% are evicted in one pass. That degrades us to "freshness-only"
//! replay protection under flood (an attacker can force eviction and
//! then replay); accept that — the alternative is unbounded memory
//! growth, which is worse.
//!
//! Restart wipes the cache. The 5-minute TTL bounds the window in which
//! a captured envelope captured pre-restart can be replayed post-
//! restart; keeping the cache in memory only is intentional.

use std::collections::HashMap;
use std::sync::Mutex;

use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::didcomm_unpack::FRESHNESS_WINDOW_SECS;

use crate::error::AppError;

/// Hard cap on the number of `(sender, msg_id)` entries the cache
/// retains. Once exceeded, the oldest 5% are dropped in one pass.
/// Tuned for ~100 msg/s sustained throughput at the
/// `FRESHNESS_WINDOW_SECS` TTL (~30k steady-state); the headroom
/// covers brief throughput spikes without forcing eviction.
const MAX_ENTRIES: usize = 50_000;

/// Fraction of `MAX_ENTRIES` evicted when the cap is hit. 5% leaves
/// the cache mostly full so the next eviction isn't far away (avoids
/// the quadratic-ish cost of evicting one entry at a time on every
/// subsequent insert under sustained pressure).
const EVICT_FRACTION_NUMERATOR: usize = 5;
const EVICT_FRACTION_DENOMINATOR: usize = 100;

/// `(sender_did, msg_id)` keys to insert-time epoch. The map is
/// guarded by a single `Mutex` because all access is short and
/// non-async. Lock contention scales with the inbound DIDComm message
/// rate, which is per-process and bounded.
#[derive(Debug, Default)]
pub struct ReplayCache {
    entries: Mutex<HashMap<(String, String), u64>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reject the message if `(sender, msg_id)` was seen within the
    /// freshness window; otherwise record it.
    ///
    /// Returns `Err(AppError::Validation)` tagged so
    /// `AppError::didcomm_code()` emits `e.p.did.replay-detected` (a new
    /// code; mapped via the generic validation path, with a
    /// distinguishable comment).
    ///
    /// The Mutex is held only for the lookup + maybe-prune + insert;
    /// no awaits occur while it is held.
    pub fn check_and_insert(&self, sender: &str, msg_id: &str) -> Result<(), AppError> {
        let now = now_epoch();
        let key = (sender.to_string(), msg_id.to_string());

        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Replay check: the same (sender, msg_id) within the window?
        if let Some(&seen_at) = guard.get(&key)
            && now.saturating_sub(seen_at) <= FRESHNESS_WINDOW_SECS
        {
            return Err(AppError::Validation(format!(
                "duplicate DIDComm message id from {} (replay-detected)",
                sender
            )));
        }

        // Prune expired entries opportunistically. O(n) but bounded by
        // MAX_ENTRIES; cheap relative to the cost of a real DIDComm
        // request.
        guard.retain(|_, &mut ts| now.saturating_sub(ts) <= FRESHNESS_WINDOW_SECS);

        // If still at the cap (e.g. inbound rate is high enough that
        // pruning didn't free anything), drop the oldest 5% to keep
        // the map bounded. Under sustained flood this degrades to
        // freshness-only protection — acceptable per the module doc.
        if guard.len() >= MAX_ENTRIES {
            let evict_count = MAX_ENTRIES * EVICT_FRACTION_NUMERATOR / EVICT_FRACTION_DENOMINATOR;
            let mut by_age: Vec<((String, String), u64)> =
                guard.iter().map(|(k, &v)| (k.clone(), v)).collect();
            by_age.sort_by_key(|(_, ts)| *ts);
            for (k, _) in by_age.into_iter().take(evict_count) {
                guard.remove(&k);
            }
        }

        guard.insert(key, now);
        Ok(())
    }

    /// Number of entries currently held. Test-only — production code
    /// has no use for it.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Test-only companion to `len` — clippy demands it.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_insert_succeeds() {
        let cache = ReplayCache::new();
        cache.check_and_insert("did:example:a", "msg-1").unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn duplicate_within_window_rejected() {
        let cache = ReplayCache::new();
        cache.check_and_insert("did:example:a", "msg-1").unwrap();
        let err = cache
            .check_and_insert("did:example:a", "msg-1")
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("replay-detected")));
    }

    /// Distinct `(sender, msg_id)` pairs do not collide. Specifically:
    /// same sender + different msg_id, and different sender + same
    /// msg_id, both accepted. Pinning this prevents a regression where
    /// one component accidentally becomes the sole cache key.
    #[test]
    fn distinct_sender_or_msg_id_accepted() {
        let cache = ReplayCache::new();
        cache.check_and_insert("did:example:a", "msg-1").unwrap();
        cache.check_and_insert("did:example:a", "msg-2").unwrap();
        cache.check_and_insert("did:example:b", "msg-1").unwrap();
        assert_eq!(cache.len(), 3);
    }

    /// Manually inject an expired entry by predating its timestamp,
    /// then assert that `check_and_insert` accepts a re-submission of
    /// the same key. This pins the TTL gate without sleeping for 5
    /// minutes in a unit test.
    #[test]
    fn expired_entry_can_be_re_inserted() {
        let cache = ReplayCache::new();
        let key = ("did:example:a".to_string(), "msg-1".to_string());
        // Pre-seed an entry that's older than the window.
        {
            let mut guard = cache.entries.lock().unwrap();
            guard.insert(
                key.clone(),
                now_epoch().saturating_sub(FRESHNESS_WINDOW_SECS + 60),
            );
        }
        // Now the same pair should be accepted (replayed past the window).
        cache.check_and_insert(&key.0, &key.1).unwrap();
    }

    /// Eviction kicks in when the cache hits MAX_ENTRIES. Pre-seeds
    /// MAX_ENTRIES - 1 entries with current timestamps (so the prune
    /// pass doesn't drop any), then inserts one more. The cap holds
    /// because no expired entries exist; the EVICT_FRACTION pass
    /// drops the oldest ~5% before the new one lands. Caps an
    /// unbounded-memory footgun under sustained-novel-id flood.
    #[test]
    fn flood_evicts_oldest_to_stay_under_cap() {
        let cache = ReplayCache::new();
        // Inject MAX_ENTRIES with strictly-monotonic timestamps so the
        // sort order is deterministic.
        {
            let mut guard = cache.entries.lock().unwrap();
            let base = now_epoch();
            for i in 0..MAX_ENTRIES {
                guard.insert((format!("did:flood:{i}"), "x".to_string()), base + i as u64);
            }
        }
        assert_eq!(cache.len(), MAX_ENTRIES);

        // One more insert triggers the eviction branch.
        cache.check_and_insert("did:flood:fresh", "x").unwrap();
        let evict = MAX_ENTRIES * EVICT_FRACTION_NUMERATOR / EVICT_FRACTION_DENOMINATOR;
        let expected_after = MAX_ENTRIES - evict + 1; // +1 = new insert
        assert_eq!(cache.len(), expected_after);
    }
}

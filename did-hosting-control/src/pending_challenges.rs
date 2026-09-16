//! Bounded set of live DID authentication challenges.
//!
//! `POST /api/auth/challenge` is unauthenticated — anyone who can reach the
//! endpoint can ask for a challenge for any DID. Two caps bound it:
//!
//! 1. **Per DID** (`MAX_PENDING_CHALLENGES_PER_DID` in `routes::auth`): no DID
//!    holds more than that many live challenges.
//! 2. **Global** ([`MAX_GLOBAL_PENDING`]): an attacker sweeping millions of
//!    distinct DIDs cannot accumulate per-DID-cap × N challenges.
//!
//! Both are O(1) in the session population, which is why this lives in memory
//! instead of scanning `session:` per request (review SM3).
//!
//! ## What is counted: live challenges, which expire by themselves
//!
//! The tracker holds the **set** of challenges it issued, each with the instant
//! its `challenge_ttl` runs out, and counts the members that have not yet run
//! out. A challenge leaves the set when
//!
//! - it **authenticates** ([`PendingChallengeTracker::release_session`], keyed
//!   by the session id — releasing one that is already gone is a no-op, so
//!   there is nothing to underflow), or
//! - its **TTL passes**. Nothing has to tell the tracker: an expired member is
//!   not counted and is pruned on the next call.
//!
//! An earlier version mirrored the set as two counters incremented on issue and
//! decremented on successful authentication only. Every other way a challenge
//! ends — expiring unused, being issued to a DID with no ACL entry (the
//! canonical handler answers those without persisting anything), or being
//! authenticated over a different binding than it was issued on — left its
//! slot taken until restart. Ten abandoned challenges locked a DID out for
//! good, and ~10,000 locked out the whole control plane: an unauthenticated
//! denial of service. Expiry is now a property of the member, not an event
//! someone must remember to deliver, so a missed release can over-count for at
//! most `challenge_ttl` and never longer.
//!
//! A failed authentication does not consume the challenge — the canonical
//! handler leaves the `ChallengeSent` row in place, so the caller may retry
//! within the TTL — and so it deliberately does not release the slot either.
//!
//! ## Why the TTL and not the session sweep
//!
//! The `ChallengeSent` row outlives its TTL until the session sweep runs
//! (`session_cleanup_interval`), but the canonical authenticate handler refuses
//! it once `challenge_ttl` has passed. A challenge past its TTL can never be
//! redeemed, so it is not pending, and holding its slot until the sweep would
//! stretch a lockout by up to the sweep interval for nothing.
//!
//! ## Restart
//!
//! The set is in memory; the rows are in the store. At boot
//! [`PendingChallengeTracker::seed_from_sessions`] reloads the still-redeemable
//! `ChallengeSent` rows, so a restart neither forgets live challenges (which
//! would let a caller exceed the caps across a restart) nor inherits phantom
//! ones.
//!
//! ## Retry-After
//!
//! A refusal names exactly when a slot frees: the moment the oldest counted
//! challenge (for the DID, or globally) passes its TTL. That is known here, so
//! the hint is computed rather than configured.
//!
//! Out of scope: IP-level rate limiting — see `crate::rate_limit`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use did_hosting_common::server::auth::session::{Session, SessionState, now_epoch};
use did_hosting_common::server::config::AuthConfig;
use tracing::{info, warn};

use crate::error::{AppError, LIMITER_PENDING_CHALLENGES_PER_DID};
use crate::store::KeyspaceHandle;

/// The `limiter` a refusal on the global cap names in its 429 body. The
/// per-DID refusal shares [`LIMITER_PENDING_CHALLENGES_PER_DID`] with the
/// canonical handler's cap on the other binaries: it is the same limit.
pub const LIMITER_GLOBAL: &str = "auth-challenge-pending-global";

/// Hard cap on the total number of live challenges across all DIDs. Defends
/// against an attacker sweeping many distinct DIDs to accumulate per-DID-cap ×
/// N entries; once reached, all new issuance is refused until one expires or
/// authenticates.
///
/// Sized for a generous-but-bounded operator footprint: 10_000 concurrent
/// challenges = ~10x the per-DID cap × 1000 distinct DIDs in flight at once.
pub const MAX_GLOBAL_PENDING: usize = 10_000;

/// Where the tracker reads the time from. Injectable so a test can move a
/// challenge past its TTL without sleeping through it.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// A slot reserved by [`PendingChallengeTracker::try_issue`], to be attached to
/// the session id the challenge was minted under
/// ([`PendingChallengeTracker::bind`]) or handed back if minting failed
/// ([`PendingChallengeTracker::cancel`]). Dropping one unused is not a leak:
/// the slot expires with the TTL like any other.
#[must_use = "bind the reservation to the issued session id, or cancel it"]
#[derive(Debug)]
pub struct Reservation {
    id: u64,
}

#[derive(Debug)]
struct Entry {
    did: String,
    session_id: Option<String>,
}

#[derive(Debug, Default)]
struct Inner {
    next_id: u64,
    /// The live set. Its length is the global count.
    entries: HashMap<u64, Entry>,
    /// Session id → entry, for release on authentication.
    by_session: HashMap<String, u64>,
    /// Live entries per DID in expiry order. The deque's length is the per-DID
    /// count; a DID with none has no key, so the map does not grow with every
    /// DID ever seen.
    per_did: HashMap<String, VecDeque<(Instant, u64)>>,
    /// Every issued entry in expiry order. May hold ids already released;
    /// those are skipped when they reach the front.
    expiry: VecDeque<(Instant, u64)>,
}

impl Inner {
    fn remove(&mut self, id: u64) -> bool {
        let Some(entry) = self.entries.remove(&id) else {
            return false;
        };
        if let Some(sid) = entry.session_id {
            self.by_session.remove(&sid);
        }
        if let Some(q) = self.per_did.get_mut(&entry.did) {
            q.retain(|(_, qid)| *qid != id);
            if q.is_empty() {
                self.per_did.remove(&entry.did);
            }
        }
        true
    }

    /// Drop every entry whose TTL has passed, and any already-released ids at
    /// the front of the expiry queue.
    fn prune(&mut self, now: Instant) {
        while let Some(&(expires_at, id)) = self.expiry.front() {
            let live = self.entries.contains_key(&id);
            if live && expires_at > now {
                break;
            }
            self.expiry.pop_front();
            if live {
                self.remove(id);
            }
        }
    }

    fn insert(&mut self, did: &str, expires_at: Instant, session_id: Option<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(sid) = &session_id {
            self.by_session.insert(sid.clone(), id);
        }
        self.entries.insert(
            id,
            Entry {
                did: did.to_string(),
                session_id,
            },
        );
        insert_sorted(
            self.per_did.entry(did.to_string()).or_default(),
            expires_at,
            id,
        );
        insert_sorted(&mut self.expiry, expires_at, id);
        id
    }
}

/// Insert keeping the queue in expiry order. Issuance always appends (a later
/// issue expires later), so this is O(1) on the hot path; only boot seeding
/// lands anywhere else.
fn insert_sorted(q: &mut VecDeque<(Instant, u64)>, expires_at: Instant, id: u64) {
    let pos = q.partition_point(|(e, _)| *e <= expires_at);
    q.insert(pos, (expires_at, id));
}

/// Whole seconds until `at`, rounded up and never below 1 — a `Retry-After` of
/// 0 invites an immediate retry that is still refused.
fn secs_until(at: Instant, now: Instant) -> u64 {
    let d = at.saturating_duration_since(now);
    let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
    secs.max(1)
}

/// In-memory set of live challenges. See the module docs.
pub struct PendingChallengeTracker {
    inner: Mutex<Inner>,
    challenge_ttl: Duration,
    global_cap: usize,
    clock: Clock,
}

impl std::fmt::Debug for PendingChallengeTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingChallengeTracker")
            .field("challenge_ttl", &self.challenge_ttl)
            .field("global_cap", &self.global_cap)
            .finish_non_exhaustive()
    }
}

impl Default for PendingChallengeTracker {
    /// The default `challenge_ttl` and global cap. Production builds the
    /// tracker from its configuration with [`Self::for_auth_config`].
    fn default() -> Self {
        Self::for_auth_config(&AuthConfig::default())
    }
}

impl PendingChallengeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// A tracker whose challenges live for the configured `challenge_ttl` —
    /// the same bound the authenticate handler enforces.
    pub fn for_auth_config(auth: &AuthConfig) -> Self {
        Self::with_clock(
            Duration::from_secs(auth.challenge_ttl),
            MAX_GLOBAL_PENDING,
            Arc::new(Instant::now),
        )
    }

    pub fn with_clock(challenge_ttl: Duration, global_cap: usize, clock: Clock) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            challenge_ttl,
            global_cap,
            clock,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // No code path panics while holding the lock, but a poisoned tracker
        // must not take authentication down with it: the set is still sound.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reserve a slot for a challenge to `did`.
    ///
    /// Refused with [`AppError::RateLimited`] when the DID already holds
    /// `per_did_cap` live challenges or the global cap is reached. The
    /// refusal's `retry_after_secs` is when the oldest counted challenge
    /// expires — the earliest moment a retry can succeed. On refusal nothing
    /// is reserved.
    pub fn try_issue(&self, did: &str, per_did_cap: usize) -> Result<Reservation, AppError> {
        let now = (self.clock)();
        let mut inner = self.lock();
        inner.prune(now);

        // Global first: the cheaper rejection for the likeliest attack shape
        // (a sweep of distinct DIDs).
        if inner.entries.len() >= self.global_cap {
            let retry_after_secs = inner
                .expiry
                .front()
                .map_or(1, |(expires_at, _)| secs_until(*expires_at, now));
            return Err(AppError::RateLimited {
                limiter: LIMITER_GLOBAL,
                message: format!(
                    "global pending-challenge cap reached ({} concurrent); try again later",
                    self.global_cap,
                ),
                retry_after_secs,
            });
        }
        if let Some(q) = inner.per_did.get(did)
            && q.len() >= per_did_cap
        {
            let retry_after_secs = q
                .front()
                .map_or(1, |(expires_at, _)| secs_until(*expires_at, now));
            return Err(AppError::RateLimited {
                limiter: LIMITER_PENDING_CHALLENGES_PER_DID,
                message: format!(
                    "too many pending challenges for this DID (>= {per_did_cap}); try again later",
                ),
                retry_after_secs,
            });
        }

        let id = inner.insert(did, now + self.challenge_ttl, None);
        Ok(Reservation { id })
    }

    /// Attach the session id the challenge was issued under, so a successful
    /// authentication can release exactly this slot.
    pub fn bind(&self, reservation: Reservation, session_id: &str) {
        let mut inner = self.lock();
        let Inner {
            entries,
            by_session,
            ..
        } = &mut *inner;
        // Already expired (a TTL shorter than minting took): nothing to bind.
        if let Some(entry) = entries.get_mut(&reservation.id) {
            entry.session_id = Some(session_id.to_string());
            by_session.insert(session_id.to_string(), reservation.id);
        }
    }

    /// Hand back a slot whose challenge was never issued.
    pub fn cancel(&self, reservation: Reservation) {
        self.lock().remove(reservation.id);
    }

    /// Release the slot of the challenge issued under `session_id`, because it
    /// authenticated. Idempotent: a session this tracker does not hold (already
    /// released, expired, or issued before a restart that did not seed it) is a
    /// no-op, so a double release cannot free someone else's slot.
    pub fn release_session(&self, session_id: &str) -> bool {
        let now = (self.clock)();
        let mut inner = self.lock();
        inner.prune(now);
        match inner.by_session.get(session_id).copied() {
            Some(id) => inner.remove(id),
            None => false,
        }
    }

    /// Reload the still-redeemable `ChallengeSent` rows from the session store,
    /// so the caps hold across a restart. Call once at boot, before serving.
    ///
    /// A row is redeemable while `now - created_at <= challenge_ttl` (the
    /// authenticate handler's rule); older rows are left for the session sweep.
    /// Seeding ignores the caps: these challenges were already issued.
    pub async fn seed_from_sessions(&self, sessions: &KeyspaceHandle) -> Result<usize, AppError> {
        let rows = sessions.prefix_iter_raw("session:").await?;
        let now_epoch = now_epoch();
        let now = (self.clock)();
        let ttl = self.challenge_ttl.as_secs();
        let mut inner = self.lock();
        let mut seeded = 0usize;
        for (_key, value) in rows {
            let Ok(session) = serde_json::from_slice::<Session>(&value) else {
                continue;
            };
            if session.state != SessionState::ChallengeSent {
                continue;
            }
            let expires_epoch = session.created_at.saturating_add(ttl);
            if expires_epoch < now_epoch {
                continue;
            }
            if inner.by_session.contains_key(&session.session_id) {
                continue;
            }
            // `+ 1`: the handler accepts the whole final second (`>` not `>=`).
            let remaining = Duration::from_secs(expires_epoch - now_epoch + 1);
            inner.insert(&session.did, now + remaining, Some(session.session_id));
            seeded += 1;
        }
        Ok(seeded)
    }

    /// [`Self::seed_from_sessions`], logging instead of failing: a tracker that
    /// could not be seeded under-counts for at most one `challenge_ttl`, which
    /// is no reason to refuse to start.
    pub async fn seed_from_sessions_or_warn(&self, sessions: &KeyspaceHandle) {
        match self.seed_from_sessions(sessions).await {
            Ok(n) => info!(
                seeded = n,
                "pending-challenge tracker seeded from session store"
            ),
            Err(e) => {
                warn!(error = %e, "could not seed pending-challenge tracker from session store")
            }
        }
    }

    /// Live challenges held for `did`.
    pub fn count_for(&self, did: &str) -> usize {
        let now = (self.clock)();
        let mut inner = self.lock();
        inner.prune(now);
        inner.per_did.get(did).map_or(0, VecDeque::len)
    }

    /// Live challenges across all DIDs.
    pub fn global_count(&self) -> usize {
        let now = (self.clock)();
        let mut inner = self.lock();
        inner.prune(now);
        inner.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(30);

    /// A clock the test moves by hand.
    fn manual_clock() -> (Clock, Arc<Mutex<Instant>>) {
        let t = Arc::new(Mutex::new(Instant::now()));
        let c = t.clone();
        (Arc::new(move || *c.lock().unwrap()), t)
    }

    fn advance(t: &Mutex<Instant>, d: Duration) {
        *t.lock().unwrap() += d;
    }

    fn tracker(global_cap: usize) -> (PendingChallengeTracker, Arc<Mutex<Instant>>) {
        let (clock, t) = manual_clock();
        (
            PendingChallengeTracker::with_clock(TTL, global_cap, clock),
            t,
        )
    }

    fn issue(t: &PendingChallengeTracker, did: &str, cap: usize, sid: &str) {
        let r = t.try_issue(did, cap).expect("under the cap");
        t.bind(r, sid);
    }

    #[test]
    fn issues_within_caps() {
        let (t, _) = tracker(100);
        for i in 0..5 {
            issue(&t, "did:example:a", 10, &format!("s{i}"));
        }
        assert_eq!(t.count_for("did:example:a"), 5);
        assert_eq!(t.global_count(), 5);
    }

    #[test]
    fn per_did_cap_rejects_excess_with_the_time_until_the_oldest_expires() {
        let (t, clock) = tracker(100);
        issue(&t, "did:example:a", 3, "s0");
        advance(&clock, Duration::from_secs(10));
        issue(&t, "did:example:a", 3, "s1");
        issue(&t, "did:example:a", 3, "s2");

        let err = t.try_issue("did:example:a", 3).unwrap_err();
        // The oldest was issued 10s ago with a 30s TTL: 20s until a slot frees.
        assert!(matches!(
            err,
            AppError::RateLimited {
                limiter: LIMITER_PENDING_CHALLENGES_PER_DID,
                retry_after_secs: 20,
                ..
            }
        ));
    }

    /// The regression: challenges that are never redeemed must give their
    /// slots back when they expire. Before, only a successful authentication
    /// released a slot, so this DID stayed locked out until restart.
    #[test]
    fn abandoned_challenges_free_their_per_did_slots_on_expiry() {
        let (t, clock) = tracker(100);
        for i in 0..10 {
            issue(&t, "did:example:a", 10, &format!("s{i}"));
        }
        let err = t.try_issue("did:example:a", 10).unwrap_err();
        let AppError::RateLimited {
            retry_after_secs, ..
        } = err
        else {
            panic!("expected a rate limit, got {err:?}");
        };

        // The hint is truthful: one second short, still refused ...
        advance(&clock, Duration::from_secs(retry_after_secs - 1));
        assert!(t.try_issue("did:example:a", 10).is_err());
        // ... and at the hinted moment, accepted.
        advance(&clock, Duration::from_secs(1));
        issue(&t, "did:example:a", 10, "fresh");
        assert_eq!(t.count_for("did:example:a"), 1);
        assert_eq!(t.global_count(), 1);
    }

    #[test]
    fn abandoned_challenges_free_global_slots_on_expiry() {
        let (t, clock) = tracker(5);
        for i in 0..5 {
            issue(&t, &format!("did:example:{i}"), 10, &format!("s{i}"));
        }
        let err = t.try_issue("did:example:6", 10).unwrap_err();
        assert!(matches!(
            err,
            AppError::RateLimited {
                limiter: LIMITER_GLOBAL,
                retry_after_secs: 30,
                ..
            }
        ));

        advance(&clock, TTL + Duration::from_millis(1));
        assert_eq!(t.global_count(), 0);
        issue(&t, "did:example:6", 10, "s6");
        // Emptied DIDs leave no residue in the per-DID map.
        assert_eq!(t.lock().per_did.len(), 1);
    }

    #[test]
    fn authentication_releases_exactly_its_own_slot() {
        let (t, _) = tracker(100);
        issue(&t, "did:example:a", 10, "s1");
        issue(&t, "did:example:a", 10, "s2");
        assert!(t.release_session("s1"));
        assert_eq!(t.count_for("did:example:a"), 1);
        assert_eq!(t.global_count(), 1);
        assert!(t.lock().by_session.contains_key("s2"));
    }

    /// Double release (and release after expiry) cannot underflow or free a
    /// different challenge's slot.
    #[test]
    fn double_release_is_a_noop() {
        let (t, clock) = tracker(100);
        issue(&t, "did:example:a", 10, "s1");
        issue(&t, "did:example:a", 10, "s2");
        assert!(t.release_session("s1"));
        assert!(!t.release_session("s1"));
        assert!(!t.release_session("s1"));
        assert_eq!(t.count_for("did:example:a"), 1);
        assert_eq!(t.global_count(), 1);

        advance(&clock, TTL + Duration::from_secs(1));
        assert!(!t.release_session("s2"), "already expired");
        assert_eq!(t.global_count(), 0);
    }

    #[test]
    fn release_unknown_session_is_a_noop() {
        let (t, _) = tracker(100);
        assert!(!t.release_session("never-issued"));
        assert_eq!(t.global_count(), 0);
    }

    #[test]
    fn cancel_hands_the_slot_back() {
        let (t, _) = tracker(1);
        let r = t.try_issue("did:example:a", 10).unwrap();
        t.cancel(r);
        assert_eq!(t.global_count(), 0);
        issue(&t, "did:example:b", 10, "s");
    }

    /// Released ids left in the expiry queue do not hold slots or distort the
    /// global retry hint.
    #[test]
    fn released_entries_do_not_linger_in_the_expiry_queue() {
        let (t, clock) = tracker(2);
        issue(&t, "did:example:a", 10, "old");
        advance(&clock, Duration::from_secs(10));
        issue(&t, "did:example:b", 10, "mid");
        assert!(t.release_session("old"));
        issue(&t, "did:example:c", 10, "new");

        let err = t.try_issue("did:example:d", 10).unwrap_err();
        // Oldest *live* entry is "mid", issued at +10s with TTL 30s, now +10s.
        assert!(matches!(
            err,
            AppError::RateLimited {
                limiter: LIMITER_GLOBAL,
                retry_after_secs: 30,
                ..
            }
        ));
    }

    #[test]
    fn retry_after_rounds_up_and_is_at_least_one() {
        let now = Instant::now();
        assert_eq!(secs_until(now, now), 1);
        assert_eq!(secs_until(now + Duration::from_millis(1), now), 1);
        assert_eq!(secs_until(now + Duration::from_millis(1001), now), 2);
        assert_eq!(secs_until(now + Duration::from_secs(5), now), 5);
    }
}

#[cfg(all(test, feature = "store-fjall"))]
mod seed_tests {
    use super::*;
    use did_hosting_common::server::auth::session::store_session;
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::store::{KS_SESSIONS, Store};

    fn row(session_id: &str, did: &str, state: SessionState, created_at: u64) -> Session {
        Session {
            session_id: session_id.into(),
            did: did.into(),
            challenge: "c".into(),
            state,
            created_at,
            last_seen: created_at,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            token_id: None,
            session_pubkey_b58btc: None,
            amr: vec![],
            acr: String::new(),
            acr_expires_at: None,
        }
    }

    /// A restart must neither forget live challenges nor inherit dead ones.
    #[tokio::test]
    async fn seeding_reloads_only_redeemable_challenges() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .unwrap();
        let ks = store.keyspace(KS_SESSIONS).unwrap();
        let now = now_epoch();
        let did = "did:example:a";
        for i in 0..3 {
            store_session(
                &ks,
                &row(&format!("live{i}"), did, SessionState::ChallengeSent, now),
            )
            .await
            .unwrap();
        }
        store_session(
            &ks,
            &row("stale", did, SessionState::ChallengeSent, now - 3600),
        )
        .await
        .unwrap();
        store_session(&ks, &row(did, did, SessionState::Authenticated, now))
            .await
            .unwrap();

        let t = PendingChallengeTracker::with_clock(
            Duration::from_secs(30),
            100,
            Arc::new(Instant::now),
        );
        assert_eq!(t.seed_from_sessions(&ks).await.unwrap(), 3);
        assert_eq!(t.count_for(did), 3);
        // Seeded slots are held under their session ids: authenticating one
        // after the restart releases it.
        assert!(t.release_session("live0"));
        assert_eq!(t.count_for(did), 2);
        // Seeding twice does not double count.
        assert_eq!(t.seed_from_sessions(&ks).await.unwrap(), 1);
        assert_eq!(t.count_for(did), 3);
    }
}

//! Bounded set of live DID authentication challenges.
//!
//! `POST /api/auth/challenge` is unauthenticated — anyone who can reach the
//! endpoint can ask for a challenge for any DID. Two caps bound it:
//!
//! 1. **Per DID** (`MAX_PENDING_CHALLENGES_PER_DID` in `routes::auth`): no DID
//!    holds more than that many live challenges. At the cap the oldest bound
//!    challenge is evicted to make room, not the new one refused — see
//!    [`PendingChallengeTracker::try_issue`].
//! 2. **Global** ([`MAX_GLOBAL_PENDING`]): an attacker sweeping millions of
//!    distinct DIDs cannot accumulate per-DID-cap × N challenges.
//!
//! Both are O(1) in the session population, which is why this lives in memory
//! instead of scanning `session:` per request (review SM3).
//!
//! Both caps are operator-configurable ([`AuthConfig::max_global_pending_challenges`]
//! and `AuthConfig::max_pending_challenges_per_did`, env
//! `*_AUTH_MAX_GLOBAL_PENDING_CHALLENGES` / `*_AUTH_MAX_PENDING_CHALLENGES_PER_DID`);
//! the defaults are [`MAX_GLOBAL_PENDING`] and
//! `routes::auth::MAX_PENDING_CHALLENGES_PER_DID`.
//!
//! ## Bounded memory (CWE-400)
//!
//! Memory cannot grow without limit. [`PendingChallengeTracker::try_issue`]
//! prunes expired members and then refuses issuance once the live set reaches
//! the global cap, *before* inserting — so every internal structure
//! (`entries`, `by_session`, `per_did`, `expiry`) is capped at the global cap.
//! Empty per-DID deques are removed rather than lingering. Refusal at the cap
//! is fail-closed by design; the per-IP limiter (`crate::rate_limit`) throttles
//! the fill rate. See the note on the global-cap check in `try_issue`.
//!
//! ## Locking (CWE-667)
//!
//! `inner` is a `std::sync::Mutex`, chosen deliberately: its guard is never
//! held across an `.await`, and doing so would fail to compile (a non-`Send`
//! future). See the notes on the `inner` field and `lock`.
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

use did_hosting_common::server::error::{AppError, LIMITER_PENDING_CHALLENGES_PER_DID};
use did_hosting_common::server::store::KeyspaceHandle;

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
    victims: Vec<Victim>,
}

impl Reservation {
    /// Session ids of the challenges marked for eviction to make room for this
    /// one. Nothing is evicted yet: see [`Eviction`].
    pub fn evicting_sessions(&self) -> Vec<&str> {
        self.victims.iter().map(Victim::session_id).collect()
    }
}

/// A challenge marked for eviction. It stays counted until
/// [`PendingChallengeTracker::complete_eviction`] — called once its row is
/// claimed, so it can no longer be redeemed — or goes back to being an
/// ordinary member on [`PendingChallengeTracker::restore_eviction`].
#[derive(Debug)]
pub struct Victim {
    id: u64,
    session_id: String,
}

impl Victim {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// The evictions a bound reservation still owes, returned by
/// [`PendingChallengeTracker::bind`]. The caller claims each victim's
/// `ChallengeSent` row and then completes or restores it. Dropping one
/// unfinished over-counts — the victims stay counted until their TTL — and
/// never under-counts.
#[must_use = "claim each victim's row, then complete or restore its eviction"]
#[derive(Debug, Default)]
pub struct Eviction {
    victims: Vec<Victim>,
}

impl Eviction {
    pub fn into_victims(self) -> Vec<Victim> {
        self.victims
    }
}

#[derive(Debug)]
struct Entry {
    did: String,
    session_id: Option<String>,
    /// Marked for eviction by a reservation whose challenge is not yet
    /// issued. Still counted (its row is still redeemable) but no longer
    /// counted *against* the cap, and not offered to another eviction.
    evicting: bool,
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

    fn restore(&mut self, id: u64) {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.evicting = false;
        }
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
                evicting: false,
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
    /// A `std::sync::Mutex` on purpose, and its guard is **never held across an
    /// `.await`** (CWE-667, improper locking). Every async method here does its
    /// awaits *before* it locks — `seed_from_sessions` reads the keyspace
    /// (`prefix_iter_raw(..).await`) and only then calls `self.lock()` — and
    /// every locked section below is purely synchronous (no `.await` between
    /// `lock()` and the guard dropping). This is not merely a convention: an
    /// `await` under this guard would make the enclosing future hold a
    /// non-`Send` `MutexGuard` across a suspend point, and the async runtime
    /// would refuse to compile it. A tokio mutex here would compile such a bug
    /// silently, so the std mutex is the stricter, deliberate choice.
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
    /// the same bound the authenticate handler enforces — and whose global cap
    /// is the configured `max_global_pending_challenges` (default
    /// [`MAX_GLOBAL_PENDING`]). The per-DID cap is applied per call by
    /// `routes::auth::issue_challenge`, which reads
    /// `max_pending_challenges_per_did` from the same config.
    pub fn for_auth_config(auth: &AuthConfig) -> Self {
        Self::with_clock(
            Duration::from_secs(auth.challenge_ttl),
            auth.max_global_pending_challenges,
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
        //
        // CWE-667: the returned guard is synchronous-only — hold it across an
        // `.await` and the future stops being `Send` and fails to compile (see
        // the note on the `inner` field). Do the keyspace read before locking.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reserve a slot for a challenge to `did`.
    ///
    /// At the per-DID cap the DID's oldest *bound* challenges are marked for
    /// eviction to make room. Refusing instead let anyone who asked for
    /// `per_did_cap` challenges in a DID's name lock its owner out of signing
    /// in for up to `challenge_ttl`, at the cost of `per_did_cap` requests per
    /// TTL. Eviction does not make the DID immune: a caller who keeps asking
    /// in its name can still evict the owner's challenge before it is signed,
    /// but has to out-pace the owner's own signing — `per_did_cap` requests
    /// inside that window, every time, from its own per-IP budget — rather
    /// than spend `per_did_cap` requests once per TTL.
    ///
    /// A victim is not evicted here. It stays counted, marked, until the
    /// caller has minted the new challenge and claimed the victim's row
    /// ([`Self::bind`], then [`Self::complete_eviction`]); a failed mint
    /// ([`Self::cancel`]) or a failed claim ([`Self::restore_eviction`]) puts
    /// it back. So the tracker never stops counting a row that can still be
    /// redeemed. Only a challenge already bound to its session can be a
    /// victim — one still being minted has no row to claim — so a newer bound
    /// challenge can go before an older one still mid-mint, and a DID whose
    /// remaining slots are all mid-mint (or already being evicted) is refused.
    ///
    /// Refused with [`AppError::RateLimited`] at the global cap, or per DID
    /// as above. The refusal's `retry_after_secs` is when the oldest counted
    /// challenge expires — the earliest moment a retry can succeed. On refusal
    /// nothing is reserved or evicted.
    pub fn try_issue(&self, did: &str, per_did_cap: usize) -> Result<Reservation, AppError> {
        let now = (self.clock)();
        let mut inner = self.lock();
        inner.prune(now);

        // CWE-400 (uncontrolled resource consumption): memory here is bounded,
        // and this check is where. `prune(now)` above drops every expired
        // member first; then issuance is refused once the live set reaches
        // `global_cap`, *before* any insert. So `entries`, `by_session`,
        // `per_did` (empty deques are removed) and `expiry` are each capped at
        // `global_cap` entries — the set cannot grow without limit. Refusing at
        // the cap is fail-closed by design (a full set rejects new challenges
        // rather than evicting live ones), and the per-IP limiter
        // (`crate::rate_limit`, 30 req / 60 s) throttles how fast the cap can be
        // approached at all.
        //
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
        // Members already being evicted are on their way out: they do not
        // count against the cap, and cannot be chosen twice.
        let mut counted = 0usize;
        let mut evictable: Vec<Victim> = Vec::new();
        if let Some(q) = inner.per_did.get(did) {
            for (_, id) in q {
                let Some(entry) = inner.entries.get(id) else {
                    continue;
                };
                if entry.evicting {
                    continue;
                }
                counted += 1;
                if let Some(sid) = &entry.session_id {
                    evictable.push(Victim {
                        id: *id,
                        session_id: sid.clone(),
                    });
                }
            }
        }
        let excess = (counted + 1).saturating_sub(per_did_cap);
        evictable.truncate(excess);
        if evictable.len() < excess {
            let retry_after_secs = inner
                .per_did
                .get(did)
                .and_then(|q| q.front())
                .map_or(1, |(expires_at, _)| secs_until(*expires_at, now));
            return Err(AppError::RateLimited {
                limiter: LIMITER_PENDING_CHALLENGES_PER_DID,
                message: format!(
                    "too many pending challenges for this DID (>= {per_did_cap}); try again later",
                ),
                retry_after_secs,
            });
        }
        for victim in &evictable {
            if let Some(entry) = inner.entries.get_mut(&victim.id) {
                entry.evicting = true;
            }
        }
        if !evictable.is_empty() {
            warn!(
                did,
                evicting = evictable.len(),
                per_did_cap,
                "per-DID challenge cap reached; evicting the oldest"
            );
        }

        let id = inner.insert(did, now + self.challenge_ttl, None);
        Ok(Reservation {
            id,
            victims: evictable,
        })
    }

    /// Attach the session id the challenge was issued under, so a successful
    /// authentication can release exactly this slot. Returns the evictions
    /// the reservation still owes: claim each victim's row, then
    /// [`Self::complete_eviction`] or [`Self::restore_eviction`] it.
    pub fn bind(&self, reservation: Reservation, session_id: &str) -> Eviction {
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
        Eviction {
            victims: reservation.victims,
        }
    }

    /// Hand back a slot whose challenge was never issued. Its victims were
    /// never claimed, so they go back to being ordinary members.
    pub fn cancel(&self, reservation: Reservation) {
        let mut inner = self.lock();
        inner.remove(reservation.id);
        for victim in &reservation.victims {
            inner.restore(victim.id);
        }
    }

    /// Drop a victim whose row has been claimed (or was already gone: it
    /// authenticated or expired first). Idempotent.
    pub fn complete_eviction(&self, victim: &Victim) {
        self.lock().remove(victim.id);
    }

    /// Put back a victim whose row could not be claimed: it may still be
    /// redeemable, so it stays counted, and may be chosen again.
    pub fn restore_eviction(&self, victim: &Victim) {
        self.lock().restore(victim.id);
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
#[path = "pending_challenges_tests.rs"]
mod tests;

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
            not_after: None,
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

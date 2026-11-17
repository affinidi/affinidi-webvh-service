//! Tests for [`super`].

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

/// Issue a challenge and settle its evictions as if every claim succeeded.
fn issue(t: &PendingChallengeTracker, did: &str, cap: usize, sid: &str) {
    let r = t.try_issue(did, cap).expect("under the cap");
    for victim in t.bind(r, sid).into_victims() {
        t.complete_eviction(&victim);
    }
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

/// At the cap the oldest issued challenge makes room; asking again in a
/// DID's name cannot lock its owner out.
#[test]
fn per_did_cap_evicts_the_oldest_issued_challenge() {
    let (t, clock) = tracker(100);
    issue(&t, "did:example:a", 3, "s0");
    advance(&clock, Duration::from_secs(1));
    issue(&t, "did:example:a", 3, "s1");
    issue(&t, "did:example:a", 3, "s2");

    let r = t
        .try_issue("did:example:a", 3)
        .expect("evicts, not refuses");
    assert_eq!(r.evicting_sessions(), ["s0"]);
    // Until its row is claimed the victim is still counted.
    assert_eq!(t.count_for("did:example:a"), 4);
    let victims = t.bind(r, "s3").into_victims();
    assert_eq!(t.count_for("did:example:a"), 4);
    for v in &victims {
        t.complete_eviction(v);
    }

    assert_eq!(t.count_for("did:example:a"), 3);
    assert_eq!(t.global_count(), 3);
    assert!(!t.release_session("s0"), "the evicted slot is gone");
    assert!(t.release_session("s3"));
}

/// A lowered cap is caught up in one issue: everything over it goes.
#[test]
fn a_lowered_cap_evicts_down_to_it() {
    let (t, _) = tracker(100);
    for i in 0..5 {
        issue(&t, "did:example:a", 10, &format!("s{i}"));
    }
    let r = t.try_issue("did:example:a", 3).unwrap();
    assert_eq!(r.evicting_sessions(), ["s0", "s1", "s2"]);
    for v in t.bind(r, "s5").into_victims() {
        t.complete_eviction(&v);
    }
    assert_eq!(t.count_for("did:example:a"), 3);
}

/// A challenge that is never minted evicts nothing: its victims go back to
/// being ordinary members, still counted and evictable again.
#[test]
fn cancel_restores_the_victims() {
    let (t, _) = tracker(100);
    for i in 0..3 {
        issue(&t, "did:example:a", 3, &format!("s{i}"));
    }
    let r = t.try_issue("did:example:a", 3).unwrap();
    assert_eq!(r.evicting_sessions(), ["s0"]);
    t.cancel(r);
    assert_eq!(t.count_for("did:example:a"), 3);

    let r = t.try_issue("did:example:a", 3).unwrap();
    assert_eq!(r.evicting_sessions(), ["s0"], "s0 is a candidate again");
    t.cancel(r);
}

/// A victim whose row could not be claimed may still be redeemable, so it
/// stays counted — the DID is over its cap rather than holding a
/// redeemable challenge the tracker forgot.
#[test]
fn a_failed_claim_keeps_the_victim_counted() {
    let (t, _) = tracker(100);
    for i in 0..3 {
        issue(&t, "did:example:a", 3, &format!("s{i}"));
    }
    let r = t.try_issue("did:example:a", 3).unwrap();
    for v in t.bind(r, "s3").into_victims() {
        t.restore_eviction(&v);
    }
    assert_eq!(t.count_for("did:example:a"), 4);
    assert!(t.release_session("s0"), "s0 is still tracked");
}

/// Two issues racing at the cap pick different victims: one already
/// being evicted is neither counted against the cap nor chosen again.
#[test]
fn concurrent_issues_evict_distinct_victims() {
    let (t, _) = tracker(100);
    for i in 0..3 {
        issue(&t, "did:example:a", 3, &format!("s{i}"));
    }
    let a = t.try_issue("did:example:a", 3).unwrap();
    let b = t.try_issue("did:example:a", 3).unwrap();
    assert_eq!(a.evicting_sessions(), ["s0"]);
    assert_eq!(b.evicting_sessions(), ["s1"]);
    for v in t
        .bind(a, "s3")
        .into_victims()
        .into_iter()
        .chain(t.bind(b, "s4").into_victims())
    {
        t.complete_eviction(&v);
    }
    assert_eq!(t.count_for("did:example:a"), 3);
}

/// A victim that authenticated before its row was claimed has already
/// released its slot; completing the eviction is then a no-op.
#[test]
fn completing_an_eviction_after_authentication_is_a_noop() {
    let (t, _) = tracker(100);
    for i in 0..3 {
        issue(&t, "did:example:a", 3, &format!("s{i}"));
    }
    let r = t.try_issue("did:example:a", 3).unwrap();
    let victims = t.bind(r, "s3").into_victims();
    assert!(t.release_session("s0"));
    for v in &victims {
        t.complete_eviction(v);
    }
    assert_eq!(t.count_for("did:example:a"), 3);
    assert!(t.release_session("s1"));
}

/// A challenge still being minted has no session to delete; evicting it
/// would let its row land untracked. With nothing bound to evict, the cap
/// still refuses — with the time until the oldest expires.
#[test]
fn per_did_cap_refuses_when_every_slot_is_still_being_minted() {
    let (t, clock) = tracker(100);
    let in_flight: Vec<Reservation> = (0..3)
        .map(|_| {
            let r = t.try_issue("did:example:a", 3).unwrap();
            advance(&clock, Duration::from_secs(5));
            r
        })
        .collect();

    let err = t.try_issue("did:example:a", 3).unwrap_err();
    // The oldest was reserved 15s ago with a 30s TTL: 15s until a slot frees.
    assert!(matches!(
        err,
        AppError::RateLimited {
            limiter: LIMITER_PENDING_CHALLENGES_PER_DID,
            retry_after_secs: 15,
            ..
        }
    ));
    assert_eq!(t.count_for("did:example:a"), 3, "nothing evicted");
    for r in in_flight {
        t.cancel(r);
    }
}

/// The regression: challenges that are never redeemed must give their
/// slots back when they expire. Before, only a successful authentication
/// released a slot, so this DID stayed locked out until restart. Shown on
/// reservations still being minted, the one case the cap still refuses.
#[test]
fn abandoned_challenges_free_their_per_did_slots_on_expiry() {
    let (t, clock) = tracker(100);
    let abandoned: Vec<Reservation> = (0..10)
        .map(|_| t.try_issue("did:example:a", 10).unwrap())
        .collect();
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
    drop(abandoned);
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

/// A custom global cap is honoured: the (cap+1)th distinct-DID challenge is
/// refused on the global limiter, whatever the cap is set to.
#[test]
fn custom_global_cap_is_honoured() {
    let (t, _) = tracker(3);
    for i in 0..3 {
        issue(&t, &format!("did:example:{i}"), 10, &format!("s{i}"));
    }
    assert_eq!(t.global_count(), 3);
    let err = t.try_issue("did:example:over", 10).unwrap_err();
    assert!(matches!(
        err,
        AppError::RateLimited {
            limiter: LIMITER_GLOBAL,
            ..
        }
    ));
}

/// `for_auth_config` plumbs the configured `max_global_pending_challenges`
/// into the tracker (not the compiled-in default).
#[test]
fn for_auth_config_uses_the_configured_global_cap() {
    let auth = AuthConfig {
        max_global_pending_challenges: 2,
        ..AuthConfig::default()
    };
    let t = PendingChallengeTracker::for_auth_config(&auth);
    // The per-DID cap is high, so only the global cap can bite.
    let _ = t.bind(t.try_issue("did:example:a", 100).unwrap(), "s0");
    let _ = t.bind(t.try_issue("did:example:b", 100).unwrap(), "s1");
    let err = t.try_issue("did:example:c", 100).unwrap_err();
    assert!(matches!(
        err,
        AppError::RateLimited {
            limiter: LIMITER_GLOBAL,
            ..
        }
    ));
}

/// The config defaults must equal the compiled-in constants that document
/// them, across the crate boundary (the constants live here; the config
/// defaults live in the lower did-hosting-common crate, which cannot
/// reference them). This test is the pin that keeps the two in step.
#[test]
fn config_defaults_match_constants() {
    let auth = AuthConfig::default();
    assert_eq!(auth.max_global_pending_challenges, MAX_GLOBAL_PENDING);
    assert_eq!(
        auth.max_pending_challenges_per_did,
        crate::routes::auth::MAX_PENDING_CHALLENGES_PER_DID,
    );
}

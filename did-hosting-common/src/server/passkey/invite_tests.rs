//! Tests for [`super`].

// The tests that open a store are fjall-only (a fresh temp-dir store
// each); what only they use is unused on other backends.
#![cfg_attr(not(feature = "store-fjall"), allow(unused_imports, dead_code))]
use super::*;
use crate::server::config::StoreConfig;
use crate::server::store::{KS_SESSIONS, Store};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(30);

#[cfg(feature = "store-fjall")]
async fn ks() -> (KeyspaceHandle, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
        ..StoreConfig::default()
    })
    .await
    .unwrap();
    (store.keyspace(KS_SESSIONS).unwrap(), dir)
}

fn request(purpose: Purpose) -> InviteRequest {
    InviteRequest {
        subject: "did:example:carol".into(),
        purpose,
        role: (purpose == Purpose::Session).then(|| "owner".into()),
        device_label: None,
        issued_by: Issuer::administrator("did:example:admin").unwrap(),
        ttl_secs: 3600,
    }
}

#[test]
fn secrets_have_the_entropy_the_spec_asks_for() {
    let token = generate_token();
    assert!(token.len() >= 16 + 4);
    let code = generate_claim_code();
    assert_eq!(normalise_claim_code(&code).len(), CLAIM_CODE_LEN);
    // 12 symbols of 5 bits each.
    const { assert!(CLAIM_CODE_LEN * 5 >= 40) };
    assert_ne!(generate_claim_code(), generate_claim_code());
}

#[test]
fn a_claim_code_is_read_forgivingly() {
    assert_eq!(normalise_claim_code("7kq4-mx2p 9tda"), "7KQ4MX2P9TDA");
    assert_eq!(normalise_claim_code("OIL"), "011");
}

/// Neither the token nor the claim code is anywhere in what is stored —
/// only a SHA-256 of the one and a salted Argon2id digest of the other.
#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn an_invite_is_stored_hashed() {
    let (ks, _dir) = ks().await;
    let issued = issue(&ks, request(Purpose::Session), WAIT).await.unwrap();
    let rows = ks.iter_all().await.unwrap();
    assert!(!rows.is_empty());
    let code = normalise_claim_code(&issued.claim_code);
    for (k, v) in &rows {
        for haystack in [String::from_utf8_lossy(k), String::from_utf8_lossy(v)] {
            assert!(
                !haystack.contains(&issued.token),
                "token stored: {haystack}"
            );
            assert!(
                !haystack.contains(&issued.claim_code),
                "code stored: {haystack}"
            );
            assert!(!haystack.contains(&code), "code stored: {haystack}");
        }
    }
    let stored = by_id(&ks, &issued.invite.invite_id).await.unwrap().unwrap();
    assert_eq!(stored.token_hash, hash_token(&issued.token));
    assert!(verify_claim_code(&stored.claim, &issued.claim_code));
    // Salted: the same code hashes differently twice.
    let again = hash_claim_code(&issued.claim_code).unwrap();
    assert_ne!(again.digest, stored.claim.digest);
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn both_halves_redeem_and_the_invite_stays_until_taken() {
    let (ks, _dir) = ks().await;
    let issued = issue(&ks, request(Purpose::Session), WAIT).await.unwrap();
    for _ in 0..2 {
        assert!(matches!(
            redeem(&ks, &issued.token, &issued.claim_code.to_lowercase(), WAIT)
                .await
                .unwrap(),
            Redemption::Valid(_)
        ));
    }
    // Single use.
    assert!(
        take(&ks, &issued.invite.token_hash)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        take(&ks, &issued.invite.token_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        redeem(&ks, &issued.token, &issued.claim_code, WAIT)
            .await
            .unwrap(),
        Redemption::Invalid
    ));
    assert!(
        by_id(&ks, &issued.invite.invite_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn wrong_codes_lock_the_invite_out() {
    let (ks, _dir) = ks().await;
    let issued = issue(&ks, request(Purpose::StepUp), WAIT).await.unwrap();
    for n in 1..MAX_WRONG_CODES {
        assert!(
            matches!(
                redeem(&ks, &issued.token, "0000-0000-0000", WAIT)
                    .await
                    .unwrap(),
                Redemption::Invalid
            ),
            "wrong code {n}"
        );
        let stored = by_id(&ks, &issued.invite.invite_id).await.unwrap().unwrap();
        assert_eq!(stored.wrong_codes, n);
    }
    assert!(matches!(
        redeem(&ks, &issued.token, "0000-0000-0000", WAIT)
            .await
            .unwrap(),
        Redemption::TooManyAttempts
    ));
    // Gone: the right code no longer redeems it.
    assert!(matches!(
        redeem(&ks, &issued.token, &issued.claim_code, WAIT)
            .await
            .unwrap(),
        Redemption::Invalid
    ));
    assert!(
        by_id(&ks, &issued.invite.invite_id)
            .await
            .unwrap()
            .is_none()
    );
}

/// The lockout holds even when wrong codes arrive through two
/// independent handles onto the same store — standing in for two
/// control-plane replicas, each with its own process memory (its own
/// `ATTEMPT_LOCKS`, its own backend mutexes) but the same backing data.
/// The count that matters lives in the store now, not in either
/// handle's process, so alternating attempts between them still lock
/// out at exactly [`MAX_WRONG_CODES`].
#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn lockout_holds_across_two_app_states_sharing_a_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&StoreConfig {
        data_dir: dir.path().to_path_buf(),
        ..StoreConfig::default()
    })
    .await
    .unwrap();
    // Two independently-obtained handles for the same keyspace name —
    // each its own Rust object, sharing only the store's data.
    let ks_a = store.keyspace(KS_SESSIONS).unwrap();
    let ks_b = store.keyspace(KS_SESSIONS).unwrap();

    let issued = issue(&ks_a, request(Purpose::Session), WAIT).await.unwrap();
    for n in 1..MAX_WRONG_CODES {
        let ks = if n % 2 == 0 { &ks_a } else { &ks_b };
        assert!(
            matches!(
                redeem(ks, &issued.token, "0000-0000-0000", WAIT)
                    .await
                    .unwrap(),
                Redemption::Invalid
            ),
            "wrong code {n}"
        );
        // Read back from the OTHER handle: the count is visible there
        // too, because it lives in the store, not in `ks`'s process.
        let other = if n % 2 == 0 { &ks_b } else { &ks_a };
        let stored = by_id(other, &issued.invite.invite_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.wrong_codes, n,
            "count not visible from the other handle"
        );
    }
    // The last allowed wrong code, from whichever handle's turn it is,
    // locks the invite out.
    assert!(matches!(
        redeem(&ks_b, &issued.token, "0000-0000-0000", WAIT)
            .await
            .unwrap(),
        Redemption::TooManyAttempts
    ));
    // Gone, seen from either handle.
    assert!(
        by_id(&ks_a, &issued.invite.invite_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        by_id(&ks_b, &issued.invite.invite_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn concurrent_wrong_codes_are_each_counted() {
    let (ks, _dir) = ks().await;
    let issued = issue(&ks, request(Purpose::Session), WAIT).await.unwrap();
    let tries = (0..MAX_WRONG_CODES).map(|_| {
        let ks = ks.clone();
        let token = issued.token.clone();
        tokio::spawn(async move { redeem(&ks, &token, "WRONGWRONG12", WAIT).await.unwrap() })
    });
    let outcomes = futures_join(tries).await;
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Redemption::TooManyAttempts))
            .count(),
        1
    );
    assert!(
        by_id(&ks, &issued.invite.invite_id)
            .await
            .unwrap()
            .is_none()
    );
}

/// A wrong code in flight while the invite is consumed must not write the
/// invite back: once taken, it stays gone.
#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn a_taken_invite_is_not_brought_back_by_a_racing_wrong_code() {
    let (ks, _dir) = ks().await;
    for _ in 0..8 {
        let issued = issue(&ks, request(Purpose::Session), WAIT).await.unwrap();
        let wrong = {
            let ks = ks.clone();
            let token = issued.token.clone();
            tokio::spawn(async move { redeem(&ks, &token, "WRONGWRONG12", WAIT).await.unwrap() })
        };
        let taken = {
            let ks = ks.clone();
            let hash = issued.invite.token_hash.clone();
            tokio::spawn(async move { take(&ks, &hash).await.unwrap() })
        };
        wrong.await.unwrap();
        assert!(taken.await.unwrap().is_some());
        assert!(
            by_token_hash(&ks, &issued.invite.token_hash)
                .await
                .unwrap()
                .is_none(),
            "a consumed invite was written back"
        );
    }
}

/// An administrator's update of an invite that has since been consumed
/// finds nothing, and writes nothing.
#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn an_update_does_not_bring_back_a_taken_invite() {
    let (ks, _dir) = ks().await;
    let issued = issue(&ks, request(Purpose::Session), WAIT).await.unwrap();
    assert!(
        take(&ks, &issued.invite.token_hash)
            .await
            .unwrap()
            .is_some()
    );
    let updated = update::<AppError>(&ks, &issued.invite.invite_id, |i| {
        i.expires_at += 60;
        Ok(())
    })
    .await
    .unwrap();
    assert!(updated.is_none());
    assert!(
        by_token_hash(&ks, &issued.invite.token_hash)
            .await
            .unwrap()
            .is_none()
    );
}

async fn futures_join<T>(handles: impl Iterator<Item = tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn an_expired_invite_redeems_nothing_and_is_swept() {
    let (ks, _dir) = ks().await;
    let issued = issue(&ks, request(Purpose::Session), WAIT).await.unwrap();
    let mut invite = by_id(&ks, &issued.invite.invite_id).await.unwrap().unwrap();
    invite.expires_at = now_epoch() - 1;
    save(&ks, &invite).await.unwrap();
    assert!(matches!(
        redeem(&ks, &issued.token, &issued.claim_code, WAIT)
            .await
            .unwrap(),
        Redemption::Invalid
    ));
    // An expired invite's wrong codes are not counted: it is not redeemable.
    assert_eq!(
        by_id(&ks, &issued.invite.invite_id)
            .await
            .unwrap()
            .unwrap()
            .wrong_codes,
        0
    );
    crate::server::auth::session::cleanup_expired_sessions(&ks, 300)
        .await
        .unwrap();
    assert!(
        by_id(&ks, &issued.invite.invite_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn a_step_up_invite_confers_no_role() {
    let (ks, _dir) = ks().await;
    let mut req = request(Purpose::StepUp);
    req.role = Some("admin".into());
    assert!(issue(&ks, req, WAIT).await.is_err());
}

/// With every permit held, a hash waits only as long as it was given and
/// is then refused as a retryable load refusal, not queued.
#[tokio::test]
async fn a_hash_that_finds_no_permit_in_time_is_refused_as_busy() {
    let permits: &'static tokio::sync::Semaphore =
        Box::leak(Box::new(tokio::sync::Semaphore::new(1)));
    let held = permits.acquire().await.unwrap();
    let started = std::time::Instant::now();
    let err = blocking(permits, Duration::from_millis(50), || ())
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        matches!(
            err,
            AppError::RateLimited {
                limiter: LIMITER_CLAIM_CODE_HASHING,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(err.retry_after_secs(), Some(HASH_BUSY_RETRY_AFTER_SECS));
    drop(held);
    assert_eq!(
        blocking(permits, Duration::from_millis(50), || 7)
            .await
            .unwrap(),
        7
    );
}

/// A hash queued behind a busy permit still runs if one frees in time.
#[tokio::test]
async fn a_hash_runs_once_a_permit_frees_within_the_wait() {
    let permits: &'static tokio::sync::Semaphore =
        Box::leak(Box::new(tokio::sync::Semaphore::new(1)));
    let held = permits.acquire().await.unwrap();
    let waiter =
        tokio::spawn(async move { blocking(permits, Duration::from_secs(10), || 1).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(held);
    assert_eq!(waiter.await.unwrap().unwrap(), 1);
}

/// A caller that stops waiting does not free the permit while its hash
/// is still running on the blocking pool.
#[tokio::test]
async fn a_cancelled_caller_keeps_its_permit_until_the_hash_ends() {
    let permits: &'static tokio::sync::Semaphore =
        Box::leak(Box::new(tokio::sync::Semaphore::new(1)));
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel::<()>();
    let caller = tokio::spawn(async move {
        blocking(permits, Duration::from_secs(10), move || {
            started_tx.send(()).unwrap();
            finish_rx.recv().unwrap();
        })
        .await
    });
    tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
        .await
        .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert_eq!(
        permits.available_permits(),
        0,
        "the hash still runs, so its permit is still taken"
    );
    finish_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while permits.available_permits() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the permit is released once the hash ends");
}

/// A redemption that cannot take its invite's attempt lock within the
/// wait is refused as busy, not queued.
#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn a_redemption_waits_a_bounded_time_for_its_invite() {
    let (ks, _dir) = ks().await;
    let issued = issue(&ks, request(Purpose::Session), WAIT).await.unwrap();
    let held = ATTEMPT_LOCKS.guard(&hash_token(&issued.token)).await;
    let err = redeem(
        &ks,
        &issued.token,
        &issued.claim_code,
        Duration::from_millis(50),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            AppError::RateLimited {
                limiter: LIMITER_CLAIM_CODE_HASHING,
                ..
            }
        ),
        "{err:?}"
    );
    drop(held);
    assert!(matches!(
        redeem(&ks, &issued.token, &issued.claim_code, WAIT)
            .await
            .unwrap(),
        Redemption::Valid(_)
    ));
}

/// An issuer is stored as the string every invite already on disk has, and
/// read back as what it was: the operator's marker only ever as the operator,
/// and no administrator issuer that is not a DID.
#[test]
fn an_issuer_round_trips_and_cannot_be_forged() {
    let operator = Issuer::operator();
    let admin = Issuer::administrator("did:example:admin").unwrap();
    for issuer in [&operator, &admin] {
        let stored = serde_json::to_string(issuer).unwrap();
        assert_eq!(&serde_json::from_str::<Issuer>(&stored).unwrap(), issuer);
    }
    assert_eq!(
        serde_json::to_string(&operator).unwrap(),
        "\"operator (CLI)\""
    );
    assert!(operator.is_operator() && operator.administrator_did().is_none());
    assert_eq!(admin.administrator_did(), Some("did:example:admin"));

    // The operator's marker is not a DID, so no administrator can carry it.
    assert!(Issuer::administrator("operator (CLI)").is_err());
    assert!(Issuer::administrator("").is_err());
    assert!(serde_json::from_str::<Issuer>("\"not a did\"").is_err());
}

/// An invite stored before amendments were recorded reads as unamended, and
/// an amendment is recorded once per administrator, never for the issuer.
#[test]
fn amendments_are_recorded_once_and_read_from_older_invites() {
    let issued = Invite {
        invite_id: "id".into(),
        token_hash: hash_token("t"),
        claim: hash_claim_code("ABCDEFGHJKMN").unwrap(),
        subject: "did:example:carol".into(),
        purpose: Purpose::Session,
        role: Some("owner".into()),
        device_label: None,
        issued_by: Issuer::operator(),
        amended_by: Vec::new(),
        created_at: 0,
        expires_at: 1,
        wrong_codes: 0,
        ceremony: None,
    };
    let mut stored = serde_json::to_value(&issued).unwrap();
    assert!(stored.get("amendedBy").is_none() && stored.get("amended_by").is_none());
    stored.as_object_mut().unwrap().remove("amended_by");
    let mut invite: Invite = serde_json::from_value(stored).unwrap();
    assert_eq!(invite.administrators().count(), 0);

    invite.record_amendment("did:example:admin");
    invite.record_amendment("did:example:admin");
    invite.record_amendment("did:example:other");
    assert_eq!(
        invite.administrators().collect::<Vec<_>>(),
        ["did:example:admin", "did:example:other"]
    );

    let mut by_admin = invite.clone();
    by_admin.issued_by = Issuer::administrator("did:example:issuer").unwrap();
    by_admin.amended_by.clear();
    by_admin.record_amendment("did:example:issuer");
    assert_eq!(
        by_admin.administrators().collect::<Vec<_>>(),
        ["did:example:issuer"]
    );
}

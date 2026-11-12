//! A hosted `did:webs` key event log only ever moves forward: an update must
//! strictly extend it. Exercised with real key event logs, incepted here,
//! through the check both write paths share: the control plane's
//! publication (`verify_publication`) and an edge's sync
//! (`Webs::verify_continuation`, via `verify_history`).
#![cfg(feature = "method-webs")]

use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri::hab::Hab;
use did_hosting_common::method::MethodError;
use did_hosting_common::method::publication::verify_publication;
use did_hosting_common::method::webs::Webs;

const DOMAIN: &str = "example.com";

/// One controller's identifier, incepted from `salt`: the same salt gives the
/// same AID and keys, so two controllers from one salt can write two
/// different histories of one identifier.
fn incept(salt: u8) -> (Hab, Vec<u8>) {
    let config = InceptionConfig {
        salt: Some(vec![salt; 16]),
        ..InceptionConfig::default()
    };
    let (hab, inception) = Hab::incept_event("did:webs", &config).expect("incept");
    (hab, inception.composed)
}

/// Append an interaction event to `log`.
fn interact(hab: &mut Hab, log: &[u8]) -> Vec<u8> {
    let event = hab.interact_event(&[]).expect("interaction event");
    [log, &event.composed].concat()
}

/// Append a rotation event to `log`.
fn rotate(hab: &mut Hab, log: &[u8]) -> Vec<u8> {
    let event = hab
        .rotate_event(&RotationConfig::default())
        .expect("rotation event");
    [log, &event.composed].concat()
}

/// Two histories of one identifier, diverging after inception:
/// `ours[n]` and `theirs[n]` are its log at sequence number `n`.
struct Histories {
    did: String,
    aid: String,
    ours: Vec<Vec<u8>>,
    theirs: Vec<Vec<u8>>,
}

fn histories() -> Histories {
    let (mut a, icp) = incept(7);
    let (mut b, same_icp) = incept(7);
    assert_eq!(icp, same_icp, "one identifier, one inception");
    let aid = a.prefix().to_string();

    let mut ours = vec![icp.clone()];
    for _ in 0..2 {
        let next = interact(&mut a, ours.last().unwrap());
        ours.push(next);
    }
    let mut theirs = vec![icp];
    let rotated = rotate(&mut b, &theirs[0]);
    theirs.push(rotated);
    for _ in 0..2 {
        let next = interact(&mut b, theirs.last().unwrap());
        theirs.push(next);
    }

    let did = Webs::slot_did(DOMAIN, &aid);
    for log in ours.iter().chain(&theirs) {
        Webs::verify_artifacts(&did, log, None).expect("each history verifies on its own");
    }
    Histories {
        did,
        aid,
        ours,
        theirs,
    }
}

fn refused(result: Result<(), MethodError>, needle: &str) {
    match result {
        Err(MethodError::Validation(message)) => {
            assert!(message.contains(needle), "{message}")
        }
        other => panic!("expected a refusal mentioning {needle:?}, got {other:?}"),
    }
}

#[test]
fn the_same_log_and_its_extensions_are_accepted() {
    let h = histories();
    Webs::verify_continuation(&h.did, &h.ours[1], &h.ours[1]).expect("the same log");
    Webs::verify_continuation(&h.did, &h.ours[1], &h.ours[2]).expect("one event more");
    Webs::verify_continuation(&h.did, &h.ours[0], &h.ours[2]).expect("two events more");
}

/// A different event at the hosted tip's sequence number.
#[test]
fn a_different_event_at_the_same_sequence_number_is_refused() {
    let h = histories();
    refused(
        Webs::verify_continuation(&h.did, &h.ours[1], &h.theirs[1]),
        "forks the key event log at sequence 1",
    );
}

/// A longer log that diverges before the hosted tip: further along, and
/// valid on its own, but not this identifier's hosted history.
#[test]
fn a_longer_log_that_diverges_before_the_hosted_tip_is_refused() {
    let h = histories();
    refused(
        Webs::verify_continuation(&h.did, &h.ours[2], &h.theirs[3]),
        "forks the key event log at sequence 1",
    );
}

#[test]
fn a_shorter_log_is_refused() {
    let h = histories();
    refused(
        Webs::verify_continuation(&h.did, &h.ours[2], &h.ours[1]),
        "rewinds",
    );
}

/// The control plane's publication goes through the same check: a fork of
/// the hosted log is not published, its extension is.
#[test]
fn a_publication_of_a_fork_is_refused() {
    let h = histories();
    let fork = verify_publication(DOMAIN, &h.aid, &h.theirs[2], Some(&h.ours[1]), None);
    assert!(
        matches!(fork, Err(MethodError::Validation(ref m)) if m.contains("forks")),
        "{:?}",
        fork.err()
    );
    verify_publication(DOMAIN, &h.aid, &h.ours[2], Some(&h.ours[1]), None)
        .expect("an extension is published");
}

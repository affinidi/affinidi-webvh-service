//! A hosted `did:webs` key event log only ever moves forward: an update must
//! extend it, or supersede its trailing interaction events with a rotation
//! (KERI's superseding recovery). Exercised with real key event logs,
//! incepted here, through the check both write paths share: the control
//! plane's publication (`verify_publication`) and an edge's sync
//! (`Webs::verify_continuation`, via `verify_history`; the edge's own test is
//! `did-hosting-server/tests/webs_sync_history.rs`, over fixtures this file
//! regenerates).
#![cfg(feature = "method-webs")]

use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri::hab::Hab;
use did_hosting_common::method::MethodError;
use did_hosting_common::method::publication::verify_publication;
use did_hosting_common::method::webs::Webs;
use serde_json::json;

const DOMAIN: &str = "example.com";

/// One controller's identifier, incepted from `salt`: the same salt gives the
/// same AID and keys, so two controllers from one salt can write two
/// different histories of one identifier.
fn incept(salt: u8) -> (Hab, Vec<u8>, String) {
    let config = InceptionConfig {
        salt: Some(vec![salt; 16]),
        ..InceptionConfig::default()
    };
    let (hab, inception) = Hab::incept_event("did:webs", &config).expect("incept");
    (hab, inception.composed, inception.said)
}

/// Append an interaction event anchoring `anchors` to `log`.
fn interact(hab: &mut Hab, log: &[u8], anchors: &[serde_json::Value]) -> Vec<u8> {
    let event = hab.interact_event(anchors).expect("interaction event");
    [log, &event.composed].concat()
}

/// Append a rotation event to `log`.
fn rotate(hab: &mut Hab, log: &[u8], config: &RotationConfig) -> Vec<u8> {
    let event = hab.rotate_event(config).expect("rotation event");
    [log, &event.composed].concat()
}

/// Histories of one identifier, all from one inception.
struct Histories {
    did: String,
    aid: String,
    /// `icp, ixn, ixn`: `ours[n]` is the log at sequence number `n`.
    ours: Vec<Vec<u8>>,
    /// `icp, rot, ixn, ixn`: a rotation at sequence number 1, then
    /// interactions. A recovery of `ours`.
    recovered: Vec<Vec<u8>>,
    /// `icp, ixn'`: a different interaction at sequence number 1.
    other_ixn: Vec<u8>,
    /// `icp, rot'`: a different rotation at sequence number 1.
    other_rot: Vec<u8>,
    /// `icp, rot, ixn'`: a different interaction after the rotation.
    recovered_other_ixn: Vec<u8>,
}

fn histories() -> Histories {
    let (mut a, icp, icp_said) = incept(7);
    let (mut b, same_icp, _) = incept(7);
    let (mut c, _, _) = incept(7);
    let (mut d, _, _) = incept(7);
    let (mut e, _, _) = incept(7);
    assert_eq!(icp, same_icp, "one identifier, one inception");
    let aid = a.prefix().to_string();

    let mut ours = vec![icp.clone()];
    for _ in 0..2 {
        let next = interact(&mut a, ours.last().unwrap(), &[]);
        ours.push(next);
    }
    let mut recovered = vec![icp.clone()];
    let rotated = rotate(&mut b, &icp, &RotationConfig::default());
    recovered.push(rotated);
    for _ in 0..2 {
        let next = interact(&mut b, recovered.last().unwrap(), &[]);
        recovered.push(next);
    }
    let other_ixn = interact(&mut c, &icp, &[json!({ "d": icp_said })]);
    let other_rot = rotate(
        &mut d,
        &icp,
        &RotationConfig {
            next_count: 2,
            ..RotationConfig::default()
        },
    );
    let rotated_again = rotate(&mut e, &icp, &RotationConfig::default());
    assert_eq!(
        rotated_again, recovered[1],
        "the same rotation from the same keys"
    );
    let recovered_other_ixn = interact(&mut e, &rotated_again, &[json!({ "d": icp_said })]);

    let did = Webs::slot_did(DOMAIN, &aid);
    for log in ours
        .iter()
        .chain(&recovered)
        .chain([&other_ixn, &other_rot, &recovered_other_ixn])
    {
        Webs::verify_artifacts(&did, log, None).expect("each history verifies on its own");
    }
    Histories {
        did,
        aid,
        ours,
        recovered,
        other_ixn,
        other_rot,
        recovered_other_ixn,
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

#[test]
fn a_shorter_log_is_refused() {
    let h = histories();
    refused(
        Webs::verify_continuation(&h.did, &h.ours[2], &h.ours[1]),
        "rewinds",
    );
}

/// Superseding recovery: a rotation at the sequence number of the first
/// interaction after the last establishment event replaces those
/// interactions, whether the recovered log is shorter, as long, or longer.
#[test]
fn a_rotation_supersedes_trailing_interactions() {
    let h = histories();
    Webs::verify_continuation(&h.did, &h.ours[1], &h.recovered[1])
        .expect("rot at 1 supersedes ixn at 1");
    Webs::verify_continuation(&h.did, &h.ours[2], &h.recovered[1])
        .expect("rot at 1 supersedes ixn at 1 and 2");
    Webs::verify_continuation(&h.did, &h.ours[2], &h.recovered[3])
        .expect("rot at 1, then more, supersedes ixn at 1 and 2");
}

/// An interaction is superseded only by a rotation: a different interaction
/// at the same sequence number is a fork.
#[test]
fn a_different_interaction_at_the_same_sequence_number_is_refused() {
    let h = histories();
    refused(
        Webs::verify_continuation(&h.did, &h.ours[1], &h.other_ixn),
        "diverges from the key event log at sequence 1",
    );
    refused(
        Webs::verify_continuation(&h.did, &h.recovered[2], &h.recovered_other_ixn),
        "diverges from the key event log at sequence 2",
    );
}

/// A rotation is never superseded, by another rotation or anything else.
#[test]
fn a_rotation_cannot_be_superseded() {
    let h = histories();
    refused(
        Webs::verify_continuation(&h.did, &h.recovered[1], &h.other_rot),
        "the hosted event is rot",
    );
    refused(
        Webs::verify_continuation(&h.did, &h.recovered[2], &h.ours[2]),
        "the hosted event is rot",
    );
}

/// The control plane's publication goes through the same check.
#[test]
fn a_publication_is_held_to_the_same_rule() {
    let h = histories();
    let fork = verify_publication(DOMAIN, &h.aid, &h.other_ixn, Some(&h.ours[1]), None);
    assert!(
        matches!(fork, Err(MethodError::Validation(ref m)) if m.contains("diverges")),
        "{:?}",
        fork.err()
    );
    verify_publication(DOMAIN, &h.aid, &h.recovered[2], Some(&h.ours[2]), None)
        .expect("a recovery is published");
    verify_publication(DOMAIN, &h.aid, &h.ours[2], Some(&h.ours[1]), None)
        .expect("an extension is published");
}

/// Regenerates the fixtures the edge's sync test
/// (`did-hosting-server/tests/webs_sync_history.rs`) replays:
/// `cargo test -p did-hosting-control --features method-webs --test
/// webs_continuation -- --ignored regenerate_fixtures`.
#[test]
#[ignore = "writes fixture files"]
fn regenerate_fixtures() {
    let h = histories();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../did-hosting-common/tests/fixtures/recovery");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, log) in [
        ("ixn-ixn.keri.cesr", &h.ours[2]),
        ("rot.keri.cesr", &h.recovered[1]),
        ("other-ixn.keri.cesr", &h.other_ixn),
    ] {
        std::fs::write(dir.join(name), log).unwrap();
    }
    std::fs::write(dir.join("AID"), &h.aid).unwrap();
}

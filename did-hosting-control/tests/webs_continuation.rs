//! A hosted `did:webs` key event log only ever moves forward: an update must
//! extend it, or supersede its trailing interaction events with a rotation
//! (KERI's superseding recovery). Exercised with real key event logs,
//! incepted here, through the check both write paths share: the control
//! plane's publication (`verify_publication`) and an edge's sync
//! (`Webs::verify_continuation`, via `verify_history`; the edge's own test is
//! `did-hosting-server/tests/webs_sync_history.rs`, over fixtures this file
//! regenerates).
#![cfg(feature = "method-webs")]

use affinidi_did_webs::{
    Artifacts, Change, CreateConfig, Kels, KeyCustody, UpdateConfig, create, update,
};
use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri_core::SadValue;
use did_hosting_common::method::MethodError;
use did_hosting_common::method::publication::verify_publication;
use did_hosting_common::method::webs::Webs;
use serde_json::json;

const DOMAIN: &str = "example.com";

/// The salt every key of the identifier is derived from: the same salt gives
/// the same keys, so two controllers holding it can write two different
/// histories of one identifier.
const SALT: [u8; 16] = [7; 16];

/// One point in a history: the stream as published, and what continuing
/// from it needs.
#[derive(Clone)]
struct At {
    artifacts: Artifacts,
    custody: KeyCustody,
}

impl At {
    fn log(&self) -> Vec<u8> {
        self.artifacts.keri_cesr.clone()
    }
}

/// Incept the identifier, with the designations naming its DID that every
/// did:webs publishes (and `affinidi-did-webs` 0.13 requires): `icp` and the
/// interaction events anchoring them.
fn incept() -> (String, At) {
    let created = create(
        CreateConfig::builder(DOMAIN)
            .inception(InceptionConfig {
                salt: Some(SALT.to_vec()),
                ..InceptionConfig::default()
            })
            .build(),
    )
    .expect("create");
    let at = At {
        artifacts: created.artifacts().clone(),
        custody: created.custody().clone(),
    };
    (created.did().to_string(), at)
}

/// Append `change` to the history at `at`.
fn append(did: &str, at: &At, change: Change) -> At {
    let updated = update(
        UpdateConfig {
            did: did.to_string(),
            prior: at.artifacts.clone(),
            custody: at.custody.clone(),
            change,
        },
        &SALT,
    )
    .expect("update");
    At {
        artifacts: updated.artifacts().clone(),
        custody: updated.custody().clone(),
    }
}

/// An interaction event anchoring `anchors`.
fn interact(anchors: &[serde_json::Value]) -> Change {
    Change::Interact(anchors.iter().map(SadValue::from_json_value).collect())
}

/// Histories of one identifier, all from one inception. Each starts from
/// `base`, the created identifier (inception and its designations), so the
/// sequence numbers below count from there.
struct Histories {
    did: String,
    aid: String,
    /// The sequence number of `base`'s last event; every history forks
    /// right after it.
    base_sn: u64,
    /// `base, ixn, ixn`: `ours[n]` is the log `n` events past `base`.
    ours: Vec<Vec<u8>>,
    /// `base, rot, ixn, ixn`: a rotation right after `base`, then
    /// interactions. A recovery of `ours`.
    recovered: Vec<Vec<u8>>,
    /// `base, ixn'`: a different interaction at the same sequence number.
    other_ixn: Vec<u8>,
    /// `base, rot'`: a different rotation at the same sequence number.
    other_rot: Vec<u8>,
    /// `base, rot, ixn'`: a different interaction after the rotation.
    recovered_other_ixn: Vec<u8>,
}

fn histories() -> Histories {
    let (did, base) = incept();
    let (same_did, _) = incept();
    assert_eq!(did, same_did, "one identifier, one inception");
    let aid = did.rsplit(':').next().unwrap().to_string();
    let base_sn = Kels::parse(&base.log())
        .and_then(|kels| kels.key_state(&aid))
        .expect("base key state")
        .sn;

    let mut ours = vec![base.clone()];
    for _ in 0..2 {
        let next = append(&did, ours.last().unwrap(), interact(&[]));
        ours.push(next);
    }
    let mut recovered = vec![base.clone()];
    recovered.push(append(
        &did,
        &base,
        Change::Rotate(RotationConfig::default()),
    ));
    for _ in 0..2 {
        let next = append(&did, recovered.last().unwrap(), interact(&[]));
        recovered.push(next);
    }
    let other_ixn = append(&did, &base, interact(&[json!({ "d": aid })]));
    let other_rot = append(
        &did,
        &base,
        Change::Rotate(RotationConfig {
            next_count: 2,
            ..RotationConfig::default()
        }),
    );
    let rotated_again = append(&did, &base, Change::Rotate(RotationConfig::default()));
    assert_eq!(
        rotated_again.log(),
        recovered[1].log(),
        "the same rotation from the same keys"
    );
    let recovered_other_ixn = append(&did, &rotated_again, interact(&[json!({ "d": aid })]));

    let ours: Vec<Vec<u8>> = ours.iter().map(At::log).collect();
    let recovered: Vec<Vec<u8>> = recovered.iter().map(At::log).collect();
    let (other_ixn, other_rot, recovered_other_ixn) =
        (other_ixn.log(), other_rot.log(), recovered_other_ixn.log());

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
        base_sn,
        ours,
        recovered,
        other_ixn,
        other_rot,
        recovered_other_ixn,
    }
}

fn refused(result: Result<(), MethodError>, needle: &str) {
    match result {
        Err(MethodError::HistoryRewrite(message)) => {
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
/// interaction after the last establishment event (here, right after
/// `base`) replaces those
/// interactions, whether the recovered log is shorter, as long, or longer.
#[test]
fn a_rotation_supersedes_trailing_interactions() {
    let h = histories();
    Webs::verify_continuation(&h.did, &h.ours[1], &h.recovered[1])
        .expect("a rotation right after base supersedes the ixn there");
    Webs::verify_continuation(&h.did, &h.ours[2], &h.recovered[1])
        .expect("a rotation right after base supersedes both ixns");
    Webs::verify_continuation(&h.did, &h.ours[2], &h.recovered[3])
        .expect("a rotation right after base, then more, supersedes both ixns");
}

/// An interaction is superseded only by a rotation: a different interaction
/// at the same sequence number is a fork.
#[test]
fn a_different_interaction_at_the_same_sequence_number_is_refused() {
    let h = histories();
    refused(
        Webs::verify_continuation(&h.did, &h.ours[1], &h.other_ixn),
        &format!(
            "diverges from the key event log at sequence {}",
            h.base_sn + 1
        ),
    );
    refused(
        Webs::verify_continuation(&h.did, &h.recovered[2], &h.recovered_other_ixn),
        &format!(
            "diverges from the key event log at sequence {}",
            h.base_sn + 2
        ),
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
        matches!(fork, Err(MethodError::HistoryRewrite(ref m)) if m.contains("diverges")),
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

/// Regenerates the publication the control plane's did:webs tests register
/// (`did_ops::tests_atomic::webs`, `control_tasks::tests`): an identifier
/// created for `control.test`, which designates itself there. The reference
/// publication cannot stand in, since `affinidi-did-webs` 0.13 holds an
/// identifier to the domains its own designated aliases name:
/// `cargo test -p did-hosting-control --features method-webs --test
/// webs_continuation -- --ignored regenerate_control_fixture`.
#[test]
#[ignore = "writes fixture files"]
fn regenerate_control_fixture() {
    let created = create(
        CreateConfig::builder("control.test")
            .inception(InceptionConfig {
                salt: Some(vec![3; 16]),
                ..InceptionConfig::default()
            })
            .build(),
    )
    .expect("create");
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../did-hosting-common/tests/fixtures/control-test");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("keri.cesr"), &created.artifacts().keri_cesr).unwrap();
    let aid = created.did().rsplit(':').next().unwrap();
    std::fs::write(dir.join("AID"), aid).unwrap();
}

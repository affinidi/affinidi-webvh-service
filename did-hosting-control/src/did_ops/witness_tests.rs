//! Tests for the register/publish witness-threshold race (SEC finding
//! #166) and witness proof storage.

use super::test_helpers::*;
use super::*;

use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;

// -----------------------------------------------------------------
// register/publish witness-threshold race (SEC finding #166)
// -----------------------------------------------------------------

/// A fresh Ed25519 key with the `did:key:{pk}#{pk}` verification-method
/// id `create_log_entry`/witness-proof lookups both require. Mirrors
/// `did_hosting_common::did_ops`'s own (private) test helper of the
/// same shape.
fn race_signing_key() -> Secret {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");
    key
}

/// A witness identity: its signing key, plus the bare `did:key:...` id a
/// `Witness` list entry names it by.
fn race_witness_identity() -> (Secret, String) {
    let key = race_signing_key();
    let witness_did = key.id.split('#').next().unwrap().to_string();
    (key, witness_did)
}

/// The smallest DID document `verify_log_entry` accepts.
fn race_doc_with_key(did: &str, key: &Secret) -> serde_json::Value {
    let pk = key.get_public_keymultibase().unwrap();
    serde_json::json!({
        "id": did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk,
            "controller": did
        }],
        "authentication": [format!("{did}#key-0")],
        "assertionMethod": [format!("{did}#key-0")],
    })
}

/// A signed witness proof over `version_id`.
async fn race_sign_witness_proof(
    witness_key: &Secret,
    version_id: &str,
) -> affinidi_data_integrity::DataIntegrityProof {
    affinidi_data_integrity::DataIntegrityProof::sign(
        &serde_json::json!({ "versionId": version_id }),
        witness_key,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .expect("sign witness proof")
}

/// A witnessed genesis (threshold 1, naming `witness_did`) plus a second
/// entry extending it. Per didwebvh's own parameter-inheritance rule, the
/// second entry's empty `Parameters` does not clear the witness config —
/// it stays active, so the second entry needs its own proof too, once it
/// stops being exempt as the "new tail".
///
/// Returns `(genesis-only jsonl, genesis+second jsonl, genesis version_id)`.
async fn race_witnessed_log_and_extension(witness_did: &str) -> (String, String, String) {
    use didwebvh_rs::Multibase;
    use didwebvh_rs::parameters::Parameters;
    use didwebvh_rs::witness::{Witness, Witnesses};

    let key = race_signing_key();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            key.get_public_keymultibase().unwrap(),
        )])),
        portable: Some(false),
        witness: Some(Arc::new(Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: Multibase::new(witness_did.to_string()),
            }],
        })),
        ..Default::default()
    };
    let doc = race_doc_with_key("did:webvh:{SCID}:control.test:race", &key);

    // Explicit, one-second-apart `versionTime`s: two `create_log_entry`
    // calls landing in the same wall-clock second (`None` stamps "now")
    // would otherwise fail the chain's own monotonic-versionTime check.
    let base_time = (chrono::Utc::now() - chrono::Duration::seconds(10)).fixed_offset();

    let mut state = didwebvh_rs::DIDWebVHState::default();
    state
        .create_log_entry(Some(base_time), &doc, &params, &key)
        .await
        .expect("genesis entry");
    let genesis_version_id = state
        .log_entries()
        .last()
        .unwrap()
        .get_version_id()
        .to_string();
    let genesis_doc = state.log_entries().last().unwrap().get_state().clone();
    let to_jsonl = |state: &didwebvh_rs::DIDWebVHState| {
        state
            .log_entries()
            .iter()
            .map(|e| serde_json::to_string(&e.log_entry).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    };
    let genesis_jsonl = to_jsonl(&state);

    state
        .create_log_entry(
            Some(base_time + chrono::Duration::seconds(1)),
            &genesis_doc,
            &Parameters::default(),
            &key,
        )
        .await
        .expect("second entry");
    let extended_jsonl = to_jsonl(&state);

    (genesis_jsonl, extended_jsonl, genesis_version_id)
}

/// A witness publishing its proof for a version again replaces its
/// earlier proof: the stored file keeps one proof per witness per
/// version.
#[tokio::test]
async fn a_witness_publishing_again_replaces_its_proof() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:dedupe-owner";
    let path = "race";
    let (witness_key, witness_did) = race_witness_identity();
    let (genesis_jsonl, _, genesis_version_id) =
        race_witnessed_log_and_extension(&witness_did).await;
    register_did_atomic(
        &owner_auth(owner),
        &state,
        path,
        &genesis_jsonl,
        false,
        None,
    )
    .await
    .expect("register");

    for _ in 0..3 {
        let proof = race_sign_witness_proof(&witness_key, &genesis_version_id).await;
        let witness_entry = serde_json::json!({
            "versionId": genesis_version_id,
            "proof": serde_json::to_value(&proof).unwrap(),
        });
        upload_witness(
            &owner_auth(owner),
            &state,
            path,
            witness_entry.as_object().unwrap(),
        )
        .await
        .expect("witness proof stored");
    }

    let stored: Vec<serde_json::Value> = serde_json::from_slice(
        &state
            .dids_ks
            .get_raw(content_witness_key(path))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(
        stored[0]["proof"].as_array().map(Vec::len),
        Some(1),
        "{stored:?}"
    );
}

/// A republish of the DID a slot already holds must extend the stored
/// log, as every edge requires of what it is sent: a log one entry
/// shorter is refused on both register and publish, and the stored log is
/// left as it was. An extension is accepted.
#[tokio::test]
async fn a_republish_of_the_same_did_must_extend_the_stored_log() {
    use didwebvh_rs::Multibase;
    use didwebvh_rs::parameters::Parameters;

    let (state, _dir) = test_state().await;
    let owner = "did:example:extends";
    let path = "extends";
    let key = race_signing_key();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            key.get_public_keymultibase().unwrap(),
        )])),
        portable: Some(false),
        ..Default::default()
    };
    let doc = race_doc_with_key("did:webvh:{SCID}:control.test:extends", &key);
    let base_time = (chrono::Utc::now() - chrono::Duration::seconds(10)).fixed_offset();
    let to_jsonl = |state: &didwebvh_rs::DIDWebVHState| {
        state
            .log_entries()
            .iter()
            .map(|e| serde_json::to_string(&e.log_entry).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mut log = didwebvh_rs::DIDWebVHState::default();
    log.create_log_entry(Some(base_time), &doc, &params, &key)
        .await
        .expect("genesis entry");
    let genesis = to_jsonl(&log);
    let genesis_doc = log.log_entries().last().unwrap().get_state().clone();
    log.create_log_entry(
        Some(base_time + chrono::Duration::seconds(1)),
        &genesis_doc,
        &Parameters::default(),
        &key,
    )
    .await
    .expect("second entry");
    let two = to_jsonl(&log);
    let second_doc = log.log_entries().last().unwrap().get_state().clone();
    log.create_log_entry(
        Some(base_time + chrono::Duration::seconds(2)),
        &second_doc,
        &Parameters::default(),
        &key,
    )
    .await
    .expect("third entry");
    let three = to_jsonl(&log);

    register_did_atomic(&owner_auth(owner), &state, path, &two, false, None)
        .await
        .expect("register two entries");

    let err = register_did_atomic(&owner_auth(owner), &state, path, &genesis, false, None)
        .await
        .expect_err("a shorter log is refused on register");
    assert!(err.to_string().contains("extension"), "{err}");
    let err = publish_did(&owner_auth(owner), &state, path, &genesis, None)
        .await
        .expect_err("a shorter log is refused on publish");
    assert!(err.to_string().contains("extension"), "{err}");
    let stored = state
        .dids_ks
        .get_raw(content_log_key(path))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(String::from_utf8(stored).unwrap(), two);

    publish_did(&owner_auth(owner), &state, path, &three, None)
        .await
        .expect("an extension is accepted");
}

/// Regression for the write-time TOCTOU behind SEC finding #166:
/// `register_did_atomic` used to read `existing_log`/`existing_witness`
/// — and run the whole witness-threshold verification against them —
/// *before* acquiring `state.path_locks`. A commit landing on the same
/// path between that read and this call's own (later) lock acquisition
/// was invisible to a verification that had already run and already
/// decided which entries were exempt "new tail".
///
/// Rather than relying on real scheduler timing to reproduce the race,
/// this test holds the path lock itself, spawns the call, and only then
/// mutates the stored log — deterministically standing in for "another
/// commit landed first". If `register_did_atomic` read before acquiring
/// the lock (the bug), it would have already captured the log as it
/// stood *before* this mutation, computed a smaller
/// `previously_published`, and succeeded; fixed, it reads only after
/// the mutation is visible, correctly inflating `previously_published`
/// to cover the new entry too — which has no matching witness proof, so
/// the call must fail.
#[tokio::test]
async fn register_atomic_rereads_state_under_the_path_lock_not_before_it() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:race-owner";
    let path = "race";

    let (witness_key, witness_did) = race_witness_identity();
    let (genesis_jsonl, extended_jsonl, genesis_version_id) =
        race_witnessed_log_and_extension(&witness_did).await;

    // Fresh registration: no prior content, so the witnessed genesis is
    // exempt from the threshold check outright — its proof arrives later.
    register_did_atomic(
        &owner_auth(owner),
        &state,
        path,
        &genesis_jsonl,
        false,
        None,
    )
    .await
    .expect("witnessed genesis registers with no proof yet");

    // The witness now attests the genesis, satisfying its threshold.
    let proof = race_sign_witness_proof(&witness_key, &genesis_version_id).await;
    let witness_entry = serde_json::json!({
        "versionId": genesis_version_id,
        "proof": serde_json::to_value(&proof).unwrap(),
    });
    upload_witness(
        &owner_auth(owner),
        &state,
        path,
        witness_entry.as_object().unwrap(),
    )
    .await
    .expect("witness proof verifies and is stored");

    // Hold the path lock ourselves, standing in for a commit in flight.
    let guard = state.path_locks.guard(path).await;

    let state_clone = state.clone();
    let owner_clone = owner.to_string();
    let path_clone = path.to_string();
    let extended = extended_jsonl.clone();
    let task = tokio::spawn(async move {
        register_did_atomic(
            &owner_auth(&owner_clone),
            &state_clone,
            &path_clone,
            &extended,
            false,
            None,
        )
        .await
    });

    // Give the spawned call a chance to run up to — and block on — the
    // lock we're holding.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(
        !task.is_finished(),
        "the spawned call must block on our guard"
    );

    // Stand in for "a concurrent commit already landed": inflate the
    // stored log's line count so a read taken *after* the lock sees two
    // already-published entries — both now requiring their own witness
    // proof — rather than the one genesis entry that was really there
    // when this test started.
    state
        .dids_ks
        .insert_raw(content_log_key(path), b"1\n2\n3\n4\n5\n".to_vec())
        .await
        .unwrap();

    drop(guard);

    let err = tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .expect("spawned call must finish once the guard is dropped")
        .unwrap()
        .expect_err(
            "a read taken under the lock must see the inflated previously_published count \
             and demand a witness proof for the new entry, which was never provided",
        );
    assert!(
        err.to_string().contains("threshold"),
        "expected a witness-threshold refusal, got: {err}"
    );
}

//! Unit tests for the register/publish witness split and the other
//! did:webvh verifiers.

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Duration, FixedOffset, Utc};
use didwebvh_rs::Multibase;
use didwebvh_rs::witness::{Witness, Witnesses};
use serde_json::json;

use super::{LogEntryValidationStatus, parse_log, validate_did_jsonl, verify_did_log_for_publish};
use didwebvh_rs::{DIDWebVHState, parameters::Parameters};

/// A `versionTime` comfortably in the past, so a second entry built at
/// `base_time() + 1s` is never mistaken for the same instant as the
/// first — `create_log_entry(None, ...)` stamps "now", and two calls in
/// the same test can land in the same wall-clock second.
fn base_time() -> DateTime<FixedOffset> {
    (Utc::now() - Duration::seconds(10)).fixed_offset()
}

/// A fresh Ed25519 key with the `did:key:{pk}#{pk}` verification-method
/// id `create_log_entry`/witness-proof lookup both require. Mirrors
/// didwebvh-rs's own (private) `test_utils::generate_signing_key`.
fn signing_key() -> Secret {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");
    key
}

/// A witness identity: its signing key, plus the bare `did:key:...` id a
/// `Witness` list entry names it by.
fn witness_identity() -> (Secret, String) {
    let key = signing_key();
    let witness_did = key.id.split('#').next().unwrap().to_string();
    (key, witness_did)
}

/// The smallest DID document `verify_log_entry` accepts. Mirrors
/// didwebvh-rs's own (private) `test_utils::did_doc_with_key`.
fn doc_with_key(did: &str, key: &Secret) -> serde_json::Value {
    let pk = key.get_public_keymultibase().unwrap();
    json!({
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

/// Serialize a state's current log entries back to jsonl, the shape
/// `verify_did_log_for_publish` parses.
fn to_jsonl(state: &DIDWebVHState) -> String {
    state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A signed witness proof over `version_id`.
async fn sign_witness_proof(witness_key: &Secret, version_id: &str) -> DataIntegrityProof {
    DataIntegrityProof::sign(
        &json!({ "versionId": version_id }),
        witness_key,
        SignOptions::new(),
    )
    .await
    .expect("sign witness proof")
}

/// A `did-witness.json`-shaped file naming one proof for `version_id` —
/// the wire format `DIDWebVHState::parse_witness_proofs` reads.
fn witness_file(version_id: &str, proof: &DataIntegrityProof) -> String {
    json!([{ "versionId": version_id, "proof": [proof] }]).to_string()
}

/// Genesis parameters naming one witness at the given threshold. Per
/// didwebvh 1.0, a witness param on the *first* entry is active
/// immediately — no one-version delay — so the genesis entry itself
/// needs a threshold-meeting proof to resolve as witnessed.
fn witnessed_genesis_params(key: &Secret, witness_did: &str, threshold: u32) -> Parameters {
    Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            key.get_public_keymultibase().unwrap(),
        )])),
        portable: Some(false),
        witness: Some(Arc::new(Witnesses::Value {
            threshold,
            witnesses: vec![Witness {
                id: Multibase::new(witness_did.to_string()),
            }],
        })),
        ..Default::default()
    }
}

/// Bug #1's exact scenario: a brand-new registration whose genesis
/// entry names an active witness. No proof can exist yet — it is the
/// witness's job to sign the version *after* it is published — so this
/// must succeed with no witness content at all, as long as the chain
/// itself verifies. This is what
/// `did_hosting_common::did_ops::verify_did_log_proofs` (unconditional
/// witness_content: None, whole-log threshold) always refused.
#[tokio::test]
async fn a_freshly_registered_witnessed_genesis_is_accepted_with_no_proof_yet() {
    let key = signing_key();
    let (_witness_key, witness_did) = witness_identity();
    let params = witnessed_genesis_params(&key, &witness_did, 1);
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);

    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let jsonl = to_jsonl(&state);

    verify_did_log_for_publish(&jsonl, None, 0)
        .expect("a witnessed DID's first version registers with no witness proof yet");
}

/// A republish (or a second `did/register` of the same slot) extends
/// the log the DID already has. The already-published genesis must
/// still meet its witness threshold — from the *stored* witness
/// content, which this call supplies as `witness_content` — while the
/// new, not-yet-witnessed tail entry is exempt.
#[tokio::test]
async fn a_republish_still_requires_the_stored_proof_for_already_published_entries() {
    let key = signing_key();
    let (witness_key, witness_did) = witness_identity();
    let params = witnessed_genesis_params(&key, &witness_did, 1);
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);

    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(Some(base_time()), &doc, &params, &key)
        .await
        .expect("genesis entry");
    let genesis_version_id = state
        .log_entries()
        .last()
        .unwrap()
        .get_version_id()
        .to_string();
    let genesis_doc = state.log_entries().last().unwrap().get_state().clone();

    // A second entry — new tail, no witness proof possible for it yet.
    state
        .create_log_entry(
            Some(base_time() + Duration::seconds(1)),
            &genesis_doc,
            &Parameters::default(),
            &key,
        )
        .await
        .expect("second entry");
    let jsonl = to_jsonl(&state);

    // Nothing supplied for the already-published genesis: its threshold
    // (1) is not met, so this must be refused.
    let err = verify_did_log_for_publish(&jsonl, None, 1)
        .expect_err("the stored genesis has no witness proof yet; threshold not met");
    assert!(err.contains("threshold"), "{err}");

    // The genesis's own stored witness proof now satisfies it, and the
    // new tail is still exempt — so this succeeds.
    let proof = sign_witness_proof(&witness_key, &genesis_version_id).await;
    let witness_content = witness_file(&genesis_version_id, &proof);
    verify_did_log_for_publish(&jsonl, Some(&witness_content), 1).expect(
        "the already-published entry's stored witness proof satisfies its threshold; \
             the new tail needs none",
    );
}

/// An unwitnessed DID is unaffected by the split — the ordinary
/// register/publish path for the overwhelming majority of DIDs, which
/// never configure witnesses at all.
#[tokio::test]
async fn an_unwitnessed_log_registers_and_republishes_normally() {
    let key = signing_key();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            key.get_public_keymultibase().unwrap(),
        )])),
        portable: Some(false),
        ..Default::default()
    };
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);

    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(Some(base_time()), &doc, &params, &key)
        .await
        .expect("genesis entry");
    verify_did_log_for_publish(&to_jsonl(&state), None, 0).expect("plain register");

    let genesis_doc = state.log_entries().last().unwrap().get_state().clone();
    state
        .create_log_entry(
            Some(base_time() + Duration::seconds(1)),
            &genesis_doc,
            &Parameters::default(),
            &key,
        )
        .await
        .expect("second entry");
    verify_did_log_for_publish(&to_jsonl(&state), None, 1).expect("plain republish");
}

/// `parse_log` returns every entry unverified, in order, with its version
/// number — and refuses a log whose last entry is not a did:webvh DID.
#[tokio::test]
async fn parse_log_returns_unverified_entries_and_requires_webvh() {
    let key = signing_key();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            key.get_public_keymultibase().unwrap(),
        )])),
        portable: Some(false),
        ..Default::default()
    };
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(Some(base_time()), &doc, &params, &key)
        .await
        .expect("genesis entry");
    let genesis_doc = state.log_entries().last().unwrap().get_state().clone();
    state
        .create_log_entry(
            Some(base_time() + Duration::seconds(1)),
            &genesis_doc,
            &Parameters::default(),
            &key,
        )
        .await
        .expect("second entry");
    // A blank line between entries is skipped.
    let jsonl = to_jsonl(&state).replacen('\n', "\n\n", 1);

    let parsed = parse_log(&jsonl).expect("parses");
    let entries = parsed.log_entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries.iter().map(|e| e.version_number).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(
        entries
            .iter()
            .all(|e| matches!(e.validation_status, LogEntryValidationStatus::NotValidated))
    );
    assert!(validate_did_jsonl(&jsonl).is_ok());

    // The same log, its last DID rewritten to another method, is refused.
    let not_webvh = jsonl.replace("did:webvh:", "did:web:");
    let err = parse_log(&not_webvh).unwrap_err();
    assert!(err.contains("state.id"), "{err}");
}

/// A tampered chain is still refused regardless of `previously_published`
/// — the witness-threshold split narrows *which* proofs are demanded,
/// it never widens what counts as a valid chain.
#[tokio::test]
async fn a_broken_chain_is_refused_even_as_new_tail() {
    let key = signing_key();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            key.get_public_keymultibase().unwrap(),
        )])),
        portable: Some(false),
        ..Default::default()
    };
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let mut jsonl = to_jsonl(&state);
    jsonl.push_str("\nnot a log entry");

    let err =
        verify_did_log_for_publish(&jsonl, None, 0).expect_err("garbage tail must be refused");
    assert!(!err.is_empty());
}

// ---- servable_did_log ----

/// An unwitnessed log is served unchanged — the ordinary case.
#[tokio::test]
async fn servable_serves_an_unwitnessed_log_unchanged() {
    let key = signing_key();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(
            key.get_public_keymultibase().unwrap(),
        )])),
        portable: Some(false),
        ..Default::default()
    };
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let jsonl = to_jsonl(&state);

    assert_eq!(super::servable_did_log(&jsonl, None), Some(jsonl));
}

/// A witnessed genesis with no proof yet is not servable at all —
/// nothing has ever been witnessed, so there is no earlier version to
/// fall back to.
#[tokio::test]
async fn servable_refuses_a_witnessed_genesis_with_no_proof() {
    let key = signing_key();
    let (_witness_key, witness_did) = witness_identity();
    let params = witnessed_genesis_params(&key, &witness_did, 1);
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let jsonl = to_jsonl(&state);

    assert_eq!(super::servable_did_log(&jsonl, None), None);
}

/// A witnessed genesis whose proof has arrived is served in full,
/// including an unwitnessed republish that follows it — did:webvh's own
/// truncation semantics: the DID still resolves to its last witnessed
/// version rather than going dark the moment a new version registers.
#[tokio::test]
async fn servable_truncates_an_unwitnessed_tail_but_keeps_the_witnessed_prefix() {
    let key = signing_key();
    let (witness_key, witness_did) = witness_identity();
    let params = witnessed_genesis_params(&key, &witness_did, 1);
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);

    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(Some(base_time()), &doc, &params, &key)
        .await
        .expect("genesis entry");
    let genesis_jsonl = to_jsonl(&state);
    let genesis_version_id = state
        .log_entries()
        .last()
        .unwrap()
        .get_version_id()
        .to_string();
    let genesis_doc = state.log_entries().last().unwrap().get_state().clone();

    state
        .create_log_entry(
            Some(base_time() + Duration::seconds(1)),
            &genesis_doc,
            &Parameters::default(),
            &key,
        )
        .await
        .expect("second entry");
    let full_jsonl = to_jsonl(&state);

    let proof = sign_witness_proof(&witness_key, &genesis_version_id).await;
    let witness_content = witness_file(&genesis_version_id, &proof);

    assert_eq!(
        super::servable_did_log(&full_jsonl, Some(&witness_content)),
        Some(genesis_jsonl),
        "only the witnessed genesis is servable; the unwitnessed republish is truncated"
    );
}

/// Content that doesn't parse as a did:webvh log at all — an integration
/// test's simplified fixture, or unrelated bytes — is served unchanged.
/// Witness enforcement is not this function's call to make when it
/// cannot even tell whether witnessing was declared.
#[test]
fn servable_fails_open_on_content_it_cannot_parse() {
    let fixture =
        "{\"versionId\":\"1-test\",\"state\":{\"id\":\"did:webvh:test:example.com:alice\"}}";
    assert_eq!(
        super::servable_did_log(fixture, None),
        Some(fixture.to_string())
    );
}

// ---- verify_witness_proof_for_version (SEC finding #165) ----

/// A proof from the log's own configured witness, over the genesis
/// versionId, verifies.
#[tokio::test]
async fn witness_proof_for_version_accepts_a_proof_from_the_named_witness() {
    let key = signing_key();
    let (witness_key, witness_did) = witness_identity();
    let params = witnessed_genesis_params(&key, &witness_did, 1);
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let jsonl = to_jsonl(&state);
    let version_id = state
        .log_entries()
        .last()
        .unwrap()
        .get_version_id()
        .to_string();

    let proof = sign_witness_proof(&witness_key, &version_id).await;
    let proof_value = serde_json::to_value(&proof).unwrap();

    super::verify_witness_proof_for_version(&jsonl, &version_id, &proof_value)
        .expect("a proof from the named witness, over the right versionId, must verify");
}

/// A proof that is cryptographically well-formed and self-consistent —
/// it verifies against its own embedded `did:key` — but signed by a key
/// the log's `witness` parameter does not name, must still be refused.
/// This is the actual fix: a bare signature check alone would accept
/// this, since a `did:key` proof always "verifies" against itself.
#[tokio::test]
async fn witness_proof_for_version_rejects_a_proof_from_an_unnamed_key() {
    let key = signing_key();
    let (_witness_key, witness_did) = witness_identity();
    let params = witnessed_genesis_params(&key, &witness_did, 1);
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let jsonl = to_jsonl(&state);
    let version_id = state
        .log_entries()
        .last()
        .unwrap()
        .get_version_id()
        .to_string();

    let (forger_key, _forger_did) = witness_identity();
    let proof = sign_witness_proof(&forger_key, &version_id).await;
    let proof_value = serde_json::to_value(&proof).unwrap();

    let err = super::verify_witness_proof_for_version(&jsonl, &version_id, &proof_value)
        .expect_err("a proof from a non-witness key must not verify");
    assert!(err.contains("does not name a witness"), "{err}");
}

/// A proof naming a `versionId` this log has never published is
/// refused outright — there is no entry to check it against, and
/// nothing should be persisted for a version that doesn't exist yet.
#[tokio::test]
async fn witness_proof_for_version_rejects_an_unknown_version_id() {
    let key = signing_key();
    let (witness_key, witness_did) = witness_identity();
    let params = witnessed_genesis_params(&key, &witness_did, 1);
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let jsonl = to_jsonl(&state);

    let proof = sign_witness_proof(&witness_key, "99-doesnotexist").await;
    let proof_value = serde_json::to_value(&proof).unwrap();

    let err = super::verify_witness_proof_for_version(&jsonl, "99-doesnotexist", &proof_value)
        .expect_err("an unpublished versionId must be refused");
    assert!(err.contains("not in this DID's"), "{err}");
}

/// Malformed `proof` shape (not a `DataIntegrityProof` at all) is
/// refused before anything else is checked.
#[tokio::test]
async fn witness_proof_for_version_rejects_a_malformed_proof_shape() {
    let key = signing_key();
    let (_witness_key, witness_did) = witness_identity();
    let params = witnessed_genesis_params(&key, &witness_did, 1);
    let doc = doc_with_key("did:webvh:{SCID}:example.com", &key);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let jsonl = to_jsonl(&state);
    let version_id = state
        .log_entries()
        .last()
        .unwrap()
        .get_version_id()
        .to_string();

    let bogus = json!({ "type": "DataIntegrityProof" });
    let err = super::verify_witness_proof_for_version(&jsonl, &version_id, &bogus)
        .expect_err("a malformed proof shape must be refused");
    assert!(err.contains("invalid witness proof shape"), "{err}");
}

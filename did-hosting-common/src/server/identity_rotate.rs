//! `identity-rotate-keys` — rotate the service's own key-agreement key.
//!
//! Produces the one thing an operator could not previously produce: a signed v2
//! webvh log entry that installs a new key-agreement key **on a fresh
//! verification-method fragment**, together with the store and secret-store state
//! that lets the outgoing key keep working through a grace period.
//!
//! # Why a fresh fragment is not a style choice
//!
//! The secrets resolver is a map keyed by kid, and inbound JWEs name their
//! recipient by kid. Two keys therefore cannot both answer to `#key-1`. A
//! rotation that reuses the fragment has **no expressible grace period** —
//! whichever key is held, half the peers fail. Rotating onto a fresh fragment is
//! what lets the old and new key be held at once, which is the entire point of
//! the overlap.
//!
//! So the new key is published at `#<its own multibase>` — self-describing, and
//! it can never collide with a previous one.
//!
//! # Offline, deliberately
//!
//! This opens the store directly, so the service must be **stopped**. That is not
//! a limitation being worked around: doing it offline is what makes the whole
//! sequence atomic from the service's point of view. It comes back up already
//! holding both generations, with no window in which the document and the key
//! material disagree.
//!
//! The three writes — the log, the secret store, the generation records — are the
//! irreducible unit. Losing any one of them mid-way is what the ordering below is
//! chosen to survive.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use didwebvh_rs::{
    DIDWebVHState,
    log_entry::{LogEntry, LogEntryMethods},
    log_entry_state::{LogEntryState, LogEntryValidationStatus},
    parameters::Parameters,
};
use serde_json::{Value, json};

use crate::did_ops::content_log_key;
use crate::server::auth::session::now_epoch;
use crate::server::error::AppError;
use crate::server::identity::{IdentityGeneration, load_generations, mnemonic_from_did};
use crate::server::secret_store::{RetiredKeys, SecretStore};
use crate::server::store::{KS_DIDS, KS_IDENTITY, Store};

/// What a rotation did, for the caller to report.
pub struct RotationReport {
    pub did: String,
    pub new_ka_kid: String,
    pub retired_ka_kid: String,
    pub new_generation: u64,
    pub retired_generation: u64,
    pub expires_at: u64,
    pub version_count: usize,
}

/// Load a `did.jsonl` into a `DIDWebVHState`, validating the chain.
///
/// Mirrors `did_ops::verify_did_log_proofs`'s parse, but keeps the state so we
/// can append to it. Validation is not optional here: appending to a chain we
/// have not verified would let a corrupted log silently become a signed one.
fn load_validated_state(content: &str) -> Result<DIDWebVHState, AppError> {
    let mut state = DIDWebVHState::default();
    let mut version = None;

    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = LogEntry::deserialize_string(line, version)
            .map_err(|e| AppError::Config(format!("invalid log entry at line {}: {e}", idx + 1)))?;
        version = Some(entry.get_webvh_version());
        let version_number = entry
            .get_version_id_fields()
            .map_err(|e| AppError::Config(format!("invalid versionId at line {}: {e}", idx + 1)))?
            .0;
        state.log_entries_mut().push(LogEntryState {
            log_entry: entry,
            version_number,
            validation_status: LogEntryValidationStatus::NotValidated,
            validated_parameters: Parameters::default(),
        });
    }

    if state.log_entries().is_empty() {
        return Err(AppError::Config("the DID log is empty".into()));
    }

    // `validate` returns a report rather than erroring on a partial chain, so
    // ignoring it would let a truncated or partially-verified log through — and
    // we are about to *sign* on top of whatever this returns.
    let report = state
        .validate()
        .map_err(|e| AppError::Config(format!("the existing DID log does not verify: {e}")))?;
    report.assert_complete().map_err(|e| {
        AppError::Config(format!(
            "the existing DID log is incomplete: {e} — refusing to append"
        ))
    })?;

    Ok(state)
}

/// Replace the document's key-agreement key with a new one on a fresh fragment.
///
/// Everything else is carried through untouched — services (mediator, TSP), the
/// authentication key, contexts. A key rotation must not quietly become a service
/// change.
fn rotate_key_agreement(doc: &Value, did_id: &str, new_ka_multibase: &str) -> (Value, String) {
    let mut doc = doc.clone();
    let new_kid = format!("{did_id}#{new_ka_multibase}");

    // The kids currently serving keyAgreement. Anything naming them has to go.
    let old_kids: Vec<String> = doc
        .get("keyAgreement")
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(|r| r.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    if let Some(vms) = doc
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
    {
        // Drop the outgoing key-agreement verification method. Note this only
        // removes methods that keyAgreement actually *referenced* — a key doing
        // double duty elsewhere in the document is left alone.
        vms.retain(|vm| {
            vm.get("id")
                .and_then(Value::as_str)
                .is_none_or(|id| !old_kids.iter().any(|k| k == id))
        });
        vms.push(json!({
            "id": new_kid,
            "type": "Multikey",
            "controller": did_id,
            "publicKeyMultibase": new_ka_multibase,
        }));
    }

    doc["keyAgreement"] = json!([new_kid]);
    (doc, new_kid)
}

/// Rotate the service's own key-agreement key.
///
/// The service must be **stopped** — this writes the DID log, the secret store,
/// and the generation records directly.
///
/// `grace_secs` is how long the outgoing key keeps being honoured. `0` retires it
/// at once (correct for a compromised key, and it means peers holding a stale
/// document cannot reach the service until their cache expires).
pub async fn rotate_key_agreement_key(
    store: &Store,
    secret_store: &dyn SecretStore,
    server_did: &str,
    new_ka_key: Option<&str>,
    grace_secs: u64,
) -> Result<RotationReport, AppError> {
    let Some(mnemonic) = mnemonic_from_did(server_did) else {
        return Err(AppError::Config(format!(
            "`{server_did}` is not a did:webvh identifier this service hosts"
        )));
    };

    let Some(mut secrets) = secret_store.get().await? else {
        return Err(AppError::Config(
            "secret store holds no server secrets".into(),
        ));
    };

    // --- read and verify the current chain -------------------------------
    let dids_ks = store.keyspace(KS_DIDS)?;
    let Some(raw) = dids_ks.get_raw(content_log_key(&mnemonic)).await? else {
        return Err(AppError::Config(format!(
            "no DID log stored at `{mnemonic}` — is `server_did` right?"
        )));
    };
    let content = String::from_utf8(raw)
        .map_err(|e| AppError::Config(format!("DID log is not valid UTF-8: {e}")))?;

    let mut state = load_validated_state(&content)?;

    let last = state
        .log_entries()
        .last()
        .ok_or_else(|| AppError::Config("the DID log is empty".into()))?;
    let current_doc = last.log_entry.get_state().clone();
    let params = last.validated_parameters.clone();

    let did_id = current_doc
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Config("the DID document has no `id`".into()))?
        .to_string();

    // --- the outgoing key, before anything overwrites it ------------------
    //
    // Read from the *document*, not from config: it is the document that says
    // which kid peers are encrypting to, and that is the kid the retired secret
    // has to be filed under to be found again.
    let retired_ka_kid = current_doc
        .get("keyAgreement")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Config("the DID document advertises no keyAgreement key to rotate".into())
        })?
        .to_string();

    // --- the incoming key -------------------------------------------------
    let new_ka = match new_ka_key {
        Some(multibase) => Secret::from_multibase(multibase, None)
            .map_err(|e| AppError::Config(format!("invalid --ka-key: {e}")))?,
        None => Secret::generate_x25519(None, None)
            .map_err(|e| AppError::Config(format!("failed to generate an X25519 key: {e}")))?,
    };
    let new_ka_multibase = new_ka
        .get_public_keymultibase()
        .map_err(|e| AppError::Config(format!("failed to derive the new public key: {e}")))?;

    // The fresh fragment. This is what makes the grace period expressible —
    // see the module docs.
    let (new_doc, new_ka_kid) = rotate_key_agreement(&current_doc, &did_id, &new_ka_multibase);

    if new_ka_kid == retired_ka_kid {
        return Err(AppError::Config(
            "the new key-agreement key is identical to the current one — nothing to rotate".into(),
        ));
    }

    // --- sign the new entry with the *current* update key ------------------
    //
    // The signing key is unchanged: this rotates the encryption key, not the
    // authority to update the DID. didwebvh validates that the signer is
    // authorised by the chain's active `updateKeys`.
    let signing = Secret::from_multibase(&secrets.signing_key, None)
        .map_err(|e| AppError::Config(format!("failed to decode signing_key: {e}")))?;
    let signing_multibase = signing
        .get_public_keymultibase()
        .map_err(|e| AppError::Config(format!("failed to derive the signing public key: {e}")))?;

    // didwebvh-rs requires the signer's verification method to embed its own
    // multibase key. Mirrors `did::create_log_entry`.
    let mut signer = signing.clone();
    if !signer.id.contains('#') {
        signer.id = format!("did:key:{signing_multibase}#{signing_multibase}");
    }

    state
        .create_log_entry(None, &new_doc, &params, &signer)
        .await
        .map_err(|e| AppError::Config(format!("failed to sign the new log entry: {e}")))?;

    let new_line = serde_json::to_string(
        &state
            .log_entries()
            .last()
            .expect("just appended an entry")
            .log_entry,
    )?;
    let version_count = state.log_entries().len();

    let mut new_log = content.trim_end().to_string();
    new_log.push('\n');
    new_log.push_str(&new_line);
    new_log.push('\n');

    // Verify what we are about to publish, before we publish it. A log we signed
    // but that does not verify is worse than no rotation at all.
    crate::did_ops::verify_did_log_proofs(&new_log)
        .map_err(|e| AppError::Config(format!("the rotated DID log does not verify: {e}")))?;

    // --- write, in the order that survives a crash -------------------------
    //
    // 1. Secret store first, carrying the outgoing key into `retired` in the
    //    SAME write that installs its replacement. There is no compare-and-swap,
    //    so this is the one write that must not lose the old key. A crash after
    //    it leaves both keys recoverable and the document unchanged — the service
    //    comes back on the old identity, which is a safe place to be.
    //
    // 2. The generation records, so a restart knows the old key is still live.
    //
    // 3. The DID log last. Once this lands the document advertises the new key,
    //    and by then everything needed to honour both is already durable.
    let now = now_epoch();
    let expires_at = now.saturating_add(grace_secs);

    if grace_secs > 0 {
        secrets.retired.retain(|r| r.ka_kid != retired_ka_kid);
        secrets.retired.push(RetiredKeys {
            ka_kid: retired_ka_kid.clone(),
            key_agreement_key: secrets.key_agreement_key.clone(),
            // The signing key is unchanged by a key-agreement rotation, so the
            // retired generation shares it. Recorded so the generation is fully
            // reconstructible on its own.
            signing_kid: format!("{did_id}#key-0"),
            signing_key: secrets.signing_key.clone(),
        });
    }
    secrets.key_agreement_key = new_ka
        .get_private_keymultibase()
        .map_err(|e| AppError::Config(format!("failed to encode the new private key: {e}")))?;
    secret_store.set(&secrets).await?;

    // 2. Generation records.
    let identity_ks = store.keyspace(KS_IDENTITY)?;
    let live = load_generations(&identity_ks, now).await?;
    let current = live.first().cloned().ok_or_else(|| {
        AppError::Config(
            "no identity generation recorded — start the service once so it can resolve its own \
             DID, then rotate"
                .into(),
        )
    })?;

    let mut retiring = current.clone();
    retiring.retired_at = Some(now);
    retiring.expires_at = Some(expires_at);

    let new_generation = IdentityGeneration {
        id: current.id + 1,
        did: did_id.clone(),
        signing_kid: current.signing_kid.clone(),
        ka_kid: new_ka_kid.clone(),
        ka_public_multibase: Some(new_ka_multibase),
        mediator_did: current.mediator_did.clone(),
        protocols: current.protocols,
        created_at: now,
        retired_at: None,
        expires_at: None,
    };

    let mut batch = store.batch();
    if grace_secs > 0 {
        batch.insert(
            &identity_ks,
            format!("identity:gen:{:020}", retiring.id),
            &retiring,
        )?;
    }
    batch.insert(
        &identity_ks,
        format!("identity:gen:{:020}", new_generation.id),
        &new_generation,
    )?;
    batch.insert(
        &identity_ks,
        b"identity:current".to_vec(),
        &new_generation.id,
    )?;
    batch.commit().await?;

    // 3. The DID log. The document now advertises the new key.
    dids_ks
        .insert_raw(content_log_key(&mnemonic), new_log.into_bytes())
        .await?;
    store.persist().await?;

    Ok(RotationReport {
        did: did_id,
        new_ka_kid,
        retired_ka_kid,
        new_generation: new_generation.id,
        retired_generation: retiring.id,
        expires_at,
        version_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:webvh:QmSCID:example.com";

    fn doc_with_ka(ka_kid: &str, ka_multibase: &str) -> Value {
        json!({
            "id": DID,
            "authentication": [format!("{DID}#key-0")],
            "keyAgreement": [ka_kid],
            "verificationMethod": [
                { "id": format!("{DID}#key-0"), "type": "Multikey",
                  "controller": DID, "publicKeyMultibase": "z6MkSigning" },
                { "id": ka_kid, "type": "Multikey",
                  "controller": DID, "publicKeyMultibase": ka_multibase },
            ],
            "service": [
                { "id": format!("{DID}#vta-didcomm"), "type": "DIDCommMessaging",
                  "serviceEndpoint": { "uri": "did:web:mediator.example" } }
            ],
        })
    }

    #[test]
    fn the_new_key_lands_on_a_fresh_fragment() {
        // The whole reason this command exists. Reusing `#key-1` would make the
        // grace period inexpressible — a kid identifies exactly one key, so the
        // old and new secret cannot both be held.
        let doc = doc_with_ka(&format!("{DID}#key-1"), "z6LSold");
        let (rotated, new_kid) = rotate_key_agreement(&doc, DID, "z6LSnew");

        assert_eq!(new_kid, format!("{DID}#z6LSnew"));
        assert_ne!(new_kid, format!("{DID}#key-1"));
        assert_eq!(rotated["keyAgreement"], json!([new_kid]));
    }

    #[test]
    fn the_outgoing_key_is_removed_from_the_document() {
        // Leaving it published would advertise a key we are about to stop using
        // for outbound — peers would pick it by document order and encrypt to a
        // key we are retiring.
        let old_kid = format!("{DID}#key-1");
        let doc = doc_with_ka(&old_kid, "z6LSold");
        let (rotated, _) = rotate_key_agreement(&doc, DID, "z6LSnew");

        let vms = rotated["verificationMethod"].as_array().unwrap();
        assert!(
            !vms.iter().any(|vm| vm["id"] == json!(old_kid)),
            "the retired key-agreement method must not stay published"
        );
        assert!(
            vms.iter()
                .any(|vm| vm["publicKeyMultibase"] == json!("z6LSnew")),
            "the new key must be published"
        );
    }

    #[test]
    fn a_key_rotation_does_not_quietly_become_a_service_change() {
        // Services and the authentication key are carried through untouched. A
        // rotation that silently dropped the mediator endpoint would look like a
        // key rotation and behave like a mediator change — with a drain, a second
        // connection, and a very confused operator.
        let doc = doc_with_ka(&format!("{DID}#key-1"), "z6LSold");
        let (rotated, _) = rotate_key_agreement(&doc, DID, "z6LSnew");

        assert_eq!(rotated["service"], doc["service"], "services must survive");
        assert_eq!(
            rotated["authentication"], doc["authentication"],
            "the signing key is not what a key-agreement rotation touches"
        );

        let vms = rotated["verificationMethod"].as_array().unwrap();
        assert!(
            vms.iter()
                .any(|vm| vm["id"] == json!(format!("{DID}#key-0"))),
            "the authentication verification method must survive"
        );
    }
}

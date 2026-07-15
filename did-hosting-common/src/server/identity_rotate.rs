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
    pub which: RotateKeys,
    pub new_ka_kid: String,
    pub retired_ka_kid: String,
    pub new_signing_kid: String,
    pub retired_signing_kid: String,
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
pub(crate) fn load_validated_state(content: &str) -> Result<DIDWebVHState, AppError> {
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

/// Replace the document's **signing** key — the one that authorises DID updates.
///
/// Rewrites `authentication` and `assertionMethod` onto a fresh fragment. The
/// caller must also set `updateKeys` to the new public key in the log entry's
/// parameters; that is what actually revokes the old key's authority to publish.
fn rotate_signing(doc: &Value, did_id: &str, new_signing_multibase: &str) -> (Value, String) {
    let mut doc = doc.clone();
    let new_kid = format!("{did_id}#{new_signing_multibase}");

    // Everything the outgoing signing key was named by. A key can appear in both
    // `authentication` and `assertionMethod`, so collect from both.
    let mut old_kids: Vec<String> = Vec::new();
    for rel in ["authentication", "assertionMethod"] {
        if let Some(refs) = doc.get(rel).and_then(Value::as_array) {
            for r in refs.iter().filter_map(Value::as_str) {
                if !old_kids.iter().any(|k| k == r) {
                    old_kids.push(r.to_string());
                }
            }
        }
    }

    // Anything the key-agreement relationship still points at must survive — a
    // signing rotation must not take the encryption key with it.
    let ka_kids: Vec<String> = doc
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
        vms.retain(|vm| {
            let Some(id) = vm.get("id").and_then(Value::as_str) else {
                return true;
            };
            let is_old_signing = old_kids.iter().any(|k| k == id);
            let still_used_for_ka = ka_kids.iter().any(|k| k == id);
            !is_old_signing || still_used_for_ka
        });
        vms.push(json!({
            "id": new_kid,
            "type": "Multikey",
            "controller": did_id,
            "publicKeyMultibase": new_signing_multibase,
        }));
    }

    doc["authentication"] = json!([new_kid]);
    if doc.get("assertionMethod").is_some() {
        doc["assertionMethod"] = json!([new_kid]);
    }

    (doc, new_kid)
}

/// Which keys a rotation touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateKeys {
    /// The key-agreement (encryption) key only. The common case, and the one the
    /// grace window is built for.
    KeyAgreement,
    /// The signing key only — the DID's `updateKeys`, i.e. the authority to
    /// publish new versions of the document.
    Signing,
    /// Both, in one log entry.
    Both,
}

impl RotateKeys {
    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ka" | "key-agreement" | "keyagreement" => Ok(Self::KeyAgreement),
            "signing" | "update" => Ok(Self::Signing),
            "both" | "all" => Ok(Self::Both),
            other => Err(AppError::Config(format!(
                "invalid --keys '{other}' (expected 'ka', 'signing', or 'both')"
            ))),
        }
    }

    fn rotates_ka(self) -> bool {
        matches!(self, Self::KeyAgreement | Self::Both)
    }

    fn rotates_signing(self) -> bool {
        matches!(self, Self::Signing | Self::Both)
    }
}

/// Rotate the service's own keys.
///
/// The service must be **stopped** — this writes the DID log, the secret store,
/// and the generation records directly.
///
/// `grace_secs` is how long the outgoing key-agreement key keeps being honoured.
/// `0` retires it at once (correct for a compromised key, and it means peers
/// holding a stale document cannot reach the service until their cache expires).
///
/// # What the grace period does and does not cover
///
/// It covers the **key-agreement** key: the old and new both stay loaded, so a
/// peer with a cached document can still be decrypted. That is what the overlap
/// is for.
///
/// It does **not** overlap the **signing** key, and cannot. The signing key's
/// authority to update the DID is revoked the moment the new `updateKeys` land —
/// which is the entire point when it is compromised, and is not something you
/// would want to defer. The knock-on is that a peer holding a stale document will
/// reject signatures made with the new key until it re-resolves (bounded by its
/// cache TTL). Overlapping that would require publishing both signing keys and a
/// *second* publish to withdraw the old one — a two-phase rotation this does not
/// attempt, because for the case that matters (a compromised update key) you want
/// the old key dead immediately, not in an hour.
pub async fn rotate_keys(
    store: &Store,
    secret_store: &dyn SecretStore,
    server_did: &str,
    which: RotateKeys,
    new_ka_key: Option<&str>,
    new_signing_key: Option<&str>,
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

    let retired_signing_kid = current_doc
        .get("authentication")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // --- the incoming key(s) ----------------------------------------------
    let mut new_doc = current_doc.clone();
    let mut new_params = params.clone();

    let (new_ka_kid, new_ka_multibase, new_ka_private) = if which.rotates_ka() {
        let new_ka = match new_ka_key {
            Some(multibase) => Secret::from_multibase(multibase, None)
                .map_err(|e| AppError::Config(format!("invalid --ka-key: {e}")))?,
            None => Secret::generate_x25519(None, None)
                .map_err(|e| AppError::Config(format!("failed to generate an X25519 key: {e}")))?,
        };
        let multibase = new_ka
            .get_public_keymultibase()
            .map_err(|e| AppError::Config(format!("failed to derive the new public key: {e}")))?;

        // The fresh fragment. This is what makes the grace period expressible —
        // see the module docs.
        let (doc, kid) = rotate_key_agreement(&new_doc, &did_id, &multibase);
        if kid == retired_ka_kid {
            return Err(AppError::Config(
                "the new key-agreement key is identical to the current one — nothing to rotate"
                    .into(),
            ));
        }
        new_doc = doc;
        let private = new_ka
            .get_private_keymultibase()
            .map_err(|e| AppError::Config(format!("failed to encode the new private key: {e}")))?;
        (kid, Some(multibase), Some(private))
    } else {
        (retired_ka_kid.clone(), None, None)
    };

    // The key that will SIGN this entry. Always the *current* update key — the
    // entry that introduces a new one must be authorised by the old one, which is
    // what makes the rotation verifiable to anyone walking the chain.
    let signing = Secret::from_multibase(&secrets.signing_key, None)
        .map_err(|e| AppError::Config(format!("failed to decode signing_key: {e}")))?;
    let signing_multibase = signing
        .get_public_keymultibase()
        .map_err(|e| AppError::Config(format!("failed to derive the signing public key: {e}")))?;

    let (new_signing_kid, new_signing_private) = if which.rotates_signing() {
        let new_signing = match new_signing_key {
            Some(multibase) => Secret::from_multibase(multibase, None)
                .map_err(|e| AppError::Config(format!("invalid --signing-key: {e}")))?,
            None => Secret::generate_ed25519(None, None),
        };
        let multibase = new_signing.get_public_keymultibase().map_err(|e| {
            AppError::Config(format!("failed to derive the new signing public key: {e}"))
        })?;
        if multibase == signing_multibase {
            return Err(AppError::Config(
                "the new signing key is identical to the current one — nothing to rotate".into(),
            ));
        }

        let (doc, kid) = rotate_signing(&new_doc, &did_id, &multibase);
        new_doc = doc;

        // This is the line that actually revokes the old key's authority. From
        // this entry on, only the new key can sign a valid update — an attacker
        // holding the old one can no longer publish anything the chain accepts.
        new_params.update_keys = Some(std::sync::Arc::new(vec![multibase.into()]));

        let private = new_signing.get_private_keymultibase().map_err(|e| {
            AppError::Config(format!("failed to encode the new signing private key: {e}"))
        })?;
        (kid, Some(private))
    } else {
        (retired_signing_kid.clone(), None)
    };

    // didwebvh-rs requires the signer's verification method to embed its own
    // multibase key. Mirrors `did::create_log_entry`.
    let mut signer = signing.clone();
    if !signer.id.contains('#') {
        signer.id = format!("did:key:{signing_multibase}#{signing_multibase}");
    }

    state
        .create_log_entry(None, &new_doc, &new_params, &signer)
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
        // The outgoing key material, filed under the kids the *document* named it
        // by — that is how `secrets_for` finds it again for a retired generation.
        secrets.retired.retain(|r| r.ka_kid != retired_ka_kid);
        secrets.retired.push(RetiredKeys {
            ka_kid: retired_ka_kid.clone(),
            key_agreement_key: secrets.key_agreement_key.clone(),
            signing_kid: retired_signing_kid.clone(),
            signing_key: secrets.signing_key.clone(),
        });
    }
    if let Some(private) = new_ka_private {
        secrets.key_agreement_key = private;
    }
    if let Some(private) = new_signing_private {
        secrets.signing_key = private;
    }
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
        signing_kid: new_signing_kid.clone(),
        ka_kid: new_ka_kid.clone(),
        // Carried forward when the key-agreement key was not rotated: it is still
        // the same key, and `None` would read as "unknown" and disarm the
        // same-kid-rotation guard.
        ka_public_multibase: new_ka_multibase
            .clone()
            .or(current.ka_public_multibase.clone()),
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
        which,
        new_ka_kid,
        retired_ka_kid,
        new_signing_kid,
        retired_signing_kid,
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
    fn a_signing_rotation_moves_the_authentication_key_and_leaves_encryption_alone() {
        // The security-critical rotation: the signing key IS the DID's
        // `updateKeys` — the authority to publish new versions. It must move, and
        // it must not take the encryption key with it.
        let ka_kid = format!("{DID}#z6LSka");
        let doc = doc_with_ka(&ka_kid, "z6LSka");
        let (rotated, new_kid) = rotate_signing(&doc, DID, "z6MkNewSigning");

        assert_eq!(new_kid, format!("{DID}#z6MkNewSigning"));
        assert_eq!(rotated["authentication"], json!([new_kid]));

        // The old signing method is gone from the document...
        let vms = rotated["verificationMethod"].as_array().unwrap();
        assert!(
            !vms.iter()
                .any(|vm| vm["id"] == json!(format!("{DID}#key-0"))),
            "the superseded signing key must not stay published"
        );

        // ...but the key-agreement key is untouched. A signing rotation that
        // silently dropped the encryption key would take every peer offline.
        assert_eq!(rotated["keyAgreement"], doc["keyAgreement"]);
        assert!(
            vms.iter().any(|vm| vm["id"] == json!(ka_kid)),
            "the key-agreement verification method must survive a signing rotation"
        );
        assert_eq!(rotated["service"], doc["service"], "services must survive");
    }

    #[test]
    fn a_key_doing_double_duty_survives_a_signing_rotation() {
        // A document may name one key for both authentication and keyAgreement.
        // Removing it as "the old signing key" would silently destroy the
        // encryption key too — so the removal is conditional on the key not still
        // being referenced by keyAgreement.
        let shared = format!("{DID}#z6MkShared");
        let doc = json!({
            "id": DID,
            "authentication": [shared],
            "keyAgreement": [shared],
            "verificationMethod": [
                { "id": shared, "type": "Multikey",
                  "controller": DID, "publicKeyMultibase": "z6MkShared" },
            ],
        });

        let (rotated, _) = rotate_signing(&doc, DID, "z6MkNewSigning");

        let vms = rotated["verificationMethod"].as_array().unwrap();
        assert!(
            vms.iter().any(|vm| vm["id"] == json!(shared)),
            "a key still referenced by keyAgreement must not be removed as a stale signing key"
        );
        assert_eq!(rotated["keyAgreement"], json!([shared]));
    }

    #[test]
    fn rotate_keys_parses_the_operator_facing_names() {
        assert_eq!(RotateKeys::parse("ka").unwrap(), RotateKeys::KeyAgreement);
        assert_eq!(RotateKeys::parse("signing").unwrap(), RotateKeys::Signing);
        assert_eq!(RotateKeys::parse("both").unwrap(), RotateKeys::Both);
        assert!(RotateKeys::parse("everything").is_err());
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

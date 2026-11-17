//! Storing a witness's proof for one version of a did:webvh log
//! (`webvh/witness/publish`).

use did_hosting_common::did_ops::{content_log_key, content_witness_key};
use did_hosting_common::server::error::ValidationKind;
use tracing::info;

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;

use super::{get_authorized_record, invalidate_cached_content, validate_slot_mnemonic};

/// Upload witness content for a DID.
pub async fn upload_witness(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    witness_entry: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AppError> {
    validate_slot_mnemonic(&state.dids_ks, mnemonic).await?;

    // Same per-path write lock as `register_did_atomic`: merging a proof
    // into the stored witness file is a read-modify-write, and two
    // witnesses publishing at once would otherwise each write back only
    // their own proof, silently dropping the other's.
    let _path_guard = state.path_locks.guard(mnemonic).await;

    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    // did-witness.json is a did:webvh artifact. A did:webs slot's witness
    // receipts travel inside its key event log, and are verified there.
    if record.method == "webs" {
        return Err(AppError::validation(
            ValidationKind::InvalidWitness,
            "a did:webs slot takes no did-witness.json: its witness receipts are part of \
             its key event log",
        ));
    }

    // `webvh/witness/publish`'s `witness` member is one witness's proof for
    // one version — `{versionId, witness, proof}` — not the did-witness.json
    // file shape (`[{versionId, proof: [...]}, ...]`, one entry per version,
    // each aggregating every witness's proof for it). Extract the two fields
    // the stored file needs; `witness` (which witness signed) travels inside
    // `proof.verificationMethod` already and is not stored separately. The
    // proof is verified below, against this DID's own stored log, before
    // either field is persisted.
    let version_id = witness_entry
        .get("versionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AppError::validation(
                ValidationKind::InvalidWitness,
                "witness object must have a string \"versionId\"",
            )
        })?
        .to_string();
    let proof = witness_entry.get("proof").cloned().ok_or_else(|| {
        AppError::validation(
            ValidationKind::InvalidWitness,
            "witness object must have a \"proof\"",
        )
    })?;

    // Verify the proof before it ever touches storage: it must
    // cryptographically verify over `version_id`, and the key that signed it
    // must actually be one of the witnesses this DID's own log configures
    // for that version — not merely a self-consistent `did:key` signature,
    // which any attacker-generated key can produce for itself. Deferring
    // this to resolve time (as before) let any caller authorized on the
    // mnemonic — not necessarily a witness — persist an arbitrary proof
    // blob; resolve-time verification meant it was never *served*, but it
    // still polluted the witness-content store. See
    // `did_hosting_common::did_ops::verify_witness_proof_for_version`'s doc
    // for why the threshold itself stays a resolve-time check.
    let log_content = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| {
            AppError::validation(
                ValidationKind::InvalidWitness,
                "no published log exists for this DID yet",
            )
        })?;
    let log_content = String::from_utf8(log_content)
        .map_err(|e| AppError::Internal(format!("stored did:webvh log is not valid UTF-8: {e}")))?;
    did_hosting_common::did_ops::verify_witness_proof_for_version(
        &log_content,
        &version_id,
        &proof,
    )
    .map_err(|e| AppError::validation(ValidationKind::InvalidWitness, e))?;

    // Merge into the existing file rather than overwrite it: a threshold
    // greater than one needs more than one witness's proof recorded per
    // version, and earlier versions' entries must survive a later
    // publish. An existing blob this control plane cannot parse is
    // replaced rather than left to wedge every future publish — the
    // resolver-side threshold check is what actually gates serving, so
    // losing a corrupt blob costs nothing that mattered.
    let existing = state.dids_ks.get_raw(content_witness_key(mnemonic)).await?;
    let mut entries: Vec<serde_json::Value> = existing
        .and_then(|bytes| serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).ok())
        .unwrap_or_default();

    match entries
        .iter_mut()
        .find(|e| e.get("versionId").and_then(|v| v.as_str()) == Some(version_id.as_str()))
    {
        Some(entry) => match entry.get_mut("proof").and_then(|p| p.as_array_mut()) {
            // One proof per witness per version: a witness publishing again
            // (a retry, a re-sign) replaces its earlier proof rather than
            // growing the file with copies.
            Some(proofs) => {
                let signer = proof_signer(&proof).map(str::to_string);
                match proofs
                    .iter_mut()
                    .find(|p| signer.is_some() && proof_signer(p) == signer.as_deref())
                {
                    Some(earlier) => *earlier = proof,
                    None => proofs.push(proof),
                }
            }
            None => {
                entry["proof"] = serde_json::json!([proof]);
            }
        },
        None => entries.push(serde_json::json!({ "versionId": version_id, "proof": [proof] })),
    }

    let witness_content = serde_json::to_string(&entries)
        .map_err(|e| AppError::Internal(format!("failed to serialise did-witness.json: {e}")))?;

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_witness_key(mnemonic),
        witness_content.into_bytes(),
    );
    let sync = crate::server_push::stage_did_sync(
        state,
        &mut batch,
        mnemonic,
        crate::server_push::DidChange::Updated,
    )
    .await;
    batch.commit().await?;
    sync.finish(state).await;
    invalidate_cached_content(state, mnemonic);

    info!(did = %auth.did, mnemonic = %mnemonic, %version_id, "did-witness.json uploaded on control plane");

    Ok(())
}

/// The DID whose key made a witness proof: its `verificationMethod` without
/// the fragment.
pub(super) fn proof_signer(proof: &serde_json::Value) -> Option<&str> {
    proof
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .map(|vm| vm.split('#').next().unwrap_or(vm))
        .filter(|d| !d.is_empty())
}

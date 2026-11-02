//! `identity-scid-alias` — list or remove the did:scid alias of the service's
//! own DID, offline.
//!
//! Every did:webvh log is also `did:scid:vh:1:<scid>`; the two forms are one
//! subject only while the did:webvh document lists the did:scid DID URL in
//! `alsoKnownAs` (VTI-KEY-164). A service DID minted since the alias existed
//! lists it from its first entry (`hosting.scid_also_known_as`); this is how
//! one minted before — or with it turned off — gets it, or loses it.
//!
//! The service's own DID is the only log this service holds the update key
//! for. Every other hosted DID is signed by its owner (a VTA, through
//! `vta/webvh/dids/update/1.1`'s `scidAlsoKnownAs`), never here.
//!
//! Like `identity-rotate-keys`, this opens the store directly, so the service
//! must be **stopped**; the semantics are [`crate::scid::with_scid_alias`]'s —
//! a stale `src` is replaced, removal drops every entry of this SCID, and a
//! request that would change nothing is refused rather than signed.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use didwebvh_rs::log_entry::LogEntryMethods;

use crate::did_ops::{DidRecord, content_log_key, did_key};
use crate::scid::{ScidAliasError, ScidAliasInfo, scid_alias_info, with_scid_alias};
use crate::server::auth::session::now_epoch;
use crate::server::error::AppError;
use crate::server::identity::mnemonic_from_did;
use crate::server::identity_rotate::load_validated_state;
use crate::server::secret_store::SecretStore;
use crate::server::store::{KS_DIDS, Store};

/// What [`set_identity_scid_alias`] published.
pub struct ScidAliasReport {
    pub did: String,
    pub alias: ScidAliasInfo,
    pub version_count: usize,
}

/// Append an entry to `content` (a verified did:webvh log) whose document
/// lists (`list`) or no longer lists (`!list`) its did:scid alias, signed by
/// `signer` — which must be the log's current update key.
///
/// Parameters are carried over unchanged, so the update key does not rotate.
/// A log with pre-rotation active is refused: its next entry has to reveal a
/// pre-committed key, which this does not hold.
pub async fn append_scid_alias_entry(
    content: &str,
    signer: &Secret,
    list: bool,
) -> Result<(String, ScidAliasInfo, usize), AppError> {
    let mut state = load_validated_state(content)?;
    let last = state
        .log_entries()
        .last()
        .ok_or_else(|| AppError::Config("the DID log is empty".into()))?;
    let params = last.validated_parameters.clone();
    if params.deactivated == Some(true) {
        return Err(AppError::Config(
            "the DID is deactivated — its log takes no further entries".into(),
        ));
    }
    if params.pre_rotation_active
        || params
            .next_key_hashes
            .as_ref()
            .is_some_and(|h| !h.is_empty())
    {
        return Err(AppError::Config(
            "the DID log commits to pre-rotation, so its next entry must reveal a \
             pre-committed update key — this command signs with the current key only"
                .into(),
        ));
    }

    let current_doc = last.log_entry.get_state().clone();
    // versionTime must strictly increase at one-second resolution and may not
    // be in the future, so an entry appended within the second of the last one
    // waits out the rest of that second.
    let not_before = last.log_entry.get_version_time() + chrono::Duration::seconds(1);
    if let Ok(wait) = (not_before - chrono::Utc::now().fixed_offset()).to_std() {
        tokio::time::sleep(wait).await;
    }
    let new_doc = with_scid_alias(&current_doc, list).map_err(|e| match e {
        ScidAliasError::NoChange(why) => AppError::Config(format!("nothing to change: {why}")),
        ScidAliasError::NotWebvh => AppError::Config(e.to_string()),
    })?;
    let alias = scid_alias_info(&new_doc)
        .ok_or_else(|| AppError::Config("the DID document's id is not a did:webvh DID".into()))?;

    // didwebvh-rs requires the signer's verification method to embed its own
    // multibase key. Mirrors `did::create_log_entry`.
    let multibase = signer
        .get_public_keymultibase()
        .map_err(|e| AppError::Config(format!("failed to derive the signing public key: {e}")))?;
    let mut signer = signer.clone();
    if !signer.id.contains('#') {
        signer.id = format!("did:key:{multibase}#{multibase}");
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

    // Verify what we are about to publish, before we publish it.
    crate::did_ops::verify_did_log_proofs(&new_log)
        .map_err(|e| AppError::Config(format!("the new DID log does not verify: {e}")))?;

    Ok((new_log, alias, version_count))
}

/// List (`list`) or remove (`!list`) the did:scid alias of the service's own
/// DID `server_did`, signing with the service's signing key.
///
/// The service must be **stopped** — this writes the DID log directly. The
/// record's version count follows; edges pick the entry up on their next sync
/// from the control plane, as after `identity-rotate-keys`.
pub async fn set_identity_scid_alias(
    store: &Store,
    secret_store: &dyn SecretStore,
    server_did: &str,
    list: bool,
) -> Result<ScidAliasReport, AppError> {
    let Some(mnemonic) = mnemonic_from_did(server_did) else {
        return Err(AppError::Config(format!(
            "`{server_did}` is not a did:webvh identifier this service hosts"
        )));
    };
    let Some(secrets) = secret_store.get().await? else {
        return Err(AppError::Config(
            "secret store holds no server secrets".into(),
        ));
    };
    let signer = Secret::from_multibase(&secrets.signing_key, None)
        .map_err(|e| AppError::Config(format!("failed to decode signing_key: {e}")))?;

    let dids_ks = store.keyspace(KS_DIDS)?;
    let Some(raw) = dids_ks.get_raw(content_log_key(&mnemonic)).await? else {
        return Err(AppError::Config(format!(
            "no DID log stored at `{mnemonic}` — is `server_did` right?"
        )));
    };
    let content = String::from_utf8(raw)
        .map_err(|e| AppError::Config(format!("DID log is not valid UTF-8: {e}")))?;

    let (new_log, alias, version_count) = append_scid_alias_entry(&content, &signer, list).await?;
    let did = crate::did_ops::extract_did_id(&new_log).unwrap_or_else(|| server_did.to_string());

    let record: Option<DidRecord> = dids_ks.get(did_key(&mnemonic)).await?;
    let mut batch = store.batch();
    if let Some(mut record) = record {
        record.version_count = version_count as u64;
        record.content_size = new_log.len() as u64;
        record.updated_at = now_epoch();
        batch.insert(&dids_ks, did_key(&mnemonic), &record)?;
    }
    batch.insert_raw(&dids_ks, content_log_key(&mnemonic), new_log.into_bytes());
    batch.commit().await?;
    store.persist().await?;

    Ok(ScidAliasReport {
        did,
        alias,
        version_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::{DidDocumentOptions, build_did_document, create_log_entry};
    use crate::scid::ScidAliasStatus;
    use serde_json::Value;

    async fn log(omit_scid_alias: bool) -> (Secret, String) {
        let secret = Secret::generate_ed25519(None, None);
        let pk = secret.get_public_keymultibase().unwrap();
        let doc = build_did_document(
            "example.com",
            "services/control",
            &pk,
            &DidDocumentOptions {
                omit_scid_alias,
                ..Default::default()
            },
        );
        let (_scid, jsonl) = create_log_entry(&doc, &secret).await.unwrap();
        (secret, jsonl)
    }

    fn latest_state(log: &str) -> Value {
        let last: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
        last["state"].clone()
    }

    #[tokio::test]
    async fn lists_then_removes_the_alias_as_new_signed_entries() {
        let (secret, v1) = log(true).await;
        let (v2, info, count) = append_scid_alias_entry(&v1, &secret, true).await.unwrap();
        assert_eq!(count, 2);
        assert_eq!(info.status, ScidAliasStatus::Listed);
        assert!(info.did_url.ends_with("?src=example.com/services/control"));
        assert_eq!(
            latest_state(&v2)["alsoKnownAs"],
            serde_json::json!([info.did_url])
        );
        // Same update key: parameters carried over, so no rotation.
        let last: Value = serde_json::from_str(v2.lines().last().unwrap()).unwrap();
        assert!(last["parameters"].get("updateKeys").is_none(), "{last}");

        let (v3, info, count) = append_scid_alias_entry(&v2, &secret, false).await.unwrap();
        assert_eq!(count, 3);
        assert_eq!(info.status, ScidAliasStatus::NotListed);
        assert!(latest_state(&v3).get("alsoKnownAs").is_none());
    }

    #[tokio::test]
    async fn refuses_an_entry_that_changes_nothing() {
        let (secret, v1) = log(false).await;
        let err = append_scid_alias_entry(&v1, &secret, true)
            .await
            .expect_err("no-op refused");
        assert!(err.to_string().contains("nothing to change"), "{err}");
    }

    #[tokio::test]
    async fn refuses_a_key_that_is_not_the_update_key() {
        let (_secret, v1) = log(true).await;
        let stranger = Secret::generate_ed25519(None, None);
        assert!(append_scid_alias_entry(&v1, &stranger, true).await.is_err());
    }
}

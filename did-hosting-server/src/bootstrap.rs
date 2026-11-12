//! Server DID bootstrap — creates DID log entries for hosted DIDs.
//!
//! Shared logic used by both the `bootstrap-did` CLI subcommand and the
//! auto-bootstrap path on server startup.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use did_hosting_common::did::{
    DidDocumentOptions, build_did_document, create_log_entry, encode_host,
};
use tracing::info;

use crate::control_register::{stage_high_water, verify_history};
use crate::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, extract_did_id,
    extract_service_types, owner_key, validate_did_jsonl,
};
use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};
use did_hosting_common::did_ops::verify_did_log_and_witness_proofs;
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::domain::safety::extract_did_host;

/// Result of bootstrapping the root DID.
#[derive(Debug)]
pub struct BootstrapResult {
    pub scid: String,
    pub did_id: String,
    pub jsonl: String,
    pub mnemonic: String,
}

/// Have a witness service witness a freshly bootstrapped DID's last log entry
/// with `webvh/witness/sign/0.1`, and return the `did-witness.json` to serve
/// with it.
///
/// The request is signed by the new DID itself (its `#key-0`, the
/// `authentication` key [`bootstrap_did`] gives it), so the witness resolves
/// that DID to verify the request: the DID must already be served where its
/// identifier says, and the witness must list it as an administrator. The
/// witness verifies the whole log before it signs, and its signed reply is
/// verified against `witness_did` before the proof is used.
pub async fn request_witness_proof(
    witness_url: &str,
    witness_did: &str,
    witness_id: &str,
    result: &BootstrapResult,
    signing_secret: &Secret,
) -> Result<String, AppError> {
    let version_id = result
        .jsonl
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .and_then(|v| v.get("versionId")?.as_str().map(String::from))
        .ok_or_else(|| AppError::Internal("the DID log has no versionId to witness".into()))?;
    let mut signer = signing_secret.clone();
    signer.id = format!("{}#key-0", result.did_id);
    let resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    .map_err(|e| AppError::Internal(format!("DID resolver: {e}")))?;
    let client = did_hosting_common::WitnessClient::new(
        witness_url,
        witness_did,
        &result.did_id,
        signer,
        resolver,
    );
    let signed = client
        .sign(witness_id, &version_id, &result.jsonl)
        .await
        .map_err(|e| AppError::Internal(format!("witness/sign: {e}")))?;
    let witness_file = serde_json::json!([{
        "versionId": signed.version_id.as_str(),
        "proof": [signed.proof],
    }]);
    Ok(witness_file.to_string())
}

/// Check whether the `.well-known` root DID already exists.
pub async fn root_did_exists(dids_ks: &KeyspaceHandle) -> Result<bool, AppError> {
    dids_ks.contains_key(did_key(".well-known")).await
}

/// Create the `.well-known` root DID log entry and store it atomically.
///
/// Convenience wrapper around [`bootstrap_did`] for the root DID path.
pub async fn bootstrap_root_did(
    store: &Store,
    dids_ks: &KeyspaceHandle,
    signing_secret: &Secret,
    ka_secret: Option<&Secret>,
    mediator_did: Option<&str>,
    public_url: &str,
) -> Result<BootstrapResult, AppError> {
    bootstrap_did(
        store,
        dids_ks,
        signing_secret,
        ka_secret,
        mediator_did,
        // Convenience wrapper: advertise both transports at the mediator
        // (callers that need a specific transport call `bootstrap_did`).
        true,
        true,
        public_url,
        ".well-known",
        true,
    )
    .await
}

/// Create a DID log entry at the given path and store it atomically.
///
/// The signing secret's public key is embedded in the DID document. If
/// `ka_secret` is provided, an X25519 key agreement key is also added.
/// If `mediator_did` is provided, a `DIDCommMessaging` service is added
/// when `advertise_didcomm` is set and a `TSPTransport` service when
/// `advertise_tsp` is set — both point at the same mediator (they share
/// its socket). Gating these on the node's transport selection lets a
/// self-managed node advertise DIDComm-only, TSP-only, or both.
/// The resulting log entry is stored alongside a `DidRecord` with owner `"system"`.
#[allow(clippy::too_many_arguments)]
pub async fn bootstrap_did(
    store: &Store,
    dids_ks: &KeyspaceHandle,
    signing_secret: &Secret,
    ka_secret: Option<&Secret>,
    mediator_did: Option<&str>,
    advertise_didcomm: bool,
    advertise_tsp: bool,
    public_url: &str,
    mnemonic: &str,
    scid_also_known_as: bool,
) -> Result<BootstrapResult, AppError> {
    // Guard: must not already exist
    if dids_ks.contains_key(did_key(mnemonic)).await? {
        return Err(AppError::Conflict(format!(
            "DID at path '{mnemonic}' already exists"
        )));
    }

    let host = encode_host(public_url)
        .map_err(|e| AppError::Config(format!("failed to encode host from public_url: {e}")))?;

    let public_key = signing_secret
        .get_public_keymultibase()
        .map_err(|e| AppError::Internal(format!("failed to get public key multibase: {e}")))?;

    let ka_public_key = ka_secret
        .map(|s| s.get_public_keymultibase())
        .transpose()
        .map_err(|e| AppError::Internal(format!("failed to get KA public key multibase: {e}")))?;

    let doc = build_did_document(
        &host,
        mnemonic,
        &public_key,
        &DidDocumentOptions {
            key_agreement_multibase: ka_public_key.as_deref(),
            // Advertise each transport's service entry only when selected;
            // both point at the same mediator (shared socket).
            mediator_endpoint: if advertise_didcomm {
                mediator_did
            } else {
                None
            },
            tsp_endpoint: if advertise_tsp { mediator_did } else { None },
            omit_scid_alias: !scid_also_known_as,
        },
    );

    let (scid, jsonl) = create_log_entry(&doc, signing_secret)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create log entry: {e}")))?;

    let did_id = extract_did_id(&jsonl)
        .ok_or_else(|| AppError::Internal("failed to extract DID id from log entry".into()))?;

    // Held to the same history as a synced log, though it was just minted: a
    // slot keeps its method, and the high-water marks record it.
    let identity = verify_history(dids_ks, mnemonic, &did_id, &jsonl, "webvh").await?;

    let mnemonic = mnemonic.to_string();
    let now = now_epoch();

    let record = DidRecord {
        owner: "system".to_string(),
        mnemonic: mnemonic.clone(),
        created_at: now,
        updated_at: now,
        version_count: 1,
        did_id: Some(did_id.clone()),
        content_size: jsonl.len() as u64,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,

        method: "webvh".to_string(),
        // The host the identifier names, as a synced record is tagged, so a
        // purge of that domain selects it.
        domain: extract_did_host(&did_id).unwrap_or_default(),

        // The server's own DID — its badges (WebVHHosting, and TSP and/or
        // DIDComm per `advertise_tsp` / `mediator_did` above) are exactly
        // what `build_did_document` just wrote into the doc.
        services: extract_service_types(&jsonl),
        agent_names: Vec::new(),
    };

    let mut batch = store.batch();
    batch.insert(dids_ks, did_key(&mnemonic), &record)?;
    batch.insert_raw(
        dids_ks,
        content_log_key(&mnemonic),
        jsonl.as_bytes().to_vec(),
    );
    batch.insert_raw(
        dids_ks,
        owner_key("system", &mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    stage_high_water(
        &mut batch, dids_ks, &identity, &mnemonic, &did_id, "webvh", &jsonl,
    )?;
    batch.commit().await?;

    info!(did = %did_id, scid = %scid, path = %mnemonic, "DID bootstrapped");

    Ok(BootstrapResult {
        scid,
        did_id,
        jsonl,
        mnemonic,
    })
}

/// Import an existing `.well-known` root DID from provided JSONL content.
///
/// Validates the JSONL, extracts the DID id and SCID, and stores everything
/// atomically. Optionally stores witness content alongside the log.
pub async fn import_root_did(
    store: &Store,
    dids_ks: &KeyspaceHandle,
    jsonl: &str,
    witness_content: Option<&str>,
) -> Result<BootstrapResult, AppError> {
    // Guard: must not already exist
    if root_did_exists(dids_ks).await? {
        return Err(AppError::Conflict(
            "root DID (.well-known) already exists".into(),
        ));
    }

    import_did_at_path(store, dids_ks, ".well-known", jsonl, witness_content).await
}

/// What setup found when it went to import the service's **own** DID — the
/// daemon's or the server's; both setups go through here.
#[derive(Debug)]
pub enum OwnDidImport {
    /// The path was free; the DID is now stored.
    Imported(BootstrapResult),
    /// The path already holds **this same DID** — a re-run of setup. Nothing
    /// to write; the caller still points its config at it.
    AlreadyPresent { did_id: String },
    /// The path holds a **different** DID. Nothing was written.
    ///
    /// The ordinary cause is moving a service to a new `public_url` with
    /// `--force-reprovision`: setup mints a new DID for the new host, while the
    /// store still holds the previous one at the same path, bound to a hostname
    /// that may no longer exist.
    HeldByAnother {
        existing: Option<String>,
        minted: String,
    },
}

/// Import the service's own DID during setup, telling a re-run apart from a
/// stale identity rather than reporting both as one conflict.
///
/// Keyring VTI-17, reported on the daemon; the server's three setup paths had
/// the identical defect. Setup used to call [`import_did_at_path`], whose guard is
/// "anything at this path", and on any error printed a warning and carried
/// on. So a daemon moved to a new host kept serving its **old** DID — the new
/// host answered 404 for `/.well-known/did.jsonl` — while setup reported
/// success and the daemon reported healthy. The warning also advised retrying
/// with `bootstrap-did`, which hits the identical guard.
///
/// [`import_did_at_path`] is left unchanged: `bootstrap-did` is an explicit
/// request, and a conflict there should stay an error.
pub async fn import_own_did(
    store: &Store,
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    jsonl: &str,
) -> Result<OwnDidImport, AppError> {
    let minted = extract_did_id(jsonl)
        .ok_or_else(|| AppError::Validation("could not extract DID id from did.jsonl".into()))?;

    if let Some(existing) = dids_ks.get::<DidRecord>(did_key(mnemonic)).await? {
        return Ok(if existing.did_id.as_deref() == Some(minted.as_str()) {
            OwnDidImport::AlreadyPresent { did_id: minted }
        } else {
            OwnDidImport::HeldByAnother {
                existing: existing.did_id,
                minted,
            }
        });
    }

    import_did_at_path(store, dids_ks, mnemonic, jsonl, None)
        .await
        .map(OwnDidImport::Imported)
}

/// Replace the service's own DID at `mnemonic`: hard-delete whatever is
/// stored there and import the freshly minted `jsonl` in its place.
///
/// Only meant to be called after [`import_own_did`] reports
/// [`OwnDidImport::HeldByAnother`], **and** the caller has independently
/// confirmed the operator opted into rotation (`--force-reprovision`).
/// Without that confirmation, [`stale_own_did_message`] is the right
/// response — refuse loudly rather than guess.
///
/// Keyring VTI-17: reprovisioning onto a new `public_url` mints a DID for the
/// new host while the store still holds the previous one at the same path —
/// bound to a hostname that may no longer serve it. These are test
/// deployments (no migration path), so the stale DID is simply removed
/// rather than left to 404 while the daemon reports healthy.
pub async fn replace_own_did(
    store: &Store,
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    jsonl: &str,
) -> Result<BootstrapResult, AppError> {
    // Verify the new DID before touching the old one: a log that would be
    // refused must leave the stored DID where it is.
    let checked = check_import(dids_ks, mnemonic, jsonl, None).await?;
    let mut batch = store.batch();
    if let Some(existing) = dids_ks.get::<DidRecord>(did_key(mnemonic)).await? {
        // The record and log are overwritten below; what the new DID does not
        // replace is removed here.
        batch.remove(dids_ks, content_witness_key(mnemonic));
        if existing.owner != "system" {
            batch.remove(dids_ks, owner_key(&existing.owner, mnemonic));
        }
    }
    stage_import(&mut batch, dids_ks, mnemonic, jsonl, None, &checked)?;
    batch.commit().await?;
    info!(did = %checked.did_id, path = %mnemonic, "own DID replaced");
    Ok(checked.into_result(mnemonic, jsonl))
}

/// The operator-facing refusal for [`OwnDidImport::HeldByAnother`], shared
/// by the interactive wizard and the recipe so both say the same thing.
///
/// It names the targeted fix. Deleting the whole store (`data/`) also clears
/// it, and is what a workaround would reach for, but it removes **every** DID
/// the service hosts — every tenant's, not just its own.
pub fn stale_own_did_message(path: &str, existing: Option<&str>, minted: &str) -> String {
    format!(
        "the store already holds a different DID at '{path}' ({existing}), not the one this \
         setup minted ({minted}). This usually means `public_url` changed: the old DID is \
         still bound to the previous hostname, and serving it from the new one returns 404.\n\
         Remove just that DID and re-run setup:\n  \
         did-hosting-server remove-did --path {path}\n\
         (Deleting the data directory also clears it, but removes every DID this daemon \
         hosts, not only its own.)",
        existing = existing.unwrap_or("an unidentified DID"),
    )
}

/// Import an existing DID at an arbitrary path (mnemonic).
///
/// Generalisation of `import_root_did` — works for any mnemonic, not just
/// `.well-known`. Guards against overwriting an existing entry at the same
/// path. The DID is stored with owner `"system"`.
///
/// The log is held to what a synced one is: its chain and witness proofs
/// must verify, and it must strictly extend every history this store has
/// served for the same DID and slot ([`verify_history`]), including one
/// since removed, so a remove followed by a load cannot put an older log
/// back. The high-water marks then record it ([`stage_high_water`]).
pub async fn import_did_at_path(
    store: &Store,
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    jsonl: &str,
    witness_content: Option<&str>,
) -> Result<BootstrapResult, AppError> {
    // Guard: must not already exist at this path
    if dids_ks.contains_key(did_key(mnemonic)).await? {
        return Err(AppError::Conflict(format!(
            "DID at path '{mnemonic}' already exists"
        )));
    }

    let checked = check_import(dids_ks, mnemonic, jsonl, witness_content).await?;
    let mut batch = store.batch();
    stage_import(
        &mut batch,
        dids_ks,
        mnemonic,
        jsonl,
        witness_content,
        &checked,
    )?;
    batch.commit().await?;

    info!(did = %checked.did_id, scid = %checked.scid, path = %mnemonic, "DID imported from files");
    Ok(checked.into_result(mnemonic, jsonl))
}

/// A `did:webvh` log [`check_import`] accepted for a slot.
struct CheckedImport {
    did_id: String,
    scid: String,
    /// The DID's identity, for [`stage_high_water`].
    identity: String,
}

impl CheckedImport {
    fn into_result(self, mnemonic: &str, jsonl: &str) -> BootstrapResult {
        BootstrapResult {
            scid: self.scid,
            did_id: self.did_id,
            jsonl: jsonl.to_string(),
            mnemonic: mnemonic.to_string(),
        }
    }
}

/// Everything [`import_did_at_path`] checks before it writes, bar the
/// "nothing at this path" guard: the log's structure, chain and witness
/// proofs, and that it extends every history this store has served for the
/// DID and slot ([`verify_history`]). Writes nothing.
async fn check_import(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    jsonl: &str,
    witness_content: Option<&str>,
) -> Result<CheckedImport, AppError> {
    validate_did_jsonl(jsonl)?;

    let did_id = extract_did_id(jsonl)
        .ok_or_else(|| AppError::Validation("could not extract DID id from did.jsonl".into()))?;

    // Extract SCID from the DID id (did:webvh:<scid>:host:...)
    let scid = did_id
        .strip_prefix("did:webvh:")
        .and_then(|rest| rest.split(':').next())
        .ok_or_else(|| AppError::Validation("could not extract SCID from DID id".into()))?
        .to_string();

    // Validate witness content is valid JSON if provided
    if let Some(witness) = witness_content {
        serde_json::from_str::<serde_json::Value>(witness).map_err(|e| {
            AppError::Validation(format!("did-witness.json must be valid JSON: {e}"))
        })?;
    }

    // The chain (entry hashes, proofs, key rotation) and, for a witnessed
    // DID, the witness proofs.
    verify_did_log_and_witness_proofs(jsonl, witness_content).map_err(AppError::Validation)?;
    let identity = verify_history(dids_ks, mnemonic, &did_id, jsonl, "webvh").await?;
    Ok(CheckedImport {
        did_id,
        scid,
        identity,
    })
}

/// Stage, in `batch`, the writes of a [`check_import`]ed log: the record
/// (owner `"system"`), the log, the owner index, any witness proofs, and the
/// high-water marks.
fn stage_import(
    batch: &mut crate::store::WriteBatch,
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    jsonl: &str,
    witness_content: Option<&str>,
    checked: &CheckedImport,
) -> Result<(), AppError> {
    let now = now_epoch();
    let version_count = jsonl.lines().filter(|l| !l.trim().is_empty()).count() as u64;
    let record = DidRecord {
        owner: "system".to_string(),
        mnemonic: mnemonic.to_string(),
        created_at: now,
        updated_at: now,
        version_count,
        did_id: Some(checked.did_id.clone()),
        content_size: jsonl.len() as u64,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,

        method: "webvh".to_string(),
        // The host the identifier names, as a synced record is tagged, so a
        // purge of that domain selects it.
        domain: extract_did_host(&checked.did_id).unwrap_or_default(),

        services: extract_service_types(jsonl),

        agent_names: Vec::new(),
    };

    batch.insert(dids_ks, did_key(mnemonic), &record)?;
    batch.insert_raw(
        dids_ks,
        content_log_key(mnemonic),
        jsonl.as_bytes().to_vec(),
    );
    batch.insert_raw(
        dids_ks,
        owner_key("system", mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    if let Some(witness) = witness_content {
        batch.insert_raw(
            dids_ks,
            content_witness_key(mnemonic),
            witness.as_bytes().to_vec(),
        );
    }
    stage_high_water(
        batch,
        dids_ks,
        &checked.identity,
        mnemonic,
        &checked.did_id,
        "webvh",
        jsonl,
    )
}

#[cfg(test)]
mod own_did_import_tests {
    use super::*;
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::store::KS_DIDS;

    async fn store() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open store");
        let ks = store.keyspace(KS_DIDS).expect("dids keyspace");
        (dir, store, ks)
    }

    /// A fresh DID for `public_url` — a new key each call, so two calls stand
    /// for the same service minting again after moving host.
    async fn minted_for(public_url: &str) -> String {
        use did_hosting_common::did::{build_did_document, create_log_entry, encode_host};
        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let pk = secret.get_public_keymultibase().unwrap();
        let host = encode_host(public_url).unwrap();
        let doc = build_did_document(&host, ".well-known", &pk, &Default::default());
        create_log_entry(&doc, &secret).await.unwrap().1
    }

    #[tokio::test]
    async fn a_free_path_imports() {
        let (_dir, store, ks) = store().await;
        let jsonl = minted_for("http://localhost:3000").await;
        assert!(matches!(
            import_own_did(&store, &ks, ".well-known", &jsonl)
                .await
                .unwrap(),
            OwnDidImport::Imported(_)
        ));
    }

    /// Re-running setup is not a conflict. Under `import_did_at_path` it was,
    /// and the only advice was to retry with a command that hit the same guard.
    #[tokio::test]
    async fn the_same_did_again_is_a_re_run_not_a_conflict() {
        let (_dir, store, ks) = store().await;
        let jsonl = minted_for("http://localhost:3000").await;
        import_own_did(&store, &ks, ".well-known", &jsonl)
            .await
            .unwrap();

        match import_own_did(&store, &ks, ".well-known", &jsonl)
            .await
            .unwrap()
        {
            OwnDidImport::AlreadyPresent { did_id } => {
                assert_eq!(Some(did_id), extract_did_id(&jsonl));
            }
            other => panic!("expected AlreadyPresent, got {other:?}"),
        }
    }

    /// Keyring VTI-17: moved to a new host, setup mints a new DID while the old
    /// one still occupies the path. That must be reported — and nothing
    /// overwritten, since the old DID may be one clients still resolve.
    #[tokio::test]
    async fn a_different_did_at_the_path_is_refused_and_left_untouched() {
        let (_dir, store, ks) = store().await;
        let old = minted_for("http://old-host.example").await;
        let new = minted_for("http://new-host.example").await;
        import_own_did(&store, &ks, ".well-known", &old)
            .await
            .unwrap();

        match import_own_did(&store, &ks, ".well-known", &new)
            .await
            .unwrap()
        {
            OwnDidImport::HeldByAnother { existing, minted } => {
                assert_eq!(existing, extract_did_id(&old));
                assert_eq!(Some(minted), extract_did_id(&new));
            }
            other => panic!("expected HeldByAnother, got {other:?}"),
        }

        let kept = ks
            .get::<DidRecord>(did_key(".well-known"))
            .await
            .unwrap()
            .expect("record still there");
        assert_eq!(
            kept.did_id,
            extract_did_id(&old),
            "the old DID was not overwritten"
        );
    }

    /// Keyring VTI-17: `--force-reprovision` onto a new host replaces the
    /// stale DID rather than leaving it in the store to 404 forever.
    #[tokio::test]
    async fn replace_own_did_swaps_the_stale_did_for_the_new_one() {
        let (_dir, store, ks) = store().await;
        let old = minted_for("http://old-host.example").await;
        let new = minted_for("http://new-host.example").await;
        import_own_did(&store, &ks, ".well-known", &old)
            .await
            .unwrap();

        let result = replace_own_did(&store, &ks, ".well-known", &new)
            .await
            .expect("replace succeeds");
        assert_eq!(Some(result.did_id.clone()), extract_did_id(&new));

        let kept = ks
            .get::<DidRecord>(did_key(".well-known"))
            .await
            .unwrap()
            .expect("record still there");
        assert_eq!(
            kept.did_id,
            extract_did_id(&new),
            "the new DID replaced the stale one"
        );

        // The re-run case (`AlreadyPresent`) now sees the new DID.
        match import_own_did(&store, &ks, ".well-known", &new)
            .await
            .unwrap()
        {
            OwnDidImport::AlreadyPresent { did_id } => {
                assert_eq!(Some(did_id), extract_did_id(&new));
            }
            other => panic!("expected AlreadyPresent, got {other:?}"),
        }
    }

    /// A new DID that would be refused leaves the stored one in place.
    #[tokio::test]
    async fn replace_own_did_keeps_the_old_did_when_the_new_one_is_refused() {
        let (_dir, store, ks) = store().await;
        let old = minted_for("http://old-host.example").await;
        import_own_did(&store, &ks, ".well-known", &old)
            .await
            .unwrap();
        let mut entry: serde_json::Value =
            serde_json::from_str(minted_for("http://new-host.example").await.trim()).unwrap();
        entry["state"]["alsoKnownAs"] = serde_json::json!(["did:example:edited"]);

        assert!(
            replace_own_did(&store, &ks, ".well-known", &entry.to_string())
                .await
                .is_err()
        );
        let kept: DidRecord = ks.get(did_key(".well-known")).await.unwrap().unwrap();
        assert_eq!(kept.did_id, extract_did_id(&old), "the old DID is kept");
        assert!(
            ks.get_raw(content_log_key(".well-known"))
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A free path is also a valid target — reprovisioning after an
    /// uninstall (or a first-ever setup that happens to route through the
    /// replace path) must not require something to already be there.
    #[tokio::test]
    async fn replace_own_did_on_a_free_path_just_imports() {
        let (_dir, store, ks) = store().await;
        let jsonl = minted_for("http://host.example").await;
        let result = replace_own_did(&store, &ks, ".well-known", &jsonl)
            .await
            .expect("replace on a free path succeeds");
        assert_eq!(Some(result.did_id), extract_did_id(&jsonl));
    }

    /// The refusal names the targeted fix, and says why the blunt one is worse:
    /// deleting the data directory takes every tenant's DID with it.
    #[test]
    fn the_refusal_names_the_targeted_fix() {
        let msg = stale_own_did_message(".well-known", Some("did:webvh:old"), "did:webvh:new");
        assert!(msg.contains("remove-did --path .well-known"), "{msg}");
        assert!(
            msg.contains("did:webvh:old") && msg.contains("did:webvh:new"),
            "{msg}"
        );
        assert!(msg.contains("every DID"), "{msg}");
        assert!(
            !msg.contains("bootstrap-did"),
            "the old advice hit the same guard: {msg}"
        );
    }
}

/// Signed `did:webvh` logs of several versions, for the history tests.
#[cfg(test)]
pub(crate) mod test_logs {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use did_hosting_common::did::{DidDocumentOptions, build_did_document};
    use std::sync::Arc;

    fn at(hours_ago: i64) -> chrono::DateTime<chrono::FixedOffset> {
        (chrono::Utc::now() - chrono::Duration::hours(hours_ago)).fixed_offset()
    }

    /// `versions` successive logs of one DID at `mnemonic` on `host`: the
    /// first holds one entry, each next one more.
    pub(crate) async fn versions(host: &str, mnemonic: &str, versions: usize) -> Vec<String> {
        let secret = Secret::generate_ed25519(None, None);
        let pk = secret.get_public_keymultibase().unwrap();
        let mut signing = secret.clone();
        signing.id = format!("did:key:{pk}#{pk}");
        let params = didwebvh_rs::parameters::Parameters {
            update_keys: Some(Arc::new(vec![pk.clone().into()])),
            ..Default::default()
        };
        let mut doc = build_did_document(host, mnemonic, &pk, &DidDocumentOptions::default());
        let mut state = didwebvh_rs::DIDWebVHState::default();
        let mut logs = Vec::new();
        for i in 0..versions {
            state
                .create_log_entry(Some(at(10 - i as i64)), &doc, &params, &signing)
                .await
                .expect("webvh log entry");
            let log = state
                .log_entries()
                .iter()
                .map(|e| serde_json::to_string(&e.log_entry).unwrap())
                .collect::<Vec<_>>()
                .join("\n");
            // Each later version restates the resolved document.
            doc = serde_json::from_str::<serde_json::Value>(log.lines().last().unwrap())
                .unwrap()["state"]
                .clone();
            logs.push(log);
        }
        logs
    }
}

#[cfg(test)]
mod local_history_tests {
    use super::*;
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::store::KS_DIDS;

    async fn store() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .expect("open store");
        let ks = store.keyspace(KS_DIDS).expect("dids keyspace");
        (dir, store, ks)
    }

    /// What `remove-did` removes: the record, its log, witness proofs and
    /// owner index. The high-water marks stay.
    async fn remove(store: &Store, ks: &KeyspaceHandle, mnemonic: &str) {
        let mut batch = store.batch();
        batch.remove(ks, did_key(mnemonic));
        batch.remove(ks, content_log_key(mnemonic));
        batch.remove(ks, content_witness_key(mnemonic));
        batch.remove(ks, owner_key("system", mnemonic));
        batch.commit().await.unwrap();
    }

    /// A removed DID cannot be loaded back at an older version: the store
    /// remembers the furthest log it served for that DID. The same or a
    /// later version loads.
    #[tokio::test]
    async fn a_removed_did_loads_back_only_at_its_latest_version_or_later() {
        let (_dir, store, ks) = store().await;
        let logs = test_logs::versions("example.com", "alice", 3).await;
        import_did_at_path(&store, &ks, "alice", &logs[1], None)
            .await
            .expect("v2 loads");

        remove(&store, &ks, "alice").await;
        let err = import_did_at_path(&store, &ks, "alice", &logs[0], None)
            .await
            .expect_err("an older version is refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(
            ks.get::<DidRecord>(did_key("alice"))
                .await
                .unwrap()
                .is_none(),
            "nothing was stored"
        );

        import_did_at_path(&store, &ks, "alice", &logs[1], None)
            .await
            .expect("the same version loads again");
        remove(&store, &ks, "alice").await;
        import_did_at_path(&store, &ks, "alice", &logs[2], None)
            .await
            .expect("a later version loads");

        // Moving the DID to another slot does not escape its history either.
        let err = import_did_at_path(&store, &ks, "elsewhere", &logs[0], None)
            .await
            .expect_err("an older version under another slot is refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    /// A log whose chain does not verify is refused, not only one that does
    /// not parse.
    #[tokio::test]
    async fn a_log_that_does_not_verify_is_not_loaded() {
        let (_dir, store, ks) = store().await;
        let logs = test_logs::versions("example.com", "bob", 2).await;
        let mut lines: Vec<serde_json::Value> = logs[1]
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        lines[1]["state"]["alsoKnownAs"] = serde_json::json!(["did:example:edited"]);
        let edited = lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let err = import_did_at_path(&store, &ks, "bob", &edited, None)
            .await
            .expect_err("an edited log is refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(ks.get::<DidRecord>(did_key("bob")).await.unwrap().is_none());
    }

    /// A loaded DID is tagged with the host its identifier names, as a synced
    /// one is, so a purge of that domain selects it.
    #[tokio::test]
    async fn a_loaded_did_is_tagged_with_its_domain() {
        let (_dir, store, ks) = store().await;
        let logs = test_logs::versions("example.com", "carol", 1).await;
        import_did_at_path(&store, &ks, "carol", &logs[0], None)
            .await
            .unwrap();
        let record: DidRecord = ks.get(did_key("carol")).await.unwrap().unwrap();
        assert_eq!(record.domain, "example.com");
    }

    /// `recreate-did` and setup's reprovision put a new DID in a slot: a new
    /// DID is a new history, so that is allowed, and the slot's mark moves.
    #[tokio::test]
    async fn a_slot_takes_a_new_did_after_its_old_one_is_removed() {
        let (_dir, store, ks) = store().await;
        let old = test_logs::versions("example.com", "dave", 2).await;
        let new = test_logs::versions("example.com", "dave", 1).await;
        import_did_at_path(&store, &ks, "dave", &old[1], None)
            .await
            .unwrap();
        remove(&store, &ks, "dave").await;
        import_did_at_path(&store, &ks, "dave", &new[0], None)
            .await
            .expect("a new DID in the slot");
        // The removed DID's history is still remembered.
        remove(&store, &ks, "dave").await;
        assert!(
            import_did_at_path(&store, &ks, "dave", &old[0], None)
                .await
                .is_err()
        );
    }
}

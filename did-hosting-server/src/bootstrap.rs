//! Server DID bootstrap — creates DID log entries for hosted DIDs.
//!
//! Shared logic used by both the `bootstrap-did` CLI subcommand and the
//! auto-bootstrap path on server startup.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use did_hosting_common::did::{
    DidDocumentOptions, build_did_document, create_log_entry, encode_host,
};
use tracing::info;

use crate::auth::session::now_epoch;
use crate::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, extract_did_id,
    extract_service_types, owner_key, validate_did_jsonl,
};
use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

/// Result of bootstrapping the root DID.
#[derive(Debug)]
pub struct BootstrapResult {
    pub scid: String,
    pub did_id: String,
    pub jsonl: String,
    pub mnemonic: String,
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
        },
    );

    let (scid, jsonl) = create_log_entry(&doc, signing_secret)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create log entry: {e}")))?;

    let did_id = extract_did_id(&jsonl)
        .ok_or_else(|| AppError::Internal("failed to extract DID id from log entry".into()))?;

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
        deleted_at: None,

        // T12: legacy construction site; T13 migration fills `domain`.
        method: "webvh".to_string(),
        domain: String::new(),

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

    // Validate the JSONL content
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

    let mnemonic_str = mnemonic.to_string();
    let now = now_epoch();
    let version_count = jsonl.lines().filter(|l| !l.trim().is_empty()).count() as u64;

    let record = DidRecord {
        owner: "system".to_string(),
        mnemonic: mnemonic_str.clone(),
        created_at: now,
        updated_at: now,
        version_count,
        did_id: Some(did_id.clone()),
        content_size: jsonl.len() as u64,
        disabled: false,
        deleted_at: None,

        // T12: legacy construction site; T13 migration fills `domain`.
        method: "webvh".to_string(),
        domain: String::new(),

        services: extract_service_types(jsonl),

        agent_names: Vec::new(),
    };

    let mut batch = store.batch();
    batch.insert(dids_ks, did_key(&mnemonic_str), &record)?;
    batch.insert_raw(
        dids_ks,
        content_log_key(&mnemonic_str),
        jsonl.as_bytes().to_vec(),
    );
    batch.insert_raw(
        dids_ks,
        owner_key("system", &mnemonic_str),
        mnemonic_str.as_bytes().to_vec(),
    );
    if let Some(witness) = witness_content {
        batch.insert_raw(
            dids_ks,
            content_witness_key(&mnemonic_str),
            witness.as_bytes().to_vec(),
        );
    }
    batch.commit().await?;

    info!(did = %did_id, scid = %scid, path = %mnemonic_str, "DID imported from files");

    Ok(BootstrapResult {
        scid,
        did_id,
        jsonl: jsonl.to_string(),
        mnemonic: mnemonic_str,
    })
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

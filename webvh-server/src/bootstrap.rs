//! Server DID bootstrap — creates DID log entries for hosted DIDs.
//!
//! Shared logic used by both the `bootstrap-did` CLI subcommand and the
//! auto-bootstrap path on server startup.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_webvh_common::did::{DidDocumentOptions, build_did_document, create_log_entry, encode_host};
use tracing::info;

use crate::auth::session::now_epoch;
use crate::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, extract_did_id, owner_key,
    validate_did_jsonl,
};
use crate::error::AppError;
use crate::store::{KeyspaceHandle, Store};

/// Result of bootstrapping the root DID.
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
    bootstrap_did(store, dids_ks, signing_secret, ka_secret, mediator_did, public_url, ".well-known").await
}

/// Create a DID log entry at the given path and store it atomically.
///
/// The signing secret's public key is embedded in the DID document. If
/// `ka_secret` is provided, an X25519 key agreement key is also added.
/// If `mediator_did` is provided, a `DIDCommMessaging` service is added.
/// The resulting log entry is stored alongside a `DidRecord` with owner `"system"`.
pub async fn bootstrap_did(
    store: &Store,
    dids_ks: &KeyspaceHandle,
    signing_secret: &Secret,
    ka_secret: Option<&Secret>,
    mediator_did: Option<&str>,
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

    let doc = build_did_document(&host, mnemonic, &public_key, &DidDocumentOptions {
        key_agreement_multibase: ka_public_key.as_deref(),
        mediator_endpoint: mediator_did,
    });

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
        return Err(AppError::Conflict(
            format!("DID at path '{mnemonic}' already exists"),
        ));
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

//! DID management business logic for the control plane.
//!
//! The control plane is the source of truth for all DIDs. Functions here
//! operate on the control plane's `dids` keyspace and use the shared types
//! from `webvh-common::did_ops`.

use affinidi_webvh_common::did_ops::{
    self, DidRecord, LogEntryInfo, LogMetadata, content_log_key, content_witness_key, did_key,
    owner_key,
};
use affinidi_webvh_common::server::mnemonic::{validate_custom_path, validate_mnemonic};
use affinidi_webvh_common::{CheckNameResponse, DidListEntry, RequestUriResponse};
use bip39::Language;
use rand::random_range;
use tracing::{debug, info, warn};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;
use crate::store::KeyspaceHandle;

// Re-export for convenience
pub use affinidi_webvh_common::did_ops::{extract_did_id, extract_log_metadata};

// ---------------------------------------------------------------------------
// JSONL validation (wraps the common version with AppError)
// ---------------------------------------------------------------------------

fn validate_did_jsonl(content: &str) -> Result<(), AppError> {
    did_ops::validate_did_jsonl(content).map_err(AppError::Validation)
}

// ---------------------------------------------------------------------------
// Mnemonic generation (same logic as webvh-server/src/mnemonic.rs)
// ---------------------------------------------------------------------------

fn random_mnemonic() -> String {
    let wordlist = Language::English.word_list();
    let w1 = wordlist[random_range(0..wordlist.len())];
    let w2 = wordlist[random_range(0..wordlist.len())];
    format!("{w1}-{w2}")
}

async fn generate_unique_mnemonic(dids_ks: &KeyspaceHandle) -> Result<String, AppError> {
    for _ in 0..100 {
        let mnemonic = random_mnemonic();
        let key = format!("did:{mnemonic}");
        if !dids_ks.contains_key(key).await? {
            return Ok(mnemonic);
        }
    }
    Err(AppError::Internal(
        "failed to generate unique mnemonic after 100 attempts".into(),
    ))
}

async fn is_path_available(dids_ks: &KeyspaceHandle, path: &str) -> Result<bool, AppError> {
    Ok(!dids_ks.contains_key(format!("did:{path}")).await?)
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Load a DID record and verify the caller is the owner (or admin).
async fn get_authorized_record(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    auth: &AuthClaims,
) -> Result<DidRecord, AppError> {
    use crate::acl::Role;

    let record: DidRecord = dids_ks
        .get(did_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;
    if record.owner != auth.did && auth.role != Role::Admin {
        warn!(
            caller = %auth.did,
            owner = %record.owner,
            mnemonic = %mnemonic,
            "access denied: not the owner of this DID"
        );
        return Err(AppError::Forbidden("not the owner of this DID".into()));
    }
    Ok(record)
}

/// Resolve a custom path during create, applying force-replace semantics.
///
/// If the path is free, returns it unchanged. If taken and `force` is false,
/// returns `Conflict(conflict_msg)`. If taken and `force` is true, the caller
/// must be an admin or the current owner of that path; the existing log
/// content, witness, and owner-index are removed so the slot can be
/// reused. Stats are left intact (separate keyspace).
async fn resolve_path_for_create(
    state: &AppState,
    custom_path: &str,
    auth: &AuthClaims,
    force: bool,
    conflict_msg: &str,
) -> Result<String, AppError> {
    use crate::acl::Role;

    if is_path_available(&state.dids_ks, custom_path).await? {
        return Ok(custom_path.to_string());
    }

    if !force {
        return Err(AppError::Conflict(conflict_msg.to_string()));
    }

    let existing: DidRecord = state
        .dids_ks
        .get(did_key(custom_path))
        .await?
        .ok_or_else(|| AppError::Internal("path conflict but record missing".into()))?;

    if existing.owner != auth.did && auth.role != Role::Admin {
        warn!(
            caller = %auth.did,
            owner = %existing.owner,
            mnemonic = %custom_path,
            "force replace denied: not the owner or admin"
        );
        return Err(AppError::Forbidden(
            "force replace requires admin or current owner".into(),
        ));
    }

    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, content_log_key(custom_path));
    batch.remove(&state.dids_ks, content_witness_key(custom_path));
    if existing.owner != auth.did {
        batch.remove(&state.dids_ks, owner_key(&existing.owner, custom_path));
    }
    batch.commit().await?;

    info!(
        caller = %auth.did,
        prev_owner = %existing.owner,
        mnemonic = %custom_path,
        "force-replacing existing DID"
    );

    Ok(custom_path.to_string())
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Create a new DID slot (reserve a mnemonic/path).
///
/// When `force` is true and the requested path already exists, the caller
/// (admin or current owner of that path) replaces the existing slot — the
/// old DID's log content, witness, and owner-index are removed and the
/// caller becomes the new owner. Without `force`, a path collision returns
/// `Conflict` as before.
pub async fn create_did(
    auth: &AuthClaims,
    state: &AppState,
    path: Option<&str>,
    force: bool,
) -> Result<RequestUriResponse, AppError> {
    use crate::acl::Role;
    use crate::auth::session::now_epoch;

    let mnemonic = match path {
        Some(custom_path) if custom_path == ".well-known" => {
            if auth.role != Role::Admin {
                return Err(AppError::Forbidden(
                    "only admins can create the root DID".into(),
                ));
            }
            resolve_path_for_create(
                state,
                custom_path,
                auth,
                force,
                "root DID (.well-known) already exists",
            )
            .await?
        }
        Some(custom_path) => {
            validate_custom_path(custom_path)?;
            let conflict_msg = format!("path '{custom_path}' is already taken");
            resolve_path_for_create(state, custom_path, auth, force, &conflict_msg).await?
        }
        None => generate_unique_mnemonic(&state.dids_ks).await?,
    };

    let now = now_epoch();
    let record = DidRecord {
        owner: auth.did.clone(),
        mnemonic: mnemonic.clone(),
        created_at: now,
        updated_at: now,
        version_count: 0,
        did_id: None,
        content_size: 0,
        disabled: false,
        deleted_at: None,
    };

    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(&mnemonic), &record)?;
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&auth.did, &mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.commit().await?;

    // Build the DID URL using the did_hosting_url if configured, else public_url
    let base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .unwrap_or("http://localhost");
    let did_url = format!("{base_url}/{mnemonic}/did.jsonl");

    info!(did = %auth.did, mnemonic = %mnemonic, "DID URI created on control plane");

    Ok(RequestUriResponse { mnemonic, did_url })
}

/// Publish (upload) a did.jsonl log for an existing DID slot.
pub async fn publish_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    did_log: &str,
) -> Result<(), AppError> {
    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    validate_did_jsonl(did_log)?;

    let new_size = did_log.len() as u64;
    let did_id_val = extract_did_id(did_log);

    record.updated_at = now_epoch();
    record.version_count += 1;
    record.did_id = did_id_val;
    record.content_size = new_size;

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        did_log.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.commit().await?;

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        size = new_size,
        version = record.version_count,
        "did.jsonl published on control plane"
    );

    Ok(())
}

/// Upload witness content for a DID.
pub async fn upload_witness(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    witness_content: &str,
) -> Result<(), AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    if witness_content.is_empty() {
        return Err(AppError::Validation(
            "did-witness.json content cannot be empty".into(),
        ));
    }

    serde_json::from_str::<serde_json::Value>(witness_content)
        .map_err(|e| AppError::Validation(format!("did-witness.json must be valid JSON: {e}")))?;

    state
        .dids_ks
        .insert_raw(
            content_witness_key(mnemonic),
            witness_content.as_bytes().to_vec(),
        )
        .await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "did-witness.json uploaded on control plane");

    Ok(())
}

/// Get detailed information about a DID.
pub async fn get_did_info(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<(DidRecord, Option<LogMetadata>), AppError> {
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let log_metadata = match state.dids_ks.get_raw(content_log_key(mnemonic)).await? {
        Some(bytes) => {
            let content = String::from_utf8(bytes).unwrap_or_default();
            Some(extract_log_metadata(&content))
        }
        None => None,
    };

    debug!(did = %auth.did, mnemonic = %mnemonic, "DID info retrieved from control plane");

    Ok((record, log_metadata))
}

/// Get parsed log entries for a DID.
pub async fn get_did_log(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<Vec<LogEntryInfo>, AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    let content = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))?;

    Ok(did_ops::parse_log_entries(&content))
}

/// Get the raw JSONL content for a DID log as a plain string.
pub async fn get_raw_log(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<String, AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    String::from_utf8(bytes).map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))
}

/// List DIDs owned by the caller (or by a specific owner if admin).
/// When the caller is admin and no `requested_owner` is provided, returns all DIDs.
pub async fn list_dids(
    auth: &AuthClaims,
    state: &AppState,
    requested_owner: Option<&str>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<Vec<DidListEntry>, AppError> {
    use crate::acl::Role;

    if auth.role == Role::Admin && requested_owner.is_none() {
        return list_all_dids(state).await;
    }

    let target_owner = if auth.role == Role::Admin {
        requested_owner.unwrap_or(&auth.did)
    } else {
        &auth.did
    };

    let prefix = format!("owner:{target_owner}:");
    let raw = state.dids_ks.prefix_iter_raw(prefix).await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let mnemonic = String::from_utf8(value)
            .map_err(|e| AppError::Internal(format!("invalid mnemonic bytes: {e}")))?;
        if let Some(record) = state.dids_ks.get::<DidRecord>(did_key(&mnemonic)).await? {
            let stats_key = format!("stats:{mnemonic}");
            let did_stats: affinidi_webvh_common::DidStats =
                state.stats_ks.get(stats_key).await?.unwrap_or_default();
            entries.push(DidListEntry {
                mnemonic: record.mnemonic,
                owner: record.owner,
                created_at: record.created_at,
                updated_at: record.updated_at,
                version_count: record.version_count,
                did_id: record.did_id,
                total_resolves: did_stats.total_resolves,
                disabled: record.disabled,
            });
        }
    }

    // Apply pagination
    let offset = offset.unwrap_or(0);
    let limit = limit.unwrap_or(1000);
    let total = entries.len();
    let entries: Vec<_> = entries.into_iter().skip(offset).take(limit).collect();

    info!(did = %auth.did, owner = %target_owner, total, returned = entries.len(), "DIDs listed on control plane");

    Ok(entries)
}

/// List all DIDs in the store (admin only).
async fn list_all_dids(state: &AppState) -> Result<Vec<DidListEntry>, AppError> {
    let raw = state.dids_ks.prefix_iter_raw("did:").await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: DidRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let stats_key = format!("stats:{}", record.mnemonic);
        let did_stats: affinidi_webvh_common::DidStats =
            state.stats_ks.get(stats_key).await?.unwrap_or_default();
        entries.push(DidListEntry {
            mnemonic: record.mnemonic,
            owner: record.owner,
            created_at: record.created_at,
            updated_at: record.updated_at,
            version_count: record.version_count,
            did_id: record.did_id,
            total_resolves: did_stats.total_resolves,
            disabled: record.disabled,
        });
    }

    info!(
        count = entries.len(),
        "all DIDs listed (admin) on control plane"
    );

    Ok(entries)
}

/// Delete a DID and all its associated data.
pub async fn delete_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<Option<String>, AppError> {
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let did_id = record.did_id.clone();

    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, did_key(mnemonic));
    batch.remove(&state.dids_ks, content_log_key(mnemonic));
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    batch.remove(&state.dids_ks, owner_key(&record.owner, mnemonic));
    batch.commit().await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "DID deleted on control plane");

    Ok(did_id)
}

/// Transfer ownership of a DID to a different DID.
///
/// The caller must be the current owner or an admin. The new owner must
/// already exist in the ACL — this prevents transferring a DID to an
/// identity that can never authenticate to claim it.
pub async fn change_did_owner(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    new_owner: &str,
) -> Result<DidRecord, AppError> {
    use affinidi_webvh_common::server::acl::get_acl_entry;

    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;

    // Authorize the caller against the existing record first — keeps the
    // error class stable (Forbidden, not Validation) when an unauthorized
    // caller submits a malformed target. Any new-owner format check after
    // this point only runs for authorized callers.
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let new_owner = new_owner.trim();
    if new_owner.is_empty() {
        return Err(AppError::Validation("new owner DID cannot be empty".into()));
    }
    if !new_owner.starts_with("did:") {
        return Err(AppError::Validation(
            "new owner must be a DID (must start with 'did:')".into(),
        ));
    }

    if record.owner == new_owner {
        return Ok(record);
    }

    if get_acl_entry(&state.acl_ks, new_owner).await?.is_none() {
        return Err(AppError::Validation(format!(
            "new owner '{new_owner}' is not in the ACL — add them first"
        )));
    }

    let prev_owner = std::mem::replace(&mut record.owner, new_owner.to_string());
    record.updated_at = now_epoch();

    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.remove(&state.dids_ks, owner_key(&prev_owner, mnemonic));
    batch.insert_raw(
        &state.dids_ks,
        owner_key(new_owner, mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.commit().await?;

    info!(
        caller = %auth.did,
        prev_owner = %prev_owner,
        new_owner = %new_owner,
        mnemonic = %mnemonic,
        "DID owner changed on control plane"
    );

    Ok(record)
}

/// Toggle the `disabled` flag on a DID record.
pub async fn set_did_disabled(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    disabled: bool,
) -> Result<(), AppError> {
    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;
    record.disabled = disabled;
    state.dids_ks.insert(did_key(mnemonic), &record).await?;
    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        disabled,
        "DID disabled state updated on control plane"
    );
    Ok(())
}

/// Roll back (remove) the last log entry from a DID's JSONL content.
pub async fn rollback_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<(DidRecord, Option<LogMetadata>), AppError> {
    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    let content = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))?;

    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 {
        return Err(AppError::Validation(
            "cannot rollback: DID log must have at least 2 entries".into(),
        ));
    }

    let truncated_lines = &lines[..lines.len() - 1];
    let truncated = truncated_lines.join("\n");

    let new_did_id = extract_did_id(&truncated);
    let new_size = truncated.len() as u64;

    record.version_count = truncated_lines.len() as u64;
    record.did_id = new_did_id;
    record.content_size = new_size;
    record.updated_at = now_epoch();

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        truncated.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    batch.commit().await?;

    let log_metadata = Some(extract_log_metadata(&truncated));

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        remaining = truncated_lines.len(),
        "DID log entry rolled back on control plane"
    );

    Ok((record, log_metadata))
}

/// Check if a custom path is available.
pub async fn check_name(state: &AppState, path: &str) -> Result<CheckNameResponse, AppError> {
    validate_custom_path(path)?;
    let available = is_path_available(&state.dids_ks, path).await?;
    Ok(CheckNameResponse {
        available,
        path: path.to_string(),
    })
}

//! Transport-independent DID management business logic.
//!
//! Both the REST handlers (`routes/did_manage.rs`) and the DIDComm protocol
//! handlers (`routes/didcomm.rs`) delegate to functions in this module so that
//! quota checks, validation, store operations, and stats updates live in one
//! place.

use crate::acl::{self, Role};
use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::mnemonic::{
    generate_unique_mnemonic, is_path_available, validate_custom_path, validate_mnemonic,
};
use crate::server::AppState;

use crate::store::KeyspaceHandle;
use affinidi_webvh_common::DidListEntry;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// Re-export shared types and helpers from webvh-common so existing code
// that imports from `crate::did_ops::*` continues to work.
pub use affinidi_webvh_common::did_ops::{
    DidRecord, LogEntryInfo, LogMetadata,
    did_key, content_log_key, content_witness_key, owner_key, watcher_sync_key,
    extract_did_id, extract_log_metadata, extract_did_web_document, parse_log_entries,
};

// ---------------------------------------------------------------------------
// Quota index — O(1) per-owner count and size tracking
// ---------------------------------------------------------------------------

/// Per-owner quota index stored at `quota:{owner_did}`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuotaIndex {
    pub did_count: u64,
    pub total_size: u64,
}

pub fn quota_key(owner: &str) -> String {
    format!("quota:{owner}")
}

/// Get or create the quota index for an owner.
pub async fn get_quota(dids_ks: &KeyspaceHandle, owner: &str) -> Result<QuotaIndex, AppError> {
    Ok(dids_ks.get(quota_key(owner)).await?.unwrap_or_default())
}

/// Increment the quota index on DID create.
pub async fn quota_on_create(
    dids_ks: &KeyspaceHandle,
    owner: &str,
) -> Result<(), AppError> {
    let mut q = get_quota(dids_ks, owner).await?;
    q.did_count += 1;
    dids_ks.insert(quota_key(owner), &q).await
}

/// Decrement the quota index on DID delete and subtract content size.
pub async fn quota_on_delete(
    dids_ks: &KeyspaceHandle,
    owner: &str,
    content_size: u64,
) -> Result<(), AppError> {
    let mut q = get_quota(dids_ks, owner).await?;
    q.did_count = q.did_count.saturating_sub(1);
    q.total_size = q.total_size.saturating_sub(content_size);
    dids_ks.insert(quota_key(owner), &q).await
}

/// Adjust the quota index on DID publish (size change).
pub async fn quota_on_size_change(
    dids_ks: &KeyspaceHandle,
    owner: &str,
    old_size: u64,
    new_size: u64,
) -> Result<(), AppError> {
    let mut q = get_quota(dids_ks, owner).await?;
    q.total_size = q.total_size.saturating_sub(old_size).saturating_add(new_size);
    dids_ks.insert(quota_key(owner), &q).await
}

// ---------------------------------------------------------------------------
// Quota checks — O(1) using the index
// ---------------------------------------------------------------------------

/// Check whether the owner has reached their DID count limit.
/// Admins are exempt.
pub async fn check_did_count_limit(
    auth: &AuthClaims,
    dids_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    config: &AppConfig,
) -> Result<(), AppError> {
    if auth.role == Role::Admin {
        return Ok(());
    }
    let acl_entry = acl::get_acl_entry(acl_ks, &auth.did).await?;
    let max = acl_entry
        .as_ref()
        .map(|e| e.effective_max_did_count(config.limits.default_max_did_count))
        .unwrap_or(config.limits.default_max_did_count);

    let quota = get_quota(dids_ks, &auth.did).await?;
    if quota.did_count >= max {
        warn!(did = %auth.did, count = quota.did_count, max, "DID count quota exceeded");
        return Err(AppError::QuotaExceeded(format!(
            "DID count limit reached ({max})"
        )));
    }
    debug!(did = %auth.did, count = quota.did_count, max, "DID count quota check passed");
    Ok(())
}

/// Check whether storing `new_size` bytes would exceed the owner's total size quota.
/// Admins are exempt. `old_size` is the current size of the DID being replaced (0 for new).
pub async fn check_total_size_limit(
    auth: &AuthClaims,
    dids_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    config: &AppConfig,
    old_size: u64,
    new_size: u64,
) -> Result<(), AppError> {
    if auth.role == Role::Admin {
        return Ok(());
    }
    let acl_entry = acl::get_acl_entry(acl_ks, &auth.did).await?;
    let max = acl_entry
        .as_ref()
        .map(|e| e.effective_max_total_size(config.limits.default_max_total_size))
        .unwrap_or(config.limits.default_max_total_size);

    let quota = get_quota(dids_ks, &auth.did).await?;
    let proposed = quota.total_size.saturating_sub(old_size).saturating_add(new_size);
    if proposed > max {
        warn!(did = %auth.did, current = quota.total_size, old_size, new_size, max, "total size quota exceeded");
        return Err(AppError::QuotaExceeded(format!(
            "total DID document size would exceed limit ({max} bytes)"
        )));
    }
    debug!(did = %auth.did, current = quota.total_size, new_size, max, "total size quota check passed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Load a DID record and verify the caller is the owner (or admin).
pub async fn get_authorized_record(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    auth: &AuthClaims,
) -> Result<DidRecord, AppError> {
    let record: DidRecord = dids_ks
        .get(did_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;
    if record.owner != auth.did && auth.role != Role::Admin {
        warn!(
            caller = %auth.did,
            role = %auth.role,
            owner = %record.owner,
            mnemonic = %mnemonic,
            "access denied: not the owner of this DID"
        );
        return Err(AppError::Forbidden("not the owner of this DID".into()));
    }
    Ok(record)
}

// ---------------------------------------------------------------------------
// Disable / enable
// ---------------------------------------------------------------------------

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
        role = %auth.role,
        mnemonic = %mnemonic,
        disabled,
        "DID disabled state updated"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// JSONL validation (wraps the common version with AppError)
// ---------------------------------------------------------------------------

/// Validate that every line in the JSONL body is a well-formed did:webvh log entry.
pub fn validate_did_jsonl(content: &str) -> Result<(), AppError> {
    affinidi_webvh_common::did_ops::validate_did_jsonl(content)
        .map_err(AppError::Validation)
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Result of creating a new DID slot.
pub struct CreateDidResult {
    pub mnemonic: String,
    pub did_url: String,
}

/// Create a new DID slot (reserve a mnemonic/path).
pub async fn create_did(
    auth: &AuthClaims,
    state: &AppState,
    path: Option<&str>,
) -> Result<CreateDidResult, AppError> {
    check_did_count_limit(auth, &state.dids_ks, &state.acl_ks, &state.config).await?;

    let mnemonic = match path {
        Some(custom_path) if custom_path == ".well-known" => {
            if auth.role != Role::Admin {
                return Err(AppError::Forbidden(
                    "only admins can create the root DID".into(),
                ));
            }
            if !is_path_available(&state.dids_ks, custom_path).await? {
                return Err(AppError::Conflict(
                    "root DID (.well-known) already exists".into(),
                ));
            }
            custom_path.to_string()
        }
        Some(custom_path) => {
            validate_custom_path(custom_path)?;
            if !is_path_available(&state.dids_ks, custom_path).await? {
                return Err(AppError::Conflict(format!(
                    "path '{custom_path}' is already taken"
                )));
            }
            custom_path.to_string()
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
    };

    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(&mnemonic), &record)?;
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&auth.did, &mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.commit().await?;

    // Update quota index
    quota_on_create(&state.dids_ks, &auth.did).await?;

    let did_url = format!("{}/{mnemonic}/did.jsonl", state.config.public_base_url());

    if let Some(ref collector) = state.stats_collector {
        collector.increment_total_dids();
    }
    info!(did = %auth.did, role = %auth.role, mnemonic = %mnemonic, "DID URI created");

    Ok(CreateDidResult { mnemonic, did_url })
}

/// Result of publishing a DID log.
pub struct PublishDidResult {
    pub did_id: Option<String>,
    pub did_url: String,
    pub version_id: Option<String>,
    pub version_count: u64,
}

/// Publish (upload) a did.jsonl log for an existing DID slot.
pub async fn publish_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    did_log: &str,
) -> Result<PublishDidResult, AppError> {
    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    validate_did_jsonl(did_log)?;

    let new_size = did_log.len() as u64;
    let old_size = record.content_size;
    check_total_size_limit(
        auth,
        &state.dids_ks,
        &state.acl_ks,
        &state.config,
        old_size,
        new_size,
    )
    .await?;

    let did_id = extract_did_id(did_log);

    let version_id = did_log
        .lines()
        .last()
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .and_then(|v| v.get("versionId").and_then(|id| id.as_str()).map(String::from));

    record.updated_at = now_epoch();
    record.version_count += 1;
    record.did_id = did_id.clone();
    record.content_size = new_size;

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        did_log.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.commit().await?;

    // Update quota index for size change
    quota_on_size_change(&state.dids_ks, &record.owner, old_size, new_size).await?;

    // Invalidate cache for this DID
    state.did_cache.invalidate(&content_log_key(mnemonic));

    if let Some(ref collector) = state.stats_collector {
        collector.record_update(mnemonic);
    }

    let did_url = format!("{}/{mnemonic}/did.jsonl", state.config.public_base_url());

    info!(
        did = %auth.did,
        role = %auth.role,
        mnemonic = %mnemonic,
        size = new_size,
        version = record.version_count,
        "did.jsonl published"
    );

    Ok(PublishDidResult {
        did_id,
        did_url,
        version_id,
        version_count: record.version_count,
    })
}

/// Result of uploading witness data.
pub struct WitnessUploadResult {
    pub witness_url: String,
}

/// Upload witness content for a DID.
pub async fn upload_witness(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    witness_content: &str,
) -> Result<WitnessUploadResult, AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    if witness_content.is_empty() {
        return Err(AppError::Validation(
            "did-witness.json content cannot be empty".into(),
        ));
    }

    // Validate that witness content is well-formed JSON
    serde_json::from_str::<serde_json::Value>(witness_content).map_err(|e| {
        AppError::Validation(format!("did-witness.json must be valid JSON: {e}"))
    })?;

    let size = witness_content.len();

    state
        .dids_ks
        .insert_raw(
            content_witness_key(mnemonic),
            witness_content.as_bytes().to_vec(),
        )
        .await?;

    let witness_url = format!("{}/{mnemonic}/did-witness.json", state.config.public_base_url());

    info!(did = %auth.did, role = %auth.role, mnemonic = %mnemonic, size, "did-witness.json uploaded");

    Ok(WitnessUploadResult { witness_url })
}

/// Result of retrieving DID info.
pub struct DidInfoResult {
    pub record: DidRecord,
    pub log_metadata: Option<LogMetadata>,
    pub stats: affinidi_webvh_common::DidStats,
    pub did_url: String,
}

/// Get detailed information about a DID.
pub async fn get_did_info(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<DidInfoResult, AppError> {
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let log_metadata = match state.dids_ks.get_raw(content_log_key(mnemonic)).await? {
        Some(bytes) => {
            let content = String::from_utf8(bytes).unwrap_or_default();
            Some(extract_log_metadata(&content))
        }
        None => None,
    };

    let did_stats = affinidi_webvh_common::DidStats::default();
    let did_url = format!("{}/{mnemonic}/did.jsonl", state.config.public_base_url());

    info!(did = %auth.did, mnemonic = %mnemonic, "DID info retrieved");

    Ok(DidInfoResult {
        record,
        log_metadata,
        stats: did_stats,
        did_url,
    })
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

    let entries = parse_log_entries(&content);

    debug!(mnemonic = %mnemonic, count = entries.len(), "DID log entries retrieved");

    Ok(entries)
}

/// List DIDs owned by the caller (or by a specific owner if the caller is admin).
/// When the caller is admin and no `requested_owner` is provided, returns *all* DIDs.
pub async fn list_dids(
    auth: &AuthClaims,
    state: &AppState,
    requested_owner: Option<&str>,
) -> Result<Vec<DidListEntry>, AppError> {
    // Admin with no owner filter → return all DIDs across all owners.
    if auth.role == Role::Admin && requested_owner.is_none() {
        return list_all_dids(auth, state).await;
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
            let did_stats = affinidi_webvh_common::DidStats::default();
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

    info!(did = %auth.did, role = %auth.role, owner = %target_owner, count = entries.len(), "DIDs listed");

    Ok(entries)
}

/// List all DIDs in the store (admin only). Iterates the `did:` prefix.
async fn list_all_dids(
    auth: &AuthClaims,
    state: &AppState,
) -> Result<Vec<DidListEntry>, AppError> {
    let raw = state.dids_ks.prefix_iter_raw("did:").await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: DidRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let did_stats = affinidi_webvh_common::DidStats::default();
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

    info!(did = %auth.did, role = %auth.role, count = entries.len(), "all DIDs listed (admin)");

    Ok(entries)
}

/// Result of deleting a DID.
pub struct DeleteDidResult {
    pub mnemonic: String,
    pub did_id: Option<String>,
}

/// Delete a DID and all its associated data.
pub async fn delete_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<DeleteDidResult, AppError> {
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let did_id = record.did_id.clone();

    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, did_key(mnemonic));
    batch.remove(&state.dids_ks, content_log_key(mnemonic));
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    batch.remove(&state.dids_ks, owner_key(&record.owner, mnemonic));
    batch.remove(&state.dids_ks, watcher_sync_key(mnemonic));
    batch.commit().await?;

    // Update quota index
    quota_on_delete(&state.dids_ks, &record.owner, record.content_size).await?;

    state.did_cache.invalidate(&content_log_key(mnemonic));

    if let Some(ref collector) = state.stats_collector {
        collector.decrement_total_dids();
    }
    info!(did = %auth.did, role = %auth.role, mnemonic = %mnemonic, "DID deleted");

    Ok(DeleteDidResult {
        mnemonic: mnemonic.to_string(),
        did_id,
    })
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Result of rolling back the last log entry.
pub struct RollbackDidResult {
    pub record: DidRecord,
    pub log_metadata: Option<LogMetadata>,
    pub did_url: String,
}

/// Roll back (remove) the last log entry from a DID's JSONL content.
///
/// Rejects the operation if there are fewer than 2 log entries (cannot roll back
/// the genesis entry). Updates the `DidRecord` with the truncated content and
/// removes any stale witness data.
pub async fn rollback_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<RollbackDidResult, AppError> {
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

    state.did_cache.invalidate(&content_log_key(mnemonic));

    let log_metadata = Some(extract_log_metadata(&truncated));
    let did_url = format!("{}/{mnemonic}/did.jsonl", state.config.public_base_url());

    info!(
        did = %auth.did,
        role = %auth.role,
        mnemonic = %mnemonic,
        remaining = truncated_lines.len(),
        "DID log entry rolled back"
    );

    Ok(RollbackDidResult {
        record,
        log_metadata,
        did_url,
    })
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

    String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Remove DID records that have `version_count == 0` and are older than `ttl_seconds`.
pub async fn cleanup_empty_dids(
    dids_ks: &KeyspaceHandle,
    ttl_seconds: u64,
) -> Result<u64, AppError> {
    let now = now_epoch();
    let raw = dids_ks.prefix_iter_raw("did:").await?;
    let mut removed = 0u64;

    for (_key, value) in raw {
        let record: DidRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if record.version_count == 0 && now.saturating_sub(record.created_at) > ttl_seconds {
            dids_ks.remove(did_key(&record.mnemonic)).await?;
            dids_ks.remove(content_log_key(&record.mnemonic)).await?;
            dids_ks
                .remove(content_witness_key(&record.mnemonic))
                .await?;
            dids_ks
                .remove(owner_key(&record.owner, &record.mnemonic))
                .await?;
            removed += 1;
        }
    }

    Ok(removed)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- validate_did_jsonl wrapper tests ----

    #[test]
    fn validate_jsonl_empty_string_rejected() {
        let result = validate_did_jsonl("");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "expected 'empty' in: {err}");
    }

    #[test]
    fn validate_jsonl_invalid_json_rejected() {
        let result = validate_did_jsonl("this is not json");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid log entry at line 1"),
            "expected line reference in: {err}"
        );
    }

    #[test]
    fn validate_jsonl_valid_json_but_not_log_entry() {
        let result = validate_did_jsonl(r#"{"hello":"world"}"#);
        assert!(result.is_err());
    }

    async fn make_valid_jsonl() -> String {
        use affinidi_webvh_common::did::{build_did_document, create_log_entry, encode_host};

        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let pk = secret.get_public_keymultibase().unwrap();
        let host = encode_host("http://localhost:3000").unwrap();
        let doc = build_did_document(&host, "test-validate", &pk, &Default::default());
        let (_scid, jsonl) = create_log_entry(&doc, &secret).await.unwrap();
        jsonl
    }

    #[tokio::test]
    async fn validate_jsonl_blank_lines_skipped() {
        let entry = make_valid_jsonl().await;
        let with_blanks = format!("\n{entry}\n\n");
        assert!(validate_did_jsonl(&with_blanks).is_ok());
    }

    #[tokio::test]
    async fn validate_jsonl_valid_single_entry() {
        let entry = make_valid_jsonl().await;
        assert!(validate_did_jsonl(&entry).is_ok());
    }

    #[tokio::test]
    async fn validate_jsonl_second_line_invalid() {
        let entry = make_valid_jsonl().await;
        let content = format!("{entry}\nnot valid json");
        let result = validate_did_jsonl(&content);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("line 2"), "expected 'line 2' in error: {err}");
    }

    // ---- rollback helper tests (pure functions used by rollback_did) ----

    #[test]
    fn rollback_removes_last_line() {
        let line1 = r#"{"state":{"id":"did:webvh:first:host:path"}}"#;
        let line2 = r#"{"state":{"id":"did:webvh:second:host:path"}}"#;
        let jsonl = format!("{line1}\n{line2}");
        let lines: Vec<&str> = jsonl.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2);
        let truncated = lines[..lines.len() - 1].join("\n");
        assert_eq!(truncated, line1);
        assert_eq!(
            extract_did_id(&truncated),
            Some("did:webvh:first:host:path".to_string())
        );
    }

    #[test]
    fn rollback_rejects_single_entry() {
        let jsonl = r#"{"state":{"id":"did:webvh:only:host:path"}}"#;
        let lines: Vec<&str> = jsonl.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(
            lines.len() < 2,
            "single entry should not be rollback-able"
        );
    }

    #[test]
    fn rollback_updates_did_id() {
        let line1 = r#"{"state":{"id":"did:webvh:genesis:host:path"}}"#;
        let line2 = r#"{"state":{"id":"did:webvh:update1:host:path"}}"#;
        let line3 = r#"{"state":{"id":"did:webvh:update2:host:path"}}"#;
        let jsonl = format!("{line1}\n{line2}\n{line3}");
        let lines: Vec<&str> = jsonl.lines().filter(|l| !l.trim().is_empty()).collect();
        let truncated = lines[..lines.len() - 1].join("\n");
        assert_eq!(
            extract_did_id(&truncated),
            Some("did:webvh:update1:host:path".to_string())
        );
    }
}

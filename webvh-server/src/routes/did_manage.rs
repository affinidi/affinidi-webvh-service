use crate::acl::{self, Role};
use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::mnemonic::{
    generate_unique_mnemonic, is_path_available, validate_custom_path, validate_mnemonic,
};
use crate::server::AppState;
use crate::stats;
use crate::store::KeyspaceHandle;
use affinidi_webvh_common::{CheckNameResponse, DidListEntry, RequestUriResponse};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use didwebvh_rs::log_entry::LogEntry;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// A record tracking a hosted DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRecord {
    pub owner: String,
    pub mnemonic: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
    #[serde(default)]
    pub did_id: Option<String>,
    #[serde(default)]
    pub content_size: u64,
}

fn did_key(mnemonic: &str) -> String {
    format!("did:{mnemonic}")
}

fn content_log_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:log")
}

fn content_witness_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:witness")
}

fn owner_key(did: &str, mnemonic: &str) -> String {
    format!("owner:{did}:{mnemonic}")
}

/// Check whether the owner has reached their DID count limit.
/// Admins are exempt.
async fn check_did_count_limit(
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

    let prefix = format!("owner:{}:", auth.did);
    let owned = dids_ks.prefix_iter_raw(prefix).await?;
    let count = owned.len() as u64;
    if count >= max {
        warn!(did = %auth.did, count, max, "DID count quota exceeded");
        return Err(AppError::QuotaExceeded(format!(
            "DID count limit reached ({max})"
        )));
    }
    debug!(did = %auth.did, count, max, "DID count quota check passed");
    Ok(())
}

/// Check whether storing `new_size` bytes would exceed the owner's total size quota.
/// Admins are exempt. `exclude_mnemonic` is excluded from the sum (the upload replaces it).
async fn check_total_size_limit(
    auth: &AuthClaims,
    dids_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    config: &AppConfig,
    exclude_mnemonic: &str,
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

    let prefix = format!("owner:{}:", auth.did);
    let owned = dids_ks.prefix_iter_raw(prefix).await?;

    let mut total: u64 = 0;
    for (_key, value) in owned {
        let mnemonic = String::from_utf8(value)
            .map_err(|e| AppError::Internal(format!("invalid mnemonic bytes: {e}")))?;
        if mnemonic == exclude_mnemonic {
            continue;
        }
        if let Some(record) = dids_ks.get::<DidRecord>(did_key(&mnemonic)).await? {
            total = total.saturating_add(record.content_size);
        }
    }

    let proposed = total.saturating_add(new_size);
    if proposed > max {
        warn!(did = %auth.did, current = total, new_size, max, "total size quota exceeded");
        return Err(AppError::QuotaExceeded(format!(
            "total DID document size would exceed limit ({max} bytes)"
        )));
    }
    debug!(did = %auth.did, current = total, new_size, max, "total size quota check passed");
    Ok(())
}

/// Load a DID record and verify the caller is the owner (or admin).
async fn get_authorized_record(
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

// ---------- POST /dids/check ----------

#[derive(Debug, Deserialize)]
pub struct CheckNameRequest {
    pub path: String,
}

pub async fn check_name(
    auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<CheckNameRequest>,
) -> Result<Json<CheckNameResponse>, AppError> {
    validate_custom_path(&req.path)?;
    let available = is_path_available(&state.dids_ks, &req.path).await?;
    info!(did = %auth.did, path = %req.path, available, "name availability checked");
    Ok(Json(CheckNameResponse {
        available,
        path: req.path,
    }))
}

// ---------- POST /dids ----------

#[derive(Debug, Deserialize, Default)]
pub struct RequestUriRequest {
    pub path: Option<String>,
}

pub async fn request_uri(
    auth: AuthClaims,
    State(state): State<AppState>,
    body: Option<Json<RequestUriRequest>>,
) -> Result<(StatusCode, Json<RequestUriResponse>), AppError> {
    // Enforce per-account DID count limit (admins exempt)
    check_did_count_limit(&auth, &state.dids_ks, &state.acl_ks, &state.config).await?;

    let mnemonic = match body.and_then(|b| b.0.path) {
        Some(custom_path) if custom_path == ".well-known" => {
            // Root DID: admin-only, skip normal path validation
            if auth.role != Role::Admin {
                return Err(AppError::Forbidden(
                    "only admins can create the root DID".into(),
                ));
            }
            if !is_path_available(&state.dids_ks, &custom_path).await? {
                return Err(AppError::Conflict(
                    "root DID (.well-known) already exists".into(),
                ));
            }
            custom_path
        }
        Some(custom_path) => {
            validate_custom_path(&custom_path)?;
            if !is_path_available(&state.dids_ks, &custom_path).await? {
                return Err(AppError::Conflict(format!(
                    "path '{custom_path}' is already taken"
                )));
            }
            custom_path
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
    };

    // Store DID record
    state.dids_ks.insert(did_key(&mnemonic), &record).await?;

    // Store owner reverse index
    state
        .dids_ks
        .insert_raw(
            owner_key(&auth.did, &mnemonic),
            mnemonic.as_bytes().to_vec(),
        )
        .await?;

    // Build the public DID URL
    let base_url = state.config.public_url.clone().unwrap_or_else(|| {
        format!(
            "http://{}:{}",
            state.config.server.host, state.config.server.port
        )
    });

    let did_url = format!("{base_url}/{mnemonic}/did.jsonl");

    info!(did = %auth.did, role = %auth.role, mnemonic = %mnemonic, "DID URI created");

    Ok((
        StatusCode::CREATED,
        Json(RequestUriResponse { mnemonic, did_url }),
    ))
}

// ---------- JSONL validation ----------

/// Validate that every line in the JSONL body is a well-formed did:webvh log entry.
fn validate_did_jsonl(content: &str) -> Result<(), AppError> {
    if content.is_empty() {
        return Err(AppError::Validation(
            "did.jsonl content cannot be empty".into(),
        ));
    }

    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        LogEntry::deserialize_string(line, None).map_err(|e| {
            AppError::Validation(format!("invalid log entry at line {}: {e}", idx + 1))
        })?;
    }

    Ok(())
}

// ---------- DID ID extraction helpers ----------

/// Extract the `did:webvh:...` identifier from the last line of JSONL content
/// via the `state.id` field.
fn extract_did_id(jsonl_content: &str) -> Option<String> {
    let last_line = jsonl_content.lines().last()?;
    let value: serde_json::Value = serde_json::from_str(last_line).ok()?;
    value
        .get("state")
        .and_then(|state| state.get("id"))
        .and_then(|id| id.as_str())
        .filter(|s| s.starts_with("did:webvh:"))
        .map(|s| s.to_string())
}

/// Summary of WebVH log entry metadata parsed from the stored JSONL content.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogMetadata {
    /// Number of log entries (JSONL lines).
    pub log_entry_count: u64,
    /// The `versionId` from the latest (last) log entry.
    pub latest_version_id: Option<String>,
    /// The `versionTime` from the latest (last) log entry.
    pub latest_version_time: Option<String>,
    /// The `parameters.method` value (e.g. "did:webvh:1.0").
    pub method: Option<String>,
    /// Whether `parameters.portable` is true.
    pub portable: bool,
    /// Whether `parameters.nextKeyHashes` is present (pre-rotation active).
    pub pre_rotation: bool,
    /// Whether `parameters.witness` is present and non-empty.
    pub witnesses: bool,
    /// Number of witnesses configured.
    pub witness_count: u32,
    /// Witness threshold required.
    pub witness_threshold: u32,
    /// Whether `parameters.watchers` is present and non-empty.
    pub watchers: bool,
    /// Number of watchers configured.
    pub watcher_count: u32,
    /// Whether the DID is deactivated.
    pub deactivated: bool,
    /// TTL in seconds, if set.
    pub ttl: Option<u32>,
}

/// Parse JSONL content and extract metadata from the log entries.
fn extract_log_metadata(jsonl_content: &str) -> LogMetadata {
    let lines: Vec<&str> = jsonl_content.lines().collect();
    let mut meta = LogMetadata {
        log_entry_count: lines.len() as u64,
        ..Default::default()
    };

    // Extract data from the last (latest) log entry
    let Some(last_line) = lines.last() else {
        return meta;
    };
    let Ok(entry) = serde_json::from_str::<serde_json::Value>(last_line) else {
        return meta;
    };

    meta.latest_version_id = entry
        .get("versionId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    meta.latest_version_time = entry
        .get("versionTime")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if let Some(params) = entry.get("parameters") {
        meta.method = params
            .get("method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        meta.portable = params
            .get("portable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        meta.pre_rotation = params
            .get("nextKeyHashes")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());

        meta.deactivated = params
            .get("deactivated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        meta.ttl = params.get("ttl").and_then(|v| v.as_u64()).map(|v| v as u32);

        if let Some(witness) = params.get("witness") {
            let threshold = witness
                .get("threshold")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let count = witness
                .get("witnesses")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u32)
                .unwrap_or(0);
            if count > 0 {
                meta.witnesses = true;
                meta.witness_count = count;
                meta.witness_threshold = threshold;
            }
        }

        if let Some(watchers_val) = params.get("watchers")
            && let Some(arr) = watchers_val.as_array()
            && !arr.is_empty()
        {
            meta.watchers = true;
            meta.watcher_count = arr.len() as u32;
        }
    }

    meta
}

// ---------- GET /dids/{mnemonic} ----------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDetailResponse {
    pub mnemonic: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
    pub did_id: Option<String>,
    pub owner: String,
    pub log: Option<LogMetadata>,
}

pub async fn get_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<DidDetailResponse>, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    // Parse stored JSONL content for log metadata
    let log = match state.dids_ks.get_raw(content_log_key(mnemonic)).await? {
        Some(bytes) => {
            let content = String::from_utf8(bytes).unwrap_or_default();
            Some(extract_log_metadata(&content))
        }
        None => None,
    };

    info!(did = %auth.did, mnemonic = %mnemonic, "DID details retrieved");

    Ok(Json(DidDetailResponse {
        mnemonic: record.mnemonic,
        created_at: record.created_at,
        updated_at: record.updated_at,
        version_count: record.version_count,
        did_id: record.did_id,
        owner: record.owner,
        log,
    }))
}

// ---------- PUT /dids/{mnemonic} ----------

pub async fn upload_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    body: String,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    // Validate that every line is a well-formed did:webvh log entry
    validate_did_jsonl(&body)?;

    // Enforce per-account total size limit (admins exempt)
    let new_size = body.len() as u64;
    check_total_size_limit(
        &auth,
        &state.dids_ks,
        &state.acl_ks,
        &state.config,
        mnemonic,
        new_size,
    )
    .await?;

    // Extract DID ID from content
    let did_id = extract_did_id(&body);

    // Store content
    state
        .dids_ks
        .insert_raw(content_log_key(mnemonic), body.into_bytes())
        .await?;

    // Update record
    record.updated_at = now_epoch();
    record.version_count += 1;
    record.did_id = did_id;
    record.content_size = new_size;
    state.dids_ks.insert(did_key(mnemonic), &record).await?;

    // Increment stats
    stats::increment_updates(&state.stats_ks, mnemonic).await?;

    info!(
        did = %auth.did,
        role = %auth.role,
        mnemonic = %mnemonic,
        size = new_size,
        version = record.version_count,
        "did.jsonl uploaded"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------- PUT /dids/{mnemonic}/witness ----------

pub async fn upload_witness(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
    body: String,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    if body.is_empty() {
        return Err(AppError::Validation(
            "did-witness.json content cannot be empty".into(),
        ));
    }

    let size = body.len();

    // Store witness content
    state
        .dids_ks
        .insert_raw(content_witness_key(mnemonic), body.into_bytes())
        .await?;

    info!(did = %auth.did, role = %auth.role, mnemonic = %mnemonic, size, "did-witness.json uploaded");

    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /dids/{mnemonic} ----------

pub async fn delete_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    // Remove all associated data
    state.dids_ks.remove(did_key(mnemonic)).await?;
    state.dids_ks.remove(content_log_key(mnemonic)).await?;
    state.dids_ks.remove(content_witness_key(mnemonic)).await?;
    state
        .dids_ks
        .remove(owner_key(&record.owner, mnemonic))
        .await?;

    // Remove stats
    stats::delete_stats(&state.stats_ks, mnemonic).await?;

    info!(did = %auth.did, role = %auth.role, mnemonic = %mnemonic, "DID deleted");

    Ok(StatusCode::NO_CONTENT)
}

// ---------- GET /dids ----------

#[derive(Debug, Deserialize)]
pub struct ListDidsQuery {
    pub owner: Option<String>,
}

pub async fn list_dids(
    auth: AuthClaims,
    State(state): State<AppState>,
    Query(query): Query<ListDidsQuery>,
) -> Result<Json<Vec<DidListEntry>>, AppError> {
    // Admins may filter by a specific owner; everyone else sees their own DIDs.
    let target_owner = if auth.role == Role::Admin {
        query.owner.as_deref().unwrap_or(&auth.did)
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
            let did_stats = stats::get_stats(&state.stats_ks, &mnemonic).await?;
            entries.push(DidListEntry {
                mnemonic: record.mnemonic,
                created_at: record.created_at,
                updated_at: record.updated_at,
                version_count: record.version_count,
                did_id: record.did_id,
                total_resolves: did_stats.total_resolves,
            });
        }
    }

    info!(did = %auth.did, role = %auth.role, owner = %target_owner, count = entries.len(), "DIDs listed");

    Ok(Json(entries))
}

// ---------- Cleanup ----------

/// Remove DID records that have `version_count == 0` and are older than `ttl_seconds`.
pub async fn cleanup_empty_dids(
    dids_ks: &KeyspaceHandle,
    stats_ks: &KeyspaceHandle,
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
            stats::delete_stats(stats_ks, &record.mnemonic).await?;
            removed += 1;
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_did_id_from_state_id() {
        let jsonl = r#"{"versionId":"1-abc","parameters":{"method":"did:webvh:1.0"},"state":{"id":"did:webvh:abc123:example.com:test"}}"#;
        assert_eq!(
            extract_did_id(jsonl),
            Some("did:webvh:abc123:example.com:test".to_string())
        );
    }

    #[test]
    fn extract_did_id_ignores_parameters_method() {
        // parameters.method contains "did:webvh:1.0" — must NOT be returned
        let jsonl = r#"{"parameters":{"method":"did:webvh:1.0"},"state":{"id":"did:webvh:real:host:path"}}"#;
        assert_eq!(
            extract_did_id(jsonl),
            Some("did:webvh:real:host:path".to_string())
        );
    }

    #[test]
    fn extract_did_id_returns_none_without_state() {
        let jsonl = r#"{"parameters":{"method":"did:webvh:1.0"}}"#;
        assert_eq!(extract_did_id(jsonl), None);
    }

    #[test]
    fn extract_did_id_returns_none_for_non_webvh_state_id() {
        let jsonl = r#"{"state":{"id":"did:key:z6Mk..."}}"#;
        assert_eq!(extract_did_id(jsonl), None);
    }

    #[test]
    fn extract_did_id_returns_none_for_invalid_json() {
        assert_eq!(extract_did_id("not valid json"), None);
    }

    #[test]
    fn extract_did_id_returns_none_for_empty() {
        assert_eq!(extract_did_id(""), None);
    }

    #[test]
    fn extract_did_id_uses_last_line() {
        // Multi-line JSONL — should read state.id from the LAST line
        let jsonl = r#"{"state":{"id":"did:webvh:first:host:path"}}
{"state":{"id":"did:webvh:second:host:path"}}"#;
        assert_eq!(
            extract_did_id(jsonl),
            Some("did:webvh:second:host:path".to_string())
        );
    }

    #[test]
    fn extract_did_id_realistic_entry() {
        let jsonl = r#"{"versionId":"1-QmHash","versionTime":"2025-01-23T04:12:36Z","parameters":{"method":"did:webvh:1.0","scid":"QmSCID","updateKeys":["z82Lk"]},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmSCID:localhost%3A3000:my-did","authentication":["did:webvh:QmSCID:localhost%3A3000:my-did#key-0"]},"proof":[{"type":"DataIntegrityProof"}]}"#;
        assert_eq!(
            extract_did_id(jsonl),
            Some("did:webvh:QmSCID:localhost%3A3000:my-did".to_string())
        );
    }

    // ---- extract_log_metadata tests ----

    #[test]
    fn log_metadata_empty_content() {
        let meta = extract_log_metadata("");
        assert_eq!(meta.log_entry_count, 0);
        assert_eq!(meta.latest_version_id, None);
    }

    #[test]
    fn log_metadata_basic_entry() {
        let jsonl = r#"{"versionId":"1-QmHash","versionTime":"2025-01-23T04:12:36Z","parameters":{"method":"did:webvh:1.0","portable":true}}"#;
        let meta = extract_log_metadata(jsonl);
        assert_eq!(meta.log_entry_count, 1);
        assert_eq!(meta.latest_version_id.as_deref(), Some("1-QmHash"));
        assert_eq!(
            meta.latest_version_time.as_deref(),
            Some("2025-01-23T04:12:36Z")
        );
        assert_eq!(meta.method.as_deref(), Some("did:webvh:1.0"));
        assert!(meta.portable);
        assert!(!meta.pre_rotation);
        assert!(!meta.witnesses);
        assert!(!meta.watchers);
        assert!(!meta.deactivated);
    }

    #[test]
    fn log_metadata_with_witnesses_and_watchers() {
        let jsonl = r#"{"versionId":"2-QmXyz","parameters":{"witness":{"threshold":2,"witnesses":[{"id":"did:key:z1"},{"id":"did:key:z2"},{"id":"did:key:z3"}]},"watchers":["https://w1.example.com","https://w2.example.com"],"nextKeyHashes":["QmHash1"]}}"#;
        let meta = extract_log_metadata(jsonl);
        assert!(meta.witnesses);
        assert_eq!(meta.witness_count, 3);
        assert_eq!(meta.witness_threshold, 2);
        assert!(meta.watchers);
        assert_eq!(meta.watcher_count, 2);
        assert!(meta.pre_rotation);
    }

    #[test]
    fn log_metadata_multi_line_uses_last() {
        let jsonl = r#"{"versionId":"1-first","parameters":{"method":"did:webvh:1.0"}}
{"versionId":"2-second","parameters":{"portable":true,"deactivated":true,"ttl":300}}"#;
        let meta = extract_log_metadata(jsonl);
        assert_eq!(meta.log_entry_count, 2);
        assert_eq!(meta.latest_version_id.as_deref(), Some("2-second"));
        assert!(meta.portable);
        assert!(meta.deactivated);
        assert_eq!(meta.ttl, Some(300));
    }

    // ---- validate_did_jsonl tests ----

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
        // Valid JSON but missing required did:webvh log entry fields
        let result = validate_did_jsonl(r#"{"hello":"world"}"#);
        assert!(result.is_err());
    }

    fn make_valid_jsonl() -> String {
        use affinidi_webvh_common::did::{build_did_document, create_log_entry, encode_host};

        let secret = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, None);
        let pk = secret.get_public_keymultibase().unwrap();
        let host = encode_host("http://localhost:3000").unwrap();
        let doc = build_did_document(&host, "test-validate", &pk);
        let (_scid, jsonl) = create_log_entry(&doc, &secret).unwrap();
        jsonl
    }

    #[test]
    fn validate_jsonl_blank_lines_skipped() {
        let entry = make_valid_jsonl();
        let with_blanks = format!("\n{entry}\n\n");
        assert!(validate_did_jsonl(&with_blanks).is_ok());
    }

    #[test]
    fn validate_jsonl_valid_single_entry() {
        let entry = make_valid_jsonl();
        assert!(validate_did_jsonl(&entry).is_ok());
    }

    #[test]
    fn validate_jsonl_second_line_invalid() {
        let entry = make_valid_jsonl();
        let content = format!("{entry}\nnot valid json");
        let result = validate_did_jsonl(&content);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("line 2"), "expected 'line 2' in error: {err}");
    }

    // ---- DidRecord serde backwards compat ----

    #[test]
    fn did_record_deserialize_without_content_size() {
        let json = r#"{"owner":"did:example:a","mnemonic":"test","created_at":100,"updated_at":100,"version_count":1}"#;
        let record: DidRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.content_size, 0);
        assert!(record.did_id.is_none());
    }

    #[test]
    fn did_record_deserialize_with_content_size() {
        let json = r#"{"owner":"did:example:a","mnemonic":"test","created_at":100,"updated_at":200,"version_count":2,"did_id":"did:webvh:abc:host:path","content_size":5000}"#;
        let record: DidRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.content_size, 5000);
        assert_eq!(record.did_id.as_deref(), Some("did:webvh:abc:host:path"));
    }
}

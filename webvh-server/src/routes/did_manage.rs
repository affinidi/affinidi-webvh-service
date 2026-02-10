use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use affinidi_webvh_common::{CheckNameResponse, DidListEntry, RequestUriResponse};

use crate::acl::Role;
use crate::auth::AuthClaims;
use crate::auth::session::now_epoch;
use crate::error::AppError;
use crate::mnemonic::{generate_unique_mnemonic, is_path_available, validate_custom_path};
use crate::server::AppState;
use crate::stats;
use crate::store::KeyspaceHandle;
use tracing::info;

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
    _auth: AuthClaims,
    State(state): State<AppState>,
    Json(req): Json<CheckNameRequest>,
) -> Result<Json<CheckNameResponse>, AppError> {
    validate_custom_path(&req.path)?;
    let available = is_path_available(&state.dids_ks, &req.path).await?;
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
    let mnemonic = match body.and_then(|b| b.0.path) {
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
    let base_url = state
        .config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", state.config.server.host, state.config.server.port));

    let did_url = format!("{base_url}/{mnemonic}/did.jsonl");

    info!(did = %auth.did, mnemonic = %mnemonic, "URI requested");

    Ok((
        StatusCode::CREATED,
        Json(RequestUriResponse { mnemonic, did_url }),
    ))
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

        if let Some(watchers_val) = params.get("watchers") {
            if let Some(arr) = watchers_val.as_array() {
                if !arr.is_empty() {
                    meta.watchers = true;
                    meta.watcher_count = arr.len() as u32;
                }
            }
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
    pub log: Option<LogMetadata>,
}

pub async fn get_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<Json<DidDetailResponse>, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    let record = get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    // Parse stored JSONL content for log metadata
    let log = match state.dids_ks.get_raw(content_log_key(mnemonic)).await? {
        Some(bytes) => {
            let content = String::from_utf8(bytes).unwrap_or_default();
            Some(extract_log_metadata(&content))
        }
        None => None,
    };

    Ok(Json(DidDetailResponse {
        mnemonic: record.mnemonic,
        created_at: record.created_at,
        updated_at: record.updated_at,
        version_count: record.version_count,
        did_id: record.did_id,
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
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    if body.is_empty() {
        return Err(AppError::Validation("did.jsonl content cannot be empty".into()));
    }

    // Extract DID ID from content
    let did_id = extract_did_id(&body);

    // Store content
    state
        .dids_ks
        .insert_raw(content_log_key(&mnemonic), body.into_bytes())
        .await?;

    // Update record
    record.updated_at = now_epoch();
    record.version_count += 1;
    record.did_id = did_id;
    state.dids_ks.insert(did_key(&mnemonic), &record).await?;

    // Increment stats
    stats::increment_updates(&state.stats_ks, &mnemonic).await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "did.jsonl uploaded");

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
    get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    if body.is_empty() {
        return Err(AppError::Validation(
            "did-witness.json content cannot be empty".into(),
        ));
    }

    // Store witness content
    state
        .dids_ks
        .insert_raw(content_witness_key(&mnemonic), body.into_bytes())
        .await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "did-witness.json uploaded");

    Ok(StatusCode::NO_CONTENT)
}

// ---------- DELETE /dids/{mnemonic} ----------

pub async fn delete_did(
    auth: AuthClaims,
    State(state): State<AppState>,
    Path(mnemonic): Path<String>,
) -> Result<StatusCode, AppError> {
    let mnemonic = mnemonic.trim_start_matches('/');
    let record = get_authorized_record(&state.dids_ks, mnemonic, &auth).await?;

    // Remove all associated data
    state.dids_ks.remove(did_key(&mnemonic)).await?;
    state.dids_ks.remove(content_log_key(&mnemonic)).await?;
    state.dids_ks.remove(content_witness_key(&mnemonic)).await?;
    state
        .dids_ks
        .remove(owner_key(&record.owner, &mnemonic))
        .await?;

    // Remove stats
    stats::delete_stats(&state.stats_ks, &mnemonic).await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "DID deleted");

    Ok(StatusCode::NO_CONTENT)
}

// ---------- GET /dids ----------

pub async fn list_dids(
    auth: AuthClaims,
    State(state): State<AppState>,
) -> Result<Json<Vec<DidListEntry>>, AppError> {
    let prefix = format!("owner:{}:", auth.did);
    let raw = state.dids_ks.prefix_iter_raw(prefix).await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let mnemonic = String::from_utf8(value)
            .map_err(|e| AppError::Internal(format!("invalid mnemonic bytes: {e}")))?;
        if let Some(record) = state
            .dids_ks
            .get::<DidRecord>(did_key(&mnemonic))
            .await?
        {
            entries.push(DidListEntry {
                mnemonic: record.mnemonic,
                created_at: record.created_at,
                updated_at: record.updated_at,
                version_count: record.version_count,
                did_id: record.did_id,
            });
        }
    }

    info!(did = %auth.did, count = entries.len(), "DIDs listed");

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
}

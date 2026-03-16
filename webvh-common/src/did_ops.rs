//! Shared DID types and pure helper functions used by both webvh-server and
//! webvh-control.
//!
//! This module contains the data types and validation/extraction functions that
//! are independent of any particular server's `AppState` or business logic.

use didwebvh_rs::log_entry::LogEntry;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

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
    #[serde(default)]
    pub disabled: bool,
}

/// A single parsed log entry with its DID document and parameters.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntryInfo {
    pub version_id: Option<String>,
    pub version_time: Option<String>,
    pub state: Option<serde_json::Value>,
    pub parameters: Option<serde_json::Value>,
}

/// Summary of WebVH log entry metadata parsed from the stored JSONL content.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogMetadata {
    pub log_entry_count: u64,
    pub latest_version_id: Option<String>,
    pub latest_version_time: Option<String>,
    pub method: Option<String>,
    pub portable: bool,
    pub pre_rotation: bool,
    pub deactivated: bool,
    pub ttl: Option<u32>,
    pub witnesses: bool,
    pub witness_count: u32,
    pub witness_threshold: u32,
    pub watchers: bool,
    pub watcher_count: u32,
    pub watcher_urls: Vec<String>,
}

// ---------------------------------------------------------------------------
// Store key helpers
// ---------------------------------------------------------------------------

pub fn did_key(mnemonic: &str) -> String {
    format!("did:{mnemonic}")
}

pub fn content_log_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:log")
}

pub fn content_witness_key(mnemonic: &str) -> String {
    format!("content:{mnemonic}:witness")
}

pub fn owner_key(did: &str, mnemonic: &str) -> String {
    format!("owner:{did}:{mnemonic}")
}

pub fn watcher_sync_key(mnemonic: &str) -> String {
    format!("watcher_sync:{mnemonic}")
}

// ---------------------------------------------------------------------------
// JSONL validation & extraction
// ---------------------------------------------------------------------------

/// Validate that every line in the JSONL body is a well-formed did:webvh log entry.
///
/// Returns an error string on failure (caller wraps in their own error type).
pub fn validate_did_jsonl(content: &str) -> Result<(), String> {
    if content.is_empty() {
        return Err("did.jsonl content cannot be empty".into());
    }

    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        LogEntry::deserialize_string(line, None)
            .map_err(|e| format!("invalid log entry at line {}: {e}", idx + 1))?;
    }

    Ok(())
}

/// Extract the `did:webvh:...` identifier from the last line of JSONL content
/// via the `state.id` field.
pub fn extract_did_id(jsonl_content: &str) -> Option<String> {
    let last_line = jsonl_content.lines().last()?;
    let value: serde_json::Value = serde_json::from_str(last_line).ok()?;
    value
        .get("state")
        .and_then(|state| state.get("id"))
        .and_then(|id| id.as_str())
        .filter(|s| s.starts_with("did:webvh:"))
        .map(|s| s.to_string())
}

/// Parse JSONL content and extract metadata from the log entries.
pub fn extract_log_metadata(jsonl_content: &str) -> LogMetadata {
    let lines: Vec<&str> = jsonl_content.lines().collect();
    let mut meta = LogMetadata {
        log_entry_count: lines.len() as u64,
        ..Default::default()
    };

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
            meta.watcher_urls = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
    }

    meta
}

/// Extract a did:web document from JSONL content by rewriting the did:webvh identity.
///
/// Returns `Some(json_bytes)` if the last log entry's `state.alsoKnownAs` contains
/// the expected `did:web` identifier.
pub fn extract_did_web_document(jsonl_content: &str, expected_did_web: &str) -> Option<Vec<u8>> {
    let last_line = jsonl_content.lines().last()?;
    let entry: serde_json::Value = serde_json::from_str(last_line).ok()?;
    let state = entry.get("state")?;

    let webvh_id = state.get("id")?.as_str()?;
    if !webvh_id.starts_with("did:webvh:") {
        return None;
    }

    let also_known_as = state.get("alsoKnownAs")?.as_array()?;
    let found = also_known_as
        .iter()
        .any(|v| v.as_str() == Some(expected_did_web));
    if !found {
        return None;
    }

    let state_json = serde_json::to_string(state).ok()?;
    let rewritten = state_json.replace(webvh_id, expected_did_web);
    Some(rewritten.into_bytes())
}

/// Parse JSONL log entries into structured `LogEntryInfo` values.
pub fn parse_log_entries(jsonl_content: &str) -> Vec<LogEntryInfo> {
    jsonl_content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            Some(LogEntryInfo {
                version_id: value
                    .get("versionId")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                version_time: value
                    .get("versionTime")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                state: value.get("state").cloned(),
                parameters: value.get("parameters").cloned(),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

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
    fn extract_did_id_returns_none_without_state() {
        let jsonl = r#"{"parameters":{"method":"did:webvh:1.0"}}"#;
        assert_eq!(extract_did_id(jsonl), None);
    }

    #[test]
    fn extract_did_id_returns_none_for_non_webvh() {
        let jsonl = r#"{"state":{"id":"did:key:z6Mk..."}}"#;
        assert_eq!(extract_did_id(jsonl), None);
    }

    #[test]
    fn extract_did_id_uses_last_line() {
        let jsonl = r#"{"state":{"id":"did:webvh:first:host:path"}}
{"state":{"id":"did:webvh:second:host:path"}}"#;
        assert_eq!(
            extract_did_id(jsonl),
            Some("did:webvh:second:host:path".to_string())
        );
    }

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
        assert!(meta.portable);
    }

    #[test]
    fn validate_jsonl_empty_rejected() {
        assert!(validate_did_jsonl("").is_err());
    }

    #[test]
    fn validate_jsonl_invalid_json_rejected() {
        assert!(validate_did_jsonl("not json").is_err());
    }

    #[test]
    fn did_record_deserialize_without_content_size() {
        let json = r#"{"owner":"did:example:a","mnemonic":"test","created_at":100,"updated_at":100,"version_count":1}"#;
        let record: DidRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.content_size, 0);
        assert!(record.did_id.is_none());
    }

    #[test]
    fn parse_log_entries_works() {
        let jsonl = r#"{"versionId":"1-abc","state":{"id":"test"},"parameters":{"method":"1.0"}}"#;
        let entries = parse_log_entries(jsonl);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version_id.as_deref(), Some("1-abc"));
    }
}

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Auth types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub did: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub session_id: String,
    pub data: ChallengeData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeData {
    pub challenge: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateResponse {
    pub session_id: String,
    pub data: AuthenticateData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateData {
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub session_id: String,
    pub data: RefreshData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshData {
    pub access_token: String,
    pub access_expires_at: u64,
}

// ---------------------------------------------------------------------------
// DID management types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDidRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckNameRequest {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckNameResponse {
    pub available: bool,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestUriResponse {
    pub mnemonic: String,
    pub did_url: String,
}

// ---------------------------------------------------------------------------
// DID list / stats types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidListEntry {
    pub mnemonic: String,
    pub owner: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
    pub did_id: Option<String>,
    pub total_resolves: u64,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DidStats {
    #[serde(alias = "total_resolves")]
    pub total_resolves: u64,
    #[serde(alias = "total_updates")]
    pub total_updates: u64,
    #[serde(alias = "last_resolved_at")]
    pub last_resolved_at: Option<u64>,
    #[serde(alias = "last_updated_at")]
    pub last_updated_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Stats sync (server → control plane)
// ---------------------------------------------------------------------------

/// Per-DID counter delta for a single sync interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidStatsDelta {
    pub mnemonic: String,
    pub resolve_delta: u64,
    pub update_delta: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_resolved_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated_at: Option<u64>,
}

/// Payload sent by webvh-server to the control plane with per-DID deltas.
///
/// Pushed periodically (configurable via `stats.sync_interval_secs`).
/// Only sent when there are actual changes — empty syncs are skipped.
/// The control plane merges these deltas into its persistent per-DID stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsSyncPayload {
    /// DID of the reporting server.
    pub server_did: String,
    /// Monotonic sequence number (incremented on each sync). Used by the
    /// control plane to detect replayed or out-of-order payloads.
    pub seq: u64,
    /// Per-DID counter deltas since the last sync.
    pub did_deltas: Vec<DidStatsDelta>,
}

// ---------------------------------------------------------------------------
// High-level create result
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_list_entry_serializes_camel_case() {
        let entry = DidListEntry {
            mnemonic: "test".to_string(),
            owner: "did:example:owner".to_string(),
            created_at: 1000,
            updated_at: 2000,
            version_count: 1,
            did_id: Some("did:webvh:abc:host:path".to_string()),
            total_resolves: 42,
            disabled: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"createdAt\""));
        assert!(json.contains("\"updatedAt\""));
        assert!(json.contains("\"versionCount\""));
        assert!(json.contains("\"didId\""));
        assert!(json.contains("\"totalResolves\""));
        assert!(!json.contains("\"created_at\""));
        assert!(!json.contains("\"updated_at\""));
        assert!(!json.contains("\"version_count\""));
        assert!(!json.contains("\"did_id\""));
        assert!(!json.contains("\"total_resolves\""));
    }

    #[test]
    fn did_list_entry_did_id_none_serializes_as_null() {
        let entry = DidListEntry {
            mnemonic: "test".to_string(),
            owner: "did:example:owner".to_string(),
            created_at: 0,
            updated_at: 0,
            version_count: 0,
            did_id: None,
            total_resolves: 0,
            disabled: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"didId\":null"));
    }

    #[test]
    fn did_list_entry_roundtrip() {
        let entry = DidListEntry {
            mnemonic: "test".to_string(),
            owner: "did:example:owner".to_string(),
            created_at: 1000,
            updated_at: 2000,
            version_count: 3,
            did_id: Some("did:webvh:abc:host:path".to_string()),
            total_resolves: 99,
            disabled: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DidListEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mnemonic, "test");
        assert_eq!(back.version_count, 3);
        assert_eq!(back.did_id, Some("did:webvh:abc:host:path".to_string()));
        assert_eq!(back.total_resolves, 99);
    }

    #[test]
    fn did_stats_default_values() {
        let stats = DidStats::default();
        assert_eq!(stats.total_resolves, 0);
        assert_eq!(stats.total_updates, 0);
        assert_eq!(stats.last_resolved_at, None);
        assert_eq!(stats.last_updated_at, None);
    }

    #[test]
    fn did_stats_serializes_camel_case() {
        let stats = DidStats {
            total_resolves: 10,
            total_updates: 5,
            last_resolved_at: Some(1000),
            last_updated_at: Some(2000),
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"totalResolves\""));
        assert!(json.contains("\"totalUpdates\""));
        assert!(json.contains("\"lastResolvedAt\""));
        assert!(json.contains("\"lastUpdatedAt\""));
        assert!(!json.contains("\"total_resolves\""));
    }

    #[test]
    fn request_uri_response_camel_case() {
        let resp = RequestUriResponse {
            mnemonic: "test".to_string(),
            did_url: "http://example.com/test/did.jsonl".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"didUrl\""));
        assert!(!json.contains("\"did_url\""));
    }
}

// ---------------------------------------------------------------------------
// Witness types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessResponse {
    pub witness_id: String,
    pub did: String,
    pub label: Option<String>,
    pub created_at: u64,
    pub proofs_signed: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WitnessListResponse {
    pub witnesses: Vec<WitnessResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignProofRequest {
    pub version_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignProofResponse {
    pub version_id: String,
    pub proof: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWitnessRequest {
    pub label: Option<String>,
}

// ---------------------------------------------------------------------------
// Watcher sync types
// ---------------------------------------------------------------------------

/// Pushed from webvh-server to webvh-watcher when a DID is published.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDidRequest {
    pub mnemonic: String,
    pub did_id: Option<String>,
    pub log_content: String,
    pub witness_content: Option<String>,
    pub source_url: String,
    pub updated_at: u64,
    pub disabled: bool,
}

/// Pushed from webvh-server to webvh-watcher when a DID is deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDeleteRequest {
    pub mnemonic: String,
    pub source_url: String,
}

// ---------------------------------------------------------------------------
// High-level create result
// ---------------------------------------------------------------------------

/// Result of the high-level `create_did` operation.
#[derive(Debug)]
pub struct CreateDidResult {
    /// The mnemonic / path assigned to this DID on the server.
    pub mnemonic: String,
    /// The full public URL where the DID log is served.
    pub did_url: String,
    /// The self-certifying identifier derived from the log entry.
    pub scid: String,
    /// The final `did:webvh:...` identifier.
    pub did: String,
    /// The public key multibase of the signing key.
    pub public_key_multibase: String,
}

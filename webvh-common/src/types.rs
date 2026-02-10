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
    pub created_at: u64,
    pub updated_at: u64,
    pub version_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DidStats {
    pub total_resolves: u64,
    pub total_updates: u64,
    pub last_resolved_at: Option<u64>,
    pub last_updated_at: Option<u64>,
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

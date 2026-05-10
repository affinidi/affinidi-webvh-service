use std::fmt;

use serde::{Deserialize, Serialize};

use tracing::{debug, warn};

use super::error::AppError;
use super::store::KeyspaceHandle;

/// Roles that determine endpoint access permissions.
///
/// The role of a JWT-authenticated request gates which `*Auth`
/// extractor will accept it:
/// - `Admin` → `AdminAuth` (and `AuthClaims`).
/// - `Owner` → `AuthClaims` only; admin-only routes reject.
/// - `Service` → `ServiceAuth` (and `AuthClaims`); admin-only routes
///   reject.
///
/// `Service` is for backend service accounts that register with the
/// control plane and push sync data. As of v0.7 it is required by
/// `POST /api/control/register-service` (a service registering its
/// public URL) and `POST /api/control/stats` (a service pushing
/// stats deltas). A token minted for a `Service`-role DID will
/// neither be accepted by admin-only routes nor by the public DID-
/// management routes a tenant would use — service accounts are
/// deliberately scoped down.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Owner,
    /// Service accounts (e.g. webvh-server registering with the control plane).
    /// Can authenticate and use the service-only endpoints
    /// (`register-service`, `stats`); cannot access admin management
    /// endpoints or tenant DID-management routes.
    Service,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Owner => write!(f, "owner"),
            Role::Service => write!(f, "service"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "owner" => Ok(Role::Owner),
            "service" => Ok(Role::Service),
            _ => Err(AppError::Validation(format!("unknown role: {s}"))),
        }
    }
}

/// An entry in the Access Control List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub max_total_size: Option<u64>,
    #[serde(default)]
    pub max_did_count: Option<u64>,
}

// -- Shared API request/response types for ACL routes --

/// Request body for creating a new ACL entry (POST /acl).
#[derive(Debug, Deserialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    #[serde(default)]
    pub max_total_size: Option<u64>,
    #[serde(default)]
    pub max_did_count: Option<u64>,
}

/// Request body for updating an existing ACL entry (PUT /acl/{did}).
#[derive(Debug, Deserialize)]
pub struct UpdateAclRequest {
    pub role: Option<Role>,
    pub label: Option<String>,
    pub max_total_size: Option<u64>,
    pub max_did_count: Option<u64>,
}

/// Serializable ACL entry returned in API responses.
#[derive(Debug, Serialize)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: Role,
    pub label: Option<String>,
    pub created_at: u64,
    pub max_total_size: Option<u64>,
    pub max_did_count: Option<u64>,
}

impl From<AclEntry> for AclEntryResponse {
    fn from(e: AclEntry) -> Self {
        Self {
            did: e.did,
            role: e.role,
            label: e.label,
            created_at: e.created_at,
            max_total_size: e.max_total_size,
            max_did_count: e.max_did_count,
        }
    }
}

/// Response body for listing ACL entries (GET /acl).
#[derive(Debug, Serialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

impl AclEntry {
    /// Return the effective maximum total DID document size for this account.
    pub fn effective_max_total_size(&self, global_default: u64) -> u64 {
        self.max_total_size.unwrap_or(global_default)
    }

    /// Return the effective maximum DID count for this account.
    pub fn effective_max_did_count(&self, global_default: u64) -> u64 {
        self.max_did_count.unwrap_or(global_default)
    }
}

fn acl_key(did: &str) -> String {
    format!("acl:{did}")
}

/// Maximum DID-string length we accept anywhere a DID is written by a
/// caller — ACL entries, ownership transfers, etc. 2048 fits a
/// `did:peer:2.*` with multiple inline keys (typical 600–1500 bytes)
/// plus headroom; tighter bounds are enforced elsewhere where needed
/// (e.g. `check_acl`'s 512-byte cap on the hot auth path).
pub const MAX_DID_LEN: usize = 2048;

/// Validate a DID-string supplied by an admin/owner before it lands in
/// storage.
///
/// Trims surrounding whitespace and checks: not empty, does not exceed
/// `MAX_DID_LEN`, starts with `did:`, contains no ASCII control chars.
/// Returns the trimmed string on success so the caller stores the
/// canonical form (a typo-trailing-space DID would otherwise silently
/// mismatch all later `check_acl` lookups).
///
/// Used by ACL create/update routes and by the ownership-transfer path
/// in `did_ops::change_did_owner` to guarantee the same shape of DIDs
/// across all admin-facing write surfaces.
pub fn validate_did_format(did: &str) -> Result<String, AppError> {
    let trimmed = did.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation("DID must not be empty".into()));
    }
    if trimmed.len() > MAX_DID_LEN {
        return Err(AppError::Validation(format!(
            "DID exceeds maximum length of {MAX_DID_LEN} characters"
        )));
    }
    if !trimmed.starts_with("did:") {
        return Err(AppError::Validation(
            "DID must start with 'did:' scheme".into(),
        ));
    }
    if trimmed.chars().any(|c| c.is_ascii_control()) {
        return Err(AppError::Validation(
            "DID must not contain ASCII control characters".into(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Retrieve an ACL entry by DID.
pub async fn get_acl_entry(acl: &KeyspaceHandle, did: &str) -> Result<Option<AclEntry>, AppError> {
    acl.get(acl_key(did)).await
}

/// Store (create or overwrite) an ACL entry.
pub async fn store_acl_entry(acl: &KeyspaceHandle, entry: &AclEntry) -> Result<(), AppError> {
    acl.insert(acl_key(&entry.did), entry).await
}

/// Delete an ACL entry by DID.
pub async fn delete_acl_entry(acl: &KeyspaceHandle, did: &str) -> Result<(), AppError> {
    acl.remove(acl_key(did)).await
}

/// List all ACL entries.
pub async fn list_acl_entries(acl: &KeyspaceHandle) -> Result<Vec<AclEntry>, AppError> {
    let raw = acl.prefix_iter_raw("acl:").await?;
    raw.into_iter()
        .map(|(_, v)| serde_json::from_slice(&v).map_err(AppError::from))
        .collect()
}

/// Check whether a DID is in the ACL and return its role.
///
/// Returns `Forbidden` if the DID is not found.
pub async fn check_acl(acl: &KeyspaceHandle, did: &str) -> Result<Role, AppError> {
    if did.len() > 512 {
        return Err(AppError::Validation("DID exceeds maximum length".into()));
    }
    match get_acl_entry(acl, did).await? {
        Some(entry) => {
            debug!(did = %did, role = %entry.role, "ACL check passed");
            Ok(entry.role)
        }
        None => {
            warn!(did = %did, "ACL check denied: DID not in ACL");
            Err(AppError::Forbidden(format!("DID not in ACL: {did}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn make_entry(max_total_size: Option<u64>, max_did_count: Option<u64>) -> AclEntry {
        AclEntry {
            did: "did:example:test".into(),
            role: Role::Owner,
            label: None,
            created_at: 0,
            max_total_size,
            max_did_count,
        }
    }

    // --- Role parsing ---

    #[test]
    fn role_from_str_admin() {
        assert_eq!(Role::from_str("admin").unwrap(), Role::Admin);
    }

    #[test]
    fn role_from_str_owner() {
        assert_eq!(Role::from_str("owner").unwrap(), Role::Owner);
    }

    #[test]
    fn role_from_str_service() {
        assert_eq!(Role::from_str("service").unwrap(), Role::Service);
    }

    #[test]
    fn role_from_str_unknown_returns_error() {
        assert!(Role::from_str("superuser").is_err());
    }

    #[test]
    fn role_display() {
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Owner.to_string(), "owner");
        assert_eq!(Role::Service.to_string(), "service");
    }

    // --- effective_max_total_size ---

    #[test]
    fn effective_max_total_size_uses_override_when_set() {
        let entry = make_entry(Some(500_000), None);
        assert_eq!(entry.effective_max_total_size(1_000_000), 500_000);
    }

    #[test]
    fn effective_max_total_size_falls_back_to_global() {
        let entry = make_entry(None, None);
        assert_eq!(entry.effective_max_total_size(1_000_000), 1_000_000);
    }

    #[test]
    fn effective_max_total_size_override_zero_is_respected() {
        let entry = make_entry(Some(0), None);
        assert_eq!(entry.effective_max_total_size(1_000_000), 0);
    }

    // --- effective_max_did_count ---

    #[test]
    fn effective_max_did_count_uses_override_when_set() {
        let entry = make_entry(None, Some(5));
        assert_eq!(entry.effective_max_did_count(20), 5);
    }

    #[test]
    fn effective_max_did_count_falls_back_to_global() {
        let entry = make_entry(None, None);
        assert_eq!(entry.effective_max_did_count(20), 20);
    }

    #[test]
    fn effective_max_did_count_override_zero_is_respected() {
        let entry = make_entry(None, Some(0));
        assert_eq!(entry.effective_max_did_count(20), 0);
    }

    // --- serde backwards compatibility ---

    #[test]
    fn acl_entry_deserialize_without_limit_fields() {
        let json = r#"{"did":"did:example:old","role":"admin","label":null,"created_at":100}"#;
        let entry: AclEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.did, "did:example:old");
        assert_eq!(entry.role, Role::Admin);
        assert!(entry.max_total_size.is_none());
        assert!(entry.max_did_count.is_none());
    }

    #[test]
    fn acl_entry_deserialize_with_limit_fields() {
        let json = r#"{"did":"did:example:new","role":"owner","label":"test","created_at":200,"max_total_size":500000,"max_did_count":10}"#;
        let entry: AclEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.max_total_size, Some(500_000));
        assert_eq!(entry.max_did_count, Some(10));
    }

    #[test]
    fn acl_entry_roundtrip_serialization() {
        let entry = make_entry(Some(1_000_000), Some(50));
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AclEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_total_size, Some(1_000_000));
        assert_eq!(deserialized.max_did_count, Some(50));
    }

    // --- validate_did_format ---

    #[test]
    fn validate_did_format_accepts_canonical() {
        let did = "did:webvh:scid:host.example:tenant";
        assert_eq!(validate_did_format(did).unwrap(), did);
    }

    #[test]
    fn validate_did_format_trims_whitespace() {
        // The bug this prevents: an admin pastes `"  did:web:tenant  "`,
        // it lands as the storage key with whitespace, and every later
        // `check_acl("did:web:tenant")` returns Forbidden.
        let trimmed = validate_did_format("  did:web:tenant\n").unwrap();
        assert_eq!(trimmed, "did:web:tenant");
    }

    #[test]
    fn validate_did_format_rejects_empty() {
        assert!(validate_did_format("").is_err());
        assert!(validate_did_format("   ").is_err());
    }

    #[test]
    fn validate_did_format_rejects_missing_did_prefix() {
        let err = validate_did_format("example.com").unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn validate_did_format_rejects_oversized() {
        // MAX_DID_LEN bytes after "did:web:" prefix => well over the cap.
        let did = format!("did:web:{}", "a".repeat(MAX_DID_LEN));
        assert!(validate_did_format(&did).is_err());
    }

    #[test]
    fn validate_did_format_accepts_realistic_did_peer() {
        // A typical `did:peer:2.*` with two inline keys is ~700 bytes —
        // pin that the cap accommodates them. Synthetic but representative.
        let did = format!(
            "did:peer:2.Vz6Mk{}.Ez6LS{}",
            "x".repeat(300),
            "y".repeat(300)
        );
        assert!(did.len() < MAX_DID_LEN);
        assert!(validate_did_format(&did).is_ok());
    }

    #[test]
    fn validate_did_format_rejects_control_chars() {
        // Newline, tab, NUL, and BEL all rejected — protects against log-
        // injection in the warning lines that include the DID, and against
        // sneaky storage keys.
        for ch in ["\n", "\t", "\0", "\x07"] {
            let did = format!("did:web:tenant{ch}rest");
            assert!(
                validate_did_format(&did).is_err(),
                "control char {:?} should be rejected",
                ch
            );
        }
    }
}

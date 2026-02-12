use std::fmt;

use serde::{Deserialize, Serialize};

use tracing::{debug, warn};

use crate::error::AppError;
use crate::store::KeyspaceHandle;

/// Roles that determine endpoint access permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Owner,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Owner => write!(f, "owner"),
        }
    }
}

impl Role {
    /// Parse a role from its string representation.
    pub fn from_str(s: &str) -> Result<Self, AppError> {
        match s {
            "admin" => Ok(Role::Admin),
            "owner" => Ok(Role::Owner),
            _ => Err(AppError::Internal(format!("unknown role: {s}"))),
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

/// Retrieve an ACL entry by DID.
pub async fn get_acl_entry(
    acl: &KeyspaceHandle,
    did: &str,
) -> Result<Option<AclEntry>, AppError> {
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
    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let entry: AclEntry = serde_json::from_slice(&value)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Check whether a DID is in the ACL and return its role.
///
/// Returns `Forbidden` if the DID is not found.
pub async fn check_acl(acl: &KeyspaceHandle, did: &str) -> Result<Role, AppError> {
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
    fn role_from_str_unknown_returns_error() {
        assert!(Role::from_str("superuser").is_err());
    }

    #[test]
    fn role_display() {
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Owner.to_string(), "owner");
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
}

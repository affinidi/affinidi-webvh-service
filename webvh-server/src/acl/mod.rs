use std::fmt;

use serde::{Deserialize, Serialize};

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
        Some(entry) => Ok(entry.role),
        None => Err(AppError::Forbidden(format!("DID not in ACL: {did}"))),
    }
}

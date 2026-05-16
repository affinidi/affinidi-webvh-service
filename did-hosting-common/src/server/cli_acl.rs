use std::str::FromStr;

use super::acl::{
    AclEntry, Role, delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use super::auth::session::now_epoch;
use super::config::StoreConfig;
use super::store::Store;

/// Add an ACL entry to the store.
pub async fn run_add_acl(
    store_config: &StoreConfig,
    did: String,
    role_str: String,
    label: Option<String>,
    max_total_size: Option<u64>,
    max_did_count: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let role = Role::from_str(&role_str)
        .map_err(|_| format!("invalid role '{role_str}': use 'admin', 'owner', or 'service'"))?;

    let store = Store::open(store_config).await?;
    let acl_ks = store.keyspace("acl")?;

    if let Some(existing) = get_acl_entry(&acl_ks, &did).await? {
        eprintln!();
        eprintln!("  ACL entry already exists for this DID:");
        eprintln!("  DID:  {}", existing.did);
        eprintln!("  Role: {}", existing.role);
        eprintln!();
        return Err("ACL entry already exists — delete it first to change the role".into());
    }

    let entry = AclEntry {
        did: did.clone(),
        role: role.clone(),
        label,
        created_at: now_epoch(),
        max_total_size,
        max_did_count,
    };

    store_acl_entry(&acl_ks, &entry).await?;

    eprintln!();
    eprintln!("  ACL entry created!");
    eprintln!();
    eprintln!("  DID:  {did}");
    eprintln!("  Role: {role}");
    if let Some(size) = max_total_size {
        eprintln!("  Max total size: {size} bytes");
    }
    if let Some(count) = max_did_count {
        eprintln!("  Max DID count:  {count}");
    }
    eprintln!();

    Ok(())
}

/// List all ACL entries in the store.
pub async fn run_list_acl(store_config: &StoreConfig) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(store_config).await?;
    let acl_ks = store.keyspace("acl")?;

    let entries = list_acl_entries(&acl_ks).await?;

    if entries.is_empty() {
        eprintln!();
        eprintln!("  No ACL entries found.");
        eprintln!();
        return Ok(());
    }

    eprintln!();
    eprintln!(
        "  {:<50} {:<8} {:<15} {:<15} LABEL",
        "DID", "ROLE", "MAX SIZE", "MAX DIDS"
    );
    eprintln!("  {}", "-".repeat(100));

    for entry in &entries {
        let max_size = entry
            .max_total_size
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into());
        let max_dids = entry
            .max_did_count
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".into());
        let label = entry.label.as_deref().unwrap_or("-");
        eprintln!(
            "  {:<50} {:<8} {:<15} {:<15} {}",
            entry.did, entry.role, max_size, max_dids, label
        );
    }

    eprintln!();
    eprintln!("  {} entries total", entries.len());
    eprintln!();

    Ok(())
}

/// Remove an ACL entry from the store.
pub async fn run_remove_acl(
    store_config: &StoreConfig,
    did: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(store_config).await?;
    let acl_ks = store.keyspace("acl")?;

    let existing = get_acl_entry(&acl_ks, &did).await?;
    if existing.is_none() {
        eprintln!();
        eprintln!("  No ACL entry found for {did}");
        eprintln!();
        return Ok(());
    }

    let entry = existing.unwrap();
    delete_acl_entry(&acl_ks, &did).await?;
    store.persist().await?;

    eprintln!();
    eprintln!("  ACL entry removed!");
    eprintln!();
    eprintln!("  DID:  {}", entry.did);
    eprintln!("  Role: {}", entry.role);
    eprintln!();

    Ok(())
}

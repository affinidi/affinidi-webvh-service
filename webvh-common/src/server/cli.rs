//! Shared CLI command implementations for ACL and passkey management.
//!
//! Each function accepts primitive config types (`&StoreConfig`, `&str`, etc.)
//! so that binaries only need to load their config and forward the relevant fields.
//! This keeps CLI behavior consistent across standalone and daemon modes.

use super::acl::{
    AclEntry, Role, delete_acl_entry, get_acl_entry, list_acl_entries, store_acl_entry,
};
use super::auth::session::now_epoch;
use super::config::StoreConfig;
use super::store::Store;

/// Add an ACL entry to the store.
pub async fn add_acl(
    store_config: &StoreConfig,
    did: &str,
    role: &str,
    label: Option<&str>,
    max_total_size: Option<u64>,
    max_did_count: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let role = role
        .parse::<Role>()
        .map_err(|_| format!("invalid role '{role}': use 'admin', 'owner', or 'service'"))?;

    let store = Store::open(store_config).await?;
    let acl_ks = store.keyspace("acl")?;

    if let Some(existing) = get_acl_entry(&acl_ks, did).await? {
        eprintln!();
        eprintln!("  ACL entry already exists for this DID:");
        eprintln!("  DID:  {}", existing.did);
        eprintln!("  Role: {}", existing.role);
        eprintln!();
        return Err("ACL entry already exists — delete it first to change the role".into());
    }

    let entry = AclEntry {
        did: did.to_string(),
        role: role.clone(),
        label: label.map(|s| s.to_string()),
        created_at: now_epoch(),
        max_total_size,
        max_did_count,
    };

    store_acl_entry(&acl_ks, &entry).await?;
    store.persist().await?;

    eprintln!();
    eprintln!("  ACL entry created!");
    eprintln!();
    eprintln!("  DID:  {did}");
    eprintln!("  Role: {role}");
    eprintln!();

    Ok(())
}

/// List all ACL entries in the store.
pub async fn list_acl(store_config: &StoreConfig) -> Result<(), Box<dyn std::error::Error>> {
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
    eprintln!("  {:<50} {:<8} LABEL", "DID", "ROLE");
    eprintln!("  {}", "-".repeat(80));

    for entry in &entries {
        let label = entry.label.as_deref().unwrap_or("-");
        eprintln!("  {:<50} {:<8} {}", entry.did, entry.role, label);
    }

    eprintln!();
    eprintln!("  {} entries total", entries.len());
    eprintln!();

    Ok(())
}

/// Remove an ACL entry from the store.
pub async fn remove_acl(
    store_config: &StoreConfig,
    did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(store_config).await?;
    let acl_ks = store.keyspace("acl")?;

    let existing = get_acl_entry(&acl_ks, did).await?;
    if existing.is_none() {
        eprintln!();
        eprintln!("  No ACL entry found for {did}");
        eprintln!();
        return Ok(());
    }

    let entry = existing.unwrap();
    delete_acl_entry(&acl_ks, did).await?;
    store.persist().await?;

    eprintln!();
    eprintln!("  ACL entry removed!");
    eprintln!();
    eprintln!("  DID:  {}", entry.did);
    eprintln!("  Role: {}", entry.role);
    eprintln!();

    Ok(())
}

/// Create a passkey enrollment invite.
#[cfg(feature = "passkey")]
pub async fn invite(
    store_config: &StoreConfig,
    public_url: &str,
    enrollment_ttl: u64,
    did: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use super::passkey::routes::create_enrollment_invite;

    let store = Store::open(store_config).await?;
    let sessions_ks = store.keyspace("sessions")?;

    let resp =
        create_enrollment_invite(&sessions_ks, public_url, enrollment_ttl, did, role).await?;

    store.persist().await?;

    eprintln!();
    eprintln!("  Enrollment invite created!");
    eprintln!();
    eprintln!("  DID:     {did}");
    eprintln!("  Role:    {role}");
    let ttl_hours = enrollment_ttl / 3600;
    eprintln!("  Expires: in {ttl_hours}h (epoch {})", resp.expires_at);
    eprintln!();
    eprintln!("  Enrollment URL:");
    eprintln!("  {}", resp.enrollment_url);
    eprintln!();

    Ok(())
}

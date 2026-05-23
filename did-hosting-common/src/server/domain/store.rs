//! CRUD over the `domains` keyspace + default-domain pointer.
//!
//! Per `docs/multi-domain-spec.md` §3:
//!
//! - One `DomainEntry` per row in `KS_DOMAINS`, keyed by the
//!   normalised `name`.
//! - Default-domain pointer at `KS_META` → `default_domain` →
//!   `<name>`. Single-key value, not a `DomainEntry` copy. Lookups
//!   for "the default" round-trip through this pointer to the
//!   `DomainEntry` itself.
//! - Domain names are **immutable** after creation. `update_domain`
//!   accepts a `DomainEntry` and refuses to write if its `name`
//!   doesn't match the existing record's `name`.
//! - The default cannot point at a `Disabled` domain (per spec §3
//!   "Default domain | Reject pointing to disabled"). `set_default_domain`
//!   enforces; `disable_domain` refuses to disable the current default.

use serde::{Deserialize, Serialize};

use super::normalize::normalize_domain_name;
use super::types::{DomainEntry, DomainStatus};
use crate::server::error::AppError;
use crate::server::pending_purge;
use crate::server::store::{KS_DOMAINS, KS_META, KeyspaceHandle, Store};

/// `pending_purge::PendingPurge::reason` value used for soft-deleted
/// (disabled, awaiting purge) domains. Distinct from
/// [`crate::server::pending_purge`]'s `"grace-expired"` (unassignment)
/// so the background sweep knows to delete the entire `DomainEntry`
/// row in addition to the hosted DID records.
pub const DISABLE_PURGE_REASON: &str = "disable-grace";

/// Storage key for the default-domain pointer in the `meta` keyspace.
/// Co-located with the migration-runner's applied markers (also in
/// `meta`) — different prefix so they don't collide.
const META_DEFAULT_DOMAIN_KEY: &str = "default_domain";

/// Wrapper value type for the default-domain pointer. JSON wrapping a
/// single field is overkill but keeps the row schema consistent with
/// the rest of the `meta` keyspace and avoids accidental confusion
/// with a raw-string value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DefaultDomainPointer {
    /// Normalised name of the default domain.
    domain: String,
}

// ---------------------------------------------------------------------------
// Keyspace handles
// ---------------------------------------------------------------------------

/// Open the `domains` keyspace handle. Centralised here so the rest of
/// the module never sees `KS_DOMAINS` directly.
fn domains_ks(store: &Store) -> Result<KeyspaceHandle, AppError> {
    store.keyspace(KS_DOMAINS)
}

fn meta_ks(store: &Store) -> Result<KeyspaceHandle, AppError> {
    store.keyspace(KS_META)
}

// ---------------------------------------------------------------------------
// CRUD on `DomainEntry`
// ---------------------------------------------------------------------------

/// Insert a new domain. The `entry.name` is normalised before storage
/// (`Example.com` → 400, not silently `example.com`).
///
/// Errors:
/// - `Validation` if `entry.name` is not in canonical form (the error
///   message names the canonical form).
/// - `Conflict` if a domain with the same name already exists. Domain
///   names are immutable per spec §3 — the only path to "rename" is
///   add-new + offboard-old.
pub async fn create_domain(store: &Store, entry: &DomainEntry) -> Result<(), AppError> {
    let canonical = normalize_domain_name(&entry.name)?;
    if canonical != entry.name {
        // This branch is unreachable because `normalize_domain_name`
        // would have returned `Err` for non-canonical input — but
        // guarding here documents the invariant for future readers.
        return Err(AppError::Validation(format!(
            "domain name not in canonical form — use '{canonical}'"
        )));
    }
    let ks = domains_ks(store)?;
    if ks.contains_key(canonical.as_bytes().to_vec()).await? {
        return Err(AppError::Conflict(format!(
            "domain '{canonical}' already exists"
        )));
    }
    ks.insert(canonical.as_bytes().to_vec(), entry).await?;
    Ok(())
}

/// Fetch one `DomainEntry` by name. `name` is normalised before lookup.
pub async fn get_domain(store: &Store, name: &str) -> Result<Option<DomainEntry>, AppError> {
    let canonical = normalize_domain_name(name)?;
    let ks = domains_ks(store)?;
    ks.get::<DomainEntry>(canonical.as_bytes().to_vec()).await
}

/// List every `DomainEntry` in the keyspace. Unordered — the keyspace
/// iter doesn't promise order across backends. Callers that need
/// stable ordering (the UI's Domains view) sort by `name`
/// downstream.
pub async fn list_domains(store: &Store) -> Result<Vec<DomainEntry>, AppError> {
    let ks = domains_ks(store)?;
    let raw = ks.iter_all().await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_, value) in raw {
        let entry: DomainEntry = serde_json::from_slice(&value)?;
        out.push(entry);
    }
    Ok(out)
}

/// Replace the stored entry for `name` with `new_entry`. The name
/// portion is **not** updateable — `new_entry.name` must match `name`
/// exactly. Use add-new + offboard-old to "rename".
///
/// Errors:
/// - `Validation` if `name` is not canonical, or if `new_entry.name`
///   differs from `name`.
/// - `NotFound` if no domain with that name exists.
pub async fn update_domain(
    store: &Store,
    name: &str,
    new_entry: &DomainEntry,
) -> Result<(), AppError> {
    let canonical = normalize_domain_name(name)?;
    if new_entry.name != canonical {
        return Err(AppError::Validation(format!(
            "cannot rename domain ('{}' → '{}') — domain names are immutable",
            canonical, new_entry.name
        )));
    }
    let ks = domains_ks(store)?;
    if !ks.contains_key(canonical.as_bytes().to_vec()).await? {
        return Err(AppError::NotFound(format!("domain '{canonical}'")));
    }
    ks.insert(canonical.as_bytes().to_vec(), new_entry).await?;
    Ok(())
}

/// Disable a domain (soft-delete). Refuses if the domain is currently
/// the default (per spec §3 "Default domain must be active" — re-point
/// default first, then disable).
///
/// Sets `disabled_at = now` and `purge_at = now + grace_seconds`, then
/// schedules a `pending_purge` row with reason
/// [`DISABLE_PURGE_REASON`]. The background sweep
/// (`did-hosting-server::purge_sweep`) sees the row, waits out the
/// grace window, then permanently removes the domain record + all
/// hosted DIDs. Re-enabling cancels.
pub async fn disable_domain(
    store: &Store,
    name: &str,
    now_epoch: u64,
    grace_seconds: u64,
    scheduled_by: &str,
) -> Result<(), AppError> {
    let canonical = normalize_domain_name(name)?;
    if let Some(current_default) = get_default_domain(store).await?
        && current_default == canonical
    {
        return Err(AppError::Conflict(format!(
            "cannot disable '{canonical}' — it is the current default; re-point default first"
        )));
    }
    let mut entry = get_domain(store, &canonical)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("domain '{canonical}'")))?;
    entry.status = DomainStatus::Disabled;
    entry.disabled_at = Some(now_epoch);
    entry.purge_at = Some(now_epoch.saturating_add(grace_seconds));
    let ks = domains_ks(store)?;
    ks.insert(canonical.as_bytes().to_vec(), &entry).await?;

    pending_purge::schedule(
        store,
        &canonical,
        now_epoch,
        grace_seconds,
        DISABLE_PURGE_REASON,
        scheduled_by,
    )
    .await?;
    Ok(())
}

/// Enable a previously-disabled domain. Cancels the pending purge if
/// one was scheduled (the common case — `disable_domain` always
/// schedules; missing pending row is a quiet no-op for old records
/// disabled before this feature shipped).
pub async fn enable_domain(store: &Store, name: &str) -> Result<(), AppError> {
    let canonical = normalize_domain_name(name)?;
    let mut entry = get_domain(store, &canonical)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("domain '{canonical}'")))?;
    entry.status = DomainStatus::Active;
    entry.disabled_at = None;
    entry.purge_at = None;
    let ks = domains_ks(store)?;
    ks.insert(canonical.as_bytes().to_vec(), &entry).await?;

    // Best-effort cancel. A `Missing` outcome is fine — it means this
    // domain was disabled before the soft-delete feature shipped and
    // never had a pending row, or the sweep already cleared it (the
    // sweep would only do that AFTER deleting the domain record, in
    // which case `get_domain` above would have returned NotFound).
    let _ = pending_purge::cancel(store, &canonical).await?;
    Ok(())
}

/// Hard-delete a domain record. Does **not** purge DIDs hosted under
/// the domain — that's the `domain.purge` admin Trust Task in T30.
/// Refuses if the domain is the current default.
pub async fn delete_domain_record(store: &Store, name: &str) -> Result<(), AppError> {
    let canonical = normalize_domain_name(name)?;
    if let Some(current_default) = get_default_domain(store).await?
        && current_default == canonical
    {
        return Err(AppError::Conflict(format!(
            "cannot delete '{canonical}' — it is the current default; re-point default first"
        )));
    }
    let ks = domains_ks(store)?;
    if !ks.contains_key(canonical.as_bytes().to_vec()).await? {
        return Err(AppError::NotFound(format!("domain '{canonical}'")));
    }
    ks.remove(canonical.as_bytes().to_vec()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Default-domain pointer
// ---------------------------------------------------------------------------

/// Read the current default-domain pointer. Returns `None` if no
/// default has been set yet (fresh install before the setup wizard /
/// bootstrap-domains finish).
pub async fn get_default_domain(store: &Store) -> Result<Option<String>, AppError> {
    let ks = meta_ks(store)?;
    let pointer: Option<DefaultDomainPointer> =
        ks.get(META_DEFAULT_DOMAIN_KEY.as_bytes().to_vec()).await?;
    Ok(pointer.map(|p| p.domain))
}

/// Set the default-domain pointer to `name`.
///
/// Errors:
/// - `Validation` if `name` isn't canonical.
/// - `NotFound` if no domain with that name exists.
/// - `Conflict` if the target domain is `Disabled` (per spec §3
///   "Default domain ... must point to an active domain").
pub async fn set_default_domain(store: &Store, name: &str) -> Result<(), AppError> {
    let canonical = normalize_domain_name(name)?;
    let entry = get_domain(store, &canonical)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("domain '{canonical}'")))?;
    if !entry.status.is_active() {
        return Err(AppError::Conflict(format!(
            "cannot set default to '{canonical}' — domain is disabled"
        )));
    }
    let ks = meta_ks(store)?;
    let pointer = DefaultDomainPointer {
        domain: canonical.clone(),
    };
    ks.insert(META_DEFAULT_DOMAIN_KEY.as_bytes().to_vec(), &pointer)
        .await?;

    // Refresh the `default_domain` boolean on every entry: set it on
    // the new default, clear it everywhere else. The pointer in
    // `meta` is the truth; this denormalised flag is what we serve
    // in API responses, so keep them in sync.
    let domains_ks = domains_ks(store)?;
    let all = list_domains(store).await?;
    for mut e in all {
        let is_default = e.name == canonical;
        if e.default_domain != is_default {
            e.default_domain = is_default;
            domains_ks.insert(e.name.as_bytes().to_vec(), &e).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::StoreConfig;
    use crate::server::domain::types::{DomainStatus, DomainUrlScheme};

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            redis_url: None,
            dynamodb_table_prefix: None,
            dynamodb_region: None,
            firestore_project: None,
            firestore_database: None,
            cosmosdb_connection_string: None,
            cosmosdb_database: None,
            cosmosdb_region: None,
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }

    fn entry(name: &str) -> DomainEntry {
        DomainEntry {
            name: name.into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status: DomainStatus::Active,
            created_at: 1_700_000_000,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        }
    }

    #[tokio::test]
    async fn create_then_get_round_trips() {
        let store = fjall_store().await;
        create_domain(&store, &entry("example.com")).await.unwrap();
        let got = get_domain(&store, "example.com")
            .await
            .unwrap()
            .expect("must exist");
        assert_eq!(got.name, "example.com");
        assert_eq!(got.status, DomainStatus::Active);
    }

    #[tokio::test]
    async fn create_rejects_duplicate() {
        let store = fjall_store().await;
        create_domain(&store, &entry("example.com")).await.unwrap();
        let err = create_domain(&store, &entry("example.com"))
            .await
            .expect_err("duplicate must reject");
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn create_rejects_non_canonical_name() {
        let store = fjall_store().await;
        let mut e = entry("Example.com");
        // The non-canonical name is in the entry — normalise rejects.
        e.name = "Example.com".into();
        let err = create_domain(&store, &e)
            .await
            .expect_err("non-canonical must reject");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn list_returns_all_entries() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        create_domain(&store, &entry("b.example")).await.unwrap();
        let mut names: Vec<String> = list_domains(&store)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.example", "b.example"]);
    }

    #[tokio::test]
    async fn update_refuses_rename() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        let mut renamed = entry("a.example");
        renamed.name = "b.example".into(); // pretend rename
        let err = update_domain(&store, "a.example", &renamed)
            .await
            .expect_err("rename must reject");
        assert!(matches!(err, AppError::Validation(_)));
        assert!(err.to_string().contains("immutable"));
    }

    #[tokio::test]
    async fn update_changes_metadata_in_place() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        let mut e = entry("a.example");
        e.label = Some("Tenant A".into());
        update_domain(&store, "a.example", &e).await.unwrap();
        let got = get_domain(&store, "a.example").await.unwrap().unwrap();
        assert_eq!(got.label.as_deref(), Some("Tenant A"));
    }

    #[tokio::test]
    async fn update_rejects_missing_domain() {
        let store = fjall_store().await;
        let err = update_domain(&store, "nope.example", &entry("nope.example"))
            .await
            .expect_err("missing must reject");
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn disable_and_re_enable_cycle() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        disable_domain(&store, "a.example", 1_000, 60, "did:example:admin")
            .await
            .unwrap();
        let after_disable = get_domain(&store, "a.example").await.unwrap().unwrap();
        assert_eq!(after_disable.status, DomainStatus::Disabled);
        assert_eq!(after_disable.disabled_at, Some(1_000));
        assert_eq!(after_disable.purge_at, Some(1_060));
        let pending = pending_purge::get(&store, "a.example")
            .await
            .unwrap()
            .expect("disable schedules a pending purge");
        assert_eq!(pending.reason, DISABLE_PURGE_REASON);
        assert_eq!(pending.scheduled_at, 1_000);
        assert_eq!(pending.grace_seconds, 60);

        enable_domain(&store, "a.example").await.unwrap();
        let after_enable = get_domain(&store, "a.example").await.unwrap().unwrap();
        assert_eq!(after_enable.status, DomainStatus::Active);
        assert_eq!(after_enable.disabled_at, None);
        assert_eq!(after_enable.purge_at, None);
        // Pending purge cancelled.
        assert!(
            pending_purge::get(&store, "a.example")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn cannot_disable_current_default() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        set_default_domain(&store, "a.example").await.unwrap();
        let err = disable_domain(&store, "a.example", 1, 60, "did:example:admin")
            .await
            .expect_err("disabling default must reject");
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn cannot_delete_current_default() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        set_default_domain(&store, "a.example").await.unwrap();
        let err = delete_domain_record(&store, "a.example")
            .await
            .expect_err("deleting default must reject");
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn delete_removes_record() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        create_domain(&store, &entry("b.example")).await.unwrap();
        set_default_domain(&store, "b.example").await.unwrap();
        delete_domain_record(&store, "a.example").await.unwrap();
        assert!(get_domain(&store, "a.example").await.unwrap().is_none());
        assert!(get_domain(&store, "b.example").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn set_default_rejects_unknown_domain() {
        let store = fjall_store().await;
        let err = set_default_domain(&store, "nope.example")
            .await
            .expect_err("unknown must reject");
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn set_default_rejects_disabled_target() {
        let store = fjall_store().await;
        // Create a domain, disable it, then try to set default → 400.
        // We can't disable through `disable_domain` because there's no
        // current default to gate against. Disable via direct insert
        // of a Disabled entry.
        let mut e = entry("a.example");
        e.status = DomainStatus::Disabled;
        create_domain(&store, &e).await.unwrap();
        let err = set_default_domain(&store, "a.example")
            .await
            .expect_err("disabled target must reject");
        assert!(matches!(err, AppError::Conflict(_)));
        assert!(err.to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn set_default_pointer_round_trips() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        set_default_domain(&store, "a.example").await.unwrap();
        assert_eq!(
            get_default_domain(&store).await.unwrap(),
            Some("a.example".to_string())
        );
    }

    #[tokio::test]
    async fn set_default_updates_default_domain_flag_on_entries() {
        let store = fjall_store().await;
        create_domain(&store, &entry("a.example")).await.unwrap();
        create_domain(&store, &entry("b.example")).await.unwrap();
        set_default_domain(&store, "a.example").await.unwrap();
        let a = get_domain(&store, "a.example").await.unwrap().unwrap();
        let b = get_domain(&store, "b.example").await.unwrap().unwrap();
        assert!(a.default_domain);
        assert!(!b.default_domain);

        // Re-pointing clears the old + sets the new in the same call.
        set_default_domain(&store, "b.example").await.unwrap();
        let a2 = get_domain(&store, "a.example").await.unwrap().unwrap();
        let b2 = get_domain(&store, "b.example").await.unwrap().unwrap();
        assert!(!a2.default_domain);
        assert!(b2.default_domain);
    }
}

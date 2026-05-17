//! Server-local domain assignment cache (T28 + T29 staging).
//!
//! Each running server keeps a local record of which domains it is
//! currently authoritative for. The list is populated by inbound
//! `MSG_DOMAIN_ASSIGN` / `MSG_DOMAIN_UNASSIGN` Trust Tasks from the
//! control plane (T28) and read on cold start before the control
//! plane is reachable (T29's fallback chain).
//!
//! ## Storage shape
//!
//! - **Key**: `assignments:<domain>` — one entry per assigned domain.
//!   The keyspace const `KS_ASSIGNMENTS` carries the prefix; per-
//!   record keys are built via [`assignment_key`].
//! - **Value**: [`AssignmentEntry`] — JSON-serialised.
//!
//! ## Idempotency semantics
//!
//! - **assign(d)** when `d` already present → returns `Existing`. No
//!   timestamp / assigner mutation; the original `assigned_at` is
//!   preserved so audit-log traces stay stable.
//! - **assign(d)** when `d` absent → returns `Created` and writes the
//!   entry.
//! - **unassign(d)** when `d` present → returns `Removed`.
//! - **unassign(d)** when `d` absent → returns `Missing`. No-op for
//!   the storage layer (the caller decides whether to audit-log the
//!   noise).

use serde::{Deserialize, Serialize};

use super::error::AppError;
use super::store::{KS_ASSIGNMENTS, Store};

/// One row in the per-server assignment cache.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssignmentEntry {
    /// Normalised domain name (lowercase, IDNA-encoded). Matches the
    /// [`super::domain::DomainEntry::name`] form so cross-key joins
    /// work without re-normalisation.
    pub domain: String,
    /// Epoch second of the first successful assignment. Preserved
    /// across re-assigns for audit-log stability.
    pub assigned_at: u64,
    /// The control-plane DID that issued the assignment. Stored so an
    /// operator can answer "which control plane told me to host this?"
    /// during multi-control-plane migrations.
    pub assigner: String,
}

/// Build the storage key for `domain`. The keyspace const is
/// `KS_ASSIGNMENTS = "assignments"`; per-record keys are
/// `assignments:<domain>`.
fn assignment_key(domain: &str) -> String {
    format!("assignments:{domain}")
}

/// Outcome of an idempotent [`assign`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum AssignOutcome {
    /// Entry was created — caller should audit-log the event.
    Created(AssignmentEntry),
    /// Entry already existed — caller should suppress duplicate audit
    /// noise. The existing entry is returned for inspection.
    Existing(AssignmentEntry),
}

/// Outcome of an idempotent [`unassign`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum UnassignOutcome {
    /// Entry was present and has been removed.
    Removed(AssignmentEntry),
    /// Entry was already absent — no-op. Caller suppresses audit noise.
    Missing,
}

/// Assign `domain` to this server. Idempotent — re-assigning a known
/// domain returns [`AssignOutcome::Existing`] without mutating the
/// stored row.
pub async fn assign(
    store: &Store,
    domain: &str,
    assigner: &str,
    now_epoch: u64,
) -> Result<AssignOutcome, AppError> {
    let ks = store.keyspace(KS_ASSIGNMENTS)?;
    let key = assignment_key(domain);

    if let Some(existing) = ks.get::<AssignmentEntry>(key.clone()).await? {
        return Ok(AssignOutcome::Existing(existing));
    }

    let entry = AssignmentEntry {
        domain: domain.to_string(),
        assigned_at: now_epoch,
        assigner: assigner.to_string(),
    };
    ks.insert(key, &entry).await?;
    Ok(AssignOutcome::Created(entry))
}

/// Unassign `domain` from this server. Idempotent.
pub async fn unassign(store: &Store, domain: &str) -> Result<UnassignOutcome, AppError> {
    let ks = store.keyspace(KS_ASSIGNMENTS)?;
    let key = assignment_key(domain);

    let Some(existing) = ks.get::<AssignmentEntry>(key.clone()).await? else {
        return Ok(UnassignOutcome::Missing);
    };
    ks.remove(key).await?;
    Ok(UnassignOutcome::Removed(existing))
}

/// Look up a single assignment by domain.
pub async fn get(store: &Store, domain: &str) -> Result<Option<AssignmentEntry>, AppError> {
    let ks = store.keyspace(KS_ASSIGNMENTS)?;
    ks.get(assignment_key(domain)).await
}

/// List every assignment held by this server. Read on cold-start by
/// T29's fallback chain.
pub async fn list(store: &Store) -> Result<Vec<AssignmentEntry>, AppError> {
    let ks = store.keyspace(KS_ASSIGNMENTS)?;
    let raw = ks.prefix_iter_raw(b"assignments:".to_vec()).await?;
    let mut out = Vec::with_capacity(raw.len());
    for (_k, v) in raw {
        if let Ok(entry) = serde_json::from_slice::<AssignmentEntry>(&v) {
            out.push(entry);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::config::StoreConfig;

    async fn fjall_store() -> Store {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        std::mem::forget(dir);
        Store::open(&cfg).await.expect("open fjall")
    }

    #[tokio::test]
    async fn assign_creates_then_idempotent() {
        let store = fjall_store().await;
        let first = assign(&store, "example.com", "did:example:control", 100)
            .await
            .unwrap();
        assert!(matches!(first, AssignOutcome::Created(_)));

        // Same call again — Existing, same assigned_at (no clobber).
        let second = assign(&store, "example.com", "did:example:control", 200)
            .await
            .unwrap();
        let AssignOutcome::Existing(entry) = second else {
            panic!("expected Existing on re-assign, got {second:?}");
        };
        assert_eq!(
            entry.assigned_at, 100,
            "re-assign must preserve original timestamp"
        );
        assert_eq!(entry.assigner, "did:example:control");
    }

    #[tokio::test]
    async fn unassign_round_trip() {
        let store = fjall_store().await;
        // Unassign missing is a no-op.
        let missing = unassign(&store, "example.com").await.unwrap();
        assert!(matches!(missing, UnassignOutcome::Missing));

        // Assign then unassign.
        assign(&store, "example.com", "did:example:control", 1)
            .await
            .unwrap();
        let removed = unassign(&store, "example.com").await.unwrap();
        let UnassignOutcome::Removed(entry) = removed else {
            panic!("expected Removed, got {removed:?}");
        };
        assert_eq!(entry.domain, "example.com");

        // Second unassign is Missing again.
        let missing2 = unassign(&store, "example.com").await.unwrap();
        assert!(matches!(missing2, UnassignOutcome::Missing));
    }

    #[tokio::test]
    async fn list_returns_every_assigned_domain() {
        let store = fjall_store().await;
        assign(&store, "a.example", "did:c", 1).await.unwrap();
        assign(&store, "b.example", "did:c", 1).await.unwrap();
        assign(&store, "c.example", "did:c", 1).await.unwrap();
        let all = list(&store).await.unwrap();
        let mut names: Vec<String> = all.into_iter().map(|e| e.domain).collect();
        names.sort();
        assert_eq!(names, vec!["a.example", "b.example", "c.example"]);
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown() {
        let store = fjall_store().await;
        assert!(get(&store, "unknown.example").await.unwrap().is_none());
    }
}

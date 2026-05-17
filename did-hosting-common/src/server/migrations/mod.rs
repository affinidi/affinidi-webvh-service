//! Idempotent migration runner for on-disk store-shape changes.
//!
//! Why this exists: the multi-domain + multi-method rollout (see
//! `docs/multi-domain-spec.md` §6.5 and `docs/multi-method-hosting-spec.md`
//! §10) introduces breaking shape changes on first boot at the new version.
//! Existing webvh deployments need their DID records and ACL entries
//! migrated in place, exactly once, in a known order. A purpose-built
//! runner is required because (a) the workspace has no existing migration
//! framework, and (b) we need each migration to be both **idempotent**
//! (safe to re-run on a partially migrated store) and **monotonic** in a
//! defined order (multi-domain `M-02` writes the `domain` field that
//! multi-method `M-01` depends on).
//!
//! ## Contract
//!
//! Each migration implements the [`Migration`] trait — a stable id and an
//! async `run`. The runner tracks applied ids in the `meta` keyspace under
//! `migration:applied:{id}`; a migration whose marker is already present
//! is skipped. A migration that errors does **not** get marked, so the
//! next boot re-runs it from the top.
//!
//! ## Ordering
//!
//! The runner walks migrations in the order they were registered. Callers
//! are expected to register in dependency order. There is no DAG; if a
//! migration B depends on A having committed its writes, register A first.
//!
//! ## What this module ships
//!
//! This is the **skeleton** (T2): the trait, the runner, the per-id
//! marker logic, an empty-set test, and a fail-fast test. The first
//! actual migrations (`M-01` legacy `did_log` → `DidRecord` wrap, `M-02`
//! domain tagging) land in subsequent tasks and register here.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::error::AppError;
use super::store::{KS_META, KeyspaceHandle, Store};

pub mod m01_tag_did_records_with_domain;
pub mod runner;

pub use m01_tag_did_records_with_domain::M01TagDidRecordsWithDomain;
pub use runner::{MigrationRunner, RunSummary};

/// Boxed future used by [`Migration::run`] so the trait stays object-safe
/// without pulling in `async-trait`. Matches the pattern used by the
/// storage backends in `super::store`.
pub type MigrationFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>>;

/// Key prefix inside the `meta` keyspace for applied-migration markers.
const APPLIED_KEY_PREFIX: &str = "migration:applied:";

/// One on-disk shape change.
///
/// Implementations are expected to be:
/// - **Idempotent.** Re-running the same migration on a fully migrated
///   store must be a no-op (or a near-no-op walk that finds nothing to
///   change). The runner skips via the applied-marker; idempotency
///   inside `run` protects against partial-application reruns.
/// - **Deterministic on success.** No reliance on wall clock, hostname,
///   or random state that would make two replicas drift if both run the
///   migration concurrently.
/// - **Crash-safe.** A crash mid-migration leaves the store in a
///   re-runnable state. Use [`Store::batch`] to commit groups of
///   related writes atomically.
pub trait Migration: Send + Sync {
    /// A stable identifier — appears in the `meta` keyspace's applied
    /// marker and in logs. Recommended format: `m{NN}_{snake_case_name}`
    /// (e.g. `m01_wrap_did_record`). Never rename after a migration has
    /// shipped — operators' stores carry markers under the old id.
    fn id(&self) -> &'static str;

    /// A one-line human-readable description for logs and the "applied"
    /// audit-log entry. Not load-bearing for correctness.
    fn description(&self) -> &'static str {
        ""
    }

    /// Apply the shape change. Called once, then the marker is written.
    /// Returns `Err` to abort the whole run — the marker is NOT written
    /// on error; the next boot retries from the top.
    fn run<'a>(&'a self, store: &'a Store) -> MigrationFuture<'a>;
}

/// Persisted marker written under `meta:migration:applied:{id}` after a
/// migration completes. The `applied_at` timestamp is informational; the
/// presence of the marker is what gates re-runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppliedMarker {
    /// Unix seconds at which the migration completed.
    pub applied_at: u64,
    /// Description carried over from the migration at the time it ran.
    /// Preserved so future operators can see what the migration did
    /// even if the source has since been deleted from the workspace.
    #[serde(default)]
    pub description: String,
}

impl AppliedMarker {
    pub(crate) fn now(description: String) -> Self {
        let applied_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            applied_at,
            description,
        }
    }
}

pub(crate) fn applied_key(id: &str) -> String {
    format!("{APPLIED_KEY_PREFIX}{id}")
}

/// Helper: open the `meta` keyspace. The keyspace name will move to the
/// centralised registry in T3; until then it lives next to its only
/// consumer.
pub(crate) fn meta_keyspace(store: &Store) -> Result<KeyspaceHandle, AppError> {
    store.keyspace(KS_META)
}

/// Convenience: register migrations as an ordered list. Lives here so the
/// per-binary boot path can hand the runner a slice without juggling
/// `Arc`s. The runner itself only reads in order.
pub fn registry() -> Vec<Arc<dyn Migration>> {
    // Migrations run in registration order. New migrations append at
    // the bottom; never reorder past a shipped release (operators'
    // stores carry `meta:migration:applied:{id}` markers that gate
    // re-runs by ID, not order).
    vec![Arc::new(M01TagDidRecordsWithDomain)]
}

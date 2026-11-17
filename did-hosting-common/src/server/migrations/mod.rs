//! Idempotent migration runner for on-disk store-shape changes.
//!
//! Why this exists: the multi-domain + multi-method rollout (see
//! `docs/archive/multi-domain-spec.md` §6.5 and `docs/archive/multi-method-hosting-spec.md`
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
//! is skipped. A migration that errors, or that reports
//! [`MigrationOutcome::Deferred`] records, does **not** get marked, so the
//! next runner invocation re-runs it from the top.
//!
//! ## Ordering
//!
//! The runner walks migrations in the order they were registered. Callers
//! are expected to register in dependency order. There is no DAG; if a
//! migration B depends on A having committed its writes, register A first.
//!
//! ## What this module ships
//!
//! The trait, the runner and the per-id marker logic, plus the migrations
//! themselves: [`m01_tag_did_records_with_domain`] (fill
//! `DidRecord.domain`), [`m02_cache_did_record_services`] (fill
//! `DidRecord.services`) and [`m03_index_did_records`] (build the usage
//! counters and slot index).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::error::AppError;
use super::store::{KS_META, KeyspaceHandle, Store};

pub mod m01_tag_did_records_with_domain;
pub mod m02_cache_did_record_services;
pub mod m03_index_did_records;
pub mod runner;

pub use m01_tag_did_records_with_domain::M01TagDidRecordsWithDomain;
pub use m02_cache_did_record_services::M02CacheDidRecordServices;
pub use m03_index_did_records::M03IndexDidRecords;
pub use runner::{MigrationRunner, RunSummary};

/// Boxed future used by [`Migration::run`] so the trait stays object-safe
/// without pulling in `async-trait`. Matches the pattern used by the
/// storage backends in `super::store`.
pub type MigrationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<MigrationOutcome, AppError>> + Send + 'a>>;

/// How a migration's run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// Every record it is responsible for is migrated: the runner writes the
    /// applied marker, and the migration never runs again.
    Complete,
    /// It finished its walk but left this many records for a later run
    /// (they lacked something the migration needs, such as a default
    /// domain, or lost a race with a concurrent writer). No marker is
    /// written, so the next runner invocation retries them.
    Deferred(u64),
}

impl MigrationOutcome {
    /// [`Self::Complete`] when nothing was deferred.
    pub fn from_deferred(deferred: u64) -> Self {
        if deferred == 0 {
            Self::Complete
        } else {
            Self::Deferred(deferred)
        }
    }
}

/// Records a page of a migration's walk over the `dids` keyspace reads, so a
/// migration holds one page, never the whole store.
pub(crate) const MIGRATION_PAGE_ROWS: usize = 256;

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

    /// Apply the shape change. The marker is written only when it returns
    /// [`MigrationOutcome::Complete`]; a [`MigrationOutcome::Deferred`] run
    /// is retried by the next runner invocation. Returns `Err` to abort the
    /// whole run — the marker is NOT written on error; the next boot retries
    /// from the top.
    fn run<'a>(&'a self, store: &'a Store) -> MigrationFuture<'a>;
}

/// Records read per page of a migration's walk over `did:` records.
pub(crate) const DID_PAGE: usize = 500;

/// A paged walk over every `did:{mnemonic}` record in a keyspace, so a
/// migration never holds the whole keyspace in memory. Falls back to one
/// whole-prefix read on a backend that cannot page.
pub(crate) struct DidRecordPages<'a> {
    ks: &'a KeyspaceHandle,
    cursor: Option<Vec<u8>>,
    done: bool,
}

impl<'a> DidRecordPages<'a> {
    pub(crate) fn new(ks: &'a KeyspaceHandle) -> Self {
        Self {
            ks,
            cursor: None,
            done: false,
        }
    }

    /// The next page of `(mnemonic, raw record)` pairs, or `None` when the
    /// walk is complete. Keys that are not UTF-8 are skipped with a warning.
    pub(crate) async fn next_page(
        &mut self,
        migration_id: &str,
    ) -> Result<Option<Vec<(String, Vec<u8>)>>, AppError> {
        if self.done {
            return Ok(None);
        }
        let rows = match self
            .ks
            .prefix_page_raw(b"did:".to_vec(), self.cursor.take(), DID_PAGE)
            .await?
        {
            Some(page) => {
                self.cursor = page.next;
                self.done = self.cursor.is_none();
                page.rows
            }
            None => {
                self.done = true;
                self.ks.prefix_iter_raw(b"did:".to_vec()).await?
            }
        };
        Ok(Some(
            rows.into_iter()
                .filter_map(|(key, value)| match String::from_utf8(key) {
                    Ok(k) => Some((k.strip_prefix("did:").unwrap_or(&k).to_string(), value)),
                    Err(_) => {
                        tracing::warn!(migration_id, "skipping non-UTF-8 key in dids keyspace");
                        None
                    }
                })
                .collect(),
        ))
    }
}

/// What [`patch_did_record_field`] did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Patched<T> {
    /// The field was written; `T` is what `decide` reported.
    Written(T),
    /// The fresh record needs nothing (or is unreadable, or gone).
    Unneeded,
    /// Concurrent writers kept changing the record; left for a later run.
    Contended,
}

/// Write one field of `did:{mnemonic}`, decided on a fresh read.
///
/// The record is re-read through `consistent` (a
/// [`Store::keyspace_consistent`] handle) immediately before the write, so a
/// migration's decision is never made on a snapshot a concurrent publish has
/// since replaced. `decide` sees the fresh record and returns the field's new
/// JSON value (or `None`: nothing to do). Only that one field is changed in
/// the stored JSON — every other field, including any this binary does not
/// model, is written back as it was read — and the write is a
/// compare-and-swap against the bytes read, so a write that landed in
/// between is never overwritten: the read and decision are retried instead.
///
/// The migration context has no path locks to take (they belong to a running
/// control plane, and would not cover another replica anyway); the
/// compare-and-swap is what makes the write safe on a store shared during a
/// rolling upgrade.
pub(crate) async fn patch_did_record_field<T>(
    consistent: &KeyspaceHandle,
    mnemonic: &str,
    field: &str,
    decide: impl Fn(&crate::did_ops::DidRecord) -> Option<(serde_json::Value, T)>,
) -> Result<Patched<T>, AppError> {
    const ATTEMPTS: usize = 5;
    let key = crate::did_ops::did_key(mnemonic);
    for _ in 0..ATTEMPTS {
        let Some(raw) = consistent.get_raw(key.clone()).await? else {
            return Ok(Patched::Unneeded);
        };
        let Ok(record) = serde_json::from_slice::<crate::did_ops::DidRecord>(&raw) else {
            return Ok(Patched::Unneeded);
        };
        let Some((value, report)) = decide(&record) else {
            return Ok(Patched::Unneeded);
        };
        let mut object: serde_json::Value = serde_json::from_slice(&raw)?;
        let Some(map) = object.as_object_mut() else {
            return Ok(Patched::Unneeded);
        };
        map.insert(field.to_string(), value);
        let new = serde_json::to_vec(&object)?;
        if consistent
            .compare_and_swap_raw(key.clone(), Some(raw), new)
            .await?
        {
            return Ok(Patched::Written(report));
        }
    }
    Ok(Patched::Contended)
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

/// Helper: open the `meta` keyspace ([`KS_META`]), where the applied
/// markers live.
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
    vec![
        Arc::new(M01TagDidRecordsWithDomain),
        Arc::new(M02CacheDidRecordServices),
    ]
}

/// [`registry`] plus the migrations only a control plane runs: the derived
/// rows its writes keep current ([`M03IndexDidRecords`]). The daemon runs
/// this; a standalone control plane runs [`M03IndexDidRecords`] on its own.
pub fn control_plane_registry() -> Vec<Arc<dyn Migration>> {
    let mut migrations = registry();
    migrations.push(Arc::new(M03IndexDidRecords));
    migrations
}

//! Per-mnemonic write-serialisation for read-then-write DID operations.
//!
//! `register_did_atomic` reads `existing` outside any transaction, builds
//! a record based on what it observes, then commits a batch. Two
//! concurrent fresh-slot calls on the *same* path can both observe
//! `existing == None`, both build records with `version_count: 1`, and
//! both commit. fjall batches are atomic per-commit but not conditional,
//! so the second commit silently overwrites the first; the first
//! caller's offer-response said they own the slot but the on-disk record
//! is the second caller's.
//!
//! `change_did_owner` has the same shape: read record + check owner,
//! build new record, commit batch — two simultaneous transfers from the
//! same caller race the version_count update. The blast radius is
//! smaller (no allocation race) but the principle is the same.
//!
//! This module provides `PathLocks::guard(path)`, an async-RAII
//! mnemonic-keyed mutex. Operations that read-then-write hold the lock
//! while the read + build + commit window runs, so the unsafe
//! interleaving is impossible. Locks are created lazily and live for
//! the lifetime of the process — tens of bytes per mnemonic, bounded by
//! the active-DID set.
//!
//! Trade-off: a single-process gate. In a clustered deployment two
//! webvh-control instances behind a load balancer would still race
//! across processes. The control plane is currently single-instance
//! (the daemon is also single-instance), so the in-process gate is
//! sufficient. If clustering is added later, swap this for a
//! distributed lock primitive (Redis SET NX / fjall row-level,
//! depending on backend).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

/// Per-mnemonic mutex map. Cloning is cheap — wraps an `Arc<Mutex<...>>`
/// so the same registry is shared across all `AppState` clones.
#[derive(Debug, Clone, Default)]
pub struct PathLocks {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl PathLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the per-mnemonic write lock and return an owned guard.
    ///
    /// Holding the guard serialises every `PathLocks::guard(<same
    /// path>)` call across the process. Callers should keep the guard
    /// alive across the read + build + commit window of an
    /// optimistic-concurrency operation, then drop it when the commit
    /// returns.
    ///
    /// The outer registry mutex is held only for the lookup-or-insert;
    /// the per-path mutex is held for the duration of the caller's
    /// critical section.
    pub async fn guard(&self, path: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut registry = self.inner.lock().await;
            registry
                .entry(path.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Two `guard()` calls for the same path must serialise: the second
    /// future does not resolve until the first guard drops. Pinning
    /// this catches a regression where the per-path mutex is recreated
    /// rather than reused (e.g. someone changes `entry().or_insert_with`
    /// to `insert` unconditionally).
    #[tokio::test]
    async fn same_path_calls_serialise() {
        let locks = PathLocks::new();
        let g1 = locks.guard("p").await;

        // Spawn a task that tries to acquire the same lock; it should
        // block until we drop g1.
        let locks2 = locks.clone();
        let task = tokio::spawn(async move {
            let _g2 = locks2.guard("p").await;
        });

        // Give the task time to start blocking on the lock.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "second guard must block while first is held"
        );

        drop(g1);
        // Now the second task can complete.
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("second guard must resolve once first drops")
            .unwrap();
    }

    /// Distinct paths use distinct mutexes — two `guard()` calls on
    /// different paths run concurrently. Pins that the gate is per-
    /// path, not global.
    #[tokio::test]
    async fn distinct_paths_do_not_serialise() {
        let locks = PathLocks::new();
        let g1 = locks.guard("path-a").await;
        // Should resolve immediately — different path.
        let _g2 = tokio::time::timeout(Duration::from_millis(50), locks.guard("path-b"))
            .await
            .expect("distinct path must not block");
        drop(g1);
    }
}

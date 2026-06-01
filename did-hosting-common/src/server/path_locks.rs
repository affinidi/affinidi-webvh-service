//! Per-key write-serialisation for read-then-write critical sections.
//!
//! Lives in `did-hosting-common` (rather than the original
//! `did-hosting-control::path_locks` home) so any crate in the
//! workspace can construct one. The control plane re-exports it from
//! `crate::path_locks` for back-compat with existing call sites; new
//! consumers (notably `server::trust_tasks`) depend on this module
//! directly.
//!
//! ## Where it's used
//!
//! - **DID-mnemonic register / change-owner** (`did-hosting-control`)
//!   — read existing record, build new record, commit batch.
//! - **Trust Tasks ACL writes** (`server::trust_tasks` handlers
//!   `grant` / `change-role` / `revoke`) — read entry, check policy,
//!   commit. The race that motivated lifting this here: two
//!   concurrent `acl/revoke` requests targeting the two remaining
//!   Admin entries could each pass the last-authority guard (each
//!   sees the *other* still present) and both commit, leaving the
//!   maintainer with zero Admins. The single-key `"::acl-write"`
//!   guard the trust-tasks handlers acquire serialises every ACL
//!   mutation through one queue, which closes the race at the cost
//!   of negligible contention on admin-only workloads.
//!
//! Trade-off: in-process only. A clustered deployment of two control
//! planes behind a load balancer would still race across processes.
//! The control plane and daemon are single-instance today; swap for
//! a distributed lock primitive if that changes.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

/// Per-key mutex map. Cloning is cheap — wraps an `Arc<Mutex<...>>`
/// so the same registry is shared across all `AppState` clones.
#[derive(Debug, Clone, Default)]
pub struct PathLocks {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl PathLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the per-key write lock and return an owned guard.
    ///
    /// Holding the guard serialises every `PathLocks::guard(<same
    /// key>)` call across the process. Callers should keep the guard
    /// alive across the read + build + commit window of an
    /// optimistic-concurrency operation, then drop it when the commit
    /// returns.
    ///
    /// The outer registry mutex is held only for the lookup-or-insert;
    /// the per-key mutex is held for the duration of the caller's
    /// critical section.
    pub async fn guard(&self, key: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut registry = self.inner.lock().await;
            registry
                .entry(key.to_string())
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

    #[tokio::test]
    async fn same_key_calls_serialise() {
        let locks = PathLocks::new();
        let g1 = locks.guard("p").await;
        let locks2 = locks.clone();
        let task = tokio::spawn(async move {
            let _g2 = locks2.guard("p").await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "second guard must block while first is held"
        );
        drop(g1);
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("second guard must resolve once first drops")
            .unwrap();
    }

    #[tokio::test]
    async fn distinct_keys_do_not_serialise() {
        let locks = PathLocks::new();
        let g1 = locks.guard("key-a").await;
        let _g2 = tokio::time::timeout(Duration::from_millis(50), locks.guard("key-b"))
            .await
            .expect("distinct key must not block");
        drop(g1);
    }
}

//! Per-server async mutex registry (T47).
//!
//! The decision ladder in T49 (`ensure_token`) does a
//! read-cache → maybe-refresh → maybe-reauth dance. Two concurrent
//! tasks against the same server can otherwise race: both observe
//! a stale cache, both call refresh, the second refresh invalidates
//! the first's freshly-minted token. Holding a per-server async
//! mutex over the entire RMW window collapses the race.
//!
//! ## Scope
//!
//! - **Per-server**, not per-(server, holder DID). One holder at a
//!   time is the common case; serialising across two holders
//!   against the same server has negligible cost and avoids a
//!   four-tuple key.
//! - **Async**, not std. `tokio::sync::Mutex` so the lock yields
//!   to the runtime while held — important because the protected
//!   region is the refresh HTTP call, which is async.
//! - **Lazy creation**, never eviction. The registry grows with
//!   the number of distinct server_ids the integrator has ever
//!   talked to. In practice that's ≤ a handful; an explicit GC
//!   isn't worth the cost.
//!
//! ## Integrator usage
//!
//! ```ignore
//! let lock = locks.for_server("did:webvh:Q1:example.com:control");
//! let _guard = lock.lock().await;
//! // decision ladder runs here, mutex protects the whole RMW.
//! ```

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Lazy registry of `Arc<Mutex<()>>` keyed by `server_id`.
///
/// `DashMap` so multiple tasks looking up locks for distinct
/// servers don't contend on a global lock. The mutex held inside
/// each entry is an empty `()`; we only care about the
/// mutual-exclusion semantics, not stored state.
#[derive(Default)]
pub struct ServerLocks {
    inner: DashMap<String, Arc<Mutex<()>>>,
}

impl ServerLocks {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the lock for `server_id`, creating it if this is the
    /// first call for that key. The returned `Arc<Mutex<()>>` is
    /// cheap to clone — integrators that hold the lock across
    /// suspend points should `clone()` rather than re-querying the
    /// registry inside the protected region.
    pub fn for_server(&self, server_id: &str) -> Arc<Mutex<()>> {
        if let Some(existing) = self.inner.get(server_id) {
            return existing.clone();
        }
        // The `entry().or_insert_with` path is the standard
        // create-if-missing pattern that avoids a double-insert
        // race: if two tasks miss simultaneously, only one runs
        // the closure and the other gets the same Arc back.
        self.inner
            .entry(server_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Number of distinct servers we've ever held locks for.
    /// Diagnostic-only; integrators don't normally call this.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when no servers have ever been locked through this
    /// registry. Convenience for tests.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn for_server_returns_same_arc_for_same_id() {
        let locks = ServerLocks::new();
        let a = locks.for_server("srv-a");
        let b = locks.for_server("srv-a");
        // Same Arc — Arc::ptr_eq confirms the registry didn't
        // accidentally create a second instance.
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(locks.len(), 1);
    }

    #[tokio::test]
    async fn for_server_returns_distinct_arc_for_distinct_id() {
        let locks = ServerLocks::new();
        let a = locks.for_server("srv-a");
        let b = locks.for_server("srv-b");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(locks.len(), 2);
    }

    /// Acquiring a lock for srv-a doesn't block tasks acquiring
    /// the lock for srv-b. Pins the per-server isolation.
    #[tokio::test]
    async fn locks_are_per_server_not_global() {
        let locks = Arc::new(ServerLocks::new());
        let lock_a = locks.for_server("srv-a");
        let _guard_a = lock_a.lock().await;

        // srv-b lock acquisition must not block on the srv-a guard.
        let lock_b = locks.for_server("srv-b");
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), lock_b.lock()).await;
        assert!(
            result.is_ok(),
            "srv-b lock should be acquirable while srv-a is held"
        );
    }

    /// Two tasks contending on the same server's lock — second
    /// acquisition blocks until the first releases.
    #[tokio::test]
    async fn same_server_serialises_concurrent_acquisitions() {
        let locks = Arc::new(ServerLocks::new());
        let lock_a = locks.for_server("srv-a");

        let held = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let observed = Arc::new(tokio::sync::Mutex::new(0u32));

        // Task 1: acquire, notify "held", wait for "release",
        // then drop the guard.
        let lock_clone = lock_a.clone();
        let held_a = held.clone();
        let release_a = release.clone();
        let observed_a = observed.clone();
        let t1 = tokio::spawn(async move {
            let _guard = lock_clone.lock().await;
            *observed_a.lock().await += 1;
            held_a.notify_one();
            release_a.notified().await;
        });

        // Wait until task 1 holds the lock.
        held.notified().await;

        // Task 2: race for the same lock — should block.
        let lock_clone = lock_a.clone();
        let observed_b = observed.clone();
        let t2 = tokio::spawn(async move {
            let _guard = lock_clone.lock().await;
            *observed_b.lock().await += 10;
        });

        // Give task 2 a chance to run if it could acquire.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(*observed.lock().await, 1, "task 2 must be blocked");

        // Release task 1 and let task 2 proceed.
        release.notify_one();
        t1.await.unwrap();
        t2.await.unwrap();
        assert_eq!(*observed.lock().await, 11);
    }
}

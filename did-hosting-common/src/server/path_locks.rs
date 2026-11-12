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
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};

use tokio::sync::{Mutex, OwnedMutexGuard};

type Registry = HashMap<String, Arc<Mutex<()>>>;

/// Per-key mutex map. Cloning is cheap — wraps an `Arc<Mutex<...>>`
/// so the same registry is shared across all `AppState` clones.
///
/// An entry lives only while some task holds or waits for its key: the
/// last [`PathGuard`] (or abandoned wait) for a key removes it, so the map
/// stays as small as the set of keys in use rather than growing with every
/// key ever locked.
#[derive(Debug, Clone, Default)]
pub struct PathLocks {
    // A std mutex, not tokio's: it is never held across an `.await`, and
    // `Drop` (which cannot await) has to take it to remove an entry.
    inner: Arc<StdMutex<Registry>>,
}

impl PathLocks {
    pub fn new() -> Self {
        Self::default()
    }

    fn registry(&self) -> StdMutexGuard<'_, Registry> {
        // The registry holds no invariant a panicking holder could break
        // half-way (each critical section is one map operation), so a
        // poisoned lock is still safe to use.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Acquire the per-key write lock and return an owned guard.
    ///
    /// Holding the guard serialises every `PathLocks::guard(<same
    /// key>)` call across the process. Callers should keep the guard
    /// alive across the read + build + commit window of an
    /// optimistic-concurrency operation, then drop it when the commit
    /// returns.
    ///
    /// The registry mutex is held only for the lookup-or-insert; the
    /// per-key mutex is held for the duration of the caller's critical
    /// section.
    pub async fn guard(&self, key: &str) -> PathGuard {
        let (claim, lock) = {
            let mut registry = self.registry();
            let lock = registry
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone();
            // The claim takes its reference while the registry is locked,
            // so a releasing holder can never see this key as unused and
            // remove it between the lookup and the wait below.
            let claim = Claim {
                locks: self.clone(),
                key: key.to_string(),
                lock: Some(lock.clone()),
            };
            (claim, lock)
        };
        // If this future is dropped while waiting, `claim` drops with it
        // and releases the entry.
        let guard = lock.lock_owned().await;
        PathGuard {
            _guard: guard,
            _claim: claim,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.registry().len()
    }
}

/// A held per-key lock from [`PathLocks::guard`]. Dropping it releases the
/// lock and, if no other task holds or waits for the same key, removes the
/// key from the registry.
#[derive(Debug)]
pub struct PathGuard {
    // Field order matters: fields drop in declaration order, so the mutex
    // is released (and its reference dropped) before `_claim` checks
    // whether anything else still refers to the entry.
    _guard: OwnedMutexGuard<()>,
    _claim: Claim,
}

/// One task's reference to a registry entry, held from lookup until the
/// guard (or the abandoned wait) is dropped.
#[derive(Debug)]
struct Claim {
    locks: PathLocks,
    key: String,
    lock: Option<Arc<Mutex<()>>>,
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut registry = self.locks.registry();
        // Drop our reference under the registry lock. Every holder and
        // waiter owns a reference taken under this same lock, so a count
        // of one (the map's own) means nobody holds the key or is about to
        // lock it, and nobody can start to until we release the registry.
        drop(self.lock.take());
        if registry
            .get(&self.key)
            .is_some_and(|lock| Arc::strong_count(lock) == 1)
        {
            registry.remove(&self.key);
        }
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

    #[tokio::test]
    async fn registry_is_empty_after_many_distinct_keys() {
        let locks = PathLocks::new();
        for index in 0..10_000 {
            let guard = locks.guard(&format!("slot-{index}")).await;
            assert_eq!(locks.len(), 1, "only the held key is registered");
            drop(guard);
        }
        assert_eq!(locks.len(), 0, "released keys must not stay registered");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_same_key_lockers_serialise_and_leave_nothing_behind() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let locks = PathLocks::new();
        let inside = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let locks = locks.clone();
            let inside = inside.clone();
            let entered = entered.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..20 {
                    let _guard = locks.guard("shared").await;
                    assert_eq!(
                        inside.fetch_add(1, Ordering::SeqCst),
                        0,
                        "two holders of the same key at once"
                    );
                    entered.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    inside.fetch_sub(1, Ordering::SeqCst);
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(entered.load(Ordering::SeqCst), 64 * 20);
        assert_eq!(locks.len(), 0);
    }

    #[tokio::test]
    async fn entry_survives_while_a_waiter_is_queued() {
        let locks = PathLocks::new();
        let first = locks.guard("p").await;
        let locks2 = locks.clone();
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let waiter = tokio::spawn(async move {
            let _second = locks2.guard("p").await;
            acquired_tx.send(()).unwrap();
            release_rx.await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(first);
        // The queued waiter still refers to the entry, so releasing the
        // first holder must not remove it.
        acquired_rx.await.unwrap();
        assert_eq!(locks.len(), 1);
        // A third locker must queue behind the waiter on the same mutex,
        // not get a fresh one.
        let third = tokio::time::timeout(Duration::from_millis(20), locks.guard("p")).await;
        assert!(third.is_err(), "third locker must wait for the second");
        release_tx.send(()).unwrap();
        waiter.await.unwrap();
        assert_eq!(locks.len(), 0);
    }

    #[tokio::test]
    async fn abandoned_wait_releases_its_entry() {
        let locks = PathLocks::new();
        let held = locks.guard("p").await;
        let abandoned = tokio::time::timeout(Duration::from_millis(20), locks.guard("p")).await;
        assert!(abandoned.is_err());
        assert_eq!(locks.len(), 1, "the holder still needs the entry");
        drop(held);
        assert_eq!(locks.len(), 0);
    }
}

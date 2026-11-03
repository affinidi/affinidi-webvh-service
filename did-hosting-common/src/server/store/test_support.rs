//! Test-only helpers for asserting multi-row writes are atomic.
//!
//! A crash cannot be simulated in-process, but the state a crash would
//! freeze can be *observed*: if a logical update is two separate writes,
//! a concurrent reader can catch the store between them. These helpers run
//! a sequence of updates while observer tasks hammer the row currently
//! being updated, so a non-atomic implementation is caught in the window a
//! crash would have exposed.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Run `step(0..n)` in order while `OBSERVERS` tasks repeatedly call
/// `check(i)` on the step currently in flight. `check` returns a
/// description of a violated invariant, or `None`. The invariant must hold
/// before, during and after its step — each step should move one row from
/// one state to another exactly once.
///
/// Panics with the first violation observed.
pub(crate) async fn assert_never_observed<S, SF, C, CF>(n: usize, step: S, check: C)
where
    S: Fn(usize) -> SF,
    SF: Future<Output = ()>,
    C: Fn(usize) -> CF + Clone + Send + Sync + 'static,
    CF: Future<Output = Option<String>> + Send,
{
    const OBSERVERS: usize = 4;
    let current = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let mut observers = Vec::new();
    for _ in 0..OBSERVERS {
        let current = current.clone();
        let done = done.clone();
        let check = check.clone();
        observers.push(tokio::spawn(async move {
            while !done.load(Ordering::Acquire) {
                if let Some(violation) = check(current.load(Ordering::Acquire)).await {
                    return Some(violation);
                }
                tokio::task::yield_now().await;
            }
            None
        }));
    }
    for i in 0..n {
        current.store(i, Ordering::Release);
        step(i).await;
    }
    done.store(true, Ordering::Release);
    for observer in observers {
        if let Some(violation) = observer.await.expect("observer panicked") {
            panic!("non-atomic update observed: {violation}");
        }
    }
}

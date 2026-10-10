//! The request store for `auth/oob/*` (base design 7.2, section 12 item 1).
//!
//! In memory, on purpose. A request lives for at most two 120 s windows, the
//! `redeem` long poll has to be woken in-process anyway, and the control
//! plane is a single process (the daemon embeds it). A restart drops open
//! requests, which costs the person one new code and nothing else: no session
//! exists until `redeem` succeeds.
//!
//! Every change of state is a compare-and-set on the record's `version`, so
//! only one caller can make it. Expired and finished records, and remembered
//! document ids, are swept lazily on writes, so no background task is needed
//! (and the daemon has nothing extra to mirror).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use super::types::OobState;

/// How long a finished or expired record is kept, so a late `redeem` or
/// `cancel` gets a meaningful answer rather than `requestNotFound`. Seconds.
pub const FINISHED_RETENTION_SECS: u64 = 300;

/// The most requests held at once. A flood of `request` documents from many
/// addresses past the per-IP limit stops here, not at memory exhaustion.
pub const MAX_OPEN_REQUESTS: usize = 10_000;

/// One sign-in request (base design 7.2).
#[derive(Debug, Clone, PartialEq)]
pub struct OobRecord {
    pub request_id: String,
    pub state: OobState,
    /// Incremented on every change; the compare-and-set key.
    pub version: u64,
    pub purpose: String,
    pub origin: String,
    /// `K_b`, an Ed25519 `did:key`.
    pub start_key: String,
    /// Egress IP of the `request`. Dropped once the request ends.
    pub start_network: Option<String>,
    pub location: String,
    pub browser: String,
    pub os: String,
    /// Epoch seconds.
    pub created_at: u64,
    /// `K_a`, set at claim.
    pub approver_key: Option<String>,
    /// Two digits, set at claim.
    pub match_number: Option<String>,
    /// Set at prove.
    pub identified_did: Option<String>,
    /// `contextDigest` of the signed step 2 response, set at prove.
    pub step2_digest: Option<String>,
    /// Epoch seconds.
    pub claim_deadline: u64,
    /// Epoch seconds, set at claim.
    pub decision_deadline: Option<u64>,
    /// The signed grant, once decided.
    pub grant: Option<serde_json::Value>,
    /// The grant's `notAfter`, epoch seconds, once approved.
    pub grant_not_after: Option<u64>,
    /// When the record reached a final state, epoch seconds.
    pub finished_at: Option<u64>,
}

impl OobRecord {
    /// Whether the deadline of the record's current state has passed: the
    /// claim window while pending, the decision window after a claim.
    pub fn lapsed(&self, now: u64) -> bool {
        match self.state {
            OobState::Pending => now > self.claim_deadline,
            s if s.in_decision_window() => now > self.decision_deadline.unwrap_or(0),
            _ => false,
        }
    }

    /// The next version of this record: same fields, `version + 1`. A final
    /// state drops the start network (T22) and stamps `finished_at`.
    pub fn next(&self, state: OobState, now: u64) -> OobRecord {
        let mut n = self.clone();
        n.state = state;
        n.version = self.version + 1;
        if state.is_final() {
            n.start_network = None;
            n.finished_at = Some(now);
        }
        n
    }
}

#[derive(Default)]
struct Inner {
    records: HashMap<String, OobRecord>,
    /// `(issuer, id)` of every document accepted, until the epoch second.
    seen: HashMap<(String, String), u64>,
    waiters: HashMap<String, Arc<Notify>>,
    open_polls: HashSet<String>,
    polls_per_ip: HashMap<String, usize>,
}

/// The store. Cheap to clone; all clones share state.
#[derive(Clone, Default)]
pub struct OobStore {
    inner: Arc<Mutex<Inner>>,
}

/// Why a create was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum CreateError {
    Duplicate,
    Full,
}

impl OobStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Insert a new record. Sweeps old records first.
    pub fn create(&self, record: OobRecord, now: u64) -> Result<(), CreateError> {
        let mut g = self.lock();
        sweep(&mut g, now);
        if g.records.contains_key(&record.request_id) {
            return Err(CreateError::Duplicate);
        }
        if g.records.len() >= MAX_OPEN_REQUESTS {
            return Err(CreateError::Full);
        }
        g.records.insert(record.request_id.clone(), record);
        Ok(())
    }

    pub fn get(&self, request_id: &str) -> Option<OobRecord> {
        self.lock().records.get(request_id).cloned()
    }

    /// Replace the record only if its stored `version` equals
    /// `expected_version`. Wakes any `redeem` waiting on it.
    pub fn compare_and_set(&self, expected_version: u64, next: OobRecord) -> bool {
        let mut g = self.lock();
        let ok = matches!(
            g.records.get(&next.request_id),
            Some(cur) if cur.version == expected_version
        );
        if ok {
            let id = next.request_id.clone();
            g.records.insert(id.clone(), next);
            if let Some(n) = g.waiters.get(&id) {
                n.notify_waiters();
            }
        }
        ok
    }

    /// Record a document `(issuer, id)` until `until`. Returns false if it was
    /// already recorded: a replay.
    pub fn remember_document(&self, issuer: &str, id: &str, until: u64, now: u64) -> bool {
        let mut g = self.lock();
        g.seen.retain(|_, exp| *exp >= now);
        let key = (issuer.to_string(), id.to_string());
        if g.seen.contains_key(&key) {
            return false;
        }
        g.seen.insert(key, until);
        true
    }

    /// The notifier for a request's changes.
    pub fn waiter(&self, request_id: &str) -> Arc<Notify> {
        self.lock()
            .waiters
            .entry(request_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Open the one poll a request may have, counted against `ip`. Returns
    /// `None` if a poll is already open for the request or `ip` has
    /// `max_per_ip` open. The guard closes it when dropped, including when
    /// the client goes away and the handler future is dropped.
    pub fn open_poll(&self, request_id: &str, ip: &str, max_per_ip: usize) -> Option<PollGuard> {
        let mut g = self.lock();
        if g.open_polls.contains(request_id) {
            return None;
        }
        let n = g.polls_per_ip.get(ip).copied().unwrap_or(0);
        if n >= max_per_ip {
            return None;
        }
        g.open_polls.insert(request_id.to_string());
        g.polls_per_ip.insert(ip.to_string(), n + 1);
        Some(PollGuard {
            store: self.clone(),
            request_id: request_id.to_string(),
            ip: ip.to_string(),
        })
    }

    #[cfg(test)]
    pub fn record_count(&self) -> usize {
        self.lock().records.len()
    }
}

/// Closes an open `redeem` poll on drop.
pub struct PollGuard {
    store: OobStore,
    request_id: String,
    ip: String,
}

impl Drop for PollGuard {
    fn drop(&mut self) {
        let mut g = self.store.lock();
        g.open_polls.remove(&self.request_id);
        if let Some(n) = g.polls_per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.polls_per_ip.remove(&self.ip);
            }
        }
    }
}

/// Drop records that finished (or whose last deadline passed) more than
/// [`FINISHED_RETENTION_SECS`] ago, with their waiters.
fn sweep(g: &mut Inner, now: u64) {
    let cutoff = now.saturating_sub(FINISHED_RETENTION_SECS);
    let stale: Vec<String> = g
        .records
        .values()
        .filter(|r| {
            let last = r
                .finished_at
                .unwrap_or_else(|| r.decision_deadline.unwrap_or(r.claim_deadline));
            last < cutoff
        })
        .map(|r| r.request_id.clone())
        .collect();
    for id in stale {
        g.records.remove(&id);
        if !g.open_polls.contains(&id) {
            g.waiters.remove(&id);
        }
    }
    g.seen.retain(|_, exp| *exp >= now);
}

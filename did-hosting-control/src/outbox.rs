//! Durable outbound DIDComm queue for control → server mutations.
//!
//! Every control-plane mutation that needs to land on hosting servers
//! (`assign`, `unassign`, `purge`, `domain/upsert`, `sync-update`,
//! `sync-delete`) is persisted to `KS_OUTBOUND_QUEUE` before any
//! delivery attempt. The [`run_outbox_loop`] worker drains the queue
//! in per-target FIFO order, retries transient failures with
//! exponential backoff, and only removes an entry once the
//! recipient's mediator has accepted it.
//!
//! ## Guarantees
//!
//! - **At-least-once delivery.** A control crash mid-send keeps the
//!   entry; the next tick (or post-restart boot) retries. Recipients
//!   MUST be idempotent — the existing `handle_domain_*` /
//!   `handle_sync_*` handlers already are.
//! - **Per-target FIFO.** Entries for the same `target_did` are
//!   processed in enqueue order. A failing entry blocks subsequent
//!   entries for that target (head-of-line) until it succeeds, is
//!   dropped via [`MAX_ATTEMPTS`], or ages out via [`MAX_AGE_SECS`].
//! - **Restart-safe.** Queue state lives in fjall — survives control-
//!   plane restarts. The worker resumes on boot.
//!
//! ## Why not the mediator's queue?
//!
//! The Affinidi mediator buffers messages for offline recipients, but
//! we also need durability for two failure modes the mediator can't
//! help with: (a) the mediator itself being unreachable from control
//! at send time, and (b) the control process crashing between local
//! mutation and the mediator-side enqueue. The outbox covers both.
//!
//! ## Key layout
//!
//! `outbox:{target_did}:{enqueue_micros:020}:{uuid_short}`
//!
//! Zero-padded microsecond timestamps give monotonic lex-order; the
//! uuid suffix breaks same-microsecond ties without coordinating a
//! sequence counter.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::DIDCommService;
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::store::{KS_OUTBOUND_QUEUE, KeyspaceHandle, Store};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Notify, watch};
use tracing::{debug, info, warn};

use crate::auth::session::now_epoch;
use crate::server::AppState;

/// Worker tick when nothing's notified. 30 s is short enough that a
/// transient mediator outage clears within a minute, long enough that
/// an idle deployment doesn't churn on empty keyspace scans.
pub const DEFAULT_OUTBOX_TICK: Duration = Duration::from_secs(30);

/// Drop entries that have failed this many times. With exponential
/// backoff capped at 5 min, 50 attempts spans roughly 4 hours of
/// continuous failure — well past any reasonable transient. Past this
/// point the receiver is genuinely down or the message is a poison
/// pill; either way, keep moving.
pub const MAX_ATTEMPTS: u32 = 50;

/// Drop entries older than this regardless of attempts. 7 days
/// protects against very-slow-failure modes (e.g. recipient comes
/// back up briefly each day, fails the first message, goes down) that
/// would otherwise let the queue grow unbounded.
pub const MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Cap exponential backoff. Beyond 5 min, the queue is effectively
/// idle until either the next notify or the periodic tick.
pub const MAX_BACKOFF_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxEntry {
    /// Recipient DID (server DID).
    pub target_did: String,
    /// DIDComm message-type URI (`MSG_DOMAIN_*` / `MSG_SYNC_*` etc).
    pub msg_type: String,
    /// Body as serialized by the original send helper.
    pub body: Value,
    /// Unix-seconds at enqueue time. Used for the [`MAX_AGE_SECS`]
    /// poison-pill check.
    pub enqueued_at: u64,
    /// Number of delivery attempts so far.
    pub attempts: u32,
    /// Earliest unix-seconds at which the worker should retry. Set
    /// after a failed attempt by [`compute_backoff`].
    pub next_attempt_at: u64,
    /// Last error string, for operator-visible diagnostics. Truncated
    /// to ~200 chars to keep keyspace rows small.
    pub last_error: Option<String>,
}

fn outbox_ks(store: &Store) -> Result<KeyspaceHandle, AppError> {
    store.keyspace(KS_OUTBOUND_QUEUE)
}

/// Build the keyspace key for an entry. Sorts lexicographically by
/// `(target_did, enqueue_micros, uuid)`.
fn outbox_key(target_did: &str, enqueue_micros: u128, uuid_short: &str) -> Vec<u8> {
    format!("outbox:{target_did}:{enqueue_micros:020}:{uuid_short}").into_bytes()
}

fn target_prefix(target_did: &str) -> Vec<u8> {
    format!("outbox:{target_did}:").into_bytes()
}

fn now_micros() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0)
}

fn truncated(err: &str) -> String {
    const MAX: usize = 200;
    if err.len() <= MAX {
        err.to_string()
    } else {
        format!("{}…", &err[..MAX])
    }
}

fn compute_backoff(attempts: u32) -> u64 {
    let secs = 1u64
        .checked_shl(attempts.min(10))
        .unwrap_or(MAX_BACKOFF_SECS);
    secs.min(MAX_BACKOFF_SECS)
}

/// Persist a control→server message. Returns immediately once the row
/// is durable; actual delivery is the worker's job. Caller fires
/// `notify.notify_one()` afterwards (or via [`enqueue_and_notify`])
/// to wake the worker for a low-latency happy path.
pub async fn enqueue(
    store: &Store,
    target_did: &str,
    msg_type: &str,
    body: Value,
) -> Result<Vec<u8>, AppError> {
    let now = now_epoch();
    let entry = OutboxEntry {
        target_did: target_did.to_string(),
        msg_type: msg_type.to_string(),
        body,
        enqueued_at: now,
        attempts: 0,
        next_attempt_at: now,
        last_error: None,
    };
    let uuid_short = uuid::Uuid::new_v4().simple().to_string();
    let key = outbox_key(target_did, now_micros(), &uuid_short[..12]);
    outbox_ks(store)?.insert(key.clone(), &entry).await?;
    Ok(key)
}

/// Enqueue + wake the worker. The common case caller wants this.
pub async fn enqueue_and_notify(
    state: &AppState,
    target_did: &str,
    msg_type: &str,
    body: Value,
) -> Result<Vec<u8>, AppError> {
    let key = enqueue(&state.store, target_did, msg_type, body).await?;
    state.outbox_notify.notify_one();
    Ok(key)
}

/// List every distinct `target_did` with pending entries.
pub async fn list_targets(store: &Store) -> Result<Vec<String>, AppError> {
    let raw = outbox_ks(store)?
        .prefix_iter_raw(b"outbox:".to_vec())
        .await?;
    let mut targets: Vec<String> = raw
        .iter()
        .filter_map(|(k, _)| {
            let s = std::str::from_utf8(k).ok()?;
            // "outbox:{target_did}:{micros}:{uuid}" — target_did
            // itself may contain ':' (did:webvh:Q…:host), so we strip
            // the leading "outbox:" prefix and trim the trailing
            // ":{micros}:{uuid}" (the last two colon-separated chunks).
            let after_prefix = s.strip_prefix("outbox:")?;
            // Find the position of the second-to-last ':' — that's
            // the boundary between the DID and the micros timestamp.
            let last_colon = after_prefix.rfind(':')?;
            let before_uuid = &after_prefix[..last_colon];
            let second_last_colon = before_uuid.rfind(':')?;
            Some(after_prefix[..second_last_colon].to_string())
        })
        .collect();
    targets.sort();
    targets.dedup();
    Ok(targets)
}

/// Pending entries for one target, in enqueue order. Returns
/// `(storage_key, entry)` so the caller can `remove` or update.
pub async fn list_pending_for_target(
    store: &Store,
    target_did: &str,
) -> Result<Vec<(Vec<u8>, OutboxEntry)>, AppError> {
    let raw = outbox_ks(store)?
        .prefix_iter_raw(target_prefix(target_did))
        .await?;
    let mut out = Vec::with_capacity(raw.len());
    for (k, v) in raw {
        match serde_json::from_slice::<OutboxEntry>(&v) {
            Ok(e) => out.push((k, e)),
            Err(e) => {
                warn!(
                    target_did,
                    error = %e,
                    "outbox: dropping malformed entry"
                );
                let _ = outbox_ks(store)?.remove(k).await;
            }
        }
    }
    // Prefix scan returns lex-sorted keys, which means enqueue-time
    // ordered for our key format. Defensive sort by enqueue_micros in
    // case a future key change perturbs the lex order.
    out.sort_by_key(|(k, _)| k.clone());
    Ok(out)
}

/// Remove a delivered entry.
pub async fn remove(store: &Store, key: Vec<u8>) -> Result<(), AppError> {
    outbox_ks(store)?.remove(key).await
}

/// Bump attempts + backoff timer + last_error on the existing row.
pub async fn record_failure(
    store: &Store,
    key: Vec<u8>,
    entry: &OutboxEntry,
    err: &str,
) -> Result<(), AppError> {
    let next = OutboxEntry {
        attempts: entry.attempts.saturating_add(1),
        last_error: Some(truncated(err)),
        next_attempt_at: now_epoch().saturating_add(compute_backoff(entry.attempts + 1)),
        ..entry.clone()
    };
    outbox_ks(store)?.insert(key, &next).await
}

/// Send one entry via the DIDComm service. Pulled out so tests can
/// substitute a mock service when the time comes.
async fn deliver(
    didcomm: &DIDCommService,
    control_did: &str,
    entry: &OutboxEntry,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        entry.msg_type.clone(),
        entry.body.clone(),
    )
    .from(control_did.to_string())
    .to(entry.target_did.clone())
    .created_time(now_epoch())
    .finalize();

    didcomm
        .send_message("control", msg, &entry.target_did)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

/// Outcome of one tick. Exposed so tests + `info!` callsites can
/// surface concrete counts.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    pub delivered: u64,
    pub deferred: u64,
    pub dropped: u64,
}

/// Process every target's queue once. Returns counts for telemetry.
pub async fn run_tick(state: &AppState) -> TickReport {
    let svc = match state.didcomm_service.get() {
        Some(s) => s.clone(),
        None => {
            debug!("outbox tick: DIDComm service not yet initialised; skipping");
            return TickReport::default();
        }
    };
    let control_did = match state.config.server_did.as_deref() {
        Some(d) => d.to_string(),
        None => {
            debug!("outbox tick: control server_did not configured; skipping");
            return TickReport::default();
        }
    };

    let targets = match list_targets(&state.store).await {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "outbox tick: list_targets failed");
            return TickReport::default();
        }
    };

    let mut report = TickReport::default();
    let now = now_epoch();
    for target in targets {
        let pending = match list_pending_for_target(&state.store, &target).await {
            Ok(p) => p,
            Err(e) => {
                warn!(target_did = %target, error = %e, "outbox tick: list_pending failed");
                continue;
            }
        };
        for (key, entry) in pending {
            // Poison-pill / age-out checks first — these short-
            // circuit ahead of next_attempt_at to keep the queue
            // bounded even when a target has been dead for days.
            if entry.attempts >= MAX_ATTEMPTS
                || now.saturating_sub(entry.enqueued_at) >= MAX_AGE_SECS
            {
                warn!(
                    target_did = %target,
                    msg_type = %entry.msg_type,
                    attempts = entry.attempts,
                    age_secs = now.saturating_sub(entry.enqueued_at),
                    last_error = entry.last_error.as_deref().unwrap_or(""),
                    "outbox: dropping entry past retry budget"
                );
                let _ = remove(&state.store, key).await;
                report.dropped += 1;
                continue;
            }
            if entry.next_attempt_at > now {
                // Head-of-line is still backing off — stop processing
                // this target's chain so we preserve order.
                report.deferred += 1;
                break;
            }

            match deliver(&svc, &control_did, &entry).await {
                Ok(()) => {
                    info!(
                        target_did = %target,
                        msg_type = %entry.msg_type,
                        attempts = entry.attempts + 1,
                        "outbox: delivered"
                    );
                    let _ = remove(&state.store, key).await;
                    report.delivered += 1;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    warn!(
                        target_did = %target,
                        msg_type = %entry.msg_type,
                        attempts = entry.attempts + 1,
                        error = %err_str,
                        "outbox: delivery failed; will retry after backoff"
                    );
                    let _ = record_failure(&state.store, key, &entry, &err_str).await;
                    report.deferred += 1;
                    // Preserve per-target ordering on transient
                    // failure: don't try later entries until the head
                    // succeeds (or ages out).
                    break;
                }
            }
        }
    }
    report
}

/// Long-running worker. Wakes on [`AppState::outbox_notify`] for low-
/// latency happy path; falls back to a 30-s tick to retry backed-off
/// entries when no fresh enqueue fires the notify.
pub async fn run_outbox_loop(
    state: AppState,
    notify: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(DEFAULT_OUTBOX_TICK);
    ticker.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let report = run_tick(&state).await;
                if report.delivered > 0 || report.dropped > 0 {
                    info!(?report, "outbox tick");
                }
            }
            _ = notify.notified() => {
                let report = run_tick(&state).await;
                if report.delivered > 0 || report.dropped > 0 {
                    info!(?report, "outbox tick (notified)");
                }
            }
            _ = shutdown.changed() => {
                info!("outbox worker shutting down");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_hosting_common::server::config::StoreConfig;
    use serde_json::json;

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
    async fn enqueue_then_list_targets_and_pending() {
        let store = fjall_store().await;
        enqueue(&store, "did:example:a", "ty/1.0", json!({"k":1}))
            .await
            .unwrap();
        enqueue(&store, "did:example:b", "ty/1.0", json!({"k":2}))
            .await
            .unwrap();
        enqueue(&store, "did:example:a", "ty/1.0", json!({"k":3}))
            .await
            .unwrap();

        let mut targets = list_targets(&store).await.unwrap();
        targets.sort();
        assert_eq!(targets, vec!["did:example:a", "did:example:b"]);

        let a = list_pending_for_target(&store, "did:example:a")
            .await
            .unwrap();
        assert_eq!(a.len(), 2);
        // FIFO ordering — first enqueued is first in the list.
        assert_eq!(a[0].1.body, json!({"k": 1}));
        assert_eq!(a[1].1.body, json!({"k": 3}));
    }

    #[tokio::test]
    async fn list_targets_handles_did_with_internal_colons() {
        // Real DIDs include several colons (`did:webvh:Q…:host`).
        let store = fjall_store().await;
        let did = "did:webvh:QmAbc:host.example.com";
        enqueue(&store, did, "ty/1.0", json!({})).await.unwrap();
        let targets = list_targets(&store).await.unwrap();
        assert_eq!(targets, vec![did.to_string()]);
    }

    #[tokio::test]
    async fn record_failure_increments_and_backs_off() {
        let store = fjall_store().await;
        let key = enqueue(&store, "did:example:a", "ty/1.0", json!({}))
            .await
            .unwrap();
        let pending = list_pending_for_target(&store, "did:example:a")
            .await
            .unwrap();
        let entry = pending[0].1.clone();
        assert_eq!(entry.attempts, 0);

        record_failure(&store, key, &entry, "boom").await.unwrap();
        let after = list_pending_for_target(&store, "did:example:a")
            .await
            .unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].1.attempts, 1);
        assert_eq!(after[0].1.last_error.as_deref(), Some("boom"));
        assert!(after[0].1.next_attempt_at >= entry.next_attempt_at);
    }

    #[tokio::test]
    async fn remove_clears_entry() {
        let store = fjall_store().await;
        let key = enqueue(&store, "did:example:a", "ty/1.0", json!({}))
            .await
            .unwrap();
        remove(&store, key).await.unwrap();
        let pending = list_pending_for_target(&store, "did:example:a")
            .await
            .unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn backoff_grows_then_caps() {
        // 2^0=1, 2^1=2, ..., 2^9=512, 2^10=1024 → cap at 300.
        assert_eq!(compute_backoff(0), 1);
        assert_eq!(compute_backoff(1), 2);
        assert_eq!(compute_backoff(4), 16);
        assert_eq!(compute_backoff(9), 300); // 2^9=512, capped
        assert_eq!(compute_backoff(50), 300); // saturating
    }

    #[test]
    fn truncated_caps_long_errors() {
        let long = "x".repeat(500);
        let t = truncated(&long);
        assert!(t.ends_with('…'));
        // 200 char prefix + … (1 char in str sense; multi-byte)
        assert_eq!(t.chars().count(), 201);
    }
}

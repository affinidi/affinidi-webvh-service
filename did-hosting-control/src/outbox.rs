//! Durable outbound queue for control → server (and watcher) mutations.
//!
//! Every control-plane mutation that needs to land on hosting servers
//! (`assign`, `unassign`, `purge`, `domain/upsert`, `sync-update`,
//! `sync-delete`, `sync-batch`) is persisted to `KS_OUTBOUND_QUEUE` before
//! any delivery attempt. The [`run_outbox_loop`] worker drains the queue in
//! per-target FIFO order and only removes an entry once the **recipient
//! itself** has acknowledged it: a signed `#response` from the target's DID
//! for a document sent for that entry ([`acknowledge`]). A mediator accepting
//! the frame is not delivery — an edge that is offline longer than the
//! freshness window would otherwise lose every queued op for good.
//!
//! ## Reference rows
//!
//! A DID sync row does not carry the `did.jsonl` it replicates: it names the
//! slot ([`Subject::Did`]), and the worker reads the slot's current log when
//! it sends ([`prepare`]). So a row is a few hundred bytes whatever the log's
//! size (no store's per-item limit is in reach), a resend carries the newest
//! state rather than the one at enqueue time, and a slot deleted before its
//! row is sent goes out as `sync/delete`. A domain upsert names the domain the
//! same way ([`Subject::DomainUpsert`]); a resync batch names its slots
//! ([`Subject::DidBatch`]). Domain assign / unassign / purge carry a literal
//! `{domain}` body: they are constant-size, and their order is the point.
//!
//! **Coalescing.** A DID or domain-upsert row is queued at most once per
//! target: enqueueing one already queued is a no-op (`outbox-ref:` index).
//! That is safe only because a row settles on an acknowledgement *of the
//! current state*: each send records a fingerprint of what it carried, and an
//! ack whose fingerprint no longer matches what [`prepare`] would send now
//! re-arms the row instead of removing it. The check and the enqueue run under
//! the same lock (the slot's `path_locks` key, or one per domain), so a change
//! committed while a send was in flight is never lost to the coalesce.
//!
//! ## Transactional enqueue
//!
//! DID mutations stage their rows in the **same** `store.batch()` as the
//! mutation itself (`server_push::stage_did_*`), under the slot's path lock.
//! A crash between the commit and the enqueue cannot lose the push, and the
//! per-target order of a slot's rows follows commit order.
//!
//! ## Delivery
//!
//! Each (re)send is a freshly signed document with a new id, so a retry is
//! never refused as stale or as a replay. The document id is recorded (with
//! an `outbox-ack:` index pointing at the row) *before* the send, so an ack
//! that beats the bookkeeping still finds its row. An ack of any of the last
//! [`MAX_TRACKED_SENDS`] documents sent for a row settles it — an edge coming
//! back online applies the first copy the mediator held for it, and that ack
//! is as good as the last one's.
//!
//! Two failure modes, counted separately:
//!
//! - **Hard failures** (`attempts`): the transport refused the frame or the
//!   document could not be built. Retried with exponential backoff, 2 s
//!   doubling to [`MAX_BACKOFF_SECS`] (5 min), with jitter. [`MAX_ATTEMPTS`]
//!   (50) of them span roughly 3.5 hours, after which the row is dropped.
//! - **Accepted but unacknowledged** (`unacked`): the transport took the
//!   frame and no ack came back. The wait doubles from [`ACK_TIMEOUT_SECS`]
//!   (1 min) to [`MAX_ACK_WAIT_SECS`] (1 h), with jitter, so an offline edge
//!   does not collect a copy a minute in its mediator queue. [`MAX_UNACKED`]
//!   (24) sends span roughly 19 hours.
//!
//! Every row is dropped after [`MAX_AGE_SECS`] (7 days) regardless. A
//! dropped row is not lost state: the edge's next registration resyncs it
//! (`edge_is_current`, `resend_domain_intents`).
//!
//! ## Guarantees
//!
//! - **At-least-once delivery.** Recipients MUST be idempotent — the
//!   edge's `webvh/sync/*` and `replica/domain/*` handlers are
//!   (`did-hosting-server`'s `messaging`).
//! - **Per-target FIFO.** Entries for the same target are processed in
//!   enqueue order, one in flight at a time; the head blocks the rest
//!   (head-of-line) until it settles or is dropped. Targets are independent
//!   and are serviced concurrently ([`MAX_CONCURRENT_TARGETS`]).
//! - **Restart-safe.** Queue state lives in the store and survives control
//!   plane restarts. The worker resumes on boot.
//!
//! ## Why not the mediator's queue?
//!
//! The mediator buffers messages for offline recipients, but it cannot help
//! when (a) the mediator itself is unreachable from control at send time, or
//! (b) the control process crashes between the local mutation and the
//! mediator-side enqueue. The transactional outbox covers both.
//!
//! ## Key layout (all in `KS_OUTBOUND_QUEUE`)
//!
//! - `outbox:{target}|{seq:020}:{uuid12}` — a queued row. `seq` is a
//!   process-monotonic microsecond stamp, so rows staged in one batch keep
//!   their order; `|` cannot occur in a DID, so no target's prefix matches
//!   another's.
//! - `outbox-target:{target}` — a target with (possibly) queued rows; what
//!   the worker iterates instead of scanning every row.
//! - `outbox-ack:{target}|{doc_id}` — the row a sent document belongs to.
//! - `outbox-ref:{target}|{subject}` — the queued row of a coalescing
//!   subject, or the latest literal domain op for a domain.
//!
//! Rows written by earlier versions (`outbox:{target}:{micros}:{uuid}`, with
//! a literal body) are re-keyed on boot ([`migrate_legacy_rows`]) and drain
//! like any other literal row.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use affinidi_messaging_didcomm_service::DIDCommService;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use did_hosting_common::did_ops::{self, DidRecord};
use did_hosting_common::didcomm_types::*;
use did_hosting_common::server::didcomm_profile::{PeerTransport, TransportFallback};
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::path_locks::{PathGuard, PathLocks};
use did_hosting_common::server::store::{KS_OUTBOUND_QUEUE, KeyspaceHandle, Store, WriteBatch};
use did_hosting_common::server::trust_tasks::send::{Peers, build_signed_request, send_trust_task};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, watch};
use tracing::{debug, info, warn};

use crate::auth::session::now_epoch;
use crate::server::AppState;

/// Worker tick when nothing's notified. 30 s is short enough that a
/// transient mediator outage clears within a minute, long enough that
/// an idle deployment doesn't churn.
pub const DEFAULT_OUTBOX_TICK: Duration = Duration::from_secs(30);

/// Drop an entry after this many hard delivery failures. With exponential
/// backoff from 2 s capped at [`MAX_BACKOFF_SECS`], 50 failures span
/// roughly 3.5 hours.
pub const MAX_ATTEMPTS: u32 = 50;

/// Drop an entry after this many sends the transport accepted but the target
/// never acknowledged. With the wait doubling from [`ACK_TIMEOUT_SECS`] to
/// [`MAX_ACK_WAIT_SECS`], 24 sends span roughly 19 hours.
pub const MAX_UNACKED: u32 = 24;

/// Drop entries older than this regardless of attempts. 7 days
/// protects against very-slow-failure modes that would otherwise let the
/// queue grow unbounded.
pub const MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Cap on the hard-failure backoff.
pub const MAX_BACKOFF_SECS: u64 = 5 * 60;

/// The first wait for a target's signed acknowledgement before the entry is
/// sent again. Doubles per unacknowledged send, up to [`MAX_ACK_WAIT_SECS`].
pub const ACK_TIMEOUT_SECS: u64 = 60;

/// Cap on the wait for an acknowledgement.
pub const MAX_ACK_WAIT_SECS: u64 = 60 * 60;

/// How many of an entry's most recent sends an acknowledgement may answer.
pub const MAX_TRACKED_SENDS: usize = 16;

/// How many targets one tick services at once.
pub const MAX_CONCURRENT_TARGETS: usize = 8;

/// What a reference row stands for; [`prepare`] turns it into the document
/// sent, from the store as it is at send time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Subject {
    /// One slot: `sync/update` with its current content, or `sync/delete`
    /// when it has none (deleted, or never published).
    Did { mnemonic: String },
    /// Several slots in one `sync/batch` (a resync to a batch-capable edge).
    /// Slots gone by send time are left out; their deletes travel as rows of
    /// their own.
    DidBatch { mnemonics: Vec<String> },
    /// `replica/domain/upsert` with the domain's current entry.
    DomainUpsert { domain: String },
}

impl Subject {
    /// The `outbox-ref:` index suffix for a subject queued at most once per
    /// target; `None` for one that is not coalesced.
    fn coalesce_key(&self) -> Option<String> {
        match self {
            Self::Did { mnemonic } => Some(format!("did|{mnemonic}")),
            Self::DomainUpsert { domain } => Some(format!("domain-upsert|{domain}")),
            Self::DidBatch { .. } => None,
        }
    }

    /// The Type URI a row is listed under before it is materialised.
    fn nominal_type(&self) -> &'static str {
        match self {
            Self::Did { .. } => MSG_SYNC_UPDATE,
            Self::DidBatch { .. } => MSG_SYNC_BATCH,
            Self::DomainUpsert { .. } => MSG_REPLICA_DOMAIN_UPSERT,
        }
    }
}

/// The lock a coalescing subject's enqueue-check and settle run under. A
/// slot's is its `path_locks` key, which every DID mutation already holds
/// while it commits — so a mutation and the settling of its slot's row are
/// serialised.
pub(crate) async fn subject_guard(state: &AppState, subject: &Subject) -> Option<PathGuard> {
    match subject {
        Subject::Did { mnemonic } => Some(state.path_locks.guard(mnemonic).await),
        Subject::DomainUpsert { domain } => Some(
            state
                .path_locks
                .guard(&format!("outbox-domain-upsert:{domain}"))
                .await,
        ),
        Subject::DidBatch { .. } => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxEntry {
    /// Recipient DID (server or watcher DID).
    pub target_did: String,
    /// Trust Task Type URI. For a reference row, the nominal type at enqueue
    /// time — the one sent is decided by [`prepare`].
    pub msg_type: String,
    /// The literal body, for a row with no [`Subject`] (domain ops, and rows
    /// written before reference rows existed).
    #[serde(default)]
    pub body: Value,
    /// What a reference row stands for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    /// Unix-seconds at enqueue time (or re-arm). Used for the
    /// [`MAX_AGE_SECS`] poison-pill check and the replication-lag gauge.
    pub enqueued_at: u64,
    /// Hard delivery failures so far.
    pub attempts: u32,
    /// Sends the transport accepted and the target has not acknowledged.
    #[serde(default)]
    pub unacked: u32,
    /// Earliest unix-seconds at which the worker should (re)send.
    pub next_attempt_at: u64,
    /// Last error string, for operator-visible diagnostics. Truncated
    /// to ~200 chars to keep rows small.
    pub last_error: Option<String>,
    /// The id of the signed document last sent for this entry, while its
    /// acknowledgement is awaited.
    #[serde(default)]
    pub awaiting_ack: Option<String>,
    /// The ids of the most recent documents sent for this entry (at most
    /// [`MAX_TRACKED_SENDS`]), each with an `outbox-ack:` index; an
    /// acknowledgement of any of them settles it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sent_docs: Vec<String>,
}

/// What an `outbox-ack:` index holds: the row the document was sent for, and
/// a fingerprint of what it carried.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AckRef {
    row: String,
    #[serde(default)]
    fp: Option<String>,
}

/// What an `outbox-ref:` index holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefIndex {
    row: String,
    /// For a literal domain op, its Type URI.
    #[serde(default)]
    msg_type: Option<String>,
}

/// What the worker should do with the entry at the head of a target's queue.
#[derive(Debug, PartialEq, Eq)]
pub enum HeadAction {
    /// Send (or re-send) it now.
    Send,
    /// Leave it: an ack is awaited, or a backoff is running.
    Wait,
}

/// Decide what to do with a head entry at `now`.
pub fn head_action(entry: &OutboxEntry, now: u64) -> HeadAction {
    if entry.next_attempt_at > now {
        HeadAction::Wait
    } else {
        HeadAction::Send
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

mod metric {
    #[cfg(feature = "metrics")]
    pub(super) use did_hosting_common::server::metrics::{
        inc_outbox_delivery_failure as delivery_failure, inc_outbox_dropped as dropped,
        inc_outbox_enqueue_failure as enqueue_failure, inc_outbox_record_failure as record_failure,
        inc_outbox_unacked_resend as unacked_resend,
    };
    #[cfg(not(feature = "metrics"))]
    pub(super) fn delivery_failure() {}
    #[cfg(not(feature = "metrics"))]
    pub(super) fn dropped() {}
    #[cfg(not(feature = "metrics"))]
    pub(super) fn enqueue_failure() {}
    #[cfg(not(feature = "metrics"))]
    pub(super) fn record_failure() {}
    #[cfg(not(feature = "metrics"))]
    pub(super) fn unacked_resend() {}
}

/// Count and log an enqueue that failed: the change it carried reaches the
/// target only on its next registration.
pub fn note_enqueue_failure(target_did: &str, what: &str, error: &AppError) {
    metric::enqueue_failure();
    warn!(
        target_did,
        what,
        error = %error,
        "outbox: enqueue failed; the target converges on its next registration"
    );
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

const ROW_PREFIX: &str = "outbox:";
const MARKER_PREFIX: &str = "outbox-target:";

fn outbox_ks(store: &Store) -> Result<KeyspaceHandle, AppError> {
    store.keyspace(KS_OUTBOUND_QUEUE)
}

fn target_prefix(target_did: &str) -> String {
    format!("{ROW_PREFIX}{target_did}|")
}

fn row_key(target_did: &str, seq: u64, uuid_short: &str) -> String {
    format!("{}{seq:020}:{uuid_short}", target_prefix(target_did))
}

fn marker_key(target_did: &str) -> String {
    format!("{MARKER_PREFIX}{target_did}")
}

fn ack_key(target_did: &str, doc_id: &str) -> String {
    format!("outbox-ack:{target_did}|{doc_id}")
}

fn ref_key(target_did: &str, suffix: &str) -> String {
    format!("outbox-ref:{target_did}|{suffix}")
}

fn domain_op_ref(domain: &str) -> String {
    format!("domain-op|{domain}")
}

/// A microsecond stamp, strictly increasing within this process, so rows
/// staged back to back (in one batch) keep their order.
fn next_seq() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    let mut last = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(last + 1);
        match LAST.compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

fn new_row_key(target_did: &str) -> String {
    let uuid_short = uuid::Uuid::new_v4().simple().to_string();
    row_key(target_did, next_seq(), &uuid_short[..12])
}

fn truncated(err: &str) -> String {
    const MAX: usize = 200;
    if err.len() <= MAX {
        err.to_string()
    } else {
        // Cut on a character boundary: the text can carry a peer's own error
        // message, and slicing a multi-byte character in half panics.
        format!("{}…", &err[..err.floor_char_boundary(MAX)])
    }
}

/// Up to a quarter of `base` on top, so targets that failed together do not
/// retry in lockstep.
fn jittered(base: u64) -> u64 {
    base + rand::random::<u64>() % (base / 4 + 1)
}

/// The hard-failure backoff before jitter: 1 s doubling, capped.
fn compute_backoff(attempts: u32) -> u64 {
    1u64.checked_shl(attempts.min(16))
        .unwrap_or(MAX_BACKOFF_SECS)
        .min(MAX_BACKOFF_SECS)
}

/// The wait for an acknowledgement after the `unacked`-th unacknowledged
/// send, before jitter: [`ACK_TIMEOUT_SECS`] doubling, capped.
fn ack_wait(unacked: u32) -> u64 {
    ACK_TIMEOUT_SECS
        .saturating_mul(1u64.checked_shl(unacked.min(16)).unwrap_or(u64::MAX))
        .min(MAX_ACK_WAIT_SECS)
}

fn fingerprint(msg_type: &str, body: &Value) -> String {
    let digest = Sha256::new()
        .chain_update(msg_type.as_bytes())
        .chain_update([0u8])
        .chain_update(body.to_string().as_bytes())
        .finalize();
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Locks
// ---------------------------------------------------------------------------

/// Serialises, per target, the rewrites of a row with the removals that
/// retire it. The worker reads a row, records the send, delivers it, and may
/// rewrite it again; a removal in between — an acknowledgement, or
/// [`drop_queued`] superseding a purge — must not be undone by a rewrite, or
/// a dropped purge comes back, is re-signed with a fresh `issuedAt`, and
/// passes the edge's `stalePurge` check after the re-assign.
static TARGET_LOCKS: LazyLock<PathLocks> = LazyLock::new(PathLocks::new);

async fn target_guard(target_did: &str) -> PathGuard {
    TARGET_LOCKS.guard(target_did).await
}

// ---------------------------------------------------------------------------
// Enqueue
// ---------------------------------------------------------------------------

fn fresh_entry(
    target_did: &str,
    msg_type: &str,
    body: Value,
    subject: Option<Subject>,
) -> OutboxEntry {
    let now = now_epoch();
    OutboxEntry {
        target_did: target_did.to_string(),
        msg_type: msg_type.to_string(),
        body,
        subject,
        enqueued_at: now,
        attempts: 0,
        unacked: 0,
        next_attempt_at: now,
        last_error: None,
        awaiting_ack: None,
        sent_docs: Vec::new(),
    }
}

/// Add `entry` (and its target's marker) to `batch` under a fresh key.
fn stage_row(
    batch: &mut WriteBatch,
    ks: &KeyspaceHandle,
    entry: &OutboxEntry,
) -> Result<String, AppError> {
    let key = new_row_key(&entry.target_did);
    batch.insert(ks, key.clone(), entry)?;
    batch.insert_raw(ks, marker_key(&entry.target_did), Vec::new());
    Ok(key)
}

/// Persist a literal control→server message. Returns once the row is
/// durable; delivery is the worker's job. The caller wakes the worker
/// (`outbox_notify`), or uses [`enqueue_and_notify`].
pub async fn enqueue(
    store: &Store,
    target_did: &str,
    msg_type: &str,
    body: Value,
) -> Result<Vec<u8>, AppError> {
    let ks = outbox_ks(store)?;
    let mut batch = store.batch();
    let key = stage_row(
        &mut batch,
        &ks,
        &fresh_entry(target_did, msg_type, body, None),
    )?;
    batch.commit().await?;
    Ok(key.into_bytes())
}

/// Enqueue + wake the worker.
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

/// Enqueue a domain assign / unassign / purge (`{domain}` body), recording it
/// as the latest domain op queued for that domain and target.
pub async fn enqueue_domain_op(
    store: &Store,
    target_did: &str,
    msg_type: &str,
    domain: &str,
) -> Result<(), AppError> {
    let ks = outbox_ks(store)?;
    let mut batch = store.batch();
    let key = stage_row(
        &mut batch,
        &ks,
        &fresh_entry(target_did, msg_type, json!({ "domain": domain }), None),
    )?;
    batch.insert(
        &ks,
        ref_key(target_did, &domain_op_ref(domain)),
        &RefIndex {
            row: key,
            msg_type: Some(msg_type.to_string()),
        },
    )?;
    batch.commit().await
}

/// Whether the latest domain op queued for `domain` and `target_did` is
/// `msg_type` and still queued.
pub async fn domain_op_queued(
    store: &Store,
    target_did: &str,
    msg_type: &str,
    domain: &str,
) -> Result<bool, AppError> {
    let ks = outbox_ks(store)?;
    match ks
        .get::<RefIndex>(ref_key(target_did, &domain_op_ref(domain)))
        .await?
    {
        Some(r) if r.msg_type.as_deref() == Some(msg_type) => ks.contains_key(r.row).await,
        _ => Ok(false),
    }
}

/// Whether a coalescing `subject` already has a row queued for `target_did`.
async fn ref_queued(ks: &KeyspaceHandle, target_did: &str, suffix: &str) -> Result<bool, AppError> {
    match ks.get::<RefIndex>(ref_key(target_did, suffix)).await? {
        Some(r) => ks.contains_key(r.row).await,
        None => Ok(false),
    }
}

/// Stage a reference row for `subject` into `batch`, unless a coalescing
/// subject is already queued for `target_did`. Returns whether a row was
/// staged.
///
/// The caller holds the subject's lock ([`subject_guard`]) from this call
/// through the batch's commit: the check and the settle of a queued row are
/// serialised by it.
pub(crate) async fn stage_ref(
    batch: &mut WriteBatch,
    store: &Store,
    target_did: &str,
    subject: Subject,
) -> Result<bool, AppError> {
    let ks = outbox_ks(store)?;
    let suffix = subject.coalesce_key();
    if let Some(suffix) = suffix.as_deref()
        && ref_queued(&ks, target_did, suffix).await?
    {
        return Ok(false);
    }
    let entry = fresh_entry(
        target_did,
        subject.nominal_type(),
        Value::Null,
        Some(subject),
    );
    let key = stage_row(batch, &ks, &entry)?;
    if let Some(suffix) = suffix {
        batch.insert(
            &ks,
            ref_key(target_did, &suffix),
            &RefIndex {
                row: key,
                msg_type: None,
            },
        )?;
    }
    Ok(true)
}

/// Enqueue a reference row on its own, taking the subject's lock. Returns
/// whether a row was queued (`false`: one already was).
pub async fn enqueue_ref(
    state: &AppState,
    target_did: &str,
    subject: Subject,
) -> Result<bool, AppError> {
    let _guard = subject_guard(state, &subject).await;
    enqueue_ref_locked(state, target_did, subject).await
}

/// [`enqueue_ref`] for a caller already holding the subject's lock.
pub(crate) async fn enqueue_ref_locked(
    state: &AppState,
    target_did: &str,
    subject: Subject,
) -> Result<bool, AppError> {
    let mut batch = state.store.batch();
    let staged = stage_ref(&mut batch, &state.store, target_did, subject).await?;
    if staged {
        batch.commit().await?;
    }
    Ok(staged)
}

/// Enqueue a `sync/batch` reference row for `mnemonics` (a resync's batch).
/// Not coalesced: a slot changed after this is queued as a row of its own.
pub async fn enqueue_batch(
    store: &Store,
    target_did: &str,
    mnemonics: Vec<String>,
) -> Result<Vec<u8>, AppError> {
    let ks = outbox_ks(store)?;
    let mut batch = store.batch();
    let subject = Subject::DidBatch { mnemonics };
    let entry = fresh_entry(
        target_did,
        subject.nominal_type(),
        Value::Null,
        Some(subject),
    );
    let key = stage_row(&mut batch, &ks, &entry)?;
    batch.commit().await?;
    Ok(key.into_bytes())
}

/// Mark `row` as the last row of a resync under `suffix`, so the next resync
/// can tell that one is still queued ([`resync_batch_queued`]).
pub async fn mark_resync_batch(
    store: &Store,
    target_did: &str,
    suffix: &str,
    row: Vec<u8>,
) -> Result<(), AppError> {
    outbox_ks(store)?
        .insert(
            ref_key(target_did, suffix),
            &RefIndex {
                row: String::from_utf8_lossy(&row).into_owned(),
                msg_type: None,
            },
        )
        .await
}

/// Whether the row marked under `suffix` ([`mark_resync_batch`]) is still
/// queued.
pub async fn resync_batch_queued(
    store: &Store,
    target_did: &str,
    suffix: &str,
) -> Result<bool, AppError> {
    ref_queued(&outbox_ks(store)?, target_did, suffix).await
}

// ---------------------------------------------------------------------------
// Reading the queue
// ---------------------------------------------------------------------------

fn parse_row(target_did: &str, key: &[u8], value: &[u8]) -> Option<OutboxEntry> {
    match serde_json::from_slice::<OutboxEntry>(value) {
        Ok(e) => Some(e),
        Err(e) => {
            warn!(
                target_did,
                key = %String::from_utf8_lossy(key),
                error = %e,
                "outbox: dropping malformed entry"
            );
            None
        }
    }
}

/// Every target with a marker: those with (possibly) queued rows.
pub async fn list_targets(store: &Store) -> Result<Vec<String>, AppError> {
    let mut targets: Vec<String> = outbox_ks(store)?
        .prefix_keys_raw(MARKER_PREFIX)
        .await?
        .into_iter()
        .filter_map(|k| {
            String::from_utf8(k)
                .ok()?
                .strip_prefix(MARKER_PREFIX)
                .map(str::to_string)
        })
        .collect();
    targets.sort();
    targets.dedup();
    Ok(targets)
}

/// The oldest queued row for `target_did`, read with a one-row page on a
/// backend whose pages are ordered, and by the smallest key otherwise.
pub async fn head(
    store: &Store,
    target_did: &str,
) -> Result<Option<(Vec<u8>, OutboxEntry)>, AppError> {
    let ks = outbox_ks(store)?;
    let prefix = target_prefix(target_did);
    // A malformed row is removed and the next one read, a bounded number of
    // times per call.
    for _ in 0..16 {
        let found = head_raw(&ks, &prefix).await?;
        let Some((key, value)) = found else {
            return Ok(None);
        };
        match parse_row(target_did, &key, &value) {
            Some(entry) => return Ok(Some((key, entry))),
            None => ks.remove(key).await?,
        }
    }
    Ok(None)
}

async fn head_raw(
    ks: &KeyspaceHandle,
    prefix: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, AppError> {
    let mut cursor = None;
    loop {
        match ks.prefix_page_raw(prefix, cursor, 1).await? {
            Some(page) if page.ordered => {
                if let Some(first) = page.rows.into_iter().next() {
                    return Ok(Some(first));
                }
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => return Ok(None),
                }
            }
            // Hash-ordered or unpaged: the smallest key, from the keys alone.
            _ => {
                for _ in 0..3 {
                    let Some(key) = ks.prefix_keys_raw(prefix).await?.into_iter().min() else {
                        return Ok(None);
                    };
                    if let Some(value) = ks.get_raw(key.clone()).await? {
                        return Ok(Some((key, value)));
                    }
                }
                return Ok(None);
            }
        }
    }
}

/// Pending entries for one target, in enqueue order — the whole queue. For
/// rare paths ([`drop_queued`]) and tests; the worker reads only the head.
pub async fn list_pending_for_target(
    store: &Store,
    target_did: &str,
) -> Result<Vec<(Vec<u8>, OutboxEntry)>, AppError> {
    let ks = outbox_ks(store)?;
    let mut out = Vec::new();
    for (k, v) in ks.prefix_iter_raw(target_prefix(target_did)).await? {
        match parse_row(target_did, &k, &v) {
            Some(e) => out.push((k, e)),
            None => ks.remove(k).await?,
        }
    }
    out.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(out)
}

/// How many rows are queued for `target_did`, and when the oldest was
/// enqueued — for the replication gauges.
pub async fn target_backlog(
    store: &Store,
    target_did: &str,
) -> Result<(usize, Option<u64>), AppError> {
    let ks = outbox_ks(store)?;
    let count = ks.prefix_count(target_prefix(target_did)).await?;
    if count == 0 {
        return Ok((0, None));
    }
    let oldest = head(store, target_did).await?.map(|(_, e)| e.enqueued_at);
    Ok((count, oldest))
}

/// Remove `target_did`'s marker if its queue is empty. An enqueue racing the
/// removal either committed before the re-check (seen, the marker is put
/// back) or after it (it wrote the marker itself).
async fn clear_marker_if_empty(store: &Store, target_did: &str) -> Result<(), AppError> {
    let ks = outbox_ks(store)?;
    ks.remove(marker_key(target_did)).await?;
    if head_raw(&ks, &target_prefix(target_did)).await?.is_some() {
        ks.insert_raw(marker_key(target_did), Vec::new()).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rewriting and retiring rows
// ---------------------------------------------------------------------------

/// Remove a row with nothing else to clean up (tests, and malformed rows).
pub async fn remove(store: &Store, key: Vec<u8>) -> Result<(), AppError> {
    outbox_ks(store)?.remove(key).await
}

/// Retire `key` (whose current content is `entry`): the row, its ack indexes,
/// and its coalescing index if it still points here. Under the target lock,
/// so no in-flight rewrite resurrects it. A coalescing row is retired only
/// under its subject's lock too — the caller holds it.
async fn retire(store: &Store, key: &[u8], entry: &OutboxEntry) -> Result<(), AppError> {
    let _guard = target_guard(&entry.target_did).await;
    let ks = outbox_ks(store)?;
    let mut batch = store.batch();
    batch.remove(&ks, key.to_vec());
    for doc in entry.sent_docs.iter().chain(entry.awaiting_ack.iter()) {
        batch.remove(&ks, ack_key(&entry.target_did, doc));
    }
    if let Some(suffix) = entry.subject.as_ref().and_then(Subject::coalesce_key) {
        let rk = ref_key(&entry.target_did, &suffix);
        if ks
            .get::<RefIndex>(rk.clone())
            .await?
            .is_some_and(|r| r.row.as_bytes() == key)
        {
            batch.remove(&ks, rk);
        }
    }
    batch.commit().await
}

/// Retire a row, taking its subject's lock first.
async fn retire_locked(state: &AppState, key: &[u8], entry: &OutboxEntry) -> Result<(), AppError> {
    let _subject = match entry.subject.as_ref() {
        Some(s) => subject_guard(state, s).await,
        None => None,
    };
    retire(&state.store, key, entry).await
}

/// Rewrite `key` with `next` only if the row is still queued, applying the
/// ack-index changes in the same batch. Returns whether it was.
async fn rewrite_if_present(
    store: &Store,
    key: &[u8],
    next: &OutboxEntry,
    add_ack: Option<(&str, AckRef)>,
    drop_acks: &[String],
) -> Result<bool, AppError> {
    let _guard = target_guard(&next.target_did).await;
    let ks = outbox_ks(store)?;
    if !ks.contains_key(key.to_vec()).await? {
        return Ok(false);
    }
    let mut batch = store.batch();
    batch.insert(&ks, key.to_vec(), next)?;
    if let Some((doc, ack)) = add_ack {
        batch.insert(&ks, ack_key(&next.target_did, doc), &ack)?;
    }
    for doc in drop_acks {
        batch.remove(&ks, ack_key(&next.target_did, doc));
    }
    batch.commit().await?;
    Ok(true)
}

/// Record that the entry is about to be handed to the transport as document
/// `doc_id` carrying content with fingerprint `fp`. Written *before* the
/// send, so an acknowledgement that arrives first still finds the row. The
/// entry then waits `ack_wait` for the target's ack. Returns the entry as
/// written, or `None` if the row was removed meanwhile (send nothing).
pub async fn record_sent(
    store: &Store,
    key: Vec<u8>,
    entry: &OutboxEntry,
    doc_id: &str,
) -> Result<Option<OutboxEntry>, AppError> {
    record_sending(store, &key, entry, doc_id, None).await
}

async fn record_sending(
    store: &Store,
    key: &[u8],
    entry: &OutboxEntry,
    doc_id: &str,
    fp: Option<String>,
) -> Result<Option<OutboxEntry>, AppError> {
    let mut sent_docs = entry.sent_docs.clone();
    // A row from before `sent_docs` existed carries only its last document.
    if let Some(prev) = entry.awaiting_ack.as_ref()
        && !sent_docs.contains(prev)
    {
        sent_docs.push(prev.clone());
    }
    sent_docs.push(doc_id.to_string());
    let overflow = sent_docs.len().saturating_sub(MAX_TRACKED_SENDS);
    let dropped: Vec<String> = sent_docs.drain(..overflow).collect();
    let next = OutboxEntry {
        unacked: entry.unacked.saturating_add(1),
        next_attempt_at: now_epoch().saturating_add(jittered(ack_wait(entry.unacked))),
        awaiting_ack: Some(doc_id.to_string()),
        sent_docs,
        ..entry.clone()
    };
    let ack = AckRef {
        row: String::from_utf8_lossy(key).into_owned(),
        fp,
    };
    Ok(
        rewrite_if_present(store, key, &next, Some((doc_id, ack)), &dropped)
            .await?
            .then_some(next),
    )
}

/// Delivering `entry` failed with `err`: count a hard failure and back off.
/// Any ack index already written stays — a send that reported failure may
/// still have arrived. A row removed meanwhile stays removed.
pub async fn record_failure(
    store: &Store,
    key: Vec<u8>,
    entry: &OutboxEntry,
    err: &str,
) -> Result<(), AppError> {
    let next = OutboxEntry {
        attempts: entry.attempts.saturating_add(1),
        last_error: Some(truncated(err)),
        next_attempt_at: now_epoch()
            .saturating_add(jittered(compute_backoff(entry.attempts.saturating_add(1)))),
        awaiting_ack: None,
        ..entry.clone()
    };
    rewrite_if_present(store, &key, &next, None, &[]).await?;
    Ok(())
}

/// [`record_sent`] for a [`Prepared`] entry: the fingerprint of what it
/// carries is recorded with the document, so its ack settles it only while
/// that is still the current state.
pub async fn record_prepared_sent(
    store: &Store,
    key: Vec<u8>,
    prepared: &Prepared,
    doc_id: &str,
) -> Result<Option<OutboxEntry>, AppError> {
    record_sending(
        store,
        &key,
        &prepared.entry,
        doc_id,
        prepared.fingerprint.clone(),
    )
    .await
}

/// Drop every literal entry queued for `target_did` under `msg_type` whose
/// body `matches` — an op a later decision has superseded. An entry already
/// sent and awaiting its acknowledgement is dropped too: if the target
/// applies it after all, the ack settles nothing. Returns how many were
/// dropped. Lists the target's queue: for rare operator actions only.
pub async fn drop_queued(
    store: &Store,
    target_did: &str,
    msg_type: &str,
    matches: impl Fn(&Value) -> bool,
) -> Result<usize, AppError> {
    let mut dropped = 0;
    for (key, entry) in list_pending_for_target(store, target_did).await? {
        if entry.subject.is_none() && entry.msg_type == msg_type && matches(&entry.body) {
            retire(store, &key, &entry).await?;
            dropped += 1;
        }
    }
    Ok(dropped)
}

/// The target `signer` acknowledged (or terminally refused) document `doc_id`:
/// settle the entry it was sent for. Returns whether one was found.
///
/// A reference row settles only if what the document carried is still what
/// would be sent now; otherwise the slot (or domain) changed after the send
/// and the row is re-armed to send the newer state.
///
/// `signer` must be the proven issuer of the acknowledgement — an entry is
/// only ever settled on its own target's signature, so no other party can
/// make the control plane forget an op it has not delivered.
pub async fn acknowledge(state: &AppState, signer: &str, doc_id: &str) -> Result<bool, AppError> {
    let ks = outbox_ks(&state.store)?;
    let ak = ack_key(signer, doc_id);
    let Some(ack) = ks.get::<AckRef>(ak.clone()).await? else {
        return Ok(false);
    };
    let key = ack.row.clone().into_bytes();
    let peek = match ks.get::<OutboxEntry>(key.clone()).await? {
        Some(e) if e.target_did == signer => e,
        _ => {
            // Its row is gone (settled through another of its documents, or
            // dropped): the index is stale.
            ks.remove(ak).await?;
            return Ok(false);
        }
    };
    let _subject = match peek.subject.as_ref() {
        Some(s) => subject_guard(state, s).await,
        None => None,
    };
    // Re-read under the subject's lock: the row may have been re-armed or
    // retired while we waited.
    let Some(entry) = ks.get::<OutboxEntry>(key.clone()).await? else {
        ks.remove(ak).await?;
        return Ok(false);
    };
    let current = match entry.subject {
        Some(Subject::Did { .. } | Subject::DomainUpsert { .. }) => {
            match prepare(state, &entry).await {
                Ok(Some(p)) => p.fingerprint,
                Ok(None) => None,
                Err(e) => {
                    // Cannot tell whether the ack was of the current state: send
                    // it again rather than risk settling a stale one.
                    warn!(target_did = signer, error = %e, "outbox: cannot read the subject to settle an ack; re-arming");
                    Some(String::new())
                }
            }
        }
        _ => None,
    };
    let stale = entry
        .subject
        .as_ref()
        .is_some_and(|s| s.coalesce_key().is_some())
        && current.is_some()
        && current != ack.fp;
    if stale {
        let now = now_epoch();
        let next = OutboxEntry {
            enqueued_at: now,
            attempts: 0,
            unacked: 0,
            next_attempt_at: now,
            last_error: None,
            awaiting_ack: None,
            ..entry.clone()
        };
        rewrite_if_present(
            &state.store,
            &key,
            &next,
            None,
            std::slice::from_ref(&doc_id.to_string()),
        )
        .await?;
        debug!(
            target_did = signer,
            doc_id, "outbox: acknowledged a superseded state; re-armed"
        );
    } else {
        retire(&state.store, &key, &entry).await?;
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Materialising and sending
// ---------------------------------------------------------------------------

/// Max DIDs per `sync/batch`, and max serialized bytes. Bounds the frame
/// (each DID carries a full `did.jsonl`) while collapsing the resync burst.
pub const SYNC_BATCH_MAX_COUNT: usize = 50;
pub const SYNC_BATCH_MAX_BYTES: usize = 512 * 1024;

/// What an entry is sent as, built from the store as it is now.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub msg_type: String,
    pub body: Value,
    /// Of what a coalescing row carries; `None` for other rows.
    pub fingerprint: Option<String>,
    /// The entry to record the send against — a batch trimmed to what fit.
    pub entry: OutboxEntry,
    /// Slots of a batch that did not fit its frame; queued as rows of their
    /// own before the send.
    pub overflow: Vec<String>,
}

/// The `sync/update` body for slot `mnemonic` as it stands, `Ok(None)` when it
/// has no published content (so it is synced as deleted), or `Err(())` when
/// its content does not fit `sync/update/0.2` (not sent at all).
async fn slot_update(
    state: &AppState,
    mnemonic: &str,
) -> Result<Option<Result<Value, ()>>, AppError> {
    let Some(record) = state
        .dids_ks
        .get::<DidRecord>(did_ops::did_key(mnemonic))
        .await?
    else {
        return Ok(None);
    };
    if record.version_count == 0 {
        return Ok(None);
    }
    let Some(log) = state
        .dids_ks
        .get_raw(did_ops::content_log_key(mnemonic))
        .await?
    else {
        return Ok(None);
    };
    let Ok(log) = String::from_utf8(log) else {
        warn!(
            mnemonic,
            "DID sync: invalid UTF-8 in log content; not sending it"
        );
        return Ok(Some(Err(())));
    };
    let witness = state
        .dids_ks
        .get_raw(did_ops::content_witness_key(mnemonic))
        .await?
        .and_then(|b| String::from_utf8(b).ok());
    Ok(Some(
        crate::server_push::sync_update_body(&record, log, witness).ok_or(()),
    ))
}

/// Build what `entry` is sent as: its literal body, or — for a reference
/// row — the subject's current state. `Ok(None)`: nothing to send (a domain
/// since deleted, a slot whose content cannot be replicated, a batch whose
/// slots are all gone); the row is retired.
pub async fn prepare(state: &AppState, entry: &OutboxEntry) -> Result<Option<Prepared>, AppError> {
    let plain = |msg_type: &str, body: Value, fingerprint| Prepared {
        msg_type: msg_type.to_string(),
        body,
        fingerprint,
        entry: entry.clone(),
        overflow: Vec::new(),
    };
    let Some(subject) = entry.subject.as_ref() else {
        return Ok(Some(plain(&entry.msg_type, entry.body.clone(), None)));
    };
    match subject {
        Subject::Did { mnemonic } => {
            let (msg_type, body) = match slot_update(state, mnemonic).await? {
                Some(Ok(body)) => (MSG_SYNC_UPDATE, body),
                Some(Err(())) => return Ok(None),
                None => (MSG_SYNC_DELETE, json!({ "mnemonic": mnemonic })),
            };
            let fp = fingerprint(msg_type, &body);
            Ok(Some(plain(msg_type, body, Some(fp))))
        }
        Subject::DomainUpsert { domain } => {
            let Some(stored) =
                did_hosting_common::server::domain::get_domain(&state.store, domain).await?
            else {
                return Ok(None);
            };
            let body =
                json!({ "entry": did_hosting_common::server::domain::wire::to_spec(&stored) });
            let fp = fingerprint(MSG_REPLICA_DOMAIN_UPSERT, &body);
            Ok(Some(plain(MSG_REPLICA_DOMAIN_UPSERT, body, Some(fp))))
        }
        Subject::DidBatch { mnemonics } => {
            let mut updates = Vec::new();
            let mut kept = Vec::new();
            let mut overflow = Vec::new();
            let mut bytes = 0usize;
            for mnemonic in mnemonics {
                if !overflow.is_empty() {
                    overflow.push(mnemonic.clone());
                    continue;
                }
                let Some(Ok(body)) = slot_update(state, mnemonic).await? else {
                    continue;
                };
                let size = body.to_string().len();
                if !updates.is_empty() && bytes + size > SYNC_BATCH_MAX_BYTES {
                    overflow.push(mnemonic.clone());
                    continue;
                }
                bytes += size;
                updates.push(body);
                kept.push(mnemonic.clone());
            }
            if updates.is_empty() {
                return Ok(None);
            }
            let mut trimmed = entry.clone();
            trimmed.subject = Some(Subject::DidBatch { mnemonics: kept });
            Ok(Some(Prepared {
                msg_type: MSG_SYNC_BATCH.to_string(),
                body: json!({ "updates": updates }),
                fingerprint: None,
                entry: trimmed,
                overflow,
            }))
        }
    }
}

/// The signed Trust Task document `prepared` is delivered as, from
/// `control_did` to `target_did`.
///
/// Built — and signed — at delivery time, not at enqueue time, so a retried
/// entry carries a fresh `issuedAt` and never ages out of the receiver's
/// freshness window while it waits in the queue. The receiving edge applies
/// it only if the proof binds it to this control plane
/// (`verify_control_plane`), so an entry this node cannot sign is not sent.
pub async fn signed_document(
    control_did: &str,
    target_did: &str,
    prepared: &Prepared,
    signer: &Secret,
) -> Result<trust_tasks_rs::TrustTask<Value>, Box<dyn std::error::Error + Send + Sync>> {
    build_signed_request(
        &prepared.msg_type,
        control_did,
        target_did,
        prepared.body.clone(),
        signer,
    )
    .await
}

/// Everything a tick needs to send, shared by the per-target tasks.
struct SendCtx {
    svc: DIDCommService,
    control_did: String,
    signer: Secret,
    fallback: TransportFallback,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Entries handed to the transport this tick (awaiting their ack).
    pub sent: u64,
    /// Targets whose head is backing off or awaiting its ack, or failed.
    pub deferred: u64,
    /// Entries dropped past their retry budget.
    pub dropped: u64,
    /// Reference rows with nothing left to send, retired.
    pub skipped: u64,
}

impl TickReport {
    fn add(&mut self, other: TickReport) {
        self.sent += other.sent;
        self.deferred += other.deferred;
        self.dropped += other.dropped;
        self.skipped += other.skipped;
    }
}

/// Process every target's queue once, up to [`MAX_CONCURRENT_TARGETS`] at a
/// time. Returns counts for telemetry.
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
    if targets.is_empty() {
        return TickReport::default();
    }

    // Every entry goes out signed; without the key there is nothing an edge
    // would accept, so leave the queue intact for a later tick.
    let signer = match crate::signing::control_signing_secret(state, &control_did) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "outbox tick: cannot sign outbound documents; skipping");
            return TickReport::default();
        }
    };

    // Control's own configured mediator, used as the send fallback when a
    // target's document advertises no transport.
    let fallback = TransportFallback::from_config(
        state.config.mediator_did.as_deref(),
        state.config.features.tsp,
    );
    let ctx = Arc::new(SendCtx {
        svc,
        control_did,
        signer,
        fallback,
    });

    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TARGETS));
    let mut tasks = tokio::task::JoinSet::new();
    for target in targets {
        let state = state.clone();
        let ctx = ctx.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await;
            process_target(&state, &ctx, &target).await
        });
    }
    let mut report = TickReport::default();
    while let Some(done) = tasks.join_next().await {
        match done {
            Ok(r) => report.add(r),
            Err(e) => warn!(error = %e, "outbox tick: a target's task failed"),
        }
    }
    report
}

/// Service one target's queue: drop or skip what is due to go, then send the
/// head if it is due.
async fn process_target(state: &AppState, ctx: &SendCtx, target: &str) -> TickReport {
    let mut report = TickReport::default();
    let now = now_epoch();
    // Bounded: each pass removes a row or ends the loop.
    for _ in 0..256 {
        let (key, entry) = match head(&state.store, target).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                if let Err(e) = clear_marker_if_empty(&state.store, target).await {
                    debug!(target_did = %target, error = %e, "outbox: failed to clear an empty target");
                }
                break;
            }
            Err(e) => {
                warn!(target_did = %target, error = %e, "outbox tick: head read failed");
                break;
            }
        };
        // Poison-pill / age-out checks first, ahead of next_attempt_at, so the
        // queue stays bounded even when a target has been dead for days.
        if entry.attempts >= MAX_ATTEMPTS
            || entry.unacked >= MAX_UNACKED && head_action(&entry, now) == HeadAction::Send
            || now.saturating_sub(entry.enqueued_at) >= MAX_AGE_SECS
        {
            warn!(
                target_did = %target,
                msg_type = %entry.msg_type,
                attempts = entry.attempts,
                unacked = entry.unacked,
                age_secs = now.saturating_sub(entry.enqueued_at),
                last_error = entry.last_error.as_deref().unwrap_or(""),
                "outbox: dropping entry past its retry budget; the target converges on its next registration"
            );
            metric::dropped();
            if let Err(e) = retire_locked(state, &key, &entry).await {
                metric::record_failure();
                warn!(target_did = %target, error = %e, "outbox: failed to drop an entry");
                break;
            }
            report.dropped += 1;
            continue;
        }
        if head_action(&entry, now) == HeadAction::Wait {
            // Head-of-line is backing off or awaiting its ack — stop here so
            // the order holds.
            report.deferred += 1;
            break;
        }
        if entry.awaiting_ack.is_some() {
            metric::unacked_resend();
            debug!(
                target_did = %target,
                msg_type = %entry.msg_type,
                unacked = entry.unacked,
                "outbox: no acknowledgement within the wait; re-sending"
            );
        }

        let prepared = match prepare(state, &entry).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                debug!(target_did = %target, subject = ?entry.subject, "outbox: nothing left to send; retiring");
                if let Err(e) = retire_locked(state, &key, &entry).await {
                    metric::record_failure();
                    warn!(target_did = %target, error = %e, "outbox: failed to retire an entry");
                    break;
                }
                report.skipped += 1;
                continue;
            }
            Err(e) => {
                fail(state, &key, &entry, &format!("reading what to send: {e}")).await;
                report.deferred += 1;
                break;
            }
        };
        for mnemonic in &prepared.overflow {
            if let Err(e) = enqueue_ref(
                state,
                target,
                Subject::Did {
                    mnemonic: mnemonic.clone(),
                },
            )
            .await
            {
                note_enqueue_failure(target, "batch overflow", &e);
            }
        }

        let doc = match signed_document(&ctx.control_did, target, &prepared, &ctx.signer).await {
            Ok(doc) => doc,
            Err(e) => {
                fail(state, &key, &prepared.entry, &format!("signing: {e}")).await;
                report.deferred += 1;
                break;
            }
        };
        let sent = match record_sending(
            &state.store,
            &key,
            &prepared.entry,
            &doc.id,
            prepared.fingerprint.clone(),
        )
        .await
        {
            Ok(Some(sent)) => sent,
            // Retired while we prepared it (acknowledged, or superseded).
            Ok(None) => continue,
            Err(e) => {
                // Not recorded, so not sent: an ack could not find the row.
                metric::record_failure();
                warn!(target_did = %target, error = %e, "outbox: failed to record a send; not sending");
                break;
            }
        };

        match send_trust_task(
            &ctx.svc,
            "control",
            &ctx.control_did,
            target,
            &doc,
            &ctx.fallback,
            Peers::new(
                state.did_resolver.as_ref(),
                state.trust_tasks_verifier.as_deref(),
            ),
        )
        .await
        {
            Ok(transport) => {
                debug!(
                    target_did = %target,
                    msg_type = %prepared.msg_type,
                    unacked = sent.unacked,
                    doc_id = %doc.id,
                    ?transport,
                    "outbox: sent; awaiting acknowledgement"
                );
                report.sent += 1;
                // HTTPS carries its own ack: `send_trust_task` already
                // verified the reply is signed by the target, addressed back
                // to us, and threaded to this exact document before returning
                // `Ok`. There is no later ack to wait for, so settle now.
                if transport == PeerTransport::Https {
                    match acknowledge(state, target, &doc.id).await {
                        Ok(true) => {
                            debug!(target_did = %target, doc_id = %doc.id, "outbox: HTTPS send self-acknowledged")
                        }
                        Ok(false) => warn!(
                            target_did = %target,
                            doc_id = %doc.id,
                            "outbox: HTTPS send succeeded but found no matching row to settle"
                        ),
                        Err(e) => {
                            metric::record_failure();
                            warn!(target_did = %target, doc_id = %doc.id, error = %e, "outbox: failed to self-acknowledge HTTPS send");
                        }
                    }
                }
            }
            Err(e) => {
                // A refused frame is a hard failure, not an unacknowledged
                // send.
                let undone = OutboxEntry {
                    unacked: sent.unacked.saturating_sub(1),
                    ..sent
                };
                fail(state, &key, &undone, &e.to_string()).await;
                report.deferred += 1;
            }
        }
        // One in flight per target: the next entry goes once this one is
        // acknowledged (`acknowledge` wakes the worker).
        break;
    }
    report
}

/// Record a hard failure, logging (and counting) one that could not be.
async fn fail(state: &AppState, key: &[u8], entry: &OutboxEntry, err: &str) {
    metric::delivery_failure();
    warn!(
        target_did = %entry.target_did,
        msg_type = %entry.msg_type,
        attempts = entry.attempts + 1,
        error = %err,
        "outbox: delivery failed; will retry after backoff"
    );
    if let Err(e) = record_failure(&state.store, key.to_vec(), entry, err).await {
        metric::record_failure();
        warn!(
            target_did = %entry.target_did,
            error = %e,
            "outbox: failed to record a delivery failure; the entry is retried without backoff"
        );
    }
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// Re-key rows written by earlier versions (`outbox:{target}:{micros}:{uuid}`)
/// into the current layout, keeping their order, with a target marker and —
/// for one awaiting its ack — the ack index, so a late ack of a document sent
/// before the upgrade still settles it. Also restores any missing target
/// marker. Idempotent; run on boot before the first tick.
pub async fn migrate_legacy_rows(store: &Store) -> Result<usize, AppError> {
    let ks = outbox_ks(store)?;
    let mut migrated = 0;
    let mut targets = std::collections::BTreeSet::new();
    for key in ks.prefix_keys_raw(ROW_PREFIX).await? {
        let Ok(k) = std::str::from_utf8(&key) else {
            continue;
        };
        let rest = &k[ROW_PREFIX.len()..];
        if let Some((target, _)) = rest.split_once('|') {
            targets.insert(target.to_string());
            continue;
        }
        let Some(value) = ks.get_raw(key.clone()).await? else {
            continue;
        };
        let Ok(entry) = serde_json::from_slice::<OutboxEntry>(&value) else {
            warn!(key = k, "outbox: dropping malformed legacy entry");
            ks.remove(key).await?;
            continue;
        };
        // `…:{micros}:{uuid}` — the DID itself contains ':'.
        let mut tail = rest.rsplitn(3, ':');
        let (uuid, micros) = (tail.next().unwrap_or(""), tail.next().unwrap_or(""));
        let Ok(micros) = micros.parse::<u64>() else {
            warn!(
                key = k,
                "outbox: dropping legacy entry with an unreadable key"
            );
            ks.remove(key).await?;
            continue;
        };
        let new_key = row_key(&entry.target_did, micros, uuid);
        let mut batch = store.batch();
        batch.insert_raw(&ks, new_key.clone(), value);
        batch.insert_raw(&ks, marker_key(&entry.target_did), Vec::new());
        if let Some(doc) = entry.awaiting_ack.as_deref() {
            batch.insert(
                &ks,
                ack_key(&entry.target_did, doc),
                &AckRef {
                    row: new_key,
                    fp: None,
                },
            )?;
        }
        batch.remove(&ks, key);
        batch.commit().await?;
        targets.insert(entry.target_did);
        migrated += 1;
    }
    for target in targets {
        ks.insert_raw(marker_key(&target), Vec::new()).await?;
    }
    if migrated > 0 {
        info!(
            migrated,
            "outbox: re-keyed entries queued by an earlier version"
        );
    }
    Ok(migrated)
}

/// Long-running worker. Wakes on [`AppState::outbox_notify`] for low-
/// latency happy path; falls back to a 30-s tick to retry backed-off
/// entries when no fresh enqueue fires the notify.
pub async fn run_outbox_loop(
    state: AppState,
    notify: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
) {
    if let Err(e) = migrate_legacy_rows(&state.store).await {
        warn!(error = %e, "outbox: migrating queued entries failed; retried on next start");
    }
    let mut ticker = tokio::time::interval(DEFAULT_OUTBOX_TICK);
    ticker.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let report = run_tick(&state).await;
                if report.sent > 0 || report.dropped > 0 {
                    info!(?report, "outbox tick");
                }
            }
            _ = notify.notified() => {
                let report = run_tick(&state).await;
                if report.sent > 0 || report.dropped > 0 {
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
#[path = "outbox_tests.rs"]
mod tests;

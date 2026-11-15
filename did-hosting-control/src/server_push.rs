//! Durable push of control-plane mutations to registered server
//! instances via the [`crate::outbox`] queue.
//!
//! Every `send_*` / `notify_servers_*` / `fanout_*` function in this
//! module persists outbound DIDComm messages to the outbox keyspace
//! and signals the outbox worker. The worker is responsible for
//! actual delivery + retry; the helpers here only build bodies and
//! enqueue. Returning Ok means "enqueued durably", NOT "the recipient
//! has acknowledged".
//!
//! See [`crate::outbox`] for delivery semantics, backoff, and poison-
//! pill behaviour. Recipients of every control→server message type
//! handled here are idempotent — the at-least-once delivery
//! guarantee is safe.

use did_hosting_common::did_ops::{self, DidRecord};
use did_hosting_common::didcomm_types::*;
use tracing::{debug, info, warn};

use crate::registry::{self, ServiceType};
use crate::server::AppState;

/// What a registering server reports holding in one slot (an entry of the
/// `preloaded_dids` in its register payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedDid {
    /// The DID the slot holds. `None` from a server that did not say — which
    /// never counts as current.
    pub did_id: Option<String>,
    pub version_count: u64,
    /// The slot's disabled state as the server holds it. `None` from a server
    /// that did not say, which is then not compared.
    pub disabled: Option<bool>,
}

/// Whether a server that reports `reported` for a slot already holds the
/// control plane's `record` for it, so nothing need be pushed.
///
/// Both the **identity** and the version must match: a DID deleted and
/// re-created at the same mnemonic has a new identifier but may well have the
/// same number of versions, and an edge that missed the delete (offline past
/// its outbox budget, say) would otherwise keep serving the old DID. On a
/// mismatch the new log is pushed; the edge's own per-identity high-water mark
/// still refuses anything that would roll a DID back.
///
/// A server that reports the slot's `disabled` state must also hold the
/// control plane's: a disable it missed is re-sent with the content.
pub fn edge_is_current(record: &DidRecord, reported: Option<&ReportedDid>) -> bool {
    reported.is_some_and(|have| {
        have.did_id.is_some()
            && have.did_id == record.did_id
            && have.version_count >= record.version_count
            && have.disabled.is_none_or(|d| d == record.disabled)
    })
}

/// Parse the `preloaded_dids` of a register payload into mnemonic →
/// [`ReportedDid`]. Absent or malformed → empty, i.e. a full push.
pub fn parse_reported(body: &serde_json::Value) -> std::collections::HashMap<String, ReportedDid> {
    body.get("preloaded_dids")
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let mnemonic = e.get("mnemonic")?.as_str()?.to_string();
                    let version_count = e.get("version_count")?.as_u64()?;
                    let did_id = e.get("did_id").and_then(|v| v.as_str()).map(String::from);
                    let disabled = e.get("disabled").and_then(|v| v.as_bool());
                    Some((
                        mnemonic,
                        ReportedDid {
                            did_id,
                            version_count,
                            disabled,
                        },
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Resync a (re-)registering server: its domains first — records, statuses
/// and unsettled assign/unassign/purge ops ([`sync_all_domains_now`]) — then
/// the DIDs it does not already hold ([`sync_all_dids_now`]). One task, so
/// the domain rows always queue ahead of the DID rows for that server.
///
/// `served_domains` are the domains the server says it serves and the control
/// plane assigned it: an acknowledged assign it still reports is not re-sent.
pub fn resync_server(
    state: &AppState,
    server_did: String,
    reported: std::collections::HashMap<String, ReportedDid>,
    served_domains: Vec<String>,
) {
    let state = state.clone();
    tokio::spawn(async move {
        sync_all_domains_now(&state, &server_did, &served_domains).await;
        sync_all_dids_now(&state, &server_did, reported).await;
    });
}

/// [`sync_all_dids_now`] on a task of its own.
pub fn sync_all_dids_to_server(
    state: &AppState,
    server_did: String,
    reported: std::collections::HashMap<String, ReportedDid>,
) {
    let state = state.clone();
    tokio::spawn(async move {
        sync_all_dids_now(&state, &server_did, reported).await;
    });
}

/// How many DID records one page of the resync scan reads.
const RESYNC_PAGE: usize = 500;

/// How a resync groups the slots it queues for a batch-capable server.
struct BatchBuilder {
    mnemonics: Vec<String>,
    /// The slots' content, estimated from their records: what the frame will
    /// carry.
    content_bytes: usize,
    /// The row's own size: its mnemonics.
    row_bytes: usize,
    /// The largest row the store takes, less room for the entry around the
    /// mnemonics.
    row_cap: usize,
}

impl BatchBuilder {
    /// Room left for the fields of the entry around the mnemonic list.
    const ROW_OVERHEAD: usize = 4 * 1024;

    fn new(store: &crate::store::Store) -> Self {
        Self {
            mnemonics: Vec::new(),
            content_bytes: 0,
            row_bytes: 0,
            row_cap: store.max_item_bytes().map_or(usize::MAX, |m| {
                m.saturating_sub(Self::ROW_OVERHEAD).max(1024)
            }),
        }
    }

    /// Whether `mnemonic` (with `content` bytes) must start a new batch.
    fn full_before(&self, mnemonic: &str, content: usize) -> bool {
        !self.mnemonics.is_empty()
            && (self.mnemonics.len() >= crate::outbox::SYNC_BATCH_MAX_COUNT
                || self.content_bytes + content > crate::outbox::SYNC_BATCH_MAX_BYTES
                || self.row_bytes + mnemonic.len() + 3 > self.row_cap)
    }

    fn push(&mut self, mnemonic: String, content: usize) {
        self.content_bytes += content;
        self.row_bytes += mnemonic.len() + 3;
        self.mnemonics.push(mnemonic);
    }

    fn take(&mut self) -> Vec<String> {
        self.content_bytes = 0;
        self.row_bytes = 0;
        std::mem::take(&mut self.mnemonics)
    }
}

/// The `outbox-ref:` suffix marking the last batch row of a resync, while it
/// is queued.
const RESYNC_BATCH_REF: &str = "resync-batch";

/// Queue to one server the published DIDs it does not already hold, as the
/// same DID at the current version ([`edge_is_current`]), then deletes for
/// slots it reports that the control plane no longer publishes.
///
/// `reported` maps mnemonic → what the registering server says it holds (from
/// the `preloaded_dids` in its register payload). An **empty** map means a full
/// push — the correct behaviour for a server with an empty store.
///
/// The rows are references ([`crate::outbox::Subject`]): the worker reads each
/// slot when it sends, and a slot already queued for this server is not queued
/// again, so a server that registers while its queue is still draining does
/// not have the same delta appended each time. A batch-capable server gets the
/// slots in `sync/batch` rows; while one from an earlier resync is still
/// queued, the next resync leaves the DIDs to it (and to the per-DID rows a
/// later change adds) and only re-checks once it has drained. The scan pages
/// through the records rather than reading them all at once.
pub async fn sync_all_dids_now(
    state: &AppState,
    server_did: &str,
    reported: std::collections::HashMap<String, ReportedDid>,
) {
    use crate::outbox::Subject;

    // Batch this server's sync only if it advertised the capability at
    // registration. A resync fires one transport-level TSP reply per inbound
    // frame; batching many DIDs into one frame keeps that reply from bursting
    // past the mediator's rate limit.
    let batch_capable = crate::registry::get_instance_for_did(&state.registry_ks, server_did)
        .await
        .ok()
        .flatten()
        .is_some_and(|inst| inst.sync_batch_capable);
    if batch_capable {
        match crate::outbox::resync_batch_queued(&state.store, server_did, RESYNC_BATCH_REF).await {
            Ok(true) => {
                info!(
                    server_did,
                    "resync: an earlier resync is still queued for this server; leaving the DIDs to it"
                );
                return;
            }
            Ok(false) => {}
            Err(e) => {
                crate::outbox::note_enqueue_failure(server_did, "resync", &e);
                return;
            }
        }
    }

    let mut count = 0u64; // DIDs queued
    let mut frames = 0u64; // outbox rows enqueued
    // Mnemonics this control plane publishes; whatever the server reports
    // beyond these it should no longer serve (a delete it missed).
    let mut published: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut batch = BatchBuilder::new(&state.store);
    let mut last_batch: Option<Vec<u8>> = None;

    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let (rows, next) = match state
            .dids_ks
            .prefix_page_raw("did:", cursor.take(), RESYNC_PAGE)
            .await
        {
            Ok(Some(page)) => (page.rows, page.next),
            Ok(None) => match state.dids_ks.prefix_iter_raw("did:").await {
                Ok(all) => (all, None),
                Err(e) => {
                    warn!(error = %e, "sync_all_dids: failed to iterate DIDs");
                    return;
                }
            },
            Err(e) => {
                warn!(error = %e, "sync_all_dids: failed to page DIDs");
                return;
            }
        };
        for (_key, value) in rows {
            let Ok(record) = serde_json::from_slice::<DidRecord>(&value) else {
                continue;
            };
            if record.version_count == 0 {
                continue;
            }
            published.insert(record.mnemonic.clone());
            // Delta: the registering server already has this same DID at this
            // version or newer — nothing to push.
            if edge_is_current(&record, reported.get(&record.mnemonic)) {
                continue;
            }
            if !batch_capable {
                match crate::outbox::enqueue_ref(
                    state,
                    server_did,
                    Subject::Did {
                        mnemonic: record.mnemonic.clone(),
                    },
                )
                .await
                {
                    Ok(true) => {
                        count += 1;
                        frames += 1;
                    }
                    Ok(false) => {}
                    Err(e) => crate::outbox::note_enqueue_failure(server_did, "resync", &e),
                }
                continue;
            }
            let content = record.content_size as usize;
            if batch.full_before(&record.mnemonic, content) {
                match crate::outbox::enqueue_batch(&state.store, server_did, batch.take()).await {
                    Ok(key) => {
                        frames += 1;
                        last_batch = Some(key);
                    }
                    Err(e) => crate::outbox::note_enqueue_failure(server_did, "resync batch", &e),
                }
            }
            batch.push(record.mnemonic.clone(), content);
            count += 1;
        }
        match next {
            Some(n) => cursor = Some(n),
            None => break,
        }
    }
    if !batch.mnemonics.is_empty() {
        match crate::outbox::enqueue_batch(&state.store, server_did, batch.take()).await {
            Ok(key) => {
                frames += 1;
                last_batch = Some(key);
            }
            Err(e) => crate::outbox::note_enqueue_failure(server_did, "resync batch", &e),
        }
    }
    if let Some(key) = last_batch
        && let Err(e) =
            crate::outbox::mark_resync_batch(&state.store, server_did, RESYNC_BATCH_REF, key).await
    {
        debug!(server_did, error = %e, "resync: failed to mark the resync's last batch");
    }

    // Deletes the server missed: it reports a DID this control plane no
    // longer publishes. Queued after the updates; each is a reference, so a
    // slot re-created before it is sent goes out as its new content instead.
    let mut deletes = 0u64;
    for mnemonic in reported.keys().filter(|m| !published.contains(*m)) {
        match crate::outbox::enqueue_ref(
            state,
            server_did,
            Subject::Did {
                mnemonic: mnemonic.clone(),
            },
        )
        .await
        {
            Ok(true) => deletes += 1,
            Ok(false) => {}
            Err(e) => crate::outbox::note_enqueue_failure(server_did, "resync delete", &e),
        }
    }
    if deletes > 0 || count > 0 {
        state.outbox_notify.notify_one();
        info!(
            server_did,
            count,
            frames,
            deletes,
            batched = batch_capable,
            "DID resync queued for registering server"
        );
    }
}

/// The `webvh/sync/update/0.2` payload for a stored slot — the same shape each
/// entry of a `webvh/sync/batch/0.1` carries — or `None` when the slot has no
/// published DID to replicate.
///
/// The slot's `disabled` state travels with its content, so disabling a DID
/// reaches every replica through the same channel as publishing one. The body
/// is read back through the generated type before it is queued: it leaves
/// only in the shape its schema allows.
pub(crate) fn sync_update_body(
    record: &DidRecord,
    log_content: String,
    witness_content: Option<String>,
) -> Option<serde_json::Value> {
    use did_hosting_common::tasks::webvh::sync::update::v0_2 as update;

    let did_id = record.did_id.clone().filter(|d| !d.is_empty())?;
    let body = serde_json::to_value(did_hosting_common::DidSyncUpdate {
        mnemonic: record.mnemonic.clone(),
        did_id,
        log_content,
        witness_content: witness_content.filter(|w| !w.is_empty()),
        version_count: record.version_count,
        disabled: record.disabled,
    })
    .ok()?;
    match serde_json::from_value::<update::Payload>(body.clone()) {
        Ok(_) => Some(body),
        Err(e) => {
            warn!(mnemonic = %record.mnemonic, error = %e, "DID sync: slot does not fit sync/update/0.2; not sending it");
            None
        }
    }
}

/// How many targets a DID mutation queues inside its own transaction. Each
/// costs three writes (row, coalescing index, target marker); past this, the
/// rest are queued right after the commit, still under the slot's lock, so a
/// fleet larger than a bounded backend's transaction (DynamoDB: 100 writes)
/// never makes a DID unpublishable.
const MAX_TRANSACTIONAL_TARGETS: usize = 10;

/// What a DID mutation did to its slot, for [`stage_did_sync`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum DidChange<'a> {
    /// New content was committed: `log` is the slot's log as committed.
    Published { log: &'a str },
    /// The slot's record changed without new content (disabled state,
    /// witness proofs).
    Updated,
    /// The slot was deleted.
    Deleted,
}

/// What [`stage_did_sync`] could not put in the batch, to finish after the
/// commit.
#[must_use = "call `finish` after the batch commits"]
#[derive(Debug, Default)]
pub(crate) struct StagedSync {
    mnemonic: String,
    staged: usize,
    deferred: Vec<String>,
}

impl StagedSync {
    /// After the batch committed, still holding the slot's lock: queue the
    /// targets past [`MAX_TRANSACTIONAL_TARGETS`] and wake the worker.
    pub(crate) async fn finish(self, state: &AppState) {
        for target in &self.deferred {
            if let Err(e) = crate::outbox::enqueue_ref_locked(
                state,
                target,
                crate::outbox::Subject::Did {
                    mnemonic: self.mnemonic.clone(),
                },
            )
            .await
            {
                crate::outbox::note_enqueue_failure(target, "DID sync", &e);
            }
        }
        if self.staged > 0 || !self.deferred.is_empty() {
            state.outbox_notify.notify_one();
        }
    }
}

/// Queue the sync of a changed slot to every server and watcher that should
/// hold it, **in the mutation's own `batch`** — the transactional outbox. The
/// caller holds the slot's `path_locks` guard from before this call until
/// after [`StagedSync::finish`]; the rows commit with the mutation or not at
/// all, and a slot's rows reach each target in commit order.
///
/// Targets: every active server, plus — for a publish — the configured
/// watchers the log names (recorded, so a later delete reaches only them), or
/// — for a delete — the watchers recorded at its last publish. A row is a
/// reference ([`crate::outbox::Subject::Did`]): the worker sends whatever the
/// slot holds when it sends, a delete included. A target with the slot
/// already queued gets no second row.
///
/// Best effort: a failure to read the registry or the queue is logged and
/// counted, and the mutation commits anyway — the server converges on its
/// next registration.
pub(crate) async fn stage_did_sync(
    state: &AppState,
    batch: &mut crate::store::WriteBatch,
    mnemonic: &str,
    change: DidChange<'_>,
) -> StagedSync {
    let mut staged = StagedSync {
        mnemonic: mnemonic.to_string(),
        ..StagedSync::default()
    };
    let mut targets: Vec<String> = Vec::new();

    let watchers = match change {
        DidChange::Published { log } => {
            // The watchers the log names, through the configured URL → DID
            // map. Recorded on every publish (even an empty list) so a later
            // delete reaches only the watchers it was published to — fanning
            // a delete out to every configured watcher would tell watchers
            // that never mirrored the DID that its mnemonic even existed.
            let named = watcher_dids_for(&state.config.registry.watchers, log);
            if let Err(e) = batch.insert(&state.dids_ks, notified_watchers_key(mnemonic), &named) {
                warn!(mnemonic, error = %e, "DID sync: failed to record notified watchers");
            }
            named
        }
        DidChange::Updated => state
            .dids_ks
            .get::<Vec<String>>(notified_watchers_key(mnemonic))
            .await
            .ok()
            .flatten()
            .unwrap_or_default(),
        DidChange::Deleted => {
            let named = state
                .dids_ks
                .get::<Vec<String>>(notified_watchers_key(mnemonic))
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
            batch.remove(&state.dids_ks, notified_watchers_key(mnemonic));
            named
        }
    };
    targets.extend(watchers.iter().cloned());

    match push_targets(&state.registry_ks).await {
        PushTargets::Active(servers) => {
            for (server_did, _) in servers {
                if !targets.contains(&server_did) {
                    targets.push(server_did);
                }
            }
        }
        other if watchers.is_empty() => other.log("DID sync", mnemonic),
        _ => {}
    }

    for target in targets {
        if staged.staged >= MAX_TRANSACTIONAL_TARGETS {
            staged.deferred.push(target);
            continue;
        }
        match crate::outbox::stage_ref(
            batch,
            &state.store,
            &target,
            crate::outbox::Subject::Did {
                mnemonic: mnemonic.to_string(),
            },
        )
        .await
        {
            Ok(true) => {
                staged.staged += 1;
                debug!(target_did = %target, mnemonic, ?change, "DID sync: queued");
            }
            Ok(false) => debug!(target_did = %target, mnemonic, "DID sync: already queued"),
            Err(e) => crate::outbox::note_enqueue_failure(&target, "DID sync", &e),
        }
    }
    staged
}

/// Queue a DID's current state to every active server (and the watchers its
/// log names) outside a mutation — for a slot written by something other than
/// the DID operations, which stage their rows transactionally
/// ([`stage_did_sync`]). Runs on a task of its own.
pub fn notify_servers_did(state: &AppState, mnemonic: String) {
    let state = state.clone();
    tokio::spawn(async move {
        let _guard = state.path_locks.guard(&mnemonic).await;
        let log = match state
            .dids_ks
            .get_raw(did_ops::content_log_key(&mnemonic))
            .await
        {
            Ok(Some(bytes)) => String::from_utf8(bytes).unwrap_or_default(),
            Ok(None) => String::new(),
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "DID sync: failed to read log");
                return;
            }
        };
        let mut batch = state.store.batch();
        let staged = stage_did_sync(
            &state,
            &mut batch,
            &mnemonic,
            DidChange::Published { log: &log },
        )
        .await;
        match batch.commit().await {
            Ok(()) => staged.finish(&state).await,
            Err(e) => crate::outbox::note_enqueue_failure("*", "DID sync", &e),
        }
    });
}

/// [`notify_servers_did`] for a deleted slot.
pub fn notify_servers_delete(state: &AppState, mnemonic: String) {
    let state = state.clone();
    tokio::spawn(async move {
        let _guard = state.path_locks.guard(&mnemonic).await;
        let mut batch = state.store.batch();
        let staged = stage_did_sync(&state, &mut batch, &mnemonic, DidChange::Deleted).await;
        match batch.commit().await {
            Ok(()) => staged.finish(&state).await,
            Err(e) => crate::outbox::note_enqueue_failure("*", "DID delete sync", &e),
        }
    });
}

// ---------------------------------------------------------------------------
// Watchers
// ---------------------------------------------------------------------------

/// Key holding the watcher DIDs a mnemonic's log named the last time
/// `notify_servers_did` ran for it. Read (and cleared) by
/// `notify_servers_delete`, so a delete reaches only the watchers the DID was
/// actually published to.
fn notified_watchers_key(mnemonic: &str) -> String {
    format!("notified_watchers:{mnemonic}")
}

/// The watcher URLs a did:webvh log names: its `watchers` parameter as last
/// set (parameters carry forward; `null` or `[]` clears it).
pub fn watchers_named(log: &str) -> Vec<String> {
    let mut current: Vec<String> = Vec::new();
    for line in log.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(watchers) = entry.get("parameters").and_then(|p| p.get("watchers")) else {
            continue;
        };
        current = watchers
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(|u| u.trim_end_matches('/').to_string())
                    .collect()
            })
            .unwrap_or_default();
    }
    current
}

/// The DIDs of the configured watchers `log` names. A named URL with no
/// configured DID is skipped (and logged): the control plane pushes only to
/// watchers it was told the DID of.
pub fn watcher_dids_for(peers: &[crate::config::WatcherPeer], log: &str) -> Vec<String> {
    let mut dids = Vec::new();
    for url in watchers_named(log) {
        match peers.iter().find(|p| p.url.trim_end_matches('/') == url) {
            Some(peer) if !dids.contains(&peer.did) => dids.push(peer.did.clone()),
            Some(_) => {}
            None => {
                warn!(watcher_url = %url, "DID sync: the log names a watcher with no configured DID; not pushing to it")
            }
        }
    }
    dids
}

/// Whether `did` is a watcher this control plane is configured to push to —
/// the only standing a watcher has here: acknowledging what it was sent.
pub fn is_configured_watcher(state: &AppState, did: &str) -> bool {
    state.config.registry.watchers.iter().any(|p| p.did == did)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The edges a DID change is pushed to, as the registry holds them.
#[derive(Debug, PartialEq, Eq)]
enum PushTargets {
    /// Active edges, as (server DID, instance id).
    Active(Vec<(String, String)>),
    /// No edge is registered: always so for a daemon, and for a control plane
    /// until its first edge registers. Nothing is missed.
    NoneRegistered,
    /// Edges are registered but none is active (degraded, unreachable, or
    /// registered without a DID), so this change reaches none of them now.
    NoneActive,
    /// The registry could not be read; the failure is already logged.
    Unknown,
}

/// Most one "registered but none active" warning per this many seconds: it
/// is a property of the registry, not of each DID change.
const NO_ACTIVE_EDGES_WARN_SECS: u64 = 300;

/// Unix second of the last "registered but none active" warning.
static LAST_NO_ACTIVE_EDGES_WARN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

impl PushTargets {
    fn from_instances(instances: Vec<registry::ServiceInstance>) -> Self {
        let registered: Vec<_> = instances
            .into_iter()
            .filter(|i| i.service_type == ServiceType::Server)
            .collect();
        if registered.is_empty() {
            return Self::NoneRegistered;
        }
        let active: Vec<_> = registered
            .into_iter()
            .filter(|i| i.status == registry::ServiceStatus::Active)
            .filter_map(|i| {
                let did = i.metadata.get("did")?.as_str()?.to_string();
                Some((did, i.instance_id))
            })
            .collect();
        if active.is_empty() {
            Self::NoneActive
        } else {
            Self::Active(active)
        }
    }

    /// Log why a change was not pushed. An empty registry is the normal
    /// state of a daemon, so it is debug; registered edges that are all
    /// down miss this change, so that warns, at most once per
    /// [`NO_ACTIVE_EDGES_WARN_SECS`].
    fn log(&self, op: &str, mnemonic: &str) {
        match self {
            Self::NoneRegistered => {
                debug!(mnemonic = %mnemonic, "{op}: no servers registered");
            }
            Self::NoneActive => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let last = LAST_NO_ACTIVE_EDGES_WARN.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= NO_ACTIVE_EDGES_WARN_SECS
                    && LAST_NO_ACTIVE_EDGES_WARN
                        .compare_exchange(
                            last,
                            now,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        )
                        .is_ok()
                {
                    warn!(
                        mnemonic = %mnemonic,
                        "{op}: servers are registered but none is active; changes are not \
                         reaching them (repeats are logged at debug for {NO_ACTIVE_EDGES_WARN_SECS} s)"
                    );
                } else {
                    debug!(mnemonic = %mnemonic, "{op}: servers are registered but none is active");
                }
            }
            Self::Active(_) | Self::Unknown => {}
        }
    }
}

/// The registry's push targets for a DID change.
async fn push_targets(registry_ks: &crate::store::KeyspaceHandle) -> PushTargets {
    match registry::list_instances(registry_ks).await {
        Ok(instances) => PushTargets::from_instances(instances),
        Err(e) => {
            warn!(error = %e, "server push: failed to list instances");
            PushTargets::Unknown
        }
    }
}

// ---------------------------------------------------------------------------
// Domain assignment push (T28)
//
// All control→server pushes route through `crate::outbox` for durable,
// at-least-once delivery: enqueue first, worker delivers. Returning
// Ok means the row is durable, not that the server has acknowledged
// — that's by design so a transient mediator outage or a temporarily-
// offline server doesn't drop the mutation. Recipients are
// idempotent (assign/unassign/purge/upsert all no-op on repeat).
// ---------------------------------------------------------------------------

/// A domain operation the control plane has sent a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainOp {
    Assign,
    Unassign,
    Purge,
}

/// The latest domain operation sent to one server for one domain — what that
/// server's assignment of the domain should be. Kept so a server that missed
/// the op (offline past its outbox budget) is brought back in line when it
/// next registers ([`resend_domain_intents`]); an unassign or purge is settled
/// once the server acknowledges it. An assign is kept (it is the desired
/// state, and what a registering server's `served_domains` claim is checked
/// against) and marked `acked` once the server applies it: it is then re-sent
/// only to a server that registers without the domain (a wiped edge).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DomainIntent {
    pub domain: String,
    pub op: DomainOp,
    pub at: u64,
    /// The server acknowledged this op (as applied). Only an assign is kept
    /// once acknowledged.
    #[serde(default)]
    pub acked: bool,
}

/// `|` cannot occur in a DID, so one server's prefix never matches another's.
fn domain_intent_prefix(server_did: &str) -> String {
    format!("domain-intent:{server_did}|")
}

fn domain_intent_key(server_did: &str, domain: &str) -> String {
    format!("{}{domain}", domain_intent_prefix(server_did))
}

/// Record `op` as the latest domain operation for `server_did`.
async fn record_domain_intent(
    state: &AppState,
    server_did: &str,
    domain: &str,
    op: DomainOp,
) -> Result<(), did_hosting_common::server::error::AppError> {
    state
        .registry_ks
        .insert(
            domain_intent_key(server_did, domain),
            &DomainIntent {
                domain: domain.to_string(),
                op,
                at: crate::auth::session::now_epoch(),
                acked: false,
            },
        )
        .await
}

/// Every recorded domain intent for one server.
pub async fn domain_intents(
    state: &AppState,
    server_did: &str,
) -> Result<Vec<DomainIntent>, did_hosting_common::server::error::AppError> {
    Ok(state
        .registry_ks
        .prefix_iter_raw(domain_intent_prefix(server_did))
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect())
}

/// A server acknowledged `op` for `domain`, only while `op` is still the latest
/// op recorded for it (the ack of an older unassign cannot erase a newer
/// assign): an unassign or purge is settled (removed); an assign the server
/// `applied` is marked acknowledged.
pub async fn settle_domain_intent(
    state: &AppState,
    server_did: &str,
    domain: &str,
    op: DomainOp,
    applied: bool,
) {
    let key = domain_intent_key(server_did, domain);
    let _guard = state.path_locks.guard(&key).await;
    match state.registry_ks.get::<DomainIntent>(key.clone()).await {
        Ok(Some(intent)) if intent.op == op => {
            let written = match op {
                DomainOp::Assign if applied && !intent.acked => {
                    state
                        .registry_ks
                        .insert(
                            key,
                            &DomainIntent {
                                acked: true,
                                ..intent
                            },
                        )
                        .await
                }
                DomainOp::Assign => Ok(()),
                DomainOp::Unassign | DomainOp::Purge => state.registry_ks.remove(key).await,
            };
            if let Err(e) = written {
                warn!(server_did, domain, error = %e, "failed to settle domain intent");
            }
        }
        Ok(_) => {}
        Err(e) => warn!(server_did, domain, error = %e, "failed to read domain intent"),
    }
}

/// Re-send every unsettled domain operation to a (re-)registering server: its
/// assignments, and any unassign or purge it has not acknowledged. Idempotent
/// on the server. A purge is preceded by its unassign, so a server that missed
/// both ends up unassigned and purged. Every assign is re-sent; see
/// [`resend_domain_intents_for`] for a server that reported what it serves.
pub async fn resend_domain_intents(state: &AppState, server_did: &str) {
    resend_domain_intents_for(state, server_did, None).await;
}

/// [`resend_domain_intents`], with the domains the server reported serving
/// at registration: an assign it acknowledged and still serves is not
/// re-sent. An op already the latest queued for its domain is not queued
/// again, so a server registering while its queue drains does not collect
/// copies.
pub async fn resend_domain_intents_for(
    state: &AppState,
    server_did: &str,
    served: Option<&[String]>,
) {
    let intents = match domain_intents(state, server_did).await {
        Ok(i) => i,
        Err(e) => {
            warn!(server_did, error = %e, "domain resync: failed to list domain intents");
            return;
        }
    };
    for intent in intents {
        let ops: &[&str] = match intent.op {
            DomainOp::Assign
                if intent.acked && served.is_some_and(|s| s.contains(&intent.domain)) =>
            {
                continue;
            }
            DomainOp::Assign => &[MSG_REPLICA_DOMAIN_ASSIGN],
            DomainOp::Unassign => &[MSG_REPLICA_DOMAIN_UNASSIGN],
            DomainOp::Purge => &[MSG_REPLICA_DOMAIN_UNASSIGN, MSG_REPLICA_DOMAIN_PURGE],
        };
        // The last op of the sequence queued and still pending means the
        // whole sequence is: nothing to add.
        let last = ops[ops.len() - 1];
        match crate::outbox::domain_op_queued(&state.store, server_did, last, &intent.domain).await
        {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                crate::outbox::note_enqueue_failure(server_did, "domain resync", &e);
                continue;
            }
        }
        for op in ops {
            if let Err(e) =
                crate::outbox::enqueue_domain_op(&state.store, server_did, op, &intent.domain).await
            {
                crate::outbox::note_enqueue_failure(server_did, "domain resync", &e);
            }
        }
    }
    state.outbox_notify.notify_one();
}

/// Enqueue `replica/domain/assign { domain }` for one server. Returns once
/// the outbox row is durable; the worker handles actual delivery and
/// retry.
///
/// A purge of the same domain still queued for this server is dropped first.
/// Each delivery attempt is signed afresh, so a purge re-sent after this
/// assignment would carry a later `issuedAt` than the assignment and pass the
/// server's `stalePurge` check: `replica/domain/purge/0.1` makes dropping it
/// the control plane's job.
pub async fn send_domain_assign(
    state: &AppState,
    target_did: &str,
    domain: &str,
) -> Result<(), did_hosting_common::server::error::AppError> {
    record_domain_intent(state, target_did, domain, DomainOp::Assign).await?;
    let dropped =
        crate::outbox::drop_queued(&state.store, target_did, MSG_REPLICA_DOMAIN_PURGE, |body| {
            body.get("domain").and_then(|d| d.as_str()) == Some(domain)
        })
        .await?;
    if dropped > 0 {
        info!(
            target_did,
            domain, dropped, "re-assign dropped a purge still queued for this server"
        );
    }
    crate::outbox::enqueue_domain_op(&state.store, target_did, MSG_REPLICA_DOMAIN_ASSIGN, domain)
        .await?;
    state.outbox_notify.notify_one();
    Ok(())
}

/// Enqueue `replica/domain/purge { domain }` for one server. Bypasses the
/// grace window on the recipient (audit-logged as
/// `reason: "admin-immediate"`). Use sparingly.
pub async fn send_domain_purge(
    state: &AppState,
    target_did: &str,
    domain: &str,
) -> Result<(), did_hosting_common::server::error::AppError> {
    record_domain_intent(state, target_did, domain, DomainOp::Purge).await?;
    crate::outbox::enqueue_domain_op(&state.store, target_did, MSG_REPLICA_DOMAIN_PURGE, domain)
        .await?;
    state.outbox_notify.notify_one();
    Ok(())
}

/// Enqueue `replica/domain/unassign { domain }` for one server. Same
/// at-least-once semantics as [`send_domain_assign`].
pub async fn send_domain_unassign(
    state: &AppState,
    target_did: &str,
    domain: &str,
) -> Result<(), did_hosting_common::server::error::AppError> {
    record_domain_intent(state, target_did, domain, DomainOp::Unassign).await?;
    crate::outbox::enqueue_domain_op(
        &state.store,
        target_did,
        MSG_REPLICA_DOMAIN_UNASSIGN,
        domain,
    )
    .await?;
    state.outbox_notify.notify_one();
    Ok(())
}

// ---------------------------------------------------------------------------
// Domain replication push (split-deployment lifecycle)
// ---------------------------------------------------------------------------

/// Enqueue `replica/domain/upsert` of `entry`'s domain for one server.
/// Replicates a control-side create / update / disable / enable so the
/// server's local store + sweeper stay in sync. Idempotent on the receiver.
///
/// The row is a reference: the worker sends the domain's entry as it stands
/// when it sends (in the shared `DomainEntry` wire shape,
/// [`did_hosting_common::server::domain::wire`]), and a domain already queued
/// for this server is not queued again.
pub async fn send_domain_upsert(
    state: &AppState,
    target_did: &str,
    entry: &did_hosting_common::server::domain::DomainEntry,
) -> Result<(), did_hosting_common::server::error::AppError> {
    crate::outbox::enqueue_ref(
        state,
        target_did,
        crate::outbox::Subject::DomainUpsert {
            domain: entry.name.clone(),
        },
    )
    .await?;
    state.outbox_notify.notify_one();
    Ok(())
}

/// Replicate every control-side `DomainEntry` to one server, then re-send its
/// unsettled domain assign/unassign/purge ops ([`resend_domain_intents_for`])
/// — run on each (re-)registration (by [`resync_server`]) so a server that
/// missed any of them while unreachable converges on the control plane's
/// domain records, statuses and assignments. `served` are the domains the
/// server reported serving, which the control plane assigned it.
pub async fn sync_all_domains_now(state: &AppState, server_did: &str, served: &[String]) {
    match did_hosting_common::server::domain::list_domains(&state.store).await {
        Ok(domains) => {
            for entry in &domains {
                if let Err(e) = send_domain_upsert(state, server_did, entry).await {
                    crate::outbox::note_enqueue_failure(server_did, "domain resync", &e);
                }
            }
        }
        Err(e) => warn!(server_did, error = %e, "domain resync: list failed"),
    }
    resend_domain_intents_for(state, server_did, Some(served)).await;
}

/// Fan an upsert out to every registered server. Used after every
/// successful control-side domain mutation so each server eventually
/// applies the change to its local DomainEntry copy + grace timer.
///
/// Enqueues one outbox entry per server (or finds it already queued); the
/// worker handles delivery and retry. A registry-list failure is logged and
/// skipped — there are no rows to enqueue against. Returns
/// `(enqueued, skipped)` for the caller's log line; `enqueued` is the number
/// of servers with the upsert queued, NOT the number that have acked.
pub async fn fanout_domain_upsert(
    state: &AppState,
    entry: &did_hosting_common::server::domain::DomainEntry,
) -> (usize, usize) {
    let instances = match registry::list_instances(&state.registry_ks).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "fanout_domain_upsert: failed to list registry — no servers notified");
            return (0, 0);
        }
    };

    let mut enqueued = 0;
    let mut skipped = 0;
    for instance in instances {
        let did = match instance.metadata.get("did").and_then(|v| v.as_str()) {
            Some(d) => d.to_string(),
            None => {
                // An instance without `did` metadata — can't address.
                skipped += 1;
                continue;
            }
        };
        match send_domain_upsert(state, &did, entry).await {
            Ok(()) => enqueued += 1,
            Err(e) => {
                crate::outbox::note_enqueue_failure(&did, "domain upsert", &e);
                skipped += 1;
            }
        }
    }
    (enqueued, skipped)
}

#[cfg(test)]
mod watcher_tests {
    use super::*;
    use crate::config::WatcherPeer;
    use serde_json::json;

    fn log(params: &[serde_json::Value]) -> String {
        params
            .iter()
            .map(|p| json!({ "versionId": "1-x", "parameters": p }).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_last_watchers_parameter_wins() {
        let l = log(&[
            json!({ "watchers": ["https://a.example/"] }),
            json!({}),
            json!({ "watchers": ["https://b.example", "https://c.example"] }),
        ]);
        assert_eq!(
            watchers_named(&l),
            vec!["https://b.example", "https://c.example"]
        );
        let cleared = log(&[
            json!({ "watchers": ["https://a.example"] }),
            json!({ "watchers": null }),
        ]);
        assert!(watchers_named(&cleared).is_empty());
    }

    #[test]
    fn only_configured_watchers_are_pushed_to() {
        let peers = vec![WatcherPeer {
            url: "https://b.example/".into(),
            did: "did:example:b".into(),
        }];
        let l = log(&[json!({ "watchers": ["https://a.example", "https://b.example"] })]);
        assert_eq!(watcher_dids_for(&peers, &l), vec!["did:example:b"]);
    }
}

#[cfg(test)]
mod push_target_tests {
    use super::*;
    use serde_json::json;

    fn instance(
        id: &str,
        kind: &str,
        status: &str,
        did: Option<&str>,
    ) -> registry::ServiceInstance {
        let metadata = did.map_or(json!({}), |d| json!({ "did": d }));
        serde_json::from_value(json!({
            "instanceId": id,
            "serviceType": kind,
            "url": "https://edge.example",
            "status": status,
            "registeredAt": 0,
            "metadata": metadata,
        }))
        .expect("instance")
    }

    #[test]
    fn test_push_targets_empty_registry_is_none_registered() {
        assert_eq!(
            PushTargets::from_instances(vec![]),
            PushTargets::NoneRegistered
        );
    }

    #[test]
    fn test_push_targets_registered_edges_that_are_down_are_told_apart_from_none() {
        let down = vec![
            instance("a", "server", "degraded", Some("did:example:a")),
            instance("b", "server", "unreachable", Some("did:example:b")),
            instance("c", "server", "active", None),
        ];
        assert_eq!(PushTargets::from_instances(down), PushTargets::NoneActive);
    }

    #[test]
    fn test_push_targets_only_active_servers_with_a_did_are_pushed_to() {
        let mixed = vec![
            instance("a", "server", "active", Some("did:example:a")),
            instance("b", "server", "degraded", Some("did:example:b")),
        ];
        assert_eq!(
            PushTargets::from_instances(mixed),
            PushTargets::Active(vec![("did:example:a".into(), "a".into())])
        );
    }
}

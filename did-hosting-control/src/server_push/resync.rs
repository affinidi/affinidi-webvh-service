//! Bringing a (re-)registering server up to date: what it reports holding
//! (`preloaded_dids`), and the DIDs — after its domains — it is then queued.

use did_hosting_common::did_ops::DidRecord;
use tracing::{debug, info, warn};

use super::sync_all_domains_now;
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
    let tracker = state.background.clone();
    let state = state.clone();
    tracker.spawn(async move {
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
    let tracker = state.background.clone();
    let state = state.clone();
    tracker.spawn(async move {
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

    fn new(store: &did_hosting_common::server::store::Store) -> Self {
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

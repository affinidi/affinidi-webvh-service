//! Queueing a changed DID slot to the servers and watchers that should hold
//! it: inside the mutation's own transaction ([`stage_did_sync`]), or on a
//! task of its own for a slot written outside the DID operations.

use did_hosting_common::did_ops::{self, DidRecord};
use tracing::{debug, warn};

use super::targets::{PushTargets, push_targets};
use super::watchers::{notified_watchers_key, watcher_dids_for};
use crate::server::AppState;

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
    batch: &mut did_hosting_common::server::store::WriteBatch,
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
/// (`stage_did_sync`). Runs on a task of its own.
pub fn notify_servers_did(state: &AppState, mnemonic: String) {
    let tracker = state.background.clone();
    let state = state.clone();
    tracker.spawn(async move {
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
    let tracker = state.background.clone();
    let state = state.clone();
    tracker.spawn(async move {
        let _guard = state.path_locks.guard(&mnemonic).await;
        let mut batch = state.store.batch();
        let staged = stage_did_sync(&state, &mut batch, &mnemonic, DidChange::Deleted).await;
        match batch.commit().await {
            Ok(()) => staged.finish(&state).await,
            Err(e) => crate::outbox::note_enqueue_failure("*", "DID delete sync", &e),
        }
    });
}

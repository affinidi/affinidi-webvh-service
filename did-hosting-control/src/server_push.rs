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
use serde_json::json;
use tracing::{info, warn};

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
pub fn edge_is_current(record: &DidRecord, reported: Option<&ReportedDid>) -> bool {
    reported.is_some_and(|have| {
        have.did_id.is_some()
            && have.did_id == record.did_id
            && have.version_count >= record.version_count
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
                    Some((
                        mnemonic,
                        ReportedDid {
                            did_id,
                            version_count,
                        },
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Enqueue published DIDs to one server's outbox — only the ones it doesn't
/// already hold, as the same DID at the current version ([`edge_is_current`]).
///
/// `reported` maps mnemonic → what the registering server says it holds (from
/// the `preloaded_dids` in its register payload). An **empty** map means a full
/// push — the correct behaviour for a server with an empty store.
///
/// Each DID is one outbox row; the worker drains them in enqueue order so the
/// server applies them deterministically, and a control restart mid-bulk
/// resumes from the remaining rows. Sending only the delta is what keeps a
/// reboot from re-pushing every DID (and re-triggering the server's own-DID
/// identity-rotation check) at thousands-of-DIDs scale.
pub fn sync_all_dids_to_server(
    state: &AppState,
    server_did: String,
    reported: std::collections::HashMap<String, ReportedDid>,
) {
    let dids_ks = state.dids_ks.clone();
    let registry_ks = state.registry_ks.clone();
    let store = state.store.clone();
    let notify = state.outbox_notify.clone();

    tokio::spawn(async move {
        // Batch this server's sync only if it advertised the capability at
        // registration (mirrors `sync_batch_capable`). A resync fires one
        // transport-level TSP reply per inbound frame; batching many DIDs into
        // one frame keeps that reply from bursting past the mediator's rate
        // limit. Servers that didn't advertise it get one message per DID.
        let instance_id = server_did.replace(':', "_");
        let batch = crate::registry::get_instance(&registry_ks, &instance_id)
            .await
            .ok()
            .flatten()
            .is_some_and(|inst| inst.sync_batch_capable);

        // Iterate all published DIDs
        let raw = match dids_ks.prefix_iter_raw("did:").await {
            Ok(raw) => raw,
            Err(e) => {
                warn!(error = %e, "sync_all_dids: failed to iterate DIDs");
                return;
            }
        };

        let mut count = 0u64; // DIDs queued
        let mut frames = 0u64; // outbox rows (transport frames) enqueued
        // Mnemonics this control plane publishes; whatever the server reports
        // beyond these it should no longer serve (a delete it missed).
        let mut published: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pending: Vec<serde_json::Value> = Vec::new();
        let mut pending_bytes = 0usize;

        for (_key, value) in raw {
            let record: DidRecord = match serde_json::from_slice(&value) {
                Ok(r) => r,
                Err(_) => continue,
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

            let log_content = match dids_ks
                .get_raw(did_ops::content_log_key(&record.mnemonic))
                .await
            {
                Ok(Some(bytes)) => match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => continue,
                },
                _ => continue,
            };

            let witness_content = match dids_ks
                .get_raw(did_ops::content_witness_key(&record.mnemonic))
                .await
            {
                Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
                _ => None,
            };

            let body = json!({
                "mnemonic": record.mnemonic,
                "did_id": record.did_id.unwrap_or_default(),
                "log_content": log_content,
                "witness_content": witness_content,
                "version_count": record.version_count,
            });

            if !batch {
                if let Err(e) =
                    crate::outbox::enqueue(&store, &server_did, MSG_SYNC_UPDATE, body).await
                {
                    warn!(server_did = %server_did, mnemonic = %record.mnemonic, error = %e, "sync_all_dids: outbox enqueue failed");
                } else {
                    count += 1;
                    frames += 1;
                }
                continue;
            }

            // Batched: flush before this entry would breach the count or byte
            // cap, so a single DID never lands split across two frames.
            let sz = body.to_string().len();
            if !pending.is_empty()
                && (pending.len() >= SYNC_BATCH_MAX_COUNT
                    || pending_bytes + sz > SYNC_BATCH_MAX_BYTES)
            {
                let payload = json!({ "updates": std::mem::take(&mut pending) });
                pending_bytes = 0;
                if let Err(e) =
                    crate::outbox::enqueue(&store, &server_did, MSG_SYNC_BATCH, payload).await
                {
                    warn!(server_did = %server_did, error = %e, "sync_all_dids: outbox batch enqueue failed");
                } else {
                    frames += 1;
                }
            }
            pending_bytes += sz;
            pending.push(body);
            count += 1;
        }

        // Flush the trailing batch.
        if !pending.is_empty() {
            let payload = json!({ "updates": pending });
            if let Err(e) =
                crate::outbox::enqueue(&store, &server_did, MSG_SYNC_BATCH, payload).await
            {
                warn!(server_did = %server_did, error = %e, "sync_all_dids: outbox batch enqueue failed");
            } else {
                frames += 1;
            }
        }

        // Deletes the server missed: it reports a DID this control plane no
        // longer publishes. Queued after the updates, in order.
        let mut deletes = 0u64;
        for mnemonic in reported.keys().filter(|m| !published.contains(*m)) {
            if let Err(e) = crate::outbox::enqueue(
                &store,
                &server_did,
                MSG_SYNC_DELETE,
                json!({ "mnemonic": mnemonic }),
            )
            .await
            {
                warn!(server_did = %server_did, %mnemonic, error = %e, "resync: delete enqueue failed");
            } else {
                deletes += 1;
            }
        }
        if deletes > 0 {
            notify.notify_one();
            info!(server_did = %server_did, deletes, "resync: queued deletes the server missed");
        }

        if count > 0 {
            notify.notify_one();
            info!(
                server_did = %server_did,
                count,
                frames,
                batched = batch,
                "initial DID sync queued for newly registered server"
            );
        }
    });
}

/// Max DIDs per `MSG_SYNC_BATCH`, and max serialized bytes. Bounds message size
/// (each DID carries a full `did.jsonl`) while collapsing the resync burst.
const SYNC_BATCH_MAX_COUNT: usize = 50;
const SYNC_BATCH_MAX_BYTES: usize = 512 * 1024;

/// Enqueue a DID update to every active server instance.
///
/// Builds the sync body from the current store contents, then writes
/// one outbox row per active server. The worker handles delivery;
/// servers that are offline at enqueue time still get the update
/// when they reconnect.
pub fn notify_servers_did(state: &AppState, mnemonic: String) {
    let registry_ks = state.registry_ks.clone();
    let dids_ks = state.dids_ks.clone();
    let store = state.store.clone();
    let notify = state.outbox_notify.clone();

    tokio::spawn(async move {
        info!(mnemonic = %mnemonic, "DID changed — queueing sync to servers");

        let record = match dids_ks.get::<DidRecord>(did_ops::did_key(&mnemonic)).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                warn!(mnemonic = %mnemonic, "DID sync: record not found in store");
                return;
            }
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "DID sync: failed to read record");
                return;
            }
        };

        let log_content = match dids_ks.get_raw(did_ops::content_log_key(&mnemonic)).await {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => {
                    warn!(mnemonic = %mnemonic, "DID sync: invalid UTF-8 in log content");
                    return;
                }
            },
            Ok(None) => {
                warn!(mnemonic = %mnemonic, "DID sync: no log content found");
                return;
            }
            Err(e) => {
                warn!(mnemonic = %mnemonic, error = %e, "DID sync: failed to read log");
                return;
            }
        };

        let witness_content = match dids_ks
            .get_raw(did_ops::content_witness_key(&mnemonic))
            .await
        {
            Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
            _ => None,
        };

        let body = json!({
            "mnemonic": mnemonic,
            "did_id": record.did_id.unwrap_or_default(),
            "log_content": log_content,
            "witness_content": witness_content,
            "version_count": record.version_count,
        });

        let servers = match get_active_servers(&registry_ks).await {
            Some(s) => s,
            None => {
                warn!(mnemonic = %mnemonic, "DID sync: no active servers in registry");
                return;
            }
        };

        for (server_did, instance_id) in &servers {
            if let Err(e) =
                crate::outbox::enqueue(&store, server_did, MSG_SYNC_UPDATE, body.clone()).await
            {
                warn!(
                    server_did,
                    instance_id,
                    mnemonic = %mnemonic,
                    error = %e,
                    "DID sync: outbox enqueue failed"
                );
            } else {
                info!(
                    server_did,
                    instance_id,
                    mnemonic = %mnemonic,
                    "DID sync: queued for server"
                );
            }
        }
        notify.notify_one();
    });
}

/// Enqueue a DID-delete sync to every active server instance.
pub fn notify_servers_delete(state: &AppState, mnemonic: String) {
    let registry_ks = state.registry_ks.clone();
    let store = state.store.clone();
    let notify = state.outbox_notify.clone();

    tokio::spawn(async move {
        info!(mnemonic = %mnemonic, "DID deleted — queueing sync to servers");

        let servers = match get_active_servers(&registry_ks).await {
            Some(s) => s,
            None => {
                warn!(mnemonic = %mnemonic, "DID delete sync: no active servers in registry");
                return;
            }
        };

        let body = json!({ "mnemonic": mnemonic });
        for (server_did, instance_id) in &servers {
            if let Err(e) =
                crate::outbox::enqueue(&store, server_did, MSG_SYNC_DELETE, body.clone()).await
            {
                warn!(
                    server_did,
                    instance_id,
                    mnemonic = %mnemonic,
                    error = %e,
                    "DID delete sync: outbox enqueue failed"
                );
            } else {
                info!(
                    server_did,
                    instance_id,
                    mnemonic = %mnemonic,
                    "DID delete sync: queued for server"
                );
            }
        }
        notify.notify_one();
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get active server DIDs and instance IDs from the registry.
async fn get_active_servers(
    registry_ks: &crate::store::KeyspaceHandle,
) -> Option<Vec<(String, String)>> {
    let instances = match registry::list_instances(registry_ks).await {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "server push: failed to list instances");
            return None;
        }
    };

    let servers: Vec<_> = instances
        .into_iter()
        .filter(|i| {
            i.service_type == ServiceType::Server && i.status == registry::ServiceStatus::Active
        })
        .filter_map(|i| {
            let did = i.metadata.get("did")?.as_str()?.to_string();
            Some((did, i.instance_id))
        })
        .collect();

    if servers.is_empty() {
        None
    } else {
        Some(servers)
    }
}

// ---------------------------------------------------------------------------
// Domain assignment push (T28)
//
// All control→server pushes route through `crate::outbox` for durable,
// at-least-once delivery: enqueue first, worker delivers. Returning
// Ok means the row hit fjall, not that the server has acknowledged
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
/// once the server acknowledges it, an assign is kept (it is the desired
/// state, and re-sending it is a no-op).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DomainIntent {
    pub domain: String,
    pub op: DomainOp,
    pub at: u64,
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

/// A server acknowledged `op` for `domain`: an unassign or purge is settled —
/// but only when it is still the latest op, so the ack of an older unassign
/// cannot erase a newer assign.
pub async fn settle_domain_intent(state: &AppState, server_did: &str, domain: &str, op: DomainOp) {
    if op == DomainOp::Assign {
        return;
    }
    let key = domain_intent_key(server_did, domain);
    match state.registry_ks.get::<DomainIntent>(key.clone()).await {
        Ok(Some(intent)) if intent.op == op => {
            if let Err(e) = state.registry_ks.remove(key).await {
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
/// both ends up unassigned and purged.
pub async fn resend_domain_intents(state: &AppState, server_did: &str) {
    let intents = match domain_intents(state, server_did).await {
        Ok(i) => i,
        Err(e) => {
            warn!(server_did, error = %e, "domain resync: failed to list domain intents");
            return;
        }
    };
    for intent in intents {
        let ops: &[&str] = match intent.op {
            DomainOp::Assign => &[MSG_DOMAIN_ASSIGN],
            DomainOp::Unassign => &[MSG_DOMAIN_UNASSIGN],
            DomainOp::Purge => &[MSG_DOMAIN_UNASSIGN, MSG_DOMAIN_PURGE],
        };
        for op in ops {
            if let Err(e) = crate::outbox::enqueue(
                &state.store,
                server_did,
                op,
                json!({ "domain": intent.domain }),
            )
            .await
            {
                warn!(server_did, domain = %intent.domain, op, error = %e, "domain resync: enqueue failed");
            }
        }
    }
    state.outbox_notify.notify_one();
}

/// Enqueue `MSG_DOMAIN_ASSIGN { domain }` for one server. Returns once
/// the outbox row is durable; the worker handles actual delivery and
/// retry.
pub async fn send_domain_assign(
    state: &AppState,
    target_did: &str,
    domain: &str,
) -> Result<(), did_hosting_common::server::error::AppError> {
    record_domain_intent(state, target_did, domain, DomainOp::Assign).await?;
    crate::outbox::enqueue_and_notify(
        state,
        target_did,
        MSG_DOMAIN_ASSIGN,
        json!({ "domain": domain }),
    )
    .await?;
    Ok(())
}

/// Enqueue `MSG_DOMAIN_PURGE { domain }` for one server. Bypasses the
/// grace window on the recipient (audit-logged as
/// `reason: "admin-immediate"`). Use sparingly.
pub async fn send_domain_purge(
    state: &AppState,
    target_did: &str,
    domain: &str,
) -> Result<(), did_hosting_common::server::error::AppError> {
    record_domain_intent(state, target_did, domain, DomainOp::Purge).await?;
    crate::outbox::enqueue_and_notify(
        state,
        target_did,
        MSG_DOMAIN_PURGE,
        json!({ "domain": domain }),
    )
    .await?;
    Ok(())
}

/// Enqueue `MSG_DOMAIN_UNASSIGN { domain }` for one server. Same
/// at-least-once semantics as [`send_domain_assign`].
pub async fn send_domain_unassign(
    state: &AppState,
    target_did: &str,
    domain: &str,
) -> Result<(), did_hosting_common::server::error::AppError> {
    record_domain_intent(state, target_did, domain, DomainOp::Unassign).await?;
    crate::outbox::enqueue_and_notify(
        state,
        target_did,
        MSG_DOMAIN_UNASSIGN,
        json!({ "domain": domain }),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Domain replication push (split-deployment lifecycle)
// ---------------------------------------------------------------------------

/// Enqueue `MSG_DOMAIN_UPSERT { ...DomainEntry }` for one server.
/// Replicates a control-side create / update / disable / enable so the
/// server's local store + sweeper stay in sync. Idempotent on the
/// receiver — re-sending the same row is harmless.
pub async fn send_domain_upsert(
    state: &AppState,
    target_did: &str,
    entry: &did_hosting_common::server::domain::DomainEntry,
) -> Result<(), did_hosting_common::server::error::AppError> {
    let body = serde_json::to_value(entry).map_err(|e| {
        did_hosting_common::server::error::AppError::Internal(format!("serialise DomainEntry: {e}"))
    })?;
    crate::outbox::enqueue_and_notify(state, target_did, MSG_DOMAIN_UPSERT, body).await?;
    Ok(())
}

/// Replicate every control-side `DomainEntry` to one server, then re-send its
/// unsettled domain assign/unassign/purge ops ([`resend_domain_intents`]) — run
/// on each (re-)registration so a server that missed any of them while
/// unreachable converges on the control plane's domain records, statuses and
/// assignments.
pub fn sync_all_domains_to_server(state: &AppState, server_did: String) {
    let state = state.clone();
    tokio::spawn(async move {
        sync_all_domains_now(&state, &server_did).await;
    });
}

/// The body of [`sync_all_domains_to_server`], awaited (for tests).
pub async fn sync_all_domains_now(state: &AppState, server_did: &str) {
    match did_hosting_common::server::domain::list_domains(&state.store).await {
        Ok(domains) => {
            for entry in &domains {
                if let Err(e) = send_domain_upsert(state, server_did, entry).await {
                    warn!(server_did, domain = %entry.name, error = %e, "domain resync: enqueue failed");
                }
            }
        }
        Err(e) => warn!(server_did, error = %e, "domain resync: list failed"),
    }
    resend_domain_intents(state, server_did).await;
}

/// Fan an upsert out to every registered server. Used after every
/// successful control-side domain mutation so each server eventually
/// applies the change to its local DomainEntry copy + grace timer.
///
/// Enqueues one outbox entry per server; the worker handles delivery
/// and retry. A registry-list failure is logged and skipped — there are
/// no rows to enqueue against. Returns `(enqueued, skipped)` for the
/// caller's log line; `enqueued` is the number of outbox rows
/// committed, NOT the number of servers that have acked.
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
                // Legacy instance without `did` metadata — can't
                // address. Operator must re-register with a DID.
                skipped += 1;
                continue;
            }
        };
        match send_domain_upsert(state, &did, entry).await {
            Ok(()) => enqueued += 1,
            Err(e) => {
                warn!(
                    target_did = %did,
                    domain = %entry.name,
                    error = %e,
                    "fanout_domain_upsert: enqueue failed"
                );
                skipped += 1;
            }
        }
    }
    (enqueued, skipped)
}

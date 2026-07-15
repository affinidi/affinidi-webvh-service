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

/// Enqueue published DIDs to one server's outbox — only the ones it doesn't
/// already have at the current version.
///
/// `reported` maps mnemonic → the `version_count` the registering server says
/// it already holds (from the `preloaded_dids` in its register payload). Any
/// DID at or above that version is skipped. An **empty** map means a full push
/// — the back-compat path for a client that sends no `preloaded_dids`, and the
/// correct behaviour for a server with an empty store.
///
/// Each DID is one outbox row; the worker drains them in enqueue order so the
/// server applies them deterministically, and a control restart mid-bulk
/// resumes from the remaining rows. Sending only the delta is what keeps a
/// reboot from re-pushing every DID (and re-triggering the server's own-DID
/// identity-rotation check) at thousands-of-DIDs scale.
pub fn sync_all_dids_to_server(
    state: &AppState,
    server_did: String,
    reported: std::collections::HashMap<String, u64>,
) {
    let dids_ks = state.dids_ks.clone();
    let store = state.store.clone();
    let notify = state.outbox_notify.clone();

    tokio::spawn(async move {
        // Iterate all published DIDs
        let raw = match dids_ks.prefix_iter_raw("did:").await {
            Ok(raw) => raw,
            Err(e) => {
                warn!(error = %e, "sync_all_dids: failed to iterate DIDs");
                return;
            }
        };

        let mut count = 0u64;
        for (_key, value) in raw {
            let record: DidRecord = match serde_json::from_slice(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };

            if record.version_count == 0 {
                continue;
            }

            // Delta: the registering server already has this DID at this
            // version or newer — nothing to push.
            if reported
                .get(&record.mnemonic)
                .is_some_and(|&have| have >= record.version_count)
            {
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

            if let Err(e) = crate::outbox::enqueue(&store, &server_did, MSG_SYNC_UPDATE, body).await
            {
                warn!(
                    server_did = %server_did,
                    mnemonic = %record.mnemonic,
                    error = %e,
                    "sync_all_dids: outbox enqueue failed"
                );
            } else {
                count += 1;
            }
        }

        if count > 0 {
            notify.notify_one();
            info!(
                server_did = %server_did,
                count,
                "initial DID sync queued for newly registered server"
            );
        }
    });
}

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

/// Enqueue `MSG_DOMAIN_ASSIGN { domain }` for one server. Returns once
/// the outbox row is durable; the worker handles actual delivery and
/// retry.
pub async fn send_domain_assign(
    state: &AppState,
    target_did: &str,
    domain: &str,
) -> Result<(), did_hosting_common::server::error::AppError> {
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

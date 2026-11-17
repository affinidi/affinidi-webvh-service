//! Domain pushes: assign / unassign / purge, the recorded intents that are
//! re-sent until a server acknowledges them, and domain-record replication.

use did_hosting_common::didcomm_types::*;
use tracing::{info, warn};

use crate::registry;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Domain assignment push
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
/// — run on each (re-)registration (by [`resync_server`](super::resync_server)) so a server that
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

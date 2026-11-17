//! Control-plane infrastructure trust tasks: server registration, health, and
//! stats sync.
//!
//! These are the control↔server ops that used to exist only as legacy `MSG_*`
//! DIDComm messages, which made them DIDComm-only and therefore invisible to a
//! TSP-only server. As trust-task documents they route through the same
//! `crate::messaging::dispatch_trust_task_doc` entry that TSP, the DIDComm
//! envelope, and HTTPS all share — so the binding is chosen from the peer's DID
//! document rather than hard-coded.
//!
//! ## One Type URI per op, on every wire
//!
//! The `MSG_*` constants in `didcomm_types` are *already* canonical Trust-Task
//! Type URIs, with the `_ACK` / `_PONG` forms being the `#response` variant of
//! their request:
//!
//! ```text
//! MSG_SERVER_REGISTER      .../spec/did-management/server/register/0.2
//! MSG_SERVER_REGISTER_ACK  .../spec/did-management/server/register/0.2#response
//! MSG_HEALTH_PING          .../spec/did-management/server/health/0.1
//! MSG_HEALTH_PONG          .../spec/did-management/server/health/0.1#response
//! MSG_STATS_SYNC           .../spec/did-management/server/stats-sync/0.1
//! MSG_STATS_ACK            .../spec/did-management/server/stats-sync/0.1#response
//! ```
//!
//! So we reuse them verbatim as document Type URIs. The op has one identity
//! whether it travels as a DIDComm `typ`, inside a trust-task envelope, or as a
//! raw TSP frame — and `TrustTask::respond_with` *derives* the reply URI rather
//! than us restating it. `send::msg_constants_are_request_response_type_uri_pairs`
//! pins that.
//!
//! Note the unused `TASK_SERVER_HEALTH_PING_1_0` / `_PONG_1_0` constants in
//! `did_hosting_tasks` are **not** used here: they sit on the `/did-hosting/`
//! authority with no `/spec/` segment, so they don't parse as Type URIs at all,
//! and they wrongly model the response as a separate URI instead of a fragment.
//! They are route-header decorators for the HTTPS surface, nothing more.
//!
//! ## Authorisation
//!
//! Every document reaching [`dispatch`] has already passed
//! `crate::messaging::dispatch_trust_task_doc`'s proof gate, so `signer` is
//! the DID whose key signed it — not a transport's report. Registration, stats
//! sync, health pongs and domain acks then require that DID to hold the
//! `Service` role in the ACL; sync acks are only logged. Their proof rule is
//! stated here ([`proof_rule`]: `authentication`), not left to the
//! dispatcher's default for an unknown Type URI, and the proof gate supplies
//! what the typed §7.2 pipeline would (issuer binding, audience, freshness,
//! replay).
//!
//! Payloads are typed and closed: registration and the replica acks by their
//! generated types; stats sync and the health pong in the pinned
//! `server/stats-sync/0.1` and `server/health/0.1` shapes, which
//! `did_hosting_common::server::trust_tasks::infra` builds and reads for
//! both ends (our extras under `ext`; the pre-#449 shape still read for one
//! release).
//! A refusal is a `messaging::InfraRejection`, each kind its own standard
//! code on the wire.

use serde_json::Value;
use tracing::warn;

use did_hosting_common::didcomm_types::{
    MSG_HEALTH_PONG, MSG_REPLICA_DOMAIN_ASSIGN_ACK, MSG_REPLICA_DOMAIN_PURGE_ACK,
    MSG_REPLICA_DOMAIN_UNASSIGN_ACK, MSG_REPLICA_DOMAIN_UPSERT_ACK, MSG_SERVER_REGISTER,
    MSG_SERVER_REGISTER_ACK, MSG_STATS_ACK, MSG_STATS_SYNC, MSG_SYNC_BATCH_ACK,
    MSG_SYNC_DELETE_ACK, MSG_SYNC_UPDATE_ACK,
};
use did_hosting_common::server::didcomm_profile::ObservedTransport;
use did_hosting_common::server::trust_tasks::ProofRule;

use crate::registry;
use crate::server::AppState;

// The handler modules below reach the messaging scope through this.
#[allow(unused_imports)]
use super::*;

pub(super) mod acks;
pub(super) mod health;
pub(super) mod register;
pub(super) mod stats_sync;

/// Does this Type URI belong to the infrastructure ops handled here?
///
/// Compared on the full string, fragment included: `register/0.1` is a request
/// we act on, while `register/0.1#response` is an ack *we* emit and must never
/// route back into ourselves. The sync and domain `#response` acks are the
/// other way round — edges emit them, we receive them.
pub fn owns(type_uri: &str) -> bool {
    INFRA_TASK_URIS.contains(&type_uri)
}

/// Every Type URI [`owns`] claims, in one list the Trust Task catalogue
/// (`docs/trust-tasks.md`) is generated from.
pub const INFRA_TASK_URIS: &[&str] = &[
    MSG_SERVER_REGISTER,
    MSG_HEALTH_PONG,
    MSG_STATS_SYNC,
    MSG_SYNC_UPDATE_ACK,
    MSG_SYNC_BATCH_ACK,
    MSG_SYNC_DELETE_ACK,
    MSG_REPLICA_DOMAIN_ASSIGN_ACK,
    MSG_REPLICA_DOMAIN_UNASSIGN_ACK,
    MSG_REPLICA_DOMAIN_PURGE_ACK,
    MSG_REPLICA_DOMAIN_UPSERT_ACK,
];

/// What an infrastructure task's proof must be: every one is an operational
/// message an edge (or a configured watcher, for its acknowledgements) signs
/// for `authentication`, by a signer the ACL lists. Stated here rather than
/// left to the dispatcher's default for a Type URI it does not know, so a
/// change to that default cannot loosen these.
pub fn proof_rule(type_uri: &str) -> Option<ProofRule> {
    owns(type_uri).then_some(ProofRule::Authentication)
}

/// Handle an infrastructure trust task signed by `sender` (the proven issuer).
///
/// Returns the serialised response document, or `None` when the op is terminal
/// (a health pong is an answer, not a question).
///
/// `via` is the transport the document actually arrived on, derived from the
/// caller's `TransportHandler::binding_uri()`. `None` when the binding is one
/// we don't recognise — recorded as "unknown" rather than guessed. The dispatch
/// itself stays transport-agnostic; this is observability only.
pub async fn dispatch(
    state: &AppState,
    sender: &str,
    via: Option<ObservedTransport>,
    doc: trust_tasks_rs::TrustTask<Value>,
) -> Option<Value> {
    let response = dispatch_inner(state, sender, doc).await;

    // *After* the dispatch, deliberately. A registration creates the instance,
    // so recording beforehand would find nothing to write to and the very
    // message that enrolled the server would go unobserved.
    if let Some(via) = via {
        registry::record_inbound_transport(
            &state.registry_ks,
            sender,
            via,
            crate::auth::session::now_epoch(),
        )
        .await;
    }

    response
}

async fn dispatch_inner(
    state: &AppState,
    sender: &str,
    doc: trust_tasks_rs::TrustTask<Value>,
) -> Option<Value> {
    match doc.type_uri.to_string().as_str() {
        MSG_SERVER_REGISTER => {
            let reply_id = uuid::Uuid::new_v4().to_string();
            match crate::messaging::do_server_register(state, sender, &doc.payload).await {
                Ok(ack) => {
                    let ack = serde_json::to_value(ack).expect("a register ack serialises");
                    let resp = doc.respond_with(reply_id, ack);
                    debug_assert_eq!(resp.type_uri.to_string(), MSG_SERVER_REGISTER_ACK);
                    Some(serde_json::to_value(&resp).expect("ack document serialises"))
                }
                Err(rej) => {
                    warn!(sender, refusal = %rej, "server registration rejected (trust task)");
                    let err = doc.reject_with(reply_id, rej.reject_reason());
                    Some(serde_json::to_value(&err).expect("error document serialises"))
                }
            }
        }
        MSG_STATS_SYNC => {
            let reply_id = uuid::Uuid::new_v4().to_string();
            match crate::messaging::do_stats_sync(state, sender, &doc.payload).await {
                Ok(ack) => {
                    let resp = doc.respond_with(reply_id, ack);
                    debug_assert_eq!(resp.type_uri.to_string(), MSG_STATS_ACK);
                    Some(serde_json::to_value(&resp).expect("ack document serialises"))
                }
                Err(rej) => {
                    let err = doc.reject_with(reply_id, rej.reject_reason());
                    Some(serde_json::to_value(&err).expect("error document serialises"))
                }
            }
        }
        MSG_HEALTH_PONG => {
            crate::messaging::do_health_pong(state, sender, &doc.payload).await;
            None
        }
        uri @ (MSG_SYNC_UPDATE_ACK | MSG_SYNC_BATCH_ACK | MSG_SYNC_DELETE_ACK) => {
            crate::messaging::do_sync_ack(sender, uri, &doc.payload);
            acknowledge_outbox(state, sender, &doc).await;
            None
        }
        uri @ (MSG_REPLICA_DOMAIN_ASSIGN_ACK
        | MSG_REPLICA_DOMAIN_UNASSIGN_ACK
        | MSG_REPLICA_DOMAIN_PURGE_ACK) => {
            crate::messaging::do_domain_ack(state, sender, uri, &doc.payload).await;
            acknowledge_outbox(state, sender, &doc).await;
            None
        }
        // The upsert ack carries nothing the registry tracks; it only settles
        // the outbox entry.
        MSG_REPLICA_DOMAIN_UPSERT_ACK => {
            acknowledge_outbox(state, sender, &doc).await;
            None
        }
        // `owns` gates this; a mismatch means the two drifted.
        other => {
            warn!(type_uri = other, "trust_tasks_infra: unowned type URI");
            None
        }
    }
}

/// Settle the outbox entry an acknowledgement answers: the document it threads
/// to, from the server that signed it. Only a Service-role signer settles
/// anything — `sender` is the proven issuer.
pub(crate) async fn acknowledge_outbox(
    state: &AppState,
    sender: &str,
    doc: &trust_tasks_rs::TrustTask<Value>,
) {
    let thread = doc.thread_id.as_deref().or_else(|| {
        doc.payload
            .get("inResponseTo")
            .and_then(|r| r.get("id"))
            .and_then(Value::as_str)
    });
    let Some(thread) = thread else {
        return;
    };
    // A registered Service settles what it was sent; so does a configured
    // watcher (see `server_push::is_configured_watcher`). The outbox only ever
    // settles an entry on its own target's signature either way.
    if !crate::server_push::is_configured_watcher(state, sender) {
        match did_hosting_common::server::acl::check_acl(&state.acl_ks, sender).await {
            Ok(did_hosting_common::server::acl::Role::Service) => {}
            // Not settled either way: a failed lookup is no answer about the
            // sender, and the entry stays queued to be acknowledged again.
            Err(e) if !did_hosting_common::server::acl::is_acl_refusal(&e) => {
                warn!(sender, error = %e, "acknowledgement ignored: ACL lookup failed");
                return;
            }
            _ => {
                warn!(sender, "acknowledgement ignored: Service role required");
                return;
            }
        }
    }
    match crate::outbox::acknowledge(state, sender, thread).await {
        Ok(true) => {
            crate::registry::record_ack(
                &state.registry_ks,
                sender,
                crate::auth::session::now_epoch(),
            )
            .await;
            state.outbox_notify.notify_one();
        }
        Ok(false) => tracing::debug!(sender, thread, "acknowledgement for no awaited entry"),
        Err(e) => warn!(sender, error = %e, "failed to settle acknowledged outbox entry"),
    }
}

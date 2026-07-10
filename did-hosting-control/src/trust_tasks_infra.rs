//! Control-plane infrastructure trust tasks: server registration and health.
//!
//! These are the control↔server ops that used to exist only as legacy `MSG_*`
//! DIDComm messages, which made them DIDComm-only and therefore invisible to a
//! TSP-only server. As trust-task documents they route through the same
//! [`crate::messaging::dispatch_trust_task_doc`] entry that TSP, the DIDComm
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
//! MSG_SERVER_REGISTER      .../spec/did-management/server/register/0.1
//! MSG_SERVER_REGISTER_ACK  .../spec/did-management/server/register/0.1#response
//! MSG_HEALTH_PING          .../spec/did-management/server/health/0.1
//! MSG_HEALTH_PONG          .../spec/did-management/server/health/0.1#response
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
//! ## Why this bypasses the §7.2 pipeline
//!
//! Registration authenticates via the ACL (`Service` role) against the
//! transport-proven sender, exactly as the DIDComm route did. Health pong
//! carries no authority at all — it only marks an already-registered instance
//! Active, keyed by sender DID. Neither needs proof verification or audience
//! binding beyond what the transport already guarantees, and running them
//! through `dispatch_inbound` would demand typed payload specs that don't exist
//! upstream. If these ops ever grow authority, move them onto the typed
//! pipeline like `trust_tasks_did`.

use serde_json::Value;
use tracing::warn;

use did_hosting_common::didcomm_types::{
    MSG_HEALTH_PONG, MSG_SERVER_REGISTER, MSG_SERVER_REGISTER_ACK,
};
use did_hosting_common::server::didcomm_profile::ObservedTransport;

use crate::registry;
use crate::server::AppState;

/// Does this Type URI belong to the infrastructure ops handled here?
///
/// Compared on the full string, fragment included: `register/0.1` is a request
/// we act on, while `register/0.1#response` is an ack *we* emit and must never
/// route back into ourselves.
pub fn owns(type_uri: &str) -> bool {
    matches!(type_uri, MSG_SERVER_REGISTER | MSG_HEALTH_PONG)
}

/// Handle an infrastructure trust task from `sender`.
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
                    let resp = doc.respond_with(reply_id, ack);
                    debug_assert_eq!(resp.type_uri.to_string(), MSG_SERVER_REGISTER_ACK);
                    Some(serde_json::to_value(&resp).expect("ack document serialises"))
                }
                Err(rej) => {
                    let err = doc.reject_with(
                        reply_id,
                        trust_tasks_rs::RejectReason::PermissionDenied {
                            reason: rej.comment.clone(),
                        },
                    );
                    warn!(
                        sender,
                        code = rej.code,
                        comment = %rej.comment,
                        "server registration rejected (trust task)"
                    );
                    Some(serde_json::to_value(&err).expect("error document serialises"))
                }
            }
        }
        MSG_HEALTH_PONG => {
            crate::messaging::do_health_pong(state, sender, &doc.payload).await;
            None
        }
        // `owns` gates this; a mismatch means the two drifted.
        other => {
            warn!(type_uri = other, "trust_tasks_infra: unowned type URI");
            None
        }
    }
}

//! Server-side infrastructure trust tasks: health ping, register ack, stats ack.
//!
//! The mirror of `did-hosting-control`'s `trust_tasks_infra`. Both sides speak
//! the same Type URIs — the `MSG_*` constants, which are already canonical
//! Trust-Task URIs with `#response` fragments for their replies — so an op has
//! one identity whether it arrives inside a trust-task envelope or as a raw
//! TSP frame.
//!
//! This is what makes a **TSP-only server** work. Before it existed the server
//! had no trust-task dispatcher at all: its TSP handler parsed the payload as a
//! DIDComm `Message`, and health lived only on the DIDComm router. A node that
//! advertised `TSPTransport` and disabled DIDComm could never answer a ping and
//! sat in the dashboard as `Unreachable` forever.
//!
//! The reply is *returned*, not sent: each transport routes it back over the
//! same connection the request arrived on (`TspResponse` for TSP,
//! `DIDCommResponse` for the envelope). So a ping delivered over TSP is ponged
//! over TSP without either side re-resolving anything.

use serde_json::{Value, json};
use tracing::{debug, info, warn};

use did_hosting_common::didcomm_types::{MSG_HEALTH_PING, MSG_SERVER_REGISTER_ACK, MSG_STATS_ACK};

use crate::server::AppState;

/// Does this Type URI belong to the infrastructure ops handled here?
pub fn owns(type_uri: &str) -> bool {
    matches!(
        type_uri,
        MSG_HEALTH_PING | MSG_SERVER_REGISTER_ACK | MSG_STATS_ACK
    )
}

/// Handle an infrastructure trust task, returning the (unsigned) reply document,
/// or `None` when the op is terminal (an ack is an answer, not a question).
///
/// A health ping is answered only when the control plane signed it (see
/// [`crate::messaging::verify_control_plane`]); any other ping gets no reply
/// at all. The pong discloses the DID count, and answering an unauthenticated
/// ping — even with a refusal — would make this server a reflector for anyone
/// who can reach its mediator. The two acks are advisory
/// — logged and nothing else — so they need no authority.
pub async fn dispatch(
    state: &AppState,
    sender: Option<&str>,
    doc: trust_tasks_rs::TrustTask<Value>,
) -> Option<trust_tasks_rs::TrustTask<Value>> {
    match doc.type_uri.to_string().as_str() {
        MSG_HEALTH_PING => {
            let verifier = crate::messaging::state_verifier(state)?;
            // A ping that is not the control plane's gets no answer — not even
            // a (signed) refusal, which would make this server answer
            // strangers. `verify_control_plane` has logged why.
            crate::messaging::verify_control_plane(state, sender, &doc, &verifier)
                .await
                .ok()?;
            let pong = do_health_ping(state).await;
            debug!(sender, "health ping answered (trust task)");
            Some(doc.respond_with(uuid::Uuid::new_v4().to_string(), pong))
        }
        MSG_SERVER_REGISTER_ACK => {
            do_register_ack(&doc.payload);
            None
        }
        // Advisory: stats are fire-and-forget. Owned so the ack isn't warned
        // about as an unimplemented type on every sync tick.
        MSG_STATS_ACK => None,
        other => {
            warn!(type_uri = other, "trust_tasks_infra: unowned type URI");
            None
        }
    }
}

/// Transport-agnostic core of the health ping: report liveness and DID count.
///
/// Shared by every transport's trust-task dispatch.
pub(crate) async fn do_health_ping(state: &AppState) -> Value {
    let did_count = state
        .dids_ks
        .prefix_iter_raw("did:")
        .await
        .map(|v| v.len() as u64)
        .unwrap_or(0);

    json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "did_count": did_count,
    })
}

/// Transport-agnostic core of the registration ack — informational only.
pub(crate) fn do_register_ack(body: &Value) {
    let instance_id = body
        .get("instance_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    info!(instance_id, "registration acknowledged by control plane");
}

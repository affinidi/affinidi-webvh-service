//! TSP receive path for `did-hosting-server`.
//!
//! The messaging-service framework unpacks each TSP frame off the shared
//! mediator socket, authenticates the sender VID, and hands us the cleartext
//! payload. **Two payload shapes arrive here**, and we sniff between them:
//!
//! 1. A **trust-task document** (`TrustTask<Value>`) — health ping, register
//!    or stats ack. Carried either inside the `binding/tsp/0.1` envelope (what a
//!    conformant peer sends) or bare (this repo's pre-binding dialect);
//!    [`did_hosting_common::server::tsp_binding`] reads both and says why, and
//!    the reply goes back in whichever arrived. Dispatched through
//!    [`crate::trust_tasks_infra`], the same entry the DIDComm envelope route
//!    uses. The response is *returned*, so the framework seals it back to the
//!    sender over TSP: a ping delivered here is ponged here.
//! 2. A serialised DIDComm [`Message`] — the control plane's outbox sends
//!    sync/domain pushes this way (`control/src/outbox.rs`). Routed to the same
//!    `do_*` cores the DIDComm listener uses via
//!    [`crate::messaging::dispatch_tsp_message`]. Fire-and-forget: the outbox
//!    treats a successful send as delivery, so no ack is routed back.
//!
//! Sniffing rather than switching conventions is deliberate. The outbox on a
//! *deployed* control plane already ships DIDComm `Message` bytes over TSP; a
//! server that stopped accepting them would break every rolling upgrade.
//!
//! The two shapes are unambiguous, but **not** for the obvious reason. A
//! `Message` also carries top-level `id` and `type`, and its `type` (e.g.
//! `MSG_SYNC_UPDATE`) is itself a canonical Type URI, so both fields parse.
//! What separates them is `payload`: `TrustTask` requires it and has no serde
//! default, while a `Message` carries `body` instead. So a `Message` can never
//! deserialise as a `TrustTask`, and trust tasks may safely be tried first.
//! `didcomm_message_never_parses_as_a_trust_task` pins that — if it ever
//! stopped holding, every sync/domain push over TSP would be silently swallowed
//! by the `owns()` gate below.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, HandlerContext, TspHandler, TspResponse,
};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{debug, warn};

use did_hosting_common::server::tsp_binding;

use crate::messaging::dispatch_tsp_message;
use crate::server::AppState;

/// messaging-service [`TspHandler`] that applies inbound sync/domain
/// messages delivered over TSP.
pub struct ServerTspHandler {
    state: AppState,
}

impl ServerTspHandler {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TspHandler for ServerTspHandler {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        payload: Vec<u8>,
        sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError> {
        // Read the binding envelope off first, if this frame is in it. A
        // conformant peer (the VTA) wraps; a not-yet-upgraded sibling sends the
        // bare document. `tsp_binding` explains why both are accepted, and
        // `carriage` is what the reply is framed for.
        //
        // Shape 2 below is unaffected: the control plane's outbox ships DIDComm
        // `Message` bytes, which are not trust tasks and were never wrapped, so
        // they fall through `open` as `Bare` and are read exactly as before.
        let (document, carriage) = tsp_binding::open(&payload);

        // Shape 1: a trust-task document. Tried first — see the module note.
        if let Ok(doc) = serde_json::from_slice::<trust_tasks_rs::TrustTask<Value>>(&document) {
            let type_uri = doc.type_uri.to_string();
            if crate::trust_tasks_infra::owns(&type_uri) {
                // Infra trust tasks are the periodic health ping (~every 60s)
                // and the register ack — routine liveness traffic, not events.
                // Keep the receipt at debug; the meaningful outcomes (server
                // registered, health status changes) log at info elsewhere.
                debug!(sender = %sender_vid, %type_uri, "inbound TSP: trust task");
                return Ok(
                    match crate::trust_tasks_infra::dispatch(&self.state, &sender_vid, doc).await {
                        Some(resp) => Some(TspResponse::new(tsp_binding::frame(
                            serde_json::to_vec(&resp)
                                .map_err(|e| DIDCommServiceError::Internal(e.to_string()))?,
                            carriage,
                        ))),
                        None => None,
                    },
                );
            }
            warn!(
                sender = %sender_vid,
                %type_uri,
                "inbound TSP: trust task of a type this server does not implement"
            );
            return Ok(None);
        }

        // Shape 2: a serialised DIDComm Message from the control plane's outbox.
        // Read from `document`, which is the original payload whenever the
        // frame was not an envelope — the case this shape is always in.
        let msg: Message = match serde_json::from_slice(&document) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    sender = %sender_vid,
                    error = %e,
                    "TSP: payload is neither a trust task nor a DIDComm Message"
                );
                return Ok(None);
            }
        };
        // Transport receipt — one per synced DID. The applied-update outcome
        // logs at info in `control_register::apply_single_update`; keep this at
        // debug so a bulk sync doesn't spam.
        debug!(sender = %sender_vid, msg_type = %msg.typ, "inbound TSP: server sync/domain message");
        // Apply via the shared `do_*` cores (which authorise the sender as
        // the control plane). Fire-and-forget: the ack is dropped, mirroring
        // the outbox's send-success-is-delivery model.
        let _ = dispatch_tsp_message(&self.state, &sender_vid, &msg).await;
        Ok(None)
    }

    /// Answer an inbound TSP relationship control message. This is the arm that
    /// clears the `no relationship with … discarded` drop the edge logs when it
    /// has lost its half of the relationship: on the control plane's (or its
    /// own connect-time) re-invite it accepts, restoring `Bidirectional` so the
    /// control plane's sync/health pushes are admitted again. Shared policy in
    /// `did_hosting_common::server::tsp_relationship` — see its module docs.
    async fn handle_control(
        &self,
        ctx: HandlerContext,
        control: affinidi_tsp::message::control::ControlMessage,
        sender_vid: String,
        thread_digest: [u8; 32],
    ) {
        did_hosting_common::server::tsp_relationship::answer_inbound_control(
            &ctx,
            &control,
            &sender_vid,
            thread_digest,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_hosting_common::didcomm_types::{MSG_HEALTH_PING, MSG_SYNC_UPDATE};
    use serde_json::json;

    /// The load-bearing assumption of the payload sniff in `handle`.
    ///
    /// A DIDComm `Message` carries `id` and `type` just like a trust task, and
    /// `MSG_SYNC_UPDATE` is a canonical Type URI — so neither field
    /// discriminates. Only `payload` does: `TrustTask` requires it, `Message`
    /// has `body` instead.
    ///
    /// If this ever passed, the `owns()` gate would reject the misparsed sync
    /// message and `handle` would return `Ok(None)` — silently discarding every
    /// DID sync and domain push the control plane sends over TSP.
    #[test]
    fn didcomm_message_never_parses_as_a_trust_task() {
        let msg = Message::build(
            "msg-1".to_string(),
            MSG_SYNC_UPDATE.to_string(),
            json!({ "mnemonic": "alice", "log_content": "..." }),
        )
        .finalize();
        let bytes = serde_json::to_vec(&msg).expect("message serialises");

        let parsed = serde_json::from_slice::<trust_tasks_rs::TrustTask<Value>>(&bytes);
        assert!(
            parsed.is_err(),
            "a DIDComm Message must not deserialise as a TrustTask — the TSP \
             sniff depends on it; got {parsed:?}"
        );
    }

    /// And the converse, so the fall-through can't misfire either.
    #[test]
    fn trust_task_never_parses_as_a_didcomm_message() {
        let doc = did_hosting_common::server::trust_tasks::send::build_request(
            MSG_HEALTH_PING,
            "did:example:control",
            "did:example:server",
            json!({}),
        )
        .expect("build request");
        let bytes = serde_json::to_vec(&doc).expect("doc serialises");

        assert!(
            serde_json::from_slice::<Message>(&bytes).is_err(),
            "a TrustTask must not deserialise as a DIDComm Message"
        );
    }

    /// The infra dispatcher owns exactly the ops the server implements — and
    /// must not claim the sync/domain types, which travel as `Message`s.
    #[test]
    fn infra_owns_only_health_ping_and_acks() {
        use crate::trust_tasks_infra::owns;
        use did_hosting_common::didcomm_types::{
            MSG_DOMAIN_ASSIGN, MSG_SERVER_REGISTER_ACK, MSG_STATS_ACK, MSG_STATS_SYNC,
        };

        assert!(owns(MSG_HEALTH_PING));
        assert!(owns(MSG_SERVER_REGISTER_ACK));
        // The stats ack answers every sync tick; unowned, it would be warned
        // about as an unimplemented type each time.
        assert!(owns(MSG_STATS_ACK));
        // The server *sends* the request; it must never route it to itself.
        assert!(!owns(MSG_STATS_SYNC));
        assert!(!owns(MSG_SYNC_UPDATE));
        assert!(!owns(MSG_DOMAIN_ASSIGN));
    }
}

//! TSP receive path for `did-hosting-server`.
//!
//! The messaging-service framework unpacks each TSP frame off the shared
//! mediator socket, authenticates the sender VID, and hands us the cleartext
//! payload. **Two payload shapes arrive here**, and we sniff between them:
//!
//! 1. A **trust-task document** (`TrustTask<Value>`) — health ping, register
//!    ack. Dispatched through [`crate::trust_tasks_infra`], the same entry the
//!    DIDComm envelope route uses. The response is *returned*, so the framework
//!    seals it back to the sender over TSP: a ping delivered here is ponged
//!    here.
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
use tracing::{info, warn};

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
        // Shape 1: a trust-task document. Tried first — see the module note.
        if let Ok(doc) = serde_json::from_slice::<trust_tasks_rs::TrustTask<Value>>(&payload) {
            let type_uri = doc.type_uri.to_string();
            if crate::trust_tasks_infra::owns(&type_uri) {
                info!(sender = %sender_vid, %type_uri, "inbound TSP: trust task");
                return Ok(
                    match crate::trust_tasks_infra::dispatch(&self.state, &sender_vid, doc).await {
                        Some(resp) => Some(TspResponse::new(
                            serde_json::to_vec(&resp)
                                .map_err(|e| DIDCommServiceError::Internal(e.to_string()))?,
                        )),
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
        let msg: Message = match serde_json::from_slice(&payload) {
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
        info!(sender = %sender_vid, msg_type = %msg.typ, "inbound TSP: server sync/domain message");
        // Apply via the shared `do_*` cores (which authorise the sender as
        // the control plane). Fire-and-forget: the ack is dropped, mirroring
        // the outbox's send-success-is-delivery model.
        let _ = dispatch_tsp_message(&self.state, &sender_vid, &msg).await;
        Ok(None)
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

    /// The infra dispatcher owns exactly the two ops the server implements —
    /// and must not claim the sync/domain types, which travel as `Message`s.
    #[test]
    fn infra_owns_only_health_ping_and_register_ack() {
        use crate::trust_tasks_infra::owns;
        use did_hosting_common::didcomm_types::{MSG_DOMAIN_ASSIGN, MSG_SERVER_REGISTER_ACK};

        assert!(owns(MSG_HEALTH_PING));
        assert!(owns(MSG_SERVER_REGISTER_ACK));
        assert!(!owns(MSG_SYNC_UPDATE));
        assert!(!owns(MSG_DOMAIN_ASSIGN));
    }
}

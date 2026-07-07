//! TSP receive path for `did-hosting-server`.
//!
//! The control plane's outbox pushes sync/domain updates to registered
//! servers. When a target server advertises a `TSPTransport` service, the
//! control plane sends the update over TSP (see the control `outbox`); this
//! handler is the receiving end. It mirrors the control plane's
//! `WebvhTspHandler`: the messaging-service framework unpacks the TSP frame
//! off the shared mediator socket, authenticates the sender VID, and hands
//! us the cleartext payload — a serialised DIDComm [`Message`] — which we
//! route to the same `do_*` cores the DIDComm listener uses via
//! [`crate::messaging::dispatch_tsp_message`].
//!
//! Delivery is fire-and-forget over TSP (the control outbox treats a
//! successful send as delivery, so no ack is routed back), matching the
//! DIDComm path's non-blocking sync semantics.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, HandlerContext, TspHandler, TspResponse,
};
use async_trait::async_trait;
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
        let msg: Message = match serde_json::from_slice(&payload) {
            Ok(m) => m,
            Err(e) => {
                warn!(sender = %sender_vid, error = %e, "TSP: payload is not a DIDComm Message");
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

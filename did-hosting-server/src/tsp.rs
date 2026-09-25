//! TSP receive path for `did-hosting-server`.
//!
//! The messaging-service framework unpacks each TSP frame off the shared
//! mediator socket and hands us the cleartext payload. Every payload is a
//! **trust-task document** (`TrustTask<Value>`) — a control-plane operation
//! (sync, domain), a health ping, or a register / stats ack — carried either
//! inside the `binding/tsp/0.1` envelope (what a conformant peer sends) or bare
//! (this repo's pre-binding dialect); [`did_hosting_common::server::tsp_binding`]
//! reads both and says why, and the reply goes back in whichever arrived.
//!
//! Dispatch is [`crate::messaging::dispatch_inbound_document`], the same entry
//! the DIDComm envelope route uses, so a control-plane operation is applied
//! only when the control plane signed it — the TSP sender VID is a routing
//! hint that must agree with the proof, never an authorisation by itself.
//!
//! A serialised DIDComm `Message` — how an older control plane's outbox sent
//! sync and domain pushes over TSP — is no longer accepted: it carries no proof
//! a receiver could check.

use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, HandlerContext, TspHandler, TspResponse,
};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{debug, warn};

use did_hosting_common::server::tsp_binding;

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
        let (document, carriage) = tsp_binding::open(&payload);

        let doc = match serde_json::from_slice::<trust_tasks_rs::TrustTask<Value>>(&document) {
            Ok(doc) => doc,
            Err(e) => {
                warn!(
                    sender = %sender_vid,
                    error = %e,
                    "inbound TSP: payload is not a trust-task document — dropped"
                );
                return Ok(None);
            }
        };
        debug!(sender = %sender_vid, type_uri = %doc.type_uri, "inbound TSP: trust task");
        match crate::messaging::dispatch_inbound_document(&self.state, Some(&sender_vid), doc).await
        {
            Some(reply) => Ok(Some(TspResponse::new(tsp_binding::frame(
                serde_json::to_vec(&reply)
                    .map_err(|e| DIDCommServiceError::Internal(e.to_string()))?,
                carriage,
            )))),
            None => Ok(None),
        }
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
    use did_hosting_common::didcomm_types::{
        MSG_DOMAIN_ASSIGN, MSG_HEALTH_PING, MSG_SERVER_REGISTER_ACK, MSG_STATS_ACK, MSG_STATS_SYNC,
        MSG_SYNC_UPDATE,
    };

    /// The infra dispatcher owns exactly the ops the server implements, and
    /// the control-plane operations are routed separately — never both.
    #[test]
    fn infra_and_control_plane_ops_are_disjoint() {
        use crate::messaging::CONTROL_PLANE_OPS;
        use crate::trust_tasks_infra::owns;

        assert!(owns(MSG_HEALTH_PING));
        assert!(owns(MSG_SERVER_REGISTER_ACK));
        // The stats ack answers every sync tick; unowned, it would be warned
        // about as an unimplemented type each time.
        assert!(owns(MSG_STATS_ACK));
        // The server *sends* the request; it must never route it to itself.
        assert!(!owns(MSG_STATS_SYNC));
        for op in CONTROL_PLANE_OPS {
            assert!(!owns(op), "{op} is a control-plane op, not an infra op");
        }
        assert!(CONTROL_PLANE_OPS.contains(&MSG_SYNC_UPDATE));
        assert!(CONTROL_PLANE_OPS.contains(&MSG_DOMAIN_ASSIGN));
    }
}

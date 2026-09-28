//! TSP receive path for the witness.
//!
//! The messaging-service framework unpacks each TSP frame off the mediator
//! socket and hands over the cleartext payload: a Trust Task document, inside
//! the `binding/tsp/0.1` envelope or bare
//! ([`did_hosting_common::server::tsp_binding`] reads both). It is dispatched
//! by [`crate::trust_tasks::dispatch_inbound_document`], the same entry the
//! DIDComm envelope route and `POST /api/trust-tasks` use; the TSP sender VID
//! is a routing hint that must agree with the proof.

use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, HandlerContext, TspHandler, TspResponse,
};
use async_trait::async_trait;
use serde_json::Value;
use tracing::warn;

use did_hosting_common::server::tsp_binding;

use crate::server::AppState;
use crate::trust_tasks::{Via, dispatch_inbound_document};

/// The messaging-service [`TspHandler`] for the witness.
pub struct WitnessTspHandler {
    state: AppState,
}

impl WitnessTspHandler {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

/// The TSP entry point, without the messaging framework around it: open the
/// frame, dispatch the Trust Task document it carries, and frame the reply the
/// same way. `Ok(None)` when there is nothing to answer.
pub async fn run_tsp_trust_task(
    state: &AppState,
    sender_vid: &str,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, DIDCommServiceError> {
    let (document, carriage) = tsp_binding::open(payload);
    let doc = match serde_json::from_slice::<trust_tasks_rs::TrustTask<Value>>(&document) {
        Ok(doc) => doc,
        Err(e) => {
            warn!(
                sender = %sender_vid,
                error = %e,
                "inbound TSP: payload is not a Trust Task document — dropped"
            );
            return Ok(None);
        }
    };
    match dispatch_inbound_document(state, Via::Tsp, Some(sender_vid), doc).await {
        Some(reply) => Ok(Some(tsp_binding::frame(
            serde_json::to_vec(&reply).map_err(|e| DIDCommServiceError::Internal(e.to_string()))?,
            carriage,
        ))),
        None => Ok(None),
    }
}

#[async_trait]
impl TspHandler for WitnessTspHandler {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        payload: Vec<u8>,
        sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError> {
        match run_tsp_trust_task(&self.state, &sender_vid, &payload).await? {
            Some(frame) => Ok(Some(TspResponse::new(frame))),
            None => Ok(None),
        }
    }

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

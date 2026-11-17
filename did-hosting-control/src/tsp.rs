//! TSP (Trust Spanning Protocol) transport binding for the control plane.
//!
//! The messaging-service framework carries TSP on the *same* shared
//! mediator websocket as DIDComm (see `ListenerConfig::protocols`). It
//! unpacks each inbound TSP frame, authenticates the sender VID
//! cryptographically, and hands us the cleartext payload via
//! [`affinidi_messaging_didcomm_service::TspHandler`].
//!
//! We treat the payload as a Trust Task document (`TrustTask<Value>`) and
//! route it through the *same* transport-agnostic
//! [`dispatch_inbound`](did_hosting_common::server::trust_tasks::dispatch_inbound)
//! core the HTTPS (`POST /api/trust-tasks`) and DIDComm-envelope
//! transports use. Because dispatch is transport-agnostic, every op
//! registered in the framework dispatcher is reachable over TSP with zero
//! extra wiring: the ACL + discovery ops today, and — once the legacy
//! `MSG_*` DID-management ops are migrated onto the framework — those too.
//!
//! The framework handles the response for us: return `Some(TspResponse)`
//! and it seals the bytes to the authenticated sender and routes them back
//! over the same socket, so this module never touches outbound TSP
//! plumbing.

use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, HandlerContext, TspHandler, TspResponse,
};
use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, warn};

use did_hosting_common::server::trust_tasks::TspTransportHandler;

use did_hosting_common::server::tsp_binding;

use crate::messaging::{body_parse_error, dispatch_trust_task_doc};
use crate::server::AppState;

/// messaging-service [`TspHandler`] that dispatches inbound TSP trust-task
/// documents through the shared Trust-Tasks core.
pub struct WebvhTspHandler {
    state: AppState,
}

impl WebvhTspHandler {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TspHandler for WebvhTspHandler {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        payload: Vec<u8>,
        sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError> {
        info!(sender = %sender_vid, "inbound TSP: trust-task document");
        match run_tsp_trust_task(&self.state, &sender_vid, &payload).await? {
            Some(bytes) => Ok(Some(TspResponse::new(bytes))),
            None => Ok(None),
        }
    }

    /// Answer an inbound TSP relationship control message. The accept policy —
    /// accept an invite from any framework-authenticated sender, authorize at
    /// the task layer — lives in `did_hosting_common` so the control plane and
    /// the edge server answer identically. See its module docs.
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

/// Compute the response bytes for an inbound TSP trust-task payload.
///
/// Extracted from [`WebvhTspHandler::handle`] so the parse + dispatch +
/// serialise logic is testable without a live TSP socket — mirrors
/// `run_trust_tasks_envelope` in [`crate::messaging`]. Returns `Ok(None)` for the SPEC §8.1 routing
/// exception (identity-mismatch with no transport sender), which the
/// TSP socket's authenticated-sender guarantee makes unreachable.
pub(crate) async fn run_tsp_trust_task(
    state: &AppState,
    sender: &str,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, DIDCommServiceError> {
    // Read whichever dialect the frame is in before parsing it. A conformant
    // peer sends the `binding/tsp/0.1` envelope; a not-yet-upgraded sibling
    // sends the bare document. See `tsp_binding` for why both are accepted.
    let (document, carriage) = tsp_binding::open(payload);

    // Per-type document size, decided from the bytes alone before they are
    // parsed into `TrustTask<Value>` — the same gate the HTTPS and DIDComm
    // transports apply (`size`), so a `did/register` log too large for the
    // default here is refused identically on every transport rather than
    // only over HTTPS.
    //
    // A document large enough to need its claimed (not yet verified)
    // issuer's ACL entry is charged against that sender's large-document
    // budget first (`vid:{sender}` — the TSP-authenticated sender VID, not
    // yet the document's proven issuer).
    let large_doc_charge =
        match did_hosting_common::server::trust_tasks::size::check_for_known_issuer(
            &document,
            &crate::control_tasks::SERVED_TRUST_TASK_URIS,
            &state.acl_ks,
            &state.large_document_budget,
            &format!("vid:{sender}"),
        )
        .await
        {
            Ok(charge) => charge,
            Err(err) => {
                let body = serde_json::to_vec(&err).expect("trust-task-error serialises");
                return Ok(Some(tsp_binding::frame(body, carriage)));
            }
        };

    let doc: trust_tasks_rs::TrustTask<Value> = match serde_json::from_slice(&document) {
        Ok(d) => d,
        Err(e) => {
            warn!(sender, error = %e, "TSP: payload did not parse as TrustTask<Value>");
            // Same `malformed_request` shape the DIDComm/HTTPS transports
            // emit, so a producer sees a consistent error across transports.
            //
            // Framed for the carriage it answers. Returning this bare to a
            // conformant peer is what made the original failure undiagnosable:
            // the VTA refused the very error that would have explained itself,
            // and waited out its timeout instead.
            let err_doc = body_parse_error(&e.to_string());
            let body = serde_json::to_vec(&err_doc).expect("trust-task-error serialises");
            return Ok(Some(tsp_binding::frame(body, carriage)));
        }
    };

    // Replay protection runs inside `dispatch_trust_task_doc`, keyed on the
    // proven issuer and the document id, after the proof has been verified.

    let my_vid = state
        .config
        .server_did
        .as_deref()
        .ok_or_else(|| DIDCommServiceError::Internal("server_did not configured".into()))?;

    // Dispatch through the unified trust-task router shared with the DIDComm
    // and HTTPS transports (`messaging::dispatch_trust_task_doc`). It routes
    // DID-management ops to their `control_tasks` rows and ACL + discovery
    // ops to the typed framework pipeline, so every op is reachable over TSP
    // as a Trust Task document.
    let transport = TspTransportHandler::new(my_vid.to_string(), sender.to_string());
    // No status codes on this transport, so the reply is the document either
    // way — `into_document` is where that flattening belongs, beside the router
    // rather than in each binding.
    let verifier = crate::messaging::require_verifier(state)?;
    match dispatch_trust_task_doc(
        state,
        sender,
        None,
        None,
        &transport,
        doc,
        verifier,
        large_doc_charge,
    )
    .await?
    .into_document()
    {
        Some(value) => Ok(Some(tsp_binding::frame(
            serde_json::to_vec(&value).expect("response serialises"),
            carriage,
        ))),
        None => Ok(None),
    }
}

#[cfg(test)]
#[path = "tsp_tests.rs"]
mod tests;

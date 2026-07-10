//! Outbound trust-task delivery — the send-side counterpart to the inbound
//! dispatchers.
//!
//! Everything else in `trust_tasks` consumes documents; nothing produced them.
//! Callers therefore hand-built legacy `MSG_*` DIDComm messages and picked a
//! transport by hand — or, more often, didn't pick at all and hard-coded
//! DIDComm.
//!
//! This module is the one place that answers "how do I reach this peer with a
//! trust task", and it answers it from the peer's **DID document**:
//!
//! | peer advertises | frame |
//! |---|---|
//! | `TSPTransport` | the document's JSON, sealed as a TSP payload |
//! | otherwise | the document inside a [`trust_tasks_didcomm::ENVELOPE_TYPE`] DIDComm message |
//!
//! Both shapes already have inbound readers: TSP frames are parsed as
//! `TrustTask<Value>` by each service's `TspHandler`, and the DIDComm envelope
//! is routed to the same dispatcher. So a trust task is a *transport-agnostic*
//! unit: the same Type URI, the same payload, the same handler — only the
//! binding differs, chosen by what the recipient says it speaks.
//!
//! ## Why the DIDComm arm is the default rather than an error
//!
//! `resolve_transport` returns `None` when a DID resolves but advertises
//! neither transport service, and also when it doesn't resolve at all. Both
//! collapse into the DIDComm arm here. That is deliberate and matches
//! [`crate::server::didcomm_profile::resolve_transport`]'s existing consumers:
//! a mediator-connected peer is reachable over DIDComm whether or not its
//! document says so, and refusing to send would strand every DID minted before
//! transports were advertised at all.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::DIDCommService;
use serde_json::Value;
use tracing::{debug, warn};

use crate::server::didcomm_profile::{PeerTransport, resolve_transport};

/// Boxed transport error — mirrors the outbox's error type so `deliver()` can
/// eventually be rewritten on top of this without changing its signature.
pub type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Send a trust-task document to `to`, choosing the binding from `to`'s DID
/// document.
///
/// Returns the transport that actually carried the document. That is **not**
/// always the one the document advertises: a TSP send that fails falls back to
/// DIDComm and reports `Didcomm`, so callers recording observed transport see
/// what really happened rather than what was intended.
///
/// `listener_id` is the messaging-service listener name (`"control"` /
/// `"server"`), not a DID.
pub async fn send_trust_task(
    didcomm: &DIDCommService,
    listener_id: &str,
    from: &str,
    to: &str,
    doc: &trust_tasks_rs::TrustTask<Value>,
    did_resolver: Option<&DIDCacheClient>,
) -> Result<PeerTransport, SendError> {
    match resolve_transport(to, did_resolver).await {
        Some((PeerTransport::Tsp, _)) => {
            let payload = serde_json::to_vec(doc)?;
            match didcomm.send_tsp(listener_id, to, &payload).await {
                Ok(()) => {
                    debug!(to, type_uri = %doc.type_uri, "trust task sent over TSP");
                    Ok(PeerTransport::Tsp)
                }
                // Same graceful degradation the outbox applies: a peer that
                // advertises TSP also advertises DIDComm (the webvh templates
                // emit both), so a TSP failure is recoverable rather than
                // terminal. Partially-upgraded fleets keep working.
                Err(tsp_err) => {
                    warn!(
                        to,
                        type_uri = %doc.type_uri,
                        error = %tsp_err,
                        "trust task: TSP send failed — falling back to DIDComm"
                    );
                    send_over_didcomm(didcomm, listener_id, from, to, doc).await?;
                    Ok(PeerTransport::Didcomm)
                }
            }
        }
        _ => {
            send_over_didcomm(didcomm, listener_id, from, to, doc).await?;
            Ok(PeerTransport::Didcomm)
        }
    }
}

/// [`send_trust_task`] with the messaging service's reconnect-aware retry.
///
/// Used where the mediator socket may not be up yet — a server registering at
/// boot races its own DIDComm connection. Note the retry wraps the *whole*
/// transport decision, so a peer that becomes TSP-reachable between attempts is
/// picked up on the next one.
pub async fn send_trust_task_with_retry(
    didcomm: &DIDCommService,
    listener_id: &str,
    from: &str,
    to: &str,
    doc: &trust_tasks_rs::TrustTask<Value>,
    did_resolver: Option<&DIDCacheClient>,
    retry: Retry,
) -> Result<PeerTransport, SendError> {
    let attempts = retry.attempts.max(1);
    let mut last: Option<SendError> = None;
    for attempt in 1..=attempts {
        match send_trust_task(didcomm, listener_id, from, to, doc, did_resolver).await {
            Ok(t) => return Ok(t),
            Err(e) => {
                debug!(
                    to,
                    attempt,
                    attempts,
                    error = %e,
                    "trust task send failed — retrying"
                );
                last = Some(e);
                if attempt < attempts {
                    tokio::time::sleep(retry.delay).await;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| "send_trust_task_with_retry: no attempts made".into()))
}

/// Retry schedule for [`send_trust_task_with_retry`]. Fixed delay, not backoff:
/// the thing being waited on is a mediator socket coming up, which either
/// happens within a few seconds or not at all.
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    pub attempts: u32,
    pub delay: std::time::Duration,
}

/// Wrap `doc` in the framework's DIDComm envelope and send it.
///
/// The envelope type is what `handle_trust_tasks_envelope` routes on, so this
/// is the exact shape the inbound side already understands.
async fn send_over_didcomm(
    didcomm: &DIDCommService,
    listener_id: &str,
    from: &str,
    to: &str,
    doc: &trust_tasks_rs::TrustTask<Value>,
) -> Result<(), SendError> {
    let body = serde_json::to_value(doc)?;
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        trust_tasks_didcomm::ENVELOPE_TYPE.to_string(),
        body,
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(crate::server::auth::session::now_epoch())
    .finalize();

    didcomm.send_message(listener_id, msg, to).await?;
    debug!(to, type_uri = %doc.type_uri, "trust task sent over DIDComm envelope");
    Ok(())
}

/// Build a request document addressed from `from` to `to`.
///
/// `type_uri` is the canonical Type URI string — for control↔server
/// infrastructure ops these are the very same `MSG_*` constants the legacy
/// DIDComm routes use (`.../spec/did-management/server/health/0.1`), so the op
/// has one identity regardless of framing. See `didcomm_types`.
pub fn build_request(
    type_uri: &str,
    from: &str,
    to: &str,
    payload: Value,
) -> Result<trust_tasks_rs::TrustTask<Value>, SendError> {
    let uri: trust_tasks_rs::TypeUri = type_uri.parse()?;
    let mut doc = trust_tasks_rs::TrustTask::new(uuid::Uuid::new_v4().to_string(), uri, payload);
    doc.issuer = Some(from.to_string());
    doc.recipient = Some(to.to_string());
    doc.issued_at = Some(chrono::Utc::now());
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::didcomm_types::{
        MSG_HEALTH_PING, MSG_HEALTH_PONG, MSG_SERVER_REGISTER, MSG_SERVER_REGISTER_ACK,
    };

    /// The whole transport-agnostic scheme rests on this: the legacy DIDComm
    /// `MSG_*` type strings are already canonical Trust-Task Type URIs, and the
    /// `_ACK`/`_PONG` constants are exactly the `#response` variant of their
    /// request. So one Type URI identifies the op on every transport and in
    /// every framing, and `respond_with` derives the reply's URI rather than us
    /// hard-coding it.
    ///
    /// If this ever fails, a reply would go out under a URI no handler routes.
    #[test]
    fn msg_constants_are_request_response_type_uri_pairs() {
        for (req, resp) in [
            (MSG_HEALTH_PING, MSG_HEALTH_PONG),
            (MSG_SERVER_REGISTER, MSG_SERVER_REGISTER_ACK),
        ] {
            let doc = build_request(req, "did:example:a", "did:example:b", Value::Null)
                .unwrap_or_else(|e| panic!("{req} must parse as a TypeUri: {e}"));
            let reply = doc.respond_with("reply-id", Value::Null);
            assert_eq!(
                reply.type_uri.to_string(),
                resp,
                "respond_with({req}) must produce {resp}"
            );
        }
    }

    /// `respond_with` swaps the parties and threads the reply to the request —
    /// the correlation the health loop and register ack depend on.
    #[test]
    fn response_swaps_parties_and_threads_to_request() {
        let doc = build_request(
            MSG_HEALTH_PING,
            "did:example:control",
            "did:example:server",
            serde_json::json!({}),
        )
        .expect("build");
        let reply = doc.respond_with("reply-id", serde_json::json!({ "status": "ok" }));

        assert_eq!(reply.issuer.as_deref(), Some("did:example:server"));
        assert_eq!(reply.recipient.as_deref(), Some("did:example:control"));
        assert_eq!(reply.thread_id.as_deref(), Some(doc.id.as_str()));
    }

    /// The non-canonical `TASK_SERVER_HEALTH_*` route-decorator URIs must NOT
    /// be used as document Type URIs — they lack the `/spec/` segment and model
    /// the response as a separate URI rather than a `#response` fragment.
    /// Pinned so nobody "unifies" them into the document layer by mistake.
    #[test]
    fn route_decorator_uris_are_not_valid_document_type_uris() {
        let decorator = "https://trusttasks.org/did-hosting/server/health-ping/1.0";
        assert!(
            build_request(decorator, "did:example:a", "did:example:b", Value::Null).is_err(),
            "route-decorator URI must not parse as a document TypeUri"
        );
    }
}

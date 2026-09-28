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
//! | `DIDCommMessaging` | the document inside a [`trust_tasks_didcomm::ENVELOPE_TYPE`] DIDComm message |
//! | `TrustTaskHTTPS` | the document's JSON, `POST`ed to `{endpoint}/trust-tasks` |
//!
//! All three shapes already have inbound readers: TSP frames are parsed as
//! `TrustTask<Value>` by each service's `TspHandler`, the DIDComm envelope is
//! routed to the same dispatcher, and the HTTPS route
//! (`did-hosting-server`'s `routes::trust_tasks::receive`) hands the posted
//! body to that dispatcher too. So a trust task is a *transport-agnostic*
//! unit: the same Type URI, the same payload, the same handler — only the
//! binding differs, chosen by what the recipient says it speaks.
//!
//! ## Transport precedence: document, then config, then fail
//!
//! The binding is chosen by
//! [`crate::server::didcomm_profile::resolve_send_binding`], which treats the
//! peer's **DID document as authoritative** — `TSPTransport` preferred, then
//! `DIDCommMessaging`, then `TrustTaskHTTPS` — and falls back to this node's
//! configured mediator only when the document advertises none of the three —
//! the compatibility bridge for DIDs minted before transports were published,
//! which worked precisely because the two ends shared a mediator. (The config
//! fallback is TSP/DIDComm only; there is no "shared HTTPS endpoint"
//! equivalent, so a document-silent peer is never guessed to speak HTTPS.)
//!
//! When neither the document nor config yields a binding, the send **fails**
//! rather than blindly attempting DIDComm. The former blind-DIDComm default
//! only ever routed because a mediator existed; a node with no mediator could
//! not have reached the peer that way regardless, so an explicit error is the
//! honest outcome and lets the caller (outbox retry, health loop) record an
//! unroutable peer instead of swallowing a send that cannot succeed.
//!
//! ## The HTTPS reply
//!
//! Over TSP and DIDComm the reply is a separate message that arrives later on
//! the mediator connection, verified by the ordinary inbound path
//! ([`super::bound::verify_sender_bound`]) whenever it shows up. HTTPS has no
//! separate inbound leg — the reply *is* the HTTP response — so
//! [`send_over_https`] applies the same rule synchronously: the reply must
//! carry a `proof` binding it to the peer we addressed, must be addressed back
//! to us, and must thread to the request. A 2xx response that fails any of
//! these is treated as a send failure, not a success — an unsigned or
//! misdirected 2xx is not evidence the peer accepted the task.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::DIDCommService;
use serde_json::Value;
use tracing::{debug, warn};

use crate::server::didcomm_profile::{PeerTransport, TransportFallback, resolve_send_binding};
use crate::server::trust_tasks::{build_verifier, verify_sender_bound};

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
    fallback: &TransportFallback,
    did_resolver: Option<&DIDCacheClient>,
) -> Result<PeerTransport, SendError> {
    match resolve_send_binding(to, fallback, did_resolver).await {
        Some((PeerTransport::Tsp, _)) => {
            // Wrapped in the `binding/tsp/0.1` envelope. This sealed the bare
            // document, which no conformant consumer can read — the same half
            // of the defect `crate::server::tsp_binding` documents, on the
            // producing side.
            //
            // Receivers must be upgraded before senders: a node still on the
            // pre-binding build cannot open this. Both inbound handlers in this
            // release read either dialect, so a fleet upgraded common-first (or
            // wholesale) is safe; a control plane upgraded ahead of its edge
            // servers is not. The TSP failure path below does not rescue it —
            // the send succeeds and the peer merely answers an error — so the
            // ordering is a deployment obligation, not something this fallback
            // covers.
            let payload = crate::server::tsp_binding::frame(
                serde_json::to_vec(doc)?,
                crate::server::tsp_binding::Carriage::Envelope,
            );
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
        Some((PeerTransport::Didcomm, _)) => {
            send_over_didcomm(didcomm, listener_id, from, to, doc).await?;
            Ok(PeerTransport::Didcomm)
        }
        Some((PeerTransport::Https, endpoint)) => {
            send_over_https(from, to, &endpoint, doc, did_resolver).await?;
            debug!(to, endpoint, type_uri = %doc.type_uri, "trust task sent over HTTPS");
            Ok(PeerTransport::Https)
        }
        // No binding: the peer advertises no messaging transport AND this node
        // has no configured mediator to fall back on. This replaces the former
        // blind-DIDComm default — a send here could never route, so we surface
        // it as an error the caller (outbox retry, health loop) can record
        // rather than swallowing it into a DIDComm attempt that hangs or drops.
        None => Err(format!(
            "no route to {to}: peer advertises no messaging transport and no mediator is configured"
        )
        .into()),
    }
}

/// [`send_trust_task`] with the messaging service's reconnect-aware retry.
///
/// Used where the mediator socket may not be up yet — a server registering at
/// boot races its own DIDComm connection. Note the retry wraps the *whole*
/// transport decision, so a peer that becomes TSP-reachable between attempts is
/// picked up on the next one.
// One over clippy's 7-arg threshold: a thin retry wrapper that mirrors
// `send_trust_task`'s parameters plus a `Retry`. Bundling them into a struct
// would only move the same values around at every call site.
#[allow(clippy::too_many_arguments)]
pub async fn send_trust_task_with_retry(
    didcomm: &DIDCommService,
    listener_id: &str,
    from: &str,
    to: &str,
    doc: &trust_tasks_rs::TrustTask<Value>,
    fallback: &TransportFallback,
    did_resolver: Option<&DIDCacheClient>,
    retry: Retry,
) -> Result<PeerTransport, SendError> {
    let attempts = retry.attempts.max(1);
    let mut last: Option<SendError> = None;
    for attempt in 1..=attempts {
        match send_trust_task(didcomm, listener_id, from, to, doc, fallback, did_resolver).await {
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

/// Refuse an HTTPS trust-task reply body larger than this. A reply is one
/// small signed JSON document; a peer sending more is misbehaving, not slow.
const HTTPS_MAX_REPLY_BYTES: u64 = 1024 * 1024;

/// `POST doc` to the peer's advertised `TrustTaskHTTPS` endpoint and verify
/// the reply.
///
/// `endpoint` is the Trust-Task **base** URL the peer's DID document
/// advertises (HTTPS binding 0.2 §6); the request goes to
/// `{endpoint}/trust-tasks`, matching [`trust_tasks_https::HttpsClient`] and
/// the inbound route this crate serves at `POST {base}/trust-tasks`.
///
/// Uses [`crate::http::outbound_client`] for the shared connect/request
/// timeouts and redirect refusal (a redirect to another origin would carry
/// the signed document to a host the peer's document never named). The reply
/// body is read with a hard cap ([`HTTPS_MAX_REPLY_BYTES`]) so a misbehaving
/// peer cannot make the caller buffer an unbounded response.
///
/// A 2xx HTTP status is not itself success: the reply must additionally be
/// signed by `to` (the peer this send addressed), addressed back to `from`,
/// and threaded to `doc` — see the module docs' "The HTTPS reply" section.
/// Any of these failing is reported as a send failure, same as a transport
/// error would be.
async fn send_over_https(
    from: &str,
    to: &str,
    endpoint: &str,
    doc: &trust_tasks_rs::TrustTask<Value>,
    did_resolver: Option<&DIDCacheClient>,
) -> Result<(), SendError> {
    let url = format!("{}/trust-tasks", endpoint.trim_end_matches('/'));
    post_trust_task_https(from, to, &url, doc, did_resolver)
        .await
        .map(|_| ())
}

/// `POST doc` to `url` — a peer's `POST /trust-tasks` route — and return the
/// reply once it has been verified.
///
/// The reply must be signed by `to` (the peer this request addressed),
/// addressed back to `from`, and threaded to `doc`; anything else is an error,
/// whatever the HTTP status. The returned document may be the task's
/// `#response` or a (signed) `trust-task-error`: telling them apart is the
/// caller's business. A peer that refuses to answer a document it could not
/// verify answers with a non-2xx status, reported as an error here.
///
/// Uses [`crate::http::outbound_client`] for the shared connect/request
/// timeouts and redirect refusal (a redirect to another origin would carry the
/// signed document to a host the peer never named). The reply body is read
/// with a hard cap ([`HTTPS_MAX_REPLY_BYTES`]).
pub async fn post_trust_task_https(
    from: &str,
    to: &str,
    url: &str,
    doc: &trust_tasks_rs::TrustTask<Value>,
    did_resolver: Option<&DIDCacheClient>,
) -> Result<trust_tasks_rs::TrustTask<Value>, SendError> {
    let resp = crate::http::outbound_client()
        .post(url)
        .json(doc)
        .send()
        .await?;
    let status = resp.status();
    let body = read_capped_body(resp, HTTPS_MAX_REPLY_BYTES).await?;

    if !status.is_success() {
        return Err(format!(
            "trust task HTTPS send to {to} ({url}) failed: HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }

    let reply: trust_tasks_rs::TrustTask<Value> = serde_json::from_slice(&body).map_err(|e| {
        format!("trust task HTTPS reply from {to} ({url}) did not parse as a Trust Task: {e}")
    })?;

    // Threaded — the reply must correlate to this exact request, the same
    // check `trust_tasks_https::HttpsClient::send` applies on the generic
    // client path.
    let expected_thread = doc.thread_id.clone().unwrap_or_else(|| doc.id.clone());
    if reply.thread_id.as_deref() != Some(expected_thread.as_str()) {
        return Err(format!(
            "trust task HTTPS reply from {to} is not threaded to the request: expected \
             threadId {expected_thread}, got {:?}",
            reply.thread_id
        )
        .into());
    }

    // Signed by the peer we addressed, and addressed back to us — the same
    // sender-bound rule every inbound document on any transport is held to.
    let verifier = build_verifier(did_resolver).ok_or_else(|| {
        format!("trust task HTTPS reply from {to}: no DID resolver configured to verify it")
    })?;
    verify_sender_bound(&reply, Some(to), None, from, &verifier).await?;

    Ok(reply)
}

/// Read `resp`'s body, refusing more than `limit` bytes — from either a
/// declared `Content-Length` or the bytes actually received, whichever
/// catches it first.
async fn read_capped_body(mut resp: reqwest::Response, limit: u64) -> Result<Vec<u8>, SendError> {
    if let Some(len) = resp.content_length()
        && len > limit
    {
        return Err(
            format!("trust task HTTPS reply body too large: {len} bytes (limit {limit})").into(),
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() as u64 > limit {
            return Err(
                format!("trust task HTTPS reply body exceeded the {limit}-byte limit").into(),
            );
        }
    }
    Ok(body)
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

/// [`build_request`], signed by `signer`.
///
/// Every request one of these services sends to another is a privileged
/// document the receiver will refuse without a proof bound to the sender
/// (see [`super::bound`]), so this — not the bare [`build_request`] — is what
/// callers put on the wire. `signer` must be `from`'s current operational key.
pub async fn build_signed_request(
    type_uri: &str,
    from: &str,
    to: &str,
    payload: Value,
    signer: &affinidi_tdk::secrets_resolver::secrets::Secret,
) -> Result<trust_tasks_rs::TrustTask<Value>, SendError> {
    let doc = build_request(type_uri, from, to, payload)?;
    Ok(super::bound::sign_document(&doc, signer).await?)
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

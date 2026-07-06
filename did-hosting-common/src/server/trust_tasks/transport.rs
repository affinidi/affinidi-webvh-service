//! TSP transport handler for the Trust-Tasks dispatch core.
//!
//! The Trust Spanning Protocol (TSP) analogue of `trust-tasks-didcomm`'s
//! `DidcommHandler`. A TSP frame is unpacked off the shared mediator
//! websocket by `affinidi-messaging-didcomm-service`, which authenticates
//! the sender VID cryptographically before handing the cleartext payload
//! to our `TspHandler`. By the time we build one of these, `peer` is the
//! *proven* sender VID and `local` is our own service DID — so
//! [`TransportHandler::derive_parties`] reports them directly and the
//! framework applies the SPEC §4.8.1 identity precedence exactly as it
//! does for the DIDComm and HTTPS bindings.
//!
//! This is deliberately a tiny value object (like `DidcommHandler`): all
//! the real transport I/O — TSP unpack, sender authentication — happens
//! in the messaging-service layer *before* this is constructed, so the
//! handler just reports the already-authenticated identities.

use trust_tasks_rs::{TransportContext, TransportHandler};

/// Stable binding URI for the TSP transport, mirroring
/// `trust-tasks-didcomm`'s `https://trusttasks.org/binding/didcomm/0.1`.
pub const TSP_BINDING_URI: &str = "https://trusttasks.org/binding/tsp/0.1";

/// A [`TransportHandler`] for one TSP exchange.
///
/// `local` is the service VID we control; `peer` is the TSP-unpack-proven
/// sender VID. Both are `Option<String>` for symmetry with `DidcommHandler`
/// — a `None` peer would make the framework fall back to the document's
/// in-band `proof`, but the TSP socket always authenticates the sender, so
/// in practice `peer` is always `Some` on the inbound path.
#[derive(Debug, Clone)]
pub struct TspTransportHandler {
    local: Option<String>,
    peer: Option<String>,
}

impl TspTransportHandler {
    /// Construct a handler. Either side may be `None`.
    pub fn new(local: impl Into<Option<String>>, peer: impl Into<Option<String>>) -> Self {
        Self {
            local: local.into(),
            peer: peer.into(),
        }
    }

    /// The local party's VID, if set.
    pub fn local(&self) -> Option<&str> {
        self.local.as_deref()
    }

    /// The TSP-authenticated peer VID, if set.
    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }
}

impl TransportHandler for TspTransportHandler {
    fn binding_uri(&self) -> &str {
        TSP_BINDING_URI
    }

    fn derive_parties(&self) -> TransportContext {
        TransportContext {
            issuer: self.peer.clone(),
            recipient: self.local.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_parties_maps_peer_to_issuer_and_local_to_recipient() {
        let h = TspTransportHandler::new(
            "did:web:maintainer.example".to_string(),
            "did:web:admin.example".to_string(),
        );
        let ctx = h.derive_parties();
        assert_eq!(ctx.issuer.as_deref(), Some("did:web:admin.example"));
        assert_eq!(ctx.recipient.as_deref(), Some("did:web:maintainer.example"));
        assert_eq!(h.binding_uri(), TSP_BINDING_URI);
    }

    #[test]
    fn none_peer_yields_no_issuer() {
        let h = TspTransportHandler::new("did:web:maintainer.example".to_string(), None);
        let ctx = h.derive_parties();
        assert!(ctx.issuer.is_none());
        assert_eq!(ctx.recipient.as_deref(), Some("did:web:maintainer.example"));
    }
}

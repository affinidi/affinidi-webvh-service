//! Shared TDK profile construction for DIDComm services.
//!
//! Resolves the server's DID document to discover the correct verification-method
//! key IDs, then builds a `TDKProfile` with the correct secrets. This is used by
//! the `affinidi-messaging-didcomm-service` framework to establish mediator
//! connections.

use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk_common::profiles::TDKProfile;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::error::AppError;
use super::identity::ServiceIdentity;

/// Resolve the mediator DID from a peer's DID document.
///
/// Looks for a `DIDCommMessaging` service endpoint in the peer's DID document
/// and extracts the mediator DID URI from it. This follows the DIDComm v2
/// convention where the `serviceEndpoint.uri` of a `DIDCommMessaging` service
/// points to the mediator that relays messages for the peer.
///
/// Returns `None` if the DID cannot be resolved or has no `DIDCommMessaging` service.
pub async fn resolve_mediator_did(
    peer_did: &str,
    did_resolver: Option<&DIDCacheClient>,
) -> Option<String> {
    let owned;
    let resolver = match did_resolver {
        Some(r) => r,
        None => match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
            Ok(r) => {
                owned = r;
                &owned
            }
            Err(e) => {
                warn!("failed to create DID resolver for mediator discovery: {e}");
                return None;
            }
        },
    };

    let doc = match resolver.resolve(peer_did).await {
        Ok(response) => response.doc,
        Err(e) => {
            warn!("failed to resolve {peer_did} for mediator discovery: {e}");
            return None;
        }
    };

    // Find the DIDCommMessaging service endpoint URI. `get_uri()` leaves
    // JSON quoting on Map-shaped endpoints, so trim it.
    let mediator = doc
        .service
        .iter()
        .find(|s| s.type_.iter().any(|t| t == "DIDCommMessaging"))
        .and_then(|s| s.service_endpoint.get_uri())
        .map(|uri| uri.trim_matches('"').to_string())?;

    info!(peer = peer_did, mediator = %mediator, "discovered mediator from DID document");
    Some(mediator)
}

/// A transport a peer's DID document advertises for reaching it.
///
/// The `did-hosting` workspace treats **TSP as preferred over DIDComm**
/// when a peer advertises both — matching the canonical service order
/// the VTA webvh templates render (`#tsp` before `#vta-didcomm`). The
/// outbound send path ([`crate::server`] / the trust-task sender) uses
/// [`resolve_transport`] to pick the binding; both services point at the
/// same mediator VID, so only the *binding* differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTransport {
    /// Trust Spanning Protocol (`TSPTransport` service).
    Tsp,
    /// DIDComm v2 (`DIDCommMessaging` service).
    Didcomm,
}

/// A transport a message was **observed** travelling on, as opposed to
/// [`PeerTransport`], which records what a DID document *advertises*.
///
/// The distinction is the whole point of persisting this. A peer that
/// advertises `TSPTransport` may still be talked to over DIDComm — because the
/// TSP send failed and fell back, or because it registered before it advertised
/// anything. Reporting the advertised transport as though it were the one in
/// use would quietly lie to the operator.
///
/// `Https` exists because the trust-task core is transport-agnostic and the
/// same documents can arrive over `POST /api/trust-tasks`. No registered
/// service instance uses it today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObservedTransport {
    Tsp,
    Didcomm,
    Https,
}

impl ObservedTransport {
    /// Map a [`trust_tasks_rs::TransportHandler::binding_uri`] to the transport
    /// it identifies.
    ///
    /// Matched against the binding crates' own exported constants rather than
    /// by substring, so a new binding shows up as `None` — an honest "we don't
    /// know" — instead of being silently mis-attributed.
    pub fn from_binding_uri(binding_uri: &str) -> Option<Self> {
        match binding_uri {
            crate::server::trust_tasks::transport::TSP_BINDING_URI => Some(Self::Tsp),
            trust_tasks_didcomm::BINDING_URI => Some(Self::Didcomm),
            trust_tasks_https::BINDING_URI => Some(Self::Https),
            _ => None,
        }
    }
}

impl From<PeerTransport> for ObservedTransport {
    fn from(t: PeerTransport) -> Self {
        match t {
            PeerTransport::Tsp => Self::Tsp,
            PeerTransport::Didcomm => Self::Didcomm,
        }
    }
}

/// Resolve every service `type` a peer's DID document advertises.
///
/// The network-facing counterpart to
/// [`crate::did::service_types_from_doc`], which reads a document we
/// already hold. Used to populate the registry's per-instance badge cache:
/// the registry stores only a DID string, so the document has to be fetched.
///
/// Skips the `#whois` / `#files` services a conforming did:webvh resolver
/// synthesises into every document — see
/// [`crate::did::is_implicit_webvh_service`]. They appear on 100% of resolved
/// webvh DIDs, are absent from the stored `did.jsonl`, and carry no operator
/// intent; reporting them would put a permanent, meaningless `Other` badge on
/// every server while the DID list (which reads the log) showed none.
///
/// Returns `None` when the DID cannot be resolved — distinct from
/// `Some(vec![])`, which means it resolved and advertises no services.
/// Callers cache the distinction; see `ServiceInstance::advertised_services`.
pub async fn resolve_service_types(
    peer_did: &str,
    did_resolver: Option<&DIDCacheClient>,
) -> Option<Vec<String>> {
    let owned;
    let resolver = match did_resolver {
        Some(r) => r,
        None => match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
            Ok(r) => {
                owned = r;
                &owned
            }
            Err(e) => {
                warn!("failed to create DID resolver for service discovery: {e}");
                return None;
            }
        },
    };

    let doc = match resolver.resolve(peer_did).await {
        Ok(response) => response.doc,
        Err(e) => {
            warn!("failed to resolve {peer_did} for service discovery: {e}");
            return None;
        }
    };

    // Flatten the resolved document's typed `service` array. Mirrors
    // `did::service_types_from_doc`'s contract — document order, deduped,
    // implicit services skipped — but over the resolver's `Service` type
    // rather than raw JSON.
    let mut out: Vec<String> = Vec::new();
    for svc in &doc.service {
        let implicit = svc
            .id
            .as_ref()
            .is_some_and(|id| crate::did::is_implicit_webvh_service(id.as_str()));
        if implicit {
            continue;
        }
        for t in &svc.type_ {
            if !t.is_empty() && !out.iter().any(|seen| seen == t) {
                out.push(t.clone());
            }
        }
    }
    Some(out)
}

/// Resolve a peer's preferred transport and its mediator endpoint from
/// the peer's DID document.
///
/// Scans for a `TSPTransport` service **first**, falling back to
/// `DIDCommMessaging`. Returns `(transport, mediator_endpoint)`, or
/// `None` if the DID cannot be resolved or advertises neither service.
///
/// This is the single canonical "which transport for this peer" reader —
/// when a DID has a `TSPTransport` service we prefer it, which is the
/// concrete realisation of "when a DID has a TSPTransport, use that
/// instead of DIDComm".
pub async fn resolve_transport(
    peer_did: &str,
    did_resolver: Option<&DIDCacheClient>,
) -> Option<(PeerTransport, String)> {
    let owned;
    let resolver = match did_resolver {
        Some(r) => r,
        None => match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
            Ok(r) => {
                owned = r;
                &owned
            }
            Err(e) => {
                warn!("failed to create DID resolver for transport discovery: {e}");
                return None;
            }
        },
    };

    let doc = match resolver.resolve(peer_did).await {
        Ok(response) => response.doc,
        Err(e) => {
            warn!("failed to resolve {peer_did} for transport discovery: {e}");
            return None;
        }
    };

    // Scan for a service of `type_name` and return its endpoint URI as a
    // plain string. Handles both endpoint shapes the webvh templates
    // emit: DIDComm's array-of-objects (`[{ "uri": ... }]`) and TSP's
    // bare-string (`"did:webvh:mediator..."`) `serviceEndpoint`.
    let find_uri = |type_name: &str| {
        doc.service
            .iter()
            .find(|s| s.type_.iter().any(|t| t == type_name))
            .and_then(|s| s.service_endpoint.get_uri())
            .map(|uri| uri.trim_matches('"').to_string())
    };

    if let Some(tsp) = find_uri("TSPTransport") {
        info!(peer = peer_did, mediator = %tsp, "peer advertises TSPTransport — preferring TSP");
        return Some((PeerTransport::Tsp, tsp));
    }
    if let Some(didcomm) = find_uri("DIDCommMessaging") {
        info!(peer = peer_did, mediator = %didcomm, "peer advertises DIDCommMessaging — using DIDComm");
        return Some((PeerTransport::Didcomm, didcomm));
    }
    None
}

/// The node's locally-configured messaging fallback, applied when a peer's
/// DID document advertises no `TSPTransport`/`DIDCommMessaging` service.
///
/// This is the compatibility bridge for the "DID document is authoritative"
/// model: before transports were published in documents, control↔server
/// links worked because both ends shared a mediator and messages were sent
/// over DIDComm regardless of what the document said. That behaviour is
/// preserved here — a node with a mediator configured keeps reaching
/// doc-silent peers over its own mediator — while a node with no mediator
/// (which could never have spoken DIDComm) yields no binding and the caller
/// treats the peer as unroutable, rather than silently attempting a DIDComm
/// send that cannot route. (There is no REST tier: no trust-task REST sender
/// or server-side inbound route exists; HTTP-only nodes are served by the
/// pull/watcher model, not a trust-task push.)
///
/// `binding` is the node's *own* mediator VID plus the transport it prefers
/// (TSP when `features.tsp`, else DIDComm). It is `None` on HTTP-only nodes.
#[derive(Debug, Clone, Default)]
pub struct TransportFallback {
    /// The node's configured `(preferred transport, mediator VID)`, or `None`
    /// when the node has no mediator configured.
    pub binding: Option<(PeerTransport, String)>,
}

impl TransportFallback {
    /// Build from a node's configured mediator and transport preference.
    ///
    /// `prefer_tsp` should track `features.tsp`; when the node advertises both
    /// transports it prefers TSP, matching [`resolve_transport`]'s document
    /// ordering. Returns an empty fallback (no binding) when `mediator_did` is
    /// `None`, so HTTP-only nodes yield no binding at all.
    pub fn from_config(mediator_did: Option<&str>, prefer_tsp: bool) -> Self {
        let binding = mediator_did.map(|m| {
            let t = if prefer_tsp {
                PeerTransport::Tsp
            } else {
                PeerTransport::Didcomm
            };
            (t, m.to_string())
        });
        Self { binding }
    }
}

/// Decide how to reach `peer_did` with a trust task, applying the
/// **DID-document-authoritative** precedence:
///
/// 1. **DID document** — a `TSPTransport` (preferred) or `DIDCommMessaging`
///    service is the authoritative statement of how to reach the peer.
/// 2. **Config fallback** — if the document advertises neither, use the local
///    node's configured mediator ([`TransportFallback`]). Preserves existing
///    shared-mediator deployments whose documents predate published transports.
/// 3. **Fail** — `None` when the peer advertises no messaging service and the
///    node has no configured mediator. The caller treats this as an unroutable
///    peer rather than blindly attempting a send that cannot succeed.
///
/// The return shape matches [`resolve_transport`] — `(transport, mediator VID)`
/// — so it drops into the existing send paths unchanged; the only addition is
/// the config tier between the document and failure. The document is resolved
/// once; the config tier still applies when the document fails to resolve
/// entirely (the shared-mediator case).
pub async fn resolve_send_binding(
    peer_did: &str,
    fallback: &TransportFallback,
    did_resolver: Option<&DIDCacheClient>,
) -> Option<(PeerTransport, String)> {
    decide_binding(
        peer_did,
        resolve_transport(peer_did, did_resolver).await,
        fallback,
    )
}

/// The pure precedence ladder behind [`resolve_send_binding`], split out so
/// the ordering can be tested without a live DID resolver. `from_doc` is what
/// the peer's document advertised (via [`resolve_transport`]), or `None` when
/// it advertised no messaging service or failed to resolve.
fn decide_binding(
    peer_did: &str,
    from_doc: Option<(PeerTransport, String)>,
    fallback: &TransportFallback,
) -> Option<(PeerTransport, String)> {
    // 1. DID document — authoritative.
    if let Some((transport, mediator)) = from_doc {
        info!(peer = peer_did, ?transport, mediator = %mediator, "send-binding: using document-advertised transport");
        return Some((transport, mediator));
    }

    // 2. Config fallback — the node's own configured mediator.
    if let Some((transport, mediator)) = &fallback.binding {
        info!(
            peer = peer_did,
            ?transport,
            mediator = %mediator,
            "send-binding: document silent — using configured mediator fallback"
        );
        return Some((*transport, mediator.clone()));
    }

    // 3. Fail — unroutable.
    warn!(
        peer = peer_did,
        "send-binding: peer advertises no messaging service and no mediator is \
         configured — cannot route (peer is unreachable for trust-task push)"
    );
    None
}

/// Wait until a DID resolves, retrying with exponential backoff.
///
/// Used at DIDComm startup to block until the mediator DID document is
/// reachable. This avoids the situation where the listener spins up against
/// an unreachable mediator and the SDK reports the cryptic "No Mediator is
/// configured for this Profile" error after silently dropping the underlying
/// network failure.
///
/// Returns `Ok(())` on first successful resolution, or `Err` if the shutdown
/// token is cancelled while waiting.
///
/// Backoff: 2s, 4s, 8s, … capped at 60s.
pub async fn wait_for_did_resolution(
    did: &str,
    label: &str,
    did_resolver: &DIDCacheClient,
    shutdown: &CancellationToken,
) -> Result<(), AppError> {
    const INITIAL_BACKOFF_SECS: u64 = 2;
    const MAX_BACKOFF_SECS: u64 = 60;

    let mut backoff_secs = INITIAL_BACKOFF_SECS;
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        match did_resolver.resolve(did).await {
            Ok(_) => {
                if attempt == 1 {
                    info!(did, label, "DID resolved");
                } else {
                    info!(did, label, attempt, "DID resolved after retries");
                }
                return Ok(());
            }
            Err(e) => {
                warn!(
                    did,
                    label,
                    attempt,
                    error = %e,
                    "DID not yet resolvable — retrying in {backoff_secs}s"
                );
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {}
            _ = shutdown.cancelled() => {
                return Err(AppError::Internal(format!(
                    "shutdown signalled while waiting for {label} DID {did} to resolve"
                )));
            }
        }

        backoff_secs = (backoff_secs.saturating_mul(2)).min(MAX_BACKOFF_SECS);
    }
}

/// Build a `TDKProfile` from an already-loaded [`ServiceIdentity`].
///
/// Differs from [`build_tdk_profile`] in two ways that matter.
///
/// The kids are **not** re-resolved — they come from the identity's generation
/// records. That is what keeps the listener's profile and the secrets resolver
/// keyed on the same fragments; resolving them independently in two places is
/// exactly how they came to disagree.
///
/// The profile carries the key material of **every live generation**, not just
/// the current one. Since inbound decryption matches the JWE recipient `kid`
/// against the secrets resolver rather than against our DID document, a message
/// encrypted to a retired key-agreement key still decrypts for as long as its
/// generation is live. This vector is also the only durable source of that
/// truth: the framework re-seeds its resolver from `profile.secrets()` on every
/// reconnect.
pub async fn build_tdk_profile_for_identity(
    alias: &str,
    identity: &ServiceIdentity,
    peer_did: Option<&str>,
) -> Result<TDKProfile, AppError> {
    let mediator_did = discover_mediator(peer_did, Some(&identity.did_resolver)).await;

    Ok(TDKProfile::new(
        alias,
        &identity.did,
        mediator_did.as_deref(),
        identity.secrets(),
    ))
}

/// Discover the actual mediator DID from a peer's DID document.
///
/// Only follows one level: if the discovered endpoint is a DID, use it; if it
/// is a URL (i.e. the peer *is* the mediator), use the peer DID directly.
async fn discover_mediator(
    peer_did: Option<&str>,
    did_resolver: Option<&DIDCacheClient>,
) -> Option<String> {
    let peer = peer_did?;

    match resolve_mediator_did(peer, did_resolver).await {
        Some(mediator) if mediator.starts_with("did:") => Some(mediator),
        Some(_url) => {
            info!("peer {peer} is a mediator (endpoint is a URL) — using it directly");
            Some(peer.to_string())
        }
        None => {
            warn!(
                "could not discover mediator from {peer} — \
                 falling back to using it directly as mediator"
            );
            Some(peer.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "did:webvh:Qm:peer.example";
    const DOC_MED: &str = "did:web:mediator.doc.example";
    const CFG_MED: &str = "did:web:mediator.config.example";

    fn cfg(mediator: Option<&str>, prefer_tsp: bool) -> TransportFallback {
        TransportFallback::from_config(mediator, prefer_tsp)
    }

    #[test]
    fn tier1_document_transport_wins_over_config() {
        // The document advertises a transport and config also has a mediator:
        // the document is authoritative and its binding wins.
        let tsp = decide_binding(
            PEER,
            Some((PeerTransport::Tsp, DOC_MED.into())),
            &cfg(Some(CFG_MED), false),
        );
        assert_eq!(tsp, Some((PeerTransport::Tsp, DOC_MED.into())));

        let didcomm = decide_binding(
            PEER,
            Some((PeerTransport::Didcomm, DOC_MED.into())),
            &cfg(Some(CFG_MED), true),
        );
        assert_eq!(didcomm, Some((PeerTransport::Didcomm, DOC_MED.into())));
    }

    #[test]
    fn tier2_config_fallback_used_when_document_silent() {
        // Document advertises no messaging service; the configured mediator
        // is used — this is the compatibility bridge for pre-transport DIDs.
        // `prefer_tsp` picks the binding.
        let tsp = decide_binding(PEER, None, &cfg(Some(CFG_MED), true));
        assert_eq!(tsp, Some((PeerTransport::Tsp, CFG_MED.into())));

        let didcomm = decide_binding(PEER, None, &cfg(Some(CFG_MED), false));
        assert_eq!(didcomm, Some((PeerTransport::Didcomm, CFG_MED.into())));
    }

    #[test]
    fn tier3_none_when_nothing_routes() {
        // No document messaging service and no configured mediator: unroutable.
        // The caller must not blindly attempt a send (the old blind-DIDComm
        // behaviour this replaces).
        let got = decide_binding(PEER, None, &cfg(None, false));
        assert_eq!(got, None);
    }

    #[test]
    fn from_config_empty_without_mediator() {
        assert!(TransportFallback::from_config(None, true).binding.is_none());
        let f = TransportFallback::from_config(Some(CFG_MED), true);
        assert_eq!(f.binding, Some((PeerTransport::Tsp, CFG_MED.to_string())));
        let f = TransportFallback::from_config(Some(CFG_MED), false);
        assert_eq!(
            f.binding,
            Some((PeerTransport::Didcomm, CFG_MED.to_string()))
        );
    }
}

//! Shared TDK profile construction for DIDComm services.
//!
//! Resolves the server's DID document to discover the correct verification-method
//! key IDs, then builds a `TDKProfile` with the correct secrets. This is used by
//! the `affinidi-messaging-didcomm-service` framework to establish mediator
//! connections.

use std::time::Duration;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::profiles::TDKProfile;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::error::AppError;
use super::secret_store::ServerSecrets;

/// Resolve the actual key IDs from a DID document.
///
/// The ATM SDK matches secrets to DID-document verification-method IDs during
/// `pack_encrypted`. If the secrets use hardcoded fragments like `#key-0` /
/// `#key-1` but the DID document uses multibase-encoded fragments like
/// `#z6Mk…` / `#z6LS…`, the mediator will fail with "Unable unwrap cek".
///
/// Falls back to `{did}#key-0` / `{did}#key-1` when the DID cannot be resolved
/// (e.g. the server hosts its own DID and hasn't published it yet).
///
/// Accepts an optional existing `DIDCacheClient` to avoid creating a throwaway
/// resolver instance.
pub async fn resolve_server_key_ids(
    server_did: &str,
    existing_resolver: Option<&DIDCacheClient>,
) -> (String, String) {
    let fallback_signing = format!("{server_did}#key-0");
    let fallback_ka = format!("{server_did}#key-1");

    // Use the provided resolver, or create a one-shot instance.
    let owned;
    let did_resolver = match existing_resolver {
        Some(r) => r,
        None => match DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await {
            Ok(r) => {
                owned = r;
                &owned
            }
            Err(e) => {
                warn!("failed to resolve DID for key IDs: {e} — using fallback");
                return (fallback_signing, fallback_ka);
            }
        },
    };

    match did_resolver.resolve(server_did).await {
        Ok(response) => {
            let doc = &response.doc;

            let ka_kid = match doc.key_agreement.first() {
                Some(vr) => {
                    let kid = vr.get_id().to_string();
                    info!(kid = %kid, "DID doc keyAgreement key ID");
                    kid
                }
                None => {
                    warn!("DID document has no keyAgreement — using fallback {fallback_ka}");
                    fallback_ka
                }
            };

            let signing_kid = match doc.authentication.first() {
                Some(vr) => {
                    let kid = vr.get_id().to_string();
                    info!(kid = %kid, "DID doc authentication key ID");
                    kid
                }
                None => {
                    warn!("DID document has no authentication — using fallback {fallback_signing}");
                    fallback_signing
                }
            };

            (signing_kid, ka_kid)
        }
        Err(e) => {
            warn!("failed to resolve DID {server_did}: {e} — using fallback key IDs");
            (fallback_signing, fallback_ka)
        }
    }
}

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

/// Resolve every service `type` a peer's DID document advertises.
///
/// The network-facing counterpart to
/// [`crate::did::service_types_from_doc`], which reads a document we
/// already hold. Used to populate the registry's per-instance badge cache:
/// the registry stores only a DID string, so the document has to be fetched.
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
    // `did::service_types_from_doc`'s contract — document order, deduped —
    // but over the resolver's `Service` type rather than raw JSON.
    let mut out: Vec<String> = Vec::new();
    for svc in &doc.service {
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

/// Build a `TDKProfile` suitable for use with `DIDCommService`.
///
/// 1. Resolves the DID document to discover actual verification-method key IDs.
/// 2. Creates `Secret` objects from the configured private keys with the correct KIDs.
/// 3. If `peer_did` is provided, resolves it to discover the mediator DID from
///    its `DIDCommMessaging` service endpoint.
/// 4. Returns a `TDKProfile` ready for `ListenerConfig`.
pub async fn build_tdk_profile(
    alias: &str,
    service_did: &str,
    peer_did: Option<&str>,
    secrets: &ServerSecrets,
    did_resolver: Option<&DIDCacheClient>,
) -> Result<TDKProfile, AppError> {
    let (signing_kid, ka_kid) = resolve_server_key_ids(service_did, did_resolver).await;

    let signing_secret = Secret::from_multibase(&secrets.signing_key, Some(&signing_kid))
        .map_err(|e| AppError::Config(format!("failed to decode signing_key: {e}")))?;

    let ka_secret = Secret::from_multibase(&secrets.key_agreement_key, Some(&ka_kid))
        .map_err(|e| AppError::Config(format!("failed to decode key_agreement_key: {e}")))?;

    // Discover the actual mediator DID from the peer's DID document.
    // Only follow one level: if the discovered endpoint is a DID, use it;
    // if it's a URL (i.e. the peer IS the mediator), use the peer DID directly.
    let mediator_did = if let Some(peer) = peer_did {
        match resolve_mediator_did(peer, did_resolver).await {
            Some(mediator) if mediator.starts_with("did:") => Some(mediator),
            Some(_url) => {
                // The peer's DIDCommMessaging points to a URL, meaning the
                // peer itself is the mediator — use the peer DID directly.
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
    } else {
        None
    };

    Ok(TDKProfile::new(
        alias,
        service_did,
        mediator_did.as_deref(),
        vec![signing_secret, ka_secret],
    ))
}

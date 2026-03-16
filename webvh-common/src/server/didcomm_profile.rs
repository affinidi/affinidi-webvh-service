//! Shared TDK profile construction for DIDComm services.
//!
//! Resolves the server's DID document to discover the correct verification-method
//! key IDs, then builds a `TDKProfile` with the correct secrets. This is used by
//! the `affinidi-messaging-didcomm-service` framework to establish mediator
//! connections.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::profiles::TDKProfile;
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

/// Build a `TDKProfile` suitable for use with `DIDCommService`.
///
/// 1. Resolves the DID document to discover actual verification-method key IDs.
/// 2. Creates `Secret` objects from the configured private keys with the correct KIDs.
/// 3. Returns a `TDKProfile` ready for `ListenerConfig`.
pub async fn build_tdk_profile(
    alias: &str,
    service_did: &str,
    mediator_did: Option<&str>,
    secrets: &ServerSecrets,
    did_resolver: Option<&DIDCacheClient>,
) -> Result<TDKProfile, AppError> {
    let (signing_kid, ka_kid) = resolve_server_key_ids(service_did, did_resolver).await;

    let signing_secret = Secret::from_multibase(&secrets.signing_key, Some(&signing_kid))
        .map_err(|e| AppError::Config(format!("failed to decode signing_key: {e}")))?;

    let ka_secret = Secret::from_multibase(&secrets.key_agreement_key, Some(&ka_kid))
        .map_err(|e| AppError::Config(format!("failed to decode key_agreement_key: {e}")))?;

    Ok(TDKProfile::new(
        alias,
        service_did,
        mediator_did,
        vec![signing_secret, ka_secret],
    ))
}

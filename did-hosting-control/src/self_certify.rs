//! Verifying a request against the document its own submission implies.
//!
//! Two kinds of request are signed by a DID that does not resolve yet,
//! because the request is what will publish it: a `did:webs` registering
//! itself (`crate::webs_self_register`, checked against the key event log it
//! submits) and a guest account registering its `did:webvh`
//! (`crate::account_register`, checked against the log it submits). Both
//! identifiers are self-certifying — the identifier commits to the keys that
//! control it — so the verified submission yields the only document the
//! request may be checked against, and nothing is resolved over the network.
//!
//! [`verify_against_document`] is that check: the sender-bound rule every
//! privileged document is held to ([`verify_sender_bound`]: issuer, transport
//! sender, recipient, freshness, `proofPurpose: authentication` with the key
//! under `authentication`), with the key looked up in that one document.

use std::sync::Arc;

use serde_json::Value;
use trust_tasks_rs::TrustTask;

use did_hosting_common::server::trust_tasks::{
    BoundError, TransportBoundVerifier, verify_sender_bound,
};

/// Verify `doc` as signed by `did`, whose document is `document`, and
/// return the proven issuer (always `did`'s identity).
///
/// `did` is an identity: a `did:scid` without its `src`. A proof whose
/// `verificationMethod` carries the `src` locator is resolved by identity.
pub(crate) async fn verify_against_document(
    doc: &TrustTask<Value>,
    did: &str,
    document: affinidi_did_common::Document,
    sender: &str,
    my_vid: &str,
) -> Result<String, BoundError> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use trust_tasks_rs::VerificationError;

    // A cache holding this one document, so the library's own relationship
    // check (listed under `authentication`, controlled by the DID that names
    // it) and key decoding decide the key — the same code every other proof
    // here goes through.
    let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| {
            BoundError::Proof(VerificationError::Other(format!(
                "could not hold the self-certified document: {e}"
            )))
        })?;
    client.add_did_document(did, document).await;
    let verifier = TransportBoundVerifier::with_resolver(Arc::new(OneDocument {
        did: did.to_string(),
        decode: trust_tasks_proof::affinidi::CachedDidResolver::new(Arc::new(client)),
    }));
    let proven = verify_sender_bound(doc, Some(did), Some(sender), my_vid, &verifier).await?;
    if !did_hosting_common::scid::same_reference(&proven, did) {
        return Err(BoundError::UnexpectedIssuer {
            issuer: proven,
            expected: did.to_string(),
        });
    }
    Ok(did_hosting_common::scid::identity(&proven))
}

/// Resolves verification methods of exactly one identifier, from the document
/// its verified submission implies. Any other DID is refused here, before the
/// cache could treat it as a miss and resolve it over the network.
struct OneDocument {
    did: String,
    decode: trust_tasks_proof::affinidi::CachedDidResolver,
}

#[async_trait::async_trait]
impl trust_tasks_proof::affinidi::ProofPurposeResolver for OneDocument {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: trust_tasks_proof::affinidi::ProofPurpose,
    ) -> Result<affinidi_data_integrity::ResolvedKey, affinidi_data_integrity::DataIntegrityError>
    {
        let controller = did_hosting_common::server::trust_tasks::verifier::controller_did(vm);
        if !did_hosting_common::scid::same_reference(controller, &self.did) {
            return Err(affinidi_data_integrity::DataIntegrityError::Resolver(
                "the proof's verificationMethod is not a key of the DID being registered".into(),
            ));
        }
        self.decode
            .resolve_vm_for_purpose(&did_hosting_common::scid::strip_scid_src(vm), purpose)
            .await
    }
}

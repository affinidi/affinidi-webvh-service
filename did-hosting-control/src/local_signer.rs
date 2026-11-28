//! Signers whose DID this host holds, verified against the host's own log.
//!
//! The control plane is the source of record for every DID it hosts: it
//! verified each log when it was written, and it is what its edges serve. So
//! when a request is signed by a `did:webvh` this host holds (or by its
//! `did:scid` alias, located by its `src`), the request's proof is checked
//! against the document that slot's stored log implies — the same check
//! [`crate::self_certify`] makes for a self-registration against its submitted
//! log — instead of resolving the DID over the network back to this host.
//!
//! That is no weaker than resolution, which would fetch the same log from this
//! host's own public URL, and it removes three ways that fetch fails:
//!
//! - a slot that is **disabled** answers 404, yet its holder still has
//!   authority (that is the ACL entry's to say, not the slot's): an account
//!   disabled for inactivity must still be able to renew, and an owner who
//!   disabled its own identity DID to re-enable it;
//! - a host behind NAT or a proxy that cannot reach its own public URL;
//! - a host on a loopback or private address, which the resolver's
//!   `PublicOnly` policy refuses.
//!
//! The document is the one a resolver would see: only the **servable** part
//! of the log ([`servable_did_log`], the witness threshold met), never a
//! not-yet-witnessed tail. A deactivated log authenticates no one; a
//! soft-deleted slot, one whose stored DID is not exactly the signer's, or a
//! stored log that no longer verifies is not used, and the signer is verified
//! as any other is.
//!
//! [`servable_did_log`]: did_hosting_common::did_ops::servable_did_log

// A refusal here is a framework `ErrorPayload`, handed to the gate's
// `rejected` whole, as `account_register`'s are.
#![allow(clippy::result_large_err)]

use serde_json::Value;
use tracing::warn;
use trust_tasks_rs::{ErrorPayload, StandardCode, TrustTask};

use did_hosting_common::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, extract_log_metadata,
    servable_did_log,
};
use did_hosting_common::scid;

use crate::server::AppState;

/// A signer whose DID this host holds, with the document its stored log
/// implies.
pub(crate) struct LocalSigner {
    /// The signer's identity (a `did:scid` without its `src`).
    did: String,
    document: affinidi_did_common::Document,
}

impl LocalSigner {
    /// Hold `doc` to the sender-bound rule, with its proof verified against
    /// the stored log's document.
    pub(crate) async fn verify(
        self,
        doc: &TrustTask<Value>,
        sender: &str,
        my_vid: &str,
    ) -> Result<String, did_hosting_common::server::trust_tasks::BoundError> {
        crate::self_certify::verify_against_document(doc, &self.did, self.document, sender, my_vid)
            .await
    }
}

/// The `did:webvh` of the slot a self-registered account holds whose
/// did:scid alias is `subject`, when there is one.
async fn account_slot_did(state: &AppState, subject: &str) -> Option<String> {
    let record = did_hosting_common::server::account::get(&state.acl_ks, subject)
        .await
        .ok()??;
    let slots = crate::did_ops::owner_mnemonics_on_domain(state, subject, &record.domain)
        .await
        .ok()?;
    for slot in slots {
        let Ok(Some(rec)) = state.dids_ks.get::<DidRecord>(did_key(&slot)).await else {
            continue;
        };
        if let Some(did_id) = rec.did_id
            && scid::identity(&scid::scid_alias(&did_id)) == subject
        {
            return Some(did_id);
        }
    }
    None
}

/// The slot a `did:webvh` names: its path segments joined with `/`, or
/// `.well-known` for a DID at the host's root.
fn slot_of(webvh_did: &str) -> Option<String> {
    let rest = webvh_did.strip_prefix("did:webvh:")?;
    let mut parts = rest.splitn(3, ':');
    parts.next().filter(|s| !s.is_empty())?; // SCID
    parts.next().filter(|s| !s.is_empty())?; // host
    Some(match parts.next() {
        None | Some("") => ".well-known".to_string(),
        Some(path) => path.replace(':', "/"),
    })
}

/// When `doc` is signed by a DID this host holds, that DID and the document
/// its stored log implies.
///
/// `Ok(None)`: no issuer, a DID of another method or host, a `did:scid` with
/// no `src` to locate it, or no live slot holding exactly this DID — the
/// signer is verified as any other is. `Err`: the slot holds it, and its log
/// authenticates no one (deactivated, or not usable).
pub(crate) async fn local_signer(
    state: &AppState,
    doc: &TrustTask<Value>,
) -> Result<Option<LocalSigner>, ErrorPayload> {
    let Some(issuer) = doc.issuer.as_deref() else {
        return Ok(None);
    };
    let subject = scid::identity(issuer);
    let as_scid = issuer.starts_with("did:scid:");
    // The did:webvh the signer's log is published as: the issuer itself, the
    // one a did:scid's `src` names, or — for a did:scid sent without `src` —
    // the slot of its self-registered account that it is the alias of.
    let webvh_did = match scid::webvh_log_did(issuer, None) {
        Some(did) => did,
        None if as_scid => match account_slot_did(state, &subject).await {
            Some(did) => did,
            None => return Ok(None),
        },
        None => return Ok(None),
    };
    let webvh_did = webvh_did
        .split(['?', '#'])
        .next()
        .unwrap_or(&webvh_did)
        .to_string();
    let Some(slot) = slot_of(&webvh_did) else {
        return Ok(None);
    };
    let record: DidRecord = match state.dids_ks.get(did_key(&slot)).await {
        Ok(Some(record)) => record,
        _ => return Ok(None),
    };
    if record.deleted_at.is_some() || record.did_id.as_deref() != Some(webvh_did.as_str()) {
        return Ok(None);
    }
    let (Ok(Some(log)), witness) = (
        state.dids_ks.get_raw(content_log_key(&slot)).await,
        state
            .dids_ks
            .get_raw(content_witness_key(&slot))
            .await
            .ok()
            .flatten(),
    ) else {
        return Ok(None);
    };
    let unusable = |why: &str| {
        warn!(signer = %subject, %slot, reason = why, "trust task refused: the signer's stored log");
        ErrorPayload::new(StandardCode::PermissionDenied)
            .with_message(format!("the signer's DID {why}"))
    };
    let Ok(log) = std::str::from_utf8(&log) else {
        return Ok(None);
    };
    let witness = witness.as_deref().and_then(|w| std::str::from_utf8(w).ok());
    // What a resolver would be served: the witnessed prefix.
    let Some(servable) = servable_did_log(log, witness) else {
        // Nothing a resolver would be served either: the ordinary path
        // reports it as it reports any DID that does not resolve.
        return Ok(None);
    };
    if extract_log_metadata(&servable).deactivated {
        return Err(unusable("is deactivated, so its keys sign nothing"));
    }
    let publication = did_hosting_common::method::publication::verify_publication(
        &record.domain,
        &slot,
        servable.as_bytes(),
        None,
        None,
    )
    // Verified when it was written; one that no longer verifies is left to
    // the ordinary path rather than trusted here.
    .ok();
    let Some(publication) = publication else {
        warn!(signer = %subject, %slot, "stored log does not verify; verifying the signer by resolution");
        return Ok(None);
    };
    if publication.did_id.as_deref() != Some(webvh_did.as_str()) {
        return Ok(None);
    }
    let Some(document) = publication.document else {
        return Ok(None);
    };
    let document = if !as_scid {
        document
    } else if scid::identity(&scid::scid_alias(&webvh_did)) == subject
        && scid::scid_alias_info(&document)
            .is_some_and(|i| i.status == scid::ScidAliasStatus::Listed)
    {
        scid::scid_document(&document)
            .map_err(|_| unusable("did:scid document cannot be derived"))?
    } else {
        // A did:scid the document does not list is not this DID's alias.
        return Ok(None);
    };
    let document =
        serde_json::from_value(document).map_err(|_| unusable("document is not a DID document"))?;
    Ok(Some(LocalSigner {
        did: subject,
        document,
    }))
}

#[cfg(test)]
mod tests {
    use super::slot_of;

    #[test]
    fn a_did_names_its_slot() {
        assert_eq!(
            slot_of("did:webvh:Qm:a.example:agents:vta").as_deref(),
            Some("agents/vta")
        );
        assert_eq!(slot_of("did:webvh:Qm:a.example:x").as_deref(), Some("x"));
        assert_eq!(
            slot_of("did:webvh:Qm:a.example").as_deref(),
            Some(".well-known")
        );
        assert_eq!(
            slot_of("did:webvh:Qm:localhost%3A8634:agents:vta").as_deref(),
            Some("agents/vta")
        );
        assert_eq!(slot_of("did:web:a.example"), None);
        assert_eq!(slot_of("did:webvh::a.example"), None);
    }
}

//! `did:scid:vh:1` identities, as callers present them and as hosted logs
//! list them.
//!
//! A hosted log is always a `did:webvh` log; its `did:scid:vh:1:<scid>` DID is
//! verified by that same log but is a distinct identity (VTI-KEY-164). Callers
//! — owners, ACL subjects, proof signers — may present either. A did:scid
//! identity is the bare DID: its `?src=` is a locator for the log, not part of
//! the identity (VTI-KEY-160), so it is recorded, keyed and compared without
//! it. A reference that carries `src` (an issuer, a `verificationMethod`, a
//! DIDComm `from`) matches the bare DID.

use didwebvh_rs::DIDWebVHState;
use serde_json::Value;

pub use affinidi_did_common::scid::{same_reference, scid_src, strip_scid_src};

/// The identity a caller-presented DID (or DID URL) names: a did:scid without
/// its `src` locator, anything else unchanged.
pub fn identity(did: &str) -> String {
    strip_scid_src(did).into_owned()
}

/// The `did:scid:vh:1:<scid>?src=…` alias of a hosted `did:webvh` log: what a
/// log lists in `alsoKnownAs` to link its two forms (VTI-KEY-166).
pub fn scid_alias(webvh_did: &str) -> String {
    DIDWebVHState::convert_webvh_id_to_scid_id(webvh_did)
}

/// The `did:webvh` DID of the log that verifies `did`, where it can be told.
///
/// A did:webvh is its own log. A did:scid with a `src` names its log. A bare
/// did:scid names none, so the resolved `document` is consulted: under the
/// native resolution the TDK performs, it lists the did:webvh DID in
/// `alsoKnownAs`; under an older resolver its `id` is the did:webvh DID.
/// The SCID must match either way, or nothing is returned.
pub fn webvh_log_did(did: &str, document: Option<&Value>) -> Option<String> {
    let did = did.split('#').next().unwrap_or(did);
    if did.starts_with("did:webvh:") {
        return Some(did.to_string());
    }
    if !did.starts_with("did:scid:vh:1:") {
        return None;
    }
    if let Some(webvh) = DIDWebVHState::convert_scid_id_to_webvh_id(did) {
        return Some(webvh);
    }
    let scid = did.strip_prefix("did:scid:vh:1:")?;
    let document = document?;
    let candidates = document
        .get("id")
        .into_iter()
        .chain(
            document
                .get("alsoKnownAs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .filter_map(Value::as_str);
    candidates
        .filter(|c| {
            c.strip_prefix("did:webvh:")
                .and_then(|rest| rest.split(':').next())
                == Some(scid)
        })
        .map(str::to_string)
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_drops_only_the_scid_locator() {
        assert_eq!(
            identity("did:scid:vh:1:Qm1?src=dids.example.org/alice"),
            "did:scid:vh:1:Qm1"
        );
        assert_eq!(
            identity("did:webvh:Qm1:dids.example.org"),
            "did:webvh:Qm1:dids.example.org"
        );
        assert_eq!(identity("did:key:z6Mk"), "did:key:z6Mk");
    }

    #[test]
    fn alias_of_a_hosted_log() {
        assert_eq!(
            scid_alias("did:webvh:Qm1:dids.example.org:alice"),
            "did:scid:vh:1:Qm1?src=dids.example.org/alice"
        );
    }

    #[test]
    fn webvh_log_of_each_form() {
        assert_eq!(
            webvh_log_did("did:webvh:Qm1:a.example#key-0", None).as_deref(),
            Some("did:webvh:Qm1:a.example")
        );
        assert_eq!(
            webvh_log_did("did:scid:vh:1:Qm1?src=a.example/x", None).as_deref(),
            Some("did:webvh:Qm1:a.example:x")
        );
        // A bare did:scid: from the native document's alsoKnownAs.
        let native = json!({
            "id": "did:scid:vh:1:Qm1",
            "alsoKnownAs": ["did:scid:vh:1:Qm1?src=a.example", "did:webvh:Qm1:a.example"]
        });
        assert_eq!(
            webvh_log_did("did:scid:vh:1:Qm1", Some(&native)).as_deref(),
            Some("did:webvh:Qm1:a.example")
        );
        // Another SCID's log is not this one's.
        let other =
            json!({ "id": "did:scid:vh:1:Qm1", "alsoKnownAs": ["did:webvh:Qm2:a.example"] });
        assert_eq!(webvh_log_did("did:scid:vh:1:Qm1", Some(&other)), None);
        assert_eq!(webvh_log_did("did:scid:vh:1:Qm1", None), None);
        assert_eq!(webvh_log_did("did:key:z6Mk", None), None);
    }
}

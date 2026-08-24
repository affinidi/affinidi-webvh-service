//! Verifying an incoming publication, whatever method it belongs to.
//!
//! The control plane's write path — `register_did_atomic`, `publish_did` —
//! is almost entirely method-agnostic. Ownership, takeover, ACL, domain
//! safety, the agent-name registry and the atomic batch write are the
//! same work regardless of what kind of DID is being published. What is
//! *not* the same is the front of it: what counts as a valid document,
//! which identifier it belongs to, and where to read the current DID
//! document out of the stored bytes.
//!
//! This module is that front. It takes the submitted bytes and returns a
//! [`Publication`] — verified, and reduced to the handful of facts the
//! shared tail needs. Adding a method means adding an arm here, not
//! threading a fourth branch through the write path.
//!
//! ## Verification is per-method, and it is the whole point
//!
//! Each arm runs its own method's real verification before anything is
//! stored, because that is what makes this service a host rather than a
//! file server:
//!
//! - **webvh** — `verify_did_log_proofs` walks the log chain, checking
//!   each entry's signature against `parameters.updateKeys` and
//!   rejecting tampered or post-deactivation entries.
//! - **webs** — `Webs::verify_artifacts` verifies the key event log:
//!   every event's SAID, the prior-event digest chain, controller
//!   signatures, pre-rotation commitments, delegation seals, witness
//!   receipts, and the designated-aliases attestation.
//! - **web** — `Web::validate` is a shape check, and deliberately so:
//!   a `did:web` document is unsigned, so there is nothing to verify
//!   against. Authorisation is the only control, and the write path
//!   applies it either way.
//!
//! ## Where `did_id` comes from, and why webs is different
//!
//! For webvh and web the identifier is *inside* the document — the log
//! states its own `state.id`, the document its own `id` — so it is read
//! out and then checked against the slot it was published to.
//!
//! A `did:webs` key event log contains no such thing. A KEL establishes
//! an **AID**, and nothing more: the host and path that turn that AID
//! into a DID are properties of where it is published, not of the log.
//! So the identifier is *constructed* from the slot (`did:webs:{domain}:
//! {mnemonic}`) and the log is then required to establish exactly the
//! AID that identifier ends in. That inverts the direction of the check
//! but not its strength — a stream for some other AID is refused, and a
//! stream cannot claim a slot by asserting a domain it was not
//! published under, because it never gets to assert one.

use serde_json::Value;

use super::{MethodError, detect_method};

/// A verified publication, reduced to what the write path needs.
#[derive(Debug, Clone)]
pub struct Publication {
    /// The method that verified this content — one of the compiled-in
    /// method names, never caller-supplied.
    pub method: &'static str,

    /// The DID identifier this publication is for.
    ///
    /// `None` only for a webvh log whose last entry has no resolvable
    /// `state.id`, which the existing write path already tolerates on
    /// the republish path.
    pub did_id: Option<String>,

    /// The current DID document.
    ///
    /// `None` means the document could not be read — callers must treat
    /// that as "unknown", not as "empty". See [`Self::services`].
    pub document: Option<Value>,

    /// The bytes to store under `content_log_key`.
    ///
    /// Always the method's canonical log artifact: the jsonl for webvh,
    /// the document for web, the CESR stream for webs. Never a derived
    /// view — those are recomputed on read.
    pub content: Vec<u8>,
}

impl Publication {
    /// Advertised `service[].type` values, for the record's badge cache.
    ///
    /// Tri-state, and the distinction is load-bearing: `None` means the
    /// document was unreadable, `Some(vec![])` means it was read and
    /// advertises nothing. Collapsing them would let a parse failure be
    /// cached as "advertises no services".
    pub fn services(&self) -> Option<Vec<String>> {
        self.document
            .as_ref()
            .map(crate::did::service_types_from_doc)
    }

    /// Agent names this document claims on `domain`.
    pub fn agent_names(&self, domain: &str) -> Vec<String> {
        self.document
            .as_ref()
            .map(|doc| crate::did_ops::agent_names_from_document(doc, domain))
            .unwrap_or_default()
    }
}

/// Verify a submitted publication for a slot.
///
/// `domain` and `mnemonic` identify the slot being published to; they are
/// only consulted for methods whose identifier is not inside the content
/// (today, `webs`). `existing` is the currently stored content for the
/// slot, if any — used for continuity checks that need the prior state.
///
/// # Errors
/// [`MethodError::Validation`] if the content does not verify, or
/// [`MethodError::Malformed`] if no compiled-in method recognises it.
// `domain`, `mnemonic` and `existing` are consulted only by methods whose
// identifier is not inside the content — today just `webs`. They stay in the
// signature when it is compiled out so callers do not need their own cfg.
#[cfg_attr(not(feature = "method-webs"), allow(unused_variables))]
pub fn verify_publication(
    domain: &str,
    mnemonic: &str,
    content: &[u8],
    existing: Option<&[u8]>,
) -> Result<Publication, MethodError> {
    let method = detect_method(content).ok_or_else(|| {
        MethodError::Malformed(
            "content matches no DID method enabled on this deployment — expected a \
             did:webvh log, a did:web document, or a did:webs keri.cesr stream"
                .into(),
        )
    })?;

    match method {
        #[cfg(feature = "method-webvh")]
        "webvh" => verify_webvh(content),
        #[cfg(feature = "method-web")]
        "web" => verify_web(content),
        #[cfg(feature = "method-webs")]
        "webs" => verify_webs(domain, mnemonic, content, existing),
        // `detect_method` only ever returns a compiled-in method, so
        // this is unreachable — but it keeps the match total without an
        // `unreachable!` that a future arm could turn into a panic.
        other => Err(MethodError::Malformed(format!(
            "no verifier for method '{other}'"
        ))),
    }
}

#[cfg(feature = "method-webvh")]
fn verify_webvh(content: &[u8]) -> Result<Publication, MethodError> {
    let text = std::str::from_utf8(content)
        .map_err(|e| MethodError::Validation(format!("did.jsonl is not valid UTF-8: {e}")))?;

    crate::did_ops::verify_did_log_proofs(text).map_err(MethodError::Validation)?;

    // The current document is the last non-blank entry's `state`. Read
    // through the same path `extract_did_id` uses so the document and
    // the identifier can never come from different entries.
    let document = text
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .and_then(|line| serde_json::from_str::<Value>(line).ok())
        .and_then(|v| v.get("state").cloned());

    Ok(Publication {
        method: "webvh",
        did_id: crate::did_ops::extract_did_id(text),
        document,
        content: content.to_vec(),
    })
}

#[cfg(feature = "method-web")]
fn verify_web(content: &[u8]) -> Result<Publication, MethodError> {
    use super::DidMethod;
    super::web::Web.validate(content)?;
    let document: Value = serde_json::from_slice(content)
        .map_err(|e| MethodError::Validation(format!("did.json is not valid JSON: {e}")))?;
    let did_id = document
        .get("id")
        .and_then(|i| i.as_str())
        .map(str::to_string);
    Ok(Publication {
        method: "web",
        did_id,
        document: Some(document),
        content: content.to_vec(),
    })
}

#[cfg(feature = "method-webs")]
fn verify_webs(
    domain: &str,
    mnemonic: &str,
    content: &[u8],
    existing: Option<&[u8]>,
) -> Result<Publication, MethodError> {
    use super::webs::Webs;

    if domain.is_empty() {
        // Not recoverable by guessing: the DID a KEL belongs to is
        // (domain, path, AID), and two of those three come from the
        // slot. Publishing without a domain would mean verifying the
        // stream against an identifier we made up.
        return Err(MethodError::Validation(
            "did:webs requires a hosting domain: the key event log establishes an AID, \
             not a DID, so the domain cannot be recovered from the content"
                .into(),
        ));
    }

    // `did:webs:{domain}:{path}:{AID}` — the mnemonic already ends in
    // the AID, because the AID *is* the last path segment.
    //
    // The host's port separator must be percent-encoded. A DID's labels
    // are colon-separated, so a literal `localhost:8534` would parse
    // back as host `localhost` with `8534` as a path segment — a
    // different DID, on a host that is not this one. Callers hand us
    // the *decoded* host (that is what `extract_did_host` and the
    // domain registry both hold), so encoding here is the conversion
    // from "hosting domain" to "DID label". Idempotent, so a caller
    // that already passed the encoded form is unaffected.
    let did_domain = domain.replace(':', "%3A");
    let did_id = format!("did:webs:{did_domain}:{}", mnemonic.replace('/', ":"));

    // Refuse an update that rewinds or forks the hosted log, before
    // deriving anything from the new one.
    if let Some(existing) = existing.filter(|e| !e.is_empty()) {
        Webs::verify_continuation(&did_id, existing, content)?;
    }

    // The real verification. Also proves the stream establishes exactly
    // the AID this slot's identifier ends in.
    let derived = Webs::verify_artifacts(&did_id, content, None)?;
    let document: Value = serde_json::from_slice(&derived)
        .map_err(|e| MethodError::Validation(format!("derived document is not valid JSON: {e}")))?;

    Ok(Publication {
        method: "webs",
        did_id: Some(did_id),
        document: Some(document),
        content: content.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "method-webs")]
    const KERI: &[u8] = include_bytes!("../../tests/fixtures/ENro7uf0.keri.cesr");
    #[cfg(feature = "method-webs")]
    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
    #[cfg(feature = "method-webs")]
    const DOMAIN: &str = "did-webs-service%3a7676";

    #[cfg(feature = "method-webs")]
    #[test]
    fn verifies_a_webs_publication_and_builds_its_did() {
        let p = verify_publication(DOMAIN, AID, KERI, None).expect("reference artifacts verify");
        assert_eq!(p.method, "webs");
        assert_eq!(
            p.did_id.as_deref(),
            Some(format!("did:webs:{DOMAIN}:{AID}").as_str())
        );
        assert_eq!(p.content, KERI, "the CESR stream is what gets stored");
        assert!(p.document.is_some());
    }

    #[cfg(feature = "method-webs")]
    #[test]
    fn refuses_a_webs_publication_to_a_slot_that_is_not_its_aid() {
        // The stream verifies, but it establishes a different AID than
        // the slot's — so it is not this DID's log.
        let err = verify_publication(DOMAIN, "EAnotherAidEntirely00000000000", KERI, None)
            .expect_err("a KEL may only be published to its own AID's slot");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    #[cfg(feature = "method-webs")]
    #[test]
    fn refuses_a_webs_publication_with_no_domain() {
        let err = verify_publication("", AID, KERI, None)
            .expect_err("a did:webs DID cannot be built without its domain");
        assert!(matches!(err, MethodError::Validation(_)));
        assert!(err.to_string().contains("domain"));
    }

    #[cfg(feature = "method-webs")]
    #[test]
    fn refuses_a_webs_update_that_rewinds_the_log() {
        let second_event = KERI
            .windows(4)
            .skip(1)
            .position(|w| w == br#"{"v""#)
            .map(|p| p + 1)
            .expect("stream has more than one message");
        let truncated = &KERI[..second_event];

        let err = verify_publication(DOMAIN, AID, truncated, Some(KERI))
            .expect_err("an update may not rewind the hosted key event log");
        assert!(err.to_string().contains("rewinds"));
    }

    #[cfg(feature = "method-webs")]
    #[test]
    fn a_webs_document_yields_services_and_no_agent_names() {
        let p = verify_publication(DOMAIN, AID, KERI, None).unwrap();
        // Read, and genuinely empty — not `None`, which would mean
        // "could not read" and must not be cached as "advertises none".
        assert_eq!(p.services(), Some(vec![]));
        // The fixture's aliases are did:web / did:webs forms, not
        // agent names, so nothing is claimed on this domain.
        assert!(p.agent_names(DOMAIN).is_empty());
    }

    #[cfg(feature = "method-webvh")]
    #[test]
    fn rejects_content_no_method_recognises() {
        let err =
            verify_publication("example.com", "alice", b"nonsense", None).expect_err("must reject");
        assert!(matches!(err, MethodError::Malformed(_)));
    }
}

#[cfg(all(test, feature = "method-webs"))]
mod webs_domain_encoding_tests {
    use super::*;

    const KERI: &[u8] = include_bytes!("../../tests/fixtures/ENro7uf0.keri.cesr");
    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    /// Regression guard. Callers hold the hosting domain in its decoded
    /// form (`extract_did_host` percent-decodes, and the domain registry
    /// stores real hostnames), but a DID's labels are colon-separated —
    /// so a literal `host:port` would parse back as host `host` with
    /// `port` as a path segment. That is a different DID on a host this
    /// deployment does not serve, and the document derived for it would
    /// carry the wrong `id`.
    #[test]
    fn a_ported_host_becomes_a_single_did_label() {
        let p = verify_publication("did-webs-service:7676", AID, KERI, None)
            .expect("the reference artifacts are published on a ported host");
        assert_eq!(
            p.did_id.as_deref(),
            Some(format!("did:webs:did-webs-service%3A7676:{AID}").as_str()),
            "the port separator must be percent-encoded into one label",
        );

        // And the derived document carries that same identifier.
        let doc = p.document.expect("document");
        assert_eq!(
            doc["id"].as_str(),
            Some(format!("did:webs:did-webs-service%3A7676:{AID}").as_str()),
        );
    }

    /// Idempotent: a caller that already holds the encoded form — the
    /// shape a DID label is written in — gets the same answer.
    #[test]
    fn an_already_encoded_host_is_left_alone() {
        let a = verify_publication("did-webs-service:7676", AID, KERI, None).unwrap();
        let b = verify_publication("did-webs-service%3A7676", AID, KERI, None).unwrap();
        assert_eq!(a.did_id, b.did_id);
    }

    /// A host with no port is untouched — the common case must not grow
    /// an encoding artefact.
    #[test]
    fn a_plain_host_is_untouched() {
        let p = verify_publication("hosting.example.com", AID, KERI, None).unwrap();
        assert_eq!(
            p.did_id.as_deref(),
            Some(format!("did:webs:hosting.example.com:{AID}").as_str()),
        );
    }
}

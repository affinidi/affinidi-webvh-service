//! `did:webs` implementation of [`DidMethod`].
//!
//! Per `docs/multi-method-hosting-spec.md` §6.1. Third method in the
//! registry, alongside [`super::webvh`] and [`super::web`], and the
//! first one that is **off by default** — it pulls the KERI stack, and
//! an operator hosting no `did:webs` DIDs should not carry it.
//!
//! ## Identifier shape
//!
//! `did:webs:{host}[%3A{port}][:{path-segment}…]:{AID}`
//!
//! The last label is a KERI **AID**, and it is always the final segment
//! of the resolution URL. That is why `did:webs` — unlike `did:web` and
//! `did:webvh` — has **no `.well-known` form**: there is always at
//! least one path element, so the root slot never applies. Handlers
//! must not grow a `.well-known` branch for this method.
//!
//! ## Two artifacts, one stored blob
//!
//! `did:webs` publishes two files at the same path:
//!
//! ```text
//! https://{domain}/{mnemonic}/keri.cesr   the key event log
//! https://{domain}/{mnemonic}/did.json    the document it implies
//! ```
//!
//! Only `keri.cesr` carries authority. `did.json` is a *cache* of what
//! the verified key state implies, and a conforming resolver derives
//! its own copy and treats a disagreement as an error rather than a
//! preference. So this service stores exactly one blob — the CESR
//! stream, under the existing `content:{mnemonic}:log` key, which is
//! this method's log in the same sense the jsonl is webvh's — and
//! **derives `did.json` on read** ([`Webs::derive_document`]).
//!
//! Storing a second blob would buy nothing and cost a drift surface:
//! the only `did.json` we are allowed to serve is the one the log
//! implies, so a stored copy could only ever be right or stale. A
//! publisher may still *submit* its own `did.json`; it is cross-checked
//! against the derivation and rejected on mismatch
//! ([`Webs::verify_artifacts`]), then discarded.
//!
//! ## Trait-level `validate` vs [`Webs::verify_artifacts`]
//!
//! [`DidMethod::validate`] takes bytes and no DID, so it can only do
//! what the stream alone supports: parse it and confirm it carries a
//! readable key event log. Binding that log to *this* DID — the AID in
//! the identifier must be the one the KEL establishes — needs the
//! identifier, so it lives in [`Webs::verify_artifacts`], which the
//! write path calls. This mirrors [`super::webvh`], whose trait
//! `validate` is line-syntactic and whose chain verification lives in
//! `crate::did_ops::verify_did_log_proofs`.

#![cfg(feature = "method-webs")]

use affinidi_did_webs::{DidWebs, Kels, resolve_from_artifacts};

use super::{DidMethod, MethodError, ParsedDid};

/// The CESR artifact's filename — `keri.cesr`.
pub const KERI_CESR: &str = affinidi_did_webs::KERI_CESR;

/// The document artifact's filename — `did.json`.
pub const DID_JSON: &str = affinidi_did_webs::DID_JSON;

/// MIME type for the `keri.cesr` artifact.
///
/// CESR's registered type. The reference implementation serves it as
/// `application/json` in places, but the stream is not JSON — it is
/// JSON messages interleaved with base64url count codes — so a client
/// that believes the header cannot parse it.
pub const CESR_CONTENT_TYPE: &str = "application/cesr";

/// Zero-size unit struct — the trait impl carries all the behaviour.
pub struct Webs;

impl DidMethod for Webs {
    fn name(&self) -> &'static str {
        "webs"
    }

    fn content_type(&self) -> &'static str {
        // The resolution endpoint (`resolution_url`) returns the DID
        // document. The CESR stream is served alongside it under
        // `CESR_CONTENT_TYPE`; see the module docs.
        "application/did+json"
    }

    fn data_ext(&self) -> &'static str {
        "json"
    }

    fn parse_identifier(&self, did: &str) -> Result<ParsedDid, MethodError> {
        // Delegate the hard part — AID shape, empty labels, query and
        // fragment stripping — to the method crate, so this service and
        // any resolver built on the same crate agree by construction.
        let parsed = DidWebs::parse(did).map_err(|e| {
            if did.starts_with("did:webs:") {
                MethodError::Malformed(format!("{did}: {e}"))
            } else {
                MethodError::MethodMismatch {
                    expected: "webs",
                    found: super::parse_did_method(did)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| "<malformed>".into()),
                }
            }
        })?;

        // `DidWebs::host()` decodes `%3A` back to a literal colon. The
        // other methods keep `domain` in the *encoded* form it appears
        // in the identifier, and the domain allowlist is keyed that way
        // — so take the raw first label rather than the decoded host.
        // Round-tripping through the decoded form would silently miss a
        // configured `example.com%3A8443`.
        let rest = did
            .strip_prefix("did:webs:")
            .and_then(|r| r.split(['?', '#']).next())
            .unwrap_or_default();
        let domain = rest
            .split(':')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| MethodError::Malformed(did.to_string()))?
            .to_string();

        // The mnemonic is every label after the host, AID included —
        // the AID is a path segment, not a suffix bolted on at serve
        // time. Joined with `:` here and split to `/` by
        // `resolution_url`, the same convention webvh and web use.
        let mut path_labels: Vec<&str> = parsed.path().iter().map(String::as_str).collect();
        path_labels.push(parsed.aid());
        let path = path_labels.join(":");

        Ok(ParsedDid {
            method: "webs",
            // The AID is this method's self-certifying identifier — the
            // same role webvh's SCID plays, so it takes the same slot.
            scid: Some(parsed.aid().to_string()),
            domain,
            path,
        })
    }

    fn resolution_url(&self, domain: &str, mnemonic: &str) -> String {
        Self::artifact_url(domain, mnemonic, DID_JSON)
    }

    fn validate(&self, data: &[u8]) -> Result<(), MethodError> {
        // Stream-level only — no identifier in scope. See module docs
        // for the split with `verify_artifacts`.
        if data.iter().all(u8::is_ascii_whitespace) {
            return Err(MethodError::Validation(
                "keri.cesr is empty / whitespace-only".into(),
            ));
        }
        let kels = Kels::parse(data)
            .map_err(|e| MethodError::Validation(format!("keri.cesr could not be read: {e}")))?;

        // Parsing is not enough, and the gap is load-bearing: the CESR
        // parser reads a bare JSON object as a message, so a did:webvh
        // log line — or any JSON at all — "parses" as a stream and
        // reaches here with a non-empty message list. What makes these
        // bytes a key event log is an **inception** event; every KEL
        // starts with one, and nothing else in the stream can stand in
        // for it. Requiring it is what stops a webvh log from being
        // accepted as a webs one, and it is what `detect_method` leans
        // on to tell the two apart.
        let has_inception = kels
            .messages()
            .iter()
            .filter_map(|m| m.serder.ilk().ok())
            .any(|ilk| ilk == "icp" || ilk == "dip");
        if !has_inception {
            return Err(MethodError::Validation(
                "keri.cesr carries no inception event — not a key event log".into(),
            ));
        }
        Ok(())
    }

    fn apply_update(
        &self,
        _existing: Option<&[u8]>,
        new_data: &[u8],
    ) -> Result<Vec<u8>, MethodError> {
        // Replace, not append. A `did:webs` update republishes the whole
        // `keri.cesr`: the key event log *is* the artifact, so an
        // updating controller returns the full new stream rather than a
        // delta. Appending raw bytes to the prior stream would duplicate
        // every event already in it.
        //
        // Continuity against `existing` — that the new log extends the
        // old one rather than replacing it with a fork — needs the AID,
        // so it is enforced by `verify_continuation` on the write path.
        self.validate(new_data)?;
        Ok(new_data.to_vec())
    }
}

impl Webs {
    /// URL an artifact is published at for a hosted mnemonic.
    ///
    /// `mnemonic` is the stored path form (labels joined with `:`); the
    /// resolution URL uses `/`.
    pub fn artifact_url(domain: &str, mnemonic: &str, artifact: &str) -> String {
        let path = mnemonic.replace(':', "/");
        if path.is_empty() {
            // Not reachable for a well-formed did:webs — the AID is
            // always a path segment — but a caller that hands us an
            // empty mnemonic gets a URL that is wrong rather than one
            // that silently points at another DID's artifact.
            return format!("https://{domain}/{artifact}");
        }
        format!("https://{domain}/{path}/{artifact}")
    }

    /// The `keri.cesr` URL for a hosted mnemonic.
    pub fn keri_cesr_url(domain: &str, mnemonic: &str) -> String {
        Self::artifact_url(domain, mnemonic, KERI_CESR)
    }

    /// Verify a submitted `keri.cesr` against the DID it claims to be,
    /// and return the `did.json` the verified key state implies.
    ///
    /// This is the check that makes the service a *host* rather than a
    /// file server, and it is the `did:webs` counterpart to
    /// `verify_did_log_proofs`. The method crate walks the whole chain:
    /// every event's SAID before any field of it is trusted, the
    /// prior-event digest chain and sequence ordering, controller
    /// signatures, pre-rotation commitments, delegation seals, witness
    /// receipts against the declared threshold, and the designated-
    /// aliases attestation that `alsoKnownAs` comes from.
    ///
    /// `did_json`, when supplied, is cross-checked against the
    /// derivation and a disagreement is rejected. It is **not** stored:
    /// the only document this service may serve is the one it derives.
    ///
    /// # Errors
    /// [`MethodError::Malformed`] if `did` is not a `did:webs`
    /// identifier; [`MethodError::Validation`] if the stream does not
    /// verify, establishes a different AID, or disagrees with a
    /// supplied `did.json`.
    pub fn verify_artifacts(
        did: &str,
        keri_cesr: &[u8],
        did_json: Option<&[u8]>,
    ) -> Result<Vec<u8>, MethodError> {
        let parsed =
            DidWebs::parse(did).map_err(|e| MethodError::Malformed(format!("{did}: {e}")))?;
        let document = resolve_from_artifacts(&parsed, keri_cesr, did_json)
            .map_err(|e| MethodError::Validation(format!("{did}: {e}")))?;
        serde_json::to_vec(&document).map_err(|e| {
            MethodError::Validation(format!("derived document could not be serialized: {e}"))
        })
    }

    /// Derive the `did.json` bytes for a stored stream.
    ///
    /// Read-path counterpart to [`Self::verify_artifacts`]. Re-verifies
    /// rather than trusting storage: the bytes went through
    /// `verify_artifacts` on the way in, so a failure here means the
    /// store is corrupt, and serving an unverified document would be
    /// worse than serving none.
    ///
    /// # Errors
    /// As [`Self::verify_artifacts`].
    pub fn derive_document(did: &str, keri_cesr: &[u8]) -> Result<Vec<u8>, MethodError> {
        Self::verify_artifacts(did, keri_cesr, None)
    }

    /// Reject an update that does not continue the stored key event log.
    ///
    /// A `did:webs` update republishes the entire stream, so nothing in
    /// the bytes themselves stops a controller — or an attacker holding
    /// a superseded key — from publishing a *shorter*, forked log that
    /// verifies perfectly well on its own. The stored log is the record
    /// of what this DID has already said, so the new one may only move
    /// forward from it.
    ///
    /// Two rules, both against the verified key state rather than the
    /// raw bytes (a stream may legitimately be re-serialized, or gain
    /// witness receipts for events it already carried):
    ///
    /// - same AID, and
    /// - the new sequence number is greater than or equal to the old.
    ///
    /// # Errors
    /// [`MethodError::Validation`] if the new stream rewinds the log or
    /// establishes a different AID. An unreadable *existing* stream is
    /// **not** an error — see below.
    pub fn verify_continuation(
        did: &str,
        existing: &[u8],
        new_data: &[u8],
    ) -> Result<(), MethodError> {
        let parsed =
            DidWebs::parse(did).map_err(|e| MethodError::Malformed(format!("{did}: {e}")))?;

        // An existing blob we cannot read is not a reason to refuse the
        // update — it is a reason to want it. Corrupt or pre-migration
        // bytes would otherwise wedge the slot permanently, with no way
        // to publish the good log that fixes it.
        let Ok(old_kels) = Kels::parse(existing) else {
            return Ok(());
        };
        let Ok(old_state) = old_kels.key_state(parsed.aid()) else {
            return Ok(());
        };

        let new_kels = Kels::parse(new_data)
            .map_err(|e| MethodError::Validation(format!("keri.cesr could not be read: {e}")))?;
        let new_state = new_kels
            .key_state(parsed.aid())
            .map_err(|e| MethodError::Validation(format!("key event log did not verify: {e}")))?;

        if new_state.prefix != old_state.prefix {
            return Err(MethodError::Validation(format!(
                "update establishes {} but the hosted log is for {}",
                new_state.prefix, old_state.prefix,
            )));
        }
        if new_state.sn < old_state.sn {
            return Err(MethodError::Validation(format!(
                "update rewinds the key event log: hosted is at sequence {}, update is at {}",
                old_state.sn, new_state.sn,
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `did:webs` artifacts published by the
    /// `hyperledger-labs/did-webs-resolver` reference implementation.
    /// See `tests/fixtures/ATTRIBUTION.md`.
    const KERI: &[u8] = include_bytes!("../../tests/fixtures/ENro7uf0.keri.cesr");
    const PUBLISHED_DID_JSON: &[u8] = include_bytes!("../../tests/fixtures/ENro7uf0.did.json");
    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
    const DID: &str =
        "did:webs:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    #[test]
    fn name_and_metadata() {
        let m = Webs;
        assert_eq!(m.name(), "webs");
        assert_eq!(m.content_type(), "application/did+json");
        assert_eq!(m.data_ext(), "json");
    }

    // ---- parse_identifier ----

    #[test]
    fn parse_identifier_host_and_aid() {
        let p = Webs
            .parse_identifier(&format!("did:webs:example.com:{AID}"))
            .unwrap();
        assert_eq!(p.method, "webs");
        assert_eq!(p.scid.as_deref(), Some(AID));
        assert_eq!(p.domain, "example.com");
        // The AID is the mnemonic — it is the last path segment.
        assert_eq!(p.path, AID);
    }

    #[test]
    fn parse_identifier_with_path_segments() {
        let p = Webs
            .parse_identifier(&format!("did:webs:example.com:tenants:acme:{AID}"))
            .unwrap();
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.path, format!("tenants:acme:{AID}"));
    }

    #[test]
    fn parse_identifier_keeps_port_percent_encoded() {
        // `DidWebs::host()` decodes `%3a` to `:`. The domain allowlist
        // is keyed on the encoded form, so this must NOT decode.
        let p = Webs.parse_identifier(DID).unwrap();
        assert_eq!(p.domain, "did-webs-service%3a7676");
        assert_eq!(p.path, AID);
    }

    #[test]
    fn parse_identifier_strips_query_and_fragment() {
        let p = Webs
            .parse_identifier(&format!("did:webs:example.com:{AID}#key-1"))
            .unwrap();
        assert_eq!(p.path, AID);
    }

    #[test]
    fn parse_identifier_rejects_wrong_method() {
        let err = Webs
            .parse_identifier("did:web:example.com:user1")
            .expect_err("did:web must reject");
        assert!(matches!(
            err,
            MethodError::MethodMismatch {
                expected: "webs",
                ..
            }
        ));
    }

    #[test]
    fn parse_identifier_rejects_host_only() {
        // No AID label — did:webs always has a trailing AID.
        assert!(Webs.parse_identifier("did:webs:example.com").is_err());
    }

    #[test]
    fn parse_identifier_rejects_a_last_label_outside_the_cesr_alphabet() {
        // The AID check at parse time is syntactic: base64url alphabet
        // and long enough to be a CESR primitive.
        assert!(
            Webs.parse_identifier("did:webs:example.com:not/an/aid")
                .is_err()
        );
        assert!(Webs.parse_identifier("did:webs:example.com:ab").is_err());
    }

    #[test]
    fn parse_identifier_accepts_a_plausible_but_bogus_aid() {
        // `user1` is in the base64url alphabet and long enough, so it
        // parses. Nothing is wrong with that: whether a label really is
        // *this DID's* AID cannot be known without the key event log,
        // and that binding is checked in `verify_artifacts`. Asserting
        // it here documents that parsing is not the security boundary.
        let p = Webs
            .parse_identifier("did:webs:example.com:user1")
            .expect("syntactically valid");
        assert_eq!(p.scid.as_deref(), Some("user1"));

        let err = Webs::verify_artifacts("did:webs:example.com:user1", KERI, None)
            .expect_err("no key event log establishes `user1`");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    #[test]
    fn parse_identifier_rejects_empty_label() {
        assert!(
            Webs.parse_identifier(&format!("did:webs:example.com::{AID}"))
                .is_err()
        );
    }

    // ---- resolution_url / artifact_url ----

    #[test]
    fn resolution_url_puts_aid_last() {
        let url = Webs.resolution_url("example.com", AID);
        assert_eq!(url, format!("https://example.com/{AID}/did.json"));
    }

    #[test]
    fn resolution_url_converts_colons_to_slashes() {
        let url = Webs.resolution_url("example.com", &format!("tenants:acme:{AID}"));
        assert_eq!(
            url,
            format!("https://example.com/tenants/acme/{AID}/did.json")
        );
    }

    #[test]
    fn keri_cesr_url_sits_beside_the_document() {
        assert_eq!(
            Webs::keri_cesr_url("example.com", AID),
            format!("https://example.com/{AID}/keri.cesr")
        );
    }

    // ---- validate ----

    #[test]
    fn validate_accepts_the_reference_stream() {
        Webs.validate(KERI).expect("reference keri.cesr must parse");
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(Webs.validate(b"").is_err());
        assert!(Webs.validate(b"   \n").is_err());
    }

    #[test]
    fn validate_rejects_a_webvh_log_line() {
        // Regression guard. The CESR parser reads a bare JSON object as
        // a message, so this *parses* — only the missing inception
        // event tells the two methods apart. Without that check a webvh
        // log would be accepted as a did:webs publication and then fail
        // to resolve, and `detect_method` would route it to the wrong
        // verifier.
        let err = Webs
            .validate(br#"{"versionId":"1-abc","versionTime":"2025-01-01T00:00:00Z"}"#)
            .expect_err("a webvh log line is not a key event log");
        assert!(matches!(err, MethodError::Validation(_)));
        assert!(err.to_string().contains("inception"));
    }

    #[test]
    fn validate_rejects_a_stream_with_events_but_no_inception() {
        // Drop the inception event, keeping the rest of the stream.
        let first_ixn = KERI
            .windows(4)
            .skip(1)
            .position(|w| w == br#"{"v""#)
            .map(|p| p + 1)
            .expect("stream has more than one message");
        let err = Webs
            .validate(&KERI[first_ixn..])
            .expect_err("a KEL without its inception is not a KEL");
        assert!(err.to_string().contains("inception"));
    }

    // ---- verify_artifacts ----

    #[test]
    fn verify_artifacts_derives_the_document() {
        let doc = Webs::verify_artifacts(DID, KERI, None).expect("reference artifacts verify");
        let v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        assert_eq!(v["id"].as_str(), Some(DID));

        // One verification method, carrying the KEL's current signing key.
        let vms = v["verificationMethod"].as_array().expect("vm array");
        assert_eq!(vms.len(), 1);
        assert_eq!(
            vms[0]["publicKeyJwk"]["kid"].as_str(),
            Some("DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr"),
        );
    }

    #[test]
    fn verify_artifacts_derives_also_known_as_from_the_attestation() {
        let doc = Webs::verify_artifacts(DID, KERI, None).expect("verify");
        let v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        let aka: Vec<&str> = v["alsoKnownAs"]
            .as_array()
            .expect("alsoKnownAs")
            .iter()
            .filter_map(|a| a.as_str())
            .collect();

        // The did:web twin always holds, without anything attesting it.
        assert!(
            aka.contains(
                &"did:web:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe"
            ),
            "twin missing from {aka:?}",
        );
        // The rest come from the designated-aliases attestation, whose
        // whole chain (registry inception, issuance, signature, and
        // non-revocation) had to verify.
        assert!(
            aka.iter().any(|a| a.ends_with(&format!("foo.com:{AID}"))),
            "attested alias missing from {aka:?}",
        );
    }

    #[test]
    fn verify_artifacts_accepts_the_published_document() {
        // The reference `did.json` names the did:web twin as its `id`,
        // which the method crate accepts as naming this identifier.
        Webs::verify_artifacts(DID, KERI, Some(PUBLISHED_DID_JSON))
            .expect("published did.json agrees with the derivation");
    }

    #[test]
    fn verify_artifacts_rejects_a_document_publishing_other_keys() {
        let mut published: serde_json::Value = serde_json::from_slice(PUBLISHED_DID_JSON).unwrap();
        published["verificationMethod"][0]["publicKeyJwk"]["kid"] =
            serde_json::json!("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let bytes = serde_json::to_vec(&published).unwrap();

        let err = Webs::verify_artifacts(DID, KERI, Some(&bytes))
            .expect_err("a document publishing keys the KEL never authorised must be rejected");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    #[test]
    fn verify_artifacts_rejects_a_stream_for_another_aid() {
        let other = format!("did:webs:example.com:E{}", "A".repeat(43));
        let err = Webs::verify_artifacts(&other, KERI, None)
            .expect_err("the KEL establishes a different AID");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    #[test]
    fn verify_artifacts_rejects_a_tampered_stream() {
        // Flip a byte inside the inception event; its SAID no longer
        // matches, so nothing in it may be trusted.
        let mut tampered = KERI.to_vec();
        let pos = tampered
            .windows(3)
            .position(|w| w == b"\"s\"")
            .expect("inception has an `s` field");
        tampered[pos + 5] = b'9';

        let err = Webs::verify_artifacts(DID, &tampered, None)
            .expect_err("a tampered key event log must not resolve");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    #[test]
    fn verify_artifacts_rejects_a_non_webs_did() {
        let err = Webs::verify_artifacts("did:web:example.com:user1", KERI, None)
            .expect_err("must reject");
        assert!(matches!(err, MethodError::Malformed(_)));
    }

    // ---- derive_document ----

    #[test]
    fn derive_document_matches_verify_artifacts() {
        let a = Webs::derive_document(DID, KERI).unwrap();
        let b = Webs::verify_artifacts(DID, KERI, None).unwrap();
        assert_eq!(a, b, "derivation must be deterministic");
    }

    // ---- apply_update / verify_continuation ----

    #[test]
    fn apply_update_replaces_rather_than_appends() {
        let out = Webs
            .apply_update(Some(KERI), KERI)
            .expect("republishing the same stream is valid");
        assert_eq!(out, KERI, "the stream is replaced, not doubled");
    }

    #[test]
    fn apply_update_rejects_an_unreadable_stream() {
        assert!(Webs.apply_update(Some(KERI), b"not a cesr stream").is_err());
    }

    #[test]
    fn verify_continuation_accepts_the_same_log() {
        Webs::verify_continuation(DID, KERI, KERI).expect("republishing the same log is a no-op");
    }

    #[test]
    fn verify_continuation_tolerates_an_unreadable_stored_log() {
        // A corrupt slot must be fixable by publishing a good log, not
        // wedged forever.
        Webs::verify_continuation(DID, b"corrupt", KERI)
            .expect("an unreadable stored log must not block the update that repairs it");
    }

    #[test]
    fn verify_continuation_rejects_an_unreadable_update() {
        assert!(Webs::verify_continuation(DID, KERI, b"not cesr").is_err());
    }

    #[test]
    fn verify_continuation_rejects_a_rewind() {
        // Truncate the stream to the inception event alone: a log that
        // verifies on its own but sits at sequence 0, behind the stored
        // one at sequence 2.
        let text = KERI;
        let second_event = text
            .windows(4)
            .skip(1)
            .position(|w| w == br#"{"v""#)
            .map(|p| p + 1)
            .expect("stream has more than one message");
        let truncated = &text[..second_event];

        // Sanity: the truncated prefix is still a valid one-event KEL.
        Webs.validate(truncated)
            .expect("the inception event alone is a readable stream");

        let err = Webs::verify_continuation(DID, KERI, truncated)
            .expect_err("an update may not rewind the key event log");
        assert!(matches!(err, MethodError::Validation(_)));
        assert!(err.to_string().contains("rewinds"));
    }
}

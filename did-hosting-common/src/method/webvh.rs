//! `did:webvh` implementation of [`DidMethod`].
//!
//! Per `docs/multi-method-hosting-spec.md` §6.1. Wraps the existing
//! webvh-specific helpers (`crate::did::encode_host`, the log-validation
//! chain in `crate::did_ops`) behind the method-agnostic trait so the
//! dispatcher in `super::method_by_name` can route to webvh through the
//! same shape it'll use for `did:web`, `did:webs`, etc.
//!
//! ## Identifier shape
//!
//! `did:webvh:{SCID}:{host}:{path-segment}[:{path-segment}…]`
//!
//! Colons inside the path become slashes in the resolution URL.
//! `{host}` may carry a non-default port encoded as `%3A` (URL-encoded
//! colon) — kept as-is in the parsed `domain` field for round-trip.
//!
//! ## Document shape
//!
//! `did.jsonl` — one JSON object per line. Each line is a signed log
//! entry recording a change to the DID document. `validate` parses each
//! line as JSON (the deeper webvh-spec validation lives in
//! `crate::did_ops::validate_jsonl` and is wired in via the
//! soon-to-land `did_ops` refactor; T11 ships the parser-level
//! validation only).
//!
//! ## `apply_update`
//!
//! Append-only: the new line is concatenated to the existing bytes,
//! ensuring a `\n` separator. Validation of the chain (signatures,
//! version IDs) is the caller's responsibility before calling — same
//! contract the existing publish-handler honours today.

#![cfg(feature = "method-webvh")]

use super::{DidMethod, MethodError, ParsedDid};

/// Zero-size unit struct — the trait impl carries all the behaviour.
pub struct Webvh;

impl DidMethod for Webvh {
    fn name(&self) -> &'static str {
        "webvh"
    }

    fn content_type(&self) -> &'static str {
        // RFC 8259 (`application/jsonl` is the spec-aligned MIME for
        // line-delimited JSON; some servers emit `application/x-jsonl`
        // — we standardise on the canonical form).
        "application/jsonl"
    }

    fn data_ext(&self) -> &'static str {
        "jsonl"
    }

    fn parse_identifier(&self, did: &str) -> Result<ParsedDid, MethodError> {
        let rest = did
            .strip_prefix("did:webvh:")
            .ok_or_else(|| MethodError::MethodMismatch {
                expected: "webvh",
                found: super::parse_did_method(did)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "<malformed>".into()),
            })?;

        // `did:webvh:{SCID}:{host}:{path-segments...}`
        let mut iter = rest.splitn(3, ':');
        let scid = iter
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| MethodError::Malformed(did.to_string()))?
            .to_string();
        let domain = iter
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| MethodError::Malformed(did.to_string()))?
            .to_string();
        // Path is optional — `did:webvh:SCID:host` (no path) resolves
        // at the host's root via `/.well-known/did.jsonl`, mirrored
        // here as `path: ""`.
        let path = iter.next().unwrap_or("").to_string();

        Ok(ParsedDid {
            method: "webvh",
            scid: Some(scid),
            domain,
            path,
        })
    }

    fn resolution_url(&self, domain: &str, mnemonic: &str) -> String {
        // Path is the multi-segment portion of the identifier with `:`
        // converted to `/`. Empty mnemonic → the well-known location
        // (per `did:webvh` spec for the no-path case).
        if mnemonic.is_empty() || mnemonic == ".well-known" {
            format!("https://{domain}/.well-known/did.jsonl")
        } else {
            let path = mnemonic.replace(':', "/");
            format!("https://{domain}/{path}/did.jsonl")
        }
    }

    fn validate(&self, data: &[u8]) -> Result<(), MethodError> {
        // Trait-level validation is line-syntactic only: every non-blank
        // line must parse as a JSON object. The deeper webvh-spec chain
        // validation (SCID continuity, version-ID monotonicity, witness
        // signatures) runs in `crate::did_ops::validate_jsonl` and is
        // called from the existing publish path. This trait method runs
        // first and gives a cheap, transport-layer rejection for
        // obviously-malformed payloads.
        let text = std::str::from_utf8(data).map_err(|e| {
            MethodError::Validation(format!("did.jsonl is not valid UTF-8: {e}"))
        })?;
        for (idx, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            serde_json::from_str::<serde_json::Value>(line).map_err(|e| {
                MethodError::Validation(format!("did.jsonl line {} is not valid JSON: {e}", idx + 1))
            })?;
        }
        Ok(())
    }

    fn apply_update(
        &self,
        existing: Option<&[u8]>,
        new_data: &[u8],
    ) -> Result<Vec<u8>, MethodError> {
        // Append-only: validation of the chain (signatures, version IDs)
        // is the caller's job before calling — same as today.
        let mut out = existing.map(|b| b.to_vec()).unwrap_or_default();
        // Ensure the existing buffer ends in a newline so the new line
        // appends cleanly. If the buffer is empty this is a no-op; if
        // it already ends in `\n` we don't add a second.
        if !out.is_empty() && !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(new_data);
        // Validate the line-syntactic shape of the new bytes before
        // returning. A caller-supplied empty `new_data` is rejected —
        // an empty update is never meaningful for webvh.
        if new_data.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(MethodError::Validation(
                "webvh apply_update: new_data is empty / whitespace-only".into(),
            ));
        }
        self.validate(new_data)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_metadata() {
        let m = Webvh;
        assert_eq!(m.name(), "webvh");
        assert_eq!(m.content_type(), "application/jsonl");
        assert_eq!(m.data_ext(), "jsonl");
    }

    #[test]
    fn parse_identifier_simple_path() {
        let p = Webvh
            .parse_identifier("did:webvh:QmABC:example.com:my-did")
            .unwrap();
        assert_eq!(p.method, "webvh");
        assert_eq!(p.scid.as_deref(), Some("QmABC"));
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.path, "my-did");
    }

    #[test]
    fn parse_identifier_deep_path() {
        let p = Webvh
            .parse_identifier("did:webvh:QmABC:example.com:people:staff:glenn")
            .unwrap();
        assert_eq!(p.scid.as_deref(), Some("QmABC"));
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.path, "people:staff:glenn");
    }

    #[test]
    fn parse_identifier_no_path() {
        let p = Webvh
            .parse_identifier("did:webvh:QmABC:example.com")
            .unwrap();
        assert_eq!(p.scid.as_deref(), Some("QmABC"));
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.path, "");
    }

    #[test]
    fn parse_identifier_host_with_port() {
        // The webvh spec URL-encodes the colon between host and port as
        // %3A. The encoded form stays in `domain` for round-trip.
        let p = Webvh
            .parse_identifier("did:webvh:QmABC:example.com%3A8085:user1")
            .unwrap();
        assert_eq!(p.domain, "example.com%3A8085");
        assert_eq!(p.path, "user1");
    }

    #[test]
    fn parse_identifier_rejects_wrong_method() {
        let err = Webvh
            .parse_identifier("did:web:example.com:user1")
            .expect_err("did:web must reject");
        assert!(matches!(
            err,
            MethodError::MethodMismatch {
                expected: "webvh",
                ..
            }
        ));
    }

    #[test]
    fn parse_identifier_rejects_missing_scid() {
        assert!(Webvh.parse_identifier("did:webvh::example.com:user").is_err());
    }

    #[test]
    fn parse_identifier_rejects_missing_domain() {
        // Two colons but only SCID, no host — `did:webvh:QmABC:` with
        // empty domain.
        assert!(Webvh.parse_identifier("did:webvh:QmABC:").is_err());
    }

    #[test]
    fn resolution_url_with_path() {
        let url = Webvh.resolution_url("example.com", "user1");
        assert_eq!(url, "https://example.com/user1/did.jsonl");
    }

    #[test]
    fn resolution_url_deep_path_converts_colons_to_slashes() {
        let url = Webvh.resolution_url("example.com", "people:staff:glenn");
        assert_eq!(url, "https://example.com/people/staff/glenn/did.jsonl");
    }

    #[test]
    fn resolution_url_empty_mnemonic_goes_to_well_known() {
        let url = Webvh.resolution_url("example.com", "");
        assert_eq!(url, "https://example.com/.well-known/did.jsonl");
    }

    #[test]
    fn resolution_url_well_known_mnemonic_explicit() {
        // The setup wizard creates the daemon's DID with mnemonic
        // ".well-known" — same logical location as empty mnemonic.
        let url = Webvh.resolution_url("example.com", ".well-known");
        assert_eq!(url, "https://example.com/.well-known/did.jsonl");
    }

    #[test]
    fn validate_accepts_single_log_entry() {
        let data = br#"{"versionId":"1","versionTime":"2025-01-01T00:00:00Z"}"#;
        assert!(Webvh.validate(data).is_ok());
    }

    #[test]
    fn validate_accepts_multi_line_jsonl() {
        let data = b"{\"versionId\":\"1\"}\n{\"versionId\":\"2\"}\n";
        assert!(Webvh.validate(data).is_ok());
    }

    #[test]
    fn validate_tolerates_trailing_newline() {
        let data = b"{\"versionId\":\"1\"}\n";
        assert!(Webvh.validate(data).is_ok());
    }

    #[test]
    fn validate_rejects_bad_json() {
        let data = b"{not json}\n";
        let err = Webvh.validate(data).expect_err("must reject malformed JSON");
        assert!(matches!(err, MethodError::Validation(_)));
        assert!(err.to_string().contains("line 1"));
    }

    #[test]
    fn validate_rejects_bad_json_at_line_2() {
        let data = b"{\"versionId\":\"1\"}\n{not json}\n";
        let err = Webvh.validate(data).expect_err("must reject malformed line 2");
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn validate_rejects_non_utf8() {
        let data = b"\xff\xfe not utf-8";
        let err = Webvh.validate(data).expect_err("must reject non-UTF-8");
        assert!(err.to_string().contains("UTF-8"));
    }

    #[test]
    fn apply_update_appends_new_line() {
        let existing = b"{\"versionId\":\"1\"}\n";
        let new_data = b"{\"versionId\":\"2\"}\n";
        let out = Webvh.apply_update(Some(existing), new_data).unwrap();
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "{\"versionId\":\"1\"}\n{\"versionId\":\"2\"}\n"
        );
    }

    #[test]
    fn apply_update_to_empty_existing() {
        let out = Webvh
            .apply_update(None, b"{\"versionId\":\"1\"}\n")
            .unwrap();
        assert_eq!(out, b"{\"versionId\":\"1\"}\n");
    }

    #[test]
    fn apply_update_adds_missing_newline_separator() {
        // Existing buffer doesn't end in `\n` — apply_update must insert
        // one before appending so the result is still valid jsonl.
        let existing = b"{\"versionId\":\"1\"}";
        let new_data = b"{\"versionId\":\"2\"}";
        let out = Webvh.apply_update(Some(existing), new_data).unwrap();
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "{\"versionId\":\"1\"}\n{\"versionId\":\"2\"}"
        );
    }

    #[test]
    fn apply_update_rejects_empty_new_data() {
        assert!(Webvh.apply_update(None, b"").is_err());
        assert!(Webvh.apply_update(None, b"   \n").is_err());
    }

    #[test]
    fn apply_update_rejects_malformed_new_line() {
        let err = Webvh
            .apply_update(None, b"{not json}\n")
            .expect_err("must reject malformed update");
        assert!(matches!(err, MethodError::Validation(_)));
    }
}

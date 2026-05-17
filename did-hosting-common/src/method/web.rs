//! `did:web` implementation of [`DidMethod`].
//!
//! Per `docs/multi-method-hosting-spec.md` §6.1. Second method shipped
//! in this release alongside [`super::webvh`]; both are
//! default-enabled.
//!
//! ## Identifier shape
//!
//! `did:web:{domain}[:{path-segment}[:{path-segment}…]]`
//!
//! - `{domain}` is the hostname (optionally `host%3Aport` for non-
//!   default ports, per the did:web spec's URL-encoding rule).
//! - Path is optional. `did:web:example.com` is the **no-path** form
//!   and resolves at `/.well-known/did.json` on the domain.
//! - Multi-segment paths join with `:` in the identifier and `/` in
//!   the resolution URL — same convention as did:webvh.
//!
//! ## Document shape
//!
//! Single JSON object — no log, no append-only history. Updates
//! overwrite outright; `apply_update` ignores `existing` and returns
//! the new bytes after validation.
//!
//! `validate` asserts the document parses as JSON, has an `id`
//! field, and that the `id` matches a `did:web:…` identifier shape.
//! (Deeper structural checks — service endpoints, verification
//! methods — are out of scope for this trait method; they're the
//! caller's responsibility if needed.)
//!
//! ## `__root` mnemonic
//!
//! Storage keys are mnemonics (the path portion of the DID, with `:`
//! replaced by `/`). A did:web with no path has an empty mnemonic;
//! that's not a valid storage key, so we substitute the literal
//! sentinel `__root`. The resolution-URL builder maps `__root` back
//! to `/.well-known/did.json` on the domain.

#![cfg(feature = "method-web")]

use super::{DidMethod, MethodError, ParsedDid};

/// Sentinel mnemonic for the no-path did:web case
/// (`did:web:example.com`). See module docs.
pub const ROOT_MNEMONIC: &str = "__root";

/// Zero-size unit struct — the trait impl carries all behaviour.
pub struct Web;

impl DidMethod for Web {
    fn name(&self) -> &'static str {
        "web"
    }

    fn content_type(&self) -> &'static str {
        // RFC-aligned MIME for DID documents. Plain `application/json`
        // also works in practice but `application/did+json` is the
        // canonical form per the DID Core spec.
        "application/did+json"
    }

    fn data_ext(&self) -> &'static str {
        "json"
    }

    fn parse_identifier(&self, did: &str) -> Result<ParsedDid, MethodError> {
        let rest = did
            .strip_prefix("did:web:")
            .ok_or_else(|| MethodError::MethodMismatch {
                expected: "web",
                found: super::parse_did_method(did)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "<malformed>".into()),
            })?;

        // `did:web:{domain}[:{path-segments...}]`
        let mut iter = rest.splitn(2, ':');
        let domain = iter
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| MethodError::Malformed(did.to_string()))?
            .to_string();
        // Path is optional. `did:web:example.com` (no path) is a
        // valid identifier and resolves at `/.well-known/did.json`.
        let path = iter.next().unwrap_or("").to_string();

        Ok(ParsedDid {
            method: "web",
            scid: None, // did:web has no SCID.
            domain,
            path,
        })
    }

    fn resolution_url(&self, domain: &str, mnemonic: &str) -> String {
        // Empty mnemonic == `__root`; both resolve at `/.well-known/did.json`.
        if mnemonic.is_empty() || mnemonic == ROOT_MNEMONIC {
            return format!("https://{domain}/.well-known/did.json");
        }
        let path = mnemonic.replace(':', "/");
        format!("https://{domain}/{path}/did.json")
    }

    fn validate(&self, data: &[u8]) -> Result<(), MethodError> {
        let v: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| MethodError::Validation(format!("did.json is not valid JSON: {e}")))?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| MethodError::Validation("did.json missing `id` field".into()))?;
        if !id.starts_with("did:web:") {
            return Err(MethodError::Validation(format!(
                "did.json `id` is not a did:web identifier: '{id}'"
            )));
        }
        // Tighter check: `id` must validate as a parseable did:web
        // identifier via our own parser. Catches malformed segments.
        Self.parse_identifier(id)?;
        Ok(())
    }

    fn apply_update(
        &self,
        _existing: Option<&[u8]>,
        new_data: &[u8],
    ) -> Result<Vec<u8>, MethodError> {
        // did:web is overwrite-only — there's no log to append to.
        // The caller has validated authorisation upstream; we just
        // do shape validation and return the new bytes.
        if new_data.is_empty() {
            return Err(MethodError::Validation(
                "web apply_update: new_data must not be empty".into(),
            ));
        }
        self.validate(new_data)?;
        Ok(new_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_metadata() {
        let m = Web;
        assert_eq!(m.name(), "web");
        assert_eq!(m.content_type(), "application/did+json");
        assert_eq!(m.data_ext(), "json");
    }

    // ---- parse_identifier ----

    #[test]
    fn parse_identifier_simple() {
        let p = Web.parse_identifier("did:web:example.com").unwrap();
        assert_eq!(p.method, "web");
        assert_eq!(p.scid, None);
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.path, "");
    }

    #[test]
    fn parse_identifier_with_path() {
        let p = Web.parse_identifier("did:web:example.com:user1").unwrap();
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.path, "user1");
    }

    #[test]
    fn parse_identifier_deep_path() {
        let p = Web
            .parse_identifier("did:web:example.com:tenants:acme:alice")
            .unwrap();
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.path, "tenants:acme:alice");
    }

    #[test]
    fn parse_identifier_host_with_port_encoded() {
        let p = Web
            .parse_identifier("did:web:example.com%3A8443:user1")
            .unwrap();
        assert_eq!(p.domain, "example.com%3A8443");
        assert_eq!(p.path, "user1");
    }

    #[test]
    fn parse_identifier_rejects_wrong_method() {
        let err = Web
            .parse_identifier("did:webvh:Q1:example.com:user1")
            .expect_err("did:webvh must reject");
        assert!(matches!(
            err,
            MethodError::MethodMismatch {
                expected: "web",
                ..
            }
        ));
    }

    #[test]
    fn parse_identifier_rejects_missing_domain() {
        // `did:web:` is malformed — no domain.
        assert!(Web.parse_identifier("did:web:").is_err());
    }

    // ---- resolution_url ----

    #[test]
    fn resolution_url_root_via_well_known_for_empty_mnemonic() {
        let url = Web.resolution_url("example.com", "");
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn resolution_url_root_via_well_known_for_root_sentinel() {
        let url = Web.resolution_url("example.com", ROOT_MNEMONIC);
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn resolution_url_simple_path() {
        let url = Web.resolution_url("example.com", "user1");
        assert_eq!(url, "https://example.com/user1/did.json");
    }

    #[test]
    fn resolution_url_deep_path_converts_colons_to_slashes() {
        let url = Web.resolution_url("example.com", "tenants:acme:alice");
        assert_eq!(url, "https://example.com/tenants/acme/alice/did.json");
    }

    // ---- validate ----

    #[test]
    fn validate_accepts_minimal_doc() {
        let data = br#"{"id":"did:web:example.com"}"#;
        assert!(Web.validate(data).is_ok());
    }

    #[test]
    fn validate_accepts_realistic_doc() {
        let data = br#"{
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com:tenants:acme",
            "verificationMethod": [],
            "service": []
        }"#;
        assert!(Web.validate(data).is_ok());
    }

    #[test]
    fn validate_rejects_non_json() {
        let err = Web.validate(b"not json").expect_err("must reject");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    #[test]
    fn validate_rejects_missing_id() {
        let err = Web.validate(br#"{"foo":"bar"}"#).expect_err("must reject");
        assert!(matches!(err, MethodError::Validation(_)));
        assert!(err.to_string().contains("missing `id` field"));
    }

    #[test]
    fn validate_rejects_id_with_wrong_method() {
        let err = Web
            .validate(br#"{"id":"did:webvh:Q1:example.com"}"#)
            .expect_err("must reject");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    #[test]
    fn validate_rejects_id_with_non_did_value() {
        let err = Web
            .validate(br#"{"id":"https://example.com"}"#)
            .expect_err("must reject");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    // ---- apply_update ----

    #[test]
    fn apply_update_overwrites_returns_new_bytes() {
        let existing = br#"{"id":"did:web:example.com","version":1}"#;
        let new_data = br#"{"id":"did:web:example.com","version":2}"#;
        let out = Web
            .apply_update(Some(existing.as_slice()), new_data)
            .unwrap();
        assert_eq!(out, new_data);
    }

    #[test]
    fn apply_update_ignores_existing_overwrite_semantics() {
        // Existing is gibberish (not even valid JSON) but apply_update
        // doesn't validate `existing` — only `new_data`. Confirms
        // overwrite semantics.
        let existing = b"GIBBERISH";
        let new_data = br#"{"id":"did:web:example.com"}"#;
        let out = Web
            .apply_update(Some(existing.as_slice()), new_data)
            .unwrap();
        assert_eq!(out, new_data);
    }

    #[test]
    fn apply_update_to_empty_existing() {
        let new_data = br#"{"id":"did:web:example.com"}"#;
        let out = Web.apply_update(None, new_data).unwrap();
        assert_eq!(out, new_data);
    }

    #[test]
    fn apply_update_rejects_empty_new_data() {
        assert!(Web.apply_update(None, b"").is_err());
    }

    #[test]
    fn apply_update_rejects_malformed_new_data() {
        let err = Web
            .apply_update(None, b"not json")
            .expect_err("must reject");
        assert!(matches!(err, MethodError::Validation(_)));
    }

    #[test]
    fn apply_update_rejects_missing_id() {
        let err = Web
            .apply_update(None, br#"{"foo":"bar"}"#)
            .expect_err("must reject");
        assert!(matches!(err, MethodError::Validation(_)));
    }
}

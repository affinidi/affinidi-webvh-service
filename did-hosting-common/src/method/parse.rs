//! Shared parsing helpers — bits of work that don't fit cleanly inside
//! one method's impl.
//!
//! Today this is just [`parse_did_method`] (extract the method name
//! from a `did:{method}:...` identifier). When the dispatcher in
//! `super::method_by_name` needs to route an inbound identifier to its
//! impl, it calls this first to get the name, then looks up the impl.

use super::MethodError;

/// Extract the method name from a DID identifier.
///
/// Returns `Ok("webvh")` for `"did:webvh:..."`, `Ok("web")` for
/// `"did:web:..."`, etc. Returns `Err(MethodError::Malformed)` if the
/// input doesn't start with `did:` or has an empty method segment.
///
/// The returned `&str` borrows from `did` — callers that need a static
/// method name resolve via [`super::method_by_name`] afterwards. Cheap
/// either way; the lookup is a single match.
pub fn parse_did_method(did: &str) -> Result<&str, MethodError> {
    // Per the DID-core spec: `did:` followed by a non-empty method-name
    // followed by `:` followed by the method-specific identifier.
    let after_did = did
        .strip_prefix("did:")
        .ok_or_else(|| MethodError::Malformed(did.to_string()))?;
    let (method, rest) = after_did
        .split_once(':')
        .ok_or_else(|| MethodError::Malformed(did.to_string()))?;
    if method.is_empty() || rest.is_empty() {
        return Err(MethodError::Malformed(did.to_string()));
    }
    // Method names per DID-core grammar are lowercase alphanumeric.
    // A future caller might pass garbage; reject early.
    if !method.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return Err(MethodError::Malformed(did.to_string()));
    }
    Ok(method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_webvh_method() {
        let m = parse_did_method("did:webvh:Q1Hh3jBb2:example.com:tenant:user1").unwrap();
        assert_eq!(m, "webvh");
    }

    #[test]
    fn extracts_web_method() {
        let m = parse_did_method("did:web:example.com:tenant:user1").unwrap();
        assert_eq!(m, "web");
    }

    #[test]
    fn extracts_web_method_no_path() {
        let m = parse_did_method("did:web:example.com").unwrap();
        assert_eq!(m, "web");
    }

    #[test]
    fn rejects_missing_did_prefix() {
        assert!(parse_did_method("webvh:Q1:example.com").is_err());
        assert!(parse_did_method("Q1:example.com").is_err());
        assert!(parse_did_method("").is_err());
    }

    #[test]
    fn rejects_missing_method_or_body() {
        // `did:` alone — no method
        assert!(parse_did_method("did:").is_err());
        // `did::body` — empty method
        assert!(parse_did_method("did::body").is_err());
        // `did:webvh:` — empty body
        assert!(parse_did_method("did:webvh:").is_err());
        // `did:webvh` — no body separator at all
        assert!(parse_did_method("did:webvh").is_err());
    }

    #[test]
    fn rejects_uppercase_or_punctuation_in_method() {
        assert!(parse_did_method("did:WebVH:Q1:host").is_err());
        assert!(parse_did_method("did:web-vh:Q1:host").is_err());
        assert!(parse_did_method("did:web_vh:Q1:host").is_err());
    }

    #[test]
    fn accepts_alphanumeric_method_name() {
        // DID-core allows digits in method names (per the grammar);
        // the future `did:webs2` or similar should parse.
        assert_eq!(parse_did_method("did:webs2:host:path").unwrap(), "webs2");
    }
}

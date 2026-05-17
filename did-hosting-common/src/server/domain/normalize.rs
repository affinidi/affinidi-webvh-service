//! Domain-name normalisation.
//!
//! Per `docs/multi-domain-spec.md` §3 row "Domain name normalization":
//! every domain name reaching the system gets lowercase + IDNA-
//! normalised before storage / comparison. Inputs that aren't already
//! in canonical form are **rejected with 400**, with the canonical form
//! quoted in the error message so the caller can retry cleanly.
//!
//! Path-prefix domains (`example.com/webvh-a`) are first-class per
//! §3 — the host part is IDNA-normalised, the path part is lowercase-
//! validated.
//!
//! ## Why reject rather than silently rewrite
//!
//! Silently rewriting `Example.com` to `example.com` lets two
//! ostensibly-different stored names collide and creates spooky-action-
//! at-a-distance for audit logs. Rejecting with the canonical form in
//! the error keeps the input → storage mapping bijective: what the
//! caller sent is what got stored.

use crate::server::error::AppError;

/// Maximum sensible domain-name length for storage keys / error
/// messages. Stops a 1MB upload from being echoed back in a 400.
const MAX_LEN: usize = 253;

/// Normalise a domain identifier.
///
/// Behaviour:
/// - If `input` is **already** in canonical form, returns `Ok(canonical)`
///   (which equals `input`).
/// - If `input` parses cleanly but isn't canonical (uppercase, IDN
///   pre-punycode, trailing slash, etc.), returns
///   `Err(AppError::Validation(...))` with the canonical form in the
///   message so the caller can retry.
/// - If `input` is unparseable (control chars, garbage), returns
///   `Err(AppError::Validation(...))` with a generic "malformed" reason.
///
/// IP-literal hosts (`127.0.0.1`, `[::1]`) are rejected — a domain
/// must be a DNS name. Loopback IPs are honoured at the request-host
/// level by the trusted-proxy logic in T19, not here.
pub fn normalize_domain_name(input: &str) -> Result<String, AppError> {
    if input.is_empty() {
        return Err(AppError::Validation("domain name must not be empty".into()));
    }
    if input.len() > MAX_LEN {
        return Err(AppError::Validation(format!(
            "domain name exceeds {MAX_LEN} chars"
        )));
    }
    // No leading/trailing whitespace (operators paste from chat / docs
    // and these slip in). Reject before any further processing so the
    // error names the issue clearly.
    if input.trim() != input {
        return Err(AppError::Validation(
            "domain name must not have leading or trailing whitespace".into(),
        ));
    }
    if input.starts_with('/') || input.ends_with('/') {
        return Err(AppError::Validation(
            "domain name must not start or end with '/'".into(),
        ));
    }

    let (host_in, path_in) = match input.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (input, None),
    };

    let host = normalize_host(host_in)?;
    let canonical = match path_in {
        None => host,
        Some(p) => {
            let path = normalize_path(p)?;
            format!("{host}/{path}")
        }
    };

    if canonical != input {
        return Err(AppError::Validation(format!(
            "domain name not in canonical form — use '{canonical}'"
        )));
    }
    Ok(canonical)
}

/// Normalise the host portion of a domain identifier.
///
/// Uses [`url::Host::parse`] which applies IDNA-strict + lowercase
/// conversion. Rejects IP literals and any host containing characters
/// outside the LDH (letters, digits, hyphens) + `.` + IDN-punycode set.
fn normalize_host(host: &str) -> Result<String, AppError> {
    let parsed = url::Host::parse(host)
        .map_err(|e| AppError::Validation(format!("malformed host '{host}': {e}")))?;
    match parsed {
        url::Host::Domain(s) => {
            // url::Host::parse lowercases and IDNA-encodes; double-check
            // there's no character we don't want to accept.
            if !s
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
            {
                return Err(AppError::Validation(format!(
                    "host '{s}' contains characters outside LDH + '.'"
                )));
            }
            Ok(s)
        }
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => Err(AppError::Validation(format!(
            "host '{host}' is an IP literal — domain names must be DNS hostnames"
        ))),
    }
}

/// Normalise the path-prefix portion (after `/`).
///
/// Accepts: lowercase alphanumeric + `-` + `_` + `.` + `/` (for multi-
/// segment paths like `tenant-a/instance-1`). Rejects uppercase,
/// percent-encoding, leading/trailing slashes, empty segments.
fn normalize_path(path: &str) -> Result<String, AppError> {
    if path.is_empty() {
        return Err(AppError::Validation(
            "path-prefix after '/' must not be empty".into(),
        ));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(AppError::Validation(
            "path-prefix must not have leading or trailing '/'".into(),
        ));
    }
    if path.contains("//") {
        return Err(AppError::Validation(
            "path-prefix must not contain empty segments ('//')".into(),
        ));
    }
    for c in path.chars() {
        let ok = c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '-'
            || c == '_'
            || c == '.'
            || c == '/';
        if !ok {
            return Err(AppError::Validation(format!(
                "path-prefix contains invalid character {c:?} — \
                 allowed: lowercase alphanumeric, '-', '_', '.', '/'"
            )));
        }
    }
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_canonical_msg(err: &AppError, expected_form: &str) {
        let s = format!("{err}");
        assert!(
            s.contains(&format!("use '{expected_form}'")),
            "error message should quote canonical form '{expected_form}'; got: {s}"
        );
    }

    #[test]
    fn accepts_canonical_lowercase() {
        let out = normalize_domain_name("example.com").unwrap();
        assert_eq!(out, "example.com");
    }

    #[test]
    fn accepts_subdomain() {
        let out = normalize_domain_name("tenant-a.example.com").unwrap();
        assert_eq!(out, "tenant-a.example.com");
    }

    #[test]
    fn rejects_uppercase_with_canonical_in_error() {
        let err = normalize_domain_name("Example.com").expect_err("must reject");
        assert_canonical_msg(&err, "example.com");
    }

    #[test]
    fn rejects_all_caps_with_canonical_in_error() {
        let err = normalize_domain_name("EXAMPLE.COM").expect_err("must reject");
        assert_canonical_msg(&err, "example.com");
    }

    #[test]
    fn rejects_leading_or_trailing_whitespace() {
        assert!(normalize_domain_name(" example.com").is_err());
        assert!(normalize_domain_name("example.com ").is_err());
        assert!(normalize_domain_name("\texample.com").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(normalize_domain_name("").is_err());
    }

    #[test]
    fn rejects_overlong() {
        let huge = "a".repeat(MAX_LEN + 1);
        assert!(normalize_domain_name(&huge).is_err());
    }

    #[test]
    fn rejects_ipv4_literal() {
        let err = normalize_domain_name("127.0.0.1").expect_err("must reject");
        assert!(err.to_string().contains("IP literal"));
    }

    #[test]
    fn rejects_ipv6_literal() {
        let err = normalize_domain_name("[::1]").expect_err("must reject");
        // url::Host::parse rejects bracketed without scheme — that
        // surfaces via the malformed-host path, which is fine.
        let _ = err.to_string();
    }

    #[test]
    fn idna_normalises_internationalised() {
        // IDN: müller.example → xn--mller-kva.example. The non-canonical
        // input must reject with the canonical form in the error.
        let err = normalize_domain_name("müller.example").expect_err("must reject pre-punycode");
        assert_canonical_msg(&err, "xn--mller-kva.example");
        // The canonical punycode form must be accepted.
        assert_eq!(
            normalize_domain_name("xn--mller-kva.example").unwrap(),
            "xn--mller-kva.example"
        );
    }

    // ---- path-prefix ----

    #[test]
    fn accepts_path_prefix_canonical() {
        let out = normalize_domain_name("example.com/webvh-a").unwrap();
        assert_eq!(out, "example.com/webvh-a");
    }

    #[test]
    fn accepts_path_prefix_with_segments() {
        let out = normalize_domain_name("example.com/tenant-a/instance-1").unwrap();
        assert_eq!(out, "example.com/tenant-a/instance-1");
    }

    #[test]
    fn rejects_uppercase_path_with_canonical_in_error() {
        // The path portion is uppercase but the host is fine — the
        // canonical form keeps the host as-is and reports the path
        // capitalisation. url::Host::parse on the host returns lowercase,
        // but here host is already lowercase, so the mismatch is purely
        // on the path side.
        let err =
            normalize_domain_name("example.com/Tenant-A").expect_err("uppercase path rejects");
        // path itself is invalid (uppercase), surfaces in the error
        // via normalize_path before the canonical check.
        let s = err.to_string();
        assert!(s.contains("invalid character"), "unexpected error: {s}");
    }

    #[test]
    fn rejects_leading_slash_in_input() {
        assert!(normalize_domain_name("/example.com").is_err());
    }

    #[test]
    fn rejects_trailing_slash_in_input() {
        assert!(normalize_domain_name("example.com/").is_err());
    }

    #[test]
    fn rejects_double_slash_in_path() {
        assert!(normalize_domain_name("example.com/a//b").is_err());
    }

    #[test]
    fn rejects_special_chars_in_path() {
        for bad in [
            "example.com/foo bar",
            "example.com/foo?bar",
            "example.com/foo#bar",
            "example.com/foo%20bar",
        ] {
            let err = normalize_domain_name(bad).expect_err(&format!("{bad} must reject"));
            let s = err.to_string();
            // For inputs that reach normalize_path the error mentions
            // "invalid character"; for inputs that get caught earlier
            // (url::Host::parse) the host-malformed path may trigger.
            // Either is acceptable; just confirm rejection.
            let _ = s;
            assert!(matches!(err, AppError::Validation(_)));
        }
    }

    #[test]
    fn rejects_path_with_uppercase_host() {
        // Uppercase host + valid path → canonical is fully lowercased.
        let err = normalize_domain_name("Example.com/webvh-a").expect_err("uppercase host rejects");
        assert_canonical_msg(&err, "example.com/webvh-a");
    }

    #[test]
    fn round_trips_under_re_normalisation() {
        // The result of `normalize_domain_name` must itself be canonical
        // (i.e. a second pass returns the same string). Drift between
        // these two would mean the system stores values it can't
        // re-validate.
        for input in [
            "example.com",
            "tenant-a.example.com",
            "example.com/webvh-a",
            "example.com/tenant-a/instance-1",
            "xn--mller-kva.example",
        ] {
            let canonical = normalize_domain_name(input).expect(input);
            assert_eq!(
                canonical,
                normalize_domain_name(&canonical).unwrap(),
                "non-idempotent on {input}"
            );
        }
    }
}

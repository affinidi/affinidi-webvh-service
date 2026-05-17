//! DIDComm-side helpers for Trust-Tasks dispatch.
//!
//! VTI's canonical `trust_task` module is REST-only — it ships
//! [`TrustTaskRouter`] for Axum but leaves DIDComm out of scope. webvh's
//! `dispatch_did_op` (in `did-hosting-control::messaging`) matches on
//! the inbound DIDComm message's `type` field; this module gives it
//! Trust-Task-shaped primitives so the same exact-match semantics
//! apply across both transports.
//!
//! Two surfaces, used together by T8's dispatcher integration:
//!
//! - [`parse_message_type`] — wraps `TrustTask::new` so a missing or
//!   malformed DIDComm `type` field surfaces as the same `AppError`
//!   variants the REST extractor produces.
//! - [`assert_matches`] — exact-match check between a parsed message
//!   type and a registered task. Returns `TrustTaskMismatch` with
//!   `expected` + `received` populated so caller logs match REST
//!   error bodies byte-for-byte.
//!
//! The existing `MSG_*` constants in `didcomm_types` keep working
//! alongside this — T8's alias layer canonicalises `MSG_*` strings to
//! their corresponding Trust-Task URL before lookup, so the legacy
//! constants and the new URLs route to the same handler.

use super::TrustTask;
use crate::server::error::AppError;

/// Parse an inbound DIDComm message's `type` field as a Trust-Task URL.
///
/// Treats an empty `type` field as `TrustTaskMissing` (analogous to the
/// REST extractor's missing-header path). A non-empty, non-HTTPS or
/// control-character-containing value surfaces as
/// `TrustTaskMalformed` via the underlying `TrustTask::new`.
///
/// Important: a `type` that's well-formed but isn't a Trust-Tasks URL
/// (e.g. the legacy `https://affinidi.com/webvh/1.0/...` constants)
/// will parse successfully here — Trust-Task URLs are opaque at the
/// validator layer. Routing-shaped failures are the dispatcher's job
/// via [`assert_matches`].
pub fn parse_message_type(msg_type: &str) -> Result<TrustTask, AppError> {
    if msg_type.is_empty() {
        return Err(AppError::TrustTaskMissing);
    }
    TrustTask::new(msg_type)
}

/// Exact-match check between a parsed `type` and a registered task.
///
/// Wire shape matches the REST router's mismatch response so the parity
/// harness (T9) can assert byte-equivalent error bodies across
/// transports.
pub fn assert_matches(actual: &TrustTask, expected: &TrustTask) -> Result<(), AppError> {
    if actual.as_str() == expected.as_str() {
        return Ok(());
    }
    Err(AppError::TrustTaskMismatch {
        expected: expected.as_str().to_string(),
        received: Some(actual.as_str().to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(url: &str) -> TrustTask {
        TrustTask::new(url).expect("test URL must validate")
    }

    #[test]
    fn parse_empty_yields_missing() {
        let err = parse_message_type("").expect_err("empty must reject");
        assert!(matches!(err, AppError::TrustTaskMissing));
    }

    #[test]
    fn parse_non_https_yields_malformed() {
        let err = parse_message_type("urn:example:not-https").expect_err("non-https must reject");
        assert!(matches!(err, AppError::TrustTaskMalformed(_)));
    }

    #[test]
    fn parse_well_formed_url_succeeds() {
        let t = parse_message_type("https://trusttasks.org/did-hosting/did/request/1.0")
            .expect("well-formed URL must parse");
        assert_eq!(
            t.as_str(),
            "https://trusttasks.org/did-hosting/did/request/1.0"
        );
    }

    #[test]
    fn parse_accepts_legacy_msg_url_too() {
        // Legacy MSG_* URLs are also well-formed HTTPS — the validator
        // doesn't know whether a URL is "really" a Trust-Task. The
        // dispatcher's alias-canonicalisation layer (T8) handles the
        // legacy → canonical mapping before assert_matches runs.
        let t = parse_message_type("https://affinidi.com/webvh/1.0/did/request")
            .expect("legacy MSG_* URL must also parse");
        assert_eq!(t.as_str(), "https://affinidi.com/webvh/1.0/did/request");
    }

    #[test]
    fn assert_matches_succeeds_on_exact_match() {
        let a = task("https://trusttasks.org/did-hosting/did/request/1.0");
        let b = task("https://trusttasks.org/did-hosting/did/request/1.0");
        assert!(assert_matches(&a, &b).is_ok());
    }

    #[test]
    fn assert_matches_byte_strict_on_version() {
        // Same path, different `min` version → must NOT match.
        let actual = task("https://trusttasks.org/did-hosting/did/request/1.1");
        let expected = task("https://trusttasks.org/did-hosting/did/request/1.0");
        let err = assert_matches(&actual, &expected).expect_err("version-skew must reject");
        match err {
            AppError::TrustTaskMismatch { expected, received } => {
                assert_eq!(
                    expected,
                    "https://trusttasks.org/did-hosting/did/request/1.0"
                );
                assert_eq!(
                    received.as_deref(),
                    Some("https://trusttasks.org/did-hosting/did/request/1.1")
                );
            }
            other => panic!("expected TrustTaskMismatch, got {other:?}"),
        }
    }

    #[test]
    fn assert_matches_byte_strict_on_path() {
        let actual = task("https://trusttasks.org/did-hosting/did/publish/1.0");
        let expected = task("https://trusttasks.org/did-hosting/did/request/1.0");
        assert!(assert_matches(&actual, &expected).is_err());
    }
}

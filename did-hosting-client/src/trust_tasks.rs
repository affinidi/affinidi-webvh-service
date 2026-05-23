//! Canonical Trust-Task URL constants — the wire-stable contract
//! between this client and a `did-hosting-server` /
//! `did-hosting-daemon`.
//!
//! Every REST call sets the `Trust-Task:` HTTP header to one of
//! these strings. The daemon's `TrustTaskRouter` (T8b) exact-matches
//! the value; a mismatch returns 415 with the expected URL in the
//! body. Bumping a version is a breaking change — both ends register
//! the new URL as a separate constant.
//!
//! ## Cross-crate consistency
//!
//! These values MUST match `did-hosting-common::did_hosting_tasks`
//! byte-for-byte. A future parity test (T51) will assert this
//! programmatically; until then, edit both files together. The
//! daemon-side test suite already pins URL shape invariants
//! (`every_url_ends_in_a_maj_min_version`,
//! `method_agnostic_urls_under_did_hosting`) so this client just
//! has to match.

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// Initial challenge request — `POST /api/auth/challenge`.
/// Canonical cross-cutting spec from trusttasks-tf.
pub const TASK_AUTH_CHALLENGE_1_0: &str = "https://trusttasks.org/spec/auth/challenge/0.1";

/// JWS-packed authenticate response — `POST /api/auth/`.
/// Canonical cross-cutting spec from trusttasks-tf.
pub const TASK_AUTH_AUTHENTICATE_1_0: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";

/// JWS-packed refresh — `POST /api/auth/refresh`.
/// Canonical cross-cutting spec from trusttasks-tf.
pub const TASK_AUTH_REFRESH_1_0: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

// ---------------------------------------------------------------------------
// DID lifecycle (the v0.1 client surface)
// ---------------------------------------------------------------------------

/// Path availability check — `POST /api/dids/check`.
pub const TASK_DID_CHECK_NAME_1_0: &str = "https://trusttasks.org/did-hosting/did/check-name/1.0";

/// Reserve a path slot — `POST /api/dids` (no payload, just path).
pub const TASK_DID_REQUEST_1_0: &str = "https://trusttasks.org/did-hosting/did/request/1.0";

/// Atomic claim-and-publish — `POST /api/dids/register`. The body
/// carries the method-specific payload + optional `domain`.
pub const TASK_DID_REGISTER_1_0: &str = "https://trusttasks.org/did-hosting/did/register/1.0";

/// Publish a new version of an existing DID — `PUT /api/dids/{*mnemonic}`.
pub const TASK_DID_PUBLISH_1_0: &str = "https://trusttasks.org/did-hosting/did/publish/1.0";

/// Delete a DID — `DELETE /api/dids/{*mnemonic}`.
pub const TASK_DID_DELETE_1_0: &str = "https://trusttasks.org/did-hosting/did/delete/1.0";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every URL must be a valid HTTPS URL under `trusttasks.org/did-hosting/`.
    #[test]
    fn every_url_is_canonical() {
        let all = [
            TASK_AUTH_CHALLENGE_1_0,
            TASK_AUTH_AUTHENTICATE_1_0,
            TASK_AUTH_REFRESH_1_0,
            TASK_DID_CHECK_NAME_1_0,
            TASK_DID_REQUEST_1_0,
            TASK_DID_REGISTER_1_0,
            TASK_DID_PUBLISH_1_0,
            TASK_DID_DELETE_1_0,
        ];
        for url in all {
            // Either the did-hosting-specific namespace (lifecycle ops
            // unique to this service) or the canonical /spec/auth/*
            // family in trusttasks-tf (cross-cutting auth primitives).
            assert!(
                url.starts_with("https://trusttasks.org/did-hosting/")
                    || url.starts_with("https://trusttasks.org/spec/auth/"),
                "URL must live under did-hosting/ or spec/auth/: {url}"
            );
            // Trailing `{maj}.{min}` per the canonical Trust-Tasks spec.
            let tail = url.rsplit('/').next().unwrap();
            let parts: Vec<&str> = tail.split('.').collect();
            assert_eq!(parts.len(), 2, "version must be maj.min: {url}");
            assert!(
                parts[0].chars().all(|c| c.is_ascii_digit())
                    && parts[1].chars().all(|c| c.is_ascii_digit()),
                "version must be digits: {url}"
            );
        }
    }
}

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
pub const TASK_AUTH_CHALLENGE_0_1: &str = "https://trusttasks.org/spec/auth/challenge/0.1";

/// JWS-packed authenticate response — `POST /api/auth/`.
/// Canonical cross-cutting spec from trusttasks-tf.
pub const TASK_AUTH_AUTHENTICATE_0_1: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";

/// JWS-packed refresh — `POST /api/auth/refresh`.
/// Canonical cross-cutting spec from trusttasks-tf.
pub const TASK_AUTH_REFRESH_0_1: &str = "https://trusttasks.org/spec/auth/refresh/0.1";

// ---------------------------------------------------------------------------
// DID lifecycle — canonical `spec/did-management/*` URIs
// ---------------------------------------------------------------------------
//
// Clean cutover (affinidi/affinidi-webvh-service#143): the legacy
// `did-hosting/*/1.0` header values were removed; every DID-lifecycle
// call now carries its canonical Trust-Task spec URI.

/// Path availability check — `POST /api/dids/check`. Also the identifier
/// for the reserve flow (`POST /api/dids`), which is the spec's
/// check-name with `reserve: true`.
pub const TASK_DID_CHECK_NAME_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/check-name/0.1";

/// Atomic claim-and-publish — `POST /api/dids/register`, and the
/// identifier for `PUT /api/dids/{*mnemonic}` (publishing a new version of
/// a slot you own — an owner re-register per the spec; the separate
/// `did/publish` task is retired).
pub const TASK_DID_REGISTER_0_1: &str =
    "https://trusttasks.org/spec/did-management/did/register/0.1";

/// Delete a DID — `DELETE /api/dids/{*mnemonic}`.
pub const TASK_DID_DELETE_0_1: &str = "https://trusttasks.org/spec/did-management/did/delete/0.1";

// ---------------------------------------------------------------------------
// Agent names
// ---------------------------------------------------------------------------
//
// A human-memorable `/@alice` on a hosted DID. The mutating ops carry a
// full new signed `did.jsonl` (`didData`) whose `alsoKnownAs` claims the
// name (`update {state: active}`) or no longer claims it
// (`update {state: parked}` / `remove`); the host verifies that direction
// matches before committing. That agreement is the specification's Layer-1
// anti-spoofing rule: a host structurally cannot serve a name the DID does
// not claim.

/// Name availability probe — `POST /api/agent-names/check`.
/// Body [`crate::AgentNameCheckRequest`], response
/// [`crate::AgentNameAvailability`].
pub const TASK_AGENT_NAME_CHECK_0_1: &str =
    "https://trusttasks.org/spec/did-management/agent-name/check/0.1";

/// Set a name's binding state — `POST /api/agent-names/update` with
/// `state: "active"` (bind / refresh / resume) or `state: "parked"`
/// (stops resolving, reservation kept). Replaces the retired
/// set / enable / disable verbs.
pub const TASK_AGENT_NAME_UPDATE_0_1: &str =
    "https://trusttasks.org/spec/did-management/agent-name/update/0.1";

/// Release a name — `POST /api/agent-names/remove`. The name becomes
/// claimable by anyone; the irreversible counterpart to parking.
pub const TASK_AGENT_NAME_REMOVE_0_1: &str =
    "https://trusttasks.org/spec/did-management/agent-name/remove/0.1";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every URL must be a valid HTTPS URL under a recognised namespace.
    #[test]
    fn every_url_is_canonical() {
        let all = [
            TASK_AUTH_CHALLENGE_0_1,
            TASK_AUTH_AUTHENTICATE_0_1,
            TASK_AUTH_REFRESH_0_1,
            TASK_DID_CHECK_NAME_0_1,
            TASK_DID_REGISTER_0_1,
            TASK_DID_DELETE_0_1,
            TASK_AGENT_NAME_CHECK_0_1,
            TASK_AGENT_NAME_UPDATE_0_1,
            TASK_AGENT_NAME_REMOVE_0_1,
        ];
        for url in all {
            // Either a canonical /spec/did-management/* task or the
            // canonical /spec/auth/* family in trusttasks-tf.
            assert!(
                url.starts_with("https://trusttasks.org/spec/did-management/")
                    || url.starts_with("https://trusttasks.org/spec/auth/"),
                "URL must live under spec/did-management/ or spec/auth/: {url}"
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

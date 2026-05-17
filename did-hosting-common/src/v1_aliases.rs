//! Bidirectional alias table: legacy `MSG_*` strings ↔ canonical
//! Trust-Task URLs.
//!
//! Why this exists: per `docs/multi-domain-spec.md` §3 we keep the
//! legacy `MSG_*` constants under `affinidi.com/webvh/1.0/...` working
//! alongside the new canonical Trust-Task URLs under
//! `trusttasks.org/{did-hosting,webvh}/...`. Old clients keep working;
//! new clients use the canonical URLs from `crate::did_hosting_tasks`.
//!
//! The DIDComm dispatcher (in `did-hosting-control::messaging`) and the
//! REST `Trust-Task:` header validator both call [`canonicalize`]
//! before matching. The dispatcher then compares the result against
//! the registered task — so a single handler accepts both spellings of
//! its operation's identifier.
//!
//! ## Drift discipline
//!
//! Every `MSG_*` const in `crate::didcomm_types` must appear in
//! [`ALIAS_PAIRS`] paired with its canonical URL. A `MSG_*` that's
//! added without an alias entry will be invisible to the canonical
//! dispatcher; the [`every_msg_constant_has_an_alias`] test catches
//! that drift on every workspace build.

use crate::did_hosting_tasks::{
    TASK_AUTH_AUTHENTICATE_1_0, TASK_AUTH_AUTHENTICATE_RESPONSE_1_0, TASK_DID_CHANGE_OWNER_1_0,
    TASK_DID_CHANGE_OWNER_CONFIRM_1_0, TASK_DID_CONFIRM_1_0, TASK_DID_DELETE_1_0,
    TASK_DID_DELETE_CONFIRM_1_0, TASK_DID_INFO_1_0, TASK_DID_INFO_REQUEST_1_0, TASK_DID_LIST_1_0,
    TASK_DID_LIST_REQUEST_1_0, TASK_DID_OFFER_1_0, TASK_DID_PROBLEM_REPORT_1_0,
    TASK_DID_PUBLISH_1_0, TASK_DID_REGISTER_1_0, TASK_DID_REGISTER_CONFIRM_1_0,
    TASK_DID_REQUEST_1_0, TASK_DOMAIN_ASSIGN_1_0, TASK_DOMAIN_PURGE_1_0, TASK_DOMAIN_UNASSIGN_1_0,
    TASK_SERVER_HEALTH_PING_1_0, TASK_SERVER_HEALTH_PONG_1_0, TASK_SERVER_REGISTER_1_0,
    TASK_SERVER_REGISTER_ACK_1_0, TASK_SERVER_STATS_ACK_1_0, TASK_SERVER_STATS_SYNC_1_0,
    TASK_WEBVH_SYNC_DELETE_1_0, TASK_WEBVH_SYNC_DELETE_ACK_1_0, TASK_WEBVH_SYNC_UPDATE_1_0,
    TASK_WEBVH_SYNC_UPDATE_ACK_1_0, TASK_WEBVH_WITNESS_CONFIRM_1_0, TASK_WEBVH_WITNESS_PUBLISH_1_0,
};
use crate::didcomm_types::{
    MSG_AUTH_RESPONSE, MSG_AUTHENTICATE, MSG_DELETE, MSG_DELETE_CONFIRM, MSG_DID_CHANGE_OWNER,
    MSG_DID_CHANGE_OWNER_CONFIRM, MSG_DID_CONFIRM, MSG_DID_OFFER, MSG_DID_PUBLISH,
    MSG_DID_REGISTER, MSG_DID_REGISTER_CONFIRM, MSG_DID_REQUEST, MSG_DOMAIN_ASSIGN,
    MSG_DOMAIN_PURGE, MSG_DOMAIN_UNASSIGN, MSG_HEALTH_PING, MSG_HEALTH_PONG, MSG_INFO,
    MSG_INFO_REQUEST, MSG_LIST, MSG_LIST_REQUEST, MSG_PROBLEM_REPORT, MSG_SERVER_REGISTER,
    MSG_SERVER_REGISTER_ACK, MSG_STATS_ACK, MSG_STATS_SYNC, MSG_SYNC_DELETE, MSG_SYNC_DELETE_ACK,
    MSG_SYNC_UPDATE, MSG_SYNC_UPDATE_ACK, MSG_WITNESS_CONFIRM, MSG_WITNESS_PUBLISH,
};

/// `(legacy MSG_* string, canonical Trust-Task URL)` pairs.
///
/// Iterated linearly on each lookup (N ≈ 30 entries — negligible vs.
/// the surrounding DIDComm decode work). Order is documentary only;
/// callers must not rely on it.
fn alias_pairs() -> [(&'static str, &'static str); 32] {
    [
        // Auth
        (MSG_AUTHENTICATE, TASK_AUTH_AUTHENTICATE_1_0.as_str()),
        (
            MSG_AUTH_RESPONSE,
            TASK_AUTH_AUTHENTICATE_RESPONSE_1_0.as_str(),
        ),
        // DID lifecycle
        (MSG_DID_REQUEST, TASK_DID_REQUEST_1_0.as_str()),
        (MSG_DID_OFFER, TASK_DID_OFFER_1_0.as_str()),
        (MSG_DID_PUBLISH, TASK_DID_PUBLISH_1_0.as_str()),
        (MSG_DID_CONFIRM, TASK_DID_CONFIRM_1_0.as_str()),
        (MSG_DID_REGISTER, TASK_DID_REGISTER_1_0.as_str()),
        (
            MSG_DID_REGISTER_CONFIRM,
            TASK_DID_REGISTER_CONFIRM_1_0.as_str(),
        ),
        (MSG_INFO_REQUEST, TASK_DID_INFO_REQUEST_1_0.as_str()),
        (MSG_INFO, TASK_DID_INFO_1_0.as_str()),
        (MSG_LIST_REQUEST, TASK_DID_LIST_REQUEST_1_0.as_str()),
        (MSG_LIST, TASK_DID_LIST_1_0.as_str()),
        (MSG_DELETE, TASK_DID_DELETE_1_0.as_str()),
        (MSG_DELETE_CONFIRM, TASK_DID_DELETE_CONFIRM_1_0.as_str()),
        (MSG_DID_CHANGE_OWNER, TASK_DID_CHANGE_OWNER_1_0.as_str()),
        (
            MSG_DID_CHANGE_OWNER_CONFIRM,
            TASK_DID_CHANGE_OWNER_CONFIRM_1_0.as_str(),
        ),
        (MSG_PROBLEM_REPORT, TASK_DID_PROBLEM_REPORT_1_0.as_str()),
        // Hosting infrastructure
        (MSG_SERVER_REGISTER, TASK_SERVER_REGISTER_1_0.as_str()),
        (
            MSG_SERVER_REGISTER_ACK,
            TASK_SERVER_REGISTER_ACK_1_0.as_str(),
        ),
        (MSG_HEALTH_PING, TASK_SERVER_HEALTH_PING_1_0.as_str()),
        (MSG_HEALTH_PONG, TASK_SERVER_HEALTH_PONG_1_0.as_str()),
        (MSG_STATS_SYNC, TASK_SERVER_STATS_SYNC_1_0.as_str()),
        (MSG_STATS_ACK, TASK_SERVER_STATS_ACK_1_0.as_str()),
        // Domain assignment (T28). Only the request side is in the
        // alias table — the ACK messages flow back as responses and
        // are matched literally in the originator's response handler,
        // so they don't need legacy/canonical canonicalisation. If a
        // future revision separates the ACK Trust-Task URL, add it
        // here with its own canonical.
        (MSG_DOMAIN_ASSIGN, TASK_DOMAIN_ASSIGN_1_0.as_str()),
        (MSG_DOMAIN_UNASSIGN, TASK_DOMAIN_UNASSIGN_1_0.as_str()),
        (MSG_DOMAIN_PURGE, TASK_DOMAIN_PURGE_1_0.as_str()),
        // webvh-specific: witness + sync
        (MSG_WITNESS_PUBLISH, TASK_WEBVH_WITNESS_PUBLISH_1_0.as_str()),
        (MSG_WITNESS_CONFIRM, TASK_WEBVH_WITNESS_CONFIRM_1_0.as_str()),
        (MSG_SYNC_UPDATE, TASK_WEBVH_SYNC_UPDATE_1_0.as_str()),
        (MSG_SYNC_UPDATE_ACK, TASK_WEBVH_SYNC_UPDATE_ACK_1_0.as_str()),
        (MSG_SYNC_DELETE, TASK_WEBVH_SYNC_DELETE_1_0.as_str()),
        (MSG_SYNC_DELETE_ACK, TASK_WEBVH_SYNC_DELETE_ACK_1_0.as_str()),
    ]
}

/// Canonicalise an incoming message `type` to its Trust-Task URL.
///
/// Returns:
/// - `Some(canonical)` if `msg_type` matches a legacy `MSG_*` string
///   (canonicalised to its Trust-Task URL).
/// - `Some(canonical)` if `msg_type` is **already** the canonical URL
///   (returned unchanged — so callers can apply `canonicalize` first
///   and compare against `TASK_*` second without a special case).
/// - `None` if `msg_type` is neither a known `MSG_*` nor a known
///   canonical URL. The dispatcher treats this as an unknown
///   operation.
pub fn canonicalize(msg_type: &str) -> Option<&'static str> {
    for (legacy, canonical) in alias_pairs() {
        if msg_type == legacy || msg_type == canonical {
            return Some(canonical);
        }
    }
    None
}

/// Inverse of [`canonicalize`]: given **either** a legacy `MSG_*` or
/// the canonical Trust-Task URL, return the legacy `MSG_*` form.
///
/// The DIDComm dispatcher in `did-hosting-control::messaging` uses this
/// to keep its existing `match msg.typ.as_str() { MSG_* => … }` arms
/// while accepting canonical URLs from new clients: it calls
/// `to_legacy(msg.typ.as_str())` once before the match and the rest of
/// the dispatcher is unchanged.
///
/// Returns `None` for an unrecognised string (handled by the dispatcher
/// the same way an unknown `msg.typ` was handled previously).
pub fn to_legacy(msg_type: &str) -> Option<&'static str> {
    for (legacy, canonical) in alias_pairs() {
        if msg_type == legacy || msg_type == canonical {
            return Some(legacy);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::didcomm_types::{
        MSG_AUTH_RESPONSE, MSG_AUTHENTICATE, MSG_DELETE, MSG_DELETE_CONFIRM, MSG_DID_CHANGE_OWNER,
        MSG_DID_CHANGE_OWNER_CONFIRM, MSG_DID_CONFIRM, MSG_DID_OFFER, MSG_DID_PUBLISH,
        MSG_DID_REGISTER, MSG_DID_REGISTER_CONFIRM, MSG_DID_REQUEST, MSG_DOMAIN_ASSIGN,
        MSG_DOMAIN_PURGE, MSG_DOMAIN_UNASSIGN, MSG_HEALTH_PING, MSG_HEALTH_PONG, MSG_INFO,
        MSG_INFO_REQUEST, MSG_LIST, MSG_LIST_REQUEST, MSG_PROBLEM_REPORT, MSG_SERVER_REGISTER,
        MSG_SERVER_REGISTER_ACK, MSG_STATS_ACK, MSG_STATS_SYNC, MSG_SYNC_DELETE,
        MSG_SYNC_DELETE_ACK, MSG_SYNC_UPDATE, MSG_SYNC_UPDATE_ACK, MSG_WITNESS_CONFIRM,
        MSG_WITNESS_PUBLISH,
    };

    #[test]
    fn to_legacy_round_trips_via_canonical() {
        // Legacy → legacy (unchanged)
        assert_eq!(to_legacy(MSG_AUTHENTICATE), Some(MSG_AUTHENTICATE));
        // Canonical → legacy
        let canonical = canonicalize(MSG_AUTHENTICATE).unwrap();
        assert_eq!(to_legacy(canonical), Some(MSG_AUTHENTICATE));
    }

    #[test]
    fn canonicalizes_legacy_authenticate() {
        let canonical = canonicalize(MSG_AUTHENTICATE).expect("MSG_AUTHENTICATE must be aliased");
        assert_eq!(
            canonical,
            "https://trusttasks.org/did-hosting/auth/authenticate/1.0"
        );
    }

    #[test]
    fn passes_canonical_url_through_unchanged() {
        let input = "https://trusttasks.org/did-hosting/auth/authenticate/1.0";
        let canonical = canonicalize(input).expect("canonical URL must round-trip");
        assert_eq!(canonical, input);
    }

    #[test]
    fn returns_none_for_unknown_type() {
        assert!(canonicalize("https://example.com/unknown/op/1.0").is_none());
        assert!(canonicalize("").is_none());
        assert!(canonicalize("not-a-url").is_none());
    }

    #[test]
    fn webvh_specific_alias_to_webvh_namespace() {
        let canonical =
            canonicalize(MSG_WITNESS_PUBLISH).expect("MSG_WITNESS_PUBLISH must be aliased");
        assert_eq!(
            canonical,
            "https://trusttasks.org/webvh/did/witness-publish/1.0"
        );
    }

    /// Drift guard: every `MSG_*` const from `crate::didcomm_types`
    /// must appear in the alias table. Without this test, adding a
    /// new `MSG_*` without aliasing it would silently route around
    /// the canonical dispatcher.
    #[test]
    fn every_msg_constant_has_an_alias() {
        let msgs = [
            MSG_AUTHENTICATE,
            MSG_AUTH_RESPONSE,
            MSG_DID_REQUEST,
            MSG_DID_OFFER,
            MSG_DID_PUBLISH,
            MSG_DID_CONFIRM,
            MSG_DID_REGISTER,
            MSG_DID_REGISTER_CONFIRM,
            MSG_WITNESS_PUBLISH,
            MSG_WITNESS_CONFIRM,
            MSG_INFO_REQUEST,
            MSG_INFO,
            MSG_LIST_REQUEST,
            MSG_LIST,
            MSG_DELETE,
            MSG_DELETE_CONFIRM,
            MSG_DID_CHANGE_OWNER,
            MSG_DID_CHANGE_OWNER_CONFIRM,
            MSG_PROBLEM_REPORT,
            MSG_SERVER_REGISTER,
            MSG_SERVER_REGISTER_ACK,
            MSG_HEALTH_PING,
            MSG_HEALTH_PONG,
            MSG_SYNC_UPDATE,
            MSG_SYNC_UPDATE_ACK,
            MSG_SYNC_DELETE,
            MSG_SYNC_DELETE_ACK,
            MSG_STATS_SYNC,
            MSG_STATS_ACK,
            MSG_DOMAIN_ASSIGN,
            MSG_DOMAIN_UNASSIGN,
            MSG_DOMAIN_PURGE,
        ];
        for m in msgs {
            assert!(canonicalize(m).is_some(), "MSG_* `{m}` has no alias entry");
        }
    }

    #[test]
    fn no_alias_table_collisions() {
        // Each canonical URL must appear exactly once on the right-hand
        // side. A duplicate would mean two MSG_* constants alias to the
        // same handler — ambiguity in the dispatcher.
        let pairs = alias_pairs();
        let mut canonicals: Vec<&str> = pairs.iter().map(|(_, c)| *c).collect();
        canonicals.sort();
        let len_before = canonicals.len();
        canonicals.dedup();
        assert_eq!(
            len_before,
            canonicals.len(),
            "alias table has duplicate canonical URL: {canonicals:?}"
        );
    }
}

//! DIDComm v2 authenticate / refresh message construction.
//!
//! Both helpers produce a JWS-packed string ready to POST as the
//! request body. The daemon's matching unpack lives in
//! `did-hosting-common::server::didcomm_unpack::unpack_signed`,
//! which:
//! - resolves the sender DID,
//! - verifies the JWS against the resolved verification method,
//! - enforces a 5-minute `created_time` freshness window,
//! - returns the inner `Message` + the JWS-verified signer DID.
//!
//! Sticking to the same `affinidi_tdk::didcomm::message::pack`
//! primitive the daemon uses for its responses guarantees byte-
//! identical envelope shapes — no protocol drift between the two
//! sides.

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::message::pack;
use serde_json::json;

use super::{HostingSigningIdentity, MSG_AUTH_RESPONSE, MSG_AUTHENTICATE};

/// Construct + sign an `authenticate` envelope.
///
/// Inputs:
/// - `identity`: holder's DID + signing key. The packed JWS will
///   carry `from = identity.did` and a `kid` of
///   `"{identity.did}{identity.kid_fragment}"`.
/// - `session_id`: returned by the daemon on
///   `POST /api/auth/challenge`.
/// - `challenge`: the nonce hex string returned alongside
///   `session_id`. The daemon constant-time-compares it.
/// - `now_epoch`: current epoch seconds. Stamped into the message's
///   `created_time` header so the daemon's 5-minute freshness window
///   evaluates correctly. Passed in (rather than read from
///   `SystemTime`) so integrator tests can pin a deterministic value.
/// - `recipient_did`: the daemon's DID (the `to` field). The
///   daemon's auth handler doesn't gate on this, but pack-side
///   wants a non-empty `to` so the resulting JWS has a well-formed
///   recipient list for any future routing.
pub fn build_authenticate_message(
    identity: &HostingSigningIdentity<'_>,
    session_id: &str,
    challenge: &str,
    now_epoch: u64,
    recipient_did: &str,
) -> Result<String, AuthMessageError> {
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_AUTHENTICATE.to_string(),
        json!({
            "session_id": session_id,
            "challenge": challenge,
        }),
    )
    .from(identity.did.to_string())
    .to(recipient_did.to_string())
    .created_time(now_epoch)
    .finalize();
    pack_with(identity, &msg)
}

/// Construct + sign a `refresh` envelope. Same shape as the
/// authenticate message but with the refresh token in place of the
/// challenge, and `typ = MSG_AUTH_RESPONSE`.
pub fn build_refresh_message(
    identity: &HostingSigningIdentity<'_>,
    refresh_token: &str,
    now_epoch: u64,
    recipient_did: &str,
) -> Result<String, AuthMessageError> {
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_AUTH_RESPONSE.to_string(),
        json!({ "refresh_token": refresh_token }),
    )
    .from(identity.did.to_string())
    .to(recipient_did.to_string())
    .created_time(now_epoch)
    .finalize();
    pack_with(identity, &msg)
}

/// Shared pack-side glue. Builds the `kid` from the identity and
/// delegates to `pack::pack_signed`.
fn pack_with(
    identity: &HostingSigningIdentity<'_>,
    msg: &Message,
) -> Result<String, AuthMessageError> {
    let kid = identity.kid();
    pack::pack_signed(msg, &kid, identity.signing_key)
        .map_err(|e| AuthMessageError::Pack(e.to_string()))
}

/// Failure modes for the message constructors.
#[derive(Debug, thiserror::Error)]
pub enum AuthMessageError {
    /// `pack_signed` rejected the message. Carries the upstream
    /// error message; the most likely cause is a malformed DID or
    /// an invalid signing-key length, both of which the
    /// constructor types should make impossible — surfaced here as
    /// defence-in-depth.
    #[error("pack_signed failed: {0}")]
    Pack(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pack primitive needs a real Ed25519 secret. We use a
    /// fixed test vector so the test runs without `OsRng`. The
    /// secret itself doesn't matter — we're checking shape, not
    /// signature validity. (Validity is exercised by the daemon's
    /// `didcomm_unpack` test suite, which uses live key pairs.)
    fn test_identity() -> HostingSigningIdentityOwned {
        HostingSigningIdentityOwned::new(
            "did:example:alice",
            // A fixed 32-byte test seed. Not cryptographically
            // meaningful; just non-zero so pack_signed doesn't
            // reject on degenerate input.
            *b"01234567890123456789012345678901",
        )
    }

    /// The constructor must produce a valid JWS envelope (a single
    /// JSON object with `signatures` array). We don't verify the
    /// signature here — that's the daemon's job — but the wrapper
    /// shape is the wire contract between us and `unpack_signed`.
    #[test]
    fn authenticate_message_packs_to_jws_envelope() {
        let owned = test_identity();
        let id = owned.borrow();
        let packed = build_authenticate_message(
            &id,
            "sess-123",
            "deadbeefcafe",
            1_700_000_000,
            "did:example:control",
        )
        .expect("pack must succeed for a well-formed identity");

        let parsed: serde_json::Value = serde_json::from_str(&packed).expect("packed is JSON");
        let signatures = parsed
            .get("signatures")
            .and_then(|v| v.as_array())
            .expect("JWS envelope has a `signatures` array");
        assert!(!signatures.is_empty(), "must carry at least one signature");

        // The signed payload base64-encodes the inner message; we
        // can't recover the typ without verification, but we can
        // assert the payload is non-empty.
        assert!(parsed.get("payload").and_then(|v| v.as_str()).is_some());
    }

    /// Refresh message uses the same packer; same envelope shape.
    /// The `typ` is `authenticate-response` (verified by the daemon
    /// after unpack); the wrapper doesn't expose it.
    #[test]
    fn refresh_message_packs_to_jws_envelope() {
        let owned = test_identity();
        let id = owned.borrow();
        let packed = build_refresh_message(
            &id,
            "the-refresh-token",
            1_700_000_000,
            "did:example:control",
        )
        .expect("pack must succeed");

        let parsed: serde_json::Value = serde_json::from_str(&packed).unwrap();
        assert!(
            parsed
                .get("signatures")
                .and_then(|v| v.as_array())
                .is_some()
        );
    }

    /// Different challenges → different packed envelopes. Pins that
    /// the constructor isn't accidentally caching or memoising.
    #[test]
    fn different_challenges_produce_different_envelopes() {
        let owned = test_identity();
        let id = owned.borrow();
        let a = build_authenticate_message(&id, "sess-1", "aaa", 1, "did:example:control").unwrap();
        let b = build_authenticate_message(&id, "sess-1", "bbb", 1, "did:example:control").unwrap();
        assert_ne!(a, b);
    }

    use super::super::HostingSigningIdentityOwned;
}

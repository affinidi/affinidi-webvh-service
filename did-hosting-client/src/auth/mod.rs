//! Challenge-response authentication against a `did-hosting-server` /
//! `did-hosting-daemon`.
//!
//! The daemon's auth flow has two REST round-trips:
//!
//! 1. `POST /api/auth/challenge` with `{ did }` → returns
//!    `{ session_id, data: { challenge } }`.
//! 2. The client self-issues a SIOPv2 `id_token` (a compact EdDSA JWS
//!    signed by the holder's Ed25519 key, with the challenge as
//!    `nonce` and the relying-party DID as `aud`), wraps it in a
//!    Trust-Task envelope (`type =
//!    "https://trusttasks.org/spec/auth/authenticate/0.1"`,
//!    `payload = { id_token, session_id, session_pubkey_b58btc? }`),
//!    and POSTs that envelope to `/api/auth/`. The daemon verifies
//!    the `id_token` via
//!    `did_hosting_common::server::didcomm_unpack::verify_siop_id_token`
//!    and issues `{ access_token, refresh_token, access_expires_at,
//!    refresh_expires_at }`.
//!
//! Token refresh is unchanged: a DIDComm message with `typ =
//! "https://affinidi.com/webvh/1.0/authenticate-response"` carrying
//! the refresh token, posted to `/api/auth/refresh`.
//!
//! ## What this module owns
//!
//! - [`HostingSigningIdentity`] / [`HostingSigningIdentityOwned`]
//!   — the holder's DID + raw Ed25519 signing key bytes. Two
//!   variants so the integrator can either pass a borrow (avoid a
//!   copy when the key already lives in their secret store) or
//!   move an owned value into the client.
//! - [`build_authenticate_body`] — builds the Trust-Task envelope
//!   carrying the self-issued SIOPv2 `id_token`. The `id_token`'s
//!   `iss`/`sub` is a `did:key` derived from the holder's Ed25519
//!   *public* key (not the `did:webvh` identity), so the server
//!   resolves it without a DID-document round-trip.
//! - [`build_refresh_message`] — the (unchanged) refresh constructor.
//!   Returns a JWS-packed string via
//!   [`affinidi_tdk::didcomm::message::pack::pack_signed`].
//!
//! ## Why not VTI
//!
//! The original spec referenced
//! `verifiable-trust-infrastructure/vta-service/src/webvh_auth.rs`;
//! that module has since been refactored upstream and the symbols
//! it named no longer exist. This port is therefore a fresh
//! implementation built directly against the daemon's wire
//! contract (see `did-hosting-control/src/routes/auth.rs` for the
//! receiving side). The shapes match what the daemon expects;
//! drift would surface as 401 from the auth handler.

pub mod message;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub use message::{build_authenticate_body, build_refresh_message};

/// Trust-Task URL stamped on `POST /api/auth/challenge` requests.
pub const TASK_AUTH_CHALLENGE_1_0: &str = super::trust_tasks::TASK_AUTH_CHALLENGE_1_0;

/// Trust-Task URL stamped on `POST /api/auth/` (authenticate)
/// requests.
pub const TASK_AUTH_AUTHENTICATE_1_0: &str = super::trust_tasks::TASK_AUTH_AUTHENTICATE_1_0;

/// Trust-Task URL stamped on `POST /api/auth/refresh` requests.
pub const TASK_AUTH_REFRESH_1_0: &str = super::trust_tasks::TASK_AUTH_REFRESH_1_0;

/// DIDComm v2 message `typ` for the authenticate-response /
/// refresh envelope.
pub const MSG_AUTH_RESPONSE: &str = "https://affinidi.com/webvh/1.0/authenticate-response";

/// Borrowed signing identity: a DID + a reference to its 32-byte
/// Ed25519 secret key. Use this when the key already lives in the
/// integrator's secret store and you don't want to copy it.
///
/// The `kid` (DID URL fragment) defaults to `#key-0` to match
/// what `did-hosting-server` / `did-hosting-daemon` constructs for
/// their own signing keys — see
/// `did-hosting-control/src/routes/didcomm.rs::pack_signed_response`.
/// Override via [`Self::with_kid`] when the holder's DID document
/// uses a different verification-method identifier.
#[derive(Debug, Clone, Copy)]
pub struct HostingSigningIdentity<'a> {
    /// The fully-qualified DID (e.g. `did:webvh:Q1:example.com:alice`).
    pub did: &'a str,
    /// 32-byte Ed25519 secret key. The pack layer turns this into
    /// the JWS signature.
    pub signing_key: &'a [u8; 32],
    /// Verification-method fragment within the DID document. The
    /// resulting JWS header `kid` is `"{did}{kid_fragment}"`. The
    /// daemon's `unpack_signed` resolves the DID document and looks
    /// up the matching public key by this fragment.
    pub kid_fragment: &'a str,
}

impl<'a> HostingSigningIdentity<'a> {
    /// Construct with the default `#key-0` fragment.
    pub const fn new(did: &'a str, signing_key: &'a [u8; 32]) -> Self {
        Self {
            did,
            signing_key,
            kid_fragment: "#key-0",
        }
    }

    /// Override the verification-method fragment.
    pub const fn with_kid(mut self, kid_fragment: &'a str) -> Self {
        self.kid_fragment = kid_fragment;
        self
    }

    /// Build the full `kid` JOSE header value (`{did}{fragment}`).
    pub fn kid(&self) -> String {
        format!("{}{}", self.did, self.kid_fragment)
    }
}

/// Owned counterpart of [`HostingSigningIdentity`]. The signing key
/// is zeroized on drop as defence-in-depth against memory dumps —
/// integrators are still responsible for not logging the structure
/// (`Debug` redacts the key by design).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HostingSigningIdentityOwned {
    /// The fully-qualified DID.
    pub did: String,
    /// 32-byte Ed25519 secret key. Zeroized on drop.
    pub signing_key: [u8; 32],
    /// Verification-method fragment (`#key-0` default).
    pub kid_fragment: String,
}

impl HostingSigningIdentityOwned {
    /// Construct with the default `#key-0` fragment.
    pub fn new(did: impl Into<String>, signing_key: [u8; 32]) -> Self {
        Self {
            did: did.into(),
            signing_key,
            kid_fragment: "#key-0".to_string(),
        }
    }

    /// Override the verification-method fragment (builder pattern).
    pub fn with_kid(mut self, kid_fragment: impl Into<String>) -> Self {
        self.kid_fragment = kid_fragment.into();
        self
    }

    /// Borrow as a [`HostingSigningIdentity`] for one-shot use.
    pub fn borrow(&self) -> HostingSigningIdentity<'_> {
        HostingSigningIdentity {
            did: &self.did,
            signing_key: &self.signing_key,
            kid_fragment: &self.kid_fragment,
        }
    }

    /// Build the full `kid` JOSE header value.
    pub fn kid(&self) -> String {
        format!("{}{}", self.did, self.kid_fragment)
    }
}

/// Redacted Debug — the signing key is the secret half; printing it
/// would defeat the `ZeroizeOnDrop` defence.
impl std::fmt::Debug for HostingSigningIdentityOwned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostingSigningIdentityOwned")
            .field("did", &self.did)
            .field("signing_key", &"<redacted>")
            .field("kid_fragment", &self.kid_fragment)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_identity_constructs_kid() {
        let key = [0u8; 32];
        let id = HostingSigningIdentity::new("did:example:alice", &key);
        assert_eq!(id.kid(), "did:example:alice#key-0");
        assert_eq!(id.with_kid("#auth-key").kid(), "did:example:alice#auth-key");
    }

    #[test]
    fn owned_identity_constructs_kid() {
        let id = HostingSigningIdentityOwned::new("did:example:alice", [1u8; 32]);
        assert_eq!(id.kid(), "did:example:alice#key-0");
        let id =
            HostingSigningIdentityOwned::new("did:example:alice", [1u8; 32]).with_kid("#auth-key");
        assert_eq!(id.kid(), "did:example:alice#auth-key");
    }

    #[test]
    fn owned_identity_redacts_key_in_debug() {
        let id = HostingSigningIdentityOwned::new("did:example:alice", [9u8; 32]);
        let rendered = format!("{id:?}");
        assert!(rendered.contains("did:example:alice"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("9, 9, 9"));
    }

    #[test]
    fn owned_can_borrow_into_short_lived_handle() {
        let owned = HostingSigningIdentityOwned::new("did:example:alice", [1u8; 32]);
        let borrowed = owned.borrow();
        assert_eq!(borrowed.did, "did:example:alice");
        assert_eq!(borrowed.kid_fragment, "#key-0");
        assert_eq!(borrowed.signing_key, &[1u8; 32]);
    }
}

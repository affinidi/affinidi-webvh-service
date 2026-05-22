//! SIOPv2 self-issued `id_token` construction for `POST /api/auth/`.
//!
//! The control plane's authenticate endpoint no longer accepts a
//! legacy DIDComm `authenticate` message. It now expects a Trust-Task
//! envelope (`type = did-hosting/auth/authenticate/1.0`) whose payload
//! carries a SIOPv2 self-issued `id_token` — a compact EdDSA JWS the
//! holder signs with its own Ed25519 key.
//!
//! The server side that consumes this is
//! `did_hosting_common::server::didcomm_unpack::verify_siop_id_token`
//! together with `did_hosting_common::AuthenticatePayload`. We mirror
//! its exact byte layout here so verification succeeds:
//!
//! - **header** `{"alg":"EdDSA","typ":"JWT","kid":"<did:key>#<multibase>"}`
//! - **payload** `{"iss","sub","aud","nonce","iat","exp"}` with
//!   `iss == sub` and `exp = iat + 300`.
//! - **signature** Ed25519 over the UTF-8 bytes of
//!   `"<b64u(header)>.<b64u(payload)>"`.
//!
//! The `iss`/`sub`/`kid`-DID is a `did:key:z6Mk…` derived from the
//! holder's Ed25519 *public* key (multicodec `0xed01 ‖ pubkey`,
//! base58btc multibase) — **not** the integration's `did:webvh`
//! identifier. The server resolves the `did:key` directly to recover
//! the verifying key, so self-issuance needs no DID-document round-trip.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use super::{HostingSigningIdentity, MSG_AUTH_RESPONSE, TASK_AUTH_AUTHENTICATE_1_0};

/// SIOPv2 `id_token` lifetime, in seconds. The server enforces
/// `iat <= now <= exp`; we stamp `exp = iat + 300` (5 minutes), which
/// comfortably outlives the round-trip while bounding replay.
const ID_TOKEN_TTL_SECS: u64 = 300;

/// Build the wire body for `POST /api/auth/`: a Trust-Task envelope
/// carrying a freshly self-issued SIOPv2 `id_token`.
///
/// Inputs:
/// - `identity`: holder's signing identity. The `signing_key` is the
///   32-byte Ed25519 secret; the `id_token`'s `iss`/`sub` and the JWS
///   `kid` are derived from its **public** key as a `did:key`. The
///   `identity.did` (`did:webvh:…`) and `kid_fragment` are *not* used
///   here — SIOPv2 self-issuance keys off the raw Ed25519 key.
/// - `session_id`: returned by the daemon on
///   `POST /api/auth/challenge`. Echoed verbatim in the payload so the
///   server can look up the pending session.
/// - `challenge`: the nonce returned alongside `session_id`. Becomes
///   the token's `nonce`; the server constant-time-compares it.
/// - `recipient_did`: the relying-party DID (the daemon's
///   `server_did`). Becomes the token's `aud`; the server rejects a
///   mismatch.
/// - `now_epoch`: current unix seconds. Stamped as `iat`; `exp` is
///   `iat + 300`. Passed in (not read from `SystemTime`) so integrator
///   tests can pin a deterministic clock.
/// - `session_pubkey_b58btc`: optional ephemeral session key
///   (Ed25519 multikey, base58btc with the `z` prefix) the server
///   binds to the issued JWT for later Data-Integrity proofs.
///
/// Returns the serialized JSON envelope ready to POST as the request
/// body.
pub fn build_authenticate_body(
    identity: &HostingSigningIdentity<'_>,
    session_id: &str,
    challenge: &str,
    recipient_did: &str,
    now_epoch: u64,
    session_pubkey_b58btc: Option<&str>,
) -> Result<String, AuthMessageError> {
    let id_token = build_siop_id_token(identity, challenge, recipient_did, now_epoch)?;

    // Trust-Task envelope. The did-hosting task identifier is a flat,
    // exact-match-routed URL (`…/did-hosting/auth/authenticate/1.0`), not a
    // framework `/spec/<slug>/<ver>` `TypeUri` — so the server parses a
    // minimal envelope by hand (`type` + `payload`) and string-matches the
    // type via `v1_aliases`, rather than deserializing a
    // `trust_tasks_rs::TrustTask<Value>` (whose strict `TypeUri` field
    // would reject the flat URL). We emit `id` + `type` + `payload`; the
    // server ignores `id`.
    let mut payload = json!({
        "id_token": id_token,
        "session_id": session_id,
    });
    if let Some(pk) = session_pubkey_b58btc {
        payload["session_pubkey_b58btc"] = json!(pk);
    }

    let envelope = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "type": TASK_AUTH_AUTHENTICATE_1_0,
        "payload": payload,
    });

    serde_json::to_string(&envelope).map_err(|e| AuthMessageError::Serialize(e.to_string()))
}

/// Construct + sign the compact EdDSA `id_token` JWS.
///
/// Byte-for-byte mirror of the shape
/// `did_hosting_common::server::didcomm_unpack::verify_siop_id_token`
/// verifies: header `{"alg":"EdDSA","typ":"JWT","kid":"<did>#<mb>"}`,
/// payload `{iss,sub,aud,nonce,iat,exp}` with `iss == sub`, signature
/// over `"<header_b64>.<payload_b64>"`.
fn build_siop_id_token(
    identity: &HostingSigningIdentity<'_>,
    challenge: &str,
    recipient_did: &str,
    now_epoch: u64,
) -> Result<String, AuthMessageError> {
    let signing_key = SigningKey::from_bytes(identity.signing_key);
    let (did_key, multibase) = ed25519_did_key(&signing_key);
    let kid = format!("{did_key}#{multibase}");

    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": kid,
    });
    let payload = json!({
        "iss": did_key,
        "sub": did_key,
        "aud": recipient_did,
        "nonce": challenge,
        "iat": now_epoch,
        "exp": now_epoch + ID_TOKEN_TTL_SECS,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|e| AuthMessageError::Serialize(e.to_string()))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload).map_err(|e| AuthMessageError::Serialize(e.to_string()))?,
    );

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Derive the Ed25519 `did:key` for a signing key. Returns
/// `(did, multibase)` where `did = "did:key:<multibase>"` and
/// `multibase` is the base58btc encoding of `0xed01 ‖ pubkey`.
///
/// This matches the multicodec/multibase shape the server's
/// `ed25519_pubkey_from_did_key` decodes (multicodec `0xed01`,
/// base58btc `z…` prefix).
fn ed25519_did_key(signing_key: &SigningKey) -> (String, String) {
    let pubkey = signing_key.verifying_key().to_bytes();
    let mut multicodec = Vec::with_capacity(2 + pubkey.len());
    multicodec.extend_from_slice(&[0xed, 0x01]);
    multicodec.extend_from_slice(&pubkey);
    let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
    let did = format!("did:key:{multibase}");
    (did, multibase)
}

/// Construct the wire body for `POST /api/auth/refresh`.
///
/// Refresh is unchanged from the legacy flow: it carries the refresh
/// token in a DIDComm-style envelope. The control-plane refresh path
/// was out of scope for the SIOPv2 cutover, so this still produces the
/// `MSG_AUTH_RESPONSE`-typed signed envelope the daemon expects on the
/// refresh endpoint.
pub fn build_refresh_message(
    identity: &HostingSigningIdentity<'_>,
    refresh_token: &str,
    now_epoch: u64,
    recipient_did: &str,
) -> Result<String, AuthMessageError> {
    use affinidi_tdk::didcomm::Message;
    use affinidi_tdk::didcomm::message::pack;

    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        MSG_AUTH_RESPONSE.to_string(),
        json!({ "refresh_token": refresh_token }),
    )
    .from(identity.did.to_string())
    .to(recipient_did.to_string())
    .created_time(now_epoch)
    .finalize();

    let kid = identity.kid();
    pack::pack_signed(&msg, &kid, identity.signing_key)
        .map_err(|e| AuthMessageError::Pack(e.to_string()))
}

/// Failure modes for the authenticate / refresh body constructors.
#[derive(Debug, thiserror::Error)]
pub enum AuthMessageError {
    /// JSON serialization of the envelope / JWS parts failed. Should
    /// be unreachable for the fixed shapes we build — surfaced as
    /// defence-in-depth.
    #[error("serialize failed: {0}")]
    Serialize(String),
    /// `pack_signed` rejected the refresh message. Carries the
    /// upstream error message; the most likely cause is a malformed
    /// DID or an invalid signing-key length, both of which the
    /// constructor types should make impossible.
    #[error("pack_signed failed: {0}")]
    Pack(String),
}

#[cfg(test)]
mod tests {
    use super::super::HostingSigningIdentityOwned;
    use super::*;

    /// The pack/sign primitives need a real Ed25519 secret. We use a
    /// fixed test vector so the test runs without `OsRng`.
    fn test_identity() -> HostingSigningIdentityOwned {
        HostingSigningIdentityOwned::new(
            "did:webvh:Q1:example.com:alice",
            *b"01234567890123456789012345678901",
        )
    }

    /// The body parses as a Trust-Task envelope with the canonical
    /// authenticate `type` and an `AuthenticatePayload`-shaped payload.
    #[test]
    fn authenticate_body_is_trust_task_envelope() {
        let owned = test_identity();
        let id = owned.borrow();
        let body = build_authenticate_body(
            &id,
            "sess-123",
            "deadbeefcafe",
            "did:key:server-rp",
            1_700_000_000,
            None,
        )
        .expect("build must succeed");

        let v: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(
            v.get("type").and_then(|t| t.as_str()),
            Some(TASK_AUTH_AUTHENTICATE_1_0)
        );
        assert!(v.get("id").and_then(|i| i.as_str()).is_some());
        let payload = v.get("payload").expect("payload present");
        assert_eq!(
            payload.get("session_id").and_then(|s| s.as_str()),
            Some("sess-123")
        );
        assert!(payload.get("id_token").and_then(|t| t.as_str()).is_some());
        // Optional pubkey omitted → absent (matches the server's
        // `skip_serializing_if = "Option::is_none"`).
        assert!(payload.get("session_pubkey_b58btc").is_none());
    }

    /// The optional session pubkey is carried through verbatim when
    /// supplied.
    #[test]
    fn authenticate_body_carries_optional_session_pubkey() {
        let owned = test_identity();
        let id = owned.borrow();
        let body = build_authenticate_body(
            &id,
            "sess-1",
            "n0nce",
            "did:key:rp",
            1,
            Some("z6MkSessionKey"),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["payload"]
                .get("session_pubkey_b58btc")
                .and_then(|s| s.as_str()),
            Some("z6MkSessionKey")
        );
    }

    /// The `id_token` is a compact JWS whose header and payload match
    /// the server's expected shape: `iss == sub`, both equal to a
    /// derived `did:key`, `kid == "<did>#<multibase>"`, `exp == iat + 300`,
    /// `nonce == challenge`, `aud == recipient_did`.
    #[test]
    fn id_token_matches_server_expected_shape() {
        let owned = test_identity();
        let id = owned.borrow();
        let token = build_siop_id_token(&id, "the-challenge", "did:key:rp", 1_700_000_000)
            .expect("token builds");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has three parts");

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        let kid = header["kid"].as_str().unwrap();

        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let iss = payload["iss"].as_str().unwrap();
        let sub = payload["sub"].as_str().unwrap();
        assert_eq!(iss, sub, "iss must equal sub");
        assert!(iss.starts_with("did:key:z6Mk"), "iss is an Ed25519 did:key");
        let multibase = iss.strip_prefix("did:key:").unwrap();
        assert_eq!(
            kid,
            format!("{iss}#{multibase}"),
            "kid is <did>#<multibase>"
        );
        assert_eq!(payload["aud"], "did:key:rp");
        assert_eq!(payload["nonce"], "the-challenge");
        assert_eq!(payload["iat"], 1_700_000_000u64);
        assert_eq!(payload["exp"], 1_700_000_000u64 + 300);
    }

    /// The signature must verify against the derived public key over
    /// the `"header.payload"` ASCII bytes — the exact check the server
    /// runs. Proves we're signing the right input with the right key.
    #[test]
    fn id_token_signature_verifies_against_derived_key() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let owned = test_identity();
        let id = owned.borrow();
        let token = build_siop_id_token(&id, "n", "rp", 1).unwrap();
        let parts: Vec<&str> = token.split('.').collect();

        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let iss = payload["iss"].as_str().unwrap();
        let multibase = iss.strip_prefix("did:key:").unwrap();
        let (_base, mc) = multibase::decode(multibase).unwrap();
        let pubkey: [u8; 32] = mc.strip_prefix(&[0xed, 0x01]).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pubkey).unwrap();

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        vk.verify(signing_input.as_bytes(), &sig)
            .expect("signature must verify");
    }

    /// Different challenges → different tokens (different `nonce` →
    /// different signed bytes). Pins that the constructor isn't
    /// caching.
    #[test]
    fn different_challenges_produce_different_tokens() {
        let owned = test_identity();
        let id = owned.borrow();
        let a = build_siop_id_token(&id, "aaa", "rp", 1).unwrap();
        let b = build_siop_id_token(&id, "bbb", "rp", 1).unwrap();
        assert_ne!(a, b);
    }

    /// The refresh message still packs to a JWS envelope (unchanged
    /// path).
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
}

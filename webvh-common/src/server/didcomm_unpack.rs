//! Helper for unpacking DIDComm signed (JWS) messages using DID resolution.
//!
//! The v0.13 `affinidi-messaging-didcomm` crate removed the async `Message::unpack_string`
//! method that internally resolved DIDs. This module provides an equivalent by:
//!
//! 1. Parsing the JWS protected header to extract the signer's key ID (kid).
//! 2. Resolving the DID document via `DIDCacheClient` to obtain the Ed25519 verifying key.
//! 3. Calling the low-level `unpack()` function with the resolved public key.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::did_common::DocumentExt;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::UnpackResult;
use affinidi_tdk::didcomm::jws::envelope::{Jws, JwsProtectedHeader};
use affinidi_tdk::didcomm::message::unpack;
use base64::Engine;

use super::error::AppError;

/// Extract the signer's key ID from a JWS protected header without verifying the signature.
///
/// Rejects multi-signature JWS envelopes outright — the threat model assumes a
/// single signer and accepting additional signatures silently would create
/// surprising states (which signature did we verify? which one bound the
/// `from` field?). If multi-sig becomes a real requirement, the decision
/// belongs in a separate, deliberate API.
fn extract_signer_kid(jws_str: &str) -> Result<String, AppError> {
    let jws: Jws = serde_json::from_str(jws_str)
        .map_err(|e| AppError::Authentication(format!("invalid JWS JSON: {e}")))?;

    if jws.signatures.is_empty() {
        return Err(AppError::Authentication("JWS has no signatures".into()));
    }
    if jws.signatures.len() > 1 {
        return Err(AppError::Authentication(format!(
            "JWS has {} signatures; only single-signer envelopes are accepted",
            jws.signatures.len()
        )));
    }

    let sig = &jws.signatures[0];

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&sig.protected)
        .map_err(|e| AppError::Authentication(format!("invalid JWS protected header: {e}")))?;

    let header: JwsProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| AppError::Authentication(format!("invalid JWS header JSON: {e}")))?;

    header
        .kid
        .ok_or_else(|| AppError::Authentication("JWS header missing kid".into()))
}

/// Resolve an Ed25519 verifying key from a DID document given a key ID (DID URL fragment).
///
/// Rejects verification methods whose `type` declares them as X25519
/// key-agreement keys. Ed25519 (signing) and X25519 (DH) keys are both 32
/// bytes, so the length check below would not catch a kid that points at
/// the wrong key type — the operator would just see a mysterious "unpack
/// failed" downstream. An explicit type-class check produces a precise
/// error and avoids confusing-key-purpose attacks where a DID document
/// publishes both signing and key-agreement keys under predictable
/// fragments.
async fn resolve_verifying_key(
    did_resolver: &DIDCacheClient,
    kid: &str,
) -> Result<[u8; 32], AppError> {
    let base_did = kid.split('#').next().unwrap_or(kid);

    let resolved = did_resolver
        .resolve(base_did)
        .await
        .map_err(|e| AppError::Authentication(format!("failed to resolve DID {base_did}: {e}")))?;

    let vm = resolved.doc.get_verification_method(kid).ok_or_else(|| {
        AppError::Authentication(format!(
            "verification method {kid} not found in DID document"
        ))
    })?;

    // Reject obvious key-agreement (X25519) types. We don't whitelist Ed25519
    // types because the spec admits several names (Ed25519VerificationKey2018,
    // Ed25519VerificationKey2020, Multikey with a z6Mk… prefix, JsonWebKey2020
    // with crv:Ed25519) — but X25519 has narrow, well-known type names that
    // are unambiguous to refuse.
    let vm_type = vm.type_.as_str();
    if matches!(
        vm_type,
        "X25519KeyAgreementKey2020" | "X25519KeyAgreementKey2019"
    ) {
        return Err(AppError::Authentication(format!(
            "verification method {kid} is an X25519 key-agreement key; expected an Ed25519 signing key"
        )));
    }

    let pk_bytes = vm
        .get_public_key_bytes()
        .map_err(|e| AppError::Authentication(format!("failed to get public key bytes: {e}")))?;

    pk_bytes
        .try_into()
        .map_err(|_| AppError::Authentication("public key must be 32 bytes".into()))
}

/// Unpack a DIDComm signed (JWS) message and verify the JWS signer matches `msg.from`.
///
/// Resolves the signer's public key from the JWS protected-header `kid`, verifies
/// the signature, then asserts that the verified signer's DID equals the message's
/// `from` DID (compared on base, ignoring `#fragment`). Returns the unpacked `Message`
/// and the *verified* signer base DID.
///
/// **Security:** Callers must use the returned base DID for sender identification.
/// Trusting `msg.from` directly allows an attacker who controls any DID to forge the
/// `from` field while signing with their own key.
///
/// The message must:
/// - Be signed (plaintext and encrypted-only payloads are rejected — those would not
///   carry a verified signer identity).
/// - Carry a `from` field whose base DID matches the JWS signer.
/// - Have a `created_time` inside the 5-minute freshness window (with 60s future tolerance).
pub async fn unpack_signed(
    input: &str,
    did_resolver: &DIDCacheClient,
) -> Result<(Message, String), AppError> {
    let kid = extract_signer_kid(input)?;
    let verifying_key = resolve_verifying_key(did_resolver, &kid).await?;

    let result = unpack::unpack(input, None, None, None, Some(&verifying_key))
        .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    let (message, signer_kid) = match result {
        UnpackResult::Signed {
            message,
            signer_kid,
        } => (message, signer_kid),
        UnpackResult::Plaintext(_) => {
            return Err(AppError::Authentication(
                "message is not signed; refusing to authenticate plaintext".into(),
            ));
        }
        UnpackResult::Encrypted { .. } => {
            return Err(AppError::Authentication(
                "message is encrypted-only; expected JWS-signed envelope".into(),
            ));
        }
    };

    // Signer kid is always present for Signed results; the resolver already used it.
    let signer_kid = signer_kid.unwrap_or(kid);
    let signer_base = signer_kid
        .split('#')
        .next()
        .unwrap_or(&signer_kid)
        .to_string();

    let claimed_from = message
        .from
        .as_deref()
        .ok_or_else(|| AppError::Authentication("signed message is missing `from` field".into()))?;
    let claimed_base = claimed_from.split('#').next().unwrap_or(claimed_from);
    if signer_base != claimed_base {
        return Err(AppError::Authentication(
            "JWS signer does not match message `from` DID".into(),
        ));
    }

    if let Some(created_time) = message.created_time {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let max_age = 300; // 5 minutes
        if now.saturating_sub(created_time) > max_age {
            return Err(AppError::Authentication(
                "message too old (created_time exceeds 5-minute window)".into(),
            ));
        }
        if created_time > now + 60 {
            return Err(AppError::Authentication(
                "message created_time is in the future".into(),
            ));
        }
    }

    Ok((message, signer_base))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `extract_signer_kid` must return the kid embedded in the JWS protected
    /// header. This is the input to the signer-verification flow; if it
    /// regressed to "the first available kid" or similar, the bypass would
    /// reopen.
    #[test]
    fn extract_signer_kid_reads_protected_header_kid() {
        // Build a synthetic JWS envelope with a known kid.
        // protected = base64url({"kid":"did:example:123#key-1","alg":"EdDSA"})
        let header_json = serde_json::json!({
            "kid": "did:example:123#key-1",
            "alg": "EdDSA",
        });
        let protected_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&header_json).unwrap(),
        );
        let jws = serde_json::json!({
            "payload": "ignored",
            "signatures": [
                {
                    "protected": protected_b64,
                    "signature": "ignored",
                }
            ],
        });
        let kid = extract_signer_kid(&jws.to_string()).unwrap();
        assert_eq!(kid, "did:example:123#key-1");
    }

    #[test]
    fn extract_signer_kid_rejects_envelope_without_signatures() {
        let jws = serde_json::json!({ "payload": "ignored", "signatures": [] });
        assert!(extract_signer_kid(&jws.to_string()).is_err());
    }

    #[test]
    fn extract_signer_kid_rejects_envelope_with_no_kid() {
        let header_json = serde_json::json!({ "alg": "EdDSA" });
        let protected_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&header_json).unwrap(),
        );
        let jws = serde_json::json!({
            "payload": "ignored",
            "signatures": [{ "protected": protected_b64, "signature": "ignored" }],
        });
        assert!(extract_signer_kid(&jws.to_string()).is_err());
    }

    #[test]
    fn extract_signer_kid_rejects_invalid_json() {
        assert!(extract_signer_kid("not-json").is_err());
    }

    #[test]
    fn extract_signer_kid_rejects_multi_signature_envelope() {
        let header_json = serde_json::json!({ "kid": "did:example:123#key-1", "alg": "EdDSA" });
        let protected_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&header_json).unwrap(),
        );
        let jws = serde_json::json!({
            "payload": "ignored",
            "signatures": [
                { "protected": protected_b64.clone(), "signature": "ignored" },
                { "protected": protected_b64, "signature": "second" },
            ],
        });
        let err = extract_signer_kid(&jws.to_string()).unwrap_err();
        match err {
            AppError::Authentication(msg) => assert!(
                msg.contains("only single-signer"),
                "expected multi-sig rejection message, got: {msg}",
            ),
            other => panic!("expected Authentication, got {other:?}"),
        }
    }
}

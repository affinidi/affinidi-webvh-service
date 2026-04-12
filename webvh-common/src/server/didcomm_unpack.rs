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
fn extract_signer_kid(jws_str: &str) -> Result<String, AppError> {
    let jws: Jws = serde_json::from_str(jws_str)
        .map_err(|e| AppError::Authentication(format!("invalid JWS JSON: {e}")))?;

    let sig = jws
        .signatures
        .first()
        .ok_or_else(|| AppError::Authentication("JWS has no signatures".into()))?;

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

    let pk_bytes = vm
        .get_public_key_bytes()
        .map_err(|e| AppError::Authentication(format!("failed to get public key bytes: {e}")))?;

    pk_bytes
        .try_into()
        .map_err(|_| AppError::Authentication("public key must be 32 bytes".into()))
}

/// Unpack a DIDComm signed (JWS) message by resolving the signer's public key from their DID.
///
/// Returns the unpacked `Message` and the signer's key ID (if present in the JWS header).
pub async fn unpack_signed(
    input: &str,
    did_resolver: &DIDCacheClient,
) -> Result<(Message, Option<String>), AppError> {
    let kid = extract_signer_kid(input)?;
    let verifying_key = resolve_verifying_key(did_resolver, &kid).await?;

    let result = unpack::unpack(input, None, None, None, Some(&verifying_key))
        .map_err(|e| AppError::Authentication(format!("failed to unpack message: {e}")))?;

    match result {
        UnpackResult::Signed {
            message,
            signer_kid,
        } => {
            // Validate message freshness — reject messages older than 5 minutes
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
            Ok((message, signer_kid))
        }
        UnpackResult::Plaintext(message) => Ok((message, None)),
        UnpackResult::Encrypted { message, .. } => Ok((message, None)),
    }
}

use std::sync::Arc;

use affinidi_tdk::dids::{DID, KeyType};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::parameters::Parameters;
use serde_json::json;

use crate::error::{Result, WebVHError};

/// Generate a new Ed25519 did:key identity.
///
/// Returns `(did, secret)` where `did` is the DID string and `secret`
/// is the signing key needed for authentication and DID operations.
pub fn generate_ed25519_identity() -> Result<(String, Secret)> {
    DID::generate_did_key(KeyType::Ed25519)
        .map_err(|e| WebVHError::DIDComm(format!("failed to generate did:key: {e}")))
}

/// Encode a server URL into the host component used in `did:webvh` identifiers.
///
/// Ports are percent-encoded (`:` becomes `%3A`), matching the did:webvh spec.
///
/// # Examples
/// - `http://localhost:8085` -> `localhost%3A8085`
/// - `https://example.com`   -> `example.com`
pub fn encode_host(server_url: &str) -> Result<String> {
    let parsed = url::Url::parse(server_url)
        .map_err(|e| WebVHError::DIDComm(format!("invalid server URL: {e}")))?;

    let host_str = parsed
        .host_str()
        .ok_or_else(|| WebVHError::DIDComm("server URL has no host".into()))?;

    Ok(match parsed.port() {
        Some(port) => format!("{host_str}%3A{port}"),
        None => host_str.to_string(),
    })
}

/// Build a standard DID document with `{SCID}` placeholders.
///
/// The returned JSON value uses the did:webvh identifier format with a
/// single Ed25519 verification method at `#key-0`.
pub fn build_did_document(
    host: &str,
    mnemonic: &str,
    public_key_multibase: &str,
) -> serde_json::Value {
    let did_path = mnemonic.replace('/', ":");
    let did_id = format!("did:webvh:{{SCID}}:{host}:{did_path}");

    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did_id,
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")],
        "verificationMethod": [{
            "id": format!("{did_id}#key-0"),
            "type": "Multikey",
            "controller": did_id,
            "publicKeyMultibase": public_key_multibase,
        }],
    })
}

/// Create a WebVH log entry from a DID document and signing secret.
///
/// Returns `(scid, jsonl)` where:
/// - `scid` is the self-certifying identifier derived from the log entry
/// - `jsonl` is the serialized log entry ready for upload to the server
pub fn create_log_entry(
    did_document: &serde_json::Value,
    secret: &Secret,
) -> Result<(String, String)> {
    let public_key_multibase = secret
        .get_public_keymultibase()
        .map_err(|e| WebVHError::DIDComm(format!("failed to get public key multibase: {e}")))?;

    let mut state = DIDWebVHState::default();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![public_key_multibase])),
        ..Default::default()
    };

    state
        .create_log_entry(None, did_document, &params, secret)
        .map_err(|e| WebVHError::DIDComm(format!("failed to create WebVH log entry: {e}")))?;

    let scid = state.scid.clone();

    let jsonl: String = state
        .log_entries
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");

    Ok((scid, jsonl))
}

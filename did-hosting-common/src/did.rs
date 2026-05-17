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

/// Construct a `did:web` identifier from a server URL and mnemonic.
///
/// Follows the did:web method spec:
/// - `did:web:example.com` for the root DID (mnemonic = `.well-known`)
/// - `did:web:host:path` for path-based DIDs
/// - Ports are percent-encoded (`:` → `%3A`)
/// - Path separators (`/`) become `:`
///
/// # Examples
/// ```
/// # use did_hosting_common::did::build_did_web_id;
/// assert_eq!(build_did_web_id("https://example.com", "my-did").unwrap(), "did:web:example.com:my-did");
/// assert_eq!(build_did_web_id("https://example.com", ".well-known").unwrap(), "did:web:example.com");
/// ```
pub fn build_did_web_id(server_url: &str, mnemonic: &str) -> Result<String> {
    let host = encode_host(server_url)?;
    if mnemonic == ".well-known" {
        Ok(format!("did:web:{host}"))
    } else {
        let path = mnemonic.replace('/', ":");
        Ok(format!("did:web:{host}:{path}"))
    }
}

/// Options for building a DID document beyond the required signing key.
#[derive(Default)]
pub struct DidDocumentOptions<'a> {
    /// X25519 key agreement public key (multibase-encoded). When set, a
    /// `keyAgreement` verification method (`#key-1`) is added to the document.
    /// Required for DIDComm encrypted messaging.
    pub key_agreement_multibase: Option<&'a str>,
    /// Mediator DID or URL for the `DIDCommMessaging` service endpoint.
    /// When set, a `DIDCommMessaging` service is added so other parties
    /// know how to route messages to this DID.
    pub mediator_endpoint: Option<&'a str>,
}

/// Build a standard DID document with `{SCID}` placeholders.
///
/// The returned JSON value uses the did:webvh identifier format with an
/// Ed25519 verification method at `#key-0`. Additional keys and services
/// can be added via [`DidDocumentOptions`].
pub fn build_did_document(
    host: &str,
    mnemonic: &str,
    public_key_multibase: &str,
    opts: &DidDocumentOptions<'_>,
) -> serde_json::Value {
    let did_path = mnemonic.replace('/', ":");
    let did_id = format!("did:webvh:{{SCID}}:{host}:{did_path}");

    let mut vm = vec![json!({
        "id": format!("{did_id}#key-0"),
        "type": "Multikey",
        "controller": &did_id,
        "publicKeyMultibase": public_key_multibase,
    })];

    // @context matches the upstream webvh VTA templates' output (W3C DID v1 +
    // CID v1). Keep these two in sync: the setup wizards have the VTA render
    // most webvh DIDs via the template, but bootstrap_did() still builds the
    // `.well-known` root DID locally with this helper — both shapes must be
    // identical so callers and resolvers don't see drift.
    let mut doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1",
        ],
        "id": did_id,
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")],
    });

    // Add X25519 key agreement key
    if let Some(ka_key) = opts.key_agreement_multibase {
        vm.push(json!({
            "id": format!("{did_id}#key-1"),
            "type": "Multikey",
            "controller": &did_id,
            "publicKeyMultibase": ka_key,
        }));
        doc["keyAgreement"] = json!([format!("{did_id}#key-1")]);
    }

    doc["verificationMethod"] = json!(vm);

    // Add services. Service id is `#vta-didcomm` to match the VTA
    // webvh VTA templates — not the older `#didcomm` convention.
    let mut services = vec![];
    if let Some(mediator) = opts.mediator_endpoint {
        services.push(json!({
            "id": format!("{did_id}#vta-didcomm"),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "accept": ["didcomm/v2"],
                "uri": mediator,
            }],
        }));
    }
    if !services.is_empty() {
        doc["service"] = json!(services);
    }

    doc
}

/// Create a WebVH log entry from a DID document and signing secret.
///
/// Returns `(scid, jsonl)` where:
/// - `scid` is the self-certifying identifier derived from the log entry
/// - `jsonl` is the serialized log entry ready for upload to the server
pub async fn create_log_entry(
    did_document: &serde_json::Value,
    secret: &Secret,
) -> Result<(String, String)> {
    let public_key_multibase = secret
        .get_public_keymultibase()
        .map_err(|e| WebVHError::DIDComm(format!("failed to get public key multibase: {e}")))?;

    // didwebvh-rs 0.3 requires the signing key's verification_method to
    // contain '#' followed by the multibase public key.
    let mut signing_key = secret.clone();
    if !signing_key.id.contains('#') {
        signing_key.id = format!("did:key:{public_key_multibase}#{public_key_multibase}");
    }

    let mut state = DIDWebVHState::default();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![public_key_multibase.into()])),
        ..Default::default()
    };

    state
        .create_log_entry(None, did_document, &params, &signing_key)
        .await
        .map_err(|e| WebVHError::DIDComm(format!("failed to create WebVH log entry: {e}")))?;

    let scid = state.scid().to_string();

    let lines: Vec<String> = state
        .log_entries()
        .iter()
        .map(|e| {
            serde_json::to_string(&e.log_entry)
                .map_err(|e| WebVHError::DIDComm(format!("failed to serialize log entry: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let jsonl = lines.join("\n");

    Ok((scid, jsonl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_host_with_port() {
        let result = encode_host("http://localhost:8085").unwrap();
        assert_eq!(result, "localhost%3A8085");
    }

    #[test]
    fn encode_host_without_port() {
        let result = encode_host("https://example.com").unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn encode_host_invalid_url() {
        assert!(encode_host("not-a-url").is_err());
    }

    #[test]
    fn build_did_web_id_simple() {
        assert_eq!(
            build_did_web_id("https://example.com", "my-did").unwrap(),
            "did:web:example.com:my-did"
        );
    }

    #[test]
    fn build_did_web_id_with_port() {
        assert_eq!(
            build_did_web_id("http://localhost:8530", "my-did").unwrap(),
            "did:web:localhost%3A8530:my-did"
        );
    }

    #[test]
    fn build_did_web_id_nested_path() {
        assert_eq!(
            build_did_web_id("https://example.com", "people/staff").unwrap(),
            "did:web:example.com:people:staff"
        );
    }

    #[test]
    fn build_did_web_id_well_known() {
        assert_eq!(
            build_did_web_id("https://example.com", ".well-known").unwrap(),
            "did:web:example.com"
        );
    }

    #[test]
    fn build_did_web_id_invalid_url() {
        assert!(build_did_web_id("not-a-url", "test").is_err());
    }

    #[test]
    fn build_did_document_correct_did_id() {
        let doc = build_did_document(
            "example.com%3A8085",
            "mypath",
            "z6Mk...",
            &Default::default(),
        );
        let id = doc["id"].as_str().unwrap();
        assert!(id.starts_with("did:webvh:{SCID}:example.com%3A8085:"));
        assert!(id.ends_with(":mypath"));
    }

    #[test]
    fn build_did_document_nested_path() {
        let doc = build_did_document(
            "example.com",
            "people/staff/glenn",
            "z6Mk...",
            &Default::default(),
        );
        let id = doc["id"].as_str().unwrap();
        assert!(id.contains(":people:staff:glenn"));
        assert!(!id.contains('/'));
    }

    #[test]
    fn build_did_document_structure() {
        let doc = build_did_document("example.com", "test", "z6MkPubKey", &Default::default());
        let context = doc["@context"].as_array().expect("@context is array");
        assert_eq!(
            context,
            &vec![
                serde_json::Value::String("https://www.w3.org/ns/did/v1".to_string()),
                serde_json::Value::String("https://www.w3.org/ns/cid/v1".to_string()),
            ]
        );
        assert!(doc["authentication"].is_array());
        assert!(doc["verificationMethod"].is_array());
        let vm = &doc["verificationMethod"][0];
        assert_eq!(vm["type"], "Multikey");
        assert_eq!(vm["publicKeyMultibase"], "z6MkPubKey");
        assert!(doc.get("service").is_none());
    }

    #[test]
    fn build_did_document_with_vta_didcomm_service() {
        let doc = build_did_document(
            "example.com",
            "test",
            "z6MkPubKey",
            &DidDocumentOptions {
                mediator_endpoint: Some("did:example:mediator"),
                ..Default::default()
            },
        );
        let service = &doc["service"];
        assert!(service.is_array());
        let svc = &service[0];
        assert!(svc["id"].as_str().unwrap().ends_with("#vta-didcomm"));
        assert_eq!(svc["type"], "DIDCommMessaging");
        assert_eq!(svc["serviceEndpoint"][0]["uri"], "did:example:mediator");
        assert_eq!(svc["serviceEndpoint"][0]["accept"][0], "didcomm/v2");
    }

    /// Locks the local builder's output to the shape produced by the VTA
    /// webvh VTA templates. Update both sides together if either ever
    /// moves. Covers: contexts, key-0 and key-1 verification method IDs,
    /// `#vta-didcomm` service ID, single-entry service array.
    #[test]
    fn build_did_document_matches_webvh_service_template() {
        let doc = build_did_document(
            "example.com",
            "control",
            "z6MkSigning",
            &DidDocumentOptions {
                key_agreement_multibase: Some("z6LSKA"),
                mediator_endpoint: Some("did:webvh:QmMED:mediator.example.com"),
            },
        );
        let did_id = doc["id"].as_str().unwrap();

        // @context
        assert_eq!(
            doc["@context"][0], "https://www.w3.org/ns/did/v1",
            "first context entry"
        );
        assert_eq!(
            doc["@context"][1], "https://www.w3.org/ns/cid/v1",
            "second context entry (cid v1)"
        );
        assert_eq!(
            doc["@context"].as_array().unwrap().len(),
            2,
            "no extra contexts"
        );

        // Verification methods
        let vm = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(vm.len(), 2);
        assert_eq!(vm[0]["id"], format!("{did_id}#key-0"));
        assert_eq!(vm[0]["type"], "Multikey");
        assert_eq!(vm[0]["controller"], did_id);
        assert_eq!(vm[1]["id"], format!("{did_id}#key-1"));
        assert_eq!(vm[1]["type"], "Multikey");

        // Purpose relations
        assert_eq!(doc["assertionMethod"][0], format!("{did_id}#key-0"));
        assert_eq!(doc["authentication"][0], format!("{did_id}#key-0"));
        assert_eq!(doc["keyAgreement"][0], format!("{did_id}#key-1"));

        // Service — single entry with `#vta-didcomm`
        let service = doc["service"].as_array().unwrap();
        assert_eq!(service.len(), 1, "exactly one service entry");
        assert_eq!(service[0]["id"], format!("{did_id}#vta-didcomm"));
        assert_eq!(service[0]["type"], "DIDCommMessaging");
        assert_eq!(
            service[0]["serviceEndpoint"][0]["uri"],
            "did:webvh:QmMED:mediator.example.com"
        );
        assert_eq!(service[0]["serviceEndpoint"][0]["accept"][0], "didcomm/v2");
    }
}

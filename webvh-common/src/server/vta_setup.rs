//! Shared VTA (Verifiable Trust Architecture) setup helpers.
//!
//! Used by all three service setup wizards to authenticate with VTA,
//! create DIDs, and retrieve key material.

use std::path::Path;

use std::collections::HashMap;
use std::sync::Mutex;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use vta_sdk::client::VtaClient;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::session::{SessionBackend, SessionStore};

/// Metadata from a successful VTA connection.
pub struct VtaConnectionInfo {
    pub vta_url: String,
    pub vta_did: String,
    pub context_id: String,
    pub client_did: String,
}

/// Result of creating or retrieving a DID via VTA.
pub struct VtaDidResult {
    pub did: String,
    pub scid: String,
    /// Ed25519 private key (multibase-encoded).
    pub signing_key: String,
    /// X25519 private key (multibase-encoded).
    pub key_agreement_key: String,
    /// DID log entry (JSONL), present only for newly created DIDs.
    pub log_entry: Option<String>,
}

/// In-memory session backend for ephemeral setup sessions.
///
/// The setup handshake only needs the session for the duration of the
/// wizard — no persistence needed. This avoids touching disk or
/// requiring any specific secrets backend to be configured.
struct InMemoryBackend {
    data: Mutex<HashMap<String, String>>,
}

impl SessionBackend for InMemoryBackend {
    fn load(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn clear(&self, key: &str) {
        self.data.lock().unwrap().remove(key);
    }
}

/// Decode a VTA credential, authenticate, and return a connected client.
///
/// The credential is the base64url string issued by the VTA operator.
/// An in-memory session backend is used for the ephemeral setup handshake.
pub async fn connect_vta(
    credential_b64: &str,
) -> Result<(VtaClient, VtaConnectionInfo), Box<dyn std::error::Error>> {
    let bundle = CredentialBundle::decode(credential_b64)?;

    let vta_url = bundle
        .vta_url
        .clone()
        .ok_or("VTA credential does not contain a vta_url")?;

    // Use an in-memory backend — the session is only needed for this setup run
    let backend = InMemoryBackend {
        data: Mutex::new(HashMap::new()),
    };
    let store = SessionStore::with_backend(Box::new(backend));
    let session_key = "setup";

    let login_result = store.login(credential_b64, &vta_url, session_key).await?;

    let client = store.connect(session_key, Some(&vta_url)).await?;

    // Discover the context: list contexts and pick the one the credential has access to
    let contexts = client.list_contexts().await?;
    let context_id = if contexts.contexts.len() == 1 {
        contexts.contexts[0].id.clone()
    } else if contexts.contexts.is_empty() {
        return Err("no VTA contexts found for this credential".into());
    } else {
        // If multiple contexts, return the first — the caller can override
        contexts.contexts[0].id.clone()
    };

    Ok((
        client,
        VtaConnectionInfo {
            vta_url,
            vta_did: login_result.vta_did,
            context_id,
            client_did: login_result.client_did,
        },
    ))
}

/// Resolve the mediator DID from the VTA's DID document.
///
/// Looks for a `DIDCommMessaging` service endpoint in the VTA DID document
/// that contains a DID URI (the mediator). Returns `None` if no mediator
/// is configured, if DID resolution fails, or if resolution times out.
pub async fn resolve_vta_mediator(vta_did: &str) -> Option<String> {
    eprintln!("  Checking VTA for mediator configuration...");

    // Use a timeout — DID resolution may hang if the network is unreachable
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        vta_sdk::session::resolve_mediator_did(vta_did),
    )
    .await
    {
        Ok(Ok(mediator)) => mediator,
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Create a new did:webvh via VTA and fetch its private keys.
///
/// The DID is created in "serverless" mode (no VTA-managed server registration).
/// The log entry is returned for the caller to import into webvh-server.
///
/// If `mediator_did` is provided, a `DIDCommMessaging` service endpoint
/// pointing to the mediator is embedded in the DID document.
pub async fn create_did(
    client: &VtaClient,
    context_id: &str,
    hosting_url: &str,
    path: &str,
    label: Option<&str>,
    mediator_did: Option<&str>,
) -> Result<VtaDidResult, Box<dyn std::error::Error>> {
    use vta_sdk::client::CreateDidWebvhRequest;

    // If a mediator DID is provided, add a DIDCommMessaging service to the DID document
    let (add_mediator, additional_services) = match mediator_did {
        Some(did) => (
            true,
            Some(vec![serde_json::json!({
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": did,
                    "accept": ["didcomm/v2"]
                }
            })]),
        ),
        None => (false, None),
    };

    let req = CreateDidWebvhRequest {
        context_id: context_id.to_string(),
        server_id: None,
        url: Some(hosting_url.to_string()),
        path: Some(path.to_string()),
        label: label.map(|l| l.to_string()),
        portable: true,
        add_mediator_service: add_mediator,
        additional_services,
        pre_rotation_count: 0,
    };

    let result = client.create_did_webvh(req).await?;

    // Fetch private keys
    let signing_secret = client.get_key_secret(&result.signing_key_id).await?;
    let ka_secret = client.get_key_secret(&result.ka_key_id).await?;

    Ok(VtaDidResult {
        did: result.did,
        scid: result.scid,
        signing_key: signing_secret.private_key_multibase,
        key_agreement_key: ka_secret.private_key_multibase,
        log_entry: result.log_entry,
    })
}

/// Generate a standalone did:key admin identity (no VTA needed).
///
/// Returns `(did_string, private_key_multibase)`.
pub fn generate_admin_did_key() -> (String, String) {
    let secret = Secret::generate_ed25519(None, None);
    let pk_multibase = secret
        .get_public_keymultibase()
        .expect("ed25519 public key multibase");
    let sk_multibase = secret
        .get_private_keymultibase()
        .expect("ed25519 private key multibase");
    let did = format!("did:key:{pk_multibase}");
    (did, sk_multibase)
}

/// Write a DID log entry to a file for later bootstrap on webvh-server.
pub fn write_log_entry_file(log_entry: &str, output_path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, log_entry)
}

/// Generate a random Ed25519 key and return its multibase-encoded private key.
pub fn generate_ed25519_multibase() -> String {
    let secret = Secret::generate_ed25519(None, None);
    secret
        .get_private_keymultibase()
        .expect("ed25519 multibase encoding")
}

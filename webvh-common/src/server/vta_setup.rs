//! Shared VTA (Verifiable Trust Architecture) setup helpers.
//!
//! Used by all three service setup wizards to authenticate with VTA,
//! create DIDs, and retrieve key material.

use std::path::Path;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use vta_sdk::client::VtaClient;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::keys::KeyType;
use vta_sdk::session::SessionStore;
use vta_sdk::webvh::WebvhDidRecord;

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

/// Decode a VTA credential, authenticate, and return a connected client.
///
/// The credential is the base64url string issued by the VTA operator.
/// A temporary session store is used for the challenge-response handshake.
pub async fn connect_vta(
    credential_b64: &str,
) -> Result<(VtaClient, VtaConnectionInfo), Box<dyn std::error::Error>> {
    let bundle = CredentialBundle::decode(credential_b64)?;

    let vta_url = bundle
        .vta_url
        .clone()
        .ok_or("VTA credential does not contain a vta_url")?;

    // Use a temp directory for the throwaway session store
    let session_dir = std::env::temp_dir().join("webvh-vta-setup");
    std::fs::create_dir_all(&session_dir)?;

    let store = SessionStore::new("webvh-setup", session_dir);
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

/// Create a new did:webvh via VTA and fetch its private keys.
///
/// The DID is created in "serverless" mode (no VTA-managed server registration).
/// The log entry is returned for the caller to import into webvh-server.
pub async fn create_did(
    client: &VtaClient,
    context_id: &str,
    hosting_url: &str,
    path: &str,
    label: Option<&str>,
) -> Result<VtaDidResult, Box<dyn std::error::Error>> {
    use vta_sdk::client::CreateDidWebvhRequest;

    let req = CreateDidWebvhRequest {
        context_id: context_id.to_string(),
        server_id: None,
        url: Some(hosting_url.to_string()),
        path: Some(path.to_string()),
        label: label.map(|l| l.to_string()),
        portable: true,
        add_mediator_service: false,
        additional_services: None,
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

/// Retrieve keys for an existing DID from a VTA context.
///
/// Lists keys in the context and matches Ed25519 (signing) and X25519
/// (key agreement) keys, then fetches their private material.
pub async fn retrieve_did_keys(
    client: &VtaClient,
    did: &str,
    context_id: &str,
) -> Result<VtaDidResult, Box<dyn std::error::Error>> {
    // Verify the DID exists
    let did_record = client.get_did_webvh(did).await?;

    // List keys in this context
    let keys_resp = client
        .list_keys(0, 100, Some("active"), Some(context_id))
        .await?;

    let ed_key = keys_resp
        .keys
        .iter()
        .find(|k| k.key_type == KeyType::Ed25519)
        .ok_or("no active Ed25519 key found in VTA context")?;

    let x_key = keys_resp
        .keys
        .iter()
        .find(|k| k.key_type == KeyType::X25519)
        .ok_or("no active X25519 key found in VTA context")?;

    let signing_secret = client.get_key_secret(&ed_key.key_id).await?;
    let ka_secret = client.get_key_secret(&x_key.key_id).await?;

    Ok(VtaDidResult {
        did: did_record.did,
        scid: did_record.scid,
        signing_key: signing_secret.private_key_multibase,
        key_agreement_key: ka_secret.private_key_multibase,
        log_entry: None,
    })
}

/// List DIDs in a VTA context (for interactive selection).
pub async fn list_context_dids(
    client: &VtaClient,
    context_id: &str,
) -> Result<Vec<WebvhDidRecord>, Box<dyn std::error::Error>> {
    let resp = client.list_dids_webvh(Some(context_id), None).await?;
    Ok(resp.dids)
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

/// Generate a random X25519 key and return its multibase-encoded private key.
pub fn generate_x25519_multibase() -> String {
    let secret = Secret::generate_x25519(None, None).expect("x25519 key generation");
    secret
        .get_private_keymultibase()
        .expect("x25519 multibase encoding")
}

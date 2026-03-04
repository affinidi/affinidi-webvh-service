//! VTA Bootstrap — connects to a VTA to create DIDs for all WebVH services.
//!
//! Lightweight VTA client built with reqwest (no VTA SDK dependency).
//! Handles DIDComm auth (pack_encrypted) and the REST calls needed for
//! bootstrapping server, control, and witness DIDs.

use std::path::Path;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::didcomm::{Message, PackEncryptedOptions};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ---------------------------------------------------------------------------
// Credential bundle (decoded from base64url)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CredentialBundle {
    pub did: String,
    #[serde(rename = "privateKeyMultibase")]
    pub private_key_multibase: String,
    #[serde(rename = "vtaDid")]
    pub vta_did: String,
    #[serde(rename = "vtaUrl", default)]
    pub vta_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DidSecretsBundle {
    pub did: String,
    pub secrets: Vec<SecretEntry>,
}

#[derive(Debug, Serialize)]
pub struct SecretEntry {
    pub key_id: String,
    pub key_type: String,
    pub private_key_multibase: String,
}

// ---------------------------------------------------------------------------
// VTA API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    session_id: String,
    data: ChallengeData,
}

#[derive(Debug, Deserialize)]
struct ChallengeData {
    challenge: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    data: AuthData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthData {
    access_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateContextResponse {
    #[allow(dead_code)]
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateDidResponse {
    did: String,
    signing_key_id: String,
    ka_key_id: String,
    log_entry: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeySecretResponse {
    private_key_multibase: String,
}

// ---------------------------------------------------------------------------
// VTA Bootstrap Client
// ---------------------------------------------------------------------------

struct VtaBootstrapClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl VtaBootstrapClient {
    /// Authenticate with VTA via DIDComm pack_encrypted.
    async fn authenticate(
        base_url: &str,
        admin_did: &str,
        vta_did: &str,
        signing_secret: &Secret,
        ka_secret: &Secret,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let http = reqwest::Client::new();

        // DID resolver
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .map_err(|e| format!("failed to create DID resolver: {e}"))?;

        // Secrets resolver — needs both Ed25519 (signing) and X25519 (key agreement)
        let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;
        secrets_resolver.insert(signing_secret.clone()).await;
        secrets_resolver.insert(ka_secret.clone()).await;

        // 1. Request challenge
        let challenge_resp: ChallengeResponse = http
            .post(format!("{base_url}/auth/challenge"))
            .json(&json!({ "did": admin_did }))
            .send()
            .await?
            .error_for_status()
            .map_err(|e| format!("challenge request rejected: {e}"))?
            .json()
            .await?;

        // 2. Build DIDComm message
        let created_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();

        let msg = Message::build(
            uuid::Uuid::new_v4().to_string(),
            "https://affinidi.com/atm/1.0/authenticate".to_string(),
            json!({
                "challenge": challenge_resp.data.challenge,
                "session_id": challenge_resp.session_id,
            }),
        )
        .from(admin_did.to_string())
        .created_time(created_time)
        .finalize();

        // 3. Pack encrypted to VTA DID
        let (packed, _meta) = msg
            .pack_encrypted(
                vta_did,
                Some(admin_did),
                None,
                &did_resolver,
                &secrets_resolver,
                &PackEncryptedOptions {
                    forward: false,
                    ..PackEncryptedOptions::default()
                },
            )
            .await
            .map_err(|e| format!("failed to pack encrypted message: {e}"))?;

        // 4. Authenticate
        let auth_resp: AuthResponse = http
            .post(format!("{base_url}/auth/"))
            .header("content-type", "text/plain")
            .body(packed)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| format!("authentication rejected: {e}"))?
            .json()
            .await?;

        Ok(Self {
            base_url: base_url.to_string(),
            token: auth_resp.data.access_token,
            http,
        })
    }

    async fn create_context(
        &self,
        id: &str,
        name: &str,
    ) -> Result<CreateContextResponse, Box<dyn std::error::Error>> {
        let resp = self
            .http
            .post(format!("{}/contexts", self.base_url))
            .bearer_auth(&self.token)
            .json(&json!({
                "id": id,
                "name": name,
            }))
            .send()
            .await?;

        // 409 = context already exists, which is fine
        if resp.status() == reqwest::StatusCode::CONFLICT {
            return Ok(CreateContextResponse {
                id: id.to_string(),
            });
        }

        let resp = resp
            .error_for_status()
            .map_err(|e| format!("create context failed: {e}"))?;

        Ok(resp.json().await?)
    }

    async fn create_did_webvh(
        &self,
        context_id: &str,
        url: &str,
    ) -> Result<CreateDidResponse, Box<dyn std::error::Error>> {
        let resp = self
            .http
            .post(format!("{}/webvh/dids", self.base_url))
            .bearer_auth(&self.token)
            .json(&json!({
                "contextId": context_id,
                "url": url,
            }))
            .send()
            .await?
            .error_for_status()
            .map_err(|e| format!("create DID failed: {e}"))?;

        Ok(resp.json().await?)
    }

    async fn get_key_secret(
        &self,
        key_id: &str,
    ) -> Result<KeySecretResponse, Box<dyn std::error::Error>> {
        // Key IDs contain '#' which needs to be URL-encoded
        let encoded_key_id = key_id.replace('#', "%23");
        let resp = self
            .http
            .get(format!("{}/keys/{}/secret", self.base_url, encoded_key_id))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| format!("get key secret failed: {e}"))?;

        Ok(resp.json().await?)
    }
}

// ---------------------------------------------------------------------------
// Bootstrap orchestration
// ---------------------------------------------------------------------------

/// Run the full VTA bootstrap flow.
pub async fn run_bootstrap(
    admin_bundle_str: &str,
    server_url: &str,
    vta_url_override: Option<&str>,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Decode admin credential bundle
    let bundle_bytes = BASE64
        .decode(admin_bundle_str.trim())
        .map_err(|e| format!("invalid base64url encoding: {e}"))?;
    let bundle: CredentialBundle = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| format!("invalid credential bundle JSON: {e}"))?;

    eprintln!("  Admin DID: {}", bundle.did);

    // 2. Determine VTA URL
    let vta_url = vta_url_override
        .map(|s| s.to_string())
        .or(bundle.vta_url.clone())
        .ok_or("VTA URL not specified — use --vta-url or ensure it's in the bundle")?;
    let vta_url = vta_url.trim_end_matches('/').to_string();

    eprintln!("  VTA URL:   {vta_url}");
    eprintln!("  VTA DID:   {}", bundle.vta_did);
    eprintln!();

    // 3. Build secrets from the credential bundle (did:key)
    let (signing_secret, ka_secret) = build_did_key_secrets(&bundle)?;

    // 4. Authenticate with VTA
    eprintln!("  Authenticating with VTA...");
    let client = VtaBootstrapClient::authenticate(
        &vta_url,
        &bundle.did,
        &bundle.vta_did,
        &signing_secret,
        &ka_secret,
    )
    .await?;
    eprintln!("  Authenticated.");
    eprintln!();

    // 5. Create output directory
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output dir {}: {e}", output_dir.display()))?;

    // 6. Bootstrap each service
    let services = ["webvh-server", "webvh-control", "webvh-witness"];
    for service in &services {
        eprintln!("  --- {service} ---");

        // Create context
        eprintln!("  Creating context...");
        let _ctx = client.create_context(service, service).await?;
        eprintln!("  Context: {service}");

        // Create DID (serverless mode)
        eprintln!("  Creating DID...");
        let did_resp = client.create_did_webvh(service, server_url).await?;
        eprintln!("  DID: {}", did_resp.did);

        // Get signing key secret
        eprintln!("  Fetching signing key...");
        let signing_key = client.get_key_secret(&did_resp.signing_key_id).await?;

        // Get key-agreement key secret
        eprintln!("  Fetching key-agreement key...");
        let ka_key = client.get_key_secret(&did_resp.ka_key_id).await?;

        // Build secrets bundle
        let secrets_bundle = DidSecretsBundle {
            did: did_resp.did.clone(),
            secrets: vec![
                SecretEntry {
                    key_id: did_resp.signing_key_id.clone(),
                    key_type: "ed25519".to_string(),
                    private_key_multibase: signing_key.private_key_multibase,
                },
                SecretEntry {
                    key_id: did_resp.ka_key_id.clone(),
                    key_type: "x25519".to_string(),
                    private_key_multibase: ka_key.private_key_multibase,
                },
            ],
        };

        // Encode bundle as base64url
        let bundle_json = serde_json::to_vec(&secrets_bundle)?;
        let bundle_encoded = BASE64.encode(&bundle_json);

        // Write files
        let bundle_path = output_dir.join(format!("{service}.bundle"));
        std::fs::write(&bundle_path, &bundle_encoded)?;
        eprintln!("  Bundle:  {}", bundle_path.display());

        if let Some(ref log_entry) = did_resp.log_entry {
            let log_path = output_dir.join(format!("{service}.did.jsonl"));
            std::fs::write(&log_path, log_entry)?;
            eprintln!("  DID log: {}", log_path.display());
        }

        eprintln!();
    }

    // 7. Print next steps
    eprintln!("  Bootstrap complete!");
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Import secrets into each service's setup:");
    eprintln!(
        "       webvh-server setup    (paste {}/webvh-server.bundle when prompted)",
        output_dir.display()
    );
    eprintln!(
        "       webvh-control setup   (paste {}/webvh-control.bundle when prompted)",
        output_dir.display()
    );
    eprintln!();
    eprintln!("    2. Load DIDs onto the webvh-server:");
    eprintln!(
        "       webvh-server load-did --path .well-known --did-log {}/webvh-server.did.jsonl",
        output_dir.display()
    );
    eprintln!(
        "       webvh-server load-did --path services/control --did-log {}/webvh-control.did.jsonl",
        output_dir.display()
    );
    eprintln!();
    eprintln!("    3. Add the server's DID to the control plane ACL:");
    eprintln!("       webvh-control add-acl --did <server-DID> --role admin");
    eprintln!();
    eprintln!("    4. Start services:");
    eprintln!("       webvh-server");
    eprintln!("       webvh-control");
    eprintln!();

    Ok(())
}

/// Build Ed25519 + X25519 secrets from a did:key credential bundle.
///
/// The credential bundle contains a did:key DID and its multibase-encoded
/// private key. We derive both the Ed25519 signing secret and the X25519
/// key agreement secret needed for DIDComm pack_encrypted.
fn build_did_key_secrets(
    bundle: &CredentialBundle,
) -> Result<(Secret, Secret), Box<dyn std::error::Error>> {
    // Decode the multibase private key to get the raw seed
    let (_base, raw_bytes) = multibase::decode(&bundle.private_key_multibase)
        .map_err(|e| format!("failed to decode private key multibase: {e}"))?;

    // Handle both raw 32-byte and 34-byte (with 0x8026 Ed25519 multicodec prefix) formats
    let seed: [u8; 32] = if raw_bytes.len() == 34 && raw_bytes[..2] == [0x80, 0x26] {
        raw_bytes[2..].try_into()?
    } else if raw_bytes.len() == 32 {
        raw_bytes.try_into().map_err(|_| "seed must be 32 bytes")?
    } else {
        return Err(format!(
            "unexpected private key length: {} bytes (expected 32 or 34)",
            raw_bytes.len()
        )
        .into());
    };

    // Extract the public key multibase from the did:key identifier
    let ed_pub_mb = bundle
        .did
        .strip_prefix("did:key:")
        .ok_or("credential bundle DID must be a did:key")?;

    // Generate Ed25519 signing secret from seed
    let mut signing = Secret::generate_ed25519(None, Some(&seed));
    signing.id = format!("{}#{}", bundle.did, ed_pub_mb);

    // Derive X25519 key agreement secret from the Ed25519 key
    let ka = signing
        .to_x25519()
        .map_err(|e| format!("failed to derive X25519 from Ed25519: {e}"))?;

    // Set correct key ID for the X25519 key
    let x_pub_mb = ka
        .get_public_keymultibase()
        .map_err(|e| format!("failed to get X25519 public key multibase: {e}"))?;
    let mut ka = ka;
    ka.id = format!("{}#{}", bundle.did, x_pub_mb);

    Ok((signing, ka))
}

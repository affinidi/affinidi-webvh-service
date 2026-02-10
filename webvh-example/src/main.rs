use std::io::{self, Write};
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::dids::{DID, KeyType};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::ThreadedSecretsResolver;
use anyhow::{Context, Result, bail};
use clap::Parser;
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::parameters::Parameters;
use serde::Deserialize;
use serde_json::json;
use tracing::info;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(about = "Create a did:webvh DID and upload it to a webvh-server")]
struct Cli {
    /// Base URL of the webvh-server (e.g. http://localhost:8085)
    #[arg(long)]
    server_url: String,
}

// ---------------------------------------------------------------------------
// Server response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChallengeData {
    challenge: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    session_id: String,
    data: ChallengeData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthData {
    access_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    data: AuthData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateDidResponse {
    mnemonic: String,
    did_url: String,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let server_url = cli.server_url.trim_end_matches('/');

    // ------------------------------------------------------------------
    // Step 1: Generate a did:key identity
    // ------------------------------------------------------------------
    let (my_did, my_secret) =
        DID::generate_did_key(KeyType::Ed25519).context("failed to generate did:key")?;

    println!("\n=== Step 1: Identity Generated ===");
    println!("  DID: {my_did}");
    println!("\nEnsure this DID is in the server ACL (e.g. via webvh-server invite).");
    print!("Press Enter to continue...");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;

    // ------------------------------------------------------------------
    // Step 2: Set up DIDComm infrastructure
    // ------------------------------------------------------------------
    println!("=== Step 2: Setting up DIDComm ===");

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .context("failed to create DID resolver")?;

    let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;
    secrets_resolver.insert(my_secret.clone()).await;

    info!("DIDComm infrastructure ready");

    // ------------------------------------------------------------------
    // Step 3: DIDComm challenge-response authentication
    // ------------------------------------------------------------------
    println!("=== Step 3: Authenticating via DIDComm ===");

    let client = reqwest::Client::new();

    // 3a. Request challenge
    let challenge_resp: ChallengeResponse = client
        .post(format!("{server_url}/auth/challenge"))
        .json(&json!({ "did": &my_did }))
        .send()
        .await
        .context("failed to request challenge")?
        .error_for_status()
        .context("challenge request rejected")?
        .json()
        .await
        .context("failed to parse challenge response")?;

    info!(session_id = %challenge_resp.session_id, "challenge received");

    // 3b. Build DIDComm message
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://affinidi.com/webvh/1.0/authenticate".to_string(),
        json!({
            "challenge": challenge_resp.data.challenge,
            "session_id": challenge_resp.session_id,
        }),
    )
    .from(my_did.clone())
    .finalize();

    // 3c. Pack as signed message
    let (packed, _meta) = msg
        .pack_signed(&my_secret.id, &did_resolver, &secrets_resolver)
        .await
        .context("failed to pack signed DIDComm message")?;

    // 3d. Authenticate
    let auth_resp: AuthResponse = client
        .post(format!("{server_url}/auth/"))
        .body(packed)
        .send()
        .await
        .context("failed to send auth message")?
        .error_for_status()
        .context("authentication rejected")?
        .json()
        .await
        .context("failed to parse auth response")?;

    let token = &auth_resp.data.access_token;
    println!("  Authenticated successfully!");

    // ------------------------------------------------------------------
    // Step 4: Request DID URI from server
    // ------------------------------------------------------------------
    println!("\n=== Step 4: Requesting DID URI ===");

    let create_resp: CreateDidResponse = client
        .post(format!("{server_url}/dids"))
        .bearer_auth(token)
        .send()
        .await
        .context("failed to request DID URI")?
        .error_for_status()
        .context("DID URI request rejected")?
        .json()
        .await
        .context("failed to parse create-DID response")?;

    let mnemonic = &create_resp.mnemonic;
    println!("  Mnemonic: {mnemonic}");
    println!("  DID URL:  {}", create_resp.did_url);

    // ------------------------------------------------------------------
    // Step 5: Build DID document with {SCID} placeholders
    // ------------------------------------------------------------------
    println!("\n=== Step 5: Building DID Document ===");

    let parsed_url = url::Url::parse(server_url).context("invalid server URL")?;
    let host = match parsed_url.port() {
        Some(port) => format!("{}%3A{}", parsed_url.host_str().unwrap(), port),
        None => parsed_url.host_str().unwrap().to_string(),
    };
    let did_id = format!("did:webvh:{{SCID}}:{host}:{mnemonic}");

    let public_key_multibase = my_secret
        .get_public_keymultibase()
        .context("failed to get public key multibase")?;

    let did_document = json!({
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
    });

    info!("DID document built with SCID placeholder");

    // ------------------------------------------------------------------
    // Step 6: Create WebVH log entry
    // ------------------------------------------------------------------
    println!("=== Step 6: Creating WebVH Log Entry ===");

    let mut didwebvh = DIDWebVHState::default();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![
            my_secret
                .get_public_keymultibase()
                .context("failed to get public key multibase for params")?,
        ])),
        ..Default::default()
    };

    didwebvh
        .create_log_entry(None, &did_document, &params, &my_secret)
        .context("failed to create WebVH log entry")?;

    let scid = &didwebvh.scid;
    let final_did = format!("did:webvh:{scid}:{host}:{mnemonic}");
    println!("  SCID: {scid}");
    println!("  DID:  {final_did}");

    // ------------------------------------------------------------------
    // Step 7: Serialize and upload
    // ------------------------------------------------------------------
    println!("\n=== Step 7: Uploading DID ===");

    let jsonl: String = didwebvh
        .log_entries
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");

    let resp = client
        .put(format!("{server_url}/dids/{mnemonic}"))
        .bearer_auth(token)
        .header("Content-Type", "text/plain")
        .body(jsonl)
        .send()
        .await
        .context("failed to upload DID")?;

    if !resp.status().is_success() {
        bail!(
            "upload failed with status {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    println!("  Uploaded successfully!");

    // ------------------------------------------------------------------
    // Step 8: Verify resolution
    // ------------------------------------------------------------------
    println!("\n=== Step 8: Verifying Resolution ===");

    let resolved = client
        .get(&create_resp.did_url)
        .send()
        .await
        .context("failed to resolve DID")?
        .error_for_status()
        .context("DID resolution failed")?
        .text()
        .await
        .context("failed to read resolved DID")?;

    println!("  Resolved DID log:\n{resolved}");

    // ------------------------------------------------------------------
    // Step 9: Summary
    // ------------------------------------------------------------------
    println!("\n=== DID Created and Hosted Successfully! ===");
    println!("  Mnemonic:   {mnemonic}");
    println!("  SCID:       {scid}");
    println!("  DID URL:    {}", create_resp.did_url);
    println!("  DID:        {final_did}");
    println!("  Public Key: {public_key_multibase}");

    Ok(())
}

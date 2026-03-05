//! Bootstrap — unpacks PNM context provision bundles for all WebVH services.
//!
//! Each WebVH service gets its own VTA context (for secret/config isolation).
//! The PNM CLI's `provision` command creates a self-contained bundle per
//! context that includes admin credentials, DID material, and private keys.
//!
//! This module decodes those bundles and writes out the files that
//! `webvh-server setup`, `webvh-server load-did`, and `webvh-control setup`
//! expect to consume.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PNM ContextProvisionBundle types (mirrors vta-sdk)
// ---------------------------------------------------------------------------

/// A self-contained bundle produced by `pnm contexts provision`.
#[derive(Debug, Deserialize)]
pub struct ContextProvisionBundle {
    pub context_id: String,
    pub context_name: String,
    #[serde(default)]
    pub vta_url: Option<String>,
    #[serde(default)]
    pub vta_did: Option<String>,
    /// Base64url-encoded admin credential (CredentialBundle format).
    pub credential: String,
    pub admin_did: String,
    /// DID material — present when a DID was created during provisioning.
    #[serde(default)]
    pub did: Option<ProvisionedDid>,
}

#[derive(Debug, Deserialize)]
pub struct ProvisionedDid {
    pub id: String,
    #[serde(default)]
    pub did_document: Option<serde_json::Value>,
    #[serde(default)]
    pub log_entry: Option<String>,
    pub secrets: Vec<ProvisionSecretEntry>,
}

#[derive(Debug, Deserialize)]
pub struct ProvisionSecretEntry {
    pub key_id: String,
    pub key_type: String,
    pub private_key_multibase: String,
}

// ---------------------------------------------------------------------------
// Output types (consumed by webvh-server/webvh-control setup wizards)
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
// Bootstrap orchestration
// ---------------------------------------------------------------------------

/// A single service bundle to process.
pub struct ServiceBundle<'a> {
    pub label: &'a str,
    pub encoded: &'a str,
}

/// Run the bootstrap flow from PNM provision bundles.
///
/// Decodes each provision bundle, extracts the secrets bundle and DID log,
/// and writes them to the output directory.
pub fn run_bootstrap(
    bundles: &[ServiceBundle<'_>],
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output dir {}: {e}", output_dir.display()))?;

    for sb in bundles {
        eprintln!("  --- {} ---", sb.label);

        let provision = decode_provision_bundle(sb.encoded)?;
        eprintln!("  Context: {}", provision.context_id);
        eprintln!("  Admin:   {}", provision.admin_did);

        let did_info = provision.did.as_ref().ok_or_else(|| {
            format!(
                "provision bundle for '{}' has no DID material — \
                 re-provision with --did-url",
                sb.label
            )
        })?;

        eprintln!("  DID:     {}", did_info.id);

        // Build secrets bundle (same format as `webvh-server setup` expects)
        let secrets_bundle = DidSecretsBundle {
            did: did_info.id.clone(),
            secrets: did_info
                .secrets
                .iter()
                .map(|s| SecretEntry {
                    key_id: s.key_id.clone(),
                    key_type: s.key_type.clone(),
                    private_key_multibase: s.private_key_multibase.clone(),
                })
                .collect(),
        };

        let bundle_json = serde_json::to_vec(&secrets_bundle)?;
        let bundle_encoded = BASE64.encode(&bundle_json);

        let bundle_path = output_dir.join(format!("{}.bundle", sb.label));
        std::fs::write(&bundle_path, &bundle_encoded)?;
        eprintln!("  Bundle:  {}", bundle_path.display());

        if let Some(ref log_entry) = did_info.log_entry {
            let log_path = output_dir.join(format!("{}.did.jsonl", sb.label));
            std::fs::write(&log_path, log_entry)?;
            eprintln!("  DID log: {}", log_path.display());
        }

        eprintln!();
    }

    Ok(())
}

/// Print the next-steps instructions after bootstrap.
pub fn print_next_steps(output_dir: &Path) {
    let dir = output_dir.display();

    eprintln!("  Bootstrap complete!");
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Import secrets into each service's setup:");
    eprintln!("       webvh-server setup    (paste {dir}/webvh-server.bundle when prompted)");
    eprintln!("       webvh-control setup   (paste {dir}/webvh-control.bundle when prompted)");
    eprintln!();
    eprintln!("    2. Load DIDs onto the webvh-server:");
    eprintln!(
        "       webvh-server load-did --path .well-known --did-log {dir}/webvh-server.did.jsonl"
    );
    eprintln!(
        "       webvh-server load-did --path services/control --did-log {dir}/webvh-control.did.jsonl"
    );
    eprintln!();
    eprintln!("    3. Add the server's DID to the control plane ACL:");
    eprintln!("       webvh-control add-acl --did <server-DID> --role admin");
    eprintln!();
    eprintln!("    4. Start services:");
    eprintln!("       webvh-server");
    eprintln!("       webvh-control");
    eprintln!();
}

fn decode_provision_bundle(
    encoded: &str,
) -> Result<ContextProvisionBundle, Box<dyn std::error::Error>> {
    let bytes = BASE64
        .decode(encoded.trim())
        .map_err(|e| format!("invalid base64url encoding: {e}"))?;
    let bundle: ContextProvisionBundle = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid provision bundle JSON: {e}"))?;
    Ok(bundle)
}

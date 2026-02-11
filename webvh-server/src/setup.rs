use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde::Deserialize;

use uuid::Uuid;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LogConfig, LogFormat, ServerConfig, StoreConfig,
};
use crate::passkey::store::{Enrollment, store_enrollment};
use crate::store::Store;

/// Generate a base64url-no-pad encoded 32-byte random key.
fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    BASE64.encode(bytes)
}

/// VTA secrets bundle format (base64url-encoded JSON).
#[derive(Deserialize)]
struct SecretsBundle {
    did: String,
    secrets: Vec<SecretEntry>,
}

#[derive(Deserialize)]
struct SecretEntry {
    key_id: String,
    key_type: String,
    private_key_multibase: String,
}

/// Decode a multibase-encoded 32-byte seed (Base58BTC, no multicodec prefix).
fn decode_multibase_seed(multibase_str: &str) -> Result<[u8; 32], String> {
    let (_base, bytes) =
        multibase::decode(multibase_str).map_err(|e| format!("invalid multibase: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "expected 32-byte seed".to_string())
}

pub async fn run_wizard(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Server — Setup Wizard");
    eprintln!("  ===========================");
    eprintln!();

    // 1. Output path
    let default_path = config_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "config.toml".to_string());

    let output_path: String = Input::new()
        .with_prompt("Configuration file path")
        .default(default_path)
        .interact_text()?;

    let output_path = PathBuf::from(&output_path);

    if output_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!("{} already exists. Overwrite?", output_path.display()))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 2. Feature selection
    let feature_items = &["DIDComm Messaging", "REST API"];
    let selected = MultiSelect::new()
        .with_prompt("Which features do you want to enable? (Space to toggle, Enter to confirm)")
        .items(feature_items)
        .defaults(&[true, true])
        .interact()?;

    let enable_didcomm = selected.contains(&0);
    let enable_rest_api = selected.contains(&1);

    // 3. DIDComm-specific: import VTA secrets bundle
    let mut server_did = None;
    let mut mediator_did = None;
    let mut signing_key = None;
    let mut key_agreement_key = None;
    let mut auth = AuthConfig::default();

    if enable_didcomm {
        eprintln!();
        eprintln!("  Paste the VTA secrets bundle export for the server DID.");
        eprintln!("  (This is the base64url string from `vta export-did-secrets`)");
        eprintln!();

        let bundle: SecretsBundle = loop {
            let input: String = Input::new()
                .with_prompt("VTA secrets bundle (base64url)")
                .interact_text()?;

            let decoded = match BASE64.decode(input.trim()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("  Error: invalid base64url encoding: {e}");
                    continue;
                }
            };

            match serde_json::from_slice::<SecretsBundle>(&decoded) {
                Ok(b) => break b,
                Err(e) => {
                    eprintln!("  Error: invalid bundle JSON: {e}");
                    continue;
                }
            }
        };

        server_did = Some(bundle.did.clone());

        // Extract Ed25519 signing key
        let ed_entry = bundle
            .secrets
            .iter()
            .find(|s| s.key_type == "ed25519")
            .ok_or("bundle has no Ed25519 signing key".to_string())?;
        let ed_seed = decode_multibase_seed(&ed_entry.private_key_multibase)?;
        signing_key = Some(BASE64.encode(ed_seed));

        // Extract X25519 key agreement key (optional)
        match bundle.secrets.iter().find(|s| s.key_type == "x25519") {
            Some(x_entry) => {
                let x_seed = decode_multibase_seed(&x_entry.private_key_multibase)?;
                key_agreement_key = Some(BASE64.encode(x_seed));
            }
            None => {
                eprintln!("  Warning: bundle has no X25519 key agreement key; continuing without it.");
            }
        }

        eprintln!();
        eprintln!("  Imported server DID: {}", bundle.did);
        eprintln!("  Signing key (Ed25519):     loaded from {}", ed_entry.key_id);
        if let Some(x_entry) = bundle.secrets.iter().find(|s| s.key_type == "x25519") {
            eprintln!("  Key agreement (X25519):    loaded from {}", x_entry.key_id);
        }
        eprintln!();

        let med_did: String = Input::new()
            .with_prompt("Mediator DID (e.g. did:webvh:mediator.example.com)")
            .default(String::new())
            .interact_text()?;
        mediator_did = if med_did.is_empty() {
            None
        } else {
            Some(med_did)
        };
    }

    // 4. Public URL
    let public_url: String = Input::new()
        .with_prompt("Public URL (e.g. https://example.com)")
        .default(String::new())
        .interact_text()?;
    let public_url = if public_url.is_empty() {
        None
    } else {
        Some(public_url)
    };

    // 5. Host / Port
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8101)
        .interact_text()?;

    // 6. Log level / format
    let log_level: String = Input::new()
        .with_prompt("Log level")
        .default("info".to_string())
        .interact_text()?;

    let format_options = &["text", "json"];
    let format_idx = Select::new()
        .with_prompt("Log format")
        .items(format_options)
        .default(0)
        .interact()?;
    let log_format = match format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    // 7. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-server".to_string())
        .interact_text()?;

    // 8. JWT signing key
    if enable_didcomm {
        let jsk = generate_key();

        eprintln!("  Generated JWT signing key (back this up!):");
        eprintln!("  -------------------------------------------");
        eprintln!("  auth.jwt_signing_key: {jsk}");
        eprintln!();

        auth = AuthConfig {
            jwt_signing_key: Some(jsk),
            ..Default::default()
        };
    } else {
        // REST API / passkey auth still needs a JWT signing key
        let jwt_options = &[
            "Generate a new random key",
            "Paste an existing base64url key",
            "Skip (no auth)",
        ];
        let jwt_idx = Select::new()
            .with_prompt("JWT signing key (required for passkey & token auth)")
            .items(jwt_options)
            .default(0)
            .interact()?;

        match jwt_idx {
            0 => {
                let jsk = generate_key();
                eprintln!();
                eprintln!("  Generated JWT signing key (back this up!):");
                eprintln!("  -------------------------------------------");
                eprintln!("  auth.jwt_signing_key: {jsk}");
                eprintln!();
                auth.jwt_signing_key = Some(jsk);
            }
            1 => {
                let jsk: String = Input::new()
                    .with_prompt("Base64url-no-pad encoded 32-byte key")
                    .interact_text()?;
                let trimmed = jsk.trim().to_string();
                if !trimmed.is_empty() {
                    auth.jwt_signing_key = Some(trimmed);
                }
            }
            _ => {
                eprintln!("  Skipping JWT key — auth endpoints will not work.");
            }
        }
    }

    // 9. Auth expiry settings
    if auth.jwt_signing_key.is_some() {
        let customize_auth = Confirm::new()
            .with_prompt("Customize auth token expiry settings?")
            .default(false)
            .interact()?;

        if customize_auth {
            auth.access_token_expiry = Input::new()
                .with_prompt("Access token expiry (seconds)")
                .default(auth.access_token_expiry)
                .interact_text()?;

            auth.refresh_token_expiry = Input::new()
                .with_prompt("Refresh token expiry (seconds)")
                .default(auth.refresh_token_expiry)
                .interact_text()?;

            auth.challenge_ttl = Input::new()
                .with_prompt("Challenge TTL (seconds)")
                .default(auth.challenge_ttl)
                .interact_text()?;

            auth.session_cleanup_interval = Input::new()
                .with_prompt("Session cleanup interval (seconds)")
                .default(auth.session_cleanup_interval)
                .interact_text()?;

            auth.passkey_enrollment_ttl = Input::new()
                .with_prompt("Passkey enrollment TTL (seconds)")
                .default(auth.passkey_enrollment_ttl)
                .interact_text()?;
        }
    }

    // 10. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: enable_didcomm,
            rest_api: enable_rest_api,
        },
        server_did,
        mediator_did,
        public_url,
        server: ServerConfig { host, port },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(&data_dir),
        },
        auth,
        signing_key,
        key_agreement_key,
        config_path: PathBuf::new(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // 11. Optional admin bootstrap (only when DIDComm is enabled)
    if enable_didcomm {
        let bootstrap = Confirm::new()
            .with_prompt("Bootstrap an initial admin ACL entry?")
            .default(true)
            .interact()?;

        if bootstrap {
            let admin_did: String = Input::new()
                .with_prompt("Admin DID")
                .interact_text()?;

            let admin_label: String = Input::new()
                .with_prompt("Label (optional)")
                .default(String::new())
                .interact_text()?;

            let label = if admin_label.is_empty() {
                None
            } else {
                Some(admin_label)
            };

            let store = Store::open(&config.store)?;
            let acl_ks = store.keyspace("acl")?;

            let entry = AclEntry {
                did: admin_did.clone(),
                role: Role::Admin,
                label,
                created_at: now_epoch(),
            };

            store_acl_entry(&acl_ks, &entry).await?;
            eprintln!("  Admin ACL entry created for {admin_did}");

            let create_invite = Confirm::new()
                .with_prompt("Create a passkey enrollment invite for this admin?")
                .default(true)
                .interact()?;

            if create_invite {
                let sessions_ks = store.keyspace("sessions")?;
                let token = Uuid::new_v4().to_string();
                let now = now_epoch();
                let enrollment = Enrollment {
                    token: token.clone(),
                    did: admin_did.clone(),
                    role: "admin".to_string(),
                    created_at: now,
                    expires_at: now + config.auth.passkey_enrollment_ttl,
                };
                store_enrollment(&sessions_ks, &enrollment).await?;

                eprintln!();
                if let Some(ref url) = config.public_url {
                    eprintln!("  Enrollment link: {url}/enroll?token={token}");
                } else {
                    eprintln!("  Enrollment token: {token}");
                    eprintln!("  (Set public_url in config, then visit {{public_url}}/enroll?token={{token}})");
                }
                eprintln!("  Expires in: {} seconds", config.auth.passkey_enrollment_ttl);
            }
        }
    }

    eprintln!();
    eprintln!("  Setup complete! Start the server with:");
    eprintln!("    webvh-server --config {}", output_path.display());
    eprintln!();

    Ok(())
}

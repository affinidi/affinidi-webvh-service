use std::path::PathBuf;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde::Deserialize;

use uuid::Uuid;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LimitsConfig, LogConfig, LogFormat, SecretsConfig,
    ServerConfig, StoreConfig,
};
use crate::passkey::store::{Enrollment, store_enrollment};
use crate::secret_store::{ServerSecrets, create_secret_store};
use crate::store::Store;

/// Generate a random Ed25519 key and return its multibase-encoded private key.
fn generate_ed25519_multibase() -> String {
    let secret = Secret::generate_ed25519(None, None);
    secret
        .get_private_keymultibase()
        .expect("ed25519 multibase encoding")
}

/// Generate a random X25519 key and return its multibase-encoded private key.
fn generate_x25519_multibase() -> String {
    let secret = Secret::generate_x25519(None, None).expect("x25519 key generation");
    secret
        .get_private_keymultibase()
        .expect("x25519 multibase encoding")
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

    // 3. DIDComm-specific: server identity and keys
    let mut server_did = None;
    let mut mediator_did = None;
    let mut signing_key = None;
    let mut key_agreement_key = None;
    let auth = AuthConfig::default();

    if enable_didcomm {
        let identity_options = &[
            "Import a VTA secrets bundle (recommended)",
            "Enter each parameter manually",
        ];
        let identity_idx = Select::new()
            .with_prompt("How do you want to configure the server DID identity?")
            .items(identity_options)
            .default(0)
            .interact()?;

        if identity_idx == 0 {
            // --- VTA bundle import ---
            eprintln!();
            eprintln!("  Paste the VTA secrets bundle export for the server DID.");
            eprintln!("  (This is the base64url string from `vta export-admin`)");
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

            // Extract Ed25519 signing key — store multibase directly
            let ed_entry = bundle
                .secrets
                .iter()
                .find(|s| s.key_type == "ed25519")
                .ok_or("bundle has no Ed25519 signing key".to_string())?;
            signing_key = Some(ed_entry.private_key_multibase.clone());

            // Extract X25519 key agreement key (optional) — store multibase directly
            match bundle.secrets.iter().find(|s| s.key_type == "x25519") {
                Some(x_entry) => {
                    key_agreement_key = Some(x_entry.private_key_multibase.clone());
                }
                None => {
                    eprintln!(
                        "  Warning: bundle has no X25519 key agreement key; generating one."
                    );
                }
            }

            eprintln!();
            eprintln!("  Imported server DID: {}", bundle.did);
            eprintln!(
                "  Signing key (Ed25519):     loaded from {}",
                ed_entry.key_id
            );
            if let Some(x_entry) = bundle.secrets.iter().find(|s| s.key_type == "x25519") {
                eprintln!(
                    "  Key agreement (X25519):    loaded from {}",
                    x_entry.key_id
                );
            }
            eprintln!();
        } else {
            // --- Manual entry ---
            eprintln!();

            let did: String = Input::new()
                .with_prompt("Server DID (e.g. did:webvh:webvh.example.com)")
                .interact_text()?;
            server_did = Some(did);

            // Signing key
            let sk_options = &[
                "Generate a new Ed25519 signing key",
                "Paste an existing multibase-encoded key",
            ];
            let sk_idx = Select::new()
                .with_prompt("Ed25519 signing key")
                .items(sk_options)
                .default(0)
                .interact()?;

            if sk_idx == 0 {
                let key = generate_ed25519_multibase();
                eprintln!("  Generated Ed25519 signing key.");
                signing_key = Some(key);
            } else {
                let key: String = Input::new()
                    .with_prompt("Multibase-encoded Ed25519 private key")
                    .interact_text()?;
                signing_key = Some(key.trim().to_string());
            }

            // Key agreement key
            let ka_options = &[
                "Generate a new X25519 key agreement key",
                "Paste an existing multibase-encoded key",
            ];
            let ka_idx = Select::new()
                .with_prompt("X25519 key agreement key")
                .items(ka_options)
                .default(0)
                .interact()?;

            if ka_idx == 0 {
                let key = generate_x25519_multibase();
                eprintln!("  Generated X25519 key agreement key.");
                key_agreement_key = Some(key);
            } else {
                let key: String = Input::new()
                    .with_prompt("Multibase-encoded X25519 private key")
                    .interact_text()?;
                key_agreement_key = Some(key.trim().to_string());
            }

            eprintln!();
        }

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
    let mut jwt_signing_key = None;
    if enable_didcomm {
        let jsk = generate_ed25519_multibase();
        eprintln!("  Generated JWT signing key.");
        jwt_signing_key = Some(jsk);
    } else {
        // REST API / passkey auth still needs a JWT signing key
        let jwt_options = &[
            "Generate a new random key",
            "Paste an existing multibase key",
            "Skip (no auth)",
        ];
        let jwt_idx = Select::new()
            .with_prompt("JWT signing key (required for passkey & token auth)")
            .items(jwt_options)
            .default(0)
            .interact()?;

        match jwt_idx {
            0 => {
                let jsk = generate_ed25519_multibase();
                eprintln!();
                eprintln!("  Generated JWT signing key.");
                eprintln!();
                jwt_signing_key = Some(jsk);
            }
            1 => {
                let jsk: String = Input::new()
                    .with_prompt("Multibase-encoded Ed25519 private key")
                    .interact_text()?;
                let trimmed = jsk.trim().to_string();
                if !trimmed.is_empty() {
                    jwt_signing_key = Some(trimmed);
                }
            }
            _ => {
                eprintln!("  Skipping JWT key — auth endpoints will not work.");
            }
        }
    }

    // 9. Auth expiry settings
    let has_jwt_key = jwt_signing_key.is_some();

    // Fill in defaults for signing/key-agreement if not from bundle
    let signing_key = signing_key.unwrap_or_else(generate_ed25519_multibase);
    let key_agreement_key = key_agreement_key.unwrap_or_else(generate_x25519_multibase);
    let jwt_signing_key = jwt_signing_key.unwrap_or_else(generate_ed25519_multibase);

    // 10. Secrets backend selection
    let secrets_config = configure_secrets()?;

    // 11. Build and write config (no key material — secrets live in the secret store)
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
        secrets: secrets_config,
        limits: LimitsConfig::default(),
        config_path: PathBuf::new(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // 12. Store secrets in the chosen backend
    let server_secrets = ServerSecrets {
        signing_key,
        key_agreement_key,
        jwt_signing_key,
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    // 13. Optional admin bootstrap (only when DIDComm is enabled)
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
                max_total_size: None,
                max_did_count: None,
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

    if !has_jwt_key {
        eprintln!();
        eprintln!("  Note: No JWT signing key was configured. Auth endpoints will not work.");
    }

    eprintln!();
    eprintln!("  Setup complete! Start the server with:");
    eprintln!("    webvh-server --config {}", output_path.display());
    eprintln!();

    Ok(())
}

/// Prompt for secrets backend selection and configuration.
fn configure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    let mut backends: Vec<&str> = Vec::new();

    #[cfg(feature = "keyring")]
    backends.push("OS Keyring (default)");

    #[cfg(feature = "aws-secrets")]
    backends.push("AWS Secrets Manager");

    #[cfg(feature = "gcp-secrets")]
    backends.push("GCP Secret Manager");

    if backends.is_empty() {
        return Err(
            "no secret store backend available — compile with at least one of: keyring, aws-secrets, gcp-secrets".into(),
        );
    }

    let mut secrets_config = SecretsConfig::default();

    if backends.len() == 1 {
        eprintln!("  Using {} for secrets storage.", backends[0]);
    } else {
        let idx = Select::new()
            .with_prompt("Secrets storage backend")
            .items(&backends)
            .default(0)
            .interact()?;

        let chosen = backends[idx];

        if chosen.starts_with("AWS") {
            let name: String = Input::new()
                .with_prompt("AWS secret name")
                .default("webvh-server-secrets".to_string())
                .interact_text()?;
            secrets_config.aws_secret_name = Some(name);

            let region: String = Input::new()
                .with_prompt("AWS region (leave empty for default)")
                .default(String::new())
                .interact_text()?;
            if !region.is_empty() {
                secrets_config.aws_region = Some(region);
            }
        } else if chosen.starts_with("GCP") {
            let project: String = Input::new()
                .with_prompt("GCP project ID")
                .interact_text()?;
            secrets_config.gcp_project = Some(project);

            let name: String = Input::new()
                .with_prompt("GCP secret name")
                .default("webvh-server-secrets".to_string())
                .interact_text()?;
            secrets_config.gcp_secret_name = Some(name);
        } else {
            // Keyring — optionally customize service name
            let service: String = Input::new()
                .with_prompt("Keyring service name")
                .default("webvh".to_string())
                .interact_text()?;
            secrets_config.keyring_service = service;
        }
    }

    Ok(secrets_config)
}

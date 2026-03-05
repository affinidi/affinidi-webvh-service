//! Interactive setup wizard for generating a control plane config.toml.

use crate::acl::{AclEntry, Role};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LogConfig, LogFormat, RegistryConfig, SecretsConfig,
    ServerConfig, StoreConfig,
};
use crate::error::AppError;
use crate::secret_store::{ServerSecrets, create_secret_store};
use crate::store::Store;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use dialoguer::{Confirm, Input, Select};
use serde::Deserialize;
use std::path::PathBuf;

/// Secrets bundle format (base64url-encoded JSON from PNM provision / bootstrap).
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

pub async fn run_setup() -> Result<(), AppError> {
    eprintln!();
    eprintln!("  WebVH Control Plane — Setup Wizard");
    eprintln!("  -----------------------------------");
    eprintln!();

    // 1. Output path
    let output_path: String = Input::new()
        .with_prompt("Config file output path")
        .default("config.toml".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let output_path = PathBuf::from(output_path);

    // 2. Public URL (required for passkeys)
    let public_url: String = Input::new()
        .with_prompt("Public URL (for passkey auth, e.g. https://control.example.com)")
        .default("http://localhost:8532".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let public_url = if public_url.is_empty() {
        None
    } else {
        Some(public_url)
    };

    // 3. Host & Port
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8532)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    // 4. Log level & format
    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(&log_levels)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let log_level = log_levels[log_level_idx].to_string();

    let log_formats = ["text", "json"];
    let log_format_idx = Select::new()
        .with_prompt("Log format")
        .items(&log_formats)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let log_format = match log_format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    // 5. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-control".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    // 6. JWT signing key
    let jwt_signing_key = generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 7. Secrets backend
    let secrets_config = configure_secrets()?;

    // 8. Identity — import PNM provision bundle or generate new keys
    let mut server_did = None;
    let mut signing_key = None;
    let mut key_agreement_key = None;

    let identity_options = &[
        "Import a PNM provision bundle (recommended)",
        "Generate new keys (no DID)",
    ];
    let identity_idx = Select::new()
        .with_prompt("Server identity")
        .items(identity_options)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    if identity_idx == 0 {
        // --- PNM provision bundle import ---
        eprintln!();
        eprintln!("  Paste the secrets bundle for the control plane.");
        eprintln!("  This is the base64url string from `webvh-control bootstrap`");
        eprintln!("  or directly from `pnm contexts provision`.");
        eprintln!();

        let bundle: SecretsBundle = loop {
            let input: String = Input::new()
                .with_prompt("Secrets bundle (base64url)")
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

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
        if let Some(ed_entry) = bundle.secrets.iter().find(|s| s.key_type == "ed25519") {
            signing_key = Some(ed_entry.private_key_multibase.clone());
            eprintln!(
                "  Signing key (Ed25519):     loaded from {}",
                ed_entry.key_id
            );
        }

        // Extract X25519 key agreement key
        if let Some(x_entry) = bundle.secrets.iter().find(|s| s.key_type == "x25519") {
            key_agreement_key = Some(x_entry.private_key_multibase.clone());
            eprintln!(
                "  Key agreement (X25519):    loaded from {}",
                x_entry.key_id
            );
        }

        eprintln!();
        eprintln!("  Imported server DID: {}", bundle.did);
        eprintln!();
    }

    // Fill in defaults for keys not from bundle
    let signing_key = signing_key.unwrap_or_else(|| {
        eprintln!("  Generated Ed25519 signing key.");
        generate_ed25519_multibase()
    });
    let key_agreement_key = key_agreement_key.unwrap_or_else(|| {
        eprintln!("  Generated X25519 key agreement key.");
        generate_x25519_multibase()
    });

    // 9. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: false,
            rest_api: true,
        },
        server_did,
        mediator_did: None,
        public_url,
        server: ServerConfig { host, port },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(&data_dir),
            ..StoreConfig::default()
        },
        auth: AuthConfig::default(),
        secrets: secrets_config,
        registry: RegistryConfig::default(),
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // 10. Store secrets
    let server_secrets = ServerSecrets {
        signing_key,
        key_agreement_key,
        jwt_signing_key,
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored.");

    // 11. Optional admin ACL bootstrap
    let add_admin = Confirm::new()
        .with_prompt("Add an admin DID to the ACL now?")
        .default(config.server_did.is_some())
        .interact()
        .unwrap_or(false);

    if add_admin {
        let admin_did: String = Input::new()
            .with_prompt("Admin DID")
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;

        let store = Store::open(&config.store).await?;
        let acl_ks = store.keyspace("acl")?;

        let entry = AclEntry {
            did: admin_did.clone(),
            role: Role::Admin,
            label: Some("Setup wizard admin".into()),
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
        };

        crate::acl::store_acl_entry(&acl_ks, &entry).await?;
        store.persist().await?;

        eprintln!("  Admin ACL entry added for {admin_did}");
    }

    eprintln!();
    if config.server_did.is_some() {
        eprintln!("  Setup complete! Start the control plane with:");
        eprintln!("    webvh-control --config {}", output_path.display());
    } else {
        eprintln!("  Setup complete!");
        eprintln!("  To finish, import a PNM provision bundle and set server_did in the config.");
        eprintln!("  Then start with: webvh-control --config {}", output_path.display());
    }
    eprintln!();

    Ok(())
}

fn generate_ed25519_multibase() -> String {
    affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, None)
        .get_private_keymultibase()
        .expect("ed25519 multibase encoding")
}

fn generate_x25519_multibase() -> String {
    affinidi_tdk::secrets_resolver::secrets::Secret::generate_x25519(None, None)
        .expect("failed to generate X25519 key")
        .get_private_keymultibase()
        .expect("x25519 multibase encoding")
}

/// Prompt for secrets backend selection and configuration.
fn configure_secrets() -> Result<SecretsConfig, AppError> {
    #[allow(unused_mut)]
    let mut backends: Vec<&str> = Vec::new();

    #[cfg(feature = "keyring")]
    backends.push("OS Keyring (default)");

    #[cfg(feature = "aws-secrets")]
    backends.push("AWS Secrets Manager");

    #[cfg(feature = "gcp-secrets")]
    backends.push("GCP Secret Manager");

    if backends.is_empty() {
        // No secure backend compiled — fall back to plaintext with a warning
        eprintln!();
        eprintln!("  *** WARNING: No secure secrets backend is available. ***");
        eprintln!("  Secrets will be stored as PLAINTEXT in the configuration file.");
        eprintln!("  This is INSECURE and should only be used for testing/development.");
        eprintln!("  For production, recompile with: keyring, aws-secrets, or gcp-secrets.");
        eprintln!();

        let proceed = Confirm::new()
            .with_prompt("Continue with plaintext secrets storage?")
            .default(false)
            .interact()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;

        if !proceed {
            return Err(AppError::Config(
                "setup cancelled — recompile with a secure secrets backend (keyring, aws-secrets, or gcp-secrets)".into(),
            ));
        }

        return Ok(SecretsConfig::default());
    }

    let chosen = if backends.len() == 1 {
        eprintln!("  Using {} for secrets storage.", backends[0]);
        backends[0]
    } else {
        let idx = Select::new()
            .with_prompt("Secrets storage backend")
            .items(&backends)
            .default(0)
            .interact()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        backends[idx]
    };

    let mut secrets_config = SecretsConfig::default();

    if chosen.starts_with("AWS") {
        let name: String = Input::new()
            .with_prompt("AWS secret name")
            .default("webvh-control-secrets".to_string())
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        secrets_config.aws_secret_name = Some(name);

        let region: String = Input::new()
            .with_prompt("AWS region (leave empty for default)")
            .default(String::new())
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        if !region.is_empty() {
            secrets_config.aws_region = Some(region);
        }
    } else if chosen.starts_with("GCP") {
        let project: String = Input::new()
            .with_prompt("GCP project ID")
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        secrets_config.gcp_project = Some(project);

        let name: String = Input::new()
            .with_prompt("GCP secret name")
            .default("webvh-control-secrets".to_string())
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        secrets_config.gcp_secret_name = Some(name);
    } else {
        // Keyring — optionally customize service name
        let service: String = Input::new()
            .with_prompt("Keyring service name")
            .default("webvh".to_string())
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        secrets_config.keyring_service = service;
    }

    Ok(secrets_config)
}

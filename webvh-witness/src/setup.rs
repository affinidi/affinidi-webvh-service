use std::path::PathBuf;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde::Deserialize;

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LogConfig, LogFormat, SecretsConfig, ServerConfig,
    StoreConfig, VtaConfig,
};
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
    eprintln!("  WebVH Witness — Setup Wizard");
    eprintln!("  ============================");
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
            .with_prompt("How do you want to configure the witness DID identity?")
            .items(identity_options)
            .default(0)
            .interact()?;

        if identity_idx == 0 {
            // --- VTA bundle import ---
            eprintln!();
            eprintln!("  Paste the VTA secrets bundle export for the witness DID.");
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

            let ed_entry = bundle
                .secrets
                .iter()
                .find(|s| s.key_type == "ed25519")
                .ok_or("bundle has no Ed25519 signing key".to_string())?;
            signing_key = Some(ed_entry.private_key_multibase.clone());

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
                .with_prompt("Witness server DID (e.g. did:webvh:witness.example.com)")
                .interact_text()?;
            server_did = Some(did);

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

    // 4. Host / Port
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8102u16)
        .interact_text()?;

    // 5. Log level / format
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

    // 6. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-witness".to_string())
        .interact_text()?;

    // 7. JWT signing key
    let mut jwt_signing_key = None;
    if enable_didcomm {
        let jsk = generate_ed25519_multibase();
        eprintln!("  Generated JWT signing key.");
        jwt_signing_key = Some(jsk);
    } else {
        let jwt_options = &[
            "Generate a new random key",
            "Paste an existing multibase key",
            "Skip (no auth)",
        ];
        let jwt_idx = Select::new()
            .with_prompt("JWT signing key (required for token auth)")
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

    let has_jwt_key = jwt_signing_key.is_some();

    // Fill in defaults for signing/key-agreement if not from bundle
    let signing_key = signing_key.unwrap_or_else(generate_ed25519_multibase);
    let key_agreement_key = key_agreement_key.unwrap_or_else(generate_x25519_multibase);
    let jwt_signing_key = jwt_signing_key.unwrap_or_else(generate_ed25519_multibase);

    // 8. VTA configuration (optional)
    let vta_config = configure_vta()?;

    // 9. Secrets backend selection
    let secrets_config = configure_secrets()?;

    // 10. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: enable_didcomm,
            rest_api: enable_rest_api,
        },
        server_did,
        mediator_did,
        server: ServerConfig { host, port },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir: PathBuf::from(&data_dir),
            ..StoreConfig::default()
        },
        auth,
        secrets: secrets_config,
        vta: vta_config,
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // 11. Store secrets in the chosen backend
    let server_secrets = ServerSecrets {
        signing_key,
        key_agreement_key,
        jwt_signing_key,
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    // 12. Optional admin bootstrap
    if enable_didcomm || enable_rest_api {
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

            let store = Store::open(&config.store).await?;
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
        }
    }

    if !has_jwt_key {
        eprintln!();
        eprintln!("  Note: No JWT signing key was configured. Auth endpoints will not work.");
    }

    eprintln!();
    eprintln!("  Setup complete! Start the witness server with:");
    eprintln!("    webvh-witness --config {}", output_path.display());
    eprintln!();

    Ok(())
}

/// Prompt for VTA configuration.
fn configure_vta() -> Result<VtaConfig, Box<dyn std::error::Error>> {
    let enable = Confirm::new()
        .with_prompt("Configure VTA (Verifiable Trust Architecture) integration?")
        .default(false)
        .interact()?;

    if !enable {
        return Ok(VtaConfig::default());
    }

    let url: String = Input::new()
        .with_prompt("VTA REST URL")
        .default(String::new())
        .interact_text()?;

    let did: String = Input::new()
        .with_prompt("VTA DID (for DIDComm)")
        .default(String::new())
        .interact_text()?;

    let context_id: String = Input::new()
        .with_prompt("VTA context ID for witness keys")
        .default(String::new())
        .interact_text()?;

    Ok(VtaConfig {
        url: if url.is_empty() { None } else { Some(url) },
        did: if did.is_empty() { None } else { Some(did) },
        context_id: if context_id.is_empty() {
            None
        } else {
            Some(context_id)
        },
    })
}

/// Prompt for secrets backend selection and configuration.
fn configure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    #[allow(unused_mut)]
    let mut backends: Vec<&str> = Vec::new();

    #[cfg(feature = "keyring")]
    backends.push("OS Keyring (default)");

    #[cfg(feature = "aws-secrets")]
    backends.push("AWS Secrets Manager");

    #[cfg(feature = "gcp-secrets")]
    backends.push("GCP Secret Manager");

    if backends.is_empty() {
        eprintln!();
        eprintln!("  *** WARNING: No secure secrets backend is available. ***");
        eprintln!("  Secrets will be stored as PLAINTEXT in the configuration file.");
        eprintln!("  This is INSECURE and should only be used for testing/development.");
        eprintln!("  For production, recompile with: keyring, aws-secrets, or gcp-secrets.");
        eprintln!();

        let proceed = Confirm::new()
            .with_prompt("Continue with plaintext secrets storage?")
            .default(false)
            .interact()?;

        if !proceed {
            return Err(
                "setup cancelled — recompile with a secure secrets backend (keyring, aws-secrets, or gcp-secrets)".into(),
            );
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
            .interact()?;
        backends[idx]
    };

    let mut secrets_config = SecretsConfig::default();

    if chosen.starts_with("AWS") {
        let name: String = Input::new()
            .with_prompt("AWS secret name")
            .default("webvh-witness-secrets".to_string())
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
            .default("webvh-witness-secrets".to_string())
            .interact_text()?;
        secrets_config.gcp_secret_name = Some(name);
    } else {
        let service: String = Input::new()
            .with_prompt("Keyring service name")
            .default("webvh-witness".to_string())
            .interact_text()?;
        secrets_config.keyring_service = service;
    }

    Ok(secrets_config)
}

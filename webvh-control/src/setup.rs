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
use dialoguer::{Confirm, Input, Select};
use std::path::PathBuf;

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
        .default("http://localhost:8100".into())
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
        .default(8100)
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

    // 8. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: false,
            rest_api: true,
        },
        server_did: None,
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

    // 9. Store secrets
    let signing_key = generate_ed25519_multibase();
    let key_agreement_key = generate_x25519_multibase();
    let server_secrets = ServerSecrets {
        signing_key,
        key_agreement_key,
        jwt_signing_key,
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored.");

    // 10. Optional admin ACL bootstrap
    let add_admin = Confirm::new()
        .with_prompt("Add an admin DID to the ACL now?")
        .default(true)
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
    eprintln!("  Setup complete! Start the control plane with:");
    eprintln!("    webvh-control --config {}", output_path.display());
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

fn configure_secrets() -> Result<SecretsConfig, AppError> {
    let options = vec![
        #[cfg(feature = "keyring")]
        "OS Keyring (recommended for local dev)",
        "Plaintext in config.toml (not recommended for production)",
    ];

    if options.len() == 1 {
        return Ok(SecretsConfig::default());
    }

    let idx = Select::new()
        .with_prompt("Where should secrets be stored?")
        .items(&options)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    match options[idx] {
        s if s.contains("Keyring") => Ok(SecretsConfig::default()),
        _ => Ok(SecretsConfig::default()),
    }
}

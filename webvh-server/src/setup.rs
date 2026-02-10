use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use dialoguer::{Confirm, Input, MultiSelect, Select};

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LogConfig, LogFormat, ServerConfig, StoreConfig,
};
use crate::store::Store;

/// Generate a base64url-no-pad encoded 32-byte random key.
fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    BASE64.encode(bytes)
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
        .defaults(&[true, false])
        .interact()?;

    let enable_didcomm = selected.contains(&0);
    let enable_rest_api = selected.contains(&1);

    // 3. DIDComm-specific: Server DID and Mediator DID
    let mut server_did = None;
    let mut mediator_did = None;
    let mut signing_key = None;
    let mut key_agreement_key = None;
    let mut auth = AuthConfig::default();

    if enable_didcomm {
        let did: String = Input::new()
            .with_prompt("WebVH Server DID (e.g. did:web:example.com)")
            .interact_text()?;
        server_did = Some(did);

        let med_did: String = Input::new()
            .with_prompt("Mediator DID (e.g. did:web:mediator.example.com)")
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
        .default(3000)
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

    // 8. Key generation
    if enable_didcomm {
        let sk = generate_key();
        let kak = generate_key();
        let jsk = generate_key();

        eprintln!();
        eprintln!("  Generated cryptographic keys (back these up!):");
        eprintln!("  -----------------------------------------------");
        eprintln!("  signing_key:          {sk}");
        eprintln!("  key_agreement_key:    {kak}");
        eprintln!("  auth.jwt_signing_key: {jsk}");
        eprintln!();

        signing_key = Some(sk);
        key_agreement_key = Some(kak);
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
        }
    }

    eprintln!();
    eprintln!("  Setup complete! Start the server with:");
    eprintln!("    webvh-server --config {}", output_path.display());
    eprintln!();

    Ok(())
}

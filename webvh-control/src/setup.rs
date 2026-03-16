//! Interactive setup wizard for generating a control plane config.toml.

use crate::acl::{AclEntry, Role};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LogConfig, LogFormat, RegistryConfig, SecretsConfig,
    ServerConfig, StoreConfig, VtaConfig,
};
use crate::error::AppError;
use crate::secret_store::{ServerSecrets, create_secret_store};
use crate::store::Store;
use affinidi_webvh_common::server::vta_setup;
use dialoguer::{Confirm, Input, Select};
use std::path::PathBuf;

pub async fn run_setup() -> Result<(), AppError> {
    eprintln!();
    eprintln!("  WebVH Control Plane — Setup Wizard");
    eprintln!("  -----------------------------------");
    eprintln!();

    // 1. Output path
    eprintln!("  The configuration file stores all settings for the control plane.");
    eprintln!("  You can edit it later or re-run setup to regenerate it.");
    eprintln!();
    let output_path: String = Input::new()
        .with_prompt("Config file output path")
        .default("config.toml".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let output_path = PathBuf::from(output_path);

    // 2. VTA credential — authenticate with control's VTA context
    eprintln!();
    eprintln!("  The control plane needs a VTA credential to create its DID identity.");
    eprintln!("  This is the base64url string issued by the VTA operator for the");
    eprintln!("  control plane's context.");
    eprintln!();

    let credential_b64: String = Input::new()
        .with_prompt("VTA credential (base64url)")
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    let (client, conn_info) = vta_setup::connect_vta(credential_b64.trim())
        .await
        .map_err(|e| AppError::Config(format!("VTA authentication failed: {e}")))?;

    eprintln!("  Authenticated with VTA as {}", conn_info.client_did);
    eprintln!("  VTA context: {}", conn_info.context_id);

    // 3. DID hosting URL (where webvh-server serves DIDs)
    eprintln!();
    eprintln!("  The DID hosting URL is where your webvh-server serves DID documents.");
    eprintln!("  The control plane's DID will be published at <url>/<path>/did.jsonl.");
    eprintln!();
    let did_hosting_url: String = Input::new()
        .with_prompt("DID hosting URL (e.g. https://did.example.com)")
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let did_hosting_url = did_hosting_url.trim_end_matches('/').to_string();

    // 4. DID path
    let did_path: String = Input::new()
        .with_prompt("DID path on the server")
        .default("services/control".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    // 5. Create control DID via VTA
    eprintln!();
    eprintln!("  Creating control plane DID via VTA...");

    let did_result = vta_setup::create_did(
        &client,
        &conn_info.context_id,
        &did_hosting_url,
        &did_path,
        Some("webvh-control"),
    )
    .await
    .map_err(|e| AppError::Config(format!("failed to create DID: {e}")))?;

    eprintln!("  Control DID created: {}", did_result.did);
    eprintln!("  SCID: {}", did_result.scid);

    // 6. Write log entry to file
    if let Some(ref log_entry) = did_result.log_entry {
        let log_file = PathBuf::from("control-did.jsonl");
        let default_log_path = log_file.display().to_string();
        let log_path: String = Input::new()
            .with_prompt("DID log entry output file")
            .default(default_log_path)
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;

        vta_setup::write_log_entry_file(log_entry, &PathBuf::from(&log_path))?;
        eprintln!("  DID log entry written to {log_path}");

        // Dump raw log entry
        eprintln!();
        eprintln!("  DID Log Entry:");
        eprintln!("  ---");
        for line in log_entry.lines() {
            eprintln!("  {line}");
        }
        eprintln!("  ---");
    }

    // 7. Public URL (for WebAuthn/passkey)
    eprintln!();
    eprintln!("  The public URL is used for WebAuthn/passkey authentication.");
    eprintln!("  It must match the URL users will access in their browser.");
    eprintln!();
    let public_url: String = Input::new()
        .with_prompt("Public URL")
        .default("http://localhost:8532".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let public_url = if public_url.is_empty() {
        None
    } else {
        Some(public_url)
    };

    // 8. Host & Port
    eprintln!();
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

    // 9. Log level & format
    eprintln!();
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

    // 10. Data directory
    eprintln!();
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-control".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    // 11. Secrets backend
    eprintln!();
    let secrets_config = configure_secrets()?;

    // 12. JWT signing key (always generated)
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 13. Store secrets
    let server_secrets = ServerSecrets {
        signing_key: did_result.signing_key,
        key_agreement_key: did_result.key_agreement_key,
        jwt_signing_key,
        vta_credential: Some(credential_b64.trim().to_string()),
    };

    // 14. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: false,
            rest_api: true,
        },
        server_did: Some(did_result.did.clone()),
        mediator_did: None,
        public_url,
        did_hosting_url: Some(did_hosting_url),
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
        vta: VtaConfig {
            url: Some(conn_info.vta_url),
            did: Some(conn_info.vta_did),
            context_id: Some(conn_info.context_id),
        },
        registry: RegistryConfig::default(),
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored.");

    // 15. Admin ACL bootstrap
    eprintln!();
    eprintln!("  The control plane needs at least one admin in the ACL.");
    eprintln!();
    let admin_options = &[
        "Enter an existing DID",
        "Generate a new did:key identity",
        "Skip (add later with webvh-control add-acl)",
    ];
    let admin_idx = Select::new()
        .with_prompt("Admin ACL entry")
        .items(admin_options)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    if admin_idx <= 1 {
        let admin_did = if admin_idx == 0 {
            let did: String = Input::new()
                .with_prompt("Admin DID")
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;
            did
        } else {
            let (did, sk) = vta_setup::generate_admin_did_key();
            eprintln!("  Generated admin did:key: {did}");
            eprintln!("  Private key (save this!): {sk}");
            did
        };

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

    // 16. Summary
    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Control DID: {}", did_result.did);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Set up webvh-server (if not already done)");
    eprintln!(
        "    2. Import this DID on the server:"
    );
    eprintln!(
        "       webvh-server bootstrap-did --path {} --did-log control-did.jsonl",
        did_path
    );
    eprintln!("    3. Start the control plane:");
    eprintln!("       webvh-control --config {}", output_path.display());
    eprintln!();

    Ok(())
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
        let service: String = Input::new()
            .with_prompt("Keyring service name")
            .default("webvh".to_string())
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        secrets_config.keyring_service = service;
    }

    Ok(secrets_config)
}

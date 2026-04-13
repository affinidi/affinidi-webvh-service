use std::path::PathBuf;

use dialoguer::{Confirm, Input, Select};

use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LimitsConfig, LogConfig, LogFormat, SecretsConfig,
    ServerConfig, StoreConfig, VtaConfig,
};
use crate::secret_store::{ServerSecrets, create_secret_store};

use affinidi_webvh_common::server::vta_setup;

pub async fn run_wizard(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Server — Setup Wizard");
    eprintln!("  ===========================");
    eprintln!();
    eprintln!("  This configures a read-only server edge node that serves DID");
    eprintln!("  documents and receives sync updates from the control plane.");
    eprintln!("  All DID management is handled by the control plane.");
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
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                output_path.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // 2. VTA credential — authenticate with server's VTA context
    eprintln!();
    eprintln!("  The server needs a VTA credential to bootstrap its own DID identity.");
    eprintln!("  This DID is used for DIDComm authentication with the control plane,");
    eprintln!("  not for hosting user DIDs (that is managed by the control plane).");
    eprintln!("  This is the base64url string issued by the VTA operator.");
    eprintln!();

    let credential_b64: String = Input::new()
        .with_prompt("VTA credential (base64url)")
        .interact_text()?;

    let (client, conn_info) = vta_setup::connect_vta(credential_b64.trim()).await?;

    eprintln!("  Authenticated with VTA as {}", conn_info.client_did);
    eprintln!("  VTA context: {}", conn_info.context_id);

    // 3. Public URL — this becomes the server's DID identifier
    eprintln!();
    eprintln!("  This server needs its own DID identity (did:webvh). The URL you");
    eprintln!("  provide here determines the DID — for example, if you enter");
    eprintln!("  https://server1.example.com, the server's DID will be:");
    eprintln!("    did:webvh:<scid>:server1.example.com");
    eprintln!();
    eprintln!("  Each server instance in a distributed deployment should have a");
    eprintln!("  unique URL and therefore a unique DID.");
    eprintln!();
    let public_url: String = Input::new()
        .with_prompt("Server URL (e.g. https://server1.example.com)")
        .interact_text()?;
    let public_url = public_url.trim_end_matches('/').to_string();

    // 4. Mediator selection (before DID creation so it's embedded in the DID doc)
    eprintln!();
    eprintln!("  A DIDComm mediator routes sync messages from the control plane.");
    eprintln!();

    // Try to discover the VTA's mediator
    let vta_mediator = vta_setup::resolve_vta_mediator(&conn_info.vta_did).await;

    let mut mediator_options: Vec<String> = vec!["No mediator".into()];
    if let Some(ref did) = vta_mediator {
        mediator_options.push(format!("Use VTA's mediator ({did})"));
    }
    mediator_options.push("Enter a custom mediator DID".into());

    let mediator_idx = Select::new()
        .with_prompt("DIDComm mediator")
        .items(&mediator_options)
        .default(if vta_mediator.is_some() { 1 } else { 0 })
        .interact()?;

    let mediator_did = if mediator_options[mediator_idx].starts_with("No mediator") {
        None
    } else if mediator_options[mediator_idx].starts_with("Use VTA") {
        vta_mediator.clone()
    } else {
        let did: String = Input::new().with_prompt("Mediator DID").interact_text()?;
        if did.is_empty() { None } else { Some(did) }
    };

    // 5. Create root DID via VTA
    //
    // If the URL has a path (e.g. https://example.com/server1), the DID is
    // hosted at that path. If it's just a domain (https://example.com), the
    // DID goes in .well-known.
    let did_path = {
        // Extract path from URL: strip scheme + authority, trim slashes
        let after_scheme = public_url
            .find("://")
            .map(|i| &public_url[i + 3..])
            .unwrap_or(&public_url);
        let path = after_scheme
            .find('/')
            .map(|i| after_scheme[i..].trim_matches('/'))
            .unwrap_or("");
        if path.is_empty() {
            ".well-known".to_string()
        } else {
            path.to_string()
        }
    };

    eprintln!();
    eprintln!("  Creating server DID at path '{did_path}'...");

    let did_result = vta_setup::create_did(
        &client,
        &conn_info.context_id,
        &public_url,
        &did_path,
        Some("webvh-server"),
        mediator_did.as_deref(),
    )
    .await?;

    eprintln!("  Server DID created: {}", did_result.did);
    eprintln!("  SCID: {}", did_result.scid);

    if let Some(ref log_entry) = did_result.log_entry {
        eprintln!();
        eprintln!("  DID Log Entry:");
        eprintln!("  ---");
        for line in log_entry.lines() {
            eprintln!("  {line}");
        }
        eprintln!("  ---");
    }

    // 6. Control plane DID (for DIDComm sync)
    eprintln!();
    eprintln!("  The control plane manages all DIDs and pushes updates to this");
    eprintln!("  server via DIDComm through the mediator. Enter the control");
    eprintln!("  plane's DID so this server can authenticate sync messages.");
    eprintln!("  (Leave empty to configure later in config.toml)");
    eprintln!();
    let control_did: String = Input::new()
        .with_prompt("Control plane DID")
        .default(String::new())
        .interact_text()?;
    let control_did = if control_did.is_empty() {
        None
    } else {
        Some(control_did)
    };

    // 7. Host / Port
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8530)
        .interact_text()?;

    // 8. Log level / format
    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(log_levels)
        .default(0)
        .interact()?;
    let log_level = log_levels[log_level_idx].to_string();

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

    // 9. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-server".to_string())
        .interact_text()?;

    // 10. JWT signing key (always generated)
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 11. Secrets backend selection
    let secrets_config = configure_secrets()?;

    // 12. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: mediator_did.is_some(),
            rest_api: false,
            ..Default::default()
        },
        server_did: Some(did_result.did.clone()),
        mediator_did,
        public_url: Some(public_url.clone()),
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
        limits: LimitsConfig::default(),
        watchers: Vec::new(),
        control_url: None,
        control_did,
        vta: VtaConfig {
            url: Some(conn_info.vta_url),
            did: Some(conn_info.vta_did),
            context_id: Some(conn_info.context_id),
        },
        stats: crate::config::StatsConfig::default(),
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // 13. Store secrets
    let server_secrets = ServerSecrets {
        signing_key: did_result.signing_key,
        key_agreement_key: did_result.key_agreement_key,
        jwt_signing_key,
        vta_credential: Some(credential_b64.trim().to_string()),
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    // 14. Import root DID log entry into store
    if let Some(ref log_entry) = did_result.log_entry {
        eprintln!();
        eprintln!("  Importing root DID into server store...");

        let store = crate::store::Store::open(&config.store).await?;
        let dids_ks = store.keyspace("dids")?;

        match crate::bootstrap::import_root_did(&store, &dids_ks, log_entry, None).await {
            Ok(result) => {
                eprintln!("  Root DID imported!");
                eprintln!("  DID:  {}", result.did_id);
                eprintln!("  SCID: {}", result.scid);

                update_server_did_in_config(&output_path, &result.did_id)?;
                eprintln!("  server_did updated in {}", output_path.display());
            }
            Err(e) => {
                eprintln!("  Warning: failed to import root DID: {e}");
                eprintln!("  You can retry later with `webvh-server bootstrap-did`");
            }
        }
    }

    // 15. Summary
    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Server DID: {}", did_result.did);
    eprintln!();
    eprintln!("  This server is a read-only edge node. To manage DIDs,");
    eprintln!("  use the control plane (webvh-control) or the daemon (webvh-daemon).");
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Add this server's DID to the control plane ACL:");
    eprintln!(
        "       webvh-control add-acl --did {} --role service",
        did_result.did
    );
    eprintln!("    2. Start the server:");
    eprintln!("       webvh-server --config {}", output_path.display());
    eprintln!();

    Ok(())
}

/// Update `server_did` in the config file without clobbering other sections.
pub fn update_server_did_in_config(
    config_path: &PathBuf,
    server_did: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(config_path)?;
    let mut doc: toml::Value = toml::from_str(&contents)?;

    if let Some(table) = doc.as_table_mut() {
        table.insert(
            "server_did".to_string(),
            toml::Value::String(server_did.to_string()),
        );
    }

    std::fs::write(config_path, toml::to_string_pretty(&doc)?)?;
    Ok(())
}

/// Prompt for secrets backend selection and configuration.
#[allow(clippy::vec_init_then_push)]
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
        let project: String = Input::new().with_prompt("GCP project ID").interact_text()?;
        secrets_config.gcp_project = Some(project);

        let name: String = Input::new()
            .with_prompt("GCP secret name")
            .default("webvh-server-secrets".to_string())
            .interact_text()?;
        secrets_config.gcp_secret_name = Some(name);
    } else {
        let service: String = Input::new()
            .with_prompt("Keyring service name")
            .default("webvh".to_string())
            .interact_text()?;
        secrets_config.keyring_service = service;
    }

    Ok(secrets_config)
}

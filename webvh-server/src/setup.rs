use std::path::PathBuf;

use dialoguer::{Confirm, Input, MultiSelect, Select};

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::bootstrap;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LimitsConfig, LogConfig, LogFormat, SecretsConfig,
    ServerConfig, StoreConfig, VtaConfig,
};
use crate::secret_store::{ServerSecrets, create_secret_store};
use crate::store::Store;

use affinidi_webvh_common::server::vta_setup;

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

    // 2. Feature selection
    let feature_items = &["DIDComm Messaging", "REST API"];
    let selected = MultiSelect::new()
        .with_prompt("Which features do you want to enable? (Space to toggle, Enter to confirm)")
        .items(feature_items)
        .defaults(&[true, true])
        .interact()?;

    let enable_didcomm = selected.contains(&0);
    let enable_rest_api = selected.contains(&1);
    let auth = AuthConfig::default();

    // 3. VTA credential — authenticate with server's VTA context
    eprintln!();
    eprintln!("  The server needs a VTA credential to create its root DID identity.");
    eprintln!("  This is the base64url string issued by the VTA operator.");
    eprintln!();

    let credential_b64: String = Input::new()
        .with_prompt("VTA credential (base64url)")
        .interact_text()?;

    let (client, conn_info) = vta_setup::connect_vta(credential_b64.trim()).await?;

    eprintln!("  Authenticated with VTA as {}", conn_info.client_did);
    eprintln!("  VTA context: {}", conn_info.context_id);

    // 4. Public URL
    eprintln!();
    eprintln!("  The public URL is where this server will serve DID documents.");
    eprintln!();
    let public_url: String = Input::new()
        .with_prompt("Public URL (e.g. https://did.example.com)")
        .interact_text()?;
    let public_url = public_url.trim_end_matches('/').to_string();

    // 5. Mediator selection (before DID creation so it's embedded in the DID doc)
    eprintln!();
    eprintln!("  A DIDComm mediator routes encrypted messages to this service.");
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

    // 6. Create root DID via VTA at .well-known
    eprintln!();
    eprintln!("  Creating server root DID via VTA...");

    let did_result = vta_setup::create_did(
        &client,
        &conn_info.context_id,
        &public_url,
        ".well-known",
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

    // 7. Control plane connection
    eprintln!();
    eprintln!("  If you have a control plane, enter its URL and DID.");
    eprintln!("  Leave empty to skip (can be set later in config.toml).");
    eprintln!();

    let control_url: String = Input::new()
        .with_prompt("Control plane URL (e.g. http://localhost:8532)")
        .default(String::new())
        .interact_text()?;
    let control_url = if control_url.is_empty() {
        None
    } else {
        Some(control_url.trim_end_matches('/').to_string())
    };

    let control_did = if control_url.is_some() {
        let cd: String = Input::new()
            .with_prompt("Control plane DID")
            .default(String::new())
            .interact_text()?;
        if cd.is_empty() { None } else { Some(cd) }
    } else {
        None
    };

    // 8. Host / Port
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8530)
        .interact_text()?;

    // 9. Log level / format
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

    // 10. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-server".to_string())
        .interact_text()?;

    // 11. JWT signing key (always generated)
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 12. Secrets backend selection
    let secrets_config = configure_secrets()?;

    // 13. Build and write config
    let mut config = AppConfig {
        features: FeaturesConfig {
            didcomm: enable_didcomm,
            rest_api: enable_rest_api,
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
        auth,
        secrets: secrets_config,
        limits: LimitsConfig::default(),
        watchers: Vec::new(),
        control_url,
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

    // 14. Store secrets
    let server_secrets = ServerSecrets {
        signing_key: did_result.signing_key,
        key_agreement_key: did_result.key_agreement_key,
        jwt_signing_key,
        vta_credential: Some(credential_b64.trim().to_string()),
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    // 15. Import root DID log entry into store
    if let Some(ref log_entry) = did_result.log_entry {
        eprintln!();
        eprintln!("  Importing root DID into server store...");

        let store = Store::open(&config.store).await?;
        let dids_ks = store.keyspace("dids")?;

        match bootstrap::import_root_did(&store, &dids_ks, log_entry, None).await {
            Ok(result) => {
                eprintln!("  Root DID imported!");
                eprintln!("  DID:  {}", result.did_id);
                eprintln!("  SCID: {}", result.scid);

                config.server_did = Some(result.did_id.clone());
                update_server_did_in_config(&output_path, &result.did_id)?;
                eprintln!("  server_did updated in {}", output_path.display());
            }
            Err(e) => {
                eprintln!("  Warning: failed to import root DID: {e}");
                eprintln!("  You can retry later with `webvh-server bootstrap-did`");
            }
        }
    }

    // 16. Optional admin ACL bootstrap
    eprintln!();
    eprintln!("  The Access Control List (ACL) determines who can authenticate");
    eprintln!("  with this service. Without at least one admin entry, all");
    eprintln!("  authenticated API calls will be rejected.");
    eprintln!();
    eprintln!("  Admins can manage all DIDs, modify ACL entries, and access");
    eprintln!("  server configuration. Regular owners can only manage their");
    eprintln!("  own DIDs.");
    eprintln!();
    eprintln!("  You can add more entries later with:");
    eprintln!("    webvh-server add-acl --did <DID> --role admin");
    eprintln!();
    let admin_options = &[
        "Enter an existing DID (e.g. operator or service DID)",
        "Generate a new did:key identity for the operator",
        "Skip (add later with webvh-server add-acl)",
    ];
    let admin_idx = Select::new()
        .with_prompt("Admin ACL entry")
        .items(admin_options)
        .default(0)
        .interact()?;

    if admin_idx <= 1 {
        let admin_did = if admin_idx == 0 {
            let did: String = Input::new().with_prompt("Admin DID").interact_text()?;
            did
        } else {
            let (did, sk) = vta_setup::generate_admin_did_key();
            eprintln!("  Generated admin did:key: {did}");
            eprintln!("  Private key (save this!): {sk}");
            did
        };

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

    // 17. Summary
    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Server DID: {}", did_result.did);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Import companion service DIDs with `webvh-server bootstrap-did`");
    eprintln!("    2. Grant the server DID admin access on the control plane:");
    eprintln!(
        "       webvh-control add-acl --did {} --role admin",
        did_result.did
    );
    eprintln!("    3. Start the server:");
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

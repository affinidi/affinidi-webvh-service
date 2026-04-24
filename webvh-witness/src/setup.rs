use std::path::{Path, PathBuf};

use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde::{Deserialize, Serialize};

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LogConfig, LogFormat, SecretsConfig, ServerConfig,
    StoreConfig, VtaConfig,
};
use crate::secret_store::{ServerSecrets, create_secret_store};
use crate::store::Store;

use affinidi_webvh_common::server::vta_setup;

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

    // 3. VTA credential — authenticate with witness's VTA context
    eprintln!();
    eprintln!("  The witness needs a VTA credential to create its DID identity.");
    eprintln!("  This is the base64url string issued by the VTA operator.");
    eprintln!();

    let credential_b64: String = Input::new()
        .with_prompt("VTA credential (base64url)")
        .interact_text()?;

    let (client, conn_info) = vta_setup::connect_vta(credential_b64.trim()).await?;

    eprintln!("  Authenticated with VTA as {}", conn_info.client_did);
    eprintln!("  VTA context: {}", conn_info.context_id);

    // 4. DID hosting URL (where webvh-server serves DIDs)
    eprintln!();
    eprintln!("  The witness DID will be hosted on your webvh-server.");
    eprintln!();
    let did_hosting_url: String = Input::new()
        .with_prompt("DID hosting URL (e.g. https://did.example.com)")
        .interact_text()?;
    let did_hosting_url = did_hosting_url.trim_end_matches('/').to_string();

    // 5. DID path
    let did_path: String = Input::new()
        .with_prompt("DID path on the server")
        .default("services/witness".into())
        .interact_text()?;

    // 6. Mediator selection (before DID creation so it's embedded in the DID doc)
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

    // 7. Create witness DID via VTA
    eprintln!();
    eprintln!("  Creating witness DID via VTA...");

    let did_result = vta_setup::create_did(
        &client,
        &conn_info.context_id,
        &did_hosting_url,
        &did_path,
        Some("webvh-witness"),
        mediator_did.as_deref(),
    )
    .await?;

    eprintln!("  Witness DID created: {}", did_result.did);
    eprintln!("  SCID: {}", did_result.scid);

    // 8. Write log entry to file
    if let Some(ref log_entry) = did_result.log_entry {
        let default_log_path = "witness-did.jsonl".to_string();
        let log_path: String = Input::new()
            .with_prompt("DID log entry output file")
            .default(default_log_path)
            .interact_text()?;

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

    // 9. Host / Port
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8102u16)
        .interact_text()?;

    // 10. Log level / format
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

    // 11. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-witness".to_string())
        .interact_text()?;

    // 12. JWT signing key (always generated)
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 13. Secrets backend selection
    let secrets_config = configure_secrets()?;

    // 14. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: enable_didcomm,
            rest_api: enable_rest_api,
            ..Default::default()
        },
        server_did: Some(did_result.did.clone()),
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
        vta: VtaConfig {
            url: Some(conn_info.vta_url),
            did: Some(conn_info.vta_did),
            context_id: Some(conn_info.context_id),
        },
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // 15. Store secrets
    let server_secrets = ServerSecrets {
        signing_key: did_result.signing_key,
        key_agreement_key: did_result.key_agreement_key,
        jwt_signing_key,
        vta_credential: Some(credential_b64.trim().to_string()),
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    // 16. Optional admin ACL bootstrap
    eprintln!();
    eprintln!("  The Access Control List (ACL) determines who can authenticate");
    eprintln!("  with this service. Without at least one admin entry, all");
    eprintln!("  authenticated API calls will be rejected.");
    eprintln!();
    eprintln!("  Admins can create and manage witness identities, which are");
    eprintln!("  needed before the witness can sign proofs.");
    eprintln!();
    eprintln!("  You can add more entries later with:");
    eprintln!("    webvh-witness add-acl --did <DID> --role admin");
    eprintln!();
    let admin_options = &[
        "Enter an existing DID (e.g. operator or service DID)",
        "Generate a new did:key identity for the operator",
        "Skip (add later with webvh-witness add-acl)",
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
    eprintln!("  Witness DID: {}", did_result.did);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Import this DID on the server:");
    eprintln!(
        "       webvh-server bootstrap-did --path {} --did-log witness-did.jsonl",
        did_path
    );
    eprintln!("    2. Start the witness:");
    eprintln!("       webvh-witness --config {}", output_path.display());
    eprintln!();

    Ok(())
}

/// Prompt for secrets backend selection and configuration.
fn configure_secrets() -> Result<SecretsConfig, Box<dyn std::error::Error>> {
    #[allow(unused_mut)]
    #[cfg(feature = "keyring")]
    let mut backends: Vec<&str> = vec!["OS Keyring (default)"];

    #[allow(unused_mut)]
    #[cfg(not(feature = "keyring"))]
    let mut backends: Vec<&str> = Vec::new();

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
        let project: String = Input::new().with_prompt("GCP project ID").interact_text()?;
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

// ---------------------------------------------------------------------------
// Offline setup wizard (air-gapped VTA)
//
// Same two-step pattern as `webvh-control setup-offline-prepare/complete`
// and `webvh-server setup-offline-*`, adapted to witness's config:
// feature toggles (didcomm / rest_api), admin ACL with optional label, and
// "import this DID on the server" next-step text.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", content = "did", rename_all = "snake_case")]
enum AdminChoice {
    Did { did: String, label: Option<String> },
    Skip,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PendingWitnessSetupState {
    config_output: PathBuf,
    seed_path: PathBuf,
    enable_didcomm: bool,
    enable_rest_api: bool,
    did_hosting_url: String,
    did_path: String,
    mediator_did: Option<String>,
    did_log_output: PathBuf,
    host: String,
    port: u16,
    log_level: String,
    log_format: LogFormat,
    data_dir: String,
    secrets: SecretsConfig,
    admin: AdminChoice,
}

pub async fn run_setup_offline_prepare(
    config_path: Option<PathBuf>,
    request_out: PathBuf,
    seed_out: PathBuf,
    state_out: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Witness — Offline Setup (step 1/2)");
    eprintln!("  =========================================");
    eprintln!();
    eprintln!("  Captures all witness settings and writes a sealed-bundle");
    eprintln!("  bootstrap request. No VTA connection is made. After the");
    eprintln!("  operator ferries the request and receives a sealed reply,");
    eprintln!("  run `webvh-witness setup-offline-complete`.");
    eprintln!();

    let default_path = config_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "config.toml".to_string());

    let output_path: String = Input::new()
        .with_prompt("Configuration file path")
        .default(default_path)
        .interact_text()?;
    let config_output = PathBuf::from(&output_path);

    if config_output.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "{} already exists. Overwrite?",
                config_output.display()
            ))
            .default(false)
            .interact()?;
        if !overwrite {
            eprintln!("Setup cancelled.");
            return Ok(());
        }
    }

    // Feature selection (mirrors online wizard)
    let feature_items = &["DIDComm Messaging", "REST API"];
    let selected = MultiSelect::new()
        .with_prompt("Which features do you want to enable? (Space to toggle, Enter to confirm)")
        .items(feature_items)
        .defaults(&[true, true])
        .interact()?;
    let enable_didcomm = selected.contains(&0);
    let enable_rest_api = selected.contains(&1);

    let did_hosting_url: String = Input::new()
        .with_prompt("DID hosting URL (e.g. https://did.example.com)")
        .interact_text()?;
    let did_hosting_url = did_hosting_url.trim_end_matches('/').to_string();

    let did_path: String = Input::new()
        .with_prompt("DID path on the server")
        .default("services/witness".into())
        .interact_text()?;

    eprintln!();
    eprintln!("  A DIDComm mediator routes encrypted messages to this service.");
    eprintln!("  In the offline flow we can't auto-discover the VTA's mediator,");
    eprintln!("  so enter the mediator DID manually or skip.");
    eprintln!();
    let mediator_raw: String = Input::new()
        .with_prompt("Mediator DID (leave empty to skip)")
        .default(String::new())
        .interact_text()?;
    let mediator_did = if mediator_raw.trim().is_empty() {
        None
    } else {
        Some(mediator_raw.trim().to_string())
    };

    let did_log_output: String = Input::new()
        .with_prompt("DID log output file (written in step 2)")
        .default("witness-did.jsonl".into())
        .interact_text()?;
    let did_log_output = PathBuf::from(did_log_output);

    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;

    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8102u16)
        .interact_text()?;

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

    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-witness".to_string())
        .interact_text()?;

    let secrets = configure_secrets()?;

    // Admin ACL choice — resolve to a concrete DID now so the operator
    // can save a generated private key immediately.
    eprintln!();
    eprintln!("  Admin ACL entry — the witness rejects authenticated calls");
    eprintln!("  until at least one admin DID is enrolled. Admins create");
    eprintln!("  and manage witness identities.");
    eprintln!();
    let admin_options = &[
        "Enter an existing DID (e.g. operator or service DID)",
        "Generate a new did:key identity for the operator",
        "Skip (add later with webvh-witness add-acl)",
    ];
    let admin_idx = Select::new()
        .with_prompt("Admin ACL entry")
        .items(admin_options)
        .default(0)
        .interact()?;

    let admin = match admin_idx {
        0 => {
            let did: String = Input::new().with_prompt("Admin DID").interact_text()?;
            let admin_label: String = Input::new()
                .with_prompt("Label (optional)")
                .default(String::new())
                .interact_text()?;
            AdminChoice::Did {
                did,
                label: if admin_label.is_empty() {
                    None
                } else {
                    Some(admin_label)
                },
            }
        }
        1 => {
            let (did, sk) = vta_setup::generate_admin_did_key();
            eprintln!("  Generated admin did:key: {did}");
            eprintln!("  Private key (save this now — will not be re-shown): {sk}");
            AdminChoice::Did { did, label: None }
        }
        _ => AdminChoice::Skip,
    };

    let info =
        vta_setup::write_offline_bootstrap_request(&request_out, &seed_out, Some("webvh-witness"))?;

    let state = PendingWitnessSetupState {
        config_output: config_output.clone(),
        seed_path: info.seed_path.clone(),
        enable_didcomm,
        enable_rest_api,
        did_hosting_url,
        did_path,
        mediator_did,
        did_log_output,
        host,
        port,
        log_level,
        log_format,
        data_dir,
        secrets,
        admin,
    };
    let state_toml = toml::to_string_pretty(&state)?;
    if let Some(parent) = state_out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&state_out, &state_toml)?;

    eprintln!();
    eprintln!("  Offline setup step 1/2 complete.");
    eprintln!();
    eprintln!("  Request file:   {}", info.request_path.display());
    eprintln!("  Seed (secret):  {} (keep safe)", info.seed_path.display());
    eprintln!("  State file:     {}", state_out.display());
    eprintln!();
    eprintln!("  Consumer DID:   {}", info.client_did);
    eprintln!("  Nonce:          {}", info.nonce);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!(
        "    1. Ferry {} to your VTA admin.",
        info.request_path.display()
    );
    eprintln!("    2. Ask them to seal a webvh-service template response:");
    eprintln!(
        "         vta bootstrap seal --request <request-file> \\\n           --template webvh-service --var MEDIATOR_DID=<mediator-did>"
    );
    eprintln!("    3. They send back an ASCII-armored sealed bundle + SHA-256 digest.");
    eprintln!("    4. Run:");
    eprintln!(
        "         webvh-witness setup-offline-complete \\\n           --bundle <bundle> --expect-digest <hex> --state {}",
        state_out.display()
    );
    eprintln!();

    Ok(())
}

pub async fn run_setup_offline_complete(
    bundle_path: PathBuf,
    expect_digest: String,
    state_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Witness — Offline Setup (step 2/2)");
    eprintln!("  =========================================");
    eprintln!();

    let state_toml = std::fs::read_to_string(&state_path)?;
    let state: PendingWitnessSetupState = toml::from_str(&state_toml)?;

    let armor = std::fs::read_to_string(&bundle_path)?;
    let result =
        vta_setup::open_offline_bootstrap_response(&armor, &expect_digest, &state.seed_path)?;

    eprintln!("  Sealed response opened.");
    eprintln!("  DID:          {}", result.did);
    eprintln!("  VTA DID:      {}", result.vta_did);
    if let Some(ref url) = result.vta_url {
        eprintln!("  VTA URL:      {url}");
    }
    eprintln!();

    if let Some(ref log_entry) = result.log_entry {
        vta_setup::write_log_entry_file(log_entry, &state.did_log_output)?;
        eprintln!(
            "  DID log entry written to {}",
            state.did_log_output.display()
        );
    } else {
        eprintln!(
            "  Warning: sealed response carried no WebvhLog — nothing written to {}",
            state.did_log_output.display()
        );
    }

    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: state.enable_didcomm,
            rest_api: state.enable_rest_api,
            ..Default::default()
        },
        server_did: Some(result.did.clone()),
        mediator_did: state.mediator_did.clone(),
        server: ServerConfig {
            host: state.host.clone(),
            port: state.port,
        },
        log: LogConfig {
            level: state.log_level.clone(),
            format: state.log_format.clone(),
        },
        store: StoreConfig {
            data_dir: PathBuf::from(&state.data_dir),
            ..StoreConfig::default()
        },
        auth: AuthConfig::default(),
        secrets: state.secrets.clone(),
        vta: VtaConfig {
            url: result.vta_url.clone(),
            did: Some(result.vta_did.clone()),
            context_id: None,
        },
        config_path: state.config_output.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&state.config_output, &toml_str)?;
    eprintln!(
        "  Configuration written to {}",
        state.config_output.display()
    );

    let server_secrets = ServerSecrets {
        signing_key: result.signing_key_multibase,
        key_agreement_key: result.key_agreement_multibase,
        jwt_signing_key,
        vta_credential: None,
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    if let AdminChoice::Did { ref did, ref label } = state.admin {
        let store = Store::open(&config.store).await?;
        let acl_ks = store.keyspace("acl")?;
        let entry = AclEntry {
            did: did.clone(),
            role: Role::Admin,
            label: label.clone(),
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
        };
        store_acl_entry(&acl_ks, &entry).await?;
        eprintln!("  Admin ACL entry created for {did}");
    }

    cleanup_offline_artifacts(&state_path, &state.seed_path);

    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Witness DID: {}", result.did);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Import this DID on the server:");
    eprintln!(
        "       webvh-server bootstrap-did --path {} --did-log {}",
        state.did_path,
        state.did_log_output.display()
    );
    eprintln!("    2. Start the witness:");
    eprintln!(
        "       webvh-witness --config {}",
        state.config_output.display()
    );
    eprintln!();

    Ok(())
}

fn cleanup_offline_artifacts(state_path: &Path, seed_path: &Path) {
    if let Err(e) = std::fs::remove_file(state_path) {
        eprintln!(
            "  Warning: failed to remove state file {}: {e}",
            state_path.display()
        );
    }
    if let Err(e) = std::fs::remove_file(seed_path) {
        eprintln!(
            "  Warning: failed to remove ephemeral seed {}: {e}",
            seed_path.display()
        );
    }
}

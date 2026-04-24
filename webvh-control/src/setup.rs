//! Interactive setup wizard for generating a control plane config.toml.
//!
//! Three entry points: `run_setup` (online, talks to the VTA), and the
//! pair `run_setup_offline_prepare` / `run_setup_offline_complete` for
//! the air-gapped case where the VTA is reachable only by ferrying
//! a sealed bootstrap bundle.

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
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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

    // 5. Mediator selection
    eprintln!();
    eprintln!("  A DIDComm mediator routes encrypted messages to this service.");
    eprintln!("  If your VTA uses a mediator, you can embed the same one in");
    eprintln!("  the control plane's DID document.");
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
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    let mediator_did = if mediator_options[mediator_idx].starts_with("No mediator") {
        None
    } else if mediator_options[mediator_idx].starts_with("Use VTA") {
        vta_mediator.clone()
    } else {
        let did: String = Input::new()
            .with_prompt("Mediator DID")
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        if did.is_empty() { None } else { Some(did) }
    };

    // 6. Create control DID via VTA
    eprintln!();
    eprintln!("  Creating control plane DID via VTA...");

    let did_result = vta_setup::create_did(
        &client,
        &conn_info.context_id,
        &did_hosting_url,
        &did_path,
        Some("webvh-control"),
        mediator_did.as_deref(),
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
        .items(log_levels)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let log_level = log_levels[log_level_idx].to_string();

    let log_formats = ["text", "json"];
    let log_format_idx = Select::new()
        .with_prompt("Log format")
        .items(log_formats)
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
            ..Default::default()
        },
        server_did: Some(did_result.did.clone()),
        mediator_did,
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
    eprintln!("  The Access Control List (ACL) determines who can authenticate");
    eprintln!("  with this service. Without at least one admin entry, all");
    eprintln!("  authenticated API calls will be rejected.");
    eprintln!();
    eprintln!("  For the control plane, the webvh-server's DID must be added");
    eprintln!("  as an admin so it can register itself on startup. You can do");
    eprintln!("  this now if you know the server DID, or later with:");
    eprintln!("    webvh-control add-acl --did <server-did> --role admin");
    eprintln!();
    eprintln!("  You may also want an operator admin (your own DID or a");
    eprintln!("  generated did:key) for manual management.");
    eprintln!();
    let admin_options = &[
        "Enter an existing DID (e.g. server DID or operator DID)",
        "Generate a new did:key identity for the operator",
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
    eprintln!("    2. Import this DID on the server:");
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
#[allow(clippy::vec_init_then_push)]
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

// ---------------------------------------------------------------------------
// Offline setup wizard (air-gapped VTA)
//
// prepare = interactive prompts for everything the online wizard asks, minus
//     the VTA credential. Emits a `bootstrap-request.json` + ephemeral seed
//     and serialises the operator's choices to a TOML state file so the
//     follow-up `complete` invocation can finish setup without re-prompting.
//
// complete = loads the state, opens the sealed response bundle, persists the
//     DID + keys + config.toml exactly like the online wizard, and bootstraps
//     the admin ACL the operator picked earlier.
//
// The state file is plaintext (no secrets — the ephemeral seed lives in
// its own chmod-0600 file). Safe to hand between operators.
// ---------------------------------------------------------------------------

/// How the operator wants to bootstrap the admin ACL. Captured at
/// `prepare` time so `complete` can insert the entry without prompting.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", content = "did", rename_all = "snake_case")]
enum AdminChoice {
    Did(String),
    Skip,
}

/// Everything the offline-prepare step captured, serialised as TOML.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct PendingSetupState {
    config_output: PathBuf,
    seed_path: PathBuf,
    did_hosting_url: String,
    did_path: String,
    mediator_did: Option<String>,
    did_log_output: PathBuf,
    public_url: Option<String>,
    host: String,
    port: u16,
    log_level: String,
    log_format: LogFormat,
    data_dir: String,
    secrets: SecretsConfig,
    admin: AdminChoice,
}

/// Interactive offline-prepare: prompt for everything except VTA
/// credentials, write a bootstrap request + ephemeral seed + state file.
pub async fn run_setup_offline_prepare(
    request_out: PathBuf,
    seed_out: PathBuf,
    state_out: PathBuf,
) -> Result<(), AppError> {
    eprintln!();
    eprintln!("  WebVH Control Plane — Offline Setup (step 1/2)");
    eprintln!("  -----------------------------------------------");
    eprintln!();
    eprintln!("  This step captures all local settings and writes a sealed-bundle");
    eprintln!("  bootstrap request. No VTA connection is made. After the operator");
    eprintln!("  ferries the request to the VTA admin and receives a sealed reply,");
    eprintln!("  run `webvh-control setup-offline-complete` to finish.");
    eprintln!();

    let output_path: String = Input::new()
        .with_prompt("Config file output path")
        .default("config.toml".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let config_output = PathBuf::from(output_path);

    let did_hosting_url: String = Input::new()
        .with_prompt("DID hosting URL (e.g. https://did.example.com)")
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let did_hosting_url = did_hosting_url.trim_end_matches('/').to_string();

    let did_path: String = Input::new()
        .with_prompt("DID path on the server")
        .default("services/control".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    eprintln!();
    eprintln!("  A DIDComm mediator routes encrypted messages to this service.");
    eprintln!("  In the offline flow we can't auto-discover the VTA's mediator,");
    eprintln!("  so enter the mediator DID manually or skip.");
    eprintln!();
    let mediator_raw: String = Input::new()
        .with_prompt("Mediator DID (leave empty to skip)")
        .default(String::new())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let mediator_did = if mediator_raw.trim().is_empty() {
        None
    } else {
        Some(mediator_raw.trim().to_string())
    };

    let did_log_output: String = Input::new()
        .with_prompt("DID log output file (written in step 2)")
        .default("control-did.jsonl".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let did_log_output = PathBuf::from(did_log_output);

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

    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(log_levels)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let log_level = log_levels[log_level_idx].to_string();

    let log_formats = ["text", "json"];
    let log_format_idx = Select::new()
        .with_prompt("Log format")
        .items(log_formats)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let log_format = match log_format_idx {
        1 => LogFormat::Json,
        _ => LogFormat::Text,
    };

    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-control".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    let secrets = configure_secrets()?;

    // Admin ACL choice — resolve to a concrete DID now (so the
    // operator can save a generated private key immediately). The
    // `complete` step won't re-prompt.
    eprintln!();
    eprintln!("  Admin ACL entry — the control plane rejects authenticated calls");
    eprintln!("  until at least one admin DID is enrolled.");
    eprintln!();
    let admin_options = &[
        "Enter an existing DID (e.g. server DID or operator DID)",
        "Generate a new did:key identity for the operator",
        "Skip (add later with webvh-control add-acl)",
    ];
    let admin_idx = Select::new()
        .with_prompt("Admin ACL entry")
        .items(admin_options)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    let admin = match admin_idx {
        0 => {
            let did: String = Input::new()
                .with_prompt("Admin DID")
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;
            AdminChoice::Did(did)
        }
        1 => {
            let (did, sk) = vta_setup::generate_admin_did_key();
            eprintln!("  Generated admin did:key: {did}");
            eprintln!("  Private key (save this now — will not be re-shown): {sk}");
            AdminChoice::Did(did)
        }
        _ => AdminChoice::Skip,
    };

    // Write the bootstrap request + seed via the shared primitive.
    let info =
        vta_setup::write_offline_bootstrap_request(&request_out, &seed_out, Some("webvh-control"))
            .map_err(|e| AppError::Config(format!("failed to write bootstrap request: {e}")))?;

    // Persist state for `setup-offline-complete` to pick up.
    let state = PendingSetupState {
        config_output: config_output.clone(),
        seed_path: info.seed_path.clone(),
        did_hosting_url,
        did_path,
        mediator_did,
        did_log_output,
        public_url,
        host,
        port,
        log_level,
        log_format,
        data_dir,
        secrets,
        admin,
    };
    let state_toml = toml::to_string_pretty(&state)
        .map_err(|e| AppError::Config(format!("failed to serialize state: {e}")))?;
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
        "         webvh-control setup-offline-complete \\\n           --bundle <bundle> --expect-digest <hex> --state {}",
        state_out.display()
    );
    eprintln!();

    Ok(())
}

/// Finalise offline setup: open the sealed response, persist the DID
/// + keys + config + admin ACL using the state saved by `prepare`.
pub async fn run_setup_offline_complete(
    bundle_path: PathBuf,
    expect_digest: String,
    state_path: PathBuf,
) -> Result<(), AppError> {
    eprintln!();
    eprintln!("  WebVH Control Plane — Offline Setup (step 2/2)");
    eprintln!("  -----------------------------------------------");
    eprintln!();

    // Load the state the prepare step wrote.
    let state_toml = std::fs::read_to_string(&state_path).map_err(|e| {
        AppError::Config(format!(
            "failed to read state {}: {e}",
            state_path.display()
        ))
    })?;
    let state: PendingSetupState = toml::from_str(&state_toml)
        .map_err(|e| AppError::Config(format!("failed to parse state: {e}")))?;

    // Open the sealed bundle.
    let armor = std::fs::read_to_string(&bundle_path).map_err(|e| {
        AppError::Config(format!(
            "failed to read bundle {}: {e}",
            bundle_path.display()
        ))
    })?;
    let result =
        vta_setup::open_offline_bootstrap_response(&armor, &expect_digest, &state.seed_path)
            .map_err(|e| AppError::Config(format!("failed to open sealed response: {e}")))?;

    eprintln!("  Sealed response opened.");
    eprintln!("  DID:          {}", result.did);
    eprintln!("  VTA DID:      {}", result.vta_did);
    if let Some(ref url) = result.vta_url {
        eprintln!("  VTA URL:      {url}");
    }
    eprintln!();

    // Write DID log entry file if the template emitted one.
    if let Some(ref log) = result.log_entry {
        vta_setup::write_log_entry_file(log, &state.did_log_output)?;
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

    // Generate JWT signing key.
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    let server_secrets = ServerSecrets {
        signing_key: result.signing_key_multibase,
        key_agreement_key: result.key_agreement_multibase,
        jwt_signing_key,
        vta_credential: None, // offline flow has no reusable VTA credential
    };

    // Build and write config.toml.
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: false,
            rest_api: true,
            ..Default::default()
        },
        server_did: Some(result.did.clone()),
        mediator_did: state.mediator_did.clone(),
        public_url: state.public_url.clone(),
        did_hosting_url: Some(state.did_hosting_url.clone()),
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
            context_id: None, // offline flow doesn't surface the VTA context id
        },
        registry: RegistryConfig::default(),
        config_path: state.config_output.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;
    std::fs::write(&state.config_output, &toml_str)?;
    eprintln!(
        "  Configuration written to {}",
        state.config_output.display()
    );

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored.");

    // Bootstrap admin ACL per the choice captured in state.
    if let AdminChoice::Did(ref admin_did) = state.admin {
        let store = Store::open(&config.store).await?;
        let acl_ks = store.keyspace("acl")?;
        let entry = AclEntry {
            did: admin_did.clone(),
            role: Role::Admin,
            label: Some("Setup wizard admin (offline)".into()),
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
        };
        crate::acl::store_acl_entry(&acl_ks, &entry).await?;
        store.persist().await?;
        eprintln!("  Admin ACL entry added for {admin_did}");
    }

    // Best-effort cleanup — the operator may also want to keep these
    // around for audit, so failure here is only a warning.
    cleanup_offline_artifacts(&state_path, &state.seed_path);

    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Control DID: {}", result.did);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Set up webvh-server (if not already done)");
    eprintln!("    2. Import this DID on the server:");
    eprintln!(
        "       webvh-server bootstrap-did --path {} --did-log {}",
        state.did_path,
        state.did_log_output.display()
    );
    eprintln!("    3. Start the control plane:");
    eprintln!(
        "       webvh-control --config {}",
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

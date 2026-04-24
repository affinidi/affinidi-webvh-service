//! Interactive setup wizard for generating a daemon config.toml.
//!
//! The daemon embeds control + server + witness + (optional) watcher in
//! a single process sharing one DID. Setup is therefore essentially
//! control's online wizard adapted for `DaemonConfig`, plus the
//! server-style local DID import since the daemon also hosts its own
//! root DID.

use std::path::PathBuf;

use affinidi_webvh_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, LogFormat, ServerConfig, StoreConfig, VtaConfig,
};
use affinidi_webvh_common::server::secret_store::{ServerSecrets, create_secret_store};
use affinidi_webvh_common::server::store::Store;
use affinidi_webvh_common::server::vta_setup;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde::{Deserialize, Serialize};

use crate::config::{DaemonConfig, EnableConfig};

pub async fn run_wizard(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Daemon — Setup Wizard");
    eprintln!("  ============================");
    eprintln!();
    eprintln!("  The daemon runs control + server + witness + (optional) watcher");
    eprintln!("  in a single process, sharing one DID identity and one listen");
    eprintln!("  port. Setup provisions the DID via VTA and writes a unified");
    eprintln!("  config.toml.");
    eprintln!();

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

    // 1. Enabled services
    let (enable, features) = prompt_enable_and_features()?;

    // 2. VTA credential → create DID
    eprintln!();
    eprintln!("  The daemon needs a VTA credential to provision its DID.");
    eprintln!();
    let credential_b64: String = Input::new()
        .with_prompt("VTA credential (base64url)")
        .interact_text()?;
    let (client, conn_info) = vta_setup::connect_vta(credential_b64.trim()).await?;
    eprintln!("  Authenticated with VTA as {}", conn_info.client_did);
    eprintln!("  VTA context: {}", conn_info.context_id);

    // 3. Public URL + derived DID path (server convention)
    eprintln!();
    eprintln!("  The public URL is where the daemon is reachable. The embedded");
    eprintln!("  server hosts DID documents under this URL; the DID path is");
    eprintln!("  derived from the URL's path component (`.well-known` when");
    eprintln!("  there is no path).");
    eprintln!();
    let public_url: String = Input::new()
        .with_prompt("Public URL (e.g. https://webvh.example.com)")
        .interact_text()?;
    let public_url = public_url.trim_end_matches('/').to_string();

    let did_path = derive_did_path(&public_url);

    // 4. Mediator
    eprintln!();
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

    // 5. Create DID via VTA
    eprintln!();
    eprintln!("  Creating daemon DID at path '{did_path}'...");
    let did_result = vta_setup::create_did(
        &client,
        &conn_info.context_id,
        &public_url,
        &did_path,
        Some("webvh-daemon"),
        mediator_did.as_deref(),
    )
    .await?;
    eprintln!("  Daemon DID created: {}", did_result.did);
    eprintln!("  SCID: {}", did_result.scid);

    // 6. Host / port / log / data
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;
    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8534u16)
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
        .with_prompt("Data directory root")
        .default("data/daemon".to_string())
        .interact_text()?;
    let store_path = PathBuf::from(&data_dir).join("store");
    let witness_store_path = PathBuf::from(&data_dir).join("witness");

    // 7. Secrets backend
    let secrets_config = configure_secrets()?;

    // 8. Admin ACL (optional, captured as AdminChoice for reuse by offline flow)
    let admin = prompt_admin_choice()?;

    // 9. JWT signing key
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 10. Build + write config
    let config = DaemonConfig {
        server: ServerConfig {
            host: host.clone(),
            port,
        },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        auth: AuthConfig::default(),
        secrets: secrets_config,
        server_did: Some(did_result.did.clone()),
        mediator_did: mediator_did.clone(),
        public_url: Some(public_url.clone()),
        did_hosting_url: Some(public_url.clone()),
        store: StoreConfig {
            data_dir: store_path,
            ..StoreConfig::default()
        },
        witness_store: StoreConfig {
            data_dir: witness_store_path,
            ..StoreConfig::default()
        },
        limits: affinidi_webvh_server::config::LimitsConfig::default(),
        watchers: Vec::new(),
        vta: VtaConfig {
            url: Some(conn_info.vta_url.clone()),
            did: Some(conn_info.vta_did.clone()),
            context_id: Some(conn_info.context_id.clone()),
        },
        watcher_sync: affinidi_webvh_watcher::config::SyncConfig::default(),
        registry: affinidi_webvh_control::config::RegistryConfig::default(),
        features,
        enable,
        config_path: output_path.clone(),
    };

    // 11. Persist via shared helper (same as offline flow path).
    finalize_daemon_setup(
        &config,
        &output_path,
        ServerSecrets {
            signing_key: did_result.signing_key,
            key_agreement_key: did_result.key_agreement_key,
            jwt_signing_key,
            vta_credential: Some(credential_b64.trim().to_string()),
        },
        did_result.log_entry.as_deref(),
        &did_path,
        admin,
    )
    .await?;

    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Daemon DID: {}", did_result.did);
    eprintln!();
    eprintln!("  Start the daemon:");
    eprintln!("    webvh-daemon --config {}", output_path.display());
    eprintln!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Offline setup (air-gapped VTA)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", content = "did", rename_all = "snake_case")]
enum AdminChoice {
    Did(String),
    Skip,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PendingDaemonSetupState {
    config_output: PathBuf,
    seed_path: PathBuf,
    enable: EnableConfig,
    features: FeaturesConfig,
    public_url: String,
    did_path: String,
    mediator_did: Option<String>,
    host: String,
    port: u16,
    log_level: String,
    log_format: LogFormat,
    data_dir: String,
    secrets: affinidi_webvh_common::server::config::SecretsConfig,
    admin: AdminChoice,
}

pub async fn run_setup_offline_prepare(
    config_path: Option<PathBuf>,
    request_out: PathBuf,
    seed_out: PathBuf,
    state_out: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Daemon — Offline Setup (step 1/2)");
    eprintln!("  ========================================");
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

    let (enable, features) = prompt_enable_and_features()?;

    let public_url: String = Input::new()
        .with_prompt("Public URL (e.g. https://webvh.example.com)")
        .interact_text()?;
    let public_url = public_url.trim_end_matches('/').to_string();
    let did_path = derive_did_path(&public_url);

    eprintln!();
    eprintln!("  In the offline flow we can't auto-discover the VTA's mediator.");
    eprintln!();
    let mediator_raw: String = Input::new()
        .with_prompt("Mediator DID (leave empty to skip)")
        .default(String::new())
        .allow_empty(true)
        .interact_text()?;
    let mediator_did = if mediator_raw.trim().is_empty() {
        None
    } else {
        Some(mediator_raw.trim().to_string())
    };

    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;
    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(8534u16)
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
        .with_prompt("Data directory root")
        .default("data/daemon".to_string())
        .interact_text()?;

    let secrets = configure_secrets()?;
    let admin = prompt_admin_choice()?;

    let info =
        vta_setup::write_offline_bootstrap_request(&request_out, &seed_out, Some("webvh-daemon"))?;

    let state = PendingDaemonSetupState {
        config_output: config_output.clone(),
        seed_path: info.seed_path.clone(),
        enable,
        features,
        public_url,
        did_path,
        mediator_did,
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
    eprintln!("  Seed (secret):  {}", info.seed_path.display());
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
        "         webvh-daemon setup-offline-complete \\\n           --bundle <bundle> --expect-digest <hex> --state {}",
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
    eprintln!("  WebVH Daemon — Offline Setup (step 2/2)");
    eprintln!("  ========================================");
    eprintln!();

    let state_toml = std::fs::read_to_string(&state_path)?;
    let state: PendingDaemonSetupState = toml::from_str(&state_toml)?;

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

    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    let store_path = PathBuf::from(&state.data_dir).join("store");
    let witness_store_path = PathBuf::from(&state.data_dir).join("witness");

    let config = DaemonConfig {
        server: ServerConfig {
            host: state.host.clone(),
            port: state.port,
        },
        log: LogConfig {
            level: state.log_level.clone(),
            format: state.log_format.clone(),
        },
        auth: AuthConfig::default(),
        secrets: state.secrets.clone(),
        server_did: Some(result.did.clone()),
        mediator_did: state.mediator_did.clone(),
        public_url: Some(state.public_url.clone()),
        did_hosting_url: Some(state.public_url.clone()),
        store: StoreConfig {
            data_dir: store_path,
            ..StoreConfig::default()
        },
        witness_store: StoreConfig {
            data_dir: witness_store_path,
            ..StoreConfig::default()
        },
        limits: affinidi_webvh_server::config::LimitsConfig::default(),
        watchers: Vec::new(),
        vta: VtaConfig {
            url: result.vta_url.clone(),
            did: Some(result.vta_did.clone()),
            context_id: None,
        },
        watcher_sync: affinidi_webvh_watcher::config::SyncConfig::default(),
        registry: affinidi_webvh_control::config::RegistryConfig::default(),
        features: state.features.clone(),
        enable: state.enable.clone(),
        config_path: state.config_output.clone(),
    };

    finalize_daemon_setup(
        &config,
        &state.config_output,
        ServerSecrets {
            signing_key: result.signing_key_multibase,
            key_agreement_key: result.key_agreement_multibase,
            jwt_signing_key,
            vta_credential: None,
        },
        result.log_entry.as_deref(),
        &state.did_path,
        state.admin.clone(),
    )
    .await?;

    // Best-effort cleanup of the pending state + seed files.
    if let Err(e) = std::fs::remove_file(&state_path) {
        eprintln!("  Warning: failed to remove state file: {e}");
    }
    if let Err(e) = std::fs::remove_file(&state.seed_path) {
        eprintln!("  Warning: failed to remove ephemeral seed: {e}");
    }

    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Daemon DID: {}", result.did);
    eprintln!();
    eprintln!("  Start the daemon:");
    eprintln!(
        "    webvh-daemon --config {}",
        state.config_output.display()
    );
    eprintln!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Prompt for which services are enabled and derive the matching
/// `FeaturesConfig`. Control always implies `rest_api=true`; a mediator
/// is handled separately downstream and drives `didcomm`.
fn prompt_enable_and_features() -> Result<(EnableConfig, FeaturesConfig), Box<dyn std::error::Error>>
{
    let service_items = &[
        "control  (management API + UI)",
        "server   (public DID hosting)",
        "witness  (witness proofs)",
        "watcher  (read-only mirror)",
    ];
    let defaults = &[true, true, true, false];
    let selected = MultiSelect::new()
        .with_prompt("Which services should the daemon run? (Space to toggle, Enter to confirm)")
        .items(service_items)
        .defaults(defaults)
        .interact()?;
    let enable = EnableConfig {
        control: selected.contains(&0),
        server: selected.contains(&1),
        witness: selected.contains(&2),
        watcher: selected.contains(&3),
    };

    let features = FeaturesConfig {
        // If control is on, REST is on (admin UI depends on it). If only
        // the server is enabled, REST is still useful for health / stats
        // endpoints, so default it on.
        rest_api: enable.control || enable.server,
        // DIDComm is turned on by `finalize_daemon_setup` if a mediator
        // is configured; the seed value here is informational only.
        didcomm: false,
        ..Default::default()
    };

    Ok((enable, features))
}

fn prompt_admin_choice() -> Result<AdminChoice, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Admin ACL entry — the daemon rejects authenticated API calls");
    eprintln!("  until at least one admin DID is enrolled.");
    eprintln!();
    let admin_options = &[
        "Enter an existing DID (e.g. operator DID)",
        "Generate a new did:key identity for the operator",
        "Skip (add later with webvh-daemon add-acl)",
    ];
    let admin_idx = Select::new()
        .with_prompt("Admin ACL entry")
        .items(admin_options)
        .default(0)
        .interact()?;
    Ok(match admin_idx {
        0 => {
            let did: String = Input::new().with_prompt("Admin DID").interact_text()?;
            AdminChoice::Did(did)
        }
        1 => {
            let (did, sk) = vta_setup::generate_admin_did_key();
            eprintln!("  Generated admin did:key: {did}");
            eprintln!("  Private key (save this now — will not be re-shown): {sk}");
            AdminChoice::Did(did)
        }
        _ => AdminChoice::Skip,
    })
}

fn derive_did_path(public_url: &str) -> String {
    let after_scheme = public_url
        .find("://")
        .map(|i| &public_url[i + 3..])
        .unwrap_or(public_url);
    let path = after_scheme
        .find('/')
        .map(|i| after_scheme[i..].trim_matches('/'))
        .unwrap_or("");
    if path.is_empty() {
        ".well-known".to_string()
    } else {
        path.to_string()
    }
}

/// Everything common to the online + offline finalisation: write
/// config.toml, persist secrets, import the daemon's root DID into the
/// local server store, bootstrap admin ACL.
async fn finalize_daemon_setup(
    config: &DaemonConfig,
    output_path: &std::path::Path,
    secrets: ServerSecrets,
    log_entry: Option<&str>,
    did_path: &str,
    admin: AdminChoice,
) -> Result<(), Box<dyn std::error::Error>> {
    let toml_str = toml::to_string_pretty(config)?;
    std::fs::write(output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // Persist secrets via the configured backend. `create_secret_store`
    // takes the secrets sub-config + the config file path (used by
    // plaintext fallback to persist back into the toml).
    let secret_store = create_secret_store(&config.secrets, output_path)?;
    secret_store.set(&secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    // Import the daemon's own DID into the local server store, exactly
    // like `webvh-server setup` does — the daemon hosts its own DID.
    if let Some(log_entry) = log_entry {
        eprintln!();
        eprintln!("  Importing daemon DID into store at path '{did_path}'...");
        let store = Store::open(&config.store).await?;
        let dids_ks = store.keyspace("dids")?;
        match affinidi_webvh_server::bootstrap::import_did_at_path(
            &store, &dids_ks, did_path, log_entry, None,
        )
        .await
        {
            Ok(res) => {
                eprintln!("  Daemon DID imported!");
                eprintln!("  DID:  {}", res.did_id);
                eprintln!("  SCID: {}", res.scid);
                affinidi_webvh_server::setup::update_server_did_in_config(
                    &output_path.to_path_buf(),
                    &res.did_id,
                )?;
                eprintln!("  server_did updated in {}", output_path.display());
            }
            Err(e) => {
                eprintln!("  Warning: failed to import daemon DID: {e}");
                eprintln!(
                    "  You can retry with `webvh-server bootstrap-did --path {did_path}` \
                     against this config's store path."
                );
            }
        }
    }

    // Admin ACL bootstrap — the daemon's control plane store is shared
    // with the server store (same StoreConfig), so we insert into the
    // same `acl` keyspace the control plane reads on startup.
    if let AdminChoice::Did(admin_did) = admin {
        let store = Store::open(&config.store).await?;
        let acl_ks = store.keyspace("acl")?;
        let entry = affinidi_webvh_common::server::acl::AclEntry {
            did: admin_did.clone(),
            role: affinidi_webvh_common::server::acl::Role::Admin,
            label: Some("Setup wizard admin".into()),
            created_at: affinidi_webvh_common::server::auth::session::now_epoch(),
            max_total_size: None,
            max_did_count: None,
        };
        affinidi_webvh_common::server::acl::store_acl_entry(&acl_ks, &entry).await?;
        store.persist().await?;
        eprintln!("  Admin ACL entry added for {admin_did}");
    }

    Ok(())
}

fn configure_secrets()
-> Result<affinidi_webvh_common::server::config::SecretsConfig, Box<dyn std::error::Error>> {
    use affinidi_webvh_common::server::config::SecretsConfig;

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
        eprintln!("  For production, recompile with: keyring, aws-secrets, or gcp-secrets.");
        eprintln!();
        let proceed = Confirm::new()
            .with_prompt("Continue with plaintext secrets storage?")
            .default(false)
            .interact()?;
        if !proceed {
            return Err("setup cancelled — recompile with a secure secrets backend".into());
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
            .default("webvh-daemon-secrets".to_string())
            .interact_text()?;
        secrets_config.aws_secret_name = Some(name);
        let region: String = Input::new()
            .with_prompt("AWS region (leave empty for default)")
            .default(String::new())
            .allow_empty(true)
            .interact_text()?;
        if !region.is_empty() {
            secrets_config.aws_region = Some(region);
        }
    } else if chosen.starts_with("GCP") {
        let project: String = Input::new().with_prompt("GCP project ID").interact_text()?;
        secrets_config.gcp_project = Some(project);
        let name: String = Input::new()
            .with_prompt("GCP secret name")
            .default("webvh-daemon-secrets".to_string())
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

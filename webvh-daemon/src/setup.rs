//! Interactive setup wizard for generating a daemon config.toml.
//!
//! The daemon embeds control + server + witness + (optional) watcher in
//! a single process sharing one DID. Setup is therefore essentially
//! control's online wizard adapted for `DaemonConfig`, plus the
//! server-style local DID import since the daemon also hosts its own
//! root DID.

use std::path::PathBuf;

use std::sync::Arc;

use affinidi_webvh_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, LogFormat, ServerConfig, StoreConfig, VtaConfig,
};
use affinidi_webvh_common::server::operator_messages::WebvhDaemonMessages;
use affinidi_webvh_common::server::secret_store::{ServerSecrets, create_secret_store};
use affinidi_webvh_common::server::store::Store;
use affinidi_webvh_common::server::vta_setup;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use serde::{Deserialize, Serialize};
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages, ProvisionAsk};

use crate::config::{DaemonConfig, EnableConfig};

/// Phase 1 of the headless setup flow: mint an ephemeral did:key,
/// persist it (chmod 0600 on Unix) under `out_path`, and print the
/// `pnm contexts create` command the operator must run before phase 2.
pub async fn run_setup_phase1(
    out_path: &std::path::Path,
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::stderr;
    let messages = WebvhDaemonMessages;
    let finalise = format!("webvh-daemon setup --setup-key-file {}", out_path.display());
    let mut writer = stderr();
    vta_sdk::provision_client::driver::run_phase1_init(
        &mut writer,
        out_path,
        context_id,
        &messages,
        Some(&finalise),
    )
    .await?;
    Ok(())
}

pub async fn run_wizard(
    config_path: Option<PathBuf>,
    preloaded_setup_key_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Daemon — Setup Wizard");
    eprintln!("  ============================");
    eprintln!();
    eprintln!("  The daemon runs control + server + witness + (optional) watcher");
    eprintln!("  in a single process, sharing one DID identity and one listen");
    eprintln!("  port. Setup provisions the DID via VTA and writes a unified");
    eprintln!("  config.toml.");
    eprintln!();

    // Headless phase 2 (--setup-key-file) skips the mode prompt — the
    // operator already picked online when they ran phase 1.
    if preloaded_setup_key_file.is_none() {
        match prompt_vta_mode()? {
            VtaMode::Online => {}
            VtaMode::OfflineStart => {
                let (request, state) = prompt_offline_prepare_paths()?;
                return run_setup_offline_prepare(config_path, request, state).await;
            }
            VtaMode::OfflineComplete => {
                let (bundle, digest, state) = prompt_offline_complete_inputs()?;
                return run_setup_offline_complete(bundle, digest, state).await;
            }
        }
    }

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

    // 2. Public URL + derived DID path
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

    // 3. VTA DID + context, then provision via ephemeral did:key.
    //    Headless phase 2 supplies a pre-loaded setup key, in which case
    //    we skip the "Has the context been created?" confirmation.
    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhDaemonMessages);
    let preloaded_setup_key = match preloaded_setup_key_file.as_deref() {
        Some(path) => Some(EphemeralSetupKey::load_from(path)?),
        None => None,
    };
    let outcome = run_online_provision(&public_url, messages, preloaded_setup_key).await?;

    // 4. Mediator preference (runtime DIDComm — separate from the
    //    integration DID document, which the VTA already minted).
    eprintln!();
    let vta_mediator = vta_setup::resolve_vta_mediator(&outcome.vta_did).await;
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

    // 5. Host / port / log / data
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

    // 6. Secrets backend
    let secrets_config =
        affinidi_webvh_common::server::secret_store::wizard::prompt_secrets_backend(
            "webvh-daemon-secrets",
            "webvh",
        )
        .await?;

    // 7. Admin ACL (optional, captured as AdminChoice for reuse by offline flow)
    let admin = prompt_admin_choice()?;

    // 8. JWT signing key
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 9. Build + write config
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
        server_did: Some(outcome.integration_did.clone()),
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
            url: outcome.vta_url.clone(),
            did: Some(outcome.vta_did.clone()),
            context_id: None,
        },
        watcher_sync: affinidi_webvh_watcher::config::SyncConfig::default(),
        registry: affinidi_webvh_control::config::RegistryConfig::default(),
        features,
        enable,
        config_path: output_path.clone(),
    };

    // 10. Persist via shared helper (same as offline flow path).
    finalize_daemon_setup(
        &config,
        &output_path,
        ServerSecrets {
            signing_key: outcome.integration_signing_key_mb,
            key_agreement_key: outcome.integration_ka_key_mb,
            jwt_signing_key,
            vta_credential: Some(outcome.vta_credential_b64),
        },
        outcome.did_log_entry.as_deref(),
        &did_path,
        admin,
    )
    .await?;

    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Daemon DID: {}", outcome.integration_did);
    eprintln!("  Admin DID:  {}", outcome.admin_did);
    eprintln!();
    eprintln!("  Start the daemon:");
    eprintln!("    webvh-daemon --config {}", output_path.display());
    eprintln!();

    Ok(())
}

/// Choice of VTA reachability for the unified `setup` wizard.
enum VtaMode {
    /// VTA reachable from this host — provision online via the SDK.
    Online,
    /// VTA is air-gapped — write a sealed bootstrap request to ferry
    /// to the VTA admin (phase 1 of 2).
    OfflineStart,
    /// Operator already has a sealed response back from the VTA admin
    /// — open it and finish setup (phase 2 of 2).
    OfflineComplete,
}

/// Top-level mode prompt — drives the dispatch in `run_wizard`.
fn prompt_vta_mode() -> Result<VtaMode, Box<dyn std::error::Error>> {
    let items = [
        "Online — VTA reachable from this host",
        "Offline — start a new sealed-bundle bootstrap (phase 1)",
        "Offline — complete a pending sealed-bundle bootstrap (phase 2)",
    ];
    let idx = Select::new()
        .with_prompt("How will the daemon reach its VTA?")
        .items(&items)
        .default(0)
        .interact()?;
    Ok(match idx {
        0 => VtaMode::Online,
        1 => VtaMode::OfflineStart,
        _ => VtaMode::OfflineComplete,
    })
}

/// Prompt for the two output paths the offline-prepare phase writes.
/// The ephemeral seed is no longer a file — it lives in the configured
/// secrets backend (keyring / AWS / GCP / plaintext-in-config).
fn prompt_offline_prepare_paths() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let request: String = Input::new()
        .with_prompt("Bootstrap request file path")
        .default("bootstrap-request.json".into())
        .interact_text()?;
    let state: String = Input::new()
        .with_prompt("Pending state file path")
        .default("setup-offline-state.toml".into())
        .interact_text()?;
    Ok((PathBuf::from(request), PathBuf::from(state)))
}

/// Prompt for the inputs the offline-complete phase consumes.
fn prompt_offline_complete_inputs() -> Result<(PathBuf, String, PathBuf), Box<dyn std::error::Error>>
{
    let bundle: String = Input::new()
        .with_prompt("ASCII-armored sealed bundle path")
        .interact_text()?;
    let digest: String = Input::new()
        .with_prompt("Expected SHA-256 digest (lowercase hex)")
        .interact_text()?;
    let state: String = Input::new()
        .with_prompt("Pending state file path (from phase 1)")
        .default("setup-offline-state.toml".into())
        .interact_text()?;
    Ok((PathBuf::from(bundle), digest, PathBuf::from(state)))
}

/// Run the online VTA provision-integration round-trip:
///
/// 1. Prompt for VTA DID + context.
/// 2. Mint an ephemeral did:key.
/// 3. Print the operator's `pnm contexts create` command and wait
///    for them to confirm the ACL is in place.
/// 4. Drive `vta_sdk::provision_client::run_provision`.
async fn run_online_provision(
    public_url: &str,
    messages: Arc<dyn OperatorMessages>,
    preloaded_setup_key: Option<EphemeralSetupKey>,
) -> Result<vta_setup::OnlineProvisionOutcome, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Authenticating to the VTA.");
    eprintln!();
    let vta_did: String = Input::new()
        .with_prompt("VTA DID (e.g. did:webvh:vta.example.com)")
        .interact_text()?;
    let context_id: String = Input::new()
        .with_prompt("Context ID")
        .default("webvh".to_string())
        .interact_text()?;

    let setup_key = match preloaded_setup_key {
        Some(key) => {
            eprintln!();
            eprintln!("  Using pre-loaded setup DID: {}", key.did);
            key
        }
        None => {
            let key = EphemeralSetupKey::generate()?;
            eprintln!();
            eprintln!("  Ephemeral setup DID: {}", key.did);
            eprintln!();
            eprintln!("  Run this on a workstation with PNM authenticated to the VTA");
            eprintln!("  to create the context and grant the setup DID admin access:");
            eprintln!();
            eprintln!(
                "    {}",
                messages.pnm_admin_command_hint(&context_id, &key.did)
            );
            eprintln!();
            eprintln!("  --admin-expires defaults to 1h. The entry is promoted to");
            eprintln!("  permanent on first auth — this wizard does that for you.");
            eprintln!();

            let proceed = Confirm::new()
                .with_prompt("Has the context been created?")
                .default(true)
                .interact()?;
            if !proceed {
                return Err("setup cancelled before VTA round-trip".into());
            }
            key
        }
    };

    let ask = ProvisionAsk::webvh_hosting_server(&context_id, public_url)
        .with_label(format!("webvh-daemon setup — {context_id}"));

    eprintln!();
    eprintln!("  Provisioning daemon DID via VTA...");
    eprintln!();

    vta_setup::online_provision_setup(vta_setup::OnlineProvisionInputs {
        vta_did,
        context_id,
        ask,
        messages,
        setup_key,
    })
    .await
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
    eprintln!("  VTA context the integration will live in. Embedded in the");
    eprintln!("  bootstrap request as `contextHint` so the VTA admin can run");
    eprintln!("  `vta bootstrap provision-integration` without `--context`.");
    eprintln!();
    let context_id: String = Input::new()
        .with_prompt("VTA context ID")
        .default("webvh".to_string())
        .interact_text()?;

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

    let secrets = affinidi_webvh_common::server::secret_store::wizard::prompt_secrets_backend(
        "webvh-daemon-secrets",
        "webvh",
    )
    .await?;
    let admin = prompt_admin_choice()?;

    // VP-framed bootstrap request — names the `webvh-service` template
    // + binds `MEDIATOR_DID` so the VTA admin can run
    // `vta bootstrap provision-integration --request <file>` directly.
    let mediator_for_template = mediator_did.clone().unwrap_or_default();
    let info = vta_setup::write_offline_bootstrap_request(
        &request_out,
        "webvh-service",
        &[("MEDIATOR_DID", &mediator_for_template)],
        &context_id,
        Some("webvh-daemon"),
    )
    .await?;

    // Persist the ephemeral seed via the chosen secret store so it
    // survives until phase 2 — no on-disk seed file.
    let secret_store = create_secret_store(&secrets, &config_output)?;
    secret_store.set_bootstrap_seed(&info.seed).await?;

    let state = PendingDaemonSetupState {
        config_output: config_output.clone(),
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
    eprintln!("  State file:     {}", state_out.display());
    eprintln!("  Bootstrap seed: stored in the configured secrets backend");
    eprintln!();
    eprintln!("  Consumer DID:   {}", info.client_did);
    eprintln!("  Nonce:          {}", info.nonce);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!(
        "    1. Ferry {} to your VTA admin.",
        info.request_path.display()
    );
    eprintln!("    2. Ask them to create the VTA context with this DID as admin");
    eprintln!("       (skip if the context already exists), via either:");
    eprintln!(
        "         pnm contexts create --context {} \\\n           --admin {}",
        context_id, info.client_did
    );
    eprintln!("       or, on the VTA host directly:");
    eprintln!("         vta context create --id {}", context_id);
    eprintln!("    3. Ask them to seal a webvh-service template response:");
    eprintln!(
        "         vta bootstrap provision-integration --request <request-file> \\\n           --out <bundle-file>"
    );
    eprintln!("    4. They send back an ASCII-armored sealed bundle + SHA-256 digest.");
    eprintln!("    5. Run:");
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

    // Read the seed back from the same secret store we wrote it to in
    // phase 1.
    let secret_store = create_secret_store(&state.secrets, &state.config_output)?;
    let seed = secret_store
        .get_bootstrap_seed()
        .await?
        .ok_or("bootstrap seed missing from secret store — phase 1 may not have run")?;
    let result = vta_setup::open_offline_bootstrap_response(&armor, &expect_digest, &seed)?;

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

    // Drop the now-spent bootstrap seed from the secret store (the
    // secret store post-finalize, since `finalize_daemon_setup` may
    // rewrite the config.toml that the plaintext backend uses).
    let post_secret_store = create_secret_store(&config.secrets, &state.config_output)?;
    if let Err(e) = post_secret_store.clear_bootstrap_seed().await {
        eprintln!("  Warning: failed to clear bootstrap seed: {e}");
    }

    // Best-effort cleanup of the pending state file.
    if let Err(e) = std::fs::remove_file(&state_path) {
        eprintln!("  Warning: failed to remove state file: {e}");
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

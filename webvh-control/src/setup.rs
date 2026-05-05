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
use affinidi_webvh_common::server::operator_messages::WebvhControlMessages;
use affinidi_webvh_common::server::vta_setup;
use dialoguer::{Confirm, Input, Select};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages, ProvisionAsk};

/// Phase 1 of the headless setup flow: mint an ephemeral did:key,
/// persist it (chmod 0600 on Unix) under `out_path`, and print the
/// `pnm contexts create` command the operator must run before phase 2.
pub async fn run_setup_phase1(out_path: &Path, context_id: &str) -> Result<(), AppError> {
    use std::io::stderr;
    let messages = WebvhControlMessages;
    let finalise = format!(
        "webvh-control setup --setup-key-file {}",
        out_path.display()
    );
    let mut writer = stderr();
    vta_sdk::provision_client::driver::run_phase1_init(
        &mut writer,
        out_path,
        context_id,
        &messages,
        Some(&finalise),
    )
    .await
    .map_err(|e| AppError::Config(format!("phase 1 failed: {e}")))?;
    Ok(())
}

pub async fn run_setup(preloaded_setup_key_file: Option<PathBuf>) -> Result<(), AppError> {
    eprintln!();
    eprintln!("  WebVH Control Plane — Setup Wizard");
    eprintln!("  -----------------------------------");
    eprintln!();

    if preloaded_setup_key_file.is_none() {
        match prompt_vta_mode()? {
            VtaMode::Online => {}
            VtaMode::OfflineStart => {
                let (request, state) = prompt_offline_prepare_paths()?;
                return run_setup_offline_prepare(request, state).await;
            }
            VtaMode::OfflineComplete => {
                let (bundle, digest, state) = prompt_offline_complete_inputs()?;
                return run_setup_offline_complete(bundle, digest, state).await;
            }
            VtaMode::SelfManaged => {
                return Err(AppError::Config(SELF_MANAGED_DAEMON_ONLY.into()));
            }
        }
    }

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

    // 2. VTA online provision: mint ephemeral did:key, print PNM
    //    `contexts create` command, drive run_provision with the
    //    `webvh-control` template. Headless phase 2 supplies a
    //    pre-loaded setup key.
    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhControlMessages);
    let preloaded_setup_key = match preloaded_setup_key_file.as_deref() {
        Some(path) => Some(
            EphemeralSetupKey::load_from(path)
                .map_err(|e| AppError::Config(format!("load setup key: {e}")))?,
        ),
        None => None,
    };

    // DID hosting URL must be collected BEFORE the VTA round-trip because
    // upstream `ProvisionAsk::webvh_control` embeds it as the
    // `WebVHHosting` service endpoint in the resulting DID document.
    eprintln!();
    eprintln!("  The DID hosting URL is where your webvh-server serves DID documents.");
    eprintln!("  The control plane's DID will be published at <url>/<path>/did.jsonl.");
    eprintln!();
    let did_hosting_url: String = Input::new()
        .with_prompt("DID hosting URL (e.g. https://did.example.com)")
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let did_hosting_url = did_hosting_url.trim_end_matches('/').to_string();

    let (mediator_did, outcome) =
        run_online_provision(messages, preloaded_setup_key, &did_hosting_url)
            .await
            .map_err(|e| AppError::Config(format!("VTA provision-integration failed: {e}")))?;

    // 4. DID path
    let did_path: String = Input::new()
        .with_prompt("DID path on the server")
        .default("services/control".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;

    // 5. Persist DID log entry (if the template emitted one) so the
    //    operator can publish it on the webvh hosting server.
    if let Some(ref log_entry) = outcome.did_log_entry {
        let log_file = PathBuf::from("control-did.jsonl");
        let default_log_path = log_file.display().to_string();
        let log_path: String = Input::new()
            .with_prompt("DID log entry output file")
            .default(default_log_path)
            .interact_text()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;

        vta_setup::write_log_entry_file(log_entry, &PathBuf::from(&log_path))?;
        eprintln!("  DID log entry written to {log_path}");

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
    let secrets_config =
        affinidi_webvh_common::server::secret_store::wizard::prompt_secrets_backend(
            "webvh-control-secrets",
            "webvh",
        )
        .await
        .map_err(|e| AppError::Config(e.to_string()))?;

    // 12. JWT signing key (always generated)
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 13. Store secrets
    let server_secrets = ServerSecrets {
        signing_key: outcome.integration_signing_key_mb.clone(),
        key_agreement_key: outcome.integration_ka_key_mb.clone(),
        jwt_signing_key,
        vta_credential: Some(outcome.vta_credential_b64.clone()),
    };

    // 14. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: true,
            rest_api: true,
            ..Default::default()
        },
        server_did: Some(outcome.integration_did.clone()),
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
            url: outcome.vta_url.clone(),
            did: Some(outcome.vta_did.clone()),
            context_id: None,
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
    eprintln!("  Control DID: {}", outcome.integration_did);
    eprintln!("  Admin DID:   {}", outcome.admin_did);
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

/// Choice of VTA reachability for the unified `setup` wizard.
enum VtaMode {
    Online,
    OfflineStart,
    OfflineComplete,
    /// Selected only to produce a clear "daemon-only" error — webvh-control
    /// has no self-managed implementation in v1.
    SelfManaged,
}

use affinidi_webvh_common::server::vta_setup::SELF_MANAGED_DAEMON_ONLY;

fn prompt_vta_mode() -> Result<VtaMode, AppError> {
    let items = [
        "Online — VTA reachable from this host",
        "Offline — start a new sealed-bundle bootstrap (phase 1)",
        "Offline — complete a pending sealed-bundle bootstrap (phase 2)",
        "Self-managed (no VTA — daemon-only mode, will exit with error here)",
    ];
    let idx = Select::new()
        .with_prompt("How will the control plane reach its VTA?")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    Ok(match idx {
        0 => VtaMode::Online,
        1 => VtaMode::OfflineStart,
        2 => VtaMode::OfflineComplete,
        _ => VtaMode::SelfManaged,
    })
}

fn prompt_offline_prepare_paths() -> Result<(PathBuf, PathBuf), AppError> {
    let request: String = Input::new()
        .with_prompt("Bootstrap request file path")
        .default("bootstrap-request.json".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let state: String = Input::new()
        .with_prompt("Pending state file path")
        .default("setup-offline-state.toml".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    Ok((PathBuf::from(request), PathBuf::from(state)))
}

fn prompt_offline_complete_inputs() -> Result<(PathBuf, String, PathBuf), AppError> {
    let bundle: String = Input::new()
        .with_prompt("ASCII-armored sealed bundle path")
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let digest: String = Input::new()
        .with_prompt("Expected SHA-256 digest (lowercase hex)")
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    let state: String = Input::new()
        .with_prompt("Pending state file path (from phase 1)")
        .default("setup-offline-state.toml".into())
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    Ok((PathBuf::from(bundle), digest, PathBuf::from(state)))
}

/// Run the online VTA provision-integration round-trip:
/// prompt for VTA DID + context, resolve the VTA's mediator (since the
/// `webvh-control` template requires `MEDIATOR_DID`), let the operator
/// confirm or override it, mint an ephemeral did:key, print the
/// operator's `pnm contexts create` command, wait for confirmation,
/// then drive `vta_sdk::provision_client::run_provision`.
///
/// Returns the chosen mediator DID alongside the provision outcome —
/// the caller persists it as `config.mediator_did` so the runtime
/// DIDComm path uses the same mediator the DID document embeds.
async fn run_online_provision(
    messages: Arc<dyn OperatorMessages>,
    preloaded_setup_key: Option<EphemeralSetupKey>,
    did_hosting_url: &str,
) -> Result<(Option<String>, vta_setup::OnlineProvisionOutcome), Box<dyn std::error::Error>> {
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

    // The webvh-control template needs a MEDIATOR_DID up-front (it
    // embeds a DIDComm service endpoint pointing at the mediator).
    eprintln!();
    eprintln!("  A DIDComm mediator routes encrypted messages to the control plane.");
    eprintln!("  The mediator DID is embedded in the control plane's DID document");
    eprintln!("  and reused at runtime for outbound DIDComm.");
    eprintln!();
    let vta_mediator = vta_setup::resolve_vta_mediator(&vta_did).await;
    let mut mediator_options: Vec<String> = Vec::new();
    if let Some(ref did) = vta_mediator {
        mediator_options.push(format!("Use VTA's mediator ({did})"));
    }
    mediator_options.push("Enter a custom mediator DID".into());
    let mediator_idx = Select::new()
        .with_prompt("DIDComm mediator")
        .items(&mediator_options)
        .default(0)
        .interact()?;
    let mediator_did: String = if mediator_options[mediator_idx].starts_with("Use VTA") {
        vta_mediator
            .clone()
            .expect("Use VTA option only present when discovered")
    } else {
        Input::new().with_prompt("Mediator DID").interact_text()?
    };

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

    let ask = ProvisionAsk::webvh_control(&context_id, did_hosting_url, &mediator_did)
        .with_label(format!("webvh-control setup — {context_id}"));

    eprintln!();
    eprintln!("  Provisioning control plane DID via VTA...");
    eprintln!();

    let outcome = vta_setup::online_provision_setup(vta_setup::OnlineProvisionInputs {
        vta_did,
        context_id,
        ask,
        messages,
        setup_key,
    })
    .await?;

    Ok((Some(mediator_did), outcome))
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
/// credentials, write a bootstrap request file, persist the ephemeral
/// seed in the configured secrets backend, and serialise the choices
/// to a state TOML.
pub async fn run_setup_offline_prepare(
    request_out: PathBuf,
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
    eprintln!("  VTA context the integration will live in. Embedded in the");
    eprintln!("  bootstrap request as `contextHint` so the VTA admin can run");
    eprintln!("  `vta bootstrap provision-integration` without `--context`.");
    eprintln!();
    let context_id: String = Input::new()
        .with_prompt("VTA context ID")
        .default("webvh".to_string())
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

    let secrets = affinidi_webvh_common::server::secret_store::wizard::prompt_secrets_backend(
        "webvh-control-secrets",
        "webvh",
    )
    .await
    .map_err(|e| AppError::Config(e.to_string()))?;

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

    // Write the VP-framed bootstrap request via the shared primitive;
    // the seed is returned in memory and persisted via the configured
    // secret store (no on-disk seed file). The VP names the
    // `webvh-control` template (HTTP + DIDComm) + binds both `URL`
    // (host_url for the WebVHHosting service) and `MEDIATOR_DID` (for
    // the DIDCommMessaging service) so the VTA admin can run
    // `vta bootstrap provision-integration --request <file>` without
    // extra flags.
    let mediator_for_template = mediator_did.clone().unwrap_or_default();
    let info = vta_setup::write_offline_bootstrap_request(
        &request_out,
        "webvh-control",
        &[
            ("URL", did_hosting_url.as_str()),
            ("MEDIATOR_DID", &mediator_for_template),
        ],
        &context_id,
        Some("webvh-control"),
    )
    .await
    .map_err(|e| AppError::Config(format!("failed to write bootstrap request: {e}")))?;
    let secret_store =
        affinidi_webvh_common::server::secret_store::create_secret_store(&secrets, &config_output)?;
    secret_store.set_bootstrap_seed(&info.seed).await?;

    // Persist state for `setup-offline-complete` to pick up.
    let state = PendingSetupState {
        config_output: config_output.clone(),
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
    eprintln!(
        "         vta contexts create --id {} \\\n           --admin-did {} --admin-expires 1h",
        context_id, info.client_did
    );
    eprintln!("    3. Ask them to seal the response:");
    eprintln!(
        "         vta bootstrap provision-integration --request <request-file> \\\n           --out <bundle-file>"
    );
    eprintln!("    4. They send back an ASCII-armored sealed bundle + SHA-256 digest.");
    eprintln!("    5. Run:");
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
    let pre_secret_store = affinidi_webvh_common::server::secret_store::create_secret_store(
        &state.secrets,
        &state.config_output,
    )?;
    let seed = pre_secret_store
        .get_bootstrap_seed()
        .await?
        .ok_or_else(|| {
            AppError::Config(
                "bootstrap seed missing from secret store — phase 1 may not have run".into(),
            )
        })?;
    let result = vta_setup::open_offline_bootstrap_response(&armor, &expect_digest, &seed)
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
            didcomm: true,
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

    // Drop the now-spent bootstrap seed from the secret store. We
    // re-instantiate post-finalize because plaintext mode rewrites the
    // config.toml when persisting `ServerSecrets`.
    let post_secret_store = affinidi_webvh_common::server::secret_store::create_secret_store(
        &config.secrets,
        &state.config_output,
    )?;
    if let Err(e) = post_secret_store.clear_bootstrap_seed().await {
        eprintln!("  Warning: failed to clear bootstrap seed: {e}");
    }

    // Best-effort cleanup — the operator may also want to keep the
    // state file around for audit, so failure here is only a warning.
    cleanup_offline_artifacts(&state_path);

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

fn cleanup_offline_artifacts(state_path: &Path) {
    if let Err(e) = std::fs::remove_file(state_path) {
        eprintln!(
            "  Warning: failed to remove state file {}: {e}",
            state_path.display()
        );
    }
}

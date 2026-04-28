use std::path::{Path, PathBuf};
use std::sync::Arc;

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

use affinidi_webvh_common::server::operator_messages::WebvhWitnessMessages;
use affinidi_webvh_common::server::vta_setup;
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages, ProvisionAsk};

/// Phase 1 of the headless setup flow: mint an ephemeral did:key,
/// persist it (chmod 0600 on Unix) under `out_path`, and print the
/// `pnm contexts create` command the operator must run before phase 2.
pub async fn run_setup_phase1(
    out_path: &Path,
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::stderr;
    let messages = WebvhWitnessMessages;
    let finalise = format!(
        "webvh-witness setup --setup-key-file {}",
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
    .await?;
    Ok(())
}

pub async fn run_wizard(
    config_path: Option<PathBuf>,
    preloaded_setup_key_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Witness — Setup Wizard");
    eprintln!("  ============================");
    eprintln!();

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

    // 3. VTA online provision: prompt for VTA DID + context + mediator,
    //    mint ephemeral did:key, print PNM `contexts create` command,
    //    drive run_provision with the `webvh-service` template.
    //    Headless phase 2 supplies a pre-loaded setup key.
    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhWitnessMessages);
    let preloaded_setup_key = match preloaded_setup_key_file.as_deref() {
        Some(path) => Some(EphemeralSetupKey::load_from(path)?),
        None => None,
    };
    let (mediator_did, outcome) = run_online_provision(messages, preloaded_setup_key).await?;

    // 4. DID hosting URL (where webvh-server serves DIDs)
    eprintln!();
    eprintln!("  The witness DID will be hosted on your webvh-server.");
    eprintln!();
    let did_hosting_url: String = Input::new()
        .with_prompt("DID hosting URL (e.g. https://did.example.com)")
        .interact_text()?;
    let _did_hosting_url = did_hosting_url.trim_end_matches('/').to_string();

    // 5. DID path
    let did_path: String = Input::new()
        .with_prompt("DID path on the server")
        .default("services/witness".into())
        .interact_text()?;

    // 6. Persist DID log entry (if the template emitted one) so the
    //    operator can publish it on the webvh hosting server.
    if let Some(ref log_entry) = outcome.did_log_entry {
        let default_log_path = "witness-did.jsonl".to_string();
        let log_path: String = Input::new()
            .with_prompt("DID log entry output file")
            .default(default_log_path)
            .interact_text()?;

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
    let secrets_config =
        affinidi_webvh_common::server::secret_store::wizard::prompt_secrets_backend(
            "webvh-witness-secrets",
            "webvh-witness",
        )
        .await?;

    // 14. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: enable_didcomm,
            rest_api: enable_rest_api,
            ..Default::default()
        },
        server_did: Some(outcome.integration_did.clone()),
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
            url: outcome.vta_url.clone(),
            did: Some(outcome.vta_did.clone()),
            context_id: None,
        },
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // 15. Store secrets
    let server_secrets = ServerSecrets {
        signing_key: outcome.integration_signing_key_mb.clone(),
        key_agreement_key: outcome.integration_ka_key_mb.clone(),
        jwt_signing_key,
        vta_credential: Some(outcome.vta_credential_b64.clone()),
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
    eprintln!("  Witness DID: {}", outcome.integration_did);
    eprintln!("  Admin DID:   {}", outcome.admin_did);
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

/// Choice of VTA reachability for the unified `setup` wizard.
enum VtaMode {
    Online,
    OfflineStart,
    OfflineComplete,
}

fn prompt_vta_mode() -> Result<VtaMode, Box<dyn std::error::Error>> {
    let items = [
        "Online — VTA reachable from this host",
        "Offline — start a new sealed-bundle bootstrap (phase 1)",
        "Offline — complete a pending sealed-bundle bootstrap (phase 2)",
    ];
    let idx = Select::new()
        .with_prompt("How will the witness reach its VTA?")
        .items(&items)
        .default(0)
        .interact()?;
    Ok(match idx {
        0 => VtaMode::Online,
        1 => VtaMode::OfflineStart,
        _ => VtaMode::OfflineComplete,
    })
}

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
/// prompt for VTA DID + context, resolve the VTA's mediator (since the
/// `webvh-service` template requires `MEDIATOR_DID`), let the operator
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

    // The webvh-service template needs a MEDIATOR_DID up-front (it
    // embeds a DIDComm service endpoint pointing at the mediator).
    eprintln!();
    eprintln!("  A DIDComm mediator routes encrypted messages to the witness.");
    eprintln!("  The mediator DID is embedded in the witness's DID document");
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

    let ask = ProvisionAsk::webvh_service(&context_id, &mediator_did)
        .with_label(format!("webvh-witness setup — {context_id}"));

    eprintln!();
    eprintln!("  Provisioning witness DID via VTA...");
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
    eprintln!("  VTA context the integration will live in. Embedded in the");
    eprintln!("  bootstrap request as `contextHint` so the VTA admin can run");
    eprintln!("  `vta bootstrap provision-integration` without `--context`.");
    eprintln!();
    let context_id: String = Input::new()
        .with_prompt("VTA context ID")
        .default("webvh".to_string())
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

    let secrets = affinidi_webvh_common::server::secret_store::wizard::prompt_secrets_backend(
        "webvh-witness-secrets",
        "webvh-witness",
    )
    .await?;

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

    // VP-framed bootstrap request — names the `webvh-service` template
    // + binds `MEDIATOR_DID` so the VTA admin can run
    // `vta bootstrap provision-integration --request <file>` directly.
    let mediator_for_template = mediator_did.clone().unwrap_or_default();
    let info = vta_setup::write_offline_bootstrap_request(
        &request_out,
        "webvh-service",
        &[("MEDIATOR_DID", &mediator_for_template)],
        &context_id,
        Some("webvh-witness"),
    )
    .await?;
    let secret_store =
        affinidi_webvh_common::server::secret_store::create_secret_store(&secrets, &config_output)?;
    secret_store.set_bootstrap_seed(&info.seed).await?;

    let state = PendingWitnessSetupState {
        config_output: config_output.clone(),
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
    let pre_secret_store = affinidi_webvh_common::server::secret_store::create_secret_store(
        &state.secrets,
        &state.config_output,
    )?;
    let seed = pre_secret_store
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

    // Drop the now-spent bootstrap seed from the secret store. We
    // re-instantiate post-finalize because plaintext mode rewrites the
    // config.toml when persisting `ServerSecrets`.
    let post_secret_store = affinidi_webvh_common::server::secret_store::create_secret_store(
        &state.secrets,
        &state.config_output,
    )?;
    if let Err(e) = post_secret_store.clear_bootstrap_seed().await {
        eprintln!("  Warning: failed to clear bootstrap seed: {e}");
    }

    cleanup_offline_artifacts(&state_path);

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

fn cleanup_offline_artifacts(state_path: &Path) {
    if let Err(e) = std::fs::remove_file(state_path) {
        eprintln!(
            "  Warning: failed to remove state file {}: {e}",
            state_path.display()
        );
    }
}

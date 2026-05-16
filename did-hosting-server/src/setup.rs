use std::path::{Path, PathBuf};
use std::sync::Arc;

use dialoguer::{Confirm, Input, Select};
use serde::{Deserialize, Serialize};

use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LimitsConfig, LogConfig, LogFormat, SecretsConfig,
    ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::store::{KS_DIDS};
use crate::secret_store::{ServerSecrets, create_secret_store};

use did_hosting_common::server::operator_messages::WebvhServerMessages;
use did_hosting_common::server::setup_prompts;
use did_hosting_common::server::vta_setup;
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages, ProvisionAsk};

/// Phase 1 of the headless setup flow: mint an ephemeral did:key,
/// persist it (chmod 0600 on Unix) under `out_path`, and print the
/// `pnm contexts create` command the operator must run before phase 2.
pub async fn run_setup_phase1(
    out_path: &Path,
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::stderr;
    let messages = WebvhServerMessages;
    let finalise = format!("did-hosting-server setup --setup-key-file {}", out_path.display());
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
    eprintln!("  WebVH Server — Setup Wizard");
    eprintln!("  ===========================");
    eprintln!();
    eprintln!("  This configures a read-only server edge node that serves DID");
    eprintln!("  documents and receives sync updates from the control plane.");
    eprintln!("  All DID management is handled by the control plane.");
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
            VtaMode::SelfManaged => {
                return Err(SELF_MANAGED_DAEMON_ONLY.into());
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

    // 2. Public URL — this becomes the server's DID identifier
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

    // DID path derived from the URL's path component. With a bare host
    // (`https://example.com`) the DID is published at `.well-known`;
    // otherwise the URL path becomes the DID path.
    let did_path = {
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

    // 3. VTA online provision — mint ephemeral did:key, print PNM
    //    `contexts create` command, then drive run_provision.
    //    Headless phase 2 supplies a pre-loaded setup key.
    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhServerMessages);
    let preloaded_setup_key = match preloaded_setup_key_file.as_deref() {
        Some(path) => Some(EphemeralSetupKey::load_from(path)?),
        None => None,
    };
    let outcome = run_online_provision(&public_url, messages, preloaded_setup_key).await?;
    let did_result_log_entry = outcome.did_log_entry.clone();

    if let Some(ref log_entry) = did_result_log_entry {
        eprintln!();
        eprintln!("  DID Log Entry:");
        eprintln!("  ---");
        for line in log_entry.lines() {
            eprintln!("  {line}");
        }
        eprintln!("  ---");
    }

    // 4. Mediator preference (runtime DIDComm with the control plane).
    eprintln!();
    eprintln!("  A DIDComm mediator routes sync messages from the control plane.");
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
    let host = setup_prompts::prompt_listen_host("0.0.0.0")?;
    let port = setup_prompts::prompt_listen_port(8530)?;

    // 8. Log level / format
    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(log_levels)
        .default(0)
        .interact()?;
    let log_level = log_levels[log_level_idx].to_string();

    let log_format = setup_prompts::prompt_log_format()?;

    // 9. Data directory
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/did-hosting-server".to_string())
        .interact_text()?;

    // 10. JWT signing key (always generated)
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!("  Generated JWT signing key.");

    // 11. Secrets backend selection
    let secrets_config =
        did_hosting_common::server::secret_store::wizard::prompt_secrets_backend(
            "did-hosting-server-secrets",
            "webvh",
        )
        .await?;

    // 12. Build and write config
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: mediator_did.is_some(),
            rest_api: false,
            ..Default::default()
        },
        server_did: Some(outcome.integration_did.clone()),
        mediator_did,
        public_url: Some(public_url.clone()),
        server: ServerConfig {
            host,
            port,
            trusted_proxies: Vec::new(),
        },
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
            url: outcome.vta_url.clone(),
            did: Some(outcome.vta_did.clone()),
            context_id: None,
        },
        stats: crate::config::StatsConfig::default(),
        config_path: output_path.clone(),
    };

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&output_path, &toml_str)?;
    eprintln!("  Configuration written to {}", output_path.display());

    // 13. Store secrets
    let server_secrets = ServerSecrets {
        signing_key: outcome.integration_signing_key_mb,
        key_agreement_key: outcome.integration_ka_key_mb,
        jwt_signing_key,
        vta_credential: Some(outcome.vta_credential_b64),
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    // 14. Import DID log entry into store at the correct path
    if let Some(ref log_entry) = did_result_log_entry {
        eprintln!();
        eprintln!("  Importing server DID into store at path '{did_path}'...");

        let store = crate::store::Store::open(&config.store).await?;
        let dids_ks = store.keyspace(KS_DIDS)?;

        match crate::bootstrap::import_did_at_path(&store, &dids_ks, &did_path, log_entry, None)
            .await
        {
            Ok(result) => {
                eprintln!("  Server DID imported!");
                eprintln!("  DID:  {}", result.did_id);
                eprintln!("  SCID: {}", result.scid);

                update_server_did_in_config(&output_path, &result.did_id)?;
                eprintln!("  server_did updated in {}", output_path.display());
            }
            Err(e) => {
                eprintln!("  Warning: failed to import server DID: {e}");
                eprintln!(
                    "  You can retry later with `did-hosting-server bootstrap-did --path {did_path}`"
                );
            }
        }
    }

    // 15. Summary
    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Server DID: {}", outcome.integration_did);
    eprintln!("  Admin DID:  {}", outcome.admin_did);
    eprintln!();
    eprintln!("  This server is a read-only edge node. To manage DIDs,");
    eprintln!("  use the control plane (did-hosting-control) or the daemon (did-hosting-daemon).");
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Add this server's DID to the control plane ACL:");
    eprintln!(
        "       did-hosting-control add-acl --did {} --role service",
        outcome.integration_did
    );
    eprintln!("    2. Start the server:");
    eprintln!("       did-hosting-server --config {}", output_path.display());
    eprintln!();

    Ok(())
}

/// Choice of VTA reachability for the unified `setup` wizard.
enum VtaMode {
    Online,
    OfflineStart,
    OfflineComplete,
    /// Selected only to produce a clear "daemon-only" error — did-hosting-server
    /// has no self-managed implementation in v1.
    SelfManaged,
}

use did_hosting_common::server::vta_setup::SELF_MANAGED_DAEMON_ONLY;

fn prompt_vta_mode() -> Result<VtaMode, Box<dyn std::error::Error>> {
    let items = [
        "Online — VTA reachable from this host",
        "Offline — start a new sealed-bundle bootstrap (phase 1)",
        "Offline — complete a pending sealed-bundle bootstrap (phase 2)",
        "Self-managed (no VTA — daemon-only mode, will exit with error here)",
    ];
    let idx = Select::new()
        .with_prompt("How will the server reach its VTA?")
        .items(items)
        .default(0)
        .interact()?;
    Ok(match idx {
        0 => VtaMode::Online,
        1 => VtaMode::OfflineStart,
        2 => VtaMode::OfflineComplete,
        _ => VtaMode::SelfManaged,
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
/// prompt for VTA DID + context, mint an ephemeral did:key, print the
/// operator's `pnm contexts create` command, wait for confirmation,
/// then drive `vta_sdk::provision_client::run_provision`.
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

    let ask = ProvisionAsk::webvh_daemon(&context_id, public_url)
        .with_label(format!("did-hosting-server setup — {context_id}"));

    eprintln!();
    eprintln!("  Provisioning server DID via VTA...");
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

/// Update `server_did` in the config file without clobbering other sections.
// ---------------------------------------------------------------------------
// Offline setup wizard (air-gapped VTA)
//
// Same two-step pattern as `did-hosting-control setup-offline-prepare/complete`,
// with server-specific config: URL-derived DID path, control_did prompt,
// limits, root-DID import into the local store. See that module for the
// design rationale.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PendingServerSetupState {
    config_output: PathBuf,
    public_url: String,
    did_path: String,
    mediator_did: Option<String>,
    control_did: Option<String>,
    host: String,
    port: u16,
    log_level: String,
    log_format: LogFormat,
    data_dir: String,
    secrets: SecretsConfig,
}

/// Interactive offline-prepare for did-hosting-server: prompts for every
/// non-VTA setting, writes the bootstrap request file, persists the
/// ephemeral seed in the configured secrets backend, and serialises
/// the choices to a state TOML.
pub async fn run_setup_offline_prepare(
    config_path: Option<PathBuf>,
    request_out: PathBuf,
    state_out: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Server — Offline Setup (step 1/2)");
    eprintln!("  ========================================");
    eprintln!();
    eprintln!("  Captures all server settings and writes a sealed-bundle");
    eprintln!("  bootstrap request. No VTA connection is made. After the");
    eprintln!("  operator ferries the request to the VTA admin and receives");
    eprintln!("  a sealed reply, run `did-hosting-server setup-offline-complete`.");
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

    eprintln!();
    let public_url: String = Input::new()
        .with_prompt("Server URL (e.g. https://server1.example.com)")
        .interact_text()?;
    let public_url = public_url.trim_end_matches('/').to_string();

    // DID path derived from URL path component (matches the online wizard).
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
    eprintln!("  A DIDComm mediator routes sync messages from the control plane.");
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

    eprintln!();
    let control_did: String = Input::new()
        .with_prompt("Control plane DID (leave empty to set later)")
        .default(String::new())
        .interact_text()?;
    let control_did = if control_did.is_empty() {
        None
    } else {
        Some(control_did)
    };

    let host = setup_prompts::prompt_listen_host("0.0.0.0")?;
    let port = setup_prompts::prompt_listen_port(8530)?;

    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(log_levels)
        .default(0)
        .interact()?;
    let log_level = log_levels[log_level_idx].to_string();

    let log_format = setup_prompts::prompt_log_format()?;

    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/did-hosting-server".to_string())
        .interact_text()?;

    let secrets = did_hosting_common::server::secret_store::wizard::prompt_secrets_backend(
        "did-hosting-server-secrets",
        "webvh",
    )
    .await?;

    // Write the VP-framed bootstrap request via the shared primitive;
    // the seed is returned in memory and persisted via the configured
    // secret store. The VP names the `did-hosting-daemon` template (HTTP-only
    // hosting — runtime DIDComm uses `mediator_did` separately) and
    // binds the `URL` template variable so the rendered DID exposes a
    // `WebVHHosting` service at the server's public URL.
    let info = vta_setup::write_offline_bootstrap_request(
        &request_out,
        "did-hosting-daemon",
        &[("URL", &public_url)],
        &context_id,
        Some("did-hosting-server"),
    )
    .await?;
    let secret_store =
        did_hosting_common::server::secret_store::create_secret_store(&secrets, &config_output)?;
    secret_store.set_bootstrap_seed(&info.seed).await?;

    let state = PendingServerSetupState {
        config_output: config_output.clone(),
        public_url,
        did_path,
        mediator_did,
        control_did,
        host,
        port,
        log_level,
        log_format,
        data_dir,
        secrets,
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
        "         did-hosting-server setup-offline-complete \\\n           --bundle <bundle> --expect-digest <hex> --state {}",
        state_out.display()
    );
    eprintln!();

    Ok(())
}

/// Finalise offline setup: open the sealed response, persist the DID
/// + keys + config + import the root DID per the state saved by prepare.
pub async fn run_setup_offline_complete(
    bundle_path: PathBuf,
    expect_digest: String,
    state_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  WebVH Server — Offline Setup (step 2/2)");
    eprintln!("  ========================================");
    eprintln!();

    let state_toml = std::fs::read_to_string(&state_path)?;
    let state: PendingServerSetupState = toml::from_str(&state_toml)?;

    let armor = std::fs::read_to_string(&bundle_path)?;
    let secret_store = did_hosting_common::server::secret_store::create_secret_store(
        &state.secrets,
        &state.config_output,
    )?;
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

    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: state.mediator_did.is_some(),
            rest_api: false,
            ..Default::default()
        },
        server_did: Some(result.did.clone()),
        mediator_did: state.mediator_did.clone(),
        public_url: Some(state.public_url.clone()),
        server: ServerConfig {
            host: state.host.clone(),
            port: state.port,
            trusted_proxies: Vec::new(),
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
        limits: LimitsConfig::default(),
        watchers: Vec::new(),
        control_url: None,
        control_did: state.control_did.clone(),
        vta: VtaConfig {
            url: result.vta_url.clone(),
            did: Some(result.vta_did.clone()),
            context_id: None,
        },
        stats: crate::config::StatsConfig::default(),
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
        vta_credential: None, // offline flow has no reusable VTA credential
    };

    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!("  Secrets stored in secret store.");

    // Import the server's own DID into the local store at the derived path.
    // Mirrors the online wizard's bootstrap::import_did_at_path step.
    if let Some(ref log_entry) = result.log_entry {
        eprintln!();
        eprintln!(
            "  Importing server DID into store at path '{}'...",
            state.did_path
        );

        let store = crate::store::Store::open(&config.store).await?;
        let dids_ks = store.keyspace(KS_DIDS)?;

        match crate::bootstrap::import_did_at_path(
            &store,
            &dids_ks,
            &state.did_path,
            log_entry,
            None,
        )
        .await
        {
            Ok(import) => {
                eprintln!("  Server DID imported!");
                eprintln!("  DID:  {}", import.did_id);
                eprintln!("  SCID: {}", import.scid);
                update_server_did_in_config(&state.config_output, &import.did_id)?;
                eprintln!("  server_did updated in {}", state.config_output.display());
            }
            Err(e) => {
                eprintln!("  Warning: failed to import server DID: {e}");
                eprintln!(
                    "  You can retry with `did-hosting-server bootstrap-did --path {}`",
                    state.did_path
                );
            }
        }
    } else {
        eprintln!();
        eprintln!("  Warning: sealed response carried no WebvhLog — server DID not imported.");
    }

    // Drop the now-spent bootstrap seed from the secret store. We
    // re-instantiate post-finalize because plaintext mode rewrites the
    // config.toml when persisting `ServerSecrets`.
    let post_secret_store = did_hosting_common::server::secret_store::create_secret_store(
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
    eprintln!("  Server DID: {}", result.did);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Add this server's DID to the control plane ACL:");
    eprintln!(
        "       did-hosting-control add-acl --did {} --role service",
        result.did
    );
    eprintln!("    2. Start the server:");
    eprintln!(
        "       did-hosting-server --config {}",
        state.config_output.display()
    );
    eprintln!();

    Ok(())
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

fn cleanup_offline_artifacts(state_path: &Path) {
    if let Err(e) = std::fs::remove_file(state_path) {
        eprintln!(
            "  Warning: failed to remove state file {}: {e}",
            state_path.display()
        );
    }
}

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

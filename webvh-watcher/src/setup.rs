//! Setup for a watcher: its own DID, with keys in a VTA context, and the
//! sources it mirrors.
//!
//! The watcher's identity follows the same VTA-context pattern as every other
//! service here: the VTA provisions a `did:webvh` for it (DIDComm/TSP via a
//! mediator, published by the operator on a hosting server), its keys and the
//! context credential go to the configured secret store, and `config.toml`
//! records the DID. A recipe (`setup --from <recipe.toml>`) drives any VTA
//! mode — online (with `--setup-key-file`), offline-prepare,
//! offline-complete; the interactive wizard drives online.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dialoguer::{Confirm, Input, Select};
use did_hosting_common::server::operator_messages::WebvhWatcherMessages;
use did_hosting_common::server::secret_store::ServerSecrets;
use did_hosting_common::server::setup_recipe::{
    DeploymentSection, IdentitySection, OutputSection, ServiceKind, SetupRecipe, VtaMode,
    VtaSection, VtaSetupOutcome, WatcherSection, active_backend, apply_env_overrides,
    back_up_config, inspect_existing, load_recipe, print_recipe_banner, refuse_overwrite,
    require_service, resolve_secrets_config, run_vta_for_recipe, to_log_format,
};
use did_hosting_common::server::vta_setup;
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages};

use crate::config::{
    AppConfig, FeaturesConfig, LogConfig, ServerConfig, StoreConfig, SyncConfig, VtaConfig,
};
use crate::error::AppError;

type BoxError = Box<dyn std::error::Error>;

/// Phase 1 of the headless online flow: mint an ephemeral did:key, persist it
/// under `out_path`, and print the `pnm contexts create` command to run before
/// `setup --from <recipe> --setup-key-file <out_path>`.
pub async fn run_setup_phase1(out_path: &Path, context_id: &str) -> Result<(), BoxError> {
    let finalise = format!(
        "webvh-watcher setup --from <recipe.toml> --setup-key-file {}",
        out_path.display()
    );
    let mut writer = std::io::stderr();
    vta_sdk::provision_client::driver::run_phase1_init(
        &mut writer,
        out_path,
        context_id,
        &WebvhWatcherMessages,
        Some(&finalise),
    )
    .await?;
    Ok(())
}

/// Non-interactive setup driven by a [`SetupRecipe`] TOML file.
pub async fn run_from_recipe(
    recipe_path: &Path,
    setup_key_file: Option<PathBuf>,
    force_reprovision: bool,
) -> Result<(), BoxError> {
    let recipe = load_recipe(recipe_path)?;
    require_service(&recipe, ServiceKind::Watcher)?;
    let setup_key = setup_key_file
        .as_deref()
        .map(EphemeralSetupKey::load_from)
        .transpose()?;
    apply_recipe(recipe, setup_key, force_reprovision).await
}

/// Interactive online setup. Builds the same recipe the headless path reads,
/// and applies it.
pub async fn run_wizard(
    config_path: Option<PathBuf>,
    setup_key_file: Option<PathBuf>,
) -> Result<(), BoxError> {
    eprintln!();
    eprintln!("  WebVH Watcher — Setup Wizard");
    eprintln!("  =============================");
    eprintln!();
    eprintln!("  The watcher mirrors DIDs its control planes push to it as signed");
    eprintln!("  Trust Tasks. It has its own DID, provisioned from a VTA context.");
    eprintln!();

    let default_path = config_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "config.toml".to_string());
    let output_path: String = Input::new()
        .with_prompt("Configuration file path")
        .default(default_path)
        .interact_text()?;
    let host: String = Input::new()
        .with_prompt("Listen host")
        .default("0.0.0.0".to_string())
        .interact_text()?;
    let port: u16 = Input::new()
        .with_prompt("Listen port")
        .default(SetupRecipe::default_port(ServiceKind::Watcher))
        .interact_text()?;
    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default("data/webvh-watcher".to_string())
        .interact_text()?;

    eprintln!();
    eprintln!("  Sources: the DIDs of the control planes this watcher mirrors.");
    eprintln!("  A sync signed by anyone else is refused.");
    eprintln!();
    let sources_raw: String = Input::new()
        .with_prompt("Source control-plane DIDs (comma-separated)")
        .interact_text()?;
    let source_dids: Vec<String> = sources_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let vta_did: String = Input::new()
        .with_prompt("VTA DID (e.g. did:webvh:vta.example.com)")
        .interact_text()?;
    let context_id: String = Input::new()
        .with_prompt("VTA context ID")
        .default("webvh".to_string())
        .interact_text()?;
    let vta_mediator = vta_setup::resolve_vta_mediator(&vta_did).await;
    let mut options: Vec<String> = Vec::new();
    if let Some(ref did) = vta_mediator {
        options.push(format!("Use VTA's mediator ({did})"));
    }
    options.push("Enter a custom mediator DID".into());
    let idx = Select::new()
        .with_prompt("Mediator (the watcher's TSP/DIDComm route)")
        .items(&options)
        .default(0)
        .interact()?;
    let mediator_did = match vta_mediator.filter(|_| options[idx].starts_with("Use VTA")) {
        Some(did) => did,
        None => Input::new().with_prompt("Mediator DID").interact_text()?,
    };

    let setup_key = match setup_key_file {
        Some(path) => EphemeralSetupKey::load_from(&path)?,
        None => {
            let key = EphemeralSetupKey::generate()?;
            eprintln!();
            eprintln!("  Ephemeral setup DID: {}", key.did);
            eprintln!("  Run this on a workstation with PNM authenticated to the VTA:");
            eprintln!();
            eprintln!(
                "    {}",
                WebvhWatcherMessages.pnm_admin_command_hint(&context_id, &key.did)
            );
            eprintln!();
            if !Confirm::new()
                .with_prompt("Has the context been created?")
                .default(true)
                .interact()?
            {
                return Err("setup cancelled before the VTA round-trip".into());
            }
            key
        }
    };

    let recipe = SetupRecipe {
        deployment: DeploymentSection {
            service: ServiceKind::Watcher,
            vta_mode: VtaMode::Online,
        },
        output: OutputSection {
            config_path: PathBuf::from(output_path),
        },
        server: did_hosting_common::server::setup_recipe::ServerSection {
            host: Some(host),
            port: Some(port),
            data_dir: Some(PathBuf::from(data_dir)),
            ..Default::default()
        },
        identity: IdentitySection {
            mediator_did: Some(mediator_did),
            ..Default::default()
        },
        vta: VtaSection {
            did: Some(vta_did),
            context_id: Some(context_id),
            ..Default::default()
        },
        secrets: Default::default(),
        admin: Default::default(),
        reprovision: Default::default(),
        watcher: WatcherSection { source_dids },
        daemon: Default::default(),
    };
    apply_recipe(recipe, Some(setup_key), false).await
}

/// Provision the watcher's DID from its VTA context and write its config and
/// secrets.
pub async fn apply_recipe(
    mut recipe: SetupRecipe,
    setup_key: Option<EphemeralSetupKey>,
    force_reprovision: bool,
) -> Result<(), BoxError> {
    apply_env_overrides(&mut recipe);
    recipe.validate()?;
    print_recipe_banner("webvh-watcher", &recipe);

    let secrets_config = resolve_secrets_config(&recipe, "webvh-watcher-secrets", "webvh-watcher");
    let scan = inspect_existing(&secrets_config, &recipe.output.config_path).await;
    if scan.is_provisioned() && !force_reprovision && !recipe.reprovision.force {
        return Err(Box::new(refuse_overwrite(
            &recipe.output.config_path,
            &scan,
        )));
    }
    if recipe.output.config_path.exists() {
        back_up_config(&recipe.output.config_path)?;
    }
    if recipe.deployment.vta_mode == VtaMode::Online && setup_key.is_none() {
        return Err(
            "online vta_mode needs a setup key: run `webvh-watcher setup \
                    --setup-key-out <path>` first, then pass --setup-key-file <path>"
                .into(),
        );
    }
    let offline_seed = if recipe.deployment.vta_mode == VtaMode::OfflineComplete {
        did_hosting_common::server::secret_store::create_secret_store(
            &secrets_config,
            &recipe.output.config_path,
        )?
        .get_bootstrap_seed()
        .await?
    } else {
        None
    };

    let context_id = recipe
        .vta
        .context_id
        .clone()
        .unwrap_or_else(|| "webvh".to_string());
    // A mediator-reachable DID with no HTTP hosting endpoint: the watcher is
    // reached over TSP/DIDComm (and `POST /api/trust-tasks` by config).
    let mediator = recipe.identity.mediator_did.clone().unwrap_or_default();
    let ask = matches!(
        recipe.deployment.vta_mode,
        VtaMode::Online | VtaMode::OfflinePrepare
    )
    .then(|| {
        vta_setup::build_webvh_provision_ask(
            &context_id,
            &vta_setup::WebvhDidShape::DidcommOnly {
                mediator_did: &mediator,
            },
            Some(&format!("webvh-watcher setup — {context_id}")),
        )
    });
    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhWatcherMessages);
    let outcome = run_vta_for_recipe(&recipe, ask, messages, setup_key, offline_seed).await?;

    let (did, signing, ka, vta_did, vta_url, credential, log_entry) = match outcome {
        VtaSetupOutcome::Online(o) => (
            o.integration_did,
            o.integration_signing_key_mb,
            o.integration_ka_key_mb,
            Some(o.vta_did),
            o.vta_url,
            Some(o.vta_credential_b64),
            o.did_log_entry,
        ),
        VtaSetupOutcome::Offline(o) => (
            o.did,
            o.signing_key_multibase,
            o.key_agreement_multibase,
            Some(o.vta_did),
            o.vta_url,
            None,
            o.log_entry,
        ),
        VtaSetupOutcome::OfflinePreparedOnly(info) => {
            did_hosting_common::server::secret_store::create_secret_store(
                &secrets_config,
                &recipe.output.config_path,
            )?
            .set_bootstrap_seed(&info.seed)
            .await?;
            eprintln!();
            eprintln!(
                "  Wrote {}. Ferry it to the VTA admin, then re-run with",
                info.request_path.display()
            );
            eprintln!("  vta_mode = \"offline-complete\", [vta].bundle_path and expect_digest.");
            return Ok(());
        }
        VtaSetupOutcome::SelfManaged(_) => {
            return Err("self-managed mode is not supported for webvh-watcher".into());
        }
    };

    let has_mediator = recipe.identity.mediator_did.is_some();
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: has_mediator,
            tsp: has_mediator,
            rest_api: true,
            ..Default::default()
        },
        server_did: Some(did.clone()),
        mediator_did: recipe.identity.mediator_did.clone(),
        server: ServerConfig {
            host: recipe
                .server
                .host
                .clone()
                .unwrap_or_else(|| "0.0.0.0".into()),
            port: recipe
                .server
                .port
                .unwrap_or_else(|| SetupRecipe::default_port(ServiceKind::Watcher)),
            trusted_proxies: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
        },
        log: LogConfig {
            level: recipe
                .server
                .log_level
                .clone()
                .unwrap_or_else(|| "info".into()),
            format: recipe
                .server
                .log_format
                .map(to_log_format)
                .unwrap_or_default(),
        },
        store: StoreConfig {
            data_dir: recipe
                .server
                .data_dir
                .clone()
                .unwrap_or_else(|| SetupRecipe::default_data_dir(ServiceKind::Watcher)),
            ..StoreConfig::default()
        },
        fjall: Default::default(),
        secrets: secrets_config.clone(),
        vta: VtaConfig {
            url: vta_url,
            did: vta_did,
            context_id: None,
        },
        identity: Default::default(),
        sync: SyncConfig {
            source_dids: recipe.watcher.source_dids.clone(),
        },
        config_path: recipe.output.config_path.clone(),
    };

    if let Some(parent) = recipe.output.config_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&recipe.output.config_path, toml::to_string_pretty(&config)?)?;
    let secrets = ServerSecrets {
        signing_key: signing,
        key_agreement_key: ka,
        jwt_signing_key: vta_setup::generate_ed25519_multibase(),
        vta_credential: credential,
        retired: Vec::new(),
    };
    crate::secret_store::create_secret_store(&config)?
        .set(&secrets)
        .await
        .map_err(|e: AppError| e.to_string())?;
    if recipe.deployment.vta_mode == VtaMode::OfflineComplete {
        let _ = did_hosting_common::server::secret_store::create_secret_store(
            &secrets_config,
            &recipe.output.config_path,
        )?
        .clear_bootstrap_seed()
        .await;
    }
    if let Some(entry) = log_entry.as_deref() {
        let log_path = recipe
            .output
            .config_path
            .parent()
            .map(|p| p.join("watcher-did.jsonl"))
            .unwrap_or_else(|| PathBuf::from("watcher-did.jsonl"));
        vta_setup::write_log_entry_file(entry, &log_path)?;
        eprintln!(
            "  DID log entry written to {} — publish it on a hosting server.",
            log_path.display()
        );
    }

    eprintln!();
    eprintln!("  Watcher DID: {did}");
    eprintln!(
        "  Secrets stored in the {:?} backend.",
        active_backend(&recipe)
    );
    eprintln!(
        "  Next: webvh-watcher --config {}",
        recipe.output.config_path.display()
    );
    eprintln!();
    Ok(())
}

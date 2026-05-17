//! Non-interactive setup driven by a `SetupRecipe` TOML file.
//!
//! Pairs with `--from <recipe.toml>` on the `setup` subcommand.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use did_hosting_common::server::operator_messages::WebvhWitnessMessages;
use did_hosting_common::server::setup_recipe::{
    EXIT_RECIPE_INVALID, ServiceKind, SetupRecipe, VtaMode, VtaSetupOutcome, active_backend,
    apply_env_overrides, back_up_config, inspect_existing, load_recipe, print_recipe_banner,
    refuse_overwrite, require_service, resolve_admin_did, resolve_secrets_config,
    run_uninstall_unchecked, run_vta_for_recipe, to_log_format,
};
use did_hosting_common::server::store::KS_ACL;
use did_hosting_common::server::vta_setup;
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages, ProvisionAsk};

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LogConfig, LogFormat, ServerConfig, StoreConfig,
    VtaConfig,
};
use crate::error::AppError;
use crate::secret_store::{ServerSecrets, create_secret_store};
use crate::store::Store;

pub async fn run_from_recipe(
    recipe_path: &Path,
    setup_key_file: Option<PathBuf>,
    force_reprovision: bool,
) -> Result<(), AppError> {
    let recipe = load_recipe(recipe_path).map_err(|e| {
        eprintln!("  [setup-recipe] {e}");
        AppError::Config(format!("recipe load failed: {e}"))
    })?;
    require_service(&recipe, ServiceKind::Witness).map_err(|e| AppError::Config(format!("{e}")))?;
    apply_recipe(recipe, setup_key_file, force_reprovision).await
}

pub async fn apply_recipe(
    mut recipe: SetupRecipe,
    setup_key_file: Option<PathBuf>,
    force_reprovision: bool,
) -> Result<(), AppError> {
    apply_env_overrides(&mut recipe);
    print_recipe_banner("webvh-witness", &recipe);

    let secrets_config = resolve_secrets_config(&recipe, "webvh-witness-secrets", "webvh-witness");
    let scan = inspect_existing(&secrets_config, &recipe.output.config_path).await;
    if scan.is_provisioned() && !force_reprovision && !recipe.reprovision.force {
        return Err(refuse_overwrite(&recipe.output.config_path, &scan));
    }
    if recipe.output.config_path.exists() {
        back_up_config(&recipe.output.config_path)
            .map_err(|e| AppError::Config(format!("config backup failed: {e}")))?;
    }

    let setup_key = match (recipe.deployment.vta_mode, setup_key_file.as_deref()) {
        (VtaMode::Online, Some(p)) => Some(
            EphemeralSetupKey::load_from(p)
                .map_err(|e| AppError::Config(format!("load setup key: {e}")))?,
        ),
        (VtaMode::Online, None) => {
            return Err(AppError::Config(
                "online vta_mode requires --setup-key-file <path>. Run \
                 `webvh-witness setup --setup-key-out <path>` first."
                    .into(),
            ));
        }
        _ => None,
    };

    let offline_complete_seed = if recipe.deployment.vta_mode == VtaMode::OfflineComplete {
        let store = did_hosting_common::server::secret_store::create_secret_store(
            &secrets_config,
            &recipe.output.config_path,
        )?;
        store.get_bootstrap_seed().await?
    } else {
        None
    };

    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhWitnessMessages);

    let did_hosting_url = recipe
        .identity
        .did_hosting_url
        .clone()
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();
    let context_id = recipe
        .vta
        .context_id
        .clone()
        .unwrap_or_else(|| "webvh".to_string());

    // The witness DID is hosted by the did-hosting-server; it doesn't host
    // its own HTTP DID. With a mediator the DID document carries a
    // `DIDCommMessaging` service (witness accepts inbound DIDComm). The
    // mint template is `did-hosting-control` when a mediator exists (both
    // HTTP + DIDComm), `did-hosting-daemon` otherwise (HTTP only).
    let template_name = if recipe.identity.mediator_did.is_some() {
        "did-hosting-control"
    } else {
        "did-hosting-daemon"
    };
    let url_var = did_hosting_url.as_str();
    let mediator_var = recipe.identity.mediator_did.as_deref();
    let template_vars: Vec<(&str, &str)> = match mediator_var {
        Some(med) => vec![("URL", url_var), ("MEDIATOR_DID", med)],
        None => vec![("URL", url_var)],
    };

    let ask = match recipe.deployment.vta_mode {
        VtaMode::Online => Some(
            (match mediator_var {
                Some(med) => ProvisionAsk::webvh_control(&context_id, &did_hosting_url, med),
                None => ProvisionAsk::webvh_daemon(&context_id, &did_hosting_url),
            })
            .with_label(format!("webvh-witness setup — {context_id}")),
        ),
        _ => None,
    };

    let outcome = run_vta_for_recipe(
        &recipe,
        ask,
        messages,
        setup_key,
        template_name,
        &template_vars,
        Some("webvh-witness"),
        offline_complete_seed,
    )
    .await?;

    let (
        witness_did,
        signing_priv,
        ka_priv,
        vta_did_persisted,
        vta_url,
        vta_credential_b64,
        log_entry,
    ) = match outcome {
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
            persist_offline_prepare(&recipe, &info, &secrets_config).await?;
            return Ok(());
        }
        VtaSetupOutcome::SelfManaged(_) => {
            return Err(AppError::Config(
                "self-managed mode is not supported for webvh-witness".into(),
            ));
        }
    };

    let jwt_signing_key = vta_setup::generate_ed25519_multibase();

    let host = recipe
        .server
        .host
        .clone()
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let port = recipe
        .server
        .port
        .unwrap_or_else(|| SetupRecipe::default_port(ServiceKind::Witness));
    let log_level = recipe
        .server
        .log_level
        .clone()
        .unwrap_or_else(|| "info".to_string());
    let log_format = recipe
        .server
        .log_format
        .map(to_log_format)
        .map(|f| match f {
            did_hosting_common::server::config::LogFormat::Text => LogFormat::Text,
            did_hosting_common::server::config::LogFormat::Json => LogFormat::Json,
        })
        .unwrap_or(LogFormat::Text);
    let data_dir = recipe
        .server
        .data_dir
        .clone()
        .unwrap_or_else(|| SetupRecipe::default_data_dir(ServiceKind::Witness));

    let config = AppConfig {
        features: FeaturesConfig {
            didcomm: recipe.identity.mediator_did.is_some(),
            rest_api: true,
            ..Default::default()
        },
        server_did: Some(witness_did.clone()),
        mediator_did: recipe.identity.mediator_did.clone(),
        server: ServerConfig {
            host,
            port,
            trusted_proxies: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
        },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        store: StoreConfig {
            data_dir,
            ..StoreConfig::default()
        },
        auth: AuthConfig::default(),
        secrets: secrets_config.clone(),
        vta: VtaConfig {
            url: vta_url,
            did: vta_did_persisted,
            context_id: None,
        },
        config_path: recipe.output.config_path.clone(),
    };

    if let Some(parent) = recipe.output.config_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| AppError::Config(format!("toml encode: {e}")))?;
    std::fs::write(&recipe.output.config_path, &toml_str)?;
    eprintln!(
        "  [setup-recipe] config written to {}",
        recipe.output.config_path.display()
    );

    let server_secrets = ServerSecrets {
        signing_key: signing_priv,
        key_agreement_key: ka_priv,
        jwt_signing_key,
        vta_credential: vta_credential_b64,
    };
    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!(
        "  [setup-recipe] secrets stored in {:?} backend",
        active_backend(&recipe)
    );

    if recipe.deployment.vta_mode == VtaMode::OfflineComplete {
        let post = did_hosting_common::server::secret_store::create_secret_store(
            &secrets_config,
            &recipe.output.config_path,
        )?;
        if let Err(e) = post.clear_bootstrap_seed().await {
            eprintln!("  Warning: failed to clear bootstrap seed: {e}");
        }
    }

    if let Some(log_entry) = log_entry.as_deref() {
        let log_path = recipe
            .output
            .config_path
            .parent()
            .map(|p| p.join("witness-did.jsonl"))
            .unwrap_or_else(|| PathBuf::from("witness-did.jsonl"));
        if let Err(e) = vta_setup::write_log_entry_file(log_entry, &log_path) {
            eprintln!(
                "  [setup-recipe] WARNING failed to write DID log entry to {}: {e}",
                log_path.display()
            );
        } else {
            eprintln!(
                "  [setup-recipe] DID log entry written to {}",
                log_path.display()
            );
        }
    }

    if let Some(admin_did) = resolve_admin_did(&recipe) {
        let store = Store::open(&config.store).await?;
        let acl_ks = store.keyspace(KS_ACL)?;
        let entry = AclEntry {
            did: admin_did.clone(),
            role: Role::Admin,
            label: Some("Setup recipe admin".into()),
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,

            domains: did_hosting_common::server::domain::DomainScope::All,
        };
        store_acl_entry(&acl_ks, &entry).await?;
        store.persist().await?;
        eprintln!("  [setup-recipe] admin ACL entry added for {admin_did}");
    }

    eprintln!();
    eprintln!("  [setup-recipe] setup complete");
    eprintln!();
    eprintln!("  Witness DID:       {witness_did}");
    eprintln!(
        "  Next: webvh-witness --config {}",
        recipe.output.config_path.display()
    );
    eprintln!();

    Ok(())
}

async fn persist_offline_prepare(
    recipe: &SetupRecipe,
    info: &did_hosting_common::server::setup_recipe::OfflinePreparedInfo,
    secrets_config: &did_hosting_common::server::config::SecretsConfig,
) -> Result<(), AppError> {
    let store = did_hosting_common::server::secret_store::create_secret_store(
        secrets_config,
        &recipe.output.config_path,
    )?;
    store.set_bootstrap_seed(&info.seed).await?;
    print_offline_prepare_recap("webvh-witness", recipe, info);
    Ok(())
}

fn print_offline_prepare_recap(
    binary: &str,
    recipe: &SetupRecipe,
    info: &did_hosting_common::server::setup_recipe::OfflinePreparedInfo,
) {
    eprintln!();
    eprintln!("  [setup-recipe:offline-prepare] phase 1 complete");
    eprintln!(
        "  [setup-recipe:offline-prepare] request_path = {}",
        info.request_path.display()
    );
    eprintln!(
        "  [setup-recipe:offline-prepare] client_did   = {}",
        info.client_did
    );
    eprintln!(
        "  [setup-recipe:offline-prepare] nonce        = {}",
        info.nonce
    );
    eprintln!("  [setup-recipe:offline-prepare] seed stored in configured secret backend");
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!(
        "    1. Ferry {} to your VTA admin.",
        info.request_path.display()
    );
    eprintln!("    2. Ask them to seal the response and communicate the SHA-256 digest OOB.");
    eprintln!(
        "    3. Edit your recipe ({}): set vta_mode = \"offline-complete\",",
        recipe.output.config_path.display()
    );
    eprintln!("       [vta].bundle_path, [vta].expect_digest.");
    eprintln!("    4. Re-run phase 2: {binary} setup --from <recipe>");
    eprintln!();
}

pub async fn run_uninstall(config_path: &Path, yes: bool) -> Result<(), AppError> {
    let config = AppConfig::load(Some(config_path.to_path_buf())).map_err(|e| {
        AppError::Config(format!(
            "failed to load {} for uninstall: {e}",
            config_path.display()
        ))
    })?;

    if !yes {
        let confirmed =
            did_hosting_common::server::setup_recipe::prompt_uninstall_confirmation(config_path)?;
        if !confirmed {
            eprintln!("  Aborted (DELETE not entered).");
            return Ok(());
        }
    }

    let companion = config_path
        .parent()
        .map(|p| p.join("witness-did.jsonl"))
        .unwrap_or_else(|| PathBuf::from("witness-did.jsonl"));
    let companions: &[&Path] = &[companion.as_path()];
    let report = run_uninstall_unchecked(&config.secrets, config_path, companions).await?;

    eprintln!();
    eprintln!("  Uninstall complete:");
    eprintln!("    secrets cleared:        {}", report.secrets_cleared);
    eprintln!("    bootstrap seed cleared: {}", report.seed_cleared);
    for f in &report.files_removed {
        eprintln!("    removed file:           {}", f.display());
    }
    eprintln!();
    Ok(())
}

pub fn map_exit_code(err: &AppError) -> i32 {
    let msg = err.to_string();
    if msg.contains("refusing to overwrite") {
        did_hosting_common::server::setup_recipe::EXIT_REPROVISION_REFUSED
    } else if msg.contains("VTA provision") || msg.contains("post-auth") {
        did_hosting_common::server::setup_recipe::EXIT_VTA_POST_AUTH
    } else if msg.contains("recipe") && (msg.contains("invalid") || msg.contains("missing")) {
        EXIT_RECIPE_INVALID
    } else {
        1
    }
}

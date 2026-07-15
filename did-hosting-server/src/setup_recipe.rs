//! Non-interactive setup driven by a `SetupRecipe` TOML file.
//!
//! Sibling to [`crate::setup`]'s interactive wizard. The recipe captures
//! every prompt the wizard would ask; this module applies it without a
//! TTY. Pairs with `--from <recipe.toml>` on the `setup` subcommand.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use did_hosting_common::server::operator_messages::WebvhServerMessages;
use did_hosting_common::server::setup_recipe::{
    EXIT_RECIPE_INVALID, ServiceKind, SetupRecipe, VtaMode, VtaSetupOutcome, active_backend,
    apply_env_overrides, back_up_config, derive_did_path, inspect_existing, load_recipe,
    print_recipe_banner, refuse_overwrite, require_service, resolve_admin_did,
    resolve_secrets_config, run_uninstall_unchecked, run_vta_for_recipe, split_origin_and_did_path,
    to_log_format,
};
use did_hosting_common::server::store::{KS_ACL, KS_DIDS};
use did_hosting_common::server::vta_setup;
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages};

use crate::acl::{AclEntry, Role, store_acl_entry};
use crate::auth::session::now_epoch;
use crate::config::{
    AppConfig, AuthConfig, FeaturesConfig, LimitsConfig, LogConfig, LogFormat, ServerConfig,
    StatsConfig, StoreConfig, VtaConfig,
};
use crate::error::AppError;
use crate::secret_store::{ServerSecrets, create_secret_store};
use crate::setup::update_server_did_in_config;
use crate::store::Store;

/// Entry point: load + validate + apply.
pub async fn run_from_recipe(
    recipe_path: &Path,
    setup_key_file: Option<PathBuf>,
    force_reprovision: bool,
) -> Result<(), AppError> {
    let recipe = load_recipe(recipe_path).map_err(|e| {
        eprintln!("  [setup-recipe] {e}");
        AppError::Config(format!("recipe load failed: {e}"))
    })?;
    require_service(&recipe, ServiceKind::Server).map_err(|e| AppError::Config(format!("{e}")))?;
    apply_recipe(recipe, setup_key_file, force_reprovision).await
}

/// Apply an already-loaded recipe. Split out so the future
/// `--non-interactive` shortcut (which builds a recipe in-memory) can
/// reuse this path.
pub async fn apply_recipe(
    mut recipe: SetupRecipe,
    setup_key_file: Option<PathBuf>,
    force_reprovision: bool,
) -> Result<(), AppError> {
    apply_env_overrides(&mut recipe);
    print_recipe_banner("did-hosting-server", &recipe);

    // Reprovision scan happens BEFORE any VTA round-trip so we don't
    // burn an enrolled setup DID on an install that's going to refuse.
    let secrets_config = resolve_secrets_config(&recipe, "did-hosting-server-secrets", "webvh");
    let scan = inspect_existing(&secrets_config, &recipe.output.config_path).await;
    if scan.is_provisioned() && !force_reprovision && !recipe.reprovision.force {
        let err = refuse_overwrite(&recipe.output.config_path, &scan);
        return Err(err);
    }

    // Back up an existing config.toml before we overwrite it. The
    // backend secrets get rotated below — the backup gives the operator
    // a recoverable view of the previous wiring.
    if recipe.output.config_path.exists() {
        back_up_config(&recipe.output.config_path)
            .map_err(|e| AppError::Config(format!("config backup failed: {e}")))?;
    }

    // Online needs --setup-key-file; phase 1 is a separate subcommand.
    let setup_key = match (recipe.deployment.vta_mode, setup_key_file.as_deref()) {
        (VtaMode::Online, Some(path)) => Some(
            EphemeralSetupKey::load_from(path)
                .map_err(|e| AppError::Config(format!("load setup key: {e}")))?,
        ),
        (VtaMode::Online, None) => {
            return Err(AppError::Config(
                "online vta_mode requires --setup-key-file <path>. Run \
                 `did-hosting-server setup --setup-key-out <path>` first to mint and \
                 enrol an ephemeral did:key."
                    .into(),
            ));
        }
        _ => None,
    };

    // Resolve the offline-complete bootstrap seed up-front so we can
    // fail fast if it's missing.
    let offline_complete_seed = if recipe.deployment.vta_mode == VtaMode::OfflineComplete {
        let store = did_hosting_common::server::secret_store::create_secret_store(
            &secrets_config,
            &recipe.output.config_path,
        )?;
        store.get_bootstrap_seed().await?
    } else {
        None
    };

    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhServerMessages);

    // One ask packages the server's own DID for both online and
    // offline-prepare. The server hosts its own DID documents via HTTP and
    // doesn't mint DIDComm into its DID document (sync uses a separate
    // `mediator_did` at runtime), so it's always HTTP-only — the builder
    // selects `did-hosting-daemon`. `public_url` carries the DID path in its
    // path component, so split it back out and let the builder fold it in.
    let public_url_owned = recipe
        .identity
        .public_url
        .clone()
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();
    let context_id = recipe
        .vta
        .context_id
        .clone()
        .unwrap_or_else(|| "webvh".to_string());
    let (origin, did_path) = split_origin_and_did_path(&public_url_owned);
    // The server's own DID advertises its messaging transport(s) when the
    // recipe configures a mediator — matching the control / daemon recipes —
    // and stays HTTP-only otherwise.
    let transport = recipe.identity.transport_selection()?;
    let ask = matches!(
        recipe.deployment.vta_mode,
        VtaMode::Online | VtaMode::OfflinePrepare
    )
    .then(|| {
        let shape = vta_setup::WebvhDidShape::Hosted {
            origin: &origin,
            did_path: &did_path,
            mediator_did: recipe.identity.mediator_did.as_deref(),
            transport,
            remote: None,
        };
        vta_setup::build_webvh_provision_ask(
            &context_id,
            &shape,
            Some(&format!("did-hosting-server setup — {context_id}")),
        )
    });

    let outcome =
        run_vta_for_recipe(&recipe, ask, messages, setup_key, offline_complete_seed).await?;

    // Three terminal shapes: online, offline-complete, or offline-prepare.
    // Server has no self-managed mode (rejected by recipe validation).
    let (
        server_did,
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
            // Recipe validation rejects this for non-daemon services,
            // but be loud if a future code change accidentally allows it.
            return Err(AppError::Config(
                "self-managed mode is not supported for did-hosting-server".into(),
            ));
        }
    };

    let jwt_signing_key = did_hosting_common::server::vta_setup::generate_ed25519_multibase();

    let host = recipe
        .server
        .host
        .clone()
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let port = recipe
        .server
        .port
        .unwrap_or_else(|| SetupRecipe::default_port(ServiceKind::Server));
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
        .unwrap_or_else(|| SetupRecipe::default_data_dir(ServiceKind::Server));

    let (didcomm, tsp) = recipe.identity.transport_flags()?;
    let config = AppConfig {
        features: FeaturesConfig {
            didcomm,
            tsp,
            rest_api: false,
            ..Default::default()
        },
        server_did: Some(server_did.clone()),
        mediator_did: recipe.identity.mediator_did.clone(),
        public_url: Some(public_url_owned.clone()),
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
        hosting: crate::config::HostingConfig::default(),
        secrets: secrets_config.clone(),
        limits: LimitsConfig::default(),
        watchers: Vec::new(),
        control_url: recipe.identity.control_url.clone(),
        control_did: recipe.identity.control_did.clone(),
        vta: VtaConfig {
            url: vta_url,
            did: vta_did_persisted,
            context_id: None,
        },
        stats: StatsConfig::default(),
        identity: Default::default(),
        config_path: recipe.output.config_path.clone(),
    };

    if let Some(parent) = recipe.output.config_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &recipe.output.config_path,
        toml::to_string_pretty(&config)
            .map_err(|e| AppError::Config(format!("toml encode: {e}")))?,
    )?;
    eprintln!(
        "  [setup-recipe] config written to {}",
        recipe.output.config_path.display()
    );

    let server_secrets = ServerSecrets {
        signing_key: signing_priv,
        key_agreement_key: ka_priv,
        jwt_signing_key,
        vta_credential: vta_credential_b64,
        retired: Vec::new(),
    };
    let secret_store = create_secret_store(&config)?;
    secret_store.set(&server_secrets).await?;
    eprintln!(
        "  [setup-recipe] secrets stored in {:?} backend",
        active_backend(&recipe)
    );

    // Drop the now-spent offline seed (if any) — phase 2 is done.
    if recipe.deployment.vta_mode == VtaMode::OfflineComplete {
        let post = did_hosting_common::server::secret_store::create_secret_store(
            &secrets_config,
            &recipe.output.config_path,
        )?;
        if let Err(e) = post.clear_bootstrap_seed().await {
            eprintln!("  Warning: failed to clear bootstrap seed: {e}");
        }
    }

    // Import the server's own DID into the local store.
    if let Some(log_entry) = log_entry.as_deref() {
        let did_path = derive_did_path(&public_url_owned);
        let store = Store::open(&config.store).await?;
        let dids_ks = store.keyspace(KS_DIDS)?;
        match crate::bootstrap::import_did_at_path(&store, &dids_ks, &did_path, log_entry, None)
            .await
        {
            Ok(result) => {
                eprintln!(
                    "  [setup-recipe] server DID imported at '{did_path}' (scid={})",
                    result.scid
                );
                update_server_did_in_config(&recipe.output.config_path, &result.did_id)
                    .map_err(|e| AppError::Config(format!("update server_did: {e}")))?;
            }
            Err(e) => {
                eprintln!(
                    "  [setup-recipe] WARNING failed to import server DID: {e}\n             retry: did-hosting-server bootstrap-did --path {did_path}"
                );
            }
        }
    }

    // Admin ACL seeding (if requested by the recipe).
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
    eprintln!("  Server DID:        {server_did}");
    eprintln!(
        "  Next: did-hosting-server --config {}",
        recipe.output.config_path.display()
    );
    eprintln!();

    Ok(())
}

/// Phase 1 of the offline flow: the bootstrap request was written by
/// `run_vta_for_recipe`; we persist the ephemeral seed in the configured
/// secret backend so phase 2 can open the sealed response, then print
/// operator-facing next-steps.
///
/// Phase 2 is driven by re-running the wizard with the SAME recipe file
/// edited to `vta_mode = "offline-complete"` and `[vta].bundle_path` /
/// `[vta].expect_digest` filled in. The seed comes back out of the same
/// secret backend automatically.
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
    print_offline_prepare_recap("did-hosting-server", recipe, info);
    Ok(())
}

/// Stable, scriptable next-steps recap for offline-prepare. CI scripts
/// can grep for `[setup-recipe:offline-prepare]` to confirm phase 1
/// succeeded and pick up the printed values.
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
    eprintln!("    2. Ask them to seal the response:");
    eprintln!(
        "         vta bootstrap provision-integration --request <request-file> \\\n           --out <bundle-file>"
    );
    eprintln!("       and to communicate the SHA-256 digest out-of-band.");
    eprintln!(
        "    3. Edit your recipe ({}):",
        recipe.output.config_path.display()
    );
    eprintln!("         - set [deployment].vta_mode = \"offline-complete\"");
    eprintln!("         - set [vta].bundle_path    = \"<bundle-path>\"");
    eprintln!("         - set [vta].expect_digest  = \"<hex-digest>\"");
    eprintln!("    4. Re-run phase 2 (no TTY required):");
    eprintln!("         {binary} setup --from <recipe>");
    eprintln!();
}

/// Uninstall: list did-hosting-server-managed entries, prompt for typed DELETE,
/// remove them. `yes` skips the prompt (CI). Returns true on completion.
pub async fn run_uninstall(config_path: &Path, yes: bool) -> Result<(), AppError> {
    // Load just enough config to find the secret backend.
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

    let report = run_uninstall_unchecked(&config.secrets, config_path, &[]).await?;

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

/// Map an [`AppError`] from any recipe / uninstall flow to the documented
/// exit code. Generic errors map to 1.
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

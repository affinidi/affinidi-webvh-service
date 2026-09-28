//! Non-interactive setup driven by a `SetupRecipe` TOML file.
//!
//! Sibling to [`crate::setup`]'s interactive wizard. The daemon is the
//! only binary that supports `vta_mode = "self-managed"`; everything else
//! mirrors the per-binary `setup_recipe` pattern.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use did_hosting_common::server::config::{
    AuthConfig, IdentityConfig, IdentityMode, LogConfig, LogFormat as CommonLogFormat,
    ServerConfig, StoreConfig, VtaConfig,
};
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::operator_messages::WebvhDaemonMessages;
use did_hosting_common::server::secret_store::{ServerSecrets, create_secret_store};
use did_hosting_common::server::setup_recipe::{
    EXIT_RECIPE_INVALID, ServiceKind, SetupRecipe, VtaMode, VtaSetupOutcome, active_backend,
    apply_env_overrides, back_up_config, derive_did_path, inspect_existing, load_recipe,
    print_recipe_banner, refuse_overwrite, require_service, resolve_admin_did,
    resolve_secrets_config, run_uninstall_unchecked, run_vta_for_recipe, split_origin_and_did_path,
    to_log_format,
};
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS};
use did_hosting_common::server::vta_setup;
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages};

use crate::config::{DaemonConfig, EnableConfig};

pub async fn run_from_recipe(
    recipe_path: &Path,
    setup_key_file: Option<PathBuf>,
    force_reprovision: bool,
) -> Result<(), AppError> {
    let recipe = load_recipe(recipe_path).map_err(|e| {
        eprintln!("  [setup-recipe] {e}");
        AppError::Config(format!("recipe load failed: {e}"))
    })?;
    require_service(&recipe, ServiceKind::Daemon).map_err(|e| AppError::Config(format!("{e}")))?;
    apply_recipe(recipe, setup_key_file, force_reprovision).await
}

pub async fn apply_recipe(
    mut recipe: SetupRecipe,
    setup_key_file: Option<PathBuf>,
    force_reprovision: bool,
) -> Result<(), AppError> {
    apply_env_overrides(&mut recipe);
    print_recipe_banner("did-hosting-daemon", &recipe);

    let secrets_config = resolve_secrets_config(&recipe, "did-hosting-daemon-secrets", "webvh");
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
                 `did-hosting-daemon setup --setup-key-out <path>` first."
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

    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhDaemonMessages);

    let public_url = recipe
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

    // The daemon recipe is serverless: `public_url` carries the DID path in
    // its path component, so split it back out and let the shared builder
    // fold it into the minted DID's URL. With a mediator the DID document
    // gets both WebVHHosting + DIDCommMessaging (`did-hosting-control`); else
    // HTTP-only (`did-hosting-daemon`).
    let (origin, did_path) = split_origin_and_did_path(&public_url);
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
            Some(&format!("did-hosting-daemon setup — {context_id}")),
        )
    });

    let outcome =
        run_vta_for_recipe(&recipe, ask, messages, setup_key, offline_complete_seed).await?;

    let (
        server_did_opt,
        signing_priv,
        ka_priv,
        vta_did_persisted,
        vta_url,
        vta_credential_b64,
        log_entry,
        identity_mode,
    ) = match outcome {
        VtaSetupOutcome::Online(o) => (
            Some(o.integration_did),
            o.integration_signing_key_mb,
            o.integration_ka_key_mb,
            Some(o.vta_did),
            o.vta_url,
            Some(o.vta_credential_b64),
            o.did_log_entry,
            IdentityMode::Vta,
        ),
        VtaSetupOutcome::Offline(o) => (
            Some(o.did),
            o.signing_key_multibase,
            o.key_agreement_multibase,
            Some(o.vta_did),
            o.vta_url,
            None,
            o.log_entry,
            IdentityMode::Vta,
        ),
        VtaSetupOutcome::SelfManaged(keys) => (
            // Self-managed populates server_did via the DID import step
            // below — it isn't known until the document is built. Leave
            // None here; finalize will fill it in.
            None,
            keys.signing_priv_mb,
            keys.ka_priv_mb,
            None,
            None,
            None,
            Some(keys.did_log_jsonl),
            IdentityMode::SelfManaged,
        ),
        VtaSetupOutcome::OfflinePreparedOnly(info) => {
            persist_offline_prepare(&recipe, &info, &secrets_config).await?;
            return Ok(());
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
        .unwrap_or_else(|| SetupRecipe::default_port(ServiceKind::Daemon));
    let log_level = recipe
        .server
        .log_level
        .clone()
        .unwrap_or_else(|| "info".to_string());
    let log_format = recipe
        .server
        .log_format
        .map(to_log_format)
        .unwrap_or(CommonLogFormat::Text);
    let data_dir_root = recipe
        .server
        .data_dir
        .clone()
        .unwrap_or_else(|| SetupRecipe::default_data_dir(ServiceKind::Daemon));
    let store_path = data_dir_root.join("store");
    let witness_store_path = data_dir_root.join("witness");

    let enable = EnableConfig {
        control: recipe.daemon.enable_control.unwrap_or(true),
        server: recipe.daemon.enable_server.unwrap_or(true),
        witness: recipe.daemon.enable_witness.unwrap_or(true),
        watcher: recipe.daemon.enable_watcher.unwrap_or(false),
    };

    // Transport selection from the recipe (`identity.transport`, default
    // `both`); both ride the mediator socket, so a mediator-less identity
    // is HTTP-only. Applies to both VTA-provisioned and self-managed modes.
    let (didcomm, tsp) = recipe.identity.transport_flags()?;
    let features = did_hosting_common::server::config::FeaturesConfig {
        rest_api: enable.control || enable.server,
        didcomm,
        tsp,
        ..Default::default()
    };

    let config = DaemonConfig {
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
        auth: AuthConfig::default(),
        secrets: secrets_config.clone(),
        server_did: server_did_opt.clone(),
        mediator_did: recipe.identity.mediator_did.clone(),
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
        fjall: Default::default(),
        limits: did_hosting_server::config::LimitsConfig::default(),
        vta: VtaConfig {
            url: vta_url,
            did: vta_did_persisted,
            context_id: None,
        },
        watcher_sync: webvh_watcher::config::SyncConfig::default(),
        registry: did_hosting_control::config::RegistryConfig::default(),
        features,
        identity: IdentityConfig {
            mode: identity_mode,
            ..Default::default()
        },
        enable,
        config_path: recipe.output.config_path.clone(),

        hosting: did_hosting_common::server::config::HostingConfig::default(),
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
        retired: Vec::new(),
    };
    let secret_store = create_secret_store(&config.secrets, &recipe.output.config_path)?;
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

    // Import the daemon's own DID into the local server store, exactly
    // like the interactive wizard does. For self-managed mode the
    // jsonl came from local key gen; for VTA modes from the round-trip.
    if let Some(log_entry) = log_entry.as_deref() {
        let did_path = derive_did_path(&public_url);
        let store = Store::open(&config.store).await?;
        let dids_ks = store.keyspace(KS_DIDS)?;
        use did_hosting_server::bootstrap::{
            OwnDidImport, import_own_did, replace_own_did, stale_own_did_message,
        };
        // A DID that cannot be served is a failed setup, not a warning. This
        // used to print one and carry on, so a daemon moved to a new host
        // reported success and health while serving its old identity
        // (Keyring VTI-17).
        let did_id = match import_own_did(&store, &dids_ks, &did_path, log_entry).await? {
            OwnDidImport::Imported(result) => {
                eprintln!(
                    "  [setup-recipe] daemon DID imported at '{did_path}' (scid={})",
                    result.scid
                );
                result.did_id
            }
            OwnDidImport::AlreadyPresent { did_id } => {
                eprintln!("  [setup-recipe] daemon DID already present at '{did_path}'");
                did_id
            }
            // `--force-reprovision` is the operator explicitly opting into
            // rotation, so a stale DID at this path is exactly what it's
            // for: re-mint and replace rather than refuse. Without that
            // flag this is unexpected — refuse loudly instead (below).
            OwnDidImport::HeldByAnother { existing, minted } if force_reprovision => {
                eprintln!(
                    "  [setup-recipe] replacing stale daemon DID at '{did_path}' \
                     ({} -> {minted}) — --force-reprovision was set",
                    existing.as_deref().unwrap_or("an unidentified DID")
                );
                let result = replace_own_did(&store, &dids_ks, &did_path, log_entry).await?;
                eprintln!(
                    "  [setup-recipe] daemon DID re-minted at '{did_path}' (scid={})",
                    result.scid
                );
                result.did_id
            }
            OwnDidImport::HeldByAnother { existing, minted } => {
                return Err(AppError::Config(stale_own_did_message(
                    &did_path,
                    existing.as_deref(),
                    &minted,
                )));
            }
        };
        did_hosting_server::setup::update_server_did_in_config(&recipe.output.config_path, &did_id)
            .map_err(|e| AppError::Config(format!("update server_did: {e}")))?;
    }

    if let Some(admin_did) = resolve_admin_did(&recipe) {
        let store = Store::open(&config.store).await?;
        let acl_ks = store.keyspace(KS_ACL)?;
        let entry = did_hosting_common::server::acl::AclEntry {
            did: admin_did.clone(),
            role: did_hosting_common::server::acl::Role::Admin,
            label: Some("Setup recipe admin".into()),
            created_at: did_hosting_common::server::auth::session::now_epoch(),
            max_total_size: None,
            max_did_count: None,

            domains: did_hosting_common::server::domain::DomainScope::All,
        };
        did_hosting_common::server::acl::store_acl_entry(&acl_ks, &entry).await?;
        store.persist().await?;
        eprintln!("  [setup-recipe] admin ACL entry added for {admin_did}");
    }

    // Trust the provisioning VTA to publish (idempotent, VTA-provisioned
    // deployments only). Mirrors the interactive wizard's
    // `finalize_daemon_setup`; see `acl::seed_provisioning_vta_acl`.
    if let Some(vta_did) = config.vta.did.as_deref() {
        let store = Store::open(&config.store).await?;
        let acl_ks = store.keyspace(KS_ACL)?;
        if did_hosting_common::server::acl::seed_provisioning_vta_acl(&acl_ks, vta_did).await? {
            store.persist().await?;
            eprintln!("  [setup-recipe] provisioning-VTA ACL entry added for {vta_did}");
        }
    }

    eprintln!();
    eprintln!("  [setup-recipe] setup complete");
    eprintln!();
    eprintln!(
        "  Next: did-hosting-daemon --config {}",
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
    print_offline_prepare_recap("did-hosting-daemon", recipe, info);
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
    let config = DaemonConfig::load(Some(config_path.to_path_buf())).map_err(|e| {
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
        .map(|p| p.join("control-did.jsonl"))
        .unwrap_or_else(|| PathBuf::from("control-did.jsonl"));
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

// ---------------------------------------------------------------------------
// Keyring VTI-17: --force-reprovision onto a new public_url
// ---------------------------------------------------------------------------

#[cfg(test)]
mod force_reprovision_tests {
    use super::*;
    use did_hosting_common::did_ops::{DidRecord, did_key};
    use did_hosting_common::server::setup_recipe::{
        AdminSection, DaemonSection, DeploymentSection, IdentitySection, OutputSection,
        ReprovisionSection, SecretsBackend, SecretsSection, ServerSection, VtaSection,
        WatcherSection,
    };

    /// A minimal, valid self-managed daemon recipe — the only `vta_mode`
    /// that never touches a network, so the test is hermetic.
    fn recipe(config_path: PathBuf, data_dir: PathBuf, public_url: &str) -> SetupRecipe {
        SetupRecipe {
            deployment: DeploymentSection {
                service: ServiceKind::Daemon,
                vta_mode: VtaMode::SelfManaged,
            },
            output: OutputSection { config_path },
            server: ServerSection {
                data_dir: Some(data_dir),
                ..Default::default()
            },
            identity: IdentitySection {
                public_url: Some(public_url.to_string()),
                ..Default::default()
            },
            vta: VtaSection::default(),
            // Plaintext + confirm: CI's Linux runners have no Secret Service,
            // so the default keyring backend cannot open there.
            secrets: SecretsSection {
                backend: Some(SecretsBackend::Plaintext),
                confirm_plaintext: true,
                ..Default::default()
            },
            admin: AdminSection::default(),
            reprovision: ReprovisionSection::default(),
            watcher: WatcherSection::default(),
            daemon: DaemonSection::default(),
        }
    }

    /// `--force-reprovision` onto a new `public_url` re-mints the daemon
    /// DID and replaces the stale one at `.well-known`, rather than
    /// leaving both the failed setup AND the old identity behind (Keyring
    /// VTI-17). The store ends up with exactly the new DID, servable, and
    /// the local-resolution health check agrees.
    #[tokio::test]
    async fn reprovision_to_a_new_url_replaces_the_stale_did() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let data_dir = dir.path().join("data");

        apply_recipe(
            recipe(
                config_path.clone(),
                data_dir.clone(),
                "https://old-host.example",
            ),
            None,
            false,
        )
        .await
        .expect("first setup succeeds");
        let old_did = DaemonConfig::load(Some(config_path.clone()))
            .unwrap()
            .server_did
            .expect("server_did set after first setup");

        apply_recipe(
            recipe(
                config_path.clone(),
                data_dir.clone(),
                "https://new-host.example",
            ),
            None,
            true,
        )
        .await
        .expect("force-reprovision to a new host succeeds");
        let new_config = DaemonConfig::load(Some(config_path.clone())).unwrap();
        let new_did = new_config
            .server_did
            .clone()
            .expect("server_did set after reprovision");
        assert_ne!(old_did, new_did, "a new host re-mints the DID");

        let store = Store::open(&new_config.store).await.unwrap();
        let dids_ks = store.keyspace(KS_DIDS).unwrap();
        let record: DidRecord = dids_ks
            .get(did_key(".well-known"))
            .await
            .unwrap()
            .expect("own DID present at .well-known");
        assert_eq!(
            record.did_id.as_deref(),
            Some(new_did.as_str()),
            "the new DID replaced the stale one rather than being refused"
        );
        // Keyring VTI-18 + the TrustTaskHTTPS sibling: a self-managed daemon
        // with no mediator still advertises both, so a VTA can register it
        // and route Trust Tasks to it (`services_overview` shape).
        assert_eq!(
            record.services,
            Some(vec![
                "WebVHHosting".to_string(),
                "TrustTaskHTTPS".to_string()
            ]),
            "a no-mediator self-managed daemon must advertise hosting + trust tasks"
        );
        assert!(
            did_hosting_common::server::health::own_did_served_locally(
                &dids_ks,
                Some(new_did.as_str())
            )
            .await,
            "health must see the new DID as served"
        );
    }

    /// The same `public_url` reprovisioned still succeeds (a credential
    /// rotation with no host change) — `.well-known` ends up matching
    /// whatever `server_did` the reprovision recorded, and health agrees.
    #[tokio::test]
    async fn reprovision_to_the_same_url_still_succeeds_and_stays_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let data_dir = dir.path().join("data");

        apply_recipe(
            recipe(
                config_path.clone(),
                data_dir.clone(),
                "https://host.example",
            ),
            None,
            false,
        )
        .await
        .expect("first setup succeeds");

        apply_recipe(
            recipe(
                config_path.clone(),
                data_dir.clone(),
                "https://host.example",
            ),
            None,
            true,
        )
        .await
        .expect("force-reprovision to the same host succeeds");

        let config = DaemonConfig::load(Some(config_path.clone())).unwrap();
        let did = config.server_did.clone().expect("server_did set");
        let store = Store::open(&config.store).await.unwrap();
        let dids_ks = store.keyspace(KS_DIDS).unwrap();
        assert!(
            did_hosting_common::server::health::own_did_served_locally(
                &dids_ks,
                Some(did.as_str())
            )
            .await
        );
    }
}

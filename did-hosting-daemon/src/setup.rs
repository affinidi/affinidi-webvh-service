//! Interactive setup wizard for generating a daemon config.toml.
//!
//! The daemon embeds control + server + witness + (optional) watcher in
//! a single process sharing one DID. Setup is therefore essentially
//! control's online wizard adapted for `DaemonConfig`, plus the
//! server-style local DID import since the daemon also hosts its own
//! root DID.

use std::path::PathBuf;

use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use did_hosting_common::did::{DidDocumentOptions, build_did_document, create_log_entry};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, IdentityConfig, IdentityMode, LogConfig, LogFormat, ServerConfig,
    StoreConfig, VtaConfig,
};
use did_hosting_common::server::operator_messages::WebvhDaemonMessages;
use did_hosting_common::server::secret_store::{ServerSecrets, create_secret_store};
use did_hosting_common::server::setup_prompts;
use did_hosting_common::server::store::Store;
use did_hosting_common::server::store::{KS_ACL, KS_DIDS};
use did_hosting_common::server::vta_setup;
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
    let finalise = format!(
        "did-hosting-daemon setup --setup-key-file {}",
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
    eprintln!("  DID Hosting Daemon — Setup Wizard");
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
            VtaMode::SelfManaged => {
                return run_self_managed_setup(config_path).await;
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
    let (enable, mut features) = prompt_enable_and_features()?;

    // 2. Public URL + DID path. `public_url` is the bare origin (WebAuthn
    //    RP, domain seed, config). The DID path is prompted separately and
    //    folded back into the hosting URL handed to the VTA, so the minted
    //    DID, the local store import, and resolution all agree on the path.
    eprintln!();
    eprintln!("  The public URL is where the daemon is reachable. The embedded");
    eprintln!("  server hosts the daemon's DID document at");
    eprintln!("  <public-url>/<did-path>/did.jsonl.");
    eprintln!();
    let entered_url: String = Input::new()
        .with_prompt("Public URL (e.g. https://webvh.example.com)")
        .interact_text()?;
    let (public_url, default_did_path) = split_origin_and_did_path(&entered_url);
    let did_path = prompt_did_path(&default_did_path)?;
    let hosting_url = hosting_url_for(&public_url, &did_path);

    // 3. VTA DID + context, then provision via ephemeral did:key.
    //    Headless phase 2 supplies a pre-loaded setup key, in which case
    //    we skip the "Has the context been created?" confirmation.
    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhDaemonMessages);
    let preloaded_setup_key = match preloaded_setup_key_file.as_deref() {
        Some(path) => Some(EphemeralSetupKey::load_from(path)?),
        None => None,
    };
    // The mediator selection happens inside `run_online_provision` so
    // it can drive the VTA template choice (did-hosting-control with mediator,
    // did-hosting-daemon without). DIDComm is enabled iff a mediator was set.
    let (outcome, mediator_did) =
        run_online_provision(&hosting_url, messages, preloaded_setup_key).await?;
    features.didcomm = mediator_did.is_some();

    // 5. Host / port / log / data
    let host = setup_prompts::prompt_listen_host("0.0.0.0")?;
    let port = setup_prompts::prompt_listen_port(8534)?;

    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(log_levels)
        .default(0)
        .interact()?;
    let log_level = log_levels[log_level_idx].to_string();
    let log_format = setup_prompts::prompt_log_format()?;

    let data_dir: String = Input::new()
        .with_prompt("Data directory root")
        .default("data/daemon".to_string())
        .interact_text()?;
    let store_path = PathBuf::from(&data_dir).join("store");
    let witness_store_path = PathBuf::from(&data_dir).join("witness");

    // 6. Secrets backend
    let secrets_config = did_hosting_common::server::secret_store::wizard::prompt_secrets_backend(
        "did-hosting-daemon-secrets",
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
            trusted_proxies: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
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
        limits: did_hosting_server::config::LimitsConfig::default(),
        watchers: Vec::new(),
        vta: VtaConfig {
            url: outcome.vta_url.clone(),
            did: Some(outcome.vta_did.clone()),
            context_id: None,
        },
        watcher_sync: webvh_watcher::config::SyncConfig::default(),
        registry: did_hosting_control::config::RegistryConfig::default(),
        features,
        identity: IdentityConfig::default(),
        enable,
        config_path: output_path.clone(),

        hosting: did_hosting_common::server::config::HostingConfig::default(),
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
    eprintln!("    did-hosting-daemon --config {}", output_path.display());
    eprintln!();

    Ok(())
}

/// Top-level identity-source choice for the `setup` wizard.
///
/// The first three variants drive a VTA-provisioned identity. `SelfManaged`
/// skips the VTA entirely — the daemon generates its own keys and self-hosts
/// its `did:webvh` identifier. Daemon-only in v1; see
/// `docs/self-managed-mode-spec.md`.
enum VtaMode {
    /// VTA reachable from this host — provision online via the SDK.
    Online,
    /// VTA is air-gapped — write a sealed bootstrap request to ferry
    /// to the VTA admin (phase 1 of 2).
    OfflineStart,
    /// Operator already has a sealed response back from the VTA admin
    /// — open it and finish setup (phase 2 of 2).
    OfflineComplete,
    /// No parent VTA — the daemon generates its own keys and DID.
    SelfManaged,
}

/// Top-level mode prompt — drives the dispatch in `run_wizard`.
fn prompt_vta_mode() -> Result<VtaMode, Box<dyn std::error::Error>> {
    let items = [
        "Online — VTA reachable from this host",
        "Offline — start a new sealed-bundle bootstrap (phase 1)",
        "Offline — complete a pending sealed-bundle bootstrap (phase 2)",
        "Self-managed (no VTA — daemon manages its own DID)",
    ];
    let idx = Select::new()
        .with_prompt("How will the daemon obtain its identity?")
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
/// 4. Resolve the VTA's recommended mediator and let the operator pick
///    one. The choice drives the VTA template: with a mediator we mint
///    via `did-hosting-control` so the integration DID document carries a
///    `DIDCommMessaging` service entry; without one we mint via
///    `did-hosting-daemon` (HTTP-only).
/// 5. Drive `vta_sdk::provision_client::run_provision`.
async fn run_online_provision(
    hosting_url: &str,
    messages: Arc<dyn OperatorMessages>,
    preloaded_setup_key: Option<EphemeralSetupKey>,
) -> Result<(vta_setup::OnlineProvisionOutcome, Option<String>), Box<dyn std::error::Error>> {
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

    eprintln!();
    // When the VTA advertises a mediator there are three genuine choices
    // (use it / enter a different one / none), so a Select earns its keep.
    // When it doesn't, a single "leave empty to skip" prompt suffices —
    // no point asking *whether* before asking *which*.
    let vta_mediator = vta_setup::resolve_vta_mediator(&vta_did).await;
    let mediator_did = match vta_mediator {
        Some(vm) => {
            let options = [
                format!("Use VTA's mediator ({vm})"),
                "Enter a different mediator DID".to_string(),
                "No mediator".to_string(),
            ];
            let idx = Select::new()
                .with_prompt("DIDComm mediator")
                .items(&options)
                .default(0)
                .interact()?;
            match idx {
                0 => Some(vm),
                1 => prompt_mediator_did()?,
                _ => None,
            }
        }
        None => prompt_mediator_did()?,
    };

    let ask = match mediator_did.as_deref() {
        Some(med) => ProvisionAsk::webvh_control(&context_id, hosting_url, med),
        None => ProvisionAsk::webvh_daemon(&context_id, hosting_url),
    }
    .with_label(format!("did-hosting-daemon setup — {context_id}"));

    eprintln!();
    eprintln!("  Provisioning daemon DID via VTA...");
    eprintln!();

    let outcome = vta_setup::online_provision_setup(vta_setup::OnlineProvisionInputs {
        vta_did,
        context_id,
        ask,
        messages,
        setup_key,
    })
    .await?;
    Ok((outcome, mediator_did))
}

// ---------------------------------------------------------------------------
// Self-managed setup (no VTA)
//
// The daemon generates its own Ed25519 + X25519 keys, builds a self-hosted
// `did:webvh` document, and persists everything via the same
// `finalize_daemon_setup` helper the VTA flows use. The wizard does not seed
// any admin into the ACL — admin enrolment happens post-start via
// `did-hosting-daemon invite --did <ADMIN_DID> --role admin` + passkey redemption.
// See docs/self-managed-mode-spec.md.
// ---------------------------------------------------------------------------

async fn run_self_managed_setup(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  Self-managed mode: the daemon generates its own keys and");
    eprintln!("  self-hosts a did:webvh identifier. No parent VTA is involved");
    eprintln!("  in the daemon's own identity. External tenant VTAs may still");
    eprintln!("  provision DIDs into this daemon over DIDComm at runtime.");
    eprintln!();
    eprintln!("  Daemon-only mode. Cannot be migrated to VTA-managed later.");
    eprintln!();

    // 0. Output config path (overwrite confirm).
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

    // 1. Enabled services + features.
    let (enable, features) = prompt_enable_and_features()?;

    // 2. Public URL + DID path (drive the did:webvh identifier).
    //    `public_url` is the bare origin; the DID path is prompted
    //    separately. Self-managed builds the DID document locally from
    //    (host, did_path), so the path is used directly — no URL folding.
    eprintln!();
    eprintln!("  The public URL is where the daemon is reachable. The daemon");
    eprintln!("  hosts its own DID document at <public-url>/<did-path>/did.jsonl.");
    eprintln!();
    let entered_url: String = Input::new()
        .with_prompt("Public URL (e.g. https://webvh.example.com)")
        .interact_text()?;
    let (public_url, default_did_path) = split_origin_and_did_path(&entered_url);
    warn_if_insecure_public_url(&public_url);
    let did_path = prompt_did_path(&default_did_path)?;

    // 3. Mediator. Optional in name, but skipping it means the daemon's DID
    //    document will not advertise a DIDCommMessaging service — and the
    //    daemon then cannot be registered as a VTA-hosting webvh server
    //    (`vta webvh add-server` rejects DIDs with no DIDComm endpoint).
    //    Warn explicitly on the empty path and require a confirmation so
    //    operators don't end up with a DID that fails downstream VTA
    //    integration silently.
    eprintln!();
    eprintln!("  DIDComm mediator. Required if you want this daemon to:");
    eprintln!("    - receive inbound DIDComm from external VTAs (tenant DID provisioning), or");
    eprintln!("    - be registered as a DID hosting server with a VTA");
    eprintln!("      (`vta webvh add-server` requires a DIDCommMessaging endpoint).");
    eprintln!();
    // A single "leave empty to skip" prompt — no separate yes/no first.
    // An empty answer triggers an explicit warn-and-confirm since a
    // mediator-less DID document can't be registered with a VTA.
    let mediator_did = match prompt_mediator_did()? {
        Some(did) => Some(did),
        None => {
            eprintln!();
            eprintln!("  No mediator configured. Without a mediator, the generated DID");
            eprintln!("  document will not include a DIDCommMessaging service. This");
            eprintln!("  daemon will not be usable as a VTA hosting server, and external");
            eprintln!("  VTAs will not be able to send DIDComm messages to it.");
            eprintln!();
            let proceed = Confirm::new()
                .with_prompt("Continue without a mediator?")
                .default(false)
                .interact()?;
            if !proceed {
                eprintln!();
                eprintln!("  Setup cancelled. Re-run and supply a mediator DID when prompted.");
                return Ok(());
            }
            None
        }
    };

    // 4. Host / port / log / data dir.
    let host = setup_prompts::prompt_listen_host("0.0.0.0")?;
    let port = setup_prompts::prompt_listen_port(8534)?;

    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(log_levels)
        .default(0)
        .interact()?;
    let log_level = log_levels[log_level_idx].to_string();
    let log_format = setup_prompts::prompt_log_format()?;

    let data_dir: String = Input::new()
        .with_prompt("Data directory root")
        .default("data/daemon".to_string())
        .interact_text()?;
    let store_path = PathBuf::from(&data_dir).join("store");
    let witness_store_path = PathBuf::from(&data_dir).join("witness");

    // 5. Secrets backend.
    let secrets_config = did_hosting_common::server::secret_store::wizard::prompt_secrets_backend(
        "did-hosting-daemon-secrets",
        "webvh",
    )
    .await?;

    // 6. Generate keys locally.
    let signing = Secret::generate_ed25519(None, None);
    let ka = Secret::generate_x25519(None, None)?;
    let signing_pub_mb = signing.get_public_keymultibase()?;
    let ka_pub_mb = ka.get_public_keymultibase()?;
    let signing_priv_mb = signing.get_private_keymultibase()?;
    let ka_priv_mb = ka.get_private_keymultibase()?;
    let jwt_signing_key = vta_setup::generate_ed25519_multibase();
    eprintln!();
    eprintln!("  Generated Ed25519 signing key, X25519 key-agreement key, and JWT signing key.");

    // 7. Build the daemon's own DID document + signed log entry.
    let host_encoded = did_hosting_common::did::encode_host(&public_url)
        .map_err(|e| format!("failed to encode host from public URL: {e}"))?;
    let doc = build_did_document(
        &host_encoded,
        &did_path,
        &signing_pub_mb,
        &DidDocumentOptions {
            key_agreement_multibase: Some(&ka_pub_mb),
            mediator_endpoint: mediator_did.as_deref(),
        },
    );
    let (_scid, jsonl) = create_log_entry(&doc, &signing)
        .await
        .map_err(|e| format!("failed to create DID log entry: {e}"))?;

    // 8. Build DaemonConfig with self-managed identity + empty VTA.
    let config = DaemonConfig {
        server: ServerConfig {
            host: host.clone(),
            port,
            trusted_proxies: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
        },
        log: LogConfig {
            level: log_level,
            format: log_format,
        },
        auth: AuthConfig::default(),
        secrets: secrets_config,
        // server_did is populated by finalize_daemon_setup after import.
        server_did: None,
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
        limits: did_hosting_server::config::LimitsConfig::default(),
        watchers: Vec::new(),
        vta: VtaConfig::default(),
        watcher_sync: webvh_watcher::config::SyncConfig::default(),
        registry: did_hosting_control::config::RegistryConfig::default(),
        features,
        identity: IdentityConfig {
            mode: IdentityMode::SelfManaged,
        },
        hosting: did_hosting_common::server::config::HostingConfig::default(),
        enable,
        config_path: output_path.clone(),
    };

    // 9. Persist via the shared finalize helper. AdminChoice::Skip leaves
    //    the ACL empty — admin enrolment is the operator's first action via
    //    `did-hosting-daemon invite` after the daemon is running.
    finalize_daemon_setup(
        &config,
        &output_path,
        ServerSecrets {
            signing_key: signing_priv_mb,
            key_agreement_key: ka_priv_mb,
            jwt_signing_key,
            vta_credential: None,
        },
        Some(&jsonl),
        &did_path,
        AdminChoice::Skip,
    )
    .await?;

    eprintln!();
    eprintln!("  Setup complete!");
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!();
    eprintln!("    1. Start the daemon:");
    eprintln!(
        "         did-hosting-daemon --config {}",
        output_path.display()
    );
    eprintln!();
    eprintln!("    2. Mint your first admin enrolment invite (replace");
    eprintln!("       <ADMIN_DID> with the DID the admin will authenticate as):");
    eprintln!(
        "         did-hosting-daemon invite --did <ADMIN_DID> --role admin \\\n           --config {}",
        output_path.display()
    );
    eprintln!();
    eprintln!("    3. Open the printed enrolment URL in a browser to bind a");
    eprintln!("       passkey to that DID. Subsequent admin login uses the");
    eprintln!("       passkey.");
    eprintln!();

    Ok(())
}

/// Emit a stderr warning when the operator-supplied public URL is plaintext
/// HTTP or points at localhost/loopback. Self-managed mode is permissive —
/// the wizard accepts these for dev workflows — but the warning makes it
/// hard to ship one of these into production by accident.
fn warn_if_insecure_public_url(url: &str) {
    let lower = url.to_ascii_lowercase();
    let is_http = lower.starts_with("http://");
    let is_loopback = lower.contains("://localhost")
        || lower.contains("://127.0.0.1")
        || lower.contains("://[::1]");

    if is_http || is_loopback {
        eprintln!();
        eprintln!("  ┌─ WARNING ──────────────────────────────────────────────");
        if is_http {
            eprintln!("  │ Public URL uses plaintext http://. DIDComm and DID");
            eprintln!("  │ resolution from peers will be unauthenticated in");
            eprintln!("  │ transit — only acceptable for development.");
        }
        if is_loopback {
            eprintln!("  │ Public URL points at localhost / loopback. The DID");
            eprintln!("  │ document will only resolve from this machine.");
        }
        eprintln!("  └────────────────────────────────────────────────────────");
        eprintln!();
    }
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
    secrets: did_hosting_common::server::config::SecretsConfig,
    admin: AdminChoice,
}

pub async fn run_setup_offline_prepare(
    config_path: Option<PathBuf>,
    request_out: PathBuf,
    state_out: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  DID Hosting Daemon — Offline Setup (step 1/2)");
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

    let (enable, mut features) = prompt_enable_and_features()?;

    // `public_url` is the bare origin; the DID path is prompted separately
    // and folded into the hosting URL embedded in the bootstrap request, so
    // the VTA-minted DID and the phase-2 local import agree on the path.
    let entered_url: String = Input::new()
        .with_prompt("Public URL (e.g. https://webvh.example.com)")
        .interact_text()?;
    let (public_url, default_did_path) = split_origin_and_did_path(&entered_url);
    let did_path = prompt_did_path(&default_did_path)?;
    let hosting_url = hosting_url_for(&public_url, &did_path);

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
    let mediator_did = prompt_mediator_did()?;
    features.didcomm = mediator_did.is_some();

    let host = setup_prompts::prompt_listen_host("0.0.0.0")?;
    let port = setup_prompts::prompt_listen_port(8534)?;

    let log_levels = ["info", "debug", "warn", "error", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(log_levels)
        .default(0)
        .interact()?;
    let log_level = log_levels[log_level_idx].to_string();
    let log_format = setup_prompts::prompt_log_format()?;

    let data_dir: String = Input::new()
        .with_prompt("Data directory root")
        .default("data/daemon".to_string())
        .interact_text()?;

    let secrets = did_hosting_common::server::secret_store::wizard::prompt_secrets_backend(
        "did-hosting-daemon-secrets",
        "webvh",
    )
    .await?;
    let admin = prompt_admin_choice()?;

    // VP-framed bootstrap request. With a mediator we name the
    // `did-hosting-control` template so the rendered DID document carries
    // both `WebVHHosting` and `DIDCommMessaging` services; without one
    // we fall back to `did-hosting-daemon` (HTTP-only).
    let (template_name, template_vars): (&str, Vec<(&str, &str)>) = match mediator_did.as_deref() {
        Some(med) => (
            "did-hosting-control",
            vec![("URL", hosting_url.as_str()), ("MEDIATOR_DID", med)],
        ),
        None => ("did-hosting-daemon", vec![("URL", hosting_url.as_str())]),
    };
    let info = vta_setup::write_offline_bootstrap_request(
        &request_out,
        template_name,
        &template_vars,
        &context_id,
        Some("did-hosting-daemon"),
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
        "         did-hosting-daemon setup-offline-complete \\\n           --bundle <bundle> --expect-digest <hex> --state {}",
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
    eprintln!("  DID Hosting Daemon — Offline Setup (step 2/2)");
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
            trusted_proxies: Vec::new(),
            trusted_proxy_cidrs: Vec::new(),
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
        limits: did_hosting_server::config::LimitsConfig::default(),
        watchers: Vec::new(),
        vta: VtaConfig {
            url: result.vta_url.clone(),
            did: Some(result.vta_did.clone()),
            context_id: None,
        },
        watcher_sync: webvh_watcher::config::SyncConfig::default(),
        registry: did_hosting_control::config::RegistryConfig::default(),
        features: state.features.clone(),
        identity: IdentityConfig::default(),
        hosting: did_hosting_common::server::config::HostingConfig::default(),
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
        "    did-hosting-daemon --config {}",
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
        // The caller flips this to true once a mediator has been chosen.
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
        "Skip (add later with did-hosting-daemon add-acl)",
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

/// Split an operator-entered URL into its origin (`scheme://host[:port]`,
/// trailing slash stripped) and the DID path encoded in its path
/// component. An empty path maps to `.well-known`, the webvh root.
///
/// The origin becomes `config.public_url` (WebAuthn RP origin, first-boot
/// domain seed, and the host component of the daemon's own DID); the DID
/// path is the sub-path the daemon publishes its DID under. Folding the
/// path back in via [`hosting_url_for`] round-trips:
/// `split_origin_and_did_path(hosting_url_for(o, p)) == (o, p)`.
fn split_origin_and_did_path(public_url: &str) -> (String, String) {
    let trimmed = public_url.trim_end_matches('/');
    let scheme_end = trimmed.find("://").map(|i| i + 3).unwrap_or(0);
    match trimmed[scheme_end..].find('/') {
        Some(rel) => {
            let at = scheme_end + rel;
            let path = trimmed[at..].trim_matches('/');
            let did_path = if path.is_empty() {
                ".well-known".to_string()
            } else {
                path.to_string()
            };
            (trimmed[..at].to_string(), did_path)
        }
        None => (trimmed.to_string(), ".well-known".to_string()),
    }
}

/// Fold a DID path back into the hosting origin so the VTA mints the DID
/// at the matching web location (the VTA derives the DID's path segment
/// from this URL, and the local import path must match). `.well-known`
/// is the webvh root and carries no path segment, so the origin is
/// returned unchanged.
fn hosting_url_for(origin: &str, did_path: &str) -> String {
    if did_path == ".well-known" {
        origin.to_string()
    } else {
        format!(
            "{}/{}",
            origin.trim_end_matches('/'),
            did_path.trim_matches('/')
        )
    }
}

/// Prompt for the DID path the daemon publishes its own DID under,
/// defaulting to `default` (the path component of the public URL, or
/// `.well-known` when it has none). An empty entry normalises back to
/// `.well-known`.
fn prompt_did_path(default: &str) -> Result<String, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("  The DID path is where the daemon publishes its own DID document,");
    eprintln!("  served at <public-url>/<did-path>/did.jsonl. Use `.well-known` for");
    eprintln!("  the host's root DID, or a sub-path such as `dids/daemon`.");
    eprintln!();
    let did_path: String = Input::new()
        .with_prompt("DID path on the server")
        .default(default.to_string())
        .interact_text()?;
    let trimmed = did_path.trim().trim_matches('/');
    Ok(if trimmed.is_empty() {
        ".well-known".to_string()
    } else {
        trimmed.to_string()
    })
}

/// Single-prompt mediator entry shared by every setup flow. Returns
/// `None` when the operator leaves it blank. Using `allow_empty` rather
/// than a `.default("")` avoids dialoguer's wrapped-line re-render of
/// long DIDs — the artifact that previously forced a two-step
/// Confirm-then-Input and made the wizard look like it asked for the
/// mediator twice.
fn prompt_mediator_did() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let did: String = Input::new()
        .with_prompt("Mediator DID (leave empty to skip)")
        .allow_empty(true)
        .interact_text()?;
    let trimmed = did.trim();
    Ok(if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    })
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
    // like `did-hosting-server setup` does — the daemon hosts its own DID.
    if let Some(log_entry) = log_entry {
        eprintln!();
        eprintln!("  Importing daemon DID into store at path '{did_path}'...");
        let store = Store::open(&config.store).await?;
        let dids_ks = store.keyspace(KS_DIDS)?;
        match did_hosting_server::bootstrap::import_did_at_path(
            &store, &dids_ks, did_path, log_entry, None,
        )
        .await
        {
            Ok(res) => {
                eprintln!("  Daemon DID imported!");
                eprintln!("  DID:  {}", res.did_id);
                eprintln!("  SCID: {}", res.scid);
                did_hosting_server::setup::update_server_did_in_config(
                    &output_path.to_path_buf(),
                    &res.did_id,
                )?;
                eprintln!("  server_did updated in {}", output_path.display());
            }
            Err(e) => {
                eprintln!("  Warning: failed to import daemon DID: {e}");
                eprintln!(
                    "  You can retry with `did-hosting-server bootstrap-did --path {did_path}` \
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
        let acl_ks = store.keyspace(KS_ACL)?;
        let entry = did_hosting_common::server::acl::AclEntry {
            did: admin_did.clone(),
            role: did_hosting_common::server::acl::Role::Admin,
            label: Some("Setup wizard admin".into()),
            created_at: did_hosting_common::server::auth::session::now_epoch(),
            max_total_size: None,
            max_did_count: None,

            domains: did_hosting_common::server::domain::DomainScope::All,
        };
        did_hosting_common::server::acl::store_acl_entry(&acl_ks, &entry).await?;
        store.persist().await?;
        eprintln!("  Admin ACL entry added for {admin_did}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{hosting_url_for, split_origin_and_did_path};

    #[test]
    fn bare_origin_maps_to_well_known_root() {
        assert_eq!(
            split_origin_and_did_path("https://webvh.example.com"),
            (
                "https://webvh.example.com".to_string(),
                ".well-known".to_string()
            )
        );
    }

    #[test]
    fn trailing_slash_is_stripped() {
        assert_eq!(
            split_origin_and_did_path("https://webvh.example.com/"),
            (
                "https://webvh.example.com".to_string(),
                ".well-known".to_string()
            )
        );
    }

    #[test]
    fn path_component_becomes_did_path() {
        assert_eq!(
            split_origin_and_did_path("https://webvh.example.com/dids/daemon"),
            (
                "https://webvh.example.com".to_string(),
                "dids/daemon".to_string()
            )
        );
    }

    #[test]
    fn port_is_preserved_in_origin() {
        assert_eq!(
            split_origin_and_did_path("http://localhost:8534/svc"),
            ("http://localhost:8534".to_string(), "svc".to_string())
        );
    }

    #[test]
    fn well_known_is_not_folded_into_url() {
        // The webvh root carries no path segment.
        assert_eq!(
            hosting_url_for("https://webvh.example.com", ".well-known"),
            "https://webvh.example.com"
        );
    }

    #[test]
    fn custom_path_is_folded_into_url() {
        assert_eq!(
            hosting_url_for("https://webvh.example.com", "dids/daemon"),
            "https://webvh.example.com/dids/daemon"
        );
    }

    #[test]
    fn fold_then_split_round_trips() {
        // The contract VTA-mode correctness depends on: the path folded
        // into the URL (handed to the VTA) is exactly the path derived
        // back out for the local store import.
        for (origin, did_path) in [
            ("https://webvh.example.com", ".well-known"),
            ("https://webvh.example.com", "dids/daemon"),
            ("http://localhost:8534", "svc"),
        ] {
            let url = hosting_url_for(origin, did_path);
            assert_eq!(
                split_origin_and_did_path(&url),
                (origin.to_string(), did_path.to_string()),
                "round-trip failed for {origin} + {did_path}"
            );
        }
    }
}

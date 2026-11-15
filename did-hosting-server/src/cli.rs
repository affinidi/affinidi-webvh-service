//! `did-hosting-server`'s command line, and the DID-store subcommands it
//! shares with `did-hosting-daemon`.
//!
//! The binary's [`Cli`] lives here, in the library, so the daemon's parity
//! test can read its subcommands. [`DidCommand`] is the group of offline
//! DID-store commands the daemon flattens into its own `Command`; the shared
//! identity, TSP, key and VTA groups come from
//! [`did_hosting_common::server::cli`].

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use did_hosting_common::server::cli::{
    CliResult, IdentityCommand, KeysCommand, Loader, ServiceConfig, TspCommand, VtaCommand,
};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, HostingConfig, IdentityConfig, SecretsConfig, ServerConfig,
    StoreConfig,
};
use did_hosting_common::server::store::{KS_DIDS, Store};

use crate::config::AppConfig;

#[derive(Parser)]
#[command(name = "did-hosting-server", about = "DID Hosting Server", version)]
pub struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run interactive setup wizard to generate config.toml.
    ///
    /// Headless mode (for CI / scripted setup):
    ///
    /// 1. Run with `--setup-key-out <path> --context <id>` to mint an
    ///    ephemeral did:key, persist it (chmod 0600), and print the
    ///    `pnm contexts create` command. Exits without further prompts.
    /// 2. Run again with `--setup-key-file <path>` to drive the rest of
    ///    the wizard reusing the persisted setup DID.
    Setup {
        /// Phase 1: mint an ephemeral did:key, persist to `<path>`, and
        /// print the `pnm contexts create` command + exit.
        #[arg(long, conflicts_with = "setup_key_file")]
        setup_key_out: Option<PathBuf>,
        /// Phase 2: reuse the setup DID persisted at `<path>`; skip the
        /// interactive "Has the context been created?" confirmation.
        #[arg(long, conflicts_with = "setup_key_out")]
        setup_key_file: Option<PathBuf>,
        /// Context id for phase 1's PNM command. Defaults to `did-hosting`.
        #[arg(long, default_value = "did-hosting", requires = "setup_key_out")]
        context: String,
        /// Path to a declarative setup recipe TOML. Drives the wizard
        /// non-interactively — see `examples/did-hosting-server-build.toml`.
        /// For `vta_mode = "online"` also pass `--setup-key-file <path>`
        /// (Phase 2). For `offline-complete`, the recipe carries the
        /// bundle path + digest.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Refuse to run when an existing setup is detected, unless this
        /// flag is set. Without it, the wizard exits 4 to protect issued
        /// JWTs and active VTA sessions.
        #[arg(long)]
        force_reprovision: bool,
        /// Explicit "no TTY available" flag. Requires `--from`. With this
        /// set, missing required recipe fields fail fast instead of
        /// dropping into prompts (which would hang in CI).
        #[arg(long, requires = "from")]
        non_interactive: bool,
    },
    /// Teardown a server install: clears managed secrets from the
    /// configured backend, removes the config file (and `.bak`).
    Uninstall {
        /// Skip the typed "DELETE" confirmation prompt. CI use only.
        #[arg(long)]
        yes: bool,
    },
    /// Run health check diagnostics. Exits non-zero when a check fails (or,
    /// with --strict, warns), so it can gate a deploy or a container probe.
    Health {
        /// Also exit non-zero when a check only warned (a store held by the
        /// running service, plaintext secrets, a non-2xx reachability probe).
        #[arg(long)]
        strict: bool,
    },
    /// Export server data to a backup file
    Backup {
        /// Output file path (use "-" for stdout)
        #[arg(short, long, default_value = "did-hosting-backup.json")]
        output: String,
    },
    /// Restore server data from a backup file.
    ///
    /// The backup is checked before anything is written, config.toml
    /// included. Each did:webvh (or did:webs) log must verify, match its
    /// record, and extend both the backup's own high-water mark and what the
    /// store already holds for that DID; otherwise nothing is restored.
    /// Restore into an empty store to start from the backup's state. The
    /// data goes into the store the backup's config names (after the
    /// usual environment overrides). If a restore is interrupted, run it
    /// again: it is safe to repeat.
    Restore {
        /// Input backup file path
        #[arg(short, long)]
        input: String,
    },
    /// Step 1/2 of the offline (air-gapped VTA) setup wizard.
    ///
    /// Runs the interactive prompts, writes the bootstrap-request.json +
    /// ephemeral seed, and serialises the operator's answers to a state
    /// TOML file. After the VTA admin returns a sealed bundle, run
    /// `setup-offline-complete`.
    SetupOfflinePrepare {
        /// Path for the bootstrap-request.json file.
        #[arg(long, default_value = "bootstrap-request.json")]
        request: PathBuf,
        /// Path for the pending state file (plain TOML, no secrets).
        ///
        /// The ephemeral bootstrap seed is persisted to the configured
        /// secrets backend (keyring / AWS / GCP / plaintext-in-config),
        /// not to a file.
        #[arg(long, default_value = "setup-offline-state.toml")]
        state: PathBuf,
    },
    /// Step 2/2 of the offline setup wizard.
    ///
    /// Opens the sealed bundle with the seed saved during step 1, then
    /// persists the DID + keys + config per the choices captured in the
    /// state file, and imports the server's own DID into the local store.
    SetupOfflineComplete {
        /// Path to the ASCII-armored sealed bundle from the VTA admin.
        #[arg(long)]
        bundle: PathBuf,
        /// Expected SHA-256 digest (lowercase hex) of the armored
        /// ciphertext; communicated out-of-band.
        #[arg(long)]
        expect_digest: String,
        /// Path to the state file written by `setup-offline-prepare`.
        #[arg(long, default_value = "setup-offline-state.toml")]
        state: PathBuf,
    },
    #[command(flatten)]
    Identity(IdentityCommand),
    #[command(flatten)]
    Tsp(TspCommand),
    #[command(flatten)]
    Did(DidCommand),
    #[command(flatten)]
    Keys(KeysCommand),
    #[command(flatten)]
    Vta(VtaCommand),
}

impl ServiceConfig for AppConfig {
    fn config_path(&self) -> &Path {
        &self.config_path
    }
    fn store(&self) -> &StoreConfig {
        &self.store
    }
    fn secrets(&self) -> &SecretsConfig {
        &self.secrets
    }
    fn server_did(&self) -> Option<&str> {
        self.server_did.as_deref()
    }
    fn mediator_did(&self) -> Option<&str> {
        self.mediator_did.as_deref()
    }
    fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }
    fn features(&self) -> &FeaturesConfig {
        &self.features
    }
    fn hosting(&self) -> &HostingConfig {
        &self.hosting
    }
    fn identity(&self) -> &IdentityConfig {
        &self.identity
    }
    fn server(&self) -> &ServerConfig {
        &self.server
    }
    fn auth(&self) -> &AuthConfig {
        &self.auth
    }
}

/// The DIDs in the service's store, offline: the service must be stopped
/// (the store is exclusively locked).
#[derive(Debug, Subcommand)]
pub enum DidCommand {
    /// Bootstrap a DID for this server (defaults to root .well-known)
    BootstrapDid {
        /// DID path/mnemonic to bootstrap (e.g. "my-org", "services/auth")
        /// Defaults to ".well-known" (the root DID for this server)
        #[arg(long, visible_alias = "mnemonic", default_value = ".well-known")]
        path: String,
        /// Path to an existing did.jsonl file to import
        #[arg(long)]
        did_log: Option<PathBuf>,
        /// Path to an existing did-witness.json file to import (requires --did-log)
        #[arg(long)]
        did_witness: Option<PathBuf>,
        /// Witness service URL for requesting a proof (auto-bootstrap only)
        #[arg(long, requires = "witness_did")]
        witness_url: Option<String>,
        /// Witness ID to use when requesting a proof (auto-bootstrap only)
        #[arg(long)]
        witness_id: Option<String>,
        /// The witness server's own DID (its `server_did`), required with
        /// --witness-url. The sign-in is addressed to it, and the witness
        /// server refuses one addressed elsewhere. This is not --witness-id,
        /// which names one of the witnesses that server hosts.
        #[arg(long)]
        witness_did: Option<String>,
    },
    /// Recreate a DID at a given path (deletes existing, creates new, updates config)
    RecreateDid {
        /// DID path/mnemonic to recreate (e.g. "webvh/server1")
        #[arg(long, visible_alias = "mnemonic")]
        path: String,
    },
    /// Recover a soft-deleted DID
    RecoverDid {
        /// DID path/mnemonic to recover (e.g. "webvh/server1")
        #[arg(long, visible_alias = "mnemonic")]
        path: String,
    },
    /// Load a DID at an arbitrary path (e.g., "services/control").
    ///
    /// The log must verify (and its witness proofs, if it is witnessed) and
    /// must extend every history this store has served for that DID,
    /// including one since removed with `remove-did`.
    LoadDid {
        /// Path to store the DID at (e.g., "services/control")
        #[arg(long, visible_alias = "mnemonic")]
        path: String,
        /// Path to the did.jsonl file
        #[arg(long)]
        did_log: PathBuf,
        /// Optional did-witness.json file
        #[arg(long)]
        did_witness: Option<PathBuf>,
    },
    /// Dump the DID log (did.jsonl) for a given path
    DumpDid {
        /// DID path/mnemonic to dump (e.g. ".well-known", "my-org")
        #[arg(long, visible_alias = "mnemonic")]
        path: String,
        /// Also dump the witness proof (did-witness.json)
        #[arg(long)]
        witness: bool,
    },
    /// List all DIDs in the store
    ListDids,
    /// Remove a DID and all its data from the store
    RemoveDid {
        /// DID path/mnemonic to remove (e.g. "glenn", ".well-known")
        #[arg(long, visible_alias = "mnemonic")]
        path: String,
    },
}

impl DidCommand {
    /// Run the command against the configuration `load` returns. `binary` is
    /// the binary the operator runs, named in the hints it prints.
    pub async fn run<C: ServiceConfig>(self, binary: &str, load: Loader<'_, C>) -> CliResult {
        let config = load()?;
        match self {
            Self::BootstrapDid {
                path,
                did_log,
                did_witness,
                witness_url,
                witness_id,
                witness_did,
            } => {
                bootstrap_did(
                    &config,
                    binary,
                    path,
                    did_log,
                    did_witness,
                    witness_url.zip(witness_id).zip(witness_did),
                )
                .await
            }
            Self::RecreateDid { path } => recreate_did(&config, binary, path).await,
            Self::RecoverDid { path } => recover_did(config.store(), &path).await,
            Self::LoadDid {
                path,
                did_log,
                did_witness,
            } => load_did(config.store(), &path, &did_log, did_witness.as_deref()).await,
            Self::DumpDid { path, witness } => {
                did_hosting_common::server::cli_dids::run_dump_did(config.store(), &path, witness)
                    .await
            }
            Self::ListDids => list_dids(config.store()).await,
            Self::RemoveDid { path } => remove_did(config.store(), &path).await,
        }
    }
}

/// Where the DID at `mnemonic` serves its log, under the public URL.
fn log_url_path(mnemonic: &str) -> String {
    format!("{mnemonic}/did.jsonl")
}

fn read_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()).into())
}

/// The service's signing and key-agreement secrets, and the mediator its
/// DID should advertise: what minting a DID for it needs.
async fn minting_inputs<C: ServiceConfig>(
    config: &C,
    binary: &str,
) -> Result<
    (
        affinidi_tdk::secrets_resolver::secrets::Secret,
        Option<affinidi_tdk::secrets_resolver::secrets::Secret>,
        Option<String>,
    ),
    Box<dyn std::error::Error>,
> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    let secret_store = did_hosting_common::server::secret_store::create_secret_store(
        config.secrets(),
        config.config_path(),
    )?;
    let secrets = secret_store
        .get()
        .await?
        .ok_or_else(|| format!("no secrets found — run `{binary} setup` first"))?;
    let signing = Secret::from_multibase(&secrets.signing_key, None)
        .map_err(|e| format!("invalid signing_key: {e}"))?;
    let ka = Secret::from_multibase(&secrets.key_agreement_key, None).ok();
    // The mediator the DID's DIDCommMessaging service points at.
    let mediator_uri = match config.mediator_did() {
        Some(vta_did) => {
            did_hosting_common::server::didcomm_profile::resolve_mediator_did(vta_did, None).await
        }
        None => None,
    };
    Ok((signing, ka, mediator_uri))
}

async fn bootstrap_did<C: ServiceConfig>(
    config: &C,
    binary: &str,
    mnemonic: String,
    did_log: Option<PathBuf>,
    did_witness: Option<PathBuf>,
    witness: Option<((String, String), String)>,
) -> CliResult {
    use crate::bootstrap;

    if did_witness.is_some() && did_log.is_none() {
        return Err("--did-witness requires --did-log".into());
    }

    let public_url = config
        .public_url()
        .ok_or("public_url must be set in config for bootstrap")?;

    let store = Store::open(config.store()).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    // Check if DID already exists at this path
    if dids_ks
        .contains_key(crate::did_ops::did_key(&mnemonic))
        .await?
    {
        eprintln!();
        eprintln!("  DID at path '{mnemonic}' already exists.");
        eprintln!("  No action taken.");
        eprintln!();
        return Ok(());
    }

    let result = if let Some(log_path) = did_log {
        // Import from existing files
        let jsonl = read_file(&log_path)?;
        let witness_content = did_witness.as_deref().map(read_file).transpose()?;
        let result = bootstrap::import_did_at_path(
            &store,
            &dids_ks,
            &mnemonic,
            &jsonl,
            witness_content.as_deref(),
        )
        .await?;
        if witness_content.is_some() {
            eprintln!("  Witness data imported.");
        }
        result
    } else {
        // Auto-bootstrap: generate a new DID
        let (signing_secret, ka_secret, mediator_uri) = minting_inputs(config, binary).await?;
        let result = bootstrap::bootstrap_did(
            &store,
            &dids_ks,
            &signing_secret,
            ka_secret.as_ref(),
            mediator_uri.as_deref(),
            config.features().didcomm,
            config.features().tsp,
            public_url,
            &mnemonic,
            config.hosting().scid_also_known_as,
        )
        .await?;

        // Optional: request witness proof
        if let Some(((w_url, w_id), w_did)) = witness {
            eprintln!("  Requesting witness proof...");
            eprintln!("  NOTE: the DID must already be served (by a running server) for the");
            eprintln!("  witness to resolve it and verify the request.");
            match bootstrap::request_witness_proof(&w_url, &w_did, &w_id, &result, &signing_secret)
                .await
            {
                Ok(witness_file) => {
                    dids_ks
                        .insert_raw(
                            crate::did_ops::content_witness_key(&mnemonic),
                            witness_file.into_bytes(),
                        )
                        .await?;
                    eprintln!("  Witness proof stored.");
                }
                Err(e) => {
                    eprintln!("  Warning: witness proof request failed: {e}");
                    eprintln!("  The DID was created but has no witness proof.");
                }
            }
        }

        result
    };

    store.persist().await?;

    let is_root = mnemonic == ".well-known";
    eprintln!();
    if is_root {
        eprintln!("  Root DID bootstrapped!");
    } else {
        eprintln!("  DID bootstrapped at path '{mnemonic}'!");
    }
    eprintln!();
    eprintln!("  DID:   {}", result.did_id);
    eprintln!("  SCID:  {}", result.scid);
    eprintln!("  JSONL: {public_url}/{}", log_url_path(&mnemonic));
    eprintln!();
    if is_root && config.server_did().is_none() {
        eprintln!("  Hint: set server_did in your config.toml:");
        eprintln!("    server_did = \"{}\"", result.did_id);
        eprintln!();
    }

    Ok(())
}

async fn recreate_did<C: ServiceConfig>(config: &C, binary: &str, mnemonic: String) -> CliResult {
    use crate::did_ops::{DidRecord, content_log_key, content_witness_key, did_key, owner_key};

    let public_url = config
        .public_url()
        .ok_or("public_url must be set in config")?;

    let store = Store::open(config.store()).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    // Delete the DID at this path, if any. The record is read first so the
    // right `owner:{owner}:{mnemonic}` reverse-index entry goes with it — not
    // only the `system` owner auto-bootstrap writes.
    if let Some(existing) = dids_ks.get::<DidRecord>(did_key(&mnemonic)).await? {
        let mut batch = store.batch();
        batch.remove(&dids_ks, did_key(&mnemonic));
        batch.remove(&dids_ks, content_log_key(&mnemonic));
        batch.remove(&dids_ks, content_witness_key(&mnemonic));
        batch.remove(&dids_ks, owner_key(&existing.owner, &mnemonic));
        did_hosting_common::server::did_index::stage_record_change(
            &mut batch,
            &dids_ks,
            None,
            Some(&existing),
            None,
        )
        .await?;
        batch.commit().await?;
        eprintln!("  Removed existing DID at path '{mnemonic}'");
    }

    let (signing_secret, ka_secret, mediator_uri) = minting_inputs(config, binary).await?;
    let result = crate::bootstrap::bootstrap_did(
        &store,
        &dids_ks,
        &signing_secret,
        ka_secret.as_ref(),
        mediator_uri.as_deref(),
        config.features().didcomm,
        config.features().tsp,
        public_url,
        &mnemonic,
        config.hosting().scid_also_known_as,
    )
    .await?;

    store.persist().await?;

    // Update server_did in config file
    crate::setup::update_server_did_in_config(config.config_path(), &result.did_id)?;

    eprintln!();
    eprintln!("  DID recreated at path '{mnemonic}'!");
    eprintln!();
    eprintln!("  DID:   {}", result.did_id);
    eprintln!("  SCID:  {}", result.scid);
    eprintln!("  JSONL: {public_url}/{}", log_url_path(&mnemonic));
    eprintln!();
    eprintln!("  config.toml updated with new server_did.");
    eprintln!();

    Ok(())
}

async fn recover_did(store_config: &StoreConfig, mnemonic: &str) -> CliResult {
    use did_hosting_common::did_ops::{DidRecord, did_key};

    let store = Store::open(store_config).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    let key = did_key(mnemonic);
    let mut record: DidRecord = dids_ks
        .get(key.as_str())
        .await?
        .ok_or(format!("DID not found at path '{mnemonic}'"))?;

    if record.deleted_at.is_none() {
        eprintln!("  DID at path '{mnemonic}' is not deleted.");
        return Ok(());
    }

    record.deleted_at = None;
    dids_ks.insert(key.as_str(), &record).await?;
    store.persist().await?;

    eprintln!();
    eprintln!("  DID recovered at path '{mnemonic}'!");
    if let Some(ref did_id) = record.did_id {
        eprintln!("  DID: {did_id}");
    }
    eprintln!();

    Ok(())
}

async fn load_did(
    store_config: &StoreConfig,
    path: &str,
    did_log: &Path,
    did_witness: Option<&Path>,
) -> CliResult {
    let store = Store::open(store_config).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    let jsonl = read_file(did_log)?;
    let witness_content = did_witness.map(read_file).transpose()?;

    let result = crate::bootstrap::import_did_at_path(
        &store,
        &dids_ks,
        path,
        &jsonl,
        witness_content.as_deref(),
    )
    .await?;

    store.persist().await?;

    eprintln!();
    eprintln!("  DID loaded at path '{path}'!");
    eprintln!();
    eprintln!("  DID:  {}", result.did_id);
    eprintln!("  SCID: {}", result.scid);
    eprintln!("  Path: {path}/did.jsonl");
    eprintln!();

    Ok(())
}

async fn list_dids(store_config: &StoreConfig) -> CliResult {
    use did_hosting_common::did_ops::DidRecord;

    let store = Store::open(store_config).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    let raw = dids_ks.prefix_iter_raw("did:").await?;

    if raw.is_empty() {
        eprintln!("  No DIDs in store.");
        return Ok(());
    }

    eprintln!("  {:<25} {:<15} {:<60}", "PATH", "VERSIONS", "DID ID");
    eprintln!("  {}", "-".repeat(100));

    for (_key, value) in &raw {
        if let Ok(record) = serde_json::from_slice::<DidRecord>(value) {
            let did_id = record.did_id.as_deref().unwrap_or("(unpublished)");
            let deleted = if record.deleted_at.is_some() {
                " [deleted]"
            } else {
                ""
            };
            let disabled = if record.disabled { " [disabled]" } else { "" };
            eprintln!(
                "  {:<25} {:<15} {}{}{}",
                record.mnemonic, record.version_count, did_id, deleted, disabled
            );
        }
    }

    eprintln!();
    eprintln!("  Total: {} DIDs", raw.len());

    Ok(())
}

async fn remove_did(store_config: &StoreConfig, path: &str) -> CliResult {
    use did_hosting_common::did_ops::{
        DidRecord, content_log_key, content_witness_key, did_key, owner_key,
    };

    let store = Store::open(store_config).await?;
    let dids_ks = store.keyspace(KS_DIDS)?;

    let record: DidRecord = dids_ks
        .get(did_key(path))
        .await?
        .ok_or_else(|| format!("DID not found at path '{path}'"))?;

    let did_id = record.did_id.as_deref().unwrap_or("(unpublished)");
    eprintln!("  Removing DID at path '{path}'");
    eprintln!("  DID ID: {did_id}");
    eprintln!("  Owner:  {}", record.owner);

    let mut batch = store.batch();
    batch.remove(&dids_ks, did_key(path));
    batch.remove(&dids_ks, content_log_key(path));
    batch.remove(&dids_ks, content_witness_key(path));
    batch.remove(&dids_ks, owner_key(&record.owner, path));
    // The usage counter and domain index row go with the record (the service
    // is stopped for this command, so nothing else writes them).
    did_hosting_common::server::did_index::stage_record_change(
        &mut batch,
        &dids_ks,
        None,
        Some(&record),
        None,
    )
    .await?;
    batch.commit().await?;

    eprintln!("  DID removed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key, owner_key};

    fn record(mnemonic: &str) -> DidRecord {
        DidRecord {
            owner: "did:example:owner".into(),
            mnemonic: mnemonic.into(),
            created_at: 1,
            updated_at: 1,
            version_count: 1,
            did_id: Some(format!("did:webvh:Q1:example.com:{mnemonic}")),
            content_size: 10,
            disabled: false,
            disabled_by_admin: false,
            deleted_at: Some(5),
            method: "webvh".into(),
            domain: "example.com".into(),
            services: None,
            agent_names: Vec::new(),
        }
    }

    /// `recover-did` clears the soft delete, and `remove-did` takes the
    /// record, its log and its owner index with it.
    #[tokio::test]
    async fn recover_then_remove_a_did_offline() {
        let dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        };
        {
            let store = Store::open(&store_config).await.unwrap();
            let ks = store.keyspace(KS_DIDS).unwrap();
            ks.insert(did_key("alice"), &record("alice")).await.unwrap();
            ks.insert_raw(content_log_key("alice"), b"{}".to_vec())
                .await
                .unwrap();
            ks.insert_raw(owner_key("did:example:owner", "alice"), Vec::new())
                .await
                .unwrap();
            store.persist().await.unwrap();
        }

        recover_did(&store_config, "alice").await.unwrap();
        {
            let store = Store::open(&store_config).await.unwrap();
            let ks = store.keyspace(KS_DIDS).unwrap();
            let r: DidRecord = ks.get(did_key("alice")).await.unwrap().unwrap();
            assert_eq!(r.deleted_at, None);
        }

        remove_did(&store_config, "alice").await.unwrap();
        let store = Store::open(&store_config).await.unwrap();
        let ks = store.keyspace(KS_DIDS).unwrap();
        assert!(!ks.contains_key(did_key("alice")).await.unwrap());
        assert!(!ks.contains_key(content_log_key("alice")).await.unwrap());
        assert!(
            !ks.contains_key(owner_key("did:example:owner", "alice"))
                .await
                .unwrap()
        );
        drop(store);
        assert!(remove_did(&store_config, "alice").await.is_err());
    }
}

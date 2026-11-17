//! `did-hosting-control`'s command line, and the ACL and statistics
//! subcommands it shares with `did-hosting-daemon`.
//!
//! The binary's [`Cli`] lives here, in the library, so the daemon's parity
//! test can read its subcommands. [`AdminCommand`] and [`StatsCommand`] are
//! the groups the daemon flattens into its own `Command`; the shared
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

use crate::config::{AppConfig, StatsFlushConfig, StatsTierConfig};

#[derive(Parser)]
#[command(
    name = "did-hosting-control",
    about = "DID Hosting Control Plane — Unified Management",
    version
)]
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
        /// non-interactively. See `examples/did-hosting-control-build.toml`.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Refuse to run when an existing setup is detected, unless this
        /// flag is set. Exit 4 protects issued JWTs / active VTA sessions.
        #[arg(long)]
        force_reprovision: bool,
        /// Explicit "no TTY available" flag. Requires `--from`.
        #[arg(long, requires = "from")]
        non_interactive: bool,
    },
    /// Teardown a control plane install: clears managed secrets and
    /// removes the config file (+ `.bak`, + `control-did.jsonl`).
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
    /// persists the DID + keys + config + admin ACL per the choices
    /// captured in the state file.
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
    Admin(AdminCommand),
    #[command(flatten)]
    Stats(StatsCommand),
    #[command(flatten)]
    Identity(IdentityCommand),
    #[command(flatten)]
    Tsp(TspCommand),
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

impl StatsSettings for AppConfig {
    fn stats_flush(&self) -> &StatsFlushConfig {
        &self.stats_flush
    }
    fn stats_tiers(&self) -> &StatsTierConfig {
        &self.stats
    }
}

/// The ACL, passkey invites and the service's own counters.
#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Add an ACL entry
    AddAcl {
        /// DID to add to the ACL
        #[arg(long)]
        did: String,
        /// Role (admin or owner)
        #[arg(long, default_value = "owner")]
        role: String,
        /// Optional label
        #[arg(long)]
        label: Option<String>,
        /// did-hosting-daemon only: add the entry to the embedded witness's
        /// ACL (`[witness_store]`) instead of the control plane's. The role
        /// must then be `admin` or `service` (request witness signatures
        /// only). Refused by a binary with no embedded witness.
        #[arg(long)]
        witness: bool,
    },
    /// List all ACL entries
    ListAcl {
        /// did-hosting-daemon only: list the embedded witness's ACL
        /// (`[witness_store]`) instead of the control plane's. Refused by a
        /// binary with no embedded witness.
        #[arg(long)]
        witness: bool,
    },
    /// Remove an ACL entry and withdraw its DID's invites
    ///
    /// Withdraws the enrolment invites issued for the DID, or issued or
    /// changed by it. With no ACL entry, only withdraws the invites issued
    /// for the DID, which is how an operator takes back a CLI invite.
    RemoveAcl {
        /// DID to remove from the ACL
        #[arg(long)]
        did: String,
    },
    /// Create a passkey enrollment invite
    Invite {
        /// DID to invite
        #[arg(long)]
        did: String,
        /// Role (admin or owner)
        #[arg(long, default_value = "owner")]
        role: String,
        /// Invite lifetime in hours (default: `auth.passkey_enrollment_ttl`)
        #[arg(long)]
        ttl_hours: Option<u64>,
    },
    /// Read this service's counters over the authenticated
    /// `server/metrics/0.1` Trust Task and print them as JSON.
    ///
    /// The counters live in the running service's process memory and are
    /// reachable only through this signed task — there is no unauthenticated
    /// scrape endpoint. Signs with the `--key` did:key (granted `MetricsReader`
    /// in the ACL) and POSTs to the running service's `POST /api/trust-tasks`.
    /// Only `counters` are returned (gauges require Admin and are omitted).
    /// Prints the counters as JSON on stdout, ready to pipe into a monitoring
    /// agent.
    ///
    /// Counter instrumentation is opt-in: the `webvh_*` counters are populated
    /// only in a build with the `metrics` feature; against one without it this
    /// prints an empty array `[]`. A genuine refusal (an ungranted or revoked
    /// key) is reported as an error rather than an empty array.
    FetchMetrics {
        /// Path to the signer's did:key JSON file — the MetricsReader key,
        /// same format `setup --setup-key-out` writes.
        #[arg(long)]
        key: PathBuf,
        /// Base URL of the running service. Defaults to
        /// `http://<server.host>:<server.port>` from config (a wildcard bind
        /// such as `0.0.0.0` / `::` is dialled as loopback).
        #[arg(long)]
        url: Option<String>,
    },
    /// Send one signed Trust Task to the running service and print the
    /// response payload as JSON.
    ///
    /// Every management operation is a Trust Task (docs/trust-tasks.md lists
    /// them). Signs the request with the `--key` did:key, POSTs it to the
    /// running service's `POST /api/trust-tasks`, verifies the reply is the
    /// service's own signed response, and prints its payload. The key is
    /// authorised like any other client: by its proof and its ACL entry (add it
    /// with `add-acl`). A refusal is reported as an error with its code.
    SendTrustTask {
        /// Path to the signer's did:key JSON file — same format
        /// `setup --setup-key-out` writes.
        #[arg(long)]
        key: PathBuf,
        /// The task: a full Type URI, or `<slug>/<version>` such as
        /// `identity/list/0.1` or `did-management/registry/list/0.2`.
        #[arg(long = "type", value_name = "TYPE")]
        task_type: String,
        /// The request payload as JSON (default `{}`).
        #[arg(long, conflicts_with = "payload_file")]
        payload: Option<String>,
        /// Read the request payload from a JSON file.
        #[arg(long)]
        payload_file: Option<PathBuf>,
        /// Base URL of the running service. Defaults to
        /// `http://<server.host>:<server.port>` from config (a wildcard bind is
        /// dialled as loopback).
        #[arg(long)]
        url: Option<String>,
    },
}

impl AdminCommand {
    /// Run the command against the configuration `load` returns.
    pub async fn run<C: ServiceConfig>(self, load: Loader<'_, C>) -> CliResult {
        use did_hosting_common::server::cli_acl;
        let config = load()?;
        match self {
            Self::AddAcl {
                did,
                role,
                label,
                witness,
            } => {
                let store = if witness {
                    // Only these do anything on a witness.
                    if !matches!(role.as_str(), "admin" | "service") {
                        return Err(format!(
                            "a witness ACL entry's role is `admin` or `service`, not '{role}'"
                        )
                        .into());
                    }
                    witness_store(&config)?
                } else {
                    config.store()
                };
                cli_acl::run_add_acl(store, did, role, label, None, None).await
            }
            Self::ListAcl { witness } => {
                let store = if witness {
                    witness_store(&config)?
                } else {
                    config.store()
                };
                cli_acl::run_list_acl(store).await
            }
            Self::RemoveAcl { did } => cli_acl::run_remove_acl(config.store(), did).await,
            Self::Invite {
                did,
                role,
                ttl_hours,
            } => invite(&config, &did, &role, ttl_hours).await,
            Self::FetchMetrics { key, url } => {
                let to = config.server_did().ok_or(
                    "server_did is not configured; this service has not completed provisioning",
                )?;
                did_hosting_common::server::cli_metrics::fetch_metrics(
                    to,
                    key.as_path(),
                    url,
                    &config.server().host,
                    config.server().port,
                )
                .await
            }
            Self::SendTrustTask {
                key,
                task_type,
                payload,
                payload_file,
                url,
            } => {
                let to = config.server_did().ok_or(
                    "server_did is not configured; this service has not completed provisioning",
                )?;
                did_hosting_common::server::cli_trust_task::run_send_trust_task(
                    to,
                    key.as_path(),
                    url,
                    &config.server().host,
                    config.server().port,
                    &task_type,
                    payload.as_deref(),
                    payload_file.as_deref(),
                )
                .await
            }
        }
    }
}

/// The embedded witness's store, or a refusal naming why there is none.
fn witness_store<C: ServiceConfig>(config: &C) -> Result<&StoreConfig, Box<dyn std::error::Error>> {
    config
        .witness_store()
        .ok_or_else(|| "--witness applies only to did-hosting-daemon's embedded witness".into())
}

async fn invite<C: ServiceConfig>(
    config: &C,
    did: &str,
    role: &str,
    ttl_hours: Option<u64>,
) -> CliResult {
    use did_hosting_common::server::store::{KS_SESSIONS, Store};

    let base_url = config
        .public_url()
        .ok_or("public_url must be set in config for enrollment invites")?;

    let enrollment_ttl = match ttl_hours {
        Some(hours) => hours * 3600,
        None => config.auth().passkey_enrollment_ttl,
    };

    let store = Store::open(config.store()).await?;
    let sessions_ks = store.keyspace(KS_SESSIONS)?;

    did_hosting_common::server::passkey::run_cli_invite(
        &sessions_ks,
        base_url,
        enrollment_ttl,
        did,
        role,
        config.auth().claim_code_hash_wait(),
    )
    .await?;

    Ok(())
}

/// What the statistics commands read beyond [`ServiceConfig`].
pub trait StatsSettings: ServiceConfig {
    /// `[stats_flush]`.
    fn stats_flush(&self) -> &StatsFlushConfig;
    /// `[stats]`.
    fn stats_tiers(&self) -> &StatsTierConfig;
}

/// Per-DID statistics settings, offline: the service must be stopped.
#[derive(Debug, Subcommand)]
pub enum StatsCommand {
    /// Show a DID's statistics resolution, recorded tier and totals
    /// (offline; stop the service first).
    StatsShow {
        /// The DID's path (mnemonic), e.g. ".well-known" or "my-org".
        #[arg(long, visible_alias = "path")]
        mnemonic: String,
    },
    /// Set a DID's statistics resolution (offline; stop the service first):
    /// `auto` (by traffic), `fine` (always 5-minute detail), `coarse` (never
    /// promoted) or `off` (totals only). Applied at the next start.
    StatsSet {
        /// The DID's path (mnemonic), e.g. ".well-known" or "my-org".
        #[arg(long, visible_alias = "path")]
        mnemonic: String,
        /// auto, fine, coarse or off.
        #[arg(long, value_parser = ["auto", "fine", "coarse", "off"])]
        resolution: String,
    },
    /// Finish the move to tiered statistics and delete the legacy time-series
    /// rows now, instead of 30 days after the migration (offline; stop the
    /// service first). An older version rolled back to afterwards has no
    /// time-series history.
    StatsPurgeLegacy,
}

impl StatsCommand {
    /// Run the command against the configuration `load` returns.
    pub async fn run<C: StatsSettings>(self, load: Loader<'_, C>) -> CliResult {
        use crate::stats_cli;
        let config = load()?;
        match self {
            Self::StatsShow { mnemonic } => {
                stats_cli::run_stats_show(config.store(), &mnemonic).await
            }
            Self::StatsSet {
                mnemonic,
                resolution,
            } => stats_cli::run_stats_set(config.store(), &mnemonic, &resolution).await,
            Self::StatsPurgeLegacy => {
                stats_cli::run_stats_purge_legacy(
                    config.store(),
                    config.stats_flush(),
                    config.stats_tiers(),
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--witness` names a store only a daemon has; any other binary refuses
    /// it rather than acting on its own ACL.
    #[tokio::test]
    async fn witness_acl_commands_are_refused_without_a_witness() {
        let dir = tempfile::tempdir().unwrap();
        let config: AppConfig = toml::from_str(&format!(
            "[store]\ndata_dir = \"{}\"\n",
            dir.path().display()
        ))
        .expect("config parses");
        let err = AdminCommand::ListAcl { witness: true }
            .run(Box::new(move || Ok(config)))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did-hosting-daemon"), "{err}");
    }
}

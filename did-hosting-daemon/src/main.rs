//! `did-hosting-daemon`: the server, control plane, witness and watcher in
//! one process, sharing one store (the witness keeps its own), one storage
//! task and one HTTP listener.
//! See the "did-hosting-daemon" section of the repository's `CLAUDE.md` for
//! what it mirrors from the standalone services and what it omits.

mod backup;
mod config;
mod setup;
mod setup_recipe;

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::handler::Handler;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use clap::{Parser, Subcommand};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, error, info, warn};

use did_hosting_common::server::cli;
use did_hosting_common::server::config::init_tracing;
use did_hosting_common::server::error::AppError;
use did_hosting_common::server::identity::ServiceIdentity;
use did_hosting_common::server::init;
use did_hosting_common::server::secret_store::ServerSecrets;
use did_hosting_common::server::stats_collector::StatsCollector;
use did_hosting_common::server::store::{KeyspaceHandle, Store};
use did_hosting_common::server::supervise::{
    PeriodicTask, SHUTDOWN_STAGE_DEADLINE, Stage, Supervisor, merge_tasks, run_periodic,
};
use did_hosting_server::server::FirstBoot;

use config::DaemonConfig;
use did_hosting_common::server::store::{KS_DIDS, KS_SESSIONS, KS_STATS, KS_TIMESERIES};

// ─── Allocator ──────────────────────────────────────────────────────────────
//
// Set on the binary only. A library that installs a #[global_allocator] forces
// it on every consumer, so this deliberately does not live in lib.rs.
//
// Why not the system allocator: the daemon churns short-lived buffers (Trust
// Task envelopes, DID logs being verified and served, UI and API responses,
// store batches). glibc malloc keeps those arenas rather than returning them,
// so RSS ratchets to the high-water mark and never falls back —
// indistinguishable from a leak on a memory graph.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read by jemalloc itself at startup via this well-known symbol.
///
/// `background_thread:true` runs the purger off the request path.
/// `dirty_decay_ms` / `muzzy_decay_ms` are how long freed pages linger before
/// being returned to the OS; jemalloc's defaults (10s / 10s) are tuned for
/// throughput on allocation-heavy workloads, and hold RSS well above the live
/// heap. 5s keeps the memory graph honest at a negligible cost here, because
/// the service's hot path is I/O-bound, not allocation-bound.
///
/// Raise these (or drop the `jemalloc` feature) if you are optimising for
/// allocation throughput over resident footprint.
///
/// The symbol must be `_rjem_malloc_conf`, not the `malloc_conf` jemalloc
/// documents: tikv-jemalloc-sys (default features) builds jemalloc with
/// `--with-jemalloc-prefix=_rjem_`, which prefixes every public symbol,
/// including the one it reads its configuration from. An unprefixed
/// `malloc_conf` would compile and link fine and be silently ignored.
///
/// SAFETY: exporting a symbol is unsafe because it could clash with another
/// definition of the same name. `_rjem_malloc_conf` is the (prefixed) name
/// jemalloc reads for exactly this, it is defined once (in the binary, never
/// the library), and the value is the NUL-terminated static string jemalloc
/// expects. This is the one `unsafe` outside tests (CONTRIBUTING rule 6),
/// signed off in the PR that added it.
///
/// The type is `&[u8; 63]`, a reference to a fixed-size array: a thin pointer,
/// which is what jemalloc's `const char *malloc_conf` is. A `&[u8]` slice
/// reference is a two-word fat pointer (address + length), which matches
/// `const char *` only by the accident of field order.
#[cfg(all(feature = "jemalloc", not(target_env = "msvc")))]
#[allow(unsafe_code)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8; 63] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000\0";

#[derive(Parser)]
#[command(
    name = "did-hosting-daemon",
    about = "DID Hosting Daemon — Unified Service",
    version
)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

/// The daemon's subcommands: its own, then every group the standalone
/// binaries share, flattened in. A test (`cli_parity_tests`) checks they
/// cover `did-hosting-server`'s and `did-hosting-control`'s.
#[derive(Subcommand)]
enum Command {
    /// Run interactive setup wizard to generate config.toml.
    ///
    /// Headless mode (for CI / scripted setup):
    ///
    /// 1. Run with `--setup-key-out <path> --context <id>` to mint an
    ///    ephemeral did:key, persist it (chmod 0600), and print the
    ///    `pnm contexts create` command the operator runs to enrol the
    ///    setup DID in the VTA. Exits without touching anything else.
    /// 2. Run again with `--setup-key-file <path>` to drive the rest of
    ///    the wizard reusing the persisted setup DID — skips the
    ///    interactive ACL-ready confirmation.
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
        /// Path to a declarative setup recipe TOML. Drives setup
        /// non-interactively. The daemon recipe also supports
        /// `vta_mode = "self-managed"` for no-VTA deployments. See
        /// `examples/did-hosting-daemon-build.toml`.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Refuse to run when an existing setup is detected, unless set.
        /// Exit 4 protects issued JWTs / active VTA sessions.
        #[arg(long)]
        force_reprovision: bool,
        /// Explicit "no TTY available" flag. Requires `--from`.
        #[arg(long, requires = "from")]
        non_interactive: bool,
    },
    /// Teardown a daemon install: clears managed secrets and removes
    /// the config file (+ `.bak`, + companion DID-log files).
    Uninstall {
        /// Skip the typed "DELETE" confirmation prompt. CI use only.
        #[arg(long)]
        yes: bool,
    },
    /// Step 1/2 of the offline (air-gapped VTA) setup wizard.
    ///
    /// The ephemeral bootstrap seed is persisted to the configured
    /// secrets backend (keyring / AWS / GCP / plaintext-in-config) —
    /// not to a file.
    SetupOfflinePrepare {
        /// Path for the bootstrap-request.json file.
        #[arg(long, default_value = "bootstrap-request.json")]
        request: PathBuf,
        /// Path for the pending state file (plain TOML, no secrets).
        #[arg(long, default_value = "setup-offline-state.toml")]
        state: PathBuf,
    },
    /// Step 2/2 of the offline setup wizard.
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
    /// Run health check diagnostics. Exits non-zero when a check fails (or,
    /// with --strict, warns), so it can gate a deploy or a container probe.
    Health {
        /// Also exit non-zero when a check only warned (a store held by the
        /// running service, plaintext secrets, a non-2xx reachability probe).
        #[arg(long)]
        strict: bool,
    },
    /// Clear the embedded witness's key-encryption-key creation claim left
    /// by a start that stopped while creating the key (`[witness_store]`).
    /// Refused once a key is held or recorded.
    ResetWitnessKekClaim,
    /// Export the daemon's data to a backup file: both stores (`[store]`,
    /// with the ACL, passkeys, identity generations and outbound queue, and
    /// `[witness_store]`) and the configuration file, verbatim.
    Backup {
        /// Output file path (use "-" for stdout)
        #[arg(short, long, default_value = "did-hosting-backup.json")]
        output: String,
    },
    /// Restore the daemon's data from a `did-hosting-daemon backup` file.
    ///
    /// The backup is checked before anything is written, config.toml
    /// included (it is written back verbatim). Each did:webvh (or did:webs)
    /// log must verify, match its
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
    #[command(flatten)]
    Admin(did_hosting_control::cli::AdminCommand),
    #[command(flatten)]
    Stats(did_hosting_control::cli::StatsCommand),
    #[command(flatten)]
    Identity(cli::IdentityCommand),
    #[command(flatten)]
    Tsp(cli::TspCommand),
    #[command(flatten)]
    Did(did_hosting_server::cli::DidCommand),
    #[command(flatten)]
    Keys(cli::KeysCommand),
    #[command(flatten)]
    Vta(cli::VtaCommand),
}

const SERVICE: cli::Service = cli::Service::Daemon;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    let config_path = cli.config;
    let load = || -> cli::Loader<'static, DaemonConfig> {
        let path = config_path.clone();
        Box::new(move || Ok(DaemonConfig::load(path)?))
    };

    match cli.command {
        Some(Command::Setup {
            setup_key_out,
            setup_key_file,
            context,
            from,
            force_reprovision,
            non_interactive: _,
        }) => {
            if let Some(path) = setup_key_out {
                cli::exit_on_error(
                    "Setup error",
                    setup::run_setup_phase1(&path, &context).await,
                );
            } else if let Some(recipe_path) = from {
                if let Err(e) =
                    setup_recipe::run_from_recipe(&recipe_path, setup_key_file, force_reprovision)
                        .await
                {
                    eprintln!("Setup error: {e}");
                    std::process::exit(setup_recipe::map_exit_code(&e));
                }
            } else {
                cli::exit_on_error(
                    "Setup error",
                    setup::run_wizard(config_path.clone(), setup_key_file).await,
                );
            }
        }
        Some(Command::Uninstall { yes }) => {
            let config_path = config_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("config.toml"));
            cli::exit_on_error(
                "Uninstall error",
                setup_recipe::run_uninstall(&config_path, yes).await,
            );
        }
        Some(Command::SetupOfflinePrepare { request, state }) => cli::exit_on_error(
            "Setup error",
            setup::run_setup_offline_prepare(config_path.clone(), request, state).await,
        ),
        Some(Command::SetupOfflineComplete {
            bundle,
            expect_digest,
            state,
        }) => cli::exit_on_error(
            "Setup error",
            setup::run_setup_offline_complete(bundle, expect_digest, state).await,
        ),
        Some(Command::Health { strict }) => {
            let code = did_hosting_common::server::health::finish(
                run_health(config_path.clone()).await,
                strict,
            );
            std::process::exit(code);
        }
        Some(Command::ResetWitnessKekClaim) => cli::exit_on_error(
            "Error",
            run_reset_witness_kek_claim(config_path.clone()).await,
        ),
        Some(Command::Backup { output }) => cli::exit_on_error(
            "Backup error",
            backup::run_backup(config_path.clone(), output).await,
        ),
        Some(Command::Restore { input }) => cli::exit_on_error(
            "Restore error",
            backup::run_restore(config_path.clone(), input).await,
        ),
        Some(Command::Admin(cmd)) => cli::exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Stats(cmd)) => cli::exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Identity(cmd)) => cli::exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Tsp(cmd)) => cli::exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Did(cmd)) => {
            cli::exit_on_error("Error", cmd.run(SERVICE.binary(), load()).await)
        }
        Some(Command::Keys(cmd)) => cli::exit_on_error("Error", cmd.run(SERVICE, load()).await),
        Some(Command::Vta(cmd)) => cli::exit_on_error("Error", cmd.run(SERVICE).await),
        None => {
            if let Err(e) = run_daemon(config_path).await {
                error!("daemon error: {e}");
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

// ===========================================================================
// Daemon lifecycle
// ===========================================================================

/// The standalone services' background tasks the daemon deliberately does not
/// run, by name (CLAUDE.md, "What the daemon intentionally does NOT
/// mirror"). Every other task of `did-hosting-server` and
/// `did-hosting-control` runs here, built by the same functions the
/// standalone binaries use; `task_parity_tests` checks that each one is
/// either run or named here.
const DAEMON_SKIPPED_TASKS: [&str; 7] = [
    // The daemon is its own control plane: it registers nowhere…
    did_hosting_server::server::tasks::KEEP_REGISTERED,
    // …reconciles with no one (the embedded server reads the control
    // plane's own store)…
    did_hosting_server::server::tasks::REPLICATION_RECONCILE,
    // …and has no remote control plane to keep a TSP relationship with.
    did_hosting_server::server::tasks::CONTROL_TSP_RELATIONSHIP,
    // Statistics are shared in-process (`Arc<StatsCollector>`).
    did_hosting_server::server::tasks::STATS_SYNC,
    // The daemon's identity is the control plane's: the embedded server runs
    // no listener, so its rotation path is inert by construction.
    did_hosting_server::server::tasks::IDENTITY_SWEEP,
    // The registry is empty in a default daemon deployment.
    did_hosting_control::server::tasks::REGISTRY_HEALTH_CHECK,
    // Superseded by the server's `purge-sweep`, which deletes a disabled
    // domain's record as well as its DIDs, under the control plane's locks.
    did_hosting_control::server::tasks::DOMAIN_PURGE_SWEEP,
];

async fn run_daemon(config_path: Option<PathBuf>) -> Result<(), AppError> {
    let mut config = match DaemonConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Create a config.toml or specify one:");
            eprintln!("  did-hosting-daemon --config <path>");
            std::process::exit(1);
        }
    };

    init_tracing(&config.log);

    // Load secrets (shared across server, witness, control)
    let secrets = load_secrets(&config).await;

    // ── Open stores ───────────────────────────────────────────────────
    // fjall locks the directory, so server/watcher/control share one handle.
    let main_store = Store::open_with(&config.store, &config.fjall)
        .await
        .map_err(|e| AppError::Internal(format!("failed to open main store: {e}")))?;
    let witness_store = Store::open_with(&config.witness_store, &config.fjall)
        .await
        .map_err(|e| AppError::Internal(format!("failed to open witness store: {e}")))?;

    // The embedded witness keeps its own ACL only if its store is its own.
    // Found by trying it, so any spelling of the same data is caught.
    if config.enable.witness {
        match config::witness_store_shares_main_data(&main_store, &witness_store).await {
            Ok(false) => {}
            Ok(true) => return Err(AppError::Config(config::shared_witness_store_refusal())),
            Err(e) => {
                return Err(AppError::Internal(format!(
                    "could not check that [witness_store] is separate from [store]: {e}"
                )));
            }
        }
    }

    // Open keyspaces early — needed for bootstrap, stats seeding, and builders.
    // Strongly consistent: the storage task's DID cleanup re-reads a record
    // to decide whether to delete it. Resolution does not use this handle.
    let dids_ks = main_store.keyspace_consistent(KS_DIDS)?;
    let stats_ks = main_store.keyspace(KS_STATS)?;
    let timeseries_ks = main_store.keyspace(KS_TIMESERIES)?;

    // ── Phase 1: Pre-serve initialization (shared with the standalone
    //    services) ─────────────────────────────────────────────────────

    // 1a. First-boot domain and assignment seed, then the control plane's
    // migrations — the edge's `run_first_boot_init`, strict: the daemon owns
    // the control plane, whose write paths need the domain catalogue.
    did_hosting_server::server::run_first_boot_init(
        &main_store,
        &config.server_config(),
        did_hosting_common::server::migrations::control_plane_registry(),
        FirstBoot::Strict,
    )
    .await?;

    if config.enable.server {
        // 1b. DID store integrity check
        did_hosting_server::server::check_store_integrity(&dids_ks).await;

        // 1c. Report the root DID (if server enabled and public_url set)
        let bootstrapped = did_hosting_server::server::auto_bootstrap_dids(
            "did-hosting-daemon",
            config.server_config(),
            &main_store,
            &dids_ks,
            &secrets,
        )
        .await;
        // Propagate server_did if it was set by auto-bootstrap
        if config.server_did.is_none() && bootstrapped.server_did.is_some() {
            config.server_did = bootstrapped.server_did;
        }
    }

    // 1d. Seed stats collector from persisted store: the aggregate, the DID
    // count and the per-DID statistics overrides; then the `[stats]` policy.
    let stats_collector = {
        let collector = StatsCollector::new();
        let agg = did_hosting_common::server::stats_collector::seed_from_store(
            &collector, &stats_ks, &dids_ks,
        )
        .await;
        collector.configure_tiers(config.stats);
        info!(
            total_dids = agg.total_dids,
            total_resolves = agg.total_resolves,
            total_updates = agg.total_updates,
            "stats collector seeded from store"
        );
        Arc::new(collector)
    };

    // ── Phase 1.5: Load the daemon's own identity ─────────────────────
    //
    // One identity, shared by every embedded service: one DID resolver and
    // one secrets resolver, rather than a copy of the key material per
    // service for a rotation to keep in step.
    //
    // Loaded after `auto_bootstrap_dids`, which may have backfilled
    // `server_did` — resolving before that would find nothing.
    //
    // The protocol set is the control plane's: in daemon mode the control
    // plane owns the only DIDComm listener (see CLAUDE.md — the embedded
    // server does not run its own).
    let identity = did_hosting_common::server::identity::load_identity(
        config.server_did.as_deref(),
        config.mediator_did.as_deref(),
        did_hosting_common::server::identity::ProtocolSet {
            didcomm: config.features.didcomm,
            tsp: config.features.tsp,
        },
        &secrets,
        &main_store,
    )
    .await;

    // ── Phase 2: Build service routers ────────────────────────────────

    let mut sup = Supervisor::new("did-hosting-daemon");
    let mut signal = std::pin::pin!(init::shutdown_signal());

    let mut combined: Router = Router::new();
    let mut server_state: Option<did_hosting_server::server::AppState> = None;

    let mut enabled_services = Vec::new();

    // One per-address resolution limit for the whole process, so a client's
    // budget covers the server's routes, the DID-serving fallback and the
    // watcher's routes together.
    //
    // One client-address rule for the whole process too, shared by that limit
    // and every handler that charges a client address, so a proxy's invalid
    // chain is logged once a minute whichever path met it.
    let client_ips =
        did_hosting_common::server::rate_limit::ClientIps::from_server_config(&config.server)?;
    let resolve_limit = Arc::new(
        did_hosting_common::server::rate_limit::ResolveRateLimiter::new(
            &config.server,
            &client_ips,
        ),
    );
    // Sweeps idle clients out of every rate limiter the daemon serves, until
    // the HTTP server stops.
    let rate_limit_gc = sup.signal(Stage::Listeners).token();
    resolve_limit.spawn_gc(rate_limit_gc.clone());

    // 2a. Server — public DID-serving routes only (.well-known)
    if config.enable.server {
        let (router, state) = build_server(
            &config,
            &main_store,
            &stats_collector,
            identity.clone(),
            resolve_limit.clone(),
        )
        .await
        .map_err(|e| AppError::Internal(format!("failed to initialize server: {e}")))?;
        combined = combined.merge(router);
        server_state = Some(state);
        enabled_services.push("server (/)");
    }

    // 2b. Witness (nested at /witness)
    if config.enable.witness {
        let router = build_witness(
            &config,
            &witness_store,
            identity.clone(),
            &client_ips,
            &rate_limit_gc,
        )
        .await
        .map_err(|e| AppError::Internal(format!("failed to initialize witness: {e}")))?;
        combined = combined.nest("/witness", router);
        enabled_services.push("witness (/witness)");
    }

    // 2c. Watcher (nested at /watcher)
    if config.enable.watcher {
        let router = build_watcher(&config, &main_store, resolve_limit.clone())
            .await
            .map_err(|e| AppError::Internal(format!("failed to initialize watcher: {e}")))?;
        combined = combined.nest("/watcher", router);
        enabled_services.push("watcher (/watcher)");
    }

    // 2d. Control plane — merged at root (no prefix)
    let mut control_state: Option<did_hosting_control::server::AppState> = None;
    if config.enable.control {
        let (router, state) = build_control(
            &config,
            &secrets,
            &main_store,
            &stats_collector,
            identity.clone(),
            server_state.as_ref(),
            &client_ips,
        )
        .await
        .map_err(|e| AppError::Internal(format!("failed to initialize control plane: {e}")))?;
        combined = combined.merge(router);
        state.spawn_rate_limit_gc(&sup.signal(Stage::Workers).token());
        control_state = Some(state);
        enabled_services.push("control (/)");
    }

    // Combined fallback: try DID public serving first, then the SPA UI.
    combined = match server_state {
        Some(ref state) => {
            // DID resolution and the console's pages are charged to the
            // public resolution rate limit…
            let limited = {
                let state = state.clone();
                move |request: axum::extract::Request| {
                    let state = state.clone();
                    async move { daemon_fallback(state, request).await }
                }
            }
            .layer(resolve_limit.layer());
            // …but a file of the console's bundle is not: it is served from
            // memory, touches no store, and a page load fetches dozens of
            // them. No DID artifact shares a name with one (the bundle holds
            // `_expo/static/…`, `assets/…` and the like), so resolution never
            // takes this path.
            #[cfg(feature = "ui")]
            let ui = did_hosting_control::frontend::static_service();
            combined.fallback(move |request: axum::extract::Request| {
                let limited = limited.clone();
                #[cfg(feature = "ui")]
                let ui = ui.clone();
                async move {
                    #[cfg(feature = "ui")]
                    if did_hosting_control::frontend::is_embedded_asset(request.uri().path()) {
                        use tower::ServiceExt;
                        return match ui.oneshot(request).await {
                            Ok(response) => axum::response::IntoResponse::into_response(response),
                            Err(never) => match never {},
                        };
                    }
                    axum::handler::Handler::call(limited, request, ()).await
                }
            })
        }
        None => {
            #[cfg(feature = "ui")]
            {
                combined.fallback_service(did_hosting_control::frontend::static_service())
            }
            #[cfg(not(feature = "ui"))]
            {
                combined
            }
        }
    };

    // Apply tracing layer, then add health route *after* so it's not traced
    let health_ks = dids_ks.clone();
    let health_did = config.server_did.clone();
    let app = combined
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::DEBUG)
                        .latency_unit(tower_http::LatencyUnit::Millis),
                ),
        )
        // The same response headers every standalone service sets (CSP,
        // `nosniff`, framing, HSTS, `no-store` unless the handler chose its
        // own `Cache-Control`), over everything the daemon serves: the
        // console and its assets, the Trust Task listener, the embedded
        // witness and watcher, and DID resolution, whose handlers set
        // `Cache-Control: public, …` themselves and keep it.
        .layer(axum::middleware::from_fn(
            did_hosting_common::server::security_headers,
        ))
        // Allow browser-based resolvers to fetch public DID documents
        // cross-origin. Read-only, unauthenticated, wildcard origin.
        .layer(did_hosting_common::server::public_resolution_cors())
        .route(
            "/health",
            get(move || {
                let (ks, did) = (health_ks.clone(), health_did.clone());
                async move { daemon_health(&ks, did.as_deref()).await }
            }),
        );

    // Log startup summary
    info!("--- daemon services ---");
    for svc in &enabled_services {
        info!("  {svc}");
    }

    // ── Phase 3: Background tasks ─────────────────────────────────────

    // 3a. The storage task: the server's and the control plane's storage
    // ticks, merged (session cleanup, DID cleanup, stats flush, DID recount,
    // purge sweep), then the last flush and the persist. Critical: it is
    // what persists the store, and it is stopped last.
    let storage = DaemonStorageParams {
        store: main_store.clone(),
        edge: did_hosting_server::server::EdgeStorage {
            store: main_store.clone(),
            dids_ks: dids_ks.clone(),
            did_ttl_seconds: config.auth.cleanup_ttl_minutes * 60,
            collector: stats_collector.clone(),
            caches: server_state
                .as_ref()
                .map(|s| s.resolution_caches())
                .unwrap_or_else(|| did_hosting_server::cache::ResolutionCaches {
                    content: Arc::new(did_hosting_server::cache::ContentCache::new(
                        did_hosting_server::cache::RESOLUTION_CACHE_TTL,
                    )),
                    gate: None,
                }),
            // The control plane publishes into slots under its path locks;
            // the cleanup and the purge take the same lock before deleting.
            path_locks: control_state.as_ref().map(|s| s.path_locks.clone()),
            on_removed: Some(removed_dids_stats_hook(
                stats_collector.clone(),
                stats_ks.clone(),
                timeseries_ks.clone(),
            )),
        },
        control: did_hosting_control::server::ControlStorage {
            sessions_ks: main_store.keyspace(KS_SESSIONS)?,
            stats_ks,
            timeseries_ks,
            dids_ks: dids_ks.clone(),
            auth: config.auth.clone(),
            has_auth: config.server_did.is_some(),
            collector: stats_collector.clone(),
            stats_flush: config.stats_flush,
        },
    };
    sup.spawn_critical(Stage::Storage, "daemon-storage", move |sd| {
        run_daemon_storage_task(storage, sd.watch())
    });

    // ── Phase 4: Serve HTTP (must start before DIDComm so self-hosted
    //    DIDs are resolvable when the mediator connection is established) ──

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| AppError::Internal(format!("failed to bind {addr}: {e}")))?;
    info!("daemon listening on {addr}");

    // Critical: it owns the listening socket, and a daemon that cannot serve
    // HTTP serves nothing. Stopped (gracefully, within the shutdown
    // deadline) after the workers.
    let (http_ready_tx, http_ready_rx) = tokio::sync::oneshot::channel::<()>();
    let trusted_proxies = config.server.trusted_proxies.clone();
    sup.spawn_critical(Stage::Listeners, "daemon-http", move |sd| async move {
        let _ = http_ready_tx.send(());
        // Header, idle, connection and per-address limits: see `listener`.
        if let Err(e) = axum::serve(
            did_hosting_common::server::listener::bounded(listener, &trusted_proxies),
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { sd.stopped().await })
        .await
        {
            error!("HTTP server failed: {e}");
        }
    });

    // Wait for HTTP to be serving before starting DIDComm — the mediator DID
    // may be hosted by this daemon and needs to be resolvable.
    let _ = http_ready_rx.await;

    let mut interrupted = false;
    if let Some(ref state) = control_state {
        // 4a. The daemon's *own* DID is hosted by the daemon, so it was not
        // resolvable when the identity was loaded — `load_identity` came up
        // on guessed `#key-0`/`#key-1` kids and deliberately persisted
        // nothing. This is the first moment the document is fetchable, so it
        // is where generation 0 is recorded with the kids the document
        // actually uses. Must run before the DIDComm listener starts, or its
        // profile would be built on the guess.
        if let Err(e) = did_hosting_control::identity_rotation::reload_now(state).await {
            warn!("failed to establish the service identity from its DID document: {e}");
        }

        // 4b. The control plane's workers — the outbox and its periodic
        // tasks, less the daemon's skip list. The same function the
        // standalone control plane starts them with.
        did_hosting_control::server::spawn_workers(state, &mut sup, &DAEMON_SKIPPED_TASKS);

        // 4c. The messaging service (DIDComm and/or TSP, for VTA integration
        // via the control plane), retried with backoff while it fails. Stored
        // in the control state so server_push and handlers can send through
        // the same connection. TSP-only deployments must still start it.
        if config.features.didcomm || config.features.tsp {
            info!(
                server_did = ?state.config.server_did,
                mediator_did = ?state.config.mediator_did,
                "starting control plane DIDComm service"
            );
            tokio::select! {
                svc = did_hosting_control::server::start_messaging(
                    state,
                    sup.signal(Stage::Workers).token(),
                ) => match svc {
                    Some(svc) => {
                        info!("DIDComm service started successfully");
                        let _ = state.didcomm_service.set(svc);
                    }
                    None => warn!(
                        "no DIDComm service — check server_did and mediator_did config"
                    ),
                },
                _ = &mut signal => interrupted = true,
            }
        } else {
            info!("DIDComm disabled in config");
        }

        // 4d. Post-listener startup shared with the standalone control plane —
        // notably resuming any old-mediator drain a previous process left
        // running.
        did_hosting_control::server::post_listener_startup(state);
    } else if config.features.didcomm || config.features.tsp {
        warn!("DIDComm enabled but control plane not enabled — skipping");
    }

    // Run until the shutdown signal, or until a critical task stops.
    let outcome = if interrupted {
        Ok(())
    } else {
        sup.run_until(&mut signal).await
    };

    // ── Phase 5: Ordered shutdown ─────────────────────────────────────
    //
    // Workers, then the messaging service (awaited), then HTTP, then
    // storage (the last flush and the persist of the main store), each
    // within `SHUTDOWN_STAGE_DEADLINE` — the control plane's own sequence.
    let stopped = match control_state {
        Some(ref state) => did_hosting_control::server::shutdown(state, sup).await,
        None => sup
            .finish(SHUTDOWN_STAGE_DEADLINE)
            .await
            .map_err(|failures| AppError::Internal(format!("{} task(s) failed", failures.len()))),
    };

    // 5b. Persist witness store (not managed by the storage task)
    if let Err(e) = witness_store.persist().await {
        error!("failed to persist witness store: {e}");
    }

    if let Err(failure) = outcome {
        return Err(AppError::Internal(format!("shut down because {failure}")));
    }
    stopped?;
    info!("daemon shut down");
    Ok(())
}

// ===========================================================================
// Unified storage task
// ===========================================================================

/// What the daemon's storage task works on: the server's storage and the
/// control plane's, over the one store.
struct DaemonStorageParams {
    store: Store,
    edge: did_hosting_server::server::EdgeStorage,
    control: did_hosting_control::server::ControlStorage,
}

/// The daemon's storage ticks: the edge's ([`did_hosting_server::server::storage_tasks`])
/// and the control plane's ([`did_hosting_control::server::storage_tasks`]),
/// merged — a tick both run (the DID recount) runs once — less the skip list.
fn daemon_storage_tasks(
    edge: &did_hosting_server::server::EdgeStorage,
    control: &did_hosting_control::server::ControlStorage,
) -> Vec<PeriodicTask> {
    merge_tasks(
        [
            did_hosting_server::server::storage_tasks(edge),
            did_hosting_control::server::storage_tasks(control),
        ],
        &DAEMON_SKIPPED_TASKS,
    )
}

/// Delete the statistics of DIDs the empty-slot cleanup or the domain purge
/// removed. Neither knows about statistics (on an edge there are none); the
/// daemon holds them in the same store, and an explicit delete already
/// clears them (`stats_admin::delete_did_stats`). Runs on the storage task,
/// between flushes, so no flush is writing these rows meanwhile.
fn removed_dids_stats_hook(
    collector: Arc<StatsCollector>,
    stats_ks: KeyspaceHandle,
    timeseries_ks: KeyspaceHandle,
) -> did_hosting_server::server::RemovedDidsHook {
    Arc::new(move |mnemonics: Vec<String>| {
        let (collector, stats_ks, timeseries_ks) =
            (collector.clone(), stats_ks.clone(), timeseries_ks.clone());
        Box::pin(async move {
            for mnemonic in &mnemonics {
                if let Err(e) = did_hosting_common::server::stats_collector::delete_did_stats(
                    &collector,
                    &stats_ks,
                    &timeseries_ks,
                    mnemonic,
                )
                .await
                {
                    warn!(mnemonic, error = %e, "could not delete a removed DID's statistics rows");
                }
            }
        })
    })
}

/// The storage ticks until shutdown, then the last statistics flush and the
/// main store's persist. Storage is the last stage stopped, so both see
/// every write — the outbox's included.
async fn run_daemon_storage_task(params: DaemonStorageParams, shutdown: watch::Receiver<bool>) {
    info!("storage task started");
    run_periodic(
        daemon_storage_tasks(&params.edge, &params.control),
        shutdown,
    )
    .await;
    info!("storage task shutting down");

    params.control.final_flush().await;
    if let Err(e) = params.store.persist().await {
        error!("failed to persist main store on shutdown: {e}");
    } else {
        info!("main store persisted");
    }
}

// ===========================================================================
// Service builders
// ===========================================================================

type ServiceResult = Result<Router, AppError>;

/// Build the server — returns both the router and the AppState.
///
/// In daemon mode the server only exposes public DID resolution. There are
/// no management routes: every management operation is a Trust Task served
/// by the control plane's listener (`POST /api/trust-tasks`, DIDComm,
/// TSP), merged at root with `/api/health` and the UI.
async fn build_server(
    config: &DaemonConfig,
    store: &Store,
    stats_collector: &Arc<StatsCollector>,
    identity: Option<Arc<ServiceIdentity>>,
    resolve_limit: Arc<did_hosting_common::server::rate_limit::ResolveRateLimiter>,
) -> Result<(Router, did_hosting_server::server::AppState), AppError> {
    use did_hosting_server::server::AppState;

    let server_config = config.server_config();

    // The daemon's embedded server does not run its own messaging listener —
    // the control plane's handles the full protocol on the authoritative store
    // (CLAUDE.md, "What the daemon intentionally does NOT mirror") — so its
    // `didcomm_service` slot stays empty. It reads the one shared store the
    // control plane writes, so there is nothing to replicate to it.
    let mut state = AppState::new(store.clone(), server_config)?.with_identity(identity);
    state.stats_collector = Some(stats_collector.clone());
    // With its control plane on, every change to a record or domain is made
    // in this process, which clears the gate cache after each commit
    // (`build_control`), so a warm resolve can skip the store entirely. With
    // it off, changes come from elsewhere and nothing would clear it: read
    // the store on every resolve, as a standalone edge does. Either way this
    // assumes one daemon per store.
    if config.enable.control {
        state.gate_cache = Some(Arc::new(did_hosting_server::cache::GateCache::new(
            store,
            did_hosting_server::cache::RESOLUTION_CACHE_TTL,
        )?));
    }

    let router = did_hosting_server::routes::router_public_only_with_resolve_limit(resolve_limit)
        .with_state(state.clone());
    info!("server service initialized (public-only, daemon mode)");

    Ok((router, state))
}

async fn build_witness(
    config: &DaemonConfig,
    store: &Store,
    identity: Option<Arc<ServiceIdentity>>,
    client_ips: &did_hosting_common::server::rate_limit::ClientIps,
    rate_limit_gc: &CancellationToken,
) -> ServiceResult {
    use webvh_witness::server::AppState;
    use webvh_witness::witness_keys;

    // The daemon's embedded witness runs no messaging listener of its own —
    // the control plane's carries the mediator connection — so its Trust Task
    // listener is the HTTPS binding, `POST /witness/api/trust-tasks`, under the
    // daemon's DID. Its `didcomm_service` slot stays empty, which is what makes
    // the witness's rotation path an inert no-op here.
    // Witness signing keys are sealed to a key-encryption key held in the
    // daemon's secret store, in an entry of its own. Load it (creating it on a
    // first start) and seal any key a record from an earlier release holds in
    // clear before the witness serves anything, as the standalone witness does.
    let witness_keys = Arc::new(
        witness_keys::prepare(
            store,
            &store.keyspace(did_hosting_common::server::store::KS_WITNESSES)?,
            &did_hosting_common::server::secret_store::create_witness_kek_store(
                &config.secrets,
                &config.config_path,
            )?,
        )
        .await?,
    );
    let mut state = AppState::new(
        store.clone(),
        config.witness_config(),
        identity,
        witness_keys,
    )?;
    state.client_ips = client_ips.clone();
    state
        .trust_tasks_rate_limiter
        .spawn_gc(rate_limit_gc.clone());

    let router = webvh_witness::routes::router().with_state(state);
    info!("witness service initialized");

    Ok(router)
}

async fn build_watcher(
    config: &DaemonConfig,
    store: &Store,
    resolve_limit: Arc<did_hosting_common::server::rate_limit::ResolveRateLimiter>,
) -> ServiceResult {
    use webvh_watcher::server::AppState;

    // Resolution only. The embedded watcher reads the daemon's one store, and
    // it has no DID of its own, so it runs no Trust Task listener: nothing is
    // ever synced into it. A watcher that mirrors control planes is a
    // standalone `webvh-watcher` with its own DID.
    let state = AppState::new(store.clone(), config.watcher_config(), None)?;
    let router = webvh_watcher::routes::router_public_only_with_resolve_limit(resolve_limit)
        .with_state(state);
    info!("watcher service initialized (resolution only, daemon mode)");

    Ok(router)
}

/// The control plane's Trust Task proof verifier, built exactly as the
/// standalone control plane builds it (the shared
/// [`did_hosting_common::server::trust_tasks::build_verifier`], called by
/// `AppState::build`): a deactivated `did:webvh` signer is refused, an
/// unreachable signer is retryable, and a proof failing against a cached DID
/// document is retried once, rate-limited, against a fresh one.
#[cfg(test)]
fn control_verifier(
    did_resolver: Option<&affinidi_did_resolver_cache_sdk::DIDCacheClient>,
) -> Option<Arc<did_hosting_common::server::trust_tasks::TransportBoundVerifier>> {
    did_hosting_common::server::trust_tasks::build_verifier(did_resolver)
}

/// The control plane's cache hook in the daemon: each change it commits
/// clears what the embedded server cached from it, so a resolve that skips
/// the store never serves a DID or domain state from before the change.
fn resolution_cache_hook(
    content: Arc<did_hosting_server::cache::ContentCache>,
    gate: Arc<did_hosting_server::cache::GateCache>,
) -> Arc<did_hosting_control::server::CacheInvalidateFn> {
    use did_hosting_control::server::CacheChange;
    Arc::new(move |change: CacheChange<'_>| match change {
        CacheChange::Did(mnemonic) => {
            content.invalidate_did(mnemonic);
            gate.forget_did(mnemonic);
        }
        CacheChange::Domains => gate.forget_domains(),
    })
}

/// Build the embedded control plane: its state by `AppState::build` and its
/// boot steps by `startup`, the standalone control plane's own recipe, with
/// what the daemon shares across services passed in.
async fn build_control(
    config: &DaemonConfig,
    secrets: &ServerSecrets,
    store: &Store,
    stats_collector: &Arc<StatsCollector>,
    identity: Option<Arc<ServiceIdentity>>,
    server: Option<&did_hosting_server::server::AppState>,
    client_ips: &did_hosting_common::server::rate_limit::ClientIps,
) -> Result<(Router, did_hosting_control::server::AppState), AppError> {
    use did_hosting_control::server::{AppState, AppStateOverrides};

    // Lets the control plane's own mutations (register, publish, disable,
    // rollback, delete, and domain changes) evict what the embedded server
    // cached from them in the same process — there is no sync round-trip to
    // do it the way a standalone edge does on receipt of `webvh/sync/*`.
    // `None` when the server component isn't enabled in this deployment:
    // nothing serves resolution, so nothing to invalidate.
    let cache_invalidate = server.and_then(|server| {
        Some(resolution_cache_hook(
            server.did_cache.clone(),
            server.gate_cache.clone()?,
        ))
    });

    let control_config = config.control_config();

    // No unsigned mode: a control plane that cannot sign refuses to start.
    did_hosting_control::signing::require_signing_identity(
        identity.as_deref(),
        control_config.server_did.as_deref(),
    )?;

    let state = AppState::build(
        control_config,
        store.clone(),
        Some(secrets),
        identity,
        AppStateOverrides {
            // The one collector the embedded server records resolutions in.
            stats_collector: Some(stats_collector.clone()),
            cache_invalidate,
            client_ips: Some(client_ips.clone()),
        },
    )
    .await?;

    // Challenges, the badge backfill and DID index, the registry seed and the
    // sign-in readiness check — the standalone control plane's boot steps.
    did_hosting_control::server::startup(&state).await?;

    // In daemon mode there are no external edges to sync with: the registry
    // is empty by default, so `server_push::notify_servers_*` finds no
    // targets. It is not skipped, so a registered remote instance still
    // gets pushes.

    // Build router without UI fallback — daemon adds its own combined fallback
    let router = did_hosting_control::routes::router_without_fallback().with_state(state.clone());
    info!("control plane service initialized");

    Ok((router, state))
}

// ===========================================================================
// Combined fallback: DID serving + SPA UI
// ===========================================================================

/// Fallback handler for the daemon's combined router.
///
/// Tries DID public serving first (e.g. `/{mnemonic}/did.jsonl`).
/// If that returns 404, falls through to the SPA static handler so that
/// paths like `/enroll` serve `index.html` for client-side routing.
///
/// The caller layers the resolution limit on it, so every request here
/// counts against it, the UI's included: whether a path is a DID is only
/// known after the store lookup the limit exists to bound.
async fn daemon_fallback(
    state: did_hosting_server::server::AppState,
    request: axum::extract::Request,
) -> Response {
    // Snapshot the URI for the SPA fallback (which only needs path
    // routing); the full Request is consumed by serve_public to read
    // ConnectInfo + headers for resolve-side host detection.
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let did_resp =
        did_hosting_server::routes::did_public::serve_public(axum::extract::State(state), request)
            .await;

    if did_resp.status() != StatusCode::NOT_FOUND {
        return did_resp;
    }

    #[cfg(feature = "ui")]
    {
        did_hosting_control::frontend::serve(&uri, &headers)
    }

    #[cfg(not(feature = "ui"))]
    {
        use axum::response::IntoResponse;
        let _ = (uri, headers);
        StatusCode::NOT_FOUND.into_response()
    }
}

// ===========================================================================
// Shared init helpers
// ===========================================================================

async fn load_secrets(config: &DaemonConfig) -> ServerSecrets {
    let secret_store = did_hosting_common::server::secret_store::create_secret_store(
        &config.secrets,
        &config.config_path,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error creating secret store: {e}");
        std::process::exit(1);
    });

    match secret_store.get().await {
        Ok(Some(s)) => {
            info!("secrets loaded from secret store");
            s
        }
        Ok(None) => {
            eprintln!("Error: no secrets found — run service setup first");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error loading secrets: {e}");
            std::process::exit(1);
        }
    }
}

// ===========================================================================
// CLI management commands
// ===========================================================================

async fn run_reset_witness_kek_claim(
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = DaemonConfig::load(config_path)?;
    let store = Store::open(&config.witness_store).await?;
    let witnesses_ks = store.keyspace(did_hosting_common::server::store::KS_WITNESSES)?;
    let kek_store = did_hosting_common::server::secret_store::create_witness_kek_store(
        &config.secrets,
        &config.config_path,
    )?;
    let had = webvh_witness::witness_keys::reset_kek_claim(&kek_store, &witnesses_ks).await?;
    store.persist().await?;
    eprintln!();
    if had {
        eprintln!("  Key-encryption-key creation claim cleared; start the daemon again.");
    } else {
        eprintln!("  No key-encryption-key creation claim was held.");
    }
    eprintln!();
    Ok(())
}

// ===========================================================================
// CLI health check
// ===========================================================================

/// Run every check and return what they found. A config that does not load
/// is an error: nothing else can be checked without it.
async fn run_health(
    config_path: Option<PathBuf>,
) -> Result<did_hosting_common::server::health::HealthReport, Box<dyn std::error::Error>> {
    use did_hosting_common::server::health;

    let mut report = health::HealthReport::new();
    health::header("did-hosting-daemon", env!("CARGO_PKG_VERSION"));

    // ── Configuration ──────────────────────────────────────────────
    health::section("Configuration");
    let config = DaemonConfig::load(config_path)
        .map_err(|e| -> Box<dyn std::error::Error> { format!("config load failed: {e}").into() })?;
    health::check_config_loaded(&config.config_path);
    health::check_value("server_did", &config.server_did);
    health::check_value("public_url", &config.public_url);
    health::check_value("did_hosting_url", &config.did_hosting_url);
    health::check_value("mediator_did", &config.mediator_did);

    // ── Compile Features ───────────────────────────────────────────
    health::section("Compile Features");
    health::print_feature("store-fjall", cfg!(feature = "store-fjall"));
    health::print_feature("keyring", cfg!(feature = "keyring"));
    health::print_feature("ui", cfg!(feature = "ui"));

    // ── Enabled Services ───────────────────────────────────────────
    health::section("Enabled Services");
    health::print_feature("server", config.enable.server);
    health::print_feature("witness", config.enable.witness);
    health::print_feature("watcher", config.enable.watcher);
    health::print_feature("control", config.enable.control);
    health::print_feature("didcomm", config.features.didcomm);
    health::print_feature("tsp", config.features.tsp);

    // ── Secrets ────────────────────────────────────────────────────
    health::section("Secrets");
    health::check_secrets(&mut report, &config.secrets, &config.config_path).await;

    // ── Per-service Stores ─────────────────────────────────────────
    if config.enable.server {
        health::section("Store (server)");
        let store = health::check_store(&mut report, &config.store).await;

        if let Some(ref store) = store
            && let Ok(dids_ks) = store.keyspace(KS_DIDS)
        {
            health::section("Root DID (.well-known)");
            match did_hosting_server::bootstrap::root_did_exists(&dids_ks).await {
                Ok(true) => {
                    report.pass("Root DID exists");
                    match dids_ks
                        .get::<did_hosting_server::did_ops::DidRecord>(
                            did_hosting_server::did_ops::did_key(".well-known"),
                        )
                        .await
                    {
                        Ok(Some(record)) => {
                            if let Some(ref did_id) = record.did_id {
                                health::info_msg(&format!("DID: {did_id}"));
                            }
                            health::info_msg(&format!("Version count: {}", record.version_count));
                        }
                        Ok(None) => {}
                        Err(e) => report.warn(&format!("Could not read DID record: {e}")),
                    }
                }
                Ok(false) => health::skip("Root DID not yet bootstrapped"),
                Err(e) => report.fail(&format!("Root DID check failed: {e}")),
            }
        }
    }

    if config.enable.witness {
        health::section("Store (witness)");
        health::check_store(&mut report, &config.witness_store).await;
    }

    if config.enable.watcher {
        health::section("Store (watcher — shared with server)");
        health::check_store(&mut report, &config.store).await;
    }

    if config.enable.control {
        health::section("Store (control — shared with server)");
        health::check_store(&mut report, &config.store).await;
    }

    // ── DID Resolution ─────────────────────────────────────────────
    if let Some(ref did) = config.server_did {
        health::section("DID Resolution");
        health::check_did_resolution(&mut report, "Server DID resolves", did).await;
    }

    if let Some(ref did) = config.mediator_did {
        health::section("Mediator DID Resolution");
        health::check_did_resolution(&mut report, "Mediator DID resolves", did).await;
    }

    Ok(report)
}

// ===========================================================================
// Health & banner
// ===========================================================================

/// `GET /health`: the daemon's liveness probe, held to the same check as the
/// standalone services' `/api/health` — healthy only while the daemon's own
/// DID is served from its store. `503` with `"status": "degraded"` otherwise.
/// Deliberately generic: no configuration or DID detail.
async fn daemon_health(
    dids_ks: &KeyspaceHandle,
    server_did: Option<&str>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    let ok = did_hosting_common::server::health::own_did_served_locally(dids_ks, server_did).await;
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        axum::Json(serde_json::json!({
            "status": if ok { "ok" } else { "degraded" },
            "service": "did-hosting-daemon",
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan}██████╗ {magenta} █████╗ {yellow}███████╗{cyan}███╗   ███╗{magenta} ██████╗ {yellow}███╗   ██╗{reset}
{cyan}██╔══██╗{magenta}██╔══██╗{yellow}██╔════╝{cyan}████╗ ████║{magenta}██╔═══██╗{yellow}████╗  ██║{reset}
{cyan}██║  ██║{magenta}███████║{yellow}█████╗  {cyan}██╔████╔██║{magenta}██║   ██║{yellow}██╔██╗ ██║{reset}
{cyan}██║  ██║{magenta}██╔══██║{yellow}██╔══╝  {cyan}██║╚██╔╝██║{magenta}██║   ██║{yellow}██║╚██╗██║{reset}
{cyan}██████╔╝{magenta}██║  ██║{yellow}███████╗{cyan}██║ ╚═╝ ██║{magenta}╚██████╔╝{yellow}██║ ╚████║{reset}
{cyan}╚═════╝ {magenta}╚═╝  ╚═╝{yellow}╚══════╝{cyan}╚═╝     ╚═╝{magenta} ╚═════╝ {yellow}╚═╝  ╚═══╝{reset}
{dim}  DID Hosting Daemon v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

#[cfg(test)]
mod verifier_tests {
    //! The daemon's control-plane verifier behaves like the standalone control
    //! plane's: status, rotation and reachability of the signer's DID.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use affinidi_did_resolver_cache_sdk::{
        AsyncResolver, DIDCacheClient, MethodName, Resolution, ResolverError,
        config::DIDCacheConfigBuilder,
    };
    use affinidi_tdk::did_common::{DID, Document};
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use did_hosting_common::server::trust_tasks::{
        BoundError, TransportBoundVerifier, send::build_request, sign_document, verify_sender_bound,
    };
    use serde_json::{Value, json};
    use trust_tasks_rs::{RejectReason, TrustTask};

    use super::control_verifier;

    const TYPE: &str = "https://trusttasks.org/spec/webvh/sync/delete/0.1";
    const ME: &str = "did:example:daemon";

    async fn cache() -> DIDCacheClient {
        DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap()
    }

    fn verifier(client: &DIDCacheClient) -> Arc<TransportBoundVerifier> {
        control_verifier(Some(client)).expect("a resolver is configured")
    }

    fn key(seed: u8, did: &str) -> Secret {
        let mut secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
        secret.id = format!("{did}#key-1");
        secret
    }

    fn document(did: &str, signer: &Secret) -> Document {
        serde_json::from_value(json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": signer.get_public_keymultibase().unwrap(),
            }],
            "authentication": [format!("{did}#key-1")],
        }))
        .unwrap()
    }

    async fn signed(did: &str, signer: &Secret) -> TrustTask<Value> {
        let doc = build_request(TYPE, did, ME, json!({ "mnemonic": "alice" })).unwrap();
        sign_document(&doc, signer).await.unwrap()
    }

    async fn check(
        doc: &TrustTask<Value>,
        did: &str,
        verifier: &TransportBoundVerifier,
    ) -> Result<String, BoundError> {
        verify_sender_bound(doc, Some(did), Some(did), ME, verifier).await
    }

    /// A deactivated `did:webvh` signer is refused even though its last
    /// document, still served from cache, lists the key; the same document
    /// from a live DID verifies. The refusal is final: it spends no forced
    /// re-resolution (which would evict the recorded verdict and the cached
    /// document, and fail here as unreachable).
    #[tokio::test]
    async fn a_deactivated_webvh_signer_is_refused() {
        let mut client = cache().await;
        let live = "did:webvh:QmLive:live.example";
        let dead = "did:webvh:QmDead:dead.example";
        let (live_key, dead_key) = (key(1, live), key(2, dead));
        client
            .add_did_document(live, document(live, &live_key))
            .await;
        client
            .add_did_document(dead, document(dead, &dead_key))
            .await;
        let v = verifier(&client);
        v.record_deactivation_verdict(live, false);
        v.record_deactivation_verdict(dead, true);

        check(&signed(live, &live_key).await, live, &v)
            .await
            .expect("a live signer verifies");
        let err = check(&signed(dead, &dead_key).await, dead, &v)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("deactivated"), "{err}");
        assert!(!err.is_transient(), "{err:?}");
        assert!(
            matches!(err.reject_reason(), RejectReason::ProofInvalid { .. }),
            "{err:?}"
        );
    }

    /// Serves `did:web` documents listing whichever key `keys` holds, and
    /// counts resolutions.
    struct RotatingResolver {
        keys: Arc<std::sync::Mutex<Secret>>,
        resolutions: Arc<AtomicUsize>,
    }

    impl AsyncResolver for RotatingResolver {
        fn name(&self) -> &str {
            "RotatingResolver"
        }

        fn resolve<'a>(
            &'a self,
            did: &'a DID,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Resolution> + Send + 'a>> {
            self.resolutions.fetch_add(1, Ordering::SeqCst);
            let current = self.keys.lock().unwrap().clone();
            let did = did.to_string();
            Box::pin(async move { Some(Ok(document(&did, &current))) })
        }
    }

    /// A signer that rotated its key after its document was cached verifies
    /// after exactly one fresh resolution.
    #[tokio::test]
    async fn a_rotated_key_verifies_after_one_refresh() {
        let did = "did:web:rotated.example";
        let (old_key, new_key) = (key(3, did), key(4, did));
        let keys = Arc::new(std::sync::Mutex::new(old_key));
        let resolutions = Arc::new(AtomicUsize::new(0));
        let mut client = cache().await;
        client.set_resolver(
            MethodName::Web,
            Box::new(RotatingResolver {
                keys: keys.clone(),
                resolutions: resolutions.clone(),
            }),
        );
        // The pre-rotation document is cached.
        client.resolve(did).await.unwrap();
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        let v = verifier(&client);

        *keys.lock().unwrap() = new_key.clone();
        let proven = check(&signed(did, &new_key).await, did, &v)
            .await
            .expect("verifies after one refresh");
        assert_eq!(proven, did);
        assert_eq!(resolutions.load(Ordering::SeqCst), 2, "exactly one refresh");
    }

    /// A signer whose DID cannot be resolved is `unavailable` — retryable —
    /// not a bad proof.
    #[tokio::test]
    async fn an_unreachable_signer_is_unavailable() {
        struct Unreachable;
        impl AsyncResolver for Unreachable {
            fn name(&self) -> &str {
                "Unreachable"
            }
            fn resolve<'a>(
                &'a self,
                _did: &'a DID,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Resolution> + Send + 'a>>
            {
                Box::pin(async {
                    Some(Err(ResolverError::ResolutionFailed(
                        "connection refused".to_string(),
                    )))
                })
            }
        }

        let did = "did:web:unreachable.example";
        let signer = key(5, did);
        let mut client = cache().await;
        client.set_resolver(MethodName::Web, Box::new(Unreachable));
        let err = check(&signed(did, &signer).await, did, &verifier(&client))
            .await
            .unwrap_err();
        assert!(err.is_transient(), "{err:?}");
        assert!(
            matches!(err.reject_reason(), RejectReason::Unavailable { .. }),
            "{err:?}"
        );
    }

    /// The `did:webvh` flavour: a document served from cache whose DID log
    /// cannot be read leaves deactivation unestablished, which is retryable.
    #[tokio::test]
    async fn a_webvh_signer_with_an_unreadable_log_is_unavailable() {
        // `.invalid` never resolves (RFC 6761).
        let did = "did:webvh:QmGone:gone.invalid";
        let signer = key(6, did);
        let mut client = cache().await;
        client.add_did_document(did, document(did, &signer)).await;
        let err = check(&signed(did, &signer).await, did, &verifier(&client))
            .await
            .unwrap_err();
        assert!(err.is_transient(), "{err:?}");
        assert!(
            matches!(err.reject_reason(), RejectReason::Unavailable { .. }),
            "{err:?}"
        );
    }
}

#[cfg(test)]
mod resolution_cache_hook_tests {
    //! The hook is what keeps the embedded server's caches honest: a resolve
    //! that skips the store must not outlive a change the control plane made.

    use std::sync::Arc;
    use std::time::Duration;

    use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
    use did_hosting_common::server::config::StoreConfig;
    use did_hosting_common::server::domain::{DomainEntry, DomainStatus, DomainUrlScheme};
    use did_hosting_common::server::store::{KS_DIDS, KS_DOMAINS, Store};
    use did_hosting_control::server::CacheChange;
    use did_hosting_server::cache::{ContentCache, GateCache};

    use super::resolution_cache_hook;

    fn record(disabled: bool) -> DidRecord {
        DidRecord {
            owner: "did:example:owner".into(),
            mnemonic: "alice".into(),
            created_at: 0,
            updated_at: 0,
            version_count: 1,
            did_id: Some("did:webvh:Q1:a.example:alice".into()),
            content_size: 0,
            disabled,
            disabled_by_admin: false,
            deleted_at: None,
            method: "webvh".into(),
            domain: "a.example".into(),
            services: None,
            agent_names: Vec::new(),
        }
    }

    fn domain(status: DomainStatus) -> DomainEntry {
        DomainEntry {
            name: "a.example".into(),
            label: None,
            scheme: DomainUrlScheme::Https,
            status,
            created_at: 0,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        }
    }

    #[tokio::test]
    async fn each_change_clears_what_the_embedded_server_cached_from_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
            ..StoreConfig::default()
        })
        .await
        .unwrap();
        let dids = store.keyspace(KS_DIDS).unwrap();
        let domains = store.keyspace(KS_DOMAINS).unwrap();
        let content = Arc::new(ContentCache::new(Duration::from_secs(60)));
        let gate = Arc::new(GateCache::new(&store, Duration::from_secs(60)).unwrap());
        let hook = resolution_cache_hook(content.clone(), gate.clone());

        // Warm every cache from the store.
        dids.insert(did_key("alice"), &record(false)).await.unwrap();
        domains
            .insert("a.example", &domain(DomainStatus::Active))
            .await
            .unwrap();
        let web_key = ContentCache::did_web_document_key("alice");
        for key in [content_log_key("alice"), web_key.clone()] {
            content.insert(content.generation(), key, b"old".to_vec());
        }
        assert!(!gate.record("alice").await.unwrap().unwrap().disabled);
        let allowed = |d: &did_hosting_common::server::domain::ResolutionDomains| {
            d.assert_allowed(Some("a.example"), "did:webvh:Q1:a.example:alice")
                .is_ok()
        };
        assert!(allowed(&gate.domains().await.unwrap()));

        // A DID change: the store moves on, and the hook names the DID.
        dids.insert(did_key("alice"), &record(true)).await.unwrap();
        hook(CacheChange::Did("alice"));
        assert!(content.get(&content_log_key("alice")).is_none(), "log");
        assert!(content.get(&web_key).is_none(), "did:web document");
        assert!(gate.record("alice").await.unwrap().unwrap().disabled);

        // A domain change, likewise.
        domains
            .insert("a.example", &domain(DomainStatus::Disabled))
            .await
            .unwrap();
        assert!(allowed(&gate.domains().await.unwrap()), "still cached");
        hook(CacheChange::Domains);
        assert!(!allowed(&gate.domains().await.unwrap()));
    }
}

#[cfg(test)]
mod cli_reference_tests {
    did_hosting_common::cli_reference_test!(super::Cli, "did-hosting-daemon");
}

#[cfg(test)]
mod parity_tests {
    //! Daemon parity (CLAUDE.md): the daemon's subcommands cover the
    //! standalone binaries', and every background task they run is either run
    //! here — built by the same functions — or named in the skip list.

    use std::collections::BTreeSet;

    use clap::CommandFactory;
    use did_hosting_common::server::supervise::names;

    use super::*;

    /// Standalone subcommands the daemon deliberately does not have. Empty:
    /// every one is a shared group the daemon flattens in, or has a daemon
    /// counterpart of the same name.
    const CLI_ALLOWLIST: &[&str] = &[];

    fn subcommands(cmd: clap::Command) -> BTreeSet<String> {
        cmd.get_subcommands()
            .map(|s| s.get_name().to_string())
            .filter(|name| name != "help")
            .collect()
    }

    #[test]
    fn the_daemon_has_every_standalone_subcommand() {
        let daemon = subcommands(Cli::command());
        let server = subcommands(did_hosting_server::cli::Cli::command());
        let control = subcommands(did_hosting_control::cli::Cli::command());
        let standalone: BTreeSet<_> = server.union(&control).cloned().collect();

        let missing: Vec<_> = standalone
            .iter()
            .filter(|name| !daemon.contains(*name) && !CLI_ALLOWLIST.contains(&name.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "did-hosting-daemon lacks {missing:?}: flatten the group into its `Command`, or \
             allowlist it here with the reason"
        );
        for name in CLI_ALLOWLIST {
            assert!(
                standalone.contains(*name),
                "`{name}` is no standalone subcommand"
            );
            assert!(
                !daemon.contains(*name),
                "`{name}` is allowlisted but present"
            );
        }
        // The shared groups reach the daemon: the ones it used to lack.
        for name in [
            "export-sealed",
            "import-sealed",
            "vta-request",
            "vta-open",
            "dump-did",
        ] {
            assert!(daemon.contains(name), "{name}");
        }
        assert!(!daemon.contains("migrate-from-webvh-config"));
    }

    #[tokio::test]
    async fn the_daemon_runs_or_skips_every_standalone_task() {
        let dir = tempfile::tempdir().unwrap();
        let config: did_hosting_control::config::AppConfig = toml::from_str(&format!(
            "[store]\ndata_dir = \"{}\"\n",
            dir.path().display()
        ))
        .expect("control config");
        let store = Store::open(&config.store).await.unwrap();
        let state = did_hosting_control::server::AppState::build(
            config,
            store.clone(),
            None,
            None,
            Default::default(),
        )
        .await
        .unwrap();
        let edge = did_hosting_server::server::EdgeStorage {
            store: store.clone(),
            dids_ks: state.dids_ks.clone(),
            did_ttl_seconds: 60,
            collector: state.stats_collector.clone(),
            caches: did_hosting_server::cache::ResolutionCaches {
                content: Arc::new(did_hosting_server::cache::ContentCache::new(
                    did_hosting_server::cache::RESOLUTION_CACHE_TTL,
                )),
                gate: None,
            },
            path_locks: Some(state.path_locks.clone()),
            on_removed: None,
        };
        let control = did_hosting_control::server::ControlStorage::of(&state);

        // The task-name constants are what the builders build.
        use did_hosting_control::server::tasks as control_tasks;
        use did_hosting_server::server::tasks as server_tasks;
        assert_eq!(
            names(&did_hosting_server::server::storage_tasks(&edge)),
            server_tasks::STORAGE
        );
        assert_eq!(
            names(&did_hosting_control::server::storage_tasks(&control)),
            control_tasks::STORAGE
        );
        assert_eq!(
            names(&did_hosting_control::server::background_tasks(&state)),
            control_tasks::PERIODIC
        );

        // What the daemon runs: its storage task, and the control plane's
        // background tasks less the skip list (`spawn_workers`).
        let mut runs: BTreeSet<&str> = names(&daemon_storage_tasks(&edge, &control))
            .into_iter()
            .collect();
        runs.extend(
            names(&did_hosting_control::server::background_tasks(&state))
                .into_iter()
                .filter(|name| !DAEMON_SKIPPED_TASKS.contains(name)),
        );

        let standalone: BTreeSet<&str> = server_tasks::STORAGE
            .into_iter()
            .chain(server_tasks::MESSAGING)
            .chain(control_tasks::STORAGE)
            .chain(control_tasks::PERIODIC)
            .collect();
        for name in &standalone {
            let skipped = DAEMON_SKIPPED_TASKS.contains(name);
            assert!(
                runs.contains(name) != skipped,
                "`{name}`: run by the daemon = {}, skipped = {skipped}; exactly one must hold",
                runs.contains(name)
            );
        }
        for name in DAEMON_SKIPPED_TASKS {
            assert!(
                standalone.contains(name),
                "`{name}` is skipped but no standalone task"
            );
        }
    }
}

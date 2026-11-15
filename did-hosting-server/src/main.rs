use clap::Parser;
use did_hosting_common::server::cli::{Loader, Service, exit_on_error};
use did_hosting_server::cli::{Cli, Command};
use did_hosting_server::config::AppConfig;
use did_hosting_server::{backup, health, secret_store, server, setup, setup_recipe, store};
use std::path::PathBuf;

const SERVICE: Service = Service::Server;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    print_banner();

    let config_path = cli.config;
    let load = || -> Loader<'static, AppConfig> {
        let path = config_path.clone();
        Box::new(move || Ok(AppConfig::load(path)?))
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
                exit_on_error(
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
                exit_on_error(
                    "Setup error",
                    setup::run_wizard(config_path.clone(), setup_key_file).await,
                );
            }
        }
        Some(Command::Uninstall { yes }) => {
            let config_path = config_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("config.toml"));
            exit_on_error(
                "Uninstall error",
                setup_recipe::run_uninstall(&config_path, yes).await,
            );
        }
        Some(Command::Health { strict }) => {
            let code = did_hosting_common::server::health::finish(
                health::run_health(config_path.clone()).await,
                strict,
            );
            std::process::exit(code);
        }
        Some(Command::Backup { output }) => exit_on_error(
            "Backup error",
            backup::run_backup(config_path.clone(), output).await,
        ),
        Some(Command::Restore { input }) => exit_on_error(
            "Restore error",
            backup::run_restore(config_path.clone(), input).await,
        ),
        Some(Command::SetupOfflinePrepare { request, state }) => exit_on_error(
            "Setup error",
            setup::run_setup_offline_prepare(config_path.clone(), request, state).await,
        ),
        Some(Command::SetupOfflineComplete {
            bundle,
            expect_digest,
            state,
        }) => exit_on_error(
            "Setup error",
            setup::run_setup_offline_complete(bundle, expect_digest, state).await,
        ),
        Some(Command::Identity(cmd)) => exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Tsp(cmd)) => exit_on_error("Error", cmd.run(load()).await),
        Some(Command::Did(cmd)) => exit_on_error("Error", cmd.run(SERVICE.binary(), load()).await),
        Some(Command::Keys(cmd)) => exit_on_error("Error", cmd.run(SERVICE, load()).await),
        Some(Command::Vta(cmd)) => exit_on_error("Error", cmd.run(SERVICE).await),
        None => run_server(config_path).await,
    }
}

async fn run_server(config_path: Option<PathBuf>) {
    let config = match AppConfig::load(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!();
            eprintln!("Create a config.toml or specify one:");
            eprintln!("  did-hosting-server --config <path>");
            eprintln!();
            eprintln!("Or run the setup wizard:");
            eprintln!("  did-hosting-server setup");
            std::process::exit(1);
        }
    };

    did_hosting_common::server::config::init_tracing(&config.log);

    // Load secrets from the configured backend
    let secret_store = match secret_store::create_secret_store(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let secrets = match secret_store.get().await {
        Ok(Some(s)) => {
            tracing::info!("secrets loaded from secret store");
            s
        }
        Ok(None) => {
            eprintln!("Error: no secrets found — run `did-hosting-server setup` first");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error loading secrets: {e}");
            std::process::exit(1);
        }
    };

    if secret_store::is_plaintext_backend(&config.secrets) {
        tracing::warn!("============================================================");
        tracing::warn!("  PLAINTEXT SECRETS MODE - INSECURE");
        tracing::warn!("  Server secrets are stored as plaintext in the config file.");
        tracing::warn!("  DO NOT use this in production.");
        tracing::warn!("  For production, recompile with a secure backend:");
        tracing::warn!("    keyring, aws-secrets, or gcp-secrets");
        tracing::warn!("============================================================");
    }

    let store = match store::Store::open_with(&config.store, &config.fjall).await {
        Ok(store) => store,
        Err(e) => {
            tracing::error!("failed to open store: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = server::run(config, store, secrets).await {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan}██╗    ██╗{magenta}███████╗{yellow}██████╗ {cyan}██╗   ██╗{magenta}██╗  ██╗{reset}
{cyan}██║    ██║{magenta}██╔════╝{yellow}██╔══██╗{cyan}██║   ██║{magenta}██║  ██║{reset}
{cyan}██║ █╗ ██║{magenta}█████╗  {yellow}██████╔╝{cyan}██║   ██║{magenta}███████║{reset}
{cyan}██║███╗██║{magenta}██╔══╝  {yellow}██╔══██╗{cyan}╚██╗ ██╔╝{magenta}██╔══██║{reset}
{cyan}╚███╔███╔╝{magenta}███████╗{yellow}██████╔╝{cyan} ╚████╔╝ {magenta}██║  ██║{reset}
{cyan} ╚══╝╚══╝ {magenta}╚══════╝{yellow}╚═════╝ {cyan}  ╚═══╝  {magenta}╚═╝  ╚═╝{reset}
{dim}  DID Hosting Server v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

#[cfg(test)]
mod cli_reference_tests {
    did_hosting_common::cli_reference_test!(did_hosting_server::cli::Cli, "did-hosting-server");
}

//! Load a [`SetupRecipe`] from disk, layer environment variables on top,
//! then validate. The result is the single struct every binary's headless
//! setup path consumes.

use std::path::Path;

use super::schema::{LogFormatStr, RecipeError, SecretsBackend, ServiceKind, SetupRecipe, VtaMode};

/// Read a recipe TOML file, apply environment-variable overrides, and
/// validate. The env prefix is derived from `[deployment].service`:
///
/// - `did-hosting-daemon`  → `DAEMON_*`
/// - `did-hosting-server`  → `DID_HOSTING_*`
/// - `did-hosting-control` → `CONTROL_*`
/// - `webvh-witness` → `WITNESS_*`
/// - `webvh-watcher` → `WATCHER_*`
///
/// Matches the runtime env prefixes documented in
/// `docs/bootstrap_startup.md` — operators using `DID_HOSTING_PUBLIC_URL` to
/// override `[server]` at runtime get the same key working at setup.
pub fn load_recipe(path: &Path) -> Result<SetupRecipe, RecipeError> {
    let raw = std::fs::read_to_string(path).map_err(|source| RecipeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut recipe: SetupRecipe = toml::from_str(&raw)?;
    apply_env_overrides(&mut recipe);
    recipe.validate()?;
    Ok(recipe)
}

/// Apply environment-variable overrides in place. Visible for tests and
/// for the `--non-interactive` path that builds a recipe in memory and
/// still wants the env to win over hard-coded defaults.
pub fn apply_env_overrides(recipe: &mut SetupRecipe) {
    let prefix = match recipe.deployment.service {
        ServiceKind::Daemon => "DAEMON",
        ServiceKind::Server => "WEBVH",
        ServiceKind::Control => "CONTROL",
        ServiceKind::Witness => "WITNESS",
        ServiceKind::Watcher => "WATCHER",
    };

    // Identity
    if let Some(v) = env_get(prefix, "PUBLIC_URL") {
        recipe.identity.public_url = Some(v);
    }
    if let Some(v) = env_get(prefix, "DID_HOSTING_URL") {
        recipe.identity.did_hosting_url = Some(v);
    }
    if let Some(v) = env_get(prefix, "MEDIATOR_DID") {
        recipe.identity.mediator_did = Some(v);
    }
    if let Some(v) = env_get(prefix, "CONTROL_DID") {
        recipe.identity.control_did = Some(v);
    }
    if let Some(v) = env_get(prefix, "CONTROL_URL") {
        recipe.identity.control_url = Some(v);
    }

    // VTA
    if let Some(v) = env_get(prefix, "VTA_DID") {
        recipe.vta.did = Some(v);
    }
    if let Some(v) = env_get(prefix, "VTA_CONTEXT_ID") {
        recipe.vta.context_id = Some(v);
    }

    // Secrets — selection precedence matches the runtime: AWS → GCP →
    // Azure → keyring. If multiple are set we honour the highest one
    // (same precedence the runtime config loader uses).
    if std::env::var(format!("{prefix}_SECRETS_AWS_SECRET_NAME")).is_ok() {
        recipe.secrets.backend = Some(SecretsBackend::Aws);
    } else if std::env::var(format!("{prefix}_SECRETS_GCP_SECRET_NAME")).is_ok() {
        recipe.secrets.backend = Some(SecretsBackend::Gcp);
    } else if std::env::var(format!("{prefix}_SECRETS_AZURE_SECRET_NAME")).is_ok() {
        recipe.secrets.backend = Some(SecretsBackend::Azure);
    } else if std::env::var(format!("{prefix}_SECRETS_KEYRING_SERVICE")).is_ok() {
        recipe.secrets.backend = Some(SecretsBackend::Keyring);
    }
    if let Some(v) = env_get(prefix, "SECRETS_KEYRING_SERVICE") {
        recipe.secrets.keyring_service = Some(v);
    }
    if let Some(v) = env_get(prefix, "SECRETS_AWS_REGION") {
        recipe.secrets.aws_region = Some(v);
    }
    if let Some(v) = env_get(prefix, "SECRETS_AWS_SECRET_NAME") {
        recipe.secrets.aws_secret_name = Some(v);
    }
    if let Some(v) = env_get(prefix, "SECRETS_GCP_PROJECT") {
        recipe.secrets.gcp_project = Some(v);
    }
    if let Some(v) = env_get(prefix, "SECRETS_GCP_SECRET_NAME") {
        recipe.secrets.gcp_secret_name = Some(v);
    }
    if let Some(v) = env_get(prefix, "SECRETS_AZURE_VAULT_URL") {
        recipe.secrets.azure_vault_url = Some(v);
    }
    if let Some(v) = env_get(prefix, "SECRETS_AZURE_SECRET_NAME") {
        recipe.secrets.azure_secret_name = Some(v);
    }

    // Server section
    if let Some(v) = env_get(prefix, "HOST") {
        recipe.server.host = Some(v);
    }
    if let Some(v) = env_get_parsed::<u16>(prefix, "PORT") {
        recipe.server.port = Some(v);
    }
    if let Some(v) = env_get(prefix, "LOG_LEVEL") {
        recipe.server.log_level = Some(v);
    }
    if let Some(v) = env_get(prefix, "LOG_FORMAT") {
        match v.to_ascii_lowercase().as_str() {
            "json" => recipe.server.log_format = Some(LogFormatStr::Json),
            "text" => recipe.server.log_format = Some(LogFormatStr::Text),
            // Anything else is left to the recipe / default; we'd rather
            // not fail validation on an env typo nobody intended.
            _ => {}
        }
    }
    if let Some(v) = env_get(prefix, "STORE_DATA_DIR") {
        recipe.server.data_dir = Some(v.into());
    }
}

fn env_get(prefix: &str, name: &str) -> Option<String> {
    std::env::var(format!("{prefix}_{name}"))
        .ok()
        .and_then(|v| if v.is_empty() { None } else { Some(v) })
}

fn env_get_parsed<T: std::str::FromStr>(prefix: &str, name: &str) -> Option<T> {
    env_get(prefix, name).and_then(|v| v.parse().ok())
}

// ---------------------------------------------------------------------------
// Header lookup
// ---------------------------------------------------------------------------

/// Peek at `[deployment].service` without fully validating. Useful when a
/// binary wants to confirm the recipe targets it before doing anything
/// expensive (e.g. probing the secret store).
pub fn peek_service(path: &Path) -> Result<ServiceKind, RecipeError> {
    let raw = std::fs::read_to_string(path).map_err(|source| RecipeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // Parse only the deployment section. `serde(deny_unknown_fields)`
    // doesn't apply here because we're using a sub-struct.
    #[derive(serde::Deserialize)]
    struct OnlyDeployment {
        deployment: super::schema::DeploymentSection,
    }
    let only: OnlyDeployment = toml::from_str(&raw)?;
    Ok(only.deployment.service)
}

/// Refuse to apply a recipe that targets a different service than the
/// binary we're running in. Saves the operator from copy-paste mistakes
/// (running `did-hosting-server setup --from daemon-build.toml`).
pub fn require_service(recipe: &SetupRecipe, expected: ServiceKind) -> Result<(), RecipeError> {
    let actual = recipe.deployment.service;
    if actual != expected {
        return Err(RecipeError::InvalidField {
            service: actual,
            field: "deployment.service",
            reason: format!(
                "recipe targets {actual} but this binary is {expected} — \
                 re-run with the matching binary or update the recipe"
            ),
        });
    }
    Ok(())
}

/// Convenience: map `LogFormatStr` → the canonical `LogFormat`.
pub fn to_log_format(s: LogFormatStr) -> crate::server::config::LogFormat {
    match s {
        LogFormatStr::Text => crate::server::config::LogFormat::Text,
        LogFormatStr::Json => crate::server::config::LogFormat::Json,
    }
}

/// Build a `SecretsConfig` from the recipe's `[secrets]` section. The
/// interactive wizard's `prompt_secrets_backend` does the same shape;
/// this is the non-interactive equivalent.
pub fn resolve_secrets_config(
    recipe: &SetupRecipe,
    default_secret_name: &str,
    default_keyring_service: &str,
) -> crate::server::config::SecretsConfig {
    let mut out = crate::server::config::SecretsConfig::default();
    let backend = recipe.secrets.backend.unwrap_or(SecretsBackend::Keyring);

    match backend {
        SecretsBackend::Keyring => {
            out.keyring_service = recipe
                .secrets
                .keyring_service
                .clone()
                .unwrap_or_else(|| default_keyring_service.to_string());
        }
        SecretsBackend::Aws => {
            out.aws_region = recipe.secrets.aws_region.clone();
            out.aws_secret_name = Some(
                recipe
                    .secrets
                    .aws_secret_name
                    .clone()
                    .unwrap_or_else(|| default_secret_name.to_string()),
            );
            out.keyring_service = default_keyring_service.to_string();
        }
        SecretsBackend::Gcp => {
            out.gcp_project = recipe.secrets.gcp_project.clone();
            out.gcp_secret_name = Some(
                recipe
                    .secrets
                    .gcp_secret_name
                    .clone()
                    .unwrap_or_else(|| default_secret_name.to_string()),
            );
            out.keyring_service = default_keyring_service.to_string();
        }
        SecretsBackend::Azure => {
            out.azure_vault_url = recipe.secrets.azure_vault_url.clone();
            out.azure_secret_name = Some(
                recipe
                    .secrets
                    .azure_secret_name
                    .clone()
                    .unwrap_or_else(|| default_secret_name.to_string()),
            );
            out.keyring_service = default_keyring_service.to_string();
        }
        SecretsBackend::Plaintext => {
            // Explicitly select plaintext so a keyring-enabled build doesn't
            // silently prefer the OS keyring (which panics on headless hosts
            // with no Secret Service). The validator already demanded
            // `confirm_plaintext = true`.
            out.plaintext_mode = true;
            out.keyring_service = default_keyring_service.to_string();
        }
    }
    out
}

/// Returns the active backend kind given a populated [`SetupRecipe`].
/// Used by `apply` paths that need to know which env vars / file paths
/// to consult.
pub fn active_backend(recipe: &SetupRecipe) -> SecretsBackend {
    recipe.secrets.backend.unwrap_or(SecretsBackend::Keyring)
}

/// Returns the VTA mode shorthand for logging / error context.
pub fn vta_mode_str(mode: VtaMode) -> &'static str {
    match mode {
        VtaMode::Online => "online",
        VtaMode::OfflinePrepare => "offline-prepare",
        VtaMode::OfflineComplete => "offline-complete",
        VtaMode::SelfManaged => "self-managed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::setup_recipe::schema::{
        DeploymentSection, IdentitySection, OutputSection, SecretsSection, SetupRecipe, VtaSection,
    };
    use std::path::PathBuf;

    fn fixture(service: ServiceKind) -> SetupRecipe {
        SetupRecipe {
            deployment: DeploymentSection {
                service,
                vta_mode: VtaMode::Online,
            },
            output: OutputSection {
                config_path: PathBuf::from("config.toml"),
            },
            server: Default::default(),
            identity: IdentitySection {
                public_url: Some("https://example.com".into()),
                did_hosting_url: Some("https://example.com".into()),
                ..Default::default()
            },
            vta: VtaSection {
                did: Some("did:webvh:vta.example.com".into()),
                ..Default::default()
            },
            secrets: SecretsSection::default(),
            admin: Default::default(),
            reprovision: Default::default(),
            watcher: Default::default(),
            daemon: Default::default(),
        }
    }

    #[test]
    fn env_overrides_apply_for_daemon_prefix() {
        // SAFETY: the test sets/unsets process env. Other tests in this
        // process must not observe these — keep them scoped + unique.
        let key = "DAEMON_PUBLIC_URL";
        // Avoid clobbering a real env if a developer is debugging.
        let prior = std::env::var(key).ok();
        unsafe { std::env::set_var(key, "https://from-env.example") };

        let mut r = fixture(ServiceKind::Daemon);
        apply_env_overrides(&mut r);
        assert_eq!(
            r.identity.public_url.as_deref(),
            Some("https://from-env.example")
        );

        // Restore
        match prior {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn resolve_secrets_keyring_default_uses_default_service_name() {
        let r = fixture(ServiceKind::Server);
        let cfg = resolve_secrets_config(&r, "test-secrets", "webvh");
        assert_eq!(cfg.keyring_service, "webvh");
    }

    #[test]
    fn require_service_rejects_mismatch() {
        let r = fixture(ServiceKind::Daemon);
        assert!(require_service(&r, ServiceKind::Server).is_err());
        require_service(&r, ServiceKind::Daemon).unwrap();
    }
}

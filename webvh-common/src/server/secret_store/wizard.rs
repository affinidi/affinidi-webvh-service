//! Interactive setup-wizard helper for picking a secrets storage backend.
//!
//! Shared between the four setup wizards (webvh-control, webvh-server,
//! webvh-witness, webvh-daemon). Each wizard supplies its own default
//! secret name and keyring service; the rest — backend selection,
//! connection-param prompts, and the existing-secrets picker — is
//! identical, so it lives here.
//!
//! Listing existing secrets is best-effort: when the cloud SDK can't
//! authenticate (no creds, network down, IAM denied) we surface a
//! one-line warning and fall back to a free-text input.

use dialoguer::{Confirm, Input, Select};

use crate::server::config::SecretsConfig;
use crate::server::error::AppError;

/// Prompt the operator for a secrets backend and its connection params.
///
/// Returns a populated [`SecretsConfig`]. Behaviour:
///
/// 1. Lists every secrets backend compiled into the binary
///    (`keyring`, `aws-secrets`, `gcp-secrets`, `azure-secrets`).
/// 2. If none are compiled in, warns about plaintext storage and
///    requires explicit confirmation.
/// 3. For cloud backends (AWS/GCP/Azure), collects connection params
///    (region/project/vault URL), then attempts to list existing
///    secrets. On success, the operator picks from the list or
///    enters a new name; on failure the wizard falls back to a
///    free-text input with a warning.
#[allow(clippy::vec_init_then_push, unused_variables)]
pub async fn prompt_secrets_backend(
    default_secret_name: &str,
    default_keyring_service: &str,
) -> Result<SecretsConfig, AppError> {
    #[allow(unused_mut)]
    let mut backends: Vec<&str> = Vec::new();

    #[cfg(feature = "keyring")]
    backends.push("OS Keyring (default)");

    #[cfg(feature = "aws-secrets")]
    backends.push("AWS Secrets Manager");

    #[cfg(feature = "gcp-secrets")]
    backends.push("GCP Secret Manager");

    #[cfg(feature = "azure-secrets")]
    backends.push("Azure Key Vault");

    if backends.is_empty() {
        eprintln!();
        eprintln!("  *** WARNING: No secure secrets backend is available. ***");
        eprintln!("  Secrets will be stored as PLAINTEXT in the configuration file.");
        eprintln!("  This is INSECURE and should only be used for testing/development.");
        eprintln!(
            "  For production, recompile with: keyring, aws-secrets, gcp-secrets, or azure-secrets."
        );
        eprintln!();

        let proceed = Confirm::new()
            .with_prompt("Continue with plaintext secrets storage?")
            .default(false)
            .interact()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;

        if !proceed {
            return Err(AppError::Config(
                "setup cancelled — recompile with a secure secrets backend (keyring, aws-secrets, gcp-secrets, or azure-secrets)".into(),
            ));
        }

        return Ok(SecretsConfig::default());
    }

    let chosen = if backends.len() == 1 {
        eprintln!("  Using {} for secrets storage.", backends[0]);
        backends[0]
    } else {
        let idx = Select::new()
            .with_prompt("Secrets storage backend")
            .items(&backends)
            .default(0)
            .interact()
            .map_err(|e| AppError::Config(format!("input error: {e}")))?;
        backends[idx]
    };

    let mut secrets_config = SecretsConfig::default();

    match chosen {
        #[cfg(feature = "aws-secrets")]
        s if s.starts_with("AWS") => {
            let region: String = Input::new()
                .with_prompt("AWS region (leave empty for default)")
                .default(String::new())
                .allow_empty(true)
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;
            let region_opt = if region.is_empty() {
                None
            } else {
                Some(region)
            };

            let name = pick_or_input_name(
                "AWS",
                default_secret_name,
                super::aws::list_secret_names(region_opt.as_deref()).await,
            )?;

            secrets_config.aws_secret_name = Some(name);
            secrets_config.aws_region = region_opt;
        }
        #[cfg(feature = "gcp-secrets")]
        s if s.starts_with("GCP") => {
            let project: String = Input::new()
                .with_prompt("GCP project ID")
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

            let name = pick_or_input_name(
                "GCP",
                default_secret_name,
                super::gcp::list_secret_names(&project).await,
            )?;

            secrets_config.gcp_project = Some(project);
            secrets_config.gcp_secret_name = Some(name);
        }
        #[cfg(feature = "azure-secrets")]
        s if s.starts_with("Azure") => {
            let vault_url: String = Input::new()
                .with_prompt("Azure Key Vault URL (e.g. https://my-vault.vault.azure.net/)")
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

            let name = pick_or_input_name(
                "Azure Key Vault",
                default_secret_name,
                super::azure::list_secret_names(&vault_url).await,
            )?;

            secrets_config.azure_vault_url = Some(vault_url);
            secrets_config.azure_secret_name = Some(name);
        }
        _ => {
            // Keyring (or only available backend)
            let service: String = Input::new()
                .with_prompt("Keyring service name")
                .default(default_keyring_service.to_string())
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;
            secrets_config.keyring_service = service;
        }
    }

    Ok(secrets_config)
}

/// Render a Select of existing secret names plus a "Enter a new name…"
/// option. On listing failure (no creds, IAM denied, network down) fall
/// back to a free-text Input with a warning.
#[cfg(any(
    feature = "aws-secrets",
    feature = "gcp-secrets",
    feature = "azure-secrets"
))]
fn pick_or_input_name(
    backend_label: &str,
    default_secret_name: &str,
    list_result: Result<Vec<String>, AppError>,
) -> Result<String, AppError> {
    const ENTER_NEW: &str = "Enter a new name…";

    let prompt_label = format!("{backend_label} secret name");

    match list_result {
        Ok(existing) if !existing.is_empty() => {
            let mut items: Vec<String> = existing;
            items.push(ENTER_NEW.to_string());

            let idx = Select::new()
                .with_prompt(&prompt_label)
                .items(&items)
                .default(0)
                .interact()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

            if items[idx] == ENTER_NEW {
                let name: String = Input::new()
                    .with_prompt(format!("New {backend_label} secret name"))
                    .default(default_secret_name.to_string())
                    .interact_text()
                    .map_err(|e| AppError::Config(format!("input error: {e}")))?;
                Ok(name)
            } else {
                Ok(items.remove(idx))
            }
        }
        Ok(_) => {
            eprintln!("  No existing secrets found in {backend_label} — you'll create a new one.");
            let name: String = Input::new()
                .with_prompt(&prompt_label)
                .default(default_secret_name.to_string())
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;
            Ok(name)
        }
        Err(e) => {
            eprintln!(
                "  Could not list existing {backend_label} secrets ({e}); falling back to manual entry."
            );
            let name: String = Input::new()
                .with_prompt(&prompt_label)
                .default(default_secret_name.to_string())
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;
            Ok(name)
        }
    }
}

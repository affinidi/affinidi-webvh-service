//! Interactive setup-wizard helper for picking a secrets storage backend.
//!
//! Shared between the four setup wizards (did-hosting-control, did-hosting-server,
//! webvh-witness, did-hosting-daemon). Each wizard supplies its own default
//! secret name and keyring service; the rest — backend selection,
//! connection-param prompts, and the existing-secrets picker — is
//! identical, so it lives here.
//!
//! Listing existing secrets is best-effort: when the cloud SDK can't
//! authenticate (no creds, network down, IAM denied) we surface a
//! one-line warning and fall back to a free-text input.

use dialoguer::{Input, Select};

use crate::server::config::SecretsConfig;
use crate::server::error::AppError;

use super::SecretBackend;

/// Prompt the operator for a secrets backend and its connection params.
///
/// Returns a populated [`SecretsConfig`]. Behaviour:
///
/// 1. Lists every secrets backend compiled into the binary
///    (`keyring`, `aws-secrets`, `gcp-secrets`, `azure-secrets`,
///    `vault-secrets`, `k8s-secrets`).
/// 2. Leaves the OS keyring out when this host has none (a headless Linux
///    box with no Secret Service). If no secure backend is left, refuses with
///    the list of secure backends — the interactive wizard never offers
///    plaintext; tests use a recipe with `confirm_plaintext = true`.
/// 3. For cloud backends (AWS/GCP/Azure), collects connection params
///    (region/project/vault URL), then attempts to list existing
///    secrets. On success, the operator picks from the list or
///    enters a new name; on failure the wizard falls back to a
///    free-text input with a warning. HashiCorp Vault and Kubernetes
///    Secret backends collect their connection params via free-text
///    prompts (no server-side secret enumeration).
#[allow(clippy::vec_init_then_push, unused_variables)]
pub async fn prompt_secrets_backend(
    default_secret_name: &str,
    default_keyring_service: &str,
) -> Result<SecretsConfig, AppError> {
    #[allow(unused_mut)]
    let mut backends: Vec<&str> = Vec::new();

    #[cfg(feature = "keyring")]
    match super::ensure_keyring() {
        Ok(()) => backends.push("OS Keyring (default)"),
        Err(e) => {
            eprintln!();
            eprintln!("  The OS keyring is not offered: {e}");
            eprintln!();
        }
    }

    #[cfg(feature = "aws-secrets")]
    backends.push("AWS Secrets Manager");

    #[cfg(feature = "gcp-secrets")]
    backends.push("GCP Secret Manager");

    #[cfg(feature = "azure-secrets")]
    backends.push("Azure Key Vault");

    #[cfg(feature = "vault-secrets")]
    backends.push("HashiCorp Vault");

    #[cfg(feature = "k8s-secrets")]
    backends.push("Kubernetes Secret");

    if backends.is_empty() {
        return Err(super::no_secure_store(
            "no secure secrets backend is compiled into this binary and usable on this host",
        ));
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
                vti_secrets::discovery::list_aws_secrets(region_opt.as_deref())
                    .await
                    .map_err(super::from_vti),
            )?;

            secrets_config.backend = Some(SecretBackend::Aws);
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
                vti_secrets::discovery::list_gcp_secrets(&project)
                    .await
                    .map_err(super::from_vti),
            )?;

            secrets_config.backend = Some(SecretBackend::Gcp);
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
                vti_secrets::discovery::list_azure_secrets(&vault_url)
                    .await
                    .map_err(super::from_vti),
            )?;

            secrets_config.backend = Some(SecretBackend::Azure);
            secrets_config.azure_vault_url = Some(vault_url);
            secrets_config.azure_secret_name = Some(name);
        }
        #[cfg(feature = "vault-secrets")]
        s if s.starts_with("HashiCorp") => {
            let addr: String = Input::new()
                .with_prompt("Vault address (e.g. https://vault.example.com:8200)")
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

            let secret_path: String = Input::new()
                .with_prompt("KV v2 secret path (e.g. webvh/server-secrets)")
                .default(default_secret_name.to_string())
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

            let kv_mount: String = Input::new()
                .with_prompt("KV v2 mount path")
                .default("secret".to_string())
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

            let auth_methods = ["kubernetes", "token", "approle"];
            let auth_idx = Select::new()
                .with_prompt("Vault auth method")
                .items(auth_methods.as_slice())
                .default(0)
                .interact()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;
            let auth_method = auth_methods[auth_idx];

            match auth_method {
                "kubernetes" => {
                    let role: String = Input::new()
                        .with_prompt("Vault Kubernetes auth role")
                        .interact_text()
                        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
                    secrets_config.vault_k8s_role = Some(role);
                }
                "token" => {
                    // Prefer the VAULT_TOKEN env var over persisting a token
                    // to the config file — leaving this empty does exactly that.
                    let token: String = Input::new()
                        .with_prompt("Vault token (leave empty to use the VAULT_TOKEN env var)")
                        .default(String::new())
                        .allow_empty(true)
                        .interact_text()
                        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
                    if !token.is_empty() {
                        secrets_config.vault_token = Some(token);
                    }
                }
                _ => {
                    let role_id: String = Input::new()
                        .with_prompt("AppRole role_id")
                        .interact_text()
                        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
                    let secret_id: String = Input::new()
                        .with_prompt("AppRole secret_id")
                        .interact_text()
                        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
                    secrets_config.vault_approle_role_id = Some(role_id);
                    secrets_config.vault_approle_secret_id = Some(secret_id);
                }
            }

            secrets_config.backend = Some(SecretBackend::Vault);
            secrets_config.vault_addr = Some(addr);
            secrets_config.vault_secret_path = Some(secret_path);
            secrets_config.vault_kv_mount = kv_mount;
            secrets_config.vault_auth_method = auth_method.to_string();
        }
        #[cfg(feature = "k8s-secrets")]
        s if s.starts_with("Kubernetes") => {
            let name: String = Input::new()
                .with_prompt("Kubernetes Secret name")
                .default(default_secret_name.to_string())
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

            let namespace: String = Input::new()
                .with_prompt("Kubernetes namespace (leave empty for the pod's default namespace)")
                .default(String::new())
                .allow_empty(true)
                .interact_text()
                .map_err(|e| AppError::Config(format!("input error: {e}")))?;

            secrets_config.backend = Some(SecretBackend::Kubernetes);
            secrets_config.k8s_secret_name = Some(name);
            if !namespace.is_empty() {
                secrets_config.k8s_namespace = Some(namespace);
            }
        }
        _ => {
            // The OS keyring — the only other entry in the list.
            secrets_config.backend = Some(SecretBackend::Keyring);
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

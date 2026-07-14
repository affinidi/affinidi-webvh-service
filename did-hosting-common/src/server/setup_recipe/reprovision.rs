//! Re-run safety scan for non-interactive setup.
//!
//! Mirrors the mediator-setup wizard's `inspect_existing` / `refuse_overwrite`
//! pattern. Before any headless setup path overwrites a live deployment,
//! we probe the configured secret backend for an existing `ServerSecrets`
//! entry. If one exists we refuse (exit 4) unless `--force-reprovision`
//! is set.
//!
//! Why scan secrets instead of just checking for `config.toml`? Because
//! the config file is recoverable from `config.toml.bak` (the interactive
//! wizard already does that); the *credentials* are not. Silently
//! rotating them invalidates issued JWTs and breaks active VTA sessions.

use std::path::Path;

use crate::server::config::SecretsConfig;
use crate::server::error::AppError;
use crate::server::secret_store::{ServerSecrets, create_secret_store};

/// Outcome of probing a configured secret backend.
#[derive(Debug)]
pub struct ProvisionedScan {
    /// `true` when [`ServerSecrets`] were found — a live deployment.
    pub has_secrets: bool,
    /// `true` when the secret backend held a bootstrap seed (an offline
    /// phase 1 is mid-flight). Distinct from a fully provisioned install.
    pub has_bootstrap_seed: bool,
    /// `true` when a config file already exists at the recipe's
    /// `output.config_path`. Cheap local check; the wizard backs it up
    /// before overwriting.
    pub config_file_exists: bool,
}

impl ProvisionedScan {
    /// Treat as "provisioned" only when real credentials exist. A
    /// half-finished phase 1 (seed only) is not blocking — operators
    /// re-running phase 1 expect to overwrite their own state.
    pub fn is_provisioned(&self) -> bool {
        self.has_secrets
    }
}

/// Probe the configured backend without writing. Best-effort: backend
/// errors map to `has_secrets = false` and are reported as a warning,
/// because failing the scan would be more disruptive than the safety
/// guarantee it provides (the operator may have just renamed the
/// backend secret).
pub async fn inspect_existing(
    secrets_config: &SecretsConfig,
    config_path: &Path,
) -> ProvisionedScan {
    let config_file_exists = config_path.exists();

    let store = match create_secret_store(secrets_config, config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  Warning: reprovision scan could not open secret store: {e}");
            return ProvisionedScan {
                has_secrets: false,
                has_bootstrap_seed: false,
                config_file_exists,
            };
        }
    };

    let has_secrets = match store.get().await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            eprintln!("  Warning: reprovision scan failed to read existing secrets: {e}");
            false
        }
    };
    let has_bootstrap_seed = matches!(store.get_bootstrap_seed().await, Ok(Some(_)));

    ProvisionedScan {
        has_secrets,
        has_bootstrap_seed,
        config_file_exists,
    }
}

/// Refuse to overwrite. Prints a stable-formatted message to stderr so
/// CI scripts can grep for it, and returns an error suitable for
/// bubbling up to the binary's exit-code mapper.
pub fn refuse_overwrite(config_path: &Path, scan: &ProvisionedScan) -> AppError {
    eprintln!();
    eprintln!("  ┌─ REFUSING TO OVERWRITE PROVISIONED INSTALL ────────────");
    eprintln!("  │ Existing setup detected:");
    if scan.config_file_exists {
        eprintln!("  │   - config file: {}", config_path.display());
    }
    if scan.has_secrets {
        eprintln!("  │   - secret store contains ServerSecrets");
    }
    if scan.has_bootstrap_seed {
        eprintln!("  │   - secret store contains a pending bootstrap seed");
    }
    eprintln!("  │");
    eprintln!("  │ Rotating credentials silently:");
    eprintln!("  │   - invalidates any JWT this service has issued,");
    eprintln!("  │   - breaks the active VTA session,");
    eprintln!("  │   - requires every authenticated client to re-auth.");
    eprintln!("  │");
    eprintln!("  │ Options:");
    eprintln!("  │   - re-run with --force-reprovision to rotate anyway");
    eprintln!("  │     (this backs up config.toml to config.toml.bak first), or");
    eprintln!("  │   - run `uninstall` first to teardown the existing deployment.");
    eprintln!("  └────────────────────────────────────────────────────────");
    eprintln!();
    AppError::Config(format!(
        "refusing to overwrite provisioned install at {}",
        config_path.display()
    ))
}

/// Back up `config.toml` to `config.toml.bak` before overwriting. The
/// interactive wizard does the same — keep the file-level recovery path
/// identical so operators can roll back from the same `.bak` extension
/// regardless of which entry point ran.
pub fn back_up_config(config_path: &Path) -> std::io::Result<()> {
    if !config_path.exists() {
        return Ok(());
    }
    let bak = config_path.with_extension(
        config_path
            .extension()
            .map(|e| format!("{}.bak", e.to_string_lossy()))
            .unwrap_or_else(|| "bak".to_string()),
    );
    std::fs::copy(config_path, &bak)?;
    eprintln!(
        "  Existing {} backed up to {} before re-provisioning.",
        config_path.display(),
        bak.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

/// Delete every webvh-managed entry from the configured secret store
/// and remove the local config + companion files. Mirrors the
/// mediator-setup wizard's `run_uninstall`.
///
/// Returns the list of removed entries (for caller-side reporting) on
/// success. The caller is responsible for the interactive `DELETE`
/// confirmation in non-`yes` mode; this helper assumes confirmation has
/// already been obtained.
pub async fn run_uninstall_unchecked(
    secrets_config: &SecretsConfig,
    config_path: &Path,
    companion_files: &[&Path],
) -> Result<UninstallReport, AppError> {
    let mut report = UninstallReport::default();

    let store = create_secret_store(secrets_config, config_path)?;

    // Drop ServerSecrets — overwrite with an empty struct so the backend's
    // `set` path runs and any backend-specific cleanup happens. Some
    // backends (plaintext-in-config) treat empty as "remove this".
    //
    // Bootstrap seed clears via the trait method (no separate "delete"
    // primitive, but `clear_bootstrap_seed` does the right thing).
    if let Ok(Some(_)) = store.get().await {
        // Best-effort: write an empty ServerSecrets to force the backend
        // to either remove the entry or zero it out. For backends that
        // don't support empty (e.g. AWS where the entry must be deleted
        // outside-the-API), we surface the warning but continue.
        let blank = ServerSecrets {
            signing_key: String::new(),
            key_agreement_key: String::new(),
            jwt_signing_key: String::new(),
            vta_credential: None,
            retired: Vec::new(),
        };
        if let Err(e) = store.set(&blank).await {
            eprintln!("  Warning: could not clear ServerSecrets ({e})");
            report.secrets_cleared = false;
        } else {
            report.secrets_cleared = true;
        }
    }

    if let Err(e) = store.clear_bootstrap_seed().await {
        eprintln!("  Warning: could not clear bootstrap seed ({e})");
    } else {
        report.seed_cleared = true;
    }

    // Local files
    if config_path.exists() {
        match std::fs::remove_file(config_path) {
            Ok(()) => report.files_removed.push(config_path.to_path_buf()),
            Err(e) => eprintln!("  Warning: could not remove {}: {e}", config_path.display()),
        }
    }
    // `config.toml.bak` too — leaving it behind is misleading after teardown.
    let bak = config_path.with_extension(
        config_path
            .extension()
            .map(|e| format!("{}.bak", e.to_string_lossy()))
            .unwrap_or_else(|| "bak".to_string()),
    );
    if bak.exists()
        && let Ok(()) = std::fs::remove_file(&bak)
    {
        report.files_removed.push(bak);
    }

    for path in companion_files {
        if path.exists()
            && let Ok(()) = std::fs::remove_file(path)
        {
            report.files_removed.push(path.to_path_buf());
        }
    }

    Ok(report)
}

#[derive(Debug, Default)]
pub struct UninstallReport {
    pub secrets_cleared: bool,
    pub seed_cleared: bool,
    pub files_removed: Vec<std::path::PathBuf>,
}

/// Prompt the operator to type `DELETE` to confirm uninstall. Returns
/// `true` when confirmed. The CI path passes `--yes` and skips this.
#[cfg(feature = "setup-wizard")]
pub fn prompt_uninstall_confirmation(config_path: &Path) -> Result<bool, AppError> {
    use dialoguer::Input;

    eprintln!();
    eprintln!("  ┌─ UNINSTALL ───────────────────────────────────────────");
    eprintln!("  │ This will:");
    eprintln!("  │   - delete ServerSecrets from the configured backend,");
    eprintln!("  │   - clear any pending bootstrap seed,");
    eprintln!(
        "  │   - remove {} (and .bak if present).",
        config_path.display()
    );
    eprintln!("  │");
    eprintln!("  │ DIDs in the local store, ACL entries, and the data");
    eprintln!("  │ directory are NOT removed — delete those manually if");
    eprintln!("  │ you want a clean slate.");
    eprintln!("  └────────────────────────────────────────────────────────");
    eprintln!();

    let typed: String = Input::new()
        .with_prompt("Type DELETE to confirm")
        .default(String::new())
        .allow_empty(true)
        .interact_text()
        .map_err(|e| AppError::Config(format!("input error: {e}")))?;
    Ok(typed.trim() == "DELETE")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn provisioned_scan_only_flags_when_secrets_present() {
        let s = ProvisionedScan {
            has_secrets: false,
            has_bootstrap_seed: true,
            config_file_exists: true,
        };
        assert!(!s.is_provisioned());
        let s = ProvisionedScan {
            has_secrets: true,
            has_bootstrap_seed: false,
            config_file_exists: false,
        };
        assert!(s.is_provisioned());
    }

    #[test]
    fn back_up_config_skips_missing_file() {
        // Verifies the no-op branch doesn't error on a fresh install.
        let p = PathBuf::from("/tmp/__webvh_does_not_exist__/config.toml");
        back_up_config(&p).expect("missing file is a no-op");
    }
}

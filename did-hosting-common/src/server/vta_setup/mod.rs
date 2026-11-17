//! Shared VTA (Verifiable Trust Architecture) setup helpers used by the
//! four webvh setup wizards (daemon, server, control, witness).
//!
//! The online flow is built on top of `vta_sdk::provision_client`
//! ([`online_provision_setup`]); the offline flow uses HPKE-sealed
//! transfer (`write_offline_bootstrap_request` /
//! `open_offline_bootstrap_response`).

use std::path::Path;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use vta_sdk::credentials::CredentialBundle;

use crate::server::config::TransportSelection;
use crate::server::setup_recipe::hosting_url_for;

mod cli;
mod export;
mod offline;
mod online;

pub use self::{cli::*, export::*, offline::*, online::*};

/// Error message rendered when an operator picks self-managed mode in a
/// non-daemon binary (server / control / witness). Kept as a single shared
/// constant so all three setup wizards print identical text — it's the
/// canonical "you wanted did-hosting-daemon, not this one" pointer.
pub const SELF_MANAGED_DAEMON_ONLY: &str = "self-managed mode is daemon-only in v1 — re-run setup with did-hosting-daemon. \
     See docs/self-managed-mode-spec.md for the full rationale.";

/// Atomically write `bytes` to `path` with mode 0600 on Unix.
///
/// Implementation: write to a sibling `<path>.tmp.<rand>` file with
/// `O_CREAT | O_EXCL` (so a concurrent attacker cannot trick us into reusing
/// a file they pre-created), `fchmod 0600` before any data lands, fsync,
/// then `rename` into place. The rename is atomic on Unix, so:
///
/// - There is no window where `path` exists at the process umask.
/// - Re-running the offline-bootstrap CLI over an existing seed file
///   succeeds rather than failing with `EEXIST` (the previous file is
///   replaced atomically).
/// - The temp file's permissions are set before the data is written, so
///   the bytes are never readable to any other UID.
///
/// On non-Unix targets, falls back to standard `fs::write` (file ACLs are
/// outside our control on Windows; the wizard prints the path so the operator
/// can lock it down).
fn write_secret_file_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut tmp_path = path.to_path_buf();
        // 128-bit random suffix gives a collision-free name across concurrent
        // wizard runs in the same directory.
        let suffix: u128 = rand::random::<u128>();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "secret".to_string());
        tmp_path.set_file_name(format!(".{file_name}.tmp.{suffix:032x}"));

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);

        // Atomic replace. On any error before this point we leave behind
        // the tmp file, which is locked to the running user — acceptable
        // and recoverable (the operator can re-run; the tmp name is unique).
        match std::fs::rename(&tmp_path, path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                Err(e)
            }
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Resolve the mediator DID from the VTA's DID document.
///
/// Looks for a `DIDCommMessaging` service endpoint in the VTA DID document
/// that contains a DID URI (the mediator). `Ok(None)`: the document names
/// no mediator. `Err`: the VTA DID could not be resolved (or resolution
/// timed out) — a different answer, which the wizard reports as such.
pub async fn resolve_vta_mediator(vta_did: &str) -> Result<Option<String>, String> {
    // Use a timeout — DID resolution may hang if the network is unreachable
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        vta_sdk::session::resolve_mediator_did(vta_did),
    )
    .await
    {
        Ok(Ok(mediator)) => Ok(mediator),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out after 10s".to_string()),
    }
}

/// The wizards' mediator discovery: [`resolve_vta_mediator`], telling the
/// operator which of "no mediator advertised" and "could not resolve the VTA
/// DID" happened, so a resolution failure is not mistaken for a VTA without
/// a mediator. Returns the mediator to offer, if any.
pub async fn discover_vta_mediator(vta_did: &str) -> Option<String> {
    eprintln!("  Checking VTA for mediator configuration...");
    match resolve_vta_mediator(vta_did).await {
        Ok(Some(mediator)) => Some(mediator),
        Ok(None) => {
            eprintln!("  The VTA's DID document advertises no mediator.");
            None
        }
        Err(e) => {
            eprintln!(
                "  Could not resolve the VTA DID ({e}), so its mediator cannot be offered. \
                 Check the VTA DID and network access, or enter a mediator DID by hand."
            );
            None
        }
    }
}

/// Generate a standalone did:key admin identity (no VTA needed).
///
/// Returns `(did_string, private_key_multibase)`.
pub fn generate_admin_did_key() -> (String, String) {
    let secret = Secret::generate_ed25519(None, None);
    let pk_multibase = secret
        .get_public_keymultibase()
        .expect("ed25519 public key multibase");
    let sk_multibase = secret
        .get_private_keymultibase()
        .expect("ed25519 private key multibase");
    let did = format!("did:key:{pk_multibase}");
    (did, sk_multibase)
}

/// Write a DID log entry to a file for later bootstrap on did-hosting-server.
pub fn write_log_entry_file(log_entry: &str, output_path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, log_entry)
}

/// Generate a random Ed25519 key and return its multibase-encoded private key.
pub fn generate_ed25519_multibase() -> String {
    let secret = Secret::generate_ed25519(None, None);
    secret
        .get_private_keymultibase()
        .expect("ed25519 multibase encoding")
}

#[cfg(test)]
#[path = "vta_setup_tests.rs"]
mod tests;

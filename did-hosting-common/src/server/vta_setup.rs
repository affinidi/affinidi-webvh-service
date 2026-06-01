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
/// that contains a DID URI (the mediator). Returns `None` if no mediator
/// is configured, if DID resolution fails, or if resolution times out.
pub async fn resolve_vta_mediator(vta_did: &str) -> Option<String> {
    eprintln!("  Checking VTA for mediator configuration...");

    // Use a timeout — DID resolution may hang if the network is unreachable
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        vta_sdk::session::resolve_mediator_did(vta_did),
    )
    .await
    {
        Ok(Ok(mediator)) => mediator,
        Ok(Err(_)) | Err(_) => None,
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

// ---------------------------------------------------------------------------
// Online provision-integration helper
//
// Wraps the SDK's `vta_sdk::provision_client::run_provision` for the three
// webvh setup wizards. Each binary owns its own dialoguer prompts (config
// path, public URL, host/port, log/data dir, secrets backend, mediator
// choice, admin ACL) and calls into here for the VTA round-trip itself.
// ---------------------------------------------------------------------------

/// Inputs the consumer (each binary's setup wizard) gathers before
/// invoking the online provision-integration round-trip.
pub struct OnlineProvisionInputs {
    /// VTA DID the integration is provisioning into.
    pub vta_did: String,
    /// VTA context the integration will live in.
    pub context_id: String,
    /// Pre-built `ProvisionAsk` (e.g. from
    /// `ProvisionAsk::did_hosting_daemon` or `did_hosting_server`).
    pub ask: vta_sdk::provision_client::ProvisionAsk,
    /// Per-binary user-facing labels and `pnm contexts create` command
    /// hint.
    pub messages: std::sync::Arc<dyn vta_sdk::provision_client::OperatorMessages>,
    /// Setup did:key the operator just enrolled at the VTA via the
    /// printed PNM command. The wizard mints + persists this; we
    /// consume it here.
    pub setup_key: vta_sdk::provision_client::EphemeralSetupKey,
}

/// Result of a successful online provision-integration round-trip,
/// flattened into the shape the wizard needs to write `ServerSecrets`,
/// `AppConfig`, the DID document log file, and the local DID store.
pub struct OnlineProvisionOutcome {
    /// Integration DID minted by the VTA (the binary's own service DID).
    pub integration_did: String,
    /// Multibase-encoded Ed25519 signing key for the integration DID.
    pub integration_signing_key_mb: String,
    /// Multibase-encoded X25519 key-agreement key for the integration DID.
    pub integration_ka_key_mb: String,
    /// `did.jsonl` content for the integration DID. Present when the
    /// template emitted a `WebvhLog` output (every webvh template does
    /// today).
    pub did_log_entry: Option<String>,
    /// Long-term admin DID. Equals the rolled-over DID minted by the
    /// VTA's `vta-admin` template render; the ephemeral setup DID is
    /// throwaway after this point.
    pub admin_did: String,
    /// Multibase-encoded Ed25519 private key paired with `admin_did`.
    pub admin_signing_key_mb: String,
    /// VTA DID the integration was provisioned against. Echoed back so
    /// the wizard can populate `config.vta.did` and run mediator lookup.
    pub vta_did: String,
    /// REST URL advertised by the VTA's DID document. Persisted so the
    /// runtime can re-authenticate without re-resolving the VTA DID.
    pub vta_url: Option<String>,
    /// Pre-encoded `vta_credential` value for `ServerSecrets` — base64url
    /// of a JSON `CredentialBundle` keyed to the rolled-over admin DID.
    /// The runtime path is unchanged: it deserialises this and calls
    /// `SessionStore::login` exactly like before.
    pub vta_credential_b64: String,
}

/// Drive the online provision-integration round-trip end-to-end.
///
/// The wizard is responsible for everything around this call: minting +
/// printing + confirming the setup DID, prompting for VTA DID / context,
/// picking the ask, etc. This helper just runs the round-trip, drains
/// progress events to stderr, and flattens the reply into the shape the
/// wizard's persistence layer needs.
pub async fn online_provision_setup(
    inputs: OnlineProvisionInputs,
) -> Result<OnlineProvisionOutcome, Box<dyn std::error::Error>> {
    use vta_sdk::provision_client::{VtaIntent, VtaReply, run_provision};

    let OnlineProvisionInputs {
        vta_did,
        context_id: _context_id,
        ask,
        messages,
        setup_key,
    } = inputs;

    let setup_did = setup_key.did.clone();
    let setup_pk_mb = setup_key.private_key_multibase().to_string();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let drain = tokio::spawn(async move { drain_provision_events_to_stderr(&mut rx).await });

    let reply = run_provision(
        VtaIntent::FullSetup,
        vta_did.clone(),
        setup_did,
        setup_pk_mb.clone(),
        ask,
        None,
        messages,
        tx,
    )
    .await?;

    // Make sure the event drain finishes before we keep going so the
    // operator sees the final lines before our success summary.
    let _ = drain.await;

    let result = match reply {
        VtaReply::Full(boxed) => *boxed,
        VtaReply::AdminOnly(_) => {
            return Err(
                "VTA returned an AdminOnly reply but FullSetup was requested — \
                 this is a wiring bug; please report"
                    .into(),
            );
        }
    };

    let integration_did = result
        .integration_did()
        .ok_or("provision reply missing integration DID")?
        .to_string();
    let integration_keys = result
        .integration_key()
        .ok_or("provision reply missing integration key material")?;
    let integration_signing_key_mb = integration_keys.signing_key.private_key_multibase.clone();
    let integration_ka_key_mb = integration_keys.ka_key.private_key_multibase.clone();

    let did_log_entry = result.webvh_log().map(str::to_string);

    let admin_did = result.admin_did().to_string();
    let admin_signing_key_mb = match result.admin_key() {
        Some(km) => km.signing_key.private_key_multibase.clone(),
        // No rollover happened: the setup DID *is* the long-term admin
        // DID. Fall back to the setup key's private half.
        None => setup_pk_mb.clone(),
    };

    let vta_url = result.payload.config.vta_url.clone();

    let vta_credential_b64 = build_vta_credential_b64(
        &admin_did,
        &admin_signing_key_mb,
        &vta_did,
        vta_url.as_deref(),
    )?;

    Ok(OnlineProvisionOutcome {
        integration_did,
        integration_signing_key_mb,
        integration_ka_key_mb,
        did_log_entry,
        admin_did,
        admin_signing_key_mb,
        vta_did,
        vta_url,
        vta_credential_b64,
    })
}

/// Build the `ServerSecrets.vta_credential` value (base64url of a JSON
/// `CredentialBundle`) from the rolled-over admin DID + key, so the
/// runtime path that calls `SessionStore::login` keeps working unchanged.
pub fn build_vta_credential_b64(
    admin_did: &str,
    admin_signing_key_mb: &str,
    vta_did: &str,
    vta_url: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let bundle = CredentialBundle {
        did: admin_did.to_string(),
        private_key_multibase: admin_signing_key_mb.to_string(),
        vta_did: vta_did.to_string(),
        vta_url: vta_url.map(str::to_string),
    };
    let json = serde_json::to_vec(&bundle)?;
    Ok(BASE64.encode(json))
}

/// Drain `VtaEvent`s emitted by the SDK and render each as a single
/// line on stderr. Intentionally minimal — the daemon/server/control
/// wizards are non-TUI, so the operator just sees a checklist scroll
/// past as the round-trip progresses.
async fn drain_provision_events_to_stderr(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<vta_sdk::provision_client::VtaEvent>,
) {
    use vta_sdk::provision_client::{DiagStatus, VtaEvent};

    while let Some(event) = rx.recv().await {
        match event {
            VtaEvent::CheckStart(check) => {
                eprintln!("  [..] {}", check.label());
            }
            VtaEvent::CheckDone(check, status) => match status {
                DiagStatus::Pending | DiagStatus::Running => {}
                DiagStatus::Ok(detail) => eprintln!("  [OK] {}  {detail}", check.label()),
                DiagStatus::Skipped(detail) => eprintln!("  [--] {}  {detail}", check.label()),
                DiagStatus::Failed(detail) => eprintln!("  [!!] {}  {detail}", check.label()),
            },
            VtaEvent::Resolved(_)
            | VtaEvent::AttemptCompleted { .. }
            | VtaEvent::PreflightDone { .. } => {
                // These are inputs to interactive UIs (recovery prompts,
                // did-hosting-server pickers) that the non-TUI wizards don't
                // surface. The runner uses 0/1-server auto-pick anyway.
            }
            VtaEvent::Connected { protocol, .. } => {
                eprintln!();
                eprintln!("  Connected via {}", protocol.label());
            }
            VtaEvent::Failed(reason) => {
                eprintln!();
                eprintln!("  ✗ {reason}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Offline (sealed-bundle) bootstrap
//
// The online flow above calls the VTA directly over DIDComm. For air-gapped
// VTA deployments the consumer instead:
//
//   1. Generates an ephemeral Ed25519 keypair + nonce and writes a
//      `bootstrap-request.json` file. The operator ferries this to the VTA
//      admin box and runs `vta bootstrap seal --request …` against the
//      pinned context, producing an ASCII-armored sealed bundle plus a
//      SHA-256 digest of the ciphertext (communicated out-of-band).
//   2. Copies the armored bundle back, and runs the open step with the
//      expected digest. Open:
//         - verifies the canonical digest,
//         - opens the HPKE-sealed chunks with the persisted seed,
//         - extracts the VTA-rendered DID document, key material, and
//           signed-DID log from the `TemplateBootstrapPayload`.
//
// The same template (`did-hosting-daemon`, `did-hosting-control`, `did-hosting-server`)
// drives both the online and offline paths, so the persisted DID shape
// is identical to what `online_provision_setup` above produces.
// ---------------------------------------------------------------------------

/// Information returned after writing an offline bootstrap request.
///
/// The operator uses `client_did` + `nonce` to eyeball that the request
/// they're sealing is the one we just produced (no swapping).
#[derive(Debug, Clone)]
pub struct OfflineRequestInfo {
    /// Ephemeral `did:key:z6Mk…` identifying this request.
    pub client_did: String,
    /// Base64url-encoded 16-byte nonce. Becomes the bundle_id after seal.
    pub nonce: String,
    /// Path of the written request JSON.
    pub request_path: std::path::PathBuf,
    /// Raw 32-byte ephemeral seed. **Treat as secret.** The caller is
    /// responsible for persisting this in their secret store
    /// (`SecretStore::set_bootstrap_seed`); it is the X25519-derivable
    /// private half needed to open the sealed response in phase 2.
    pub seed: [u8; 32],
}

/// Rich result of opening an offline bootstrap response.
///
/// Shaped to feed the same secret-store / DID-bootstrap plumbing the
/// online path uses, plus the extra VTA trust material the sealed
/// bundle carries (authorization VC, pinned VTA DID, trust bundle).
#[derive(Debug, Clone)]
pub struct OfflineBootstrapResult {
    /// Integration DID — the service's own `did:webvh:…` identifier.
    pub did: String,
    /// Multibase-encoded Ed25519 private signing key for the integration DID.
    pub signing_key_multibase: String,
    /// Multibase-encoded X25519 private key agreement key for the integration DID.
    pub key_agreement_multibase: String,
    /// Rendered DID document (published verbatim on the webvh host).
    pub did_document: serde_json::Value,
    /// JSONL DID log when the template emitted a `WebvhLog` output. Most
    /// webvh consumers will get one; `None` indicates the template did
    /// not ask the VTA to produce a signed log.
    pub log_entry: Option<String>,
    /// VTA-issued authorization credential (opaque VC).
    pub authorization_vc: serde_json::Value,
    /// Pinned VTA DID (store for future offline VC verification).
    pub vta_did: String,
    /// VTA REST URL (store for future online re-auth, if we ever need it).
    pub vta_url: Option<String>,
    /// Admin DID — the long-term operator DID the VTA rolled over to.
    /// Present when the VTA's `vta-admin` template ran during provision-
    /// integration; absent when the VTA disabled rollover and the
    /// integration DID is also the admin identity. Use for seeding the
    /// service's ACL with the operator's long-term identity.
    pub admin_did: Option<String>,
    /// Multibase-encoded Ed25519 private signing key for the admin DID.
    /// Present iff `admin_did` is. Use for downstream operations that
    /// need to authenticate as the admin (passkey enrolment, manual
    /// DIDComm flows, etc.).
    pub admin_signing_key_multibase: Option<String>,
}

/// Write an offline bootstrap request and return the in-memory ephemeral seed.
///
/// `template` and `vars` describe the target DID template (e.g.
/// `did-hosting-server` + `MEDIATOR_DID`, or `did-hosting-control` + `URL` +
/// `MEDIATOR_DID`); `context_id` is embedded as the
/// VP's `contextHint` so the VTA admin can run `vta bootstrap
/// provision-integration` without `--context`. The resulting
/// **VP-framed** `BootstrapRequest` is what `vta bootstrap
/// provision-integration` consumes on the producer side. The VP's
/// `validUntil` is set to 7 days from now to give operators headroom
/// for the manual seal/return round-trip.
///
/// The caller hands `request_path` to the VTA operator and persists the
/// returned `seed` in their secret store via
/// `SecretStore::set_bootstrap_seed` — never to disk. The seed is the
/// X25519-derivable private half needed to open the sealed response in
/// phase 2.
pub async fn write_offline_bootstrap_request(
    request_path: &Path,
    template: &str,
    vars: &[(&str, &str)],
    context_id: &str,
    label: Option<&str>,
) -> Result<OfflineRequestInfo, Box<dyn std::error::Error>> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use vta_sdk::provision_integration::ProvisionRequestBuilder;

    let mut builder = ProvisionRequestBuilder::new(template)
        .context_hint(context_id)
        .validity(chrono::Duration::days(7));
    for (k, v) in vars {
        builder = builder.var(*k, *v);
    }
    if let Some(l) = label {
        builder = builder.label(l);
    }

    let signed = builder.sign_ephemeral().await?;
    let request_json = serde_json::to_string_pretty(&signed.request)?;

    if let Some(parent) = request_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(request_path, request_json)?;

    // Copy the seed out of the Zeroizing wrapper so it can be persisted
    // by the secret store — caller is responsible for handling it
    // carefully from here on.
    let seed_bytes: [u8; 32] = *signed.seed;
    let nonce_b64 = B64.encode(signed.bundle_id);

    Ok(OfflineRequestInfo {
        client_did: signed.client_did,
        nonce: nonce_b64,
        request_path: request_path.to_path_buf(),
        seed: seed_bytes,
    })
}

/// Open a sealed bootstrap response and extract the provisioned identity.
///
/// `bundle_armor` is the ASCII-armored sealed bundle the operator
/// ferries back (contents of what `vta bootstrap seal` produced).
/// `expect_digest` is the lowercase hex SHA-256 the operator communicated
/// out-of-band; `open_bundle` rejects the bundle in constant time if it
/// doesn't match, and for `PinnedOnly` producer assertions this is the
/// only trust anchor.
///
/// `seed` is the 32-byte ephemeral seed `write_offline_bootstrap_request`
/// returned and the caller persisted in their secret store
/// (`SecretStore::set_bootstrap_seed`). Phase 2 reads it back via
/// `SecretStore::get_bootstrap_seed`.
pub fn open_offline_bootstrap_response(
    bundle_armor: &str,
    expect_digest: &str,
    seed: &[u8; 32],
) -> Result<OfflineBootstrapResult, Box<dyn std::error::Error>> {
    use vta_sdk::sealed_transfer::template_bootstrap::TemplateOutput;
    use vta_sdk::sealed_transfer::{
        SealedPayloadV1, armor, ed25519_seed_to_x25519_secret, open_bundle,
    };

    let recipient_secret = ed25519_seed_to_x25519_secret(seed);

    // Decode the armor. We only expect a single bundle per response.
    let bundles = armor::decode(bundle_armor)?;
    let bundle = match bundles.as_slice() {
        [one] => one,
        other => {
            return Err(format!(
                "expected exactly 1 sealed bundle in armor, got {}",
                other.len()
            )
            .into());
        }
    };

    // `open_bundle` handles digest check, HPKE open, chunk reassembly,
    // and the PinnedOnly → digest-required coupling check.
    let opened = open_bundle(&recipient_secret, bundle, Some(expect_digest))?;

    let payload = match opened.payload {
        SealedPayloadV1::TemplateBootstrap(boxed) => *boxed,
        _ => return Err("sealed response was not a TemplateBootstrap payload".into()),
    };

    // Pick the integration DID's key material by matching against
    // `config.did_document.id`. The payload carries a map keyed by DID
    // and may include both an integration entry and an admin-rolled-over
    // entry when the VTA enabled admin rollover; relying on the BTreeMap
    // iteration order would silently pick the alphabetically-first DID
    // (typically the admin did:key, since "did:key:..." sorts before
    // "did:webvh:...").
    let integration_did = payload
        .config
        .did_document
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("sealed payload missing config.did_document.id")?
        .to_string();
    let mut secrets_map = payload.secrets;
    let integration_key_material = secrets_map
        .remove(&integration_did)
        .or_else(|| {
            // Forward-compat fallback: if the payload doesn't carry a
            // matching entry (e.g. because a future template renames the
            // canonical DID field), accept the first secret as a last
            // resort. Logged so an operator can correlate with the wire.
            tracing::warn!(
                integration_did = %integration_did,
                "sealed payload secrets map does not contain integration DID; falling back to first entry",
            );
            // Take the first remaining entry without consuming the whole
            // map — the next block needs the leftover entries to find
            // the admin material.
            let key = secrets_map.keys().next().cloned()?;
            secrets_map.remove(&key)
        })
        .ok_or("sealed payload has no secrets")?;

    // Any remaining entry is the admin DID rolled over by the VTA's
    // `vta-admin` template. Surface it so the wizard can seed the
    // service's ACL with the operator's long-term identity. The VTA
    // emits at most one rolled-over admin per provision-integration; if
    // future templates emit more we'd surface only the first and log,
    // matching the integration DID fallback.
    let admin_entry = secrets_map.into_iter().next();
    let (admin_did, admin_signing_key_multibase) = match admin_entry {
        Some((_did, mat)) => (Some(mat.did), Some(mat.signing_key.private_key_multibase)),
        None => (None, None),
    };

    let log_entry = payload.config.outputs.iter().find_map(|o| match o {
        TemplateOutput::WebvhLog { log, .. } => Some(log.clone()),
        _ => None,
    });

    Ok(OfflineBootstrapResult {
        did: integration_key_material.did,
        signing_key_multibase: integration_key_material.signing_key.private_key_multibase,
        key_agreement_multibase: integration_key_material.ka_key.private_key_multibase,
        did_document: payload.config.did_document,
        log_entry,
        authorization_vc: payload.authorization,
        vta_did: payload.config.vta_trust.vta_did,
        vta_url: payload.config.vta_url,
        admin_did,
        admin_signing_key_multibase,
    })
}

// ---------------------------------------------------------------------------
// CLI wrappers
//
// Thin, user-facing wrappers around the primitives above. Each service's
// `main.rs` gets a pair of subcommands by delegating here rather than
// re-printing the same operator instructions in three places.
// ---------------------------------------------------------------------------

/// How the `run_offline_open_cli` handler should describe the final
/// "feed these keys into your secret store" step. Kept small and
/// type-driven so each service picks the shape that matches its own CLI.
#[derive(Debug, Clone, Copy)]
pub enum OfflineOpenNextStep<'a> {
    /// Service already has an `import-secrets` subcommand that takes
    /// `--signing-key` and `--ka-key` multibase flags (e.g. did-hosting-server,
    /// webvh-witness). The instruction tells the operator to run it with
    /// the keys from the secrets JSON.
    ImportSecrets {
        /// The binary name to put in the suggested command line.
        binary: &'a str,
    },
    /// Service has no import-secrets subcommand yet; point at its
    /// interactive setup wizard (e.g. did-hosting-control).
    Setup {
        /// The binary name to put in the suggested command line.
        binary: &'a str,
    },
}

/// CLI-facing wrapper around [`write_offline_bootstrap_request`]. Writes
/// a VP-framed bootstrap request targeting `template` with the supplied
/// `vars` bindings, persists the ephemeral seed to `seed_path`
/// (chmod 0600 on Unix), and prints step-by-step operator instructions.
///
/// Each binary picks its own template + vars:
/// - `webvh-witness` → `"did-hosting-server"` + `[("MEDIATOR_DID", ...)]`
/// - `did-hosting-server`  → `"did-hosting-daemon"` + `[("URL", ...)]`
/// - `did-hosting-control` → `"did-hosting-control"` + `[("URL", ...), ("MEDIATOR_DID", ...)]`
///
/// Note: this is the **standalone-CLI** entry point (`vta-request`) for
/// operators managing files explicitly. The wizard's `setup-offline-prepare`
/// flow uses `SecretStore::set_bootstrap_seed` instead — no seed file.
pub async fn run_offline_request_cli(
    out: &Path,
    seed_path: &Path,
    label: &str,
    binary: &str,
    template: &str,
    vars: &[(&str, &str)],
    context_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let info =
        write_offline_bootstrap_request(out, template, vars, context_id, Some(label)).await?;

    write_secret_file_0600(seed_path, &info.seed)?;

    eprintln!();
    eprintln!("  Offline bootstrap request ready.");
    eprintln!();
    eprintln!("  Request file:   {}", info.request_path.display());
    eprintln!("  Seed (secret):  {}", seed_path.display());
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
    eprintln!("         {binary} vta-open --bundle <bundle> --expect-digest <hex>");
    eprintln!();
    eprintln!("  KEEP THE SEED FILE. Losing it means you cannot open the response.");
    eprintln!();

    Ok(())
}

/// CLI-facing wrapper around [`open_offline_bootstrap_response`]. Opens
/// the armored bundle and writes three artifacts:
///
/// 1. `did_doc_out` — pretty-printed DID document JSON.
/// 2. `did_log_out` — signed DID log JSONL (only when the template
///    emitted a `WebvhLog` output).
/// 3. `secrets_out` — minted private keys + VTA trust material JSON,
///    chmod-0600 on Unix.
///
/// Prints the minted DID + VTA metadata and a per-service "next steps"
/// block picked from `next`.
pub fn run_offline_open_cli(
    bundle: &Path,
    expect_digest: &str,
    seed_path: &Path,
    did_doc_out: &Path,
    did_log_out: &Path,
    secrets_out: &Path,
    next: OfflineOpenNextStep<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let armor =
        std::fs::read_to_string(bundle).map_err(|e| format!("read {}: {e}", bundle.display()))?;

    let seed_bytes = std::fs::read(seed_path).map_err(|e| {
        format!(
            "failed to read ephemeral seed at {}: {e}",
            seed_path.display()
        )
    })?;
    let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "ephemeral seed at {} has {} bytes (expected 32)",
            seed_path.display(),
            seed_bytes.len()
        )
    })?;

    let result = open_offline_bootstrap_response(&armor, expect_digest, &seed)?;

    let did_doc_json = serde_json::to_string_pretty(&result.did_document)?;
    std::fs::write(did_doc_out, &did_doc_json)?;

    if let Some(ref log) = result.log_entry {
        std::fs::write(did_log_out, log)?;
    }

    let secrets_payload = serde_json::json!({
        "did": result.did,
        "signing_key_multibase": result.signing_key_multibase,
        "key_agreement_multibase": result.key_agreement_multibase,
        "admin_did": result.admin_did,
        "admin_signing_key_multibase": result.admin_signing_key_multibase,
        "vta_did": result.vta_did,
        "vta_url": result.vta_url,
        "authorization_vc": result.authorization_vc,
    });
    write_secret_file_0600(
        secrets_out,
        serde_json::to_string_pretty(&secrets_payload)?.as_bytes(),
    )?;

    eprintln!();
    eprintln!("  Sealed response opened.");
    eprintln!();
    eprintln!("  DID:            {}", result.did);
    eprintln!("  VTA DID:        {}", result.vta_did);
    if let Some(ref url) = result.vta_url {
        eprintln!("  VTA URL:        {url}");
    }
    eprintln!();
    eprintln!("  Wrote {}", did_doc_out.display());
    if result.log_entry.is_some() {
        eprintln!("  Wrote {}", did_log_out.display());
    } else {
        eprintln!("  No WebvhLog output in the sealed response — did_log_out not written.");
    }
    eprintln!("  Wrote {} (0600)", secrets_out.display());
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!("    1. Publish the DID document at <hosting-url>/<path>/did.jsonl using");
    eprintln!(
        "       `did-hosting-server bootstrap-did --did-log {}` on the hosting server.",
        did_log_out.display()
    );
    match next {
        OfflineOpenNextStep::ImportSecrets { binary } => {
            eprintln!("    2. Persist the keys via `{binary} import-secrets --signing-key");
            eprintln!("       <signing_key_multibase> --ka-key <key_agreement_multibase>`,");
            eprintln!("       using the values from {}.", secrets_out.display());
        }
        OfflineOpenNextStep::Setup { binary } => {
            eprintln!("    2. Run `{binary} setup` and, when the wizard asks for keys,");
            eprintln!("       feed in the `signing_key_multibase` and `key_agreement_multibase`");
            eprintln!("       values from {}.", secrets_out.display());
            eprintln!("       (A dedicated `import-secrets` subcommand for {binary} is");
            eprintln!("       planned; for now the setup wizard is the supported entry point.)");
        }
    }
    eprintln!();

    Ok(())
}

// ---------------------------------------------------------------------------
// Offline export (sealed outbound for migration / onboarding)
//
// The inverse of the offline bootstrap: take an already-provisioned webvh
// identity (DID + signing + KA keys) and hand it to another party through
// an HPKE-sealed bundle that matches the format their `open_bundle` path
// expects. The receiver must have already produced a
// `bootstrap-request.json` (same shape `write_offline_bootstrap_request`
// writes), containing their ephemeral did:key + nonce.
//
// Two assertion modes. `PinnedOnly` relies on the OOB digest as the
// sole integrity anchor; `DidSigned` additionally signs a domain-tagged
// message (`b"vta-sealed-transfer/v1\0" || client_x25519_pub ||
// bundle_id`) with the producer's Ed25519 key so the receiver can verify
// against the producer DID's `#key-0` pubkey. Prefer DidSigned when both
// sides have the pubkey available; fall back to PinnedOnly for
// pinned-digest-only deployments.
// ---------------------------------------------------------------------------

/// How the exporter builds its `ProducerAssertion`.
#[derive(Debug, Clone)]
pub enum ExportAssertionMode {
    /// No in-band proof. The receiver must verify the SHA-256 digest
    /// out-of-band — that's the only trust anchor.
    PinnedOnly,
    /// Sign a domain-tagged assertion with the exporter's Ed25519 key.
    /// `signing_key_multibase` is the private key (raw seed in multibase
    /// form, same shape we persist to the secret store). `verification_method`
    /// goes on the assertion verbatim — typically `{producer_did}#key-0`.
    DidSigned {
        signing_key_multibase: String,
        verification_method: String,
    },
}

/// Result of a successful export. Use `digest` as the OOB value the
/// receiver will pass as `--expect-digest` when opening the bundle.
#[derive(Debug, Clone)]
pub struct SealedExportInfo {
    /// Where the armored sealed bundle was written.
    pub out_path: std::path::PathBuf,
    /// SHA-256 of the bundle ciphertext, lowercase hex. Communicate
    /// this to the receiver out-of-band (email, phone, etc.). For a
    /// `PinnedOnly` producer assertion this is the *only* integrity
    /// anchor protecting the seal.
    pub digest: String,
    /// The receiver's ephemeral did:key (for the operator to
    /// eyeball-check which request they just sealed to).
    pub recipient_did: String,
    /// Hex-encoded 16-byte bundle id (same as the receiver's nonce).
    pub bundle_id_hex: String,
}

/// Seal an existing DID + its signing and key-agreement private keys as
/// a `DidSecrets` payload directed at the receiver described in
/// `request_path`.
///
/// `producer_did` goes into the `ProducerAssertion::producer_did` field —
/// typically the exporting service's own DID (e.g. `config.server_did`).
/// `did` is the DID the exported keys belong to (usually the same).
/// `signing_key_multibase` / `ka_key_multibase` are the private multibase
/// strings from the local secret store. Key IDs are derived as
/// `<did>#key-0` / `<did>#key-1` to match the upstream webvh templates.
pub async fn export_sealed_did_secrets(
    request_path: &Path,
    out_path: &Path,
    producer_did: &str,
    did: &str,
    signing_key_multibase: String,
    ka_key_multibase: String,
    assertion: ExportAssertionMode,
) -> Result<SealedExportInfo, Box<dyn std::error::Error>> {
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
    use vta_sdk::keys::KeyType;
    use vta_sdk::sealed_transfer::bundle::{AssertionProof, DidSignedAssertion, ProducerAssertion};
    use vta_sdk::sealed_transfer::verify::DID_SIGNED_DOMAIN_TAG;
    use vta_sdk::sealed_transfer::{
        BootstrapRequest, InMemoryNonceStore, SealedPayloadV1, armor, bundle_digest, seal_payload,
    };

    let req_json = std::fs::read_to_string(request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest = serde_json::from_str(&req_json)
        .map_err(|e| format!("parse {}: {e}", request_path.display()))?;

    let recipient_x25519 = request.decode_client_x25519_pub()?;
    let bundle_id = request.decode_nonce()?;

    let secrets = DidSecretsBundle {
        did: did.to_string(),
        secrets: vec![
            SecretEntry {
                key_id: format!("{did}#key-0"),
                key_type: KeyType::Ed25519,
                private_key_multibase: signing_key_multibase,
            },
            SecretEntry {
                key_id: format!("{did}#key-1"),
                key_type: KeyType::X25519,
                private_key_multibase: ka_key_multibase,
            },
        ],
    };
    let payload = SealedPayloadV1::DidSecrets(Box::new(secrets));

    let proof = match &assertion {
        ExportAssertionMode::PinnedOnly => AssertionProof::PinnedOnly,
        ExportAssertionMode::DidSigned {
            signing_key_multibase,
            verification_method,
        } => {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
            use ed25519_dalek::{Signer, SigningKey};

            // Extract the raw 32-byte Ed25519 seed from the multibase
            // private key string. We go through the affinidi-tdk Secret
            // helper so the multicodec framing matches however the key
            // was persisted at setup time.
            let signer_secret = Secret::from_multibase(signing_key_multibase, None)
                .map_err(|e| format!("invalid signing key: {e}"))?;
            let seed_bytes: [u8; 32] = signer_secret
                .get_private_bytes()
                .try_into()
                .map_err(|_| "signing key is not a 32-byte Ed25519 seed")?;
            let sk = SigningKey::from_bytes(&seed_bytes);

            // Domain-tagged message — matches the producer side of the
            // VTA's `build_did_signed_assertion` and what
            // `verify_did_signed_assertion_with_pubkey` checks.
            let mut msg = Vec::with_capacity(
                DID_SIGNED_DOMAIN_TAG.len() + recipient_x25519.len() + bundle_id.len(),
            );
            msg.extend_from_slice(DID_SIGNED_DOMAIN_TAG);
            msg.extend_from_slice(&recipient_x25519);
            msg.extend_from_slice(&bundle_id);
            let sig = sk.sign(&msg);

            AssertionProof::DidSigned(DidSignedAssertion {
                did: producer_did.to_string(),
                signature_b64: B64URL.encode(sig.to_bytes()),
                verification_method: verification_method.clone(),
            })
        }
    };

    let producer = ProducerAssertion {
        producer_did: producer_did.to_string(),
        proof,
    };

    // Each export is a one-shot operation, so a fresh in-memory nonce
    // store is sufficient — we only need the "is this bundle_id reused
    // within this call?" check, not cross-invocation history (the
    // receiver's nonce is a fresh 16-byte value anyway).
    let nonce_store = InMemoryNonceStore::new();

    let sealed = seal_payload(
        &recipient_x25519,
        bundle_id,
        producer,
        &payload,
        &nonce_store,
    )
    .await?;
    let digest = bundle_digest(&sealed);
    let armored = armor::encode(&sealed);

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, &armored).map_err(|e| format!("write {}: {e}", out_path.display()))?;

    Ok(SealedExportInfo {
        out_path: out_path.to_path_buf(),
        digest,
        recipient_did: request.client_did,
        bundle_id_hex: hex::encode(bundle_id),
    })
}

/// Result of opening a sealed `DidSecrets` migration bundle — the inverse
/// of [`export_sealed_did_secrets`]. Carries just the DID + key material
/// the exporter included (no DID document, no VTA trust bundle — those
/// live in a `TemplateBootstrap` bundle, not a `DidSecrets` one).
#[derive(Debug, Clone)]
pub struct SealedDidSecretsResult {
    pub did: String,
    pub signing_key_multibase: String,
    pub key_agreement_multibase: String,
    /// The producer DID the sealer claimed. With `PinnedOnly` assertions
    /// this is informational only; with `DidSigned` + a caller-supplied
    /// pubkey it has been cryptographically verified and `assertion_verified`
    /// is true.
    pub producer_did: String,
    /// True when the producer assertion was `DidSigned` and successfully
    /// verified against `expected_producer_pubkey`. False when the
    /// assertion was `PinnedOnly` (digest-only trust) or when no
    /// expected pubkey was supplied and the assertion was informational.
    pub assertion_verified: bool,
}

/// Open a sealed migration bundle produced by
/// [`export_sealed_did_secrets`] and surface the private key material
/// the exporter included.
///
/// Reads the ephemeral seed the receiver persisted at
/// `write_offline_bootstrap_request` time, verifies the OOB digest,
/// opens the HPKE-sealed payload, and asserts it is the `DidSecrets`
/// variant carrying one Ed25519 (signing) + one X25519 (key agreement)
/// entry keyed to the same DID.
///
/// `expected_producer_pubkey` enables `DidSigned` verification: when
/// supplied, the assertion MUST be `DidSigned`, its `producer_did` must
/// match the chunk header, and its signature must verify against the
/// given 32-byte Ed25519 pubkey. When `None`, the opener accepts both
/// `PinnedOnly` and `DidSigned` assertions and treats the producer
/// identity as informational (the OOB digest is the only anchor).
pub fn open_sealed_did_secrets(
    bundle_armor: &str,
    expect_digest: &str,
    seed_path: &Path,
    expected_producer_pubkey: Option<&[u8; 32]>,
) -> Result<SealedDidSecretsResult, Box<dyn std::error::Error>> {
    use vta_sdk::didcomm_light::ed25519_pub_to_x25519_pub;
    use vta_sdk::keys::KeyType;
    use vta_sdk::sealed_transfer::bundle::AssertionProof;
    use vta_sdk::sealed_transfer::verify::verify_did_signed_assertion_with_pubkey;
    use vta_sdk::sealed_transfer::{
        SealedPayloadV1, armor, ed25519_seed_to_x25519_secret, open_bundle,
    };

    let seed_bytes = std::fs::read(seed_path).map_err(|e| {
        format!(
            "failed to read ephemeral seed at {}: {e}",
            seed_path.display()
        )
    })?;
    if seed_bytes.len() != 32 {
        return Err(format!(
            "ephemeral seed at {} has {} bytes (expected 32)",
            seed_path.display(),
            seed_bytes.len()
        )
        .into());
    }
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .expect("checked length above");
    let recipient_secret = ed25519_seed_to_x25519_secret(&seed);

    let bundles = armor::decode(bundle_armor)?;
    let bundle = match bundles.as_slice() {
        [one] => one,
        other => {
            return Err(format!(
                "expected exactly 1 sealed bundle in armor, got {}",
                other.len()
            )
            .into());
        }
    };

    let opened = open_bundle(&recipient_secret, bundle, Some(expect_digest))?;

    // If the caller pinned the producer's Ed25519 pubkey, demand a
    // DidSigned assertion and verify the signature. Otherwise the
    // OOB digest stays the only anchor (matches the original behaviour).
    let mut assertion_verified = false;
    if let Some(expected_pubkey) = expected_producer_pubkey {
        match &opened.producer.proof {
            AssertionProof::DidSigned(assertion) => {
                // Derive client_x25519_pub from our own seed (what the
                // producer signed over). Ed25519 pub → X25519 pub is the
                // Montgomery-form conversion of the verifying key.
                use ed25519_dalek::SigningKey;
                let client_ed_pub = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
                let client_x_pub = ed25519_pub_to_x25519_pub(&client_ed_pub)
                    .map_err(|e| format!("derive client X25519 pubkey: {e}"))?;
                verify_did_signed_assertion_with_pubkey(
                    assertion,
                    &opened.producer.producer_did,
                    expected_pubkey,
                    &client_x_pub,
                    &opened.bundle_id,
                )
                .map_err(|e| format!("DidSigned verification failed: {e}"))?;
                assertion_verified = true;
            }
            AssertionProof::PinnedOnly => {
                return Err(
                    "expected DidSigned producer assertion but bundle carries PinnedOnly — \
                     either drop the expected pubkey to accept PinnedOnly, or ask the \
                     exporter to sign"
                        .into(),
                );
            }
            AssertionProof::Attested(_) => {
                return Err(
                    "expected DidSigned producer assertion but bundle carries Attested (Nitro); \
                     not supported in this flow"
                        .into(),
                );
            }
        }
    }

    let did_secrets = match opened.payload {
        SealedPayloadV1::DidSecrets(boxed) => *boxed,
        _ => return Err("sealed bundle was not a DidSecrets payload".into()),
    };

    let mut signing = None;
    let mut ka = None;
    for entry in did_secrets.secrets {
        match entry.key_type {
            KeyType::Ed25519 if signing.is_none() => signing = Some(entry.private_key_multibase),
            KeyType::X25519 if ka.is_none() => ka = Some(entry.private_key_multibase),
            _ => {}
        }
    }

    Ok(SealedDidSecretsResult {
        did: did_secrets.did,
        signing_key_multibase: signing
            .ok_or("sealed DidSecrets bundle has no Ed25519 signing key")?,
        key_agreement_multibase: ka
            .ok_or("sealed DidSecrets bundle has no X25519 key agreement key")?,
        producer_did: opened.producer.producer_did,
        assertion_verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mint a plain `vta_sdk::sealed_transfer::BootstrapRequest` and
    /// persist its seed to a file. Used by the export/import-migration
    /// tests, which seal to a *plain* recipient request (not the
    /// VP-framed shape the offline-setup wizard now produces).
    fn write_plain_bootstrap_request_for_test(
        request_path: &Path,
        seed_path: &Path,
        label: Option<&str>,
    ) {
        use rand::RngExt;
        use vta_sdk::sealed_transfer::{BootstrapRequest, generate_ed25519_keypair};

        let (seed, ed_pub) = generate_ed25519_keypair();
        let mut nonce = [0u8; 16];
        rand::rng().fill(&mut nonce);
        let request = BootstrapRequest::new(ed_pub, nonce, label.map(String::from));
        let request_json = serde_json::to_string_pretty(&request).expect("serialize request");
        std::fs::write(request_path, request_json).expect("write request");
        let seed_bytes: [u8; 32] = *seed;
        std::fs::write(seed_path, seed_bytes).expect("write seed");
    }

    #[tokio::test]
    async fn offline_request_produces_valid_bootstrap_request_and_in_memory_seed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let request_path = tmp.path().join("bootstrap-request.json");

        let info = write_offline_bootstrap_request(
            &request_path,
            "did-hosting-server",
            &[("MEDIATOR_DID", "did:key:z6MkMockMediator")],
            "webvh-test-ctx",
            Some("did-hosting-control-test"),
        )
        .await
        .expect("write request");

        // Request file: VP-framed BootstrapRequest as produced by
        // `ProvisionRequestBuilder::sign_ephemeral`.
        let raw = std::fs::read_to_string(&request_path).expect("read request");
        let parsed: vta_sdk::provision_integration::BootstrapRequest =
            serde_json::from_str(&raw).expect("parse VP request");
        assert!(
            parsed.holder.starts_with("did:key:z6Mk"),
            "holder must be an Ed25519 did:key, got {}",
            parsed.holder
        );
        assert_eq!(parsed.label.as_deref(), Some("did-hosting-control-test"));
        // Nonce is base64url(16 bytes) — 22 chars no padding.
        assert_eq!(parsed.nonce.len(), 22, "nonce length");

        // Returned info matches the written artifact, and the seed is
        // returned in memory only — the helper doesn't touch disk for
        // it.
        assert_eq!(info.client_did, parsed.holder);
        assert_eq!(info.nonce, parsed.nonce);
        assert_eq!(info.request_path, request_path);
        assert_ne!(info.seed, [0u8; 32], "seed must not be all zeros");
    }

    /// Full webvh ↔ VTA sealed-bootstrap roundtrip in-process.
    ///
    /// Phase 1 (webvh): `write_offline_bootstrap_request` produces the
    /// VP-framed BootstrapRequest the operator hands to the VTA admin.
    /// Phase 2 (simulated VTA): we verify that VP, build a synthetic
    /// `TemplateBootstrapPayload`, and seal it with `seal_payload` —
    /// the same primitive `vta bootstrap provision-integration` uses on
    /// the VTA side. Phase 3 (webvh): `open_offline_bootstrap_response`
    /// opens the armored bundle, verifies the OOB digest, and surfaces
    /// the integration DID + signing keys + key-agreement keys + admin
    /// material + VTA trust bundle.
    ///
    /// This is the contract test for the end-to-end offline-bootstrap
    /// shape did-hosting-server, did-hosting-control, and webvh-witness setup
    /// wizards depend on. A regression in any of:
    /// - the VP-framed request sign/verify path (provision_integration);
    /// - HPKE seal / open (sealed_transfer);
    /// - `TemplateBootstrapPayload` field shape;
    /// - SHA-256 digest binding;
    /// - Ed25519→X25519 derivation symmetry between consumer and
    ///   producer;
    /// would surface here rather than the next time an operator runs
    /// the wizard against a real VTA.
    #[tokio::test]
    async fn offline_bootstrap_full_webvh_to_vta_roundtrip() {
        use std::collections::BTreeMap;
        use vta_sdk::provision_integration::payload::{
            DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload,
            TemplateOutput, VtaTrustBundle,
        };
        use vta_sdk::sealed_transfer::bundle::AssertionProof;
        use vta_sdk::sealed_transfer::{
            InMemoryNonceStore, ProducerAssertion, SealedPayloadV1, armor, bundle_digest,
            seal_payload,
        };

        let tmp = tempfile::tempdir().expect("tempdir");
        let request_path = tmp.path().join("bootstrap-request.json");

        // -------- Phase 1: webvh produces the VP-framed request ----------
        let info = write_offline_bootstrap_request(
            &request_path,
            "did-hosting-server",
            &[("MEDIATOR_DID", "did:key:z6MkMockMediator")],
            "webvh-roundtrip-ctx",
            Some("roundtrip-full"),
        )
        .await
        .expect("write request");

        // -------- Phase 2: simulated VTA opens, builds, seals ------------
        // Verify the VP exactly as a real VTA would, surfacing the holder
        // and the recipient X25519 pubkey for HPKE.
        let raw_vp = std::fs::read_to_string(&request_path).expect("read request");
        let request: vta_sdk::provision_integration::BootstrapRequest =
            serde_json::from_str(&raw_vp).expect("parse VP");
        let verified = request.verify().expect("VP verifies");
        let recipient_x25519_pub = verified
            .decode_client_x25519_pub()
            .expect("derive X25519 pub");
        let bundle_id = verified.decode_nonce().expect("decode nonce");
        // Sanity: the consumer-side info matches what the VTA would see.
        assert_eq!(verified.holder(), info.client_did);

        // Synthetic VTA-issued material. Keys are placeholders — the
        // sealing flow doesn't crypto-verify the inner secrets, only the
        // envelope. The webvh-side consumer is responsible for using the
        // returned multibase strings to reconstruct working `Secret`s.
        let integration_did = "did:webvh:roundtrip:integration.example.com";
        let admin_did = "did:key:z6MkAdminRotated";
        let mut secrets = BTreeMap::new();
        secrets.insert(
            integration_did.to_string(),
            DidKeyMaterial {
                did: integration_did.into(),
                signing_key: KeyPair {
                    key_id: format!("{integration_did}#key-0"),
                    public_key_multibase: "z6MkSigningPub".into(),
                    private_key_multibase: "zSigningPriv".into(),
                },
                ka_key: KeyPair {
                    key_id: format!("{integration_did}#key-1"),
                    public_key_multibase: "z6LSKaPub".into(),
                    private_key_multibase: "zKaPriv".into(),
                },
            },
        );
        secrets.insert(
            admin_did.to_string(),
            DidKeyMaterial {
                did: admin_did.into(),
                signing_key: KeyPair {
                    key_id: format!("{admin_did}#key-0"),
                    public_key_multibase: "z6MkAdminPub".into(),
                    private_key_multibase: "zAdminPriv".into(),
                },
                ka_key: KeyPair {
                    key_id: format!("{admin_did}#key-1"),
                    public_key_multibase: "z6LSAdminKa".into(),
                    private_key_multibase: "zAdminKaPriv".into(),
                },
            },
        );
        let payload = TemplateBootstrapPayload {
            authorization: serde_json::json!({
                "type": ["VerifiableCredential", "VtaAuthorizationCredential"],
                "credentialSubject": { "id": admin_did, "vtaContext": "webvh-roundtrip-ctx" },
            }),
            secrets,
            config: TemplateBootstrapConfig {
                template_name: "did-hosting-server".into(),
                template_kind: "integration".into(),
                did_document: serde_json::json!({ "id": integration_did }),
                outputs: vec![TemplateOutput::WebvhLog {
                    did: integration_did.into(),
                    log: "{\"versionId\":\"1-roundtrip\"}\n".into(),
                }],
                vta_url: Some("https://vta.example.com".into()),
                vta_trust: VtaTrustBundle {
                    vta_did: "did:webvh:vta.example.com".into(),
                    vta_did_document: serde_json::json!({ "id": "did:webvh:vta.example.com" }),
                    vta_did_log: None,
                },
            },
        };
        let sealed_payload = SealedPayloadV1::TemplateBootstrap(Box::new(payload));

        // PinnedOnly producer assertion: the consumer trusts the
        // out-of-band digest as the integrity anchor. Mirrors the
        // simplest VTA configuration.
        let producer = ProducerAssertion {
            producer_did: "did:key:z6MkProducerSyntheticForTest".into(),
            proof: AssertionProof::PinnedOnly,
        };
        let nonce_store = InMemoryNonceStore::default();
        let bundle = seal_payload(
            &recipient_x25519_pub,
            bundle_id,
            producer,
            &sealed_payload,
            &nonce_store,
        )
        .await
        .expect("seal");
        let digest = bundle_digest(&bundle);
        let armored = armor::encode(&bundle);

        // -------- Phase 3: webvh opens the bundle ------------------------
        let result = open_offline_bootstrap_response(&armored, &digest, &info.seed)
            .expect("open sealed response");

        // Round-trip assertions: every operator-facing field must survive
        // the seal/open trip intact.
        assert_eq!(result.did, integration_did);
        assert_eq!(result.signing_key_multibase, "zSigningPriv");
        assert_eq!(result.key_agreement_multibase, "zKaPriv");
        assert_eq!(result.vta_did, "did:webvh:vta.example.com");
        assert_eq!(result.vta_url.as_deref(), Some("https://vta.example.com"));
        // `WebvhLog` output → log entry surfaces under `log_entry` for
        // the webvh wizard to write to disk.
        assert_eq!(
            result.log_entry.as_deref(),
            Some("{\"versionId\":\"1-roundtrip\"}\n")
        );
        // Admin rollover material — the original bug silently dropped
        // these on the floor. The wizard needs them to seed the ACL
        // with the operator's long-term identity.
        assert_eq!(result.admin_did.as_deref(), Some(admin_did));
        assert_eq!(
            result.admin_signing_key_multibase.as_deref(),
            Some("zAdminPriv")
        );

        // Bad digest must reject in constant time. Flip the first hex
        // character; constant-time-eq still rejects, and the failure
        // path is what the operator sees if the OOB digest was tampered.
        let mut bad = digest.clone();
        bad.replace_range(0..1, if bad.starts_with('0') { "1" } else { "0" });
        let err = open_offline_bootstrap_response(&armored, &bad, &info.seed)
            .expect_err("bad digest must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("digest") || msg.contains("Digest"),
            "expected digest-mismatch error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn sealed_did_secrets_export_open_roundtrip_pinned_only() {
        // PinnedOnly path: exporter emits no signature, opener trusts
        // only the OOB digest.
        let tmp = tempfile::tempdir().expect("tempdir");
        let request_path = tmp.path().join("bootstrap-request.json");
        let seed_path = tmp.path().join("seed.bin");
        let bundle_path = tmp.path().join("sealed.txt");

        // Migration / export-sealed seals to a *plain* BootstrapRequest
        // (created by `pnm bootstrap request` on the recipient side),
        // not the VP-framed shape the offline-setup wizard produces.
        write_plain_bootstrap_request_for_test(&request_path, &seed_path, Some("roundtrip-test"));

        let producer_did = "did:webvh:QmPROD:producer.example.com".to_string();
        let exported_did = "did:webvh:QmEXP:example.com:services/export".to_string();
        let signing_mb = "z3uFakeEd25519SigningKey".to_string();
        let ka_mb = "z3uFakeX25519KaKey".to_string();

        let export = export_sealed_did_secrets(
            &request_path,
            &bundle_path,
            &producer_did,
            &exported_did,
            signing_mb.clone(),
            ka_mb.clone(),
            ExportAssertionMode::PinnedOnly,
        )
        .await
        .expect("export");

        assert_eq!(export.out_path, bundle_path);
        assert_eq!(export.digest.len(), 64, "SHA-256 hex");
        assert!(export.recipient_did.starts_with("did:key:z6Mk"));
        assert_eq!(export.bundle_id_hex.len(), 32, "16 bytes hex");

        let armor = std::fs::read_to_string(&bundle_path).expect("read bundle");
        let opened =
            open_sealed_did_secrets(&armor, &export.digest, &seed_path, None).expect("open");

        assert_eq!(opened.did, exported_did);
        assert_eq!(opened.signing_key_multibase, signing_mb);
        assert_eq!(opened.key_agreement_multibase, ka_mb);
        assert_eq!(opened.producer_did, producer_did);
        assert!(
            !opened.assertion_verified,
            "PinnedOnly should not report verified"
        );

        // Digest binding: a flipped digest must reject the bundle.
        let mut bad = export.digest.clone();
        bad.replace_range(0..1, if bad.starts_with('0') { "1" } else { "0" });
        let err = open_sealed_did_secrets(&armor, &bad, &seed_path, None).expect_err("bad digest");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("digest"),
            "expected digest mismatch error, got {msg}"
        );
    }

    #[tokio::test]
    async fn sealed_did_secrets_export_open_roundtrip_did_signed() {
        // DidSigned path: exporter signs with a real Ed25519 key; opener
        // pins the matching pubkey and verifies the assertion.
        use affinidi_tdk::secrets_resolver::secrets::Secret;

        let tmp = tempfile::tempdir().expect("tempdir");
        let request_path = tmp.path().join("bootstrap-request.json");
        let seed_path = tmp.path().join("seed.bin");
        let bundle_path = tmp.path().join("sealed.txt");

        // Same migration path as the PinnedOnly test — plain
        // BootstrapRequest, not VP-framed.
        write_plain_bootstrap_request_for_test(&request_path, &seed_path, Some("ds-test"));

        // Producer-side signing key — generate fresh so we have both
        // halves available for the round-trip.
        let signer = Secret::generate_ed25519(None, None);
        let signer_priv = signer.get_private_keymultibase().expect("priv mb");
        let signer_pub_mb = signer.get_public_keymultibase().expect("pub mb");

        // Decode the pub multibase back to raw [u8; 32] for the opener.
        let (_, pub_raw) = multibase::decode(&signer_pub_mb).expect("decode pub mb");
        let signer_pub_bytes: [u8; 32] =
            if pub_raw.len() == 34 && pub_raw[0] == 0xed && pub_raw[1] == 0x01 {
                pub_raw[2..].try_into().expect("32 bytes")
            } else {
                pub_raw[..].try_into().expect("32 bytes")
            };

        let producer_did = "did:webvh:QmPROD:producer.example.com".to_string();
        let exported_did = "did:webvh:QmEXP:example.com:services/export".to_string();
        let ka_mb = "z3uFakeX25519KaKey".to_string();

        let export = export_sealed_did_secrets(
            &request_path,
            &bundle_path,
            &producer_did,
            &exported_did,
            signer_priv.clone(),
            ka_mb.clone(),
            ExportAssertionMode::DidSigned {
                signing_key_multibase: signer_priv.clone(),
                verification_method: format!("{producer_did}#key-0"),
            },
        )
        .await
        .expect("export");

        let armor = std::fs::read_to_string(&bundle_path).expect("read bundle");

        // With the correct pinned pubkey, verification succeeds.
        let opened =
            open_sealed_did_secrets(&armor, &export.digest, &seed_path, Some(&signer_pub_bytes))
                .expect("open");
        assert!(opened.assertion_verified, "DidSigned should verify");
        assert_eq!(opened.producer_did, producer_did);

        // With a wrong pinned pubkey, verification fails.
        let mut wrong = signer_pub_bytes;
        wrong[0] ^= 0x01;
        let err = open_sealed_did_secrets(&armor, &export.digest, &seed_path, Some(&wrong))
            .expect_err("wrong pubkey");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("didsigned") || msg.contains("signature") || msg.contains("verify"),
            "expected signature verification failure, got {msg}"
        );
    }

    #[tokio::test]
    async fn offline_request_unique_client_did_per_call() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let r1 = tmp.path().join("r1.json");
        let r2 = tmp.path().join("r2.json");

        let a = write_offline_bootstrap_request(
            &r1,
            "did-hosting-server",
            &[("MEDIATOR_DID", "did:key:z6MkMockMediator")],
            "webvh-test-ctx",
            None,
        )
        .await
        .unwrap();
        let b = write_offline_bootstrap_request(
            &r2,
            "did-hosting-server",
            &[("MEDIATOR_DID", "did:key:z6MkMockMediator")],
            "webvh-test-ctx",
            None,
        )
        .await
        .unwrap();

        // Each call mints a fresh Ed25519 seed → different did:key,
        // different nonce, different seed.
        assert_ne!(a.client_did, b.client_did, "new keypair per call");
        assert_ne!(a.nonce, b.nonce, "new nonce per call");
        assert_ne!(a.seed, b.seed, "new seed per call");
    }
}

//! Shared VTA (Verifiable Trust Architecture) setup helpers.
//!
//! Used by all three service setup wizards to authenticate with VTA,
//! create DIDs, and retrieve key material.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use vta_sdk::client::VtaClient;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::session::{SessionBackend, SessionStore};

/// Name of the VTA built-in DID template we use for every webvh service
/// (control plane, DID-hosting server, witness, watcher). The template
/// renders the two-key Multikey shape with a `#vta-didcomm` service
/// pointing at the mediator DID supplied in `template_vars`.
const WEBVH_SERVICE_TEMPLATE: &str = "webvh-service";

/// Metadata from a successful VTA connection.
pub struct VtaConnectionInfo {
    pub vta_url: String,
    pub vta_did: String,
    pub context_id: String,
    pub client_did: String,
}

/// Result of creating or retrieving a DID via VTA.
pub struct VtaDidResult {
    pub did: String,
    pub scid: String,
    /// Ed25519 private key (multibase-encoded).
    pub signing_key: String,
    /// X25519 private key (multibase-encoded).
    pub key_agreement_key: String,
    /// DID log entry (JSONL), present only for newly created DIDs.
    pub log_entry: Option<String>,
}

/// In-memory session backend for ephemeral setup sessions.
///
/// The setup handshake only needs the session for the duration of the
/// wizard — no persistence needed. This avoids touching disk or
/// requiring any specific secrets backend to be configured.
struct InMemoryBackend {
    data: Mutex<HashMap<String, String>>,
}

impl SessionBackend for InMemoryBackend {
    fn load(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }
    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn clear(&self, key: &str) {
        self.data.lock().unwrap().remove(key);
    }
}

/// Decode a VTA credential, authenticate via DIDComm, and return a connected client.
///
/// Uses `SessionStore` to establish a full DIDComm session through the VTA's
/// mediator. This is required for operations like `create_did_webvh` where the
/// VTA needs to relay DIDComm messages to the webvh server.
///
/// An in-memory session backend is used — the session is only needed for the
/// duration of the setup wizard.
pub async fn connect_vta(
    credential_b64: &str,
) -> Result<(VtaClient, VtaConnectionInfo), Box<dyn std::error::Error>> {
    // vta-sdk 0.5 dropped CredentialBundle::decode; operators still paste
    // a base64url blob, so deserialize inline: base64url → JSON → bundle.
    let bundle_json = BASE64.decode(credential_b64.as_bytes())?;
    let bundle: CredentialBundle = serde_json::from_slice(&bundle_json)?;

    let vta_url = bundle
        .vta_url
        .clone()
        .ok_or("VTA credential does not contain a vta_url")?;

    // Use an in-memory backend — the session is only needed for this setup run
    let backend = InMemoryBackend {
        data: Mutex::new(HashMap::new()),
    };
    let store = SessionStore::with_backend(Box::new(backend));
    let session_key = "setup";

    let login_result = store.login(&bundle, &vta_url, session_key).await?;

    // Pass None so connect() resolves the VTA DID and uses DIDComm transport
    // through the VTA's mediator (required for create_did_webvh etc.)
    let client = store.connect(session_key, None).await?;

    // Discover the context: list contexts and pick the one the credential has access to
    let contexts = client.list_contexts().await?;
    let context_id = if contexts.contexts.len() == 1 {
        contexts.contexts[0].id.clone()
    } else if contexts.contexts.is_empty() {
        return Err("no VTA contexts found for this credential".into());
    } else {
        // If multiple contexts, return the first — the caller can override
        contexts.contexts[0].id.clone()
    };

    Ok((
        client,
        VtaConnectionInfo {
            vta_url,
            vta_did: login_result.vta_did,
            context_id,
            client_did: login_result.client_did,
        },
    ))
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

/// Create a new did:webvh via VTA and fetch its private keys.
///
/// The DID is created in "serverless" mode (no VTA-managed server registration).
/// The log entry is returned for the caller to import into webvh-server.
///
/// If `mediator_did` is provided, a `DIDCommMessaging` service endpoint
/// pointing to the mediator is embedded in the DID document.
pub async fn create_did(
    client: &VtaClient,
    context_id: &str,
    hosting_url: &str,
    path: &str,
    label: Option<&str>,
    mediator_did: Option<&str>,
) -> Result<VtaDidResult, Box<dyn std::error::Error>> {
    use vta_sdk::client::CreateDidWebvhRequest;

    // vta-sdk 0.5: the VTA renders the DID document server-side from the
    // named template. When a mediator is configured, hand the template the
    // MEDIATOR_DID var and it produces the reference shape (#key-0/#key-1
    // Multikey verification methods + single #vta-didcomm service). When
    // there's no mediator, leave the template unset so the VTA falls back
    // to its default service-less DID document.
    let (template, template_vars) = match mediator_did {
        Some(did) => {
            let mut vars = HashMap::new();
            vars.insert(
                "MEDIATOR_DID".to_string(),
                serde_json::Value::String(did.to_string()),
            );
            (Some(WEBVH_SERVICE_TEMPLATE.to_string()), vars)
        }
        None => (None, HashMap::new()),
    };

    let req = CreateDidWebvhRequest {
        context_id: context_id.to_string(),
        server_id: None,
        url: Some(hosting_url.to_string()),
        path: Some(path.to_string()),
        label: label.map(|l| l.to_string()),
        portable: true,
        // Template-rendered DIDs already include the mediator service;
        // leaving these off avoids the VTA appending a duplicate.
        add_mediator_service: false,
        additional_services: None,
        pre_rotation_count: 0,
        did_document: None,
        did_log: None,
        set_primary: true,
        signing_key_id: None,
        ka_key_id: None,
        template,
        template_context: Some(context_id.to_string()),
        template_vars,
    };

    let result = client.create_did_webvh(req).await?;

    // Fetch private keys
    let signing_secret = client.get_key_secret(&result.signing_key_id).await?;
    let ka_secret = client.get_key_secret(&result.ka_key_id).await?;

    Ok(VtaDidResult {
        did: result.did,
        scid: result.scid,
        signing_key: signing_secret.private_key_multibase,
        key_agreement_key: ka_secret.private_key_multibase,
        log_entry: result.log_entry,
    })
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

/// Write a DID log entry to a file for later bootstrap on webvh-server.
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
// Same `webvh-service` template drives both the online and offline paths,
// so the persisted DID shape is identical to what `create_did()` above
// produces.
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
    /// Path of the persisted ephemeral seed. **Treat as secret.** Must
    /// survive to the `open_offline_bootstrap_response` call (usually a
    /// separate CLI invocation, potentially minutes or hours later).
    pub seed_path: std::path::PathBuf,
}

/// Rich result of opening an offline bootstrap response.
///
/// Shaped to feed the same secret-store / DID-bootstrap plumbing the
/// online path uses, plus the extra VTA trust material the sealed
/// bundle carries (authorization VC, pinned VTA DID, trust bundle).
#[derive(Debug, Clone)]
pub struct OfflineBootstrapResult {
    pub did: String,
    /// Multibase-encoded Ed25519 private signing key.
    pub signing_key_multibase: String,
    /// Multibase-encoded X25519 private key agreement key.
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
}

/// Write an offline bootstrap request + persist the ephemeral seed.
///
/// The caller hands `request_path` to the VTA operator and keeps
/// `seed_path` locally — it's the private half needed to open the sealed
/// response. Both parent directories are created if absent.
///
/// On Unix, `seed_path` is chmodded to 0600 after writing. On other
/// platforms the file-system's default permissions apply; colocate it
/// inside a directory under the operator's control.
pub fn write_offline_bootstrap_request(
    request_path: &Path,
    seed_path: &Path,
    label: Option<&str>,
) -> Result<OfflineRequestInfo, Box<dyn std::error::Error>> {
    use rand::RngExt;
    use vta_sdk::sealed_transfer::{BootstrapRequest, generate_ed25519_keypair};

    let (seed, ed_pub) = generate_ed25519_keypair();

    let mut nonce = [0u8; 16];
    rand::rng().fill(&mut nonce);

    let request = BootstrapRequest::new(ed_pub, nonce, label.map(String::from));
    let request_json = serde_json::to_string_pretty(&request)?;

    if let Some(parent) = request_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = seed_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(request_path, request_json)?;
    // Zeroizing<[u8; 32]> deref is [u8; 32]; pass as &[u8] for write().
    std::fs::write(seed_path, &seed[..])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(seed_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(seed_path, perms)?;
    }

    Ok(OfflineRequestInfo {
        client_did: request.client_did.clone(),
        nonce: request.nonce.clone(),
        request_path: request_path.to_path_buf(),
        seed_path: seed_path.to_path_buf(),
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
/// `seed_path` must point at the file `write_offline_bootstrap_request`
/// wrote earlier — reopening requires the persisted ephemeral seed.
pub fn open_offline_bootstrap_response(
    bundle_armor: &str,
    expect_digest: &str,
    seed_path: &Path,
) -> Result<OfflineBootstrapResult, Box<dyn std::error::Error>> {
    use vta_sdk::sealed_transfer::template_bootstrap::TemplateOutput;
    use vta_sdk::sealed_transfer::{
        SealedPayloadV1, armor, ed25519_seed_to_x25519_secret, open_bundle,
    };

    // Load + validate seed.
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

    // Take the single DidKeyMaterial entry. (The payload carries a map
    // keyed by DID for forward-compat with multi-DID templates; today
    // the VTA provisions one per bootstrap.)
    let (_map_key, key_material) = payload
        .secrets
        .into_iter()
        .next()
        .ok_or("sealed payload has no secrets")?;

    let log_entry = payload.config.outputs.iter().find_map(|o| match o {
        TemplateOutput::WebvhLog { log, .. } => Some(log.clone()),
        _ => None,
    });

    Ok(OfflineBootstrapResult {
        did: key_material.did,
        signing_key_multibase: key_material.signing_key.private_key_multibase,
        key_agreement_multibase: key_material.ka_key.private_key_multibase,
        did_document: payload.config.did_document,
        log_entry,
        authorization_vc: payload.authorization,
        vta_did: payload.config.vta_trust.vta_did,
        vta_url: payload.config.vta_url,
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
    /// `--signing-key` and `--ka-key` multibase flags (e.g. webvh-server,
    /// webvh-witness). The instruction tells the operator to run it with
    /// the keys from the secrets JSON.
    ImportSecrets {
        /// The binary name to put in the suggested command line.
        binary: &'a str,
    },
    /// Service has no import-secrets subcommand yet; point at its
    /// interactive setup wizard (e.g. webvh-control).
    Setup {
        /// The binary name to put in the suggested command line.
        binary: &'a str,
    },
}

/// CLI-facing wrapper around [`write_offline_bootstrap_request`]. Writes
/// the request + seed files and prints step-by-step operator instructions
/// on stderr. Intended for direct delegation from per-service `main.rs`
/// subcommands so the operator UX stays consistent across binaries.
pub fn run_offline_request_cli(
    out: &Path,
    seed: &Path,
    label: &str,
    binary: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let info = write_offline_bootstrap_request(out, seed, Some(label))?;

    eprintln!();
    eprintln!("  Offline bootstrap request ready.");
    eprintln!();
    eprintln!("  Request file:   {}", info.request_path.display());
    eprintln!("  Seed (secret):  {}", info.seed_path.display());
    eprintln!();
    eprintln!("  Consumer DID:   {}", info.client_did);
    eprintln!("  Nonce:          {}", info.nonce);
    eprintln!();
    eprintln!("  Next steps:");
    eprintln!(
        "    1. Ferry {} to your VTA admin.",
        info.request_path.display()
    );
    eprintln!("    2. Ask them to run:");
    eprintln!(
        "         vta bootstrap seal --request <request-file> \\\n           --template webvh-service --var MEDIATOR_DID=<mediator-did>"
    );
    eprintln!("    3. They send back an ASCII-armored sealed bundle + SHA-256 digest.");
    eprintln!("    4. Run:");
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
    seed: &Path,
    did_doc_out: &Path,
    did_log_out: &Path,
    secrets_out: &Path,
    next: OfflineOpenNextStep<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let armor =
        std::fs::read_to_string(bundle).map_err(|e| format!("read {}: {e}", bundle.display()))?;

    let result = open_offline_bootstrap_response(&armor, expect_digest, seed)?;

    let did_doc_json = serde_json::to_string_pretty(&result.did_document)?;
    std::fs::write(did_doc_out, &did_doc_json)?;

    if let Some(ref log) = result.log_entry {
        std::fs::write(did_log_out, log)?;
    }

    let secrets_payload = serde_json::json!({
        "did": result.did,
        "signing_key_multibase": result.signing_key_multibase,
        "key_agreement_multibase": result.key_agreement_multibase,
        "vta_did": result.vta_did,
        "vta_url": result.vta_url,
        "authorization_vc": result.authorization_vc,
    });
    std::fs::write(secrets_out, serde_json::to_string_pretty(&secrets_payload)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(secrets_out)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(secrets_out, perms)?;
    }

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
        "       `webvh-server bootstrap-did --did-log {}` on the hosting server.",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_request_produces_valid_bootstrap_request() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let request_path = tmp.path().join("bootstrap-request.json");
        let seed_path = tmp.path().join("secrets/seed.bin");

        let info =
            write_offline_bootstrap_request(&request_path, &seed_path, Some("webvh-control-test"))
                .expect("write request");

        // Request file: valid JSON, matches vta-sdk's expected shape.
        let raw = std::fs::read_to_string(&request_path).expect("read request");
        let parsed: vta_sdk::sealed_transfer::BootstrapRequest =
            serde_json::from_str(&raw).expect("parse request");
        assert_eq!(parsed.version, 1, "version");
        assert!(
            parsed.client_did.starts_with("did:key:z6Mk"),
            "client_did must be an Ed25519 did:key, got {}",
            parsed.client_did
        );
        assert_eq!(parsed.label.as_deref(), Some("webvh-control-test"));
        // Nonce is base64url(16 bytes) — 22 chars no padding.
        assert_eq!(parsed.nonce.len(), 22, "nonce length");

        // Returned info matches the written artifact.
        assert_eq!(info.client_did, parsed.client_did);
        assert_eq!(info.nonce, parsed.nonce);
        assert_eq!(info.request_path, request_path);
        assert_eq!(info.seed_path, seed_path);

        // Seed file: exactly 32 bytes.
        let seed = std::fs::read(&seed_path).expect("read seed");
        assert_eq!(seed.len(), 32, "ephemeral seed is 32 bytes");

        // On Unix, the seed is chmod 0600 so it isn't world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&seed_path)
                .expect("stat seed")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "seed file mode");
        }
    }

    #[test]
    fn offline_request_unique_client_did_per_call() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let r1 = tmp.path().join("r1.json");
        let s1 = tmp.path().join("s1.bin");
        let r2 = tmp.path().join("r2.json");
        let s2 = tmp.path().join("s2.bin");

        let a = write_offline_bootstrap_request(&r1, &s1, None).unwrap();
        let b = write_offline_bootstrap_request(&r2, &s2, None).unwrap();

        // Each call mints a fresh Ed25519 seed → different did:key, different nonce.
        assert_ne!(a.client_did, b.client_did, "new keypair per call");
        assert_ne!(a.nonce, b.nonce, "new nonce per call");
    }
}

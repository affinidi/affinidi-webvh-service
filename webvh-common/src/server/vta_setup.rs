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
/// `<did>#key-0` / `<did>#key-1` to match the `webvh-service` template.
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

    #[tokio::test]
    async fn sealed_did_secrets_export_open_roundtrip_pinned_only() {
        // PinnedOnly path: exporter emits no signature, opener trusts
        // only the OOB digest.
        let tmp = tempfile::tempdir().expect("tempdir");
        let request_path = tmp.path().join("bootstrap-request.json");
        let seed_path = tmp.path().join("seed.bin");
        let bundle_path = tmp.path().join("sealed.txt");

        let _info =
            write_offline_bootstrap_request(&request_path, &seed_path, Some("roundtrip-test"))
                .expect("write request");

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

        let _info = write_offline_bootstrap_request(&request_path, &seed_path, Some("ds-test"))
            .expect("write request");

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

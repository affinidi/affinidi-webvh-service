//! Subcommands every service binary shares, as `clap` subcommand groups.
//!
//! `did-hosting-server`, `did-hosting-control` and `did-hosting-daemon` each
//! `#[command(flatten)]` the groups that apply to them into their own
//! `Command` enum, and dispatch to the group's `run`. A subcommand defined
//! here is therefore defined once, with one implementation: adding one to a
//! group adds it to every binary that flattens the group, the daemon
//! included. The daemon's `Cli` has a test that its subcommands cover the
//! standalone binaries' (CLAUDE.md, daemon parity).
//!
//! Groups whose implementation lives in a service crate are defined there:
//! the DID-store commands in `did_hosting_server::cli`, the ACL and
//! statistics commands in `did_hosting_control::cli`.
//!
//! A command reads the binary's configuration through [`ServiceConfig`],
//! which each binary's config type implements, and loads it only when it
//! needs it — `vta-request` and `vta-open` work without a config file.

use std::path::{Path, PathBuf};

use clap::Subcommand;

use super::config::{
    AuthConfig, FeaturesConfig, HostingConfig, IdentityConfig, SecretsConfig, ServerConfig,
    StoreConfig,
};

/// What a CLI command returns.
pub type CliResult = Result<(), Box<dyn std::error::Error>>;

/// The service binary a command runs in: named in the output, and choosing
/// the defaults that differ between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// `did-hosting-server`, the edge.
    Server,
    /// `did-hosting-control`, the control plane.
    Control,
    /// `did-hosting-daemon`, both in one process.
    Daemon,
}

impl Service {
    /// The binary's name, as an operator types it.
    pub fn binary(self) -> &'static str {
        match self {
            Self::Server => "did-hosting-server",
            Self::Control => "did-hosting-control",
            Self::Daemon => "did-hosting-daemon",
        }
    }

    /// The prefix of the files `vta-open` writes (`<prefix>-did.json`, …).
    pub fn artifact_prefix(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Control => "control",
            Self::Daemon => "daemon",
        }
    }

    /// Who "this service" is, in a sentence.
    fn noun(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Control => "control plane",
            Self::Daemon => "daemon",
        }
    }

    /// The step `vta-open` tells the operator to take next: every binary but
    /// the standalone control plane has `import-secrets`.
    fn open_next_step(self) -> super::vta_setup::OfflineOpenNextStep<'static> {
        use super::vta_setup::OfflineOpenNextStep;
        match self {
            Self::Control => OfflineOpenNextStep::Setup {
                binary: self.binary(),
            },
            Self::Server | Self::Daemon => OfflineOpenNextStep::ImportSecrets {
                binary: self.binary(),
            },
        }
    }
}

/// What the shared commands read from a binary's configuration.
pub trait ServiceConfig {
    /// The file the configuration was loaded from.
    fn config_path(&self) -> &Path;
    /// The service's store (`[store]`).
    fn store(&self) -> &StoreConfig;
    /// Where its secrets live (`[secrets]`).
    fn secrets(&self) -> &SecretsConfig;
    /// The service's own DID, once provisioned.
    fn server_did(&self) -> Option<&str>;
    /// The mediator its DID advertises.
    fn mediator_did(&self) -> Option<&str>;
    /// The public URL it serves.
    fn public_url(&self) -> Option<&str>;
    /// `[features]`.
    fn features(&self) -> &FeaturesConfig;
    /// `[hosting]`.
    fn hosting(&self) -> &HostingConfig;
    /// `[identity]`.
    fn identity(&self) -> &IdentityConfig;
    /// `[server]`: the bind address.
    fn server(&self) -> &ServerConfig;
    /// `[auth]`.
    fn auth(&self) -> &AuthConfig;
    /// The embedded witness's store (`[witness_store]`), for a binary that
    /// embeds one (the daemon).
    fn witness_store(&self) -> Option<&StoreConfig> {
        None
    }
}

/// Load a binary's configuration on demand.
pub type Loader<'a, C> = Box<dyn FnOnce() -> Result<C, Box<dyn std::error::Error>> + 'a>;

/// Print `error` prefixed by `label` and exit 1, or return.
pub fn exit_on_error<T, E: std::fmt::Display>(label: &str, result: Result<T, E>) {
    if let Err(e) = result {
        eprintln!("{label}: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// The service's own identity
// ---------------------------------------------------------------------------

/// The service's own DID identity: its generations, key rotation and did:scid
/// alias. Offline: the service must be stopped.
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// List the service's own identity generations (key material still honoured).
    IdentityList,
    /// Rotate the service's own key-agreement key.
    ///
    /// Publishes a new DID log entry installing a fresh key-agreement key on a
    /// NEW verification-method fragment, and keeps the outgoing key honoured for
    /// the grace period so peers holding a cached DID document can still reach
    /// this service.
    ///
    /// The fresh fragment is not cosmetic: a kid identifies exactly one key, so
    /// reusing `#key-1` would make any grace period impossible.
    ///
    /// The service must be STOPPED (the store is exclusively locked).
    IdentityRotateKeys {
        /// Which keys to rotate: "ka" (default), "signing", or "both".
        ///
        /// "ka"      — the encryption key. This is what the grace period covers.
        /// "signing" — the DID's updateKeys: the authority to publish updates.
        ///             Revoked IMMEDIATELY; there is no grace period for it, and
        ///             for a compromised key that is exactly what you want.
        #[arg(long, default_value = "ka")]
        keys: String,
        /// X25519 key-agreement key to install (multibase). Generated if omitted.
        #[arg(long)]
        ka_key: Option<String>,
        /// Ed25519 signing key to install (multibase). Generated if omitted.
        #[arg(long)]
        signing_key: Option<String>,
        /// How long to keep honouring the outgoing key-agreement key ("1h", "0").
        /// Defaults to `[identity] rotation_grace_period`.
        #[arg(long)]
        grace: Option<String>,
    },
    /// List or remove the did:scid alias of the service's own DID.
    ///
    /// Publishes a new DID log entry whose `alsoKnownAs` lists (`list`) or no
    /// longer lists (`remove`) `did:scid:vh:1:<scid>?src=<location>` — the
    /// listing that makes the DID's did:webvh and did:scid forms one subject
    /// (VTI-KEY-164). `list` replaces an alias listed for an older location.
    /// Refused when nothing would change. Signed with the current update key,
    /// which does not rotate.
    ///
    /// The service must be STOPPED (the store is exclusively locked).
    IdentityScidAlias {
        /// "list" or "remove".
        #[arg(value_parser = ["list", "remove"])]
        action: String,
    },
    /// Stop honouring a superseded identity generation immediately.
    ///
    /// The offline kill switch, for a compromised key. Messages still addressed
    /// to that generation's key-agreement key will no longer decrypt.
    ///
    /// The service must be stopped (the store is exclusively locked). For a
    /// LIVE service use the control plane's `identity/retire/0.1` Trust Task
    /// (`send-trust-task`, see docs/sending-trust-tasks.md) or the UI button,
    /// which drops the key from the running process immediately.
    IdentityRetireNow {
        /// Generation id to retire (see `identity-list`).
        #[arg(long)]
        generation: u64,
    },
}

impl IdentityCommand {
    /// Run the command against the configuration `load` returns.
    pub async fn run<C: ServiceConfig>(self, load: Loader<'_, C>) -> CliResult {
        use super::cli_identity;
        let config = load()?;
        match self {
            Self::IdentityList => cli_identity::run_list_generations(config.store()).await,
            Self::IdentityRetireNow { generation } => {
                cli_identity::run_retire_generation(
                    config.store(),
                    config.secrets(),
                    config.config_path(),
                    generation,
                )
                .await
            }
            Self::IdentityScidAlias { action } => {
                cli_identity::run_identity_scid_alias(
                    config.store(),
                    config.secrets(),
                    config.config_path(),
                    config.server_did(),
                    &action,
                )
                .await
            }
            Self::IdentityRotateKeys {
                keys,
                ka_key,
                signing_key,
                grace,
            } => rotate_keys(&config, &keys, ka_key, signing_key, grace).await,
        }
    }
}

/// `identity-rotate-keys` — rotate the service's own keys, offline.
///
/// Writes the new DID log entry, the new key material (carrying the outgoing key
/// into the retired set in the same write), and the generation records. The
/// service comes back up already holding both key-agreement keys.
async fn rotate_keys<C: ServiceConfig>(
    config: &C,
    keys: &str,
    ka_key: Option<String>,
    signing_key: Option<String>,
    grace: Option<String>,
) -> CliResult {
    use super::identity_rotate::{RotateKeys, rotate_keys};
    use super::secret_store::create_secret_store;
    use super::store::Store;

    let server_did = config
        .server_did()
        .ok_or("server_did is not set — this service has no identity to rotate")?;

    let which = RotateKeys::parse(keys)?;
    let grace_secs = match grace.as_deref() {
        Some(s) => super::pending_purge::parse_grace_string(s)
            .map_err(|e| format!("invalid --grace: {e}"))?,
        None => config.identity().rotation_grace_secs(),
    };

    let store = Store::open(config.store()).await?;
    let secret_store = create_secret_store(config.secrets(), config.config_path())?;

    let report = rotate_keys(
        &store,
        secret_store.as_ref(),
        server_did,
        which,
        ka_key.as_deref(),
        signing_key.as_deref(),
        grace_secs,
    )
    .await?;

    eprintln!();
    eprintln!("  Rotated keys for {}", report.did);

    if report.which != RotateKeys::Signing {
        eprintln!("    key agreement (new) : {}", report.new_ka_kid);
        if grace_secs > 0 {
            eprintln!(
                "    key agreement (old) : {}  — honoured for {}m",
                report.retired_ka_kid,
                grace_secs / 60
            );
        } else {
            eprintln!(
                "    key agreement (old) : {}  — RETIRED IMMEDIATELY, no grace period",
                report.retired_ka_kid
            );
        }
    }

    if report.which != RotateKeys::KeyAgreement {
        eprintln!("    signing       (new) : {}", report.new_signing_kid);
        eprintln!("    signing       (old) : {}", report.retired_signing_kid);
        eprintln!();
        eprintln!("  The old signing key's authority to publish DID updates is REVOKED as of");
        eprintln!("  this log entry — it can no longer sign an update the chain will accept.");
        eprintln!("  There is no grace period for a signing key and there cannot be: peers");
        eprintln!("  holding a cached DID document will reject signatures made with the new");
        eprintln!("  key until they re-resolve.");
    }

    eprintln!();
    eprintln!(
        "    generation {} -> {}",
        report.retired_generation, report.new_generation
    );
    eprintln!("    did.jsonl now has {} entries", report.version_count);
    eprintln!();
    if grace_secs > 0 && report.which != RotateKeys::Signing {
        eprintln!("  Start the service. It will honour BOTH key-agreement keys, so peers");
        eprintln!("  holding a cached DID document can still reach it until the old one expires.");
    } else {
        eprintln!("  Start the service.");
    }
    eprintln!();

    Ok(())
}

// ---------------------------------------------------------------------------
// TSP relationships
// ---------------------------------------------------------------------------

/// The service's TSP relationships. Offline: the service must be stopped.
#[derive(Debug, Subcommand)]
pub enum TspCommand {
    /// List this service's established TSP relationships (offline; stop the
    /// service first).
    ///
    /// Each endpoint keeps its own half of every relationship; the mediator holds
    /// none, so resetting a peer pairing means clearing both ends.
    TspRelationshipList,
    /// Reset our half of a TSP relationship to `None`, so the next send to the
    /// peer re-invites (offline). Keeps the cached peer capability.
    TspRelationshipReset {
        /// The peer's DID (its TSP VID).
        #[arg(long)]
        peer: String,
        /// This service's VID for the pair. Needed only for a half-formed
        /// relationship, which `tsp-relationship-list` cannot show.
        #[arg(long)]
        our: Option<String>,
    },
    /// Delete TSP relationship records outright (offline).
    TspRelationshipDelete {
        /// The peer's DID (its TSP VID).
        #[arg(long, required_unless_present = "all", conflicts_with = "all")]
        peer: Option<String>,
        /// This service's VID for the pair. Needed only for a half-formed
        /// relationship, which `tsp-relationship-list` cannot show.
        #[arg(long, requires = "peer", conflicts_with = "all")]
        our: Option<String>,
        /// Delete every record, established or half-formed.
        #[arg(long)]
        all: bool,
        /// Confirm `--all`. Without it, only reports what would be deleted.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

impl TspCommand {
    /// Run the command against the configuration `load` returns.
    pub async fn run<C: ServiceConfig>(self, load: Loader<'_, C>) -> CliResult {
        use super::cli_tsp::{Target, run_delete, run_list, run_reset};
        let config = load()?;
        match self {
            Self::TspRelationshipList => run_list(config.store()).await,
            Self::TspRelationshipReset { peer, our } => {
                run_reset(config.store(), Target::Peer { peer, our }).await
            }
            Self::TspRelationshipDelete {
                peer,
                our,
                all,
                yes,
            } => {
                let target = match peer {
                    Some(peer) if !all => Target::Peer { peer, our },
                    _ => Target::All,
                };
                run_delete(config.store(), target, yes).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The service's keys
// ---------------------------------------------------------------------------

/// Moving the service's keys in and out of its secret store.
#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Import secrets from a VTA secrets bundle or individual keys
    ImportSecrets {
        /// Base64url-encoded VTA secrets bundle (from `vta create-did-webvh`)
        #[arg(long, group = "source")]
        vta_bundle: Option<String>,
        /// Ed25519 signing key (multibase-encoded)
        #[arg(long, group = "source")]
        signing_key: Option<String>,
        /// X25519 key agreement key (multibase-encoded, required with --signing-key)
        #[arg(long)]
        ka_key: Option<String>,
        /// Ed25519 JWT signing key (multibase-encoded, generated if omitted)
        #[arg(long)]
        jwt_key: Option<String>,
        /// VTA credential bundle (base64url-encoded, optional)
        #[arg(long)]
        vta_credential: Option<String>,
        /// Overwrite existing secrets without prompting
        #[arg(long)]
        force: bool,
    },
    /// Export this service's DID + signing/KA keys as an HPKE-sealed
    /// migration bundle.
    ///
    /// Reads the receiver's `bootstrap-request.json` (same shape that
    /// `vta-request` or `setup-offline-prepare` produces), loads the
    /// existing identity from the configured secret store, wraps the keys
    /// as a `DidSecrets` payload, and seals to the receiver's ephemeral
    /// X25519 pubkey. Prints a SHA-256 digest that the receiver MUST verify
    /// out-of-band before opening. The receiver opens it with
    /// `import-sealed`.
    ExportSealed {
        /// Path to the receiver's bootstrap-request.json.
        #[arg(long)]
        request: PathBuf,
        /// Path for the ASCII-armored sealed output.
        #[arg(long, default_value = "sealed-export.txt")]
        out: PathBuf,
        /// Optional file to write the SHA-256 digest to. Always
        /// printed to stderr regardless.
        #[arg(long)]
        digest_out: Option<PathBuf>,
    },
    /// Open a sealed `DidSecrets` migration bundle and import the
    /// contained keys as this service's identity. Inverse of
    /// `export-sealed` on the sending side.
    ImportSealed {
        /// Path to the ASCII-armored sealed bundle.
        #[arg(long)]
        bundle: PathBuf,
        /// Expected SHA-256 digest of the armored ciphertext (from
        /// the operator, out-of-band).
        #[arg(long)]
        expect_digest: String,
        /// Path to the ephemeral seed the receiver saved when
        /// generating the bootstrap-request.json.
        #[arg(long, default_value = "bootstrap-seed.bin")]
        seed: PathBuf,
        /// Optional Ed25519 public key of the producer (multibase-
        /// encoded, matches `#key-0` in the producer's DID document).
        /// When supplied, the bundle's `DidSigned` assertion is
        /// verified against it; omit to fall back to digest-only trust.
        #[arg(long)]
        producer_pubkey: Option<String>,
        /// Ed25519 JWT signing key (multibase-encoded, generated if omitted)
        #[arg(long)]
        jwt_key: Option<String>,
        /// Overwrite existing secrets without prompting.
        #[arg(long)]
        force: bool,
    },
}

impl KeysCommand {
    /// Run the command against the configuration `load` returns.
    pub async fn run<C: ServiceConfig>(self, service: Service, load: Loader<'_, C>) -> CliResult {
        let config = load()?;
        match self {
            Self::ImportSecrets {
                vta_bundle,
                signing_key,
                ka_key,
                jwt_key,
                vta_credential,
                force,
            } => {
                import_secrets(
                    &config,
                    vta_bundle,
                    signing_key,
                    ka_key,
                    jwt_key,
                    vta_credential,
                    force,
                )
                .await
            }
            Self::ExportSealed {
                request,
                out,
                digest_out,
            } => export_sealed(&config, service, &request, &out, digest_out.as_deref()).await,
            Self::ImportSealed {
                bundle,
                expect_digest,
                seed,
                producer_pubkey,
                jwt_key,
                force,
            } => {
                import_sealed(
                    &config,
                    &bundle,
                    &expect_digest,
                    &seed,
                    producer_pubkey.as_deref(),
                    jwt_key,
                    force,
                )
                .await
            }
        }
    }
}

/// The JWT signing key to store: `jwt_key` checked, or a fresh one.
fn jwt_signing_key(jwt_key: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    match jwt_key {
        Some(key) => {
            Secret::from_multibase(&key, None)
                .map_err(|e| format!("invalid JWT signing key: {e}"))?;
            Ok(key)
        }
        None => {
            eprintln!("  Generated JWT signing key.");
            Ok(super::vta_setup::generate_ed25519_multibase())
        }
    }
}

/// The retired key material already held, to carry into a replacement.
///
/// `retired` holds the keys of identity generations that are superseded but
/// still inside their grace period — the ones peers with a cached DID document
/// are still encrypting to. Blanking it would silently destroy that overlap:
/// the generation records would survive, their key material would not, and the
/// service would come back unable to decrypt traffic still addressed to the
/// old key. The entries are keyed by kid and self-describing, so keeping them is
/// harmless even when the imported keys are for a wholly different identity.
async fn retired_keys(
    secret_store: &dyn super::secret_store::SecretStore,
) -> Vec<super::secret_store::RetiredKeys> {
    let retired = match secret_store.get().await {
        Ok(Some(mut existing)) => std::mem::take(&mut existing.retired),
        _ => Vec::new(),
    };
    if !retired.is_empty() {
        eprintln!(
            "  Preserving {} retired key(s) — superseded generations still inside their grace period.",
            retired.len()
        );
    }
    retired
}

async fn import_secrets<C: ServiceConfig>(
    config: &C,
    vta_bundle: Option<String>,
    signing_key: Option<String>,
    ka_key: Option<String>,
    jwt_key: Option<String>,
    vta_credential: Option<String>,
    force: bool,
) -> CliResult {
    use super::secret_store::{ServerSecrets, create_secret_store, is_plaintext_backend};
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use vta_sdk::did_secrets::DidSecretsBundle;
    use vta_sdk::keys::KeyType;

    let secret_store = create_secret_store(config.secrets(), config.config_path())?;

    if !force && let Ok(Some(_)) = secret_store.get().await {
        return Err("secrets already exist — use --force to overwrite".into());
    }

    let (resolved_signing, resolved_ka) = if let Some(ref bundle_str) = vta_bundle {
        // vta-sdk 0.5 dropped DidSecretsBundle::decode — operators still
        // paste a base64url blob, so deserialize inline:
        // base64url → JSON → bundle.
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
        let bundle_json = BASE64
            .decode(bundle_str.as_bytes())
            .map_err(|e| format!("failed to decode VTA secrets bundle base64: {e}"))?;
        let bundle: DidSecretsBundle = serde_json::from_slice(&bundle_json)
            .map_err(|e| format!("failed to decode VTA secrets bundle: {e}"))?;

        let mut signing = None;
        let mut ka = None;
        for entry in &bundle.secrets {
            match entry.key_type {
                KeyType::Ed25519 if signing.is_none() => {
                    signing = Some(entry.private_key_multibase.clone());
                }
                KeyType::X25519 if ka.is_none() => {
                    ka = Some(entry.private_key_multibase.clone());
                }
                _ => {}
            }
        }

        let signing = signing.ok_or("VTA bundle contains no Ed25519 signing key")?;
        let ka = ka.ok_or("VTA bundle contains no X25519 key agreement key")?;

        eprintln!("  VTA bundle decoded for DID: {}", bundle.did);
        eprintln!("  Found {} secret(s)", bundle.secrets.len());

        (signing, ka)
    } else if let Some(signing) = signing_key {
        let ka = ka_key.ok_or("--ka-key is required when using --signing-key")?;
        (signing, ka)
    } else {
        return Err("provide either --vta-bundle or --signing-key + --ka-key".into());
    };

    // Validate keys by attempting to parse them
    Secret::from_multibase(&resolved_signing, None)
        .map_err(|e| format!("invalid signing key: {e}"))?;
    Secret::from_multibase(&resolved_ka, None)
        .map_err(|e| format!("invalid key agreement key: {e}"))?;

    let server_secrets = ServerSecrets {
        signing_key: resolved_signing,
        key_agreement_key: resolved_ka,
        jwt_signing_key: jwt_signing_key(jwt_key)?,
        vta_credential,
        retired: retired_keys(secret_store.as_ref()).await,
    };

    secret_store.set(&server_secrets).await?;

    eprintln!();
    eprintln!("  Secrets imported successfully!");
    eprintln!();
    if is_plaintext_backend(config.secrets()) {
        eprintln!("  WARNING: secrets stored in plaintext — not for production use.");
        eprintln!();
    }

    Ok(())
}

async fn export_sealed<C: ServiceConfig>(
    config: &C,
    service: Service,
    request: &Path,
    out: &Path,
    digest_out: Option<&Path>,
) -> CliResult {
    use super::secret_store::create_secret_store;
    use super::vta_setup::{ExportAssertionMode, export_sealed_did_secrets};

    let producer_did = config
        .server_did()
        .ok_or("server_did not set in config — run setup first")?
        .to_string();

    // Load the existing signing + KA keys from the configured secret store.
    let secret_store = create_secret_store(config.secrets(), config.config_path())?;
    let secrets = secret_store
        .get()
        .await?
        .ok_or("no secrets found — run setup or import-secrets first")?;

    let info = export_sealed_did_secrets(
        request,
        out,
        &producer_did,
        &producer_did,
        secrets.signing_key.clone(),
        secrets.key_agreement_key.clone(),
        ExportAssertionMode::DidSigned {
            signing_key_multibase: secrets.signing_key.clone(),
            verification_method: format!("{producer_did}#key-0"),
        },
    )
    .await?;

    if let Some(digest_path) = digest_out {
        if let Some(parent) = digest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(digest_path, format!("{}\n", info.digest))?;
    }

    // The Ed25519 public-key multibase, for the operator to share with the
    // receiver (for DidSigned verification).
    let producer_pub = affinidi_tdk::secrets_resolver::secrets::Secret::from_multibase(
        &secrets.signing_key,
        None,
    )?
    .get_public_keymultibase()?;

    eprintln!();
    eprintln!("  Sealed export ready.");
    eprintln!();
    eprintln!("  Out:            {}", info.out_path.display());
    eprintln!("  Recipient DID:  {}", info.recipient_did);
    eprintln!("  Bundle id:      {}", info.bundle_id_hex);
    eprintln!();
    eprintln!("  SHA-256 digest (send OOB to receiver):");
    eprintln!("    {}", info.digest);
    if let Some(p) = digest_out {
        eprintln!("  Digest also written to {}", p.display());
    }
    eprintln!();
    eprintln!("  Producer assertion mode: DidSigned. The bundle is signed by");
    eprintln!(
        "  this {}'s `#key-0` Ed25519 key. Receivers who pin the",
        service.noun()
    );
    eprintln!("  producer pubkey via --producer-pubkey get cryptographic");
    eprintln!("  verification; without it the OOB digest stays the only anchor.");
    eprintln!();
    eprintln!("  Producer pubkey (share with receiver — matches #key-0):");
    eprintln!("    {producer_pub}");
    eprintln!();
    eprintln!("  Next steps on the receiver:");
    eprintln!(
        "    {} import-sealed --bundle {} \\\n      --expect-digest {} \\\n      --producer-pubkey {producer_pub}",
        service.binary(),
        info.out_path.display(),
        info.digest
    );
    eprintln!();

    Ok(())
}

async fn import_sealed<C: ServiceConfig>(
    config: &C,
    bundle: &Path,
    expect_digest: &str,
    seed: &Path,
    producer_pubkey: Option<&str>,
    jwt_key: Option<String>,
    force: bool,
) -> CliResult {
    use super::secret_store::{ServerSecrets, create_secret_store};
    use super::vta_setup::open_sealed_did_secrets;
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let secret_store = create_secret_store(config.secrets(), config.config_path())?;

    if !force && let Ok(Some(_)) = secret_store.get().await {
        return Err("secrets already exist — use --force to overwrite".into());
    }

    // The optional producer pubkey (multibase-encoded Ed25519 public) for
    // DidSigned verification. None falls back to digest-only trust (accepts
    // any assertion variant, unverified).
    let expected_pubkey_bytes = producer_pubkey
        .map(decode_ed25519_pubkey_multibase)
        .transpose()?;

    let armor =
        std::fs::read_to_string(bundle).map_err(|e| format!("read {}: {e}", bundle.display()))?;
    let result =
        open_sealed_did_secrets(&armor, expect_digest, seed, expected_pubkey_bytes.as_ref())?;

    // Sanity-check the keys parse before writing anything.
    Secret::from_multibase(&result.signing_key_multibase, None)
        .map_err(|e| format!("invalid signing key in bundle: {e}"))?;
    Secret::from_multibase(&result.key_agreement_multibase, None)
        .map_err(|e| format!("invalid key-agreement key in bundle: {e}"))?;

    let server_secrets = ServerSecrets {
        signing_key: result.signing_key_multibase,
        key_agreement_key: result.key_agreement_multibase,
        jwt_signing_key: jwt_signing_key(jwt_key)?,
        vta_credential: None,
        retired: retired_keys(secret_store.as_ref()).await,
    };

    secret_store.set(&server_secrets).await?;

    eprintln!();
    eprintln!("  Sealed bundle opened and imported.");
    eprintln!();
    eprintln!("  DID:            {}", result.did);
    if result.assertion_verified {
        eprintln!(
            "  Producer DID:   {} (DidSigned — signature verified)",
            result.producer_did
        );
    } else {
        eprintln!(
            "  Producer DID:   {} (informational — no producer pubkey supplied)",
            result.producer_did
        );
    }
    eprintln!();
    eprintln!(
        "  Note: update server_did in config.toml to {} if not already set.",
        result.did
    );
    eprintln!();

    Ok(())
}

/// Decode a multibase-encoded Ed25519 public key into the raw 32-byte
/// array. Accepts both the bare-key form (32 bytes after multibase
/// decode) and the multicodec-prefixed form (34 bytes, leading
/// 0xED 0x01).
pub fn decode_ed25519_pubkey_multibase(mb: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let (_, raw) =
        multibase::decode(mb).map_err(|e| format!("invalid producer pubkey multibase: {e}"))?;
    let pk_bytes: &[u8] = if raw.len() == 34 && raw[0] == 0xed && raw[1] == 0x01 {
        &raw[2..]
    } else {
        &raw[..]
    };
    pk_bytes
        .try_into()
        .map_err(|_| "producer pubkey is not a 32-byte Ed25519 key".into())
}

// ---------------------------------------------------------------------------
// Air-gapped VTA provisioning
// ---------------------------------------------------------------------------

/// The primitives of air-gapped VTA provisioning. Neither reads the
/// service's configuration.
#[derive(Debug, Subcommand)]
pub enum VtaCommand {
    /// Write an offline VTA bootstrap request (for air-gapped VTAs).
    ///
    /// Generates an ephemeral Ed25519 keypair and writes a JSON request
    /// the operator ferries to the VTA admin. Keep the companion seed
    /// file safe — it's needed to open the sealed response.
    VtaRequest {
        /// Path for the bootstrap-request.json file.
        #[arg(long, default_value = "bootstrap-request.json")]
        out: PathBuf,
        /// Path for the ephemeral seed (keep this secret; chmod 0600 on Unix).
        #[arg(long, default_value = "bootstrap-seed.bin")]
        seed: PathBuf,
        /// Operator-visible label identifying this request. Defaults to the
        /// binary's name.
        #[arg(long)]
        label: Option<String>,
        /// Public URL where this service serves its DID (e.g.
        /// `https://server1.example.com`). It names where the VTA publishes
        /// the DID's log and, through its path, the DID path. With
        /// `--mediator-did` the DID advertises only its messaging transports
        /// (`TSPTransport` / `DIDCommMessaging`), not this URL; only an
        /// HTTP-only DID (no mediator) carries a `WebVHHosting` service here.
        #[arg(long, visible_alias = "did-hosting-url")]
        public_url: String,
        /// VTA context the integration will live in. Embedded as
        /// `contextHint` in the request so the VTA admin can run
        /// `vta bootstrap provision-integration` without `--context`.
        #[arg(long, default_value = "did-hosting")]
        context: String,
        /// DIDComm mediator DID to advertise on this service's DID. When set,
        /// the rendered DID exposes a `TSPTransport` and/or `DIDCommMessaging`
        /// service at this mediator (per `--transport`), so peers can reach
        /// the service over messaging without out-of-band config — matching
        /// the interactive setup. Omit for an HTTP-only DID.
        #[arg(long)]
        mediator_did: Option<String>,
        /// Which messaging transport(s) to advertise at `--mediator-did`:
        /// `both`, `tsp`, or `didcomm`. Ignored when no mediator is given.
        #[arg(long, default_value = "both")]
        transport: String,
    },
    /// Open a sealed VTA bootstrap response (primitive — prefer
    /// `setup-offline-complete` for a full wizard-driven finish).
    ///
    /// Reads the armored bundle the operator ferried back, verifies the
    /// out-of-band digest, opens the HPKE sealed payload with the
    /// ephemeral seed, and emits the DID document + signed DID log, and the
    /// minted keys for `import-secrets` (or `setup`).
    VtaOpen {
        /// Path to the ASCII-armored sealed bundle.
        #[arg(long)]
        bundle: PathBuf,
        /// Expected SHA-256 digest of the armored ciphertext (from the
        /// operator, out-of-band).
        #[arg(long)]
        expect_digest: String,
        /// Path to the ephemeral seed saved by `vta-request`.
        #[arg(long, default_value = "bootstrap-seed.bin")]
        seed: PathBuf,
        /// Where to write the rendered DID document as JSON. Defaults to
        /// `<service>-did.json` (`server`, `control` or `daemon`).
        #[arg(long)]
        did_doc_out: Option<PathBuf>,
        /// Where to write the signed DID log (JSONL). Omitted when the
        /// template didn't emit a WebvhLog output. Defaults to
        /// `<service>-did.jsonl`.
        #[arg(long)]
        did_log_out: Option<PathBuf>,
        /// Where to save the minted private signing + KA key pair plus
        /// VTA trust material (authorization VC, pinned VTA DID) as JSON.
        /// Defaults to `<service>-secrets.json`.
        #[arg(long)]
        secrets_out: Option<PathBuf>,
    },
}

impl VtaCommand {
    /// Run the command as `service`.
    pub async fn run(self, service: Service) -> CliResult {
        use super::vta_setup::{
            WebvhDidShape, build_webvh_provision_ask, run_offline_open_cli, run_offline_request_cli,
        };
        match self {
            Self::VtaRequest {
                out,
                seed,
                label,
                public_url,
                context,
                mediator_did,
                transport,
            } => {
                // `public_url` may carry the DID path; split it back out so
                // the shared builder folds it identically to the wizard. The
                // DID advertises its messaging transport(s) when
                // `--mediator-did` is given, and stays HTTP-only otherwise.
                let transport = super::config::TransportSelection::parse(&transport)?;
                let (origin, did_path) =
                    super::setup_recipe::split_origin_and_did_path(&public_url);
                let shape = WebvhDidShape::Hosted {
                    origin: &origin,
                    did_path: &did_path,
                    mediator_did: mediator_did.as_deref(),
                    transport,
                    remote: None,
                };
                let label = label.unwrap_or_else(|| service.binary().to_string());
                let ask = build_webvh_provision_ask(&context, &shape, Some(&label));
                run_offline_request_cli(&out, &seed, service.binary(), &ask).await
            }
            Self::VtaOpen {
                bundle,
                expect_digest,
                seed,
                did_doc_out,
                did_log_out,
                secrets_out,
            } => {
                let prefix = service.artifact_prefix();
                let or = |p: Option<PathBuf>, suffix: &str| {
                    p.unwrap_or_else(|| PathBuf::from(format!("{prefix}-{suffix}")))
                };
                run_offline_open_cli(
                    &bundle,
                    &expect_digest,
                    &seed,
                    &or(did_doc_out, "did.json"),
                    &or(did_log_out, "did.jsonl"),
                    &or(secrets_out, "secrets.json"),
                    service.open_next_step(),
                )
            }
        }
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;

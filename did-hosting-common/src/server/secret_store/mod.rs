//! Storage for the service's own key material.
//!
//! Every backend is [`vti_secrets`]' implementation — the same code the VTA and
//! VTC use: OS keyring, AWS Secrets Manager, GCP Secret Manager, Azure Key
//! Vault, HashiCorp Vault, Kubernetes `Secret`, and a test-only plaintext file.
//! This module adds only what is specific to a webvh service:
//!
//! - [`ServerSecrets`], the keys a service holds, and the offline-bootstrap
//!   seed, serialised together as one [`StoredSecrets`] JSON envelope that is
//!   the backend's payload. One entry means one IAM/RBAC grant, and a rotation
//!   that retires a key and installs its replacement is a single write.
//! - [`to_vti_config`], which maps the `[secrets]` config onto
//!   [`vti_secrets::SecretsConfig`] with an explicit backend.
//! - A refusal, not a fallback, when no secure store exists. The default
//!   backend is the OS keyring; a host without one (a headless Linux box with
//!   no Secret Service) is told which secure backends it can use instead.
//!   Plaintext is never chosen implicitly: it needs `backend = "plaintext"`
//!   *and* `confirm_plaintext = true`, and is for tests only.

#[cfg(feature = "setup-wizard")]
pub mod wizard;

pub use vti_secrets::SecretBackend;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use vti_secrets::SeedStore;
use vti_secrets::seed_store::PlaintextSeedStore;

use crate::server::config::SecretsConfig;
use crate::server::error::AppError;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Server secret key material stored in the secret store.
///
/// All keys are stored as multibase-encoded private keys (Base58BTC with
/// multicodec type prefix), matching the format used by `Secret::from_multibase()`
/// and `Secret::get_private_keymultibase()` in the affinidi-secrets-resolver.
///
/// This encoding is self-describing: the multicodec prefix identifies the key
/// type (Ed25519, X25519, etc.), so a `Secret` can be reconstructed directly
/// via `Secret::from_multibase(key, kid)`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerSecrets {
    /// Ed25519 private key for server DID signing (multibase-encoded).
    pub signing_key: String,
    /// X25519 private key for DIDComm key agreement (multibase-encoded).
    pub key_agreement_key: String,
    /// Ed25519 private key for JWT token signing (multibase-encoded).
    pub jwt_signing_key: String,
    /// VTA credential bundle (base64url-encoded) for re-authenticating with VTA.
    #[serde(default)]
    pub vta_credential: Option<String>,
    /// Key material for identity generations that have been retired but whose
    /// grace period has not yet elapsed.
    ///
    /// Peers cache DID documents, so after a key rotation they keep encrypting
    /// to the *old* key-agreement key for a while. Inbound decryption matches
    /// the JWE recipient `kid` against the secrets resolver rather than against
    /// our document, so holding the old secret is exactly what lets those
    /// messages still decrypt. See [`crate::server::identity`].
    ///
    /// **This lives in the same blob as the current keys on purpose.** A
    /// rotation must move the outgoing key here in the *same* write that
    /// installs its replacement: the secret store has no compare-and-swap, so
    /// two separate writes leave a crash window in which the old private key is
    /// gone from the store while peers are still encrypting to it — the precise
    /// failure the retirement window exists to prevent. Modelled on
    /// `vta_credential` (optional, `serde(default)`), not on the bootstrap seed,
    /// whose lifecycle is genuinely independent of these keys.
    ///
    /// Empty is the steady state; `skip_serializing_if` keeps the wire format
    /// byte-identical for deployments that have never rotated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<RetiredKeys>,
}

/// Key material for one retired identity generation, tagged with the key IDs
/// the DID document gave it.
///
/// Keyed by `kid` rather than by generation id: the kid is what a `Secret` must
/// be tagged with to be found during unpack, it is self-describing, and it
/// avoids having to agree with a generation id that is assigned later, on a
/// different write, in a different store.
#[derive(Clone, Serialize, Deserialize)]
pub struct RetiredKeys {
    /// The `keyAgreement` verification-method id this generation's DID document
    /// advertised. Inbound JWEs from peers with a stale document are addressed
    /// to this.
    pub ka_kid: String,
    /// X25519 private key for DIDComm key agreement (multibase-encoded).
    pub key_agreement_key: String,
    /// The `authentication` verification-method id. Inert for DIDComm (the
    /// outbound path does not sign), retained so a generation is fully
    /// reconstructible.
    pub signing_kid: String,
    /// Ed25519 private key for DID signing (multibase-encoded).
    pub signing_key: String,
}

impl std::fmt::Debug for RetiredKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetiredKeys")
            .field("ka_kid", &self.ka_kid)
            .field("key_agreement_key", &"<redacted>")
            .field("signing_kid", &self.signing_kid)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

// `Debug` is implemented manually to redact key material — derived `Debug`
// would print private keys verbatim if a caller ever wrote `tracing::debug!(?secrets)`.
impl std::fmt::Debug for ServerSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSecrets")
            .field("signing_key", &"<redacted>")
            .field("key_agreement_key", &"<redacted>")
            .field("jwt_signing_key", &"<redacted>")
            .field(
                "vta_credential",
                &self.vta_credential.as_ref().map(|_| "<redacted>"),
            )
            .field("retired", &self.retired)
            .finish()
    }
}

/// The payload every backend stores: the long-lived [`ServerSecrets`] and the
/// short-lived offline-bootstrap seed, in **one** entry.
///
/// One entry means one IAM/RBAC grant covers both, and one write moves both.
/// Both fields are optional: phase 1 of the offline-bootstrap wizard writes
/// only the seed (before any signing keys exist), and phase 2 clears it.
///
/// Wire format (the backend stores these bytes; most hex-encode them):
/// ```json
/// { "secrets": { ... } | absent, "bootstrap_seed": "base64url..." | absent }
/// ```
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct StoredSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<ServerSecrets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_seed: Option<String>,
}

// `bootstrap_seed` is base64 of a 32-byte HPKE seed used to open sealed VTA
// bundles, so it is secret material. The inner `ServerSecrets` redacts itself.
impl std::fmt::Debug for StoredSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSecrets")
            .field("secrets", &self.secrets)
            .field(
                "bootstrap_seed",
                &self.bootstrap_seed.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl StoredSecrets {
    fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        serde_json::from_slice(bytes).map_err(|e| {
            AppError::SecretStore(format!(
                "the stored secrets envelope is not valid JSON: {e}"
            ))
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, AppError> {
        serde_json::to_vec(self)
            .map_err(|e| AppError::SecretStore(format!("failed to serialise secrets: {e}")))
    }

    fn encode_seed(seed: &[u8; 32]) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        B64.encode(seed)
    }

    fn decode_seed(b64: &str) -> Result<[u8; 32], AppError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        let bytes = B64.decode(b64.trim().as_bytes()).map_err(|e| {
            AppError::SecretStore(format!("failed to base64-decode bootstrap seed: {e}"))
        })?;
        bytes.as_slice().try_into().map_err(|_| {
            AppError::SecretStore(format!(
                "bootstrap seed has {} bytes, expected 32",
                bytes.len()
            ))
        })
    }
}

pub trait SecretStore: Send + Sync {
    fn get(&self) -> BoxFuture<'_, Result<Option<ServerSecrets>, AppError>>;
    fn set(&self, secrets: &ServerSecrets) -> BoxFuture<'_, Result<(), AppError>>;

    /// Read the persisted offline-bootstrap ephemeral seed, if any.
    ///
    /// Returns `None` when no seed has been stored — the typical state
    /// at runtime, since the seed is short-lived (set during phase 1,
    /// consumed and cleared at phase 2).
    fn get_bootstrap_seed(&self) -> BoxFuture<'_, Result<Option<[u8; 32]>, AppError>>;

    /// Persist the offline-bootstrap ephemeral seed.
    ///
    /// Called by phase 1 of the offline-bootstrap wizard; the seed is
    /// the receiver-side X25519 secret needed to open the sealed
    /// response in phase 2.
    fn set_bootstrap_seed(&self, seed: &[u8; 32]) -> BoxFuture<'_, Result<(), AppError>>;

    /// Remove the persisted offline-bootstrap ephemeral seed.
    ///
    /// Called by phase 2 once the sealed response has been opened
    /// successfully.  No-op if no seed is stored.
    fn clear_bootstrap_seed(&self) -> BoxFuture<'_, Result<(), AppError>>;
}

/// A [`SecretStore`] over any `vti-secrets` backend: the [`StoredSecrets`]
/// envelope is the backend's payload.
struct EnvelopeStore {
    inner: Box<dyn SeedStore>,
}

impl EnvelopeStore {
    async fn load(&self) -> Result<StoredSecrets, AppError> {
        match self.inner.get().await.map_err(from_vti)? {
            Some(bytes) => StoredSecrets::from_bytes(&bytes),
            None => Ok(StoredSecrets::default()),
        }
    }

    async fn save(&self, env: &StoredSecrets) -> Result<(), AppError> {
        self.inner.set(&env.to_bytes()?).await.map_err(from_vti)
    }
}

impl SecretStore for EnvelopeStore {
    fn get(&self) -> BoxFuture<'_, Result<Option<ServerSecrets>, AppError>> {
        Box::pin(async move { Ok(self.load().await?.secrets) })
    }

    fn set(&self, secrets: &ServerSecrets) -> BoxFuture<'_, Result<(), AppError>> {
        let secrets = secrets.clone();
        Box::pin(async move {
            let mut env = self.load().await?;
            env.secrets = Some(secrets);
            self.save(&env).await
        })
    }

    fn get_bootstrap_seed(&self) -> BoxFuture<'_, Result<Option<[u8; 32]>, AppError>> {
        Box::pin(async move {
            self.load()
                .await?
                .bootstrap_seed
                .as_deref()
                .map(StoredSecrets::decode_seed)
                .transpose()
        })
    }

    fn set_bootstrap_seed(&self, seed: &[u8; 32]) -> BoxFuture<'_, Result<(), AppError>> {
        let encoded = StoredSecrets::encode_seed(seed);
        Box::pin(async move {
            let mut env = self.load().await?;
            env.bootstrap_seed = Some(encoded);
            self.save(&env).await
        })
    }

    fn clear_bootstrap_seed(&self) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            let mut env = self.load().await?;
            if env.bootstrap_seed.take().is_none() {
                return Ok(());
            }
            self.save(&env).await
        })
    }
}

/// `vti-secrets` reports errors in `vti-common`'s `AppError`; keep the
/// config-vs-store distinction when bringing them into this crate's.
pub(crate) fn from_vti(e: vti_common::error::AppError) -> AppError {
    match e {
        vti_common::error::AppError::Config(msg) => AppError::Config(msg),
        other => AppError::SecretStore(other.to_string()),
    }
}

/// The keyring entry (`user`) that holds the envelope, under
/// `secrets.keyring_service`.
const KEYRING_USER: &str = "server_secrets";

/// Which backend `secrets` selects.
///
/// `secrets.backend`, when set, wins outright. Otherwise the backend is the one
/// whose selector field is set — AWS (`aws_secret_name`) → GCP
/// (`gcp_secret_name`) → Azure (`azure_secret_name`) → Vault (`vault_addr`) →
/// Kubernetes (`k8s_secret_name`) — and failing all of those, the OS keyring.
/// Plaintext is never selected implicitly.
pub fn resolve_backend(secrets: &SecretsConfig) -> SecretBackend {
    if let Some(b) = secrets.backend {
        return b;
    }
    if secrets.aws_secret_name.is_some() {
        SecretBackend::Aws
    } else if secrets.gcp_secret_name.is_some() {
        SecretBackend::Gcp
    } else if secrets.azure_secret_name.is_some() {
        SecretBackend::Azure
    } else if secrets.vault_addr.is_some() {
        SecretBackend::Vault
    } else if secrets.k8s_secret_name.is_some() {
        SecretBackend::Kubernetes
    } else {
        SecretBackend::Keyring
    }
}

/// Returns `true` when `secrets` selects the (test-only) plaintext backend.
pub fn is_plaintext_backend(secrets: &SecretsConfig) -> bool {
    resolve_backend(secrets) == SecretBackend::Plaintext
}

/// Human-readable name of the backend `secrets` selects.
pub fn backend_label(secrets: &SecretsConfig) -> &'static str {
    match resolve_backend(secrets) {
        SecretBackend::Keyring => "OS keyring",
        SecretBackend::Aws => "AWS Secrets Manager",
        SecretBackend::Gcp => "GCP Secret Manager",
        SecretBackend::Azure => "Azure Key Vault",
        SecretBackend::Vault => "HashiCorp Vault",
        SecretBackend::Kubernetes => "Kubernetes Secret",
        SecretBackend::Plaintext => "Plaintext file",
        SecretBackend::ConfigSeed => "config_seed (unsupported)",
    }
}

fn required(value: &Option<String>, backend: &str, field: &str) -> Result<String, AppError> {
    value.clone().ok_or_else(|| {
        AppError::Config(format!(
            "secrets backend '{backend}' requires secrets.{field}"
        ))
    })
}

/// Map the `[secrets]` config onto [`vti_secrets::SecretsConfig`].
///
/// The result always names its backend explicitly, so a stray selector field
/// left over from another backend can never redirect the keys. Only the
/// selected backend's fields are copied. Fails when a required field is
/// missing, when plaintext is selected without `confirm_plaintext`, or when
/// `config_seed` is selected (it would put private keys in `config.toml`).
pub fn to_vti_config(secrets: &SecretsConfig) -> Result<vti_secrets::SecretsConfig, AppError> {
    let backend = resolve_backend(secrets);
    let mut out = vti_secrets::SecretsConfig::default();
    out.backend = Some(backend);
    // A store is built per operation and read once, so an in-memory cache
    // would never be hit; keep reads direct.
    out.cache_ttl_secs = 0;
    match backend {
        SecretBackend::Keyring => {
            out.keyring_service = secrets.keyring_service.clone();
        }
        SecretBackend::Aws => {
            out.aws_secret_name = Some(required(
                &secrets.aws_secret_name,
                "aws",
                "aws_secret_name",
            )?);
            out.aws_region = secrets.aws_region.clone();
        }
        SecretBackend::Gcp => {
            out.gcp_secret_name = Some(required(
                &secrets.gcp_secret_name,
                "gcp",
                "gcp_secret_name",
            )?);
            out.gcp_project = Some(required(&secrets.gcp_project, "gcp", "gcp_project")?);
        }
        SecretBackend::Azure => {
            out.azure_vault_url = Some(required(
                &secrets.azure_vault_url,
                "azure",
                "azure_vault_url",
            )?);
            out.azure_secret_name = Some(required(
                &secrets.azure_secret_name,
                "azure",
                "azure_secret_name",
            )?);
        }
        SecretBackend::Vault => {
            out.vault_addr = Some(required(&secrets.vault_addr, "vault", "vault_addr")?);
            out.vault_secret_path = Some(required(
                &secrets.vault_secret_path,
                "vault",
                "vault_secret_path",
            )?);
            out.vault_kv_mount = secrets.vault_kv_mount.clone();
            out.vault_secret_key = secrets.vault_secret_key.clone();
            out.vault_namespace = secrets.vault_namespace.clone();
            out.vault_auth_method = secrets.vault_auth_method.clone();
            out.vault_k8s_role = secrets.vault_k8s_role.clone();
            out.vault_k8s_mount = secrets.vault_k8s_mount.clone();
            out.vault_k8s_jwt_path = secrets.vault_k8s_jwt_path.clone();
            out.vault_token = secrets.vault_token.clone();
            out.vault_approle_role_id = secrets.vault_approle_role_id.clone();
            out.vault_approle_secret_id = secrets.vault_approle_secret_id.clone();
            out.vault_approle_mount = secrets.vault_approle_mount.clone();
            out.vault_skip_verify = secrets.vault_skip_verify;
        }
        SecretBackend::Kubernetes => {
            out.k8s_secret_name = Some(required(
                &secrets.k8s_secret_name,
                "kubernetes",
                "k8s_secret_name",
            )?);
            out.k8s_namespace = secrets.k8s_namespace.clone();
            out.k8s_secret_key = secrets.k8s_secret_key.clone();
        }
        SecretBackend::Plaintext => {
            if !secrets.confirm_plaintext {
                return Err(AppError::Config(
                    "secrets.backend = \"plaintext\" stores the service's private keys in a \
                     clear-text file and is for tests only. Set secrets.confirm_plaintext = true \
                     to accept that, or choose a secure backend."
                        .into(),
                ));
            }
            out.allow_plaintext = true;
        }
        SecretBackend::ConfigSeed => {
            return Err(AppError::Config(
                "secrets.backend = \"config_seed\" is not supported: it would put the \
                 service's private keys in config.toml. Choose a secure backend."
                    .into(),
            ));
        }
    }
    Ok(out)
}

/// The refusal a host without a secure store gets, naming what it can use.
pub(crate) fn no_secure_store(reason: &str) -> AppError {
    AppError::SecretStore(format!(
        "no secure secret store is available on this host: {reason}\n\
         \n\
         The service will not fall back to keeping its private keys in clear text. \
         Configure one of these in [secrets] (or [secrets] backend in a setup recipe):\n\
         \x20 - vault:    HashiCorp Vault KV v2 (vault_addr, vault_secret_path)\n\
         \x20 - k8s:      a Kubernetes Secret (k8s_secret_name)\n\
         \x20 - aws:      AWS Secrets Manager, KMS-encrypted (aws_secret_name)\n\
         \x20 - gcp:      GCP Secret Manager (gcp_project, gcp_secret_name)\n\
         \x20 - azure:    Azure Key Vault (azure_vault_url, azure_secret_name)\n\
         \x20 - keyring:  the OS credential store: macOS Keychain, Windows Credential \
         Manager, or on Linux a Secret Service provider (gnome-keyring, KWallet, \
         KeePassXC) on a reachable D-Bus session\n\
         Each needs its cargo feature (vault-secrets, k8s-secrets, aws-secrets, \
         gcp-secrets, azure-secrets, keyring). For tests only, backend = \"plaintext\" \
         with confirm_plaintext = true keeps the keys in a clear-text file."
    ))
}

/// Refuse unless the OS credential store can be opened, via `install` (the
/// platform-store registration). Split out so the refusal is testable on a
/// host that does have a keychain.
#[allow(dead_code)] // unused when the `keyring` feature is off
fn keyring_gate(install: impl FnOnce() -> Result<(), String>) -> Result<(), AppError> {
    install().map_err(|e| {
        no_secure_store(&format!(
            "the OS credential store (the default secrets backend) cannot be opened: {e}"
        ))
    })
}

/// Register the platform credential store once per process. A failure is not
/// cached, so a store that comes up later (D-Bus at boot) is picked up.
#[cfg(feature = "keyring")]
pub(crate) fn ensure_keyring() -> Result<(), AppError> {
    static REGISTERED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if REGISTERED.get().is_some() {
        return Ok(());
    }
    keyring_gate(|| vta_sdk::keyring_init::install_default_store().map_err(|e| e.to_string()))?;
    let _ = REGISTERED.set(());
    Ok(())
}

/// Where the plaintext backend keeps its file: beside the config file, named
/// after it (`config.toml` → `config.secrets.plaintext`), so services sharing a
/// directory do not share keys.
pub fn plaintext_path(config_path: &Path) -> PathBuf {
    let dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = config_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    dir.join(format!("{stem}.secrets.plaintext"))
}

/// Build the secret store `secrets` selects (see [`resolve_backend`]).
///
/// `config_path` is consulted only by the plaintext backend, whose file sits
/// beside the config (see [`plaintext_path`]).
///
/// Fails closed: a backend this binary was built without, a missing required
/// field, or an OS keyring that cannot be opened is an error listing the secure
/// backends — never a silent fall-through to a weaker store.
pub fn create_secret_store(
    secrets: &SecretsConfig,
    config_path: &Path,
) -> Result<Box<dyn SecretStore>, AppError> {
    let vti = to_vti_config(secrets)?;
    let inner: Box<dyn SeedStore> = match resolve_backend(secrets) {
        SecretBackend::Keyring => keyring_store(&vti)?,
        SecretBackend::Plaintext => {
            let path = plaintext_path(config_path);
            tracing::warn!(
                path = %path.display(),
                "secrets are stored in a PLAINTEXT file — for tests only, never production"
            );
            let dir = path.parent().unwrap_or_else(|| Path::new("."));
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("config.secrets.plaintext");
            Box::new(PlaintextSeedStore::with_filename(dir, name))
        }
        // Cloud / Vault / Kubernetes: vti-secrets' factory builds them, and
        // refuses one this binary was compiled without.
        _ => vti_secrets::create_seed_store(&vti, Path::new(".")).map_err(from_vti)?,
    };
    Ok(Box::new(EnvelopeStore { inner }))
}

#[cfg(feature = "keyring")]
fn keyring_store(vti: &vti_secrets::SecretsConfig) -> Result<Box<dyn SeedStore>, AppError> {
    ensure_keyring()?;
    Ok(Box::new(vti_secrets::seed_store::KeyringSeedStore::new(
        vti.keyring_service.clone(),
        KEYRING_USER,
    )))
}

#[cfg(not(feature = "keyring"))]
fn keyring_store(_vti: &vti_secrets::SecretsConfig) -> Result<Box<dyn SeedStore>, AppError> {
    let _ = KEYRING_USER;
    Err(no_secure_store(
        "no backend is configured, and the default (the OS keyring) is not compiled \
         into this binary",
    ))
}

#[cfg(test)]
mod tests;

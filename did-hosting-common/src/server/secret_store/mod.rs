#[cfg(feature = "aws-secrets")]
pub mod aws;
#[cfg(feature = "azure-secrets")]
pub mod azure;
#[cfg(feature = "gcp-secrets")]
pub mod gcp;
#[cfg(feature = "keyring")]
mod keyring;
mod plaintext;
#[cfg(feature = "setup-wizard")]
pub mod wizard;

#[cfg(feature = "aws-secrets")]
pub use aws::AwsSecretStore;
#[cfg(feature = "azure-secrets")]
pub use azure::AzureKeyVaultStore;
#[cfg(feature = "gcp-secrets")]
pub use gcp::GcpSecretStore;
#[cfg(feature = "keyring")]
pub use keyring::KeyringSecretStore;

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::server::config::SecretsConfig;
use crate::server::error::AppError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
            .finish()
    }
}

/// On-the-wire envelope for cloud-backed secret stores (AWS, GCP, Azure).
///
/// Holds both the long-lived [`ServerSecrets`] and the short-lived
/// offline-bootstrap ephemeral seed in the **same** secret entry, so a
/// single IAM/RBAC grant covers both. Earlier 0.6.x releases stored
/// the seed in a sibling `<name>-bootstrap-seed` secret, which forced
/// operators to scope IAM more broadly than expected.
///
/// All fields are optional so phase 1 of the offline-bootstrap wizard
/// (which writes only the seed, before any signing keys exist) and
/// the post-phase-2 cleared state (no seed, only secrets) both
/// serialise cleanly.
///
/// Wire format:
/// ```json
/// { "secrets": { ... } | absent, "bootstrap_seed": "base64..." | absent }
/// ```
#[cfg(any(
    feature = "aws-secrets",
    feature = "gcp-secrets",
    feature = "azure-secrets"
))]
#[derive(Default, Clone, Serialize, Deserialize)]
pub(crate) struct StoredSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<ServerSecrets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_seed: Option<String>,
}

// `bootstrap_seed` is base64 of a 32-byte HPKE seed used to open sealed
// VTA bundles. Treat it as secret material and redact in `Debug`. The inner
// `ServerSecrets` already redacts itself.
#[cfg(any(
    feature = "aws-secrets",
    feature = "gcp-secrets",
    feature = "azure-secrets"
))]
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

#[cfg(any(
    feature = "aws-secrets",
    feature = "gcp-secrets",
    feature = "azure-secrets"
))]
impl StoredSecrets {
    /// Parse the on-the-wire shape, accepting both the new envelope and
    /// the legacy bare [`ServerSecrets`] blob written by 0.6.x deployments
    /// before the envelope refactor. Legacy blobs migrate transparently
    /// on the next write.
    pub(crate) fn parse(json: &str) -> Result<Self, serde_json::Error> {
        // Bare ServerSecrets has three mandatory string fields and would
        // never match an empty/seed-only envelope. Try it first so we
        // fall through to envelope parsing only when this can't load.
        if let Ok(bare) = serde_json::from_str::<ServerSecrets>(json) {
            return Ok(Self {
                secrets: Some(bare),
                bootstrap_seed: None,
            });
        }
        serde_json::from_str(json)
    }

    /// Serialise the envelope as JSON. Empty fields are skipped.
    pub(crate) fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Encode a 32-byte bootstrap seed into the envelope's wire form
    /// (URL-safe base64, no padding).
    #[allow(dead_code)] // used only when at least one cloud backend is enabled
    pub(crate) fn encode_seed(seed: &[u8; 32]) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        B64.encode(seed)
    }

    /// Decode a 32-byte bootstrap seed from the envelope's wire form.
    #[allow(dead_code)] // used only when at least one cloud backend is enabled
    pub(crate) fn decode_seed(b64: &str) -> Result<[u8; 32], AppError> {
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

/// Returns `true` when the plaintext fallback backend will actually be used.
///
/// This mirrors the priority logic in [`create_secret_store`]: AWS → GCP →
/// keyring → plaintext. Returns `true` only when no higher-priority backend
/// is both compiled in and configured.
#[allow(unused_variables)]
pub fn is_plaintext_backend(secrets: &SecretsConfig) -> bool {
    // If any secure backend is compiled in AND would be selected, not plaintext.
    #[cfg(feature = "aws-secrets")]
    if secrets.aws_secret_name.is_some() {
        return false;
    }

    #[cfg(feature = "gcp-secrets")]
    if secrets.gcp_secret_name.is_some() {
        return false;
    }

    #[cfg(feature = "azure-secrets")]
    if secrets.azure_secret_name.is_some() {
        return false;
    }

    // Explicit plaintext selection (e.g. recipe `backend = "plaintext"`) beats a
    // compiled-in keyring — see `create_secret_store`.
    if secrets.plaintext_mode {
        return true;
    }

    // Keyring is only used when compiled in AND no cloud backend was selected above.
    // But it is unconditionally preferred over plaintext when compiled in.
    #[cfg(feature = "keyring")]
    {
        return false;
    }

    // No secure backend compiled in — plaintext fallback will be used.
    #[allow(unreachable_code)]
    true
}

/// Create a secret store backend based on compiled features and configuration.
///
/// Priority:
/// 1. AWS Secrets Manager (if `aws-secrets` compiled + `secrets.aws_secret_name` set)
/// 2. GCP Secret Manager (if `gcp-secrets` compiled + `secrets.gcp_secret_name` set)
/// 3. Azure Key Vault (if `azure-secrets` compiled + `secrets.azure_secret_name` set)
/// 4. OS keyring (if `keyring` compiled — the default)
/// 5. Plaintext in config file (fallback when no secure backend is available)
#[allow(unused_variables)]
pub fn create_secret_store(
    secrets: &SecretsConfig,
    config_path: &std::path::Path,
) -> Result<Box<dyn SecretStore>, AppError> {
    #[cfg(feature = "aws-secrets")]
    if secrets.aws_secret_name.is_some() {
        let store = AwsSecretStore::new(
            secrets.aws_secret_name.clone().unwrap(),
            secrets.aws_region.clone(),
        );
        return Ok(Box::new(store));
    }

    #[cfg(feature = "gcp-secrets")]
    if secrets.gcp_secret_name.is_some() {
        let project = secrets.gcp_project.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.gcp_project is required when secrets.gcp_secret_name is set".into(),
            )
        })?;
        let store = GcpSecretStore::new(project, secrets.gcp_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }

    #[cfg(feature = "azure-secrets")]
    if secrets.azure_secret_name.is_some() {
        let vault_url = secrets.azure_vault_url.clone().ok_or_else(|| {
            AppError::Config(
                "secrets.azure_vault_url is required when secrets.azure_secret_name is set".into(),
            )
        })?;
        let store = AzureKeyVaultStore::new(vault_url, secrets.azure_secret_name.clone().unwrap());
        return Ok(Box::new(store));
    }

    // Explicit plaintext selection beats a compiled-in keyring. Operators on a
    // headless host (no Secret Service) opt into plaintext via the recipe's
    // `backend = "plaintext"` / wizard confirmation; forcing keyring there would
    // panic at startup. Cloud backends above still take precedence when set.
    if secrets.plaintext_mode {
        let store = plaintext::PlaintextSecretStore::new(
            secrets.plaintext.as_ref(),
            config_path.to_path_buf(),
        );
        return Ok(Box::new(store));
    }

    #[cfg(feature = "keyring")]
    {
        let store = KeyringSecretStore::try_new(&secrets.keyring_service, "server_secrets")?;
        return Ok(Box::new(store));
    }

    // Fallback: plaintext secrets stored in the config file
    #[allow(unreachable_code)]
    {
        let store = plaintext::PlaintextSecretStore::new(
            secrets.plaintext.as_ref(),
            config_path.to_path_buf(),
        );
        Ok(Box::new(store))
    }
}

#[cfg(all(
    test,
    any(
        feature = "aws-secrets",
        feature = "gcp-secrets",
        feature = "azure-secrets"
    )
))]
mod stored_secrets_tests {
    use super::{ServerSecrets, StoredSecrets};

    #[test]
    fn parse_legacy_bare_server_secrets_blob() {
        let legacy = r#"{
            "signing_key": "sig",
            "key_agreement_key": "ka",
            "jwt_signing_key": "jwt"
        }"#;
        let env = StoredSecrets::parse(legacy).expect("legacy parses");
        let secrets = env.secrets.expect("secrets present");
        assert_eq!(secrets.signing_key, "sig");
        assert_eq!(secrets.key_agreement_key, "ka");
        assert_eq!(secrets.jwt_signing_key, "jwt");
        assert!(env.bootstrap_seed.is_none());
    }

    #[test]
    fn parse_envelope_with_seed_only() {
        let envelope = r#"{ "bootstrap_seed": "AAAA" }"#;
        let env = StoredSecrets::parse(envelope).expect("envelope parses");
        assert!(env.secrets.is_none());
        assert_eq!(env.bootstrap_seed.as_deref(), Some("AAAA"));
    }

    #[test]
    fn parse_envelope_with_both_fields() {
        let envelope = r#"{
            "secrets": {
                "signing_key": "sig",
                "key_agreement_key": "ka",
                "jwt_signing_key": "jwt"
            },
            "bootstrap_seed": "AAAA"
        }"#;
        let env = StoredSecrets::parse(envelope).expect("envelope parses");
        assert!(env.secrets.is_some());
        assert_eq!(env.bootstrap_seed.as_deref(), Some("AAAA"));
    }

    #[test]
    fn roundtrip_encodes_and_decodes_seed() {
        let seed = [42u8; 32];
        let b64 = StoredSecrets::encode_seed(&seed);
        let mut env = StoredSecrets::default();
        env.bootstrap_seed = Some(b64);
        env.secrets = Some(ServerSecrets {
            signing_key: "s".into(),
            key_agreement_key: "k".into(),
            jwt_signing_key: "j".into(),
            vta_credential: None,
        });
        let json = env.to_json().expect("serialises");
        let parsed = StoredSecrets::parse(&json).expect("re-parses");
        let decoded = StoredSecrets::decode_seed(parsed.bootstrap_seed.as_ref().unwrap()).unwrap();
        assert_eq!(decoded, seed);
    }

    #[test]
    fn empty_envelope_serialises_to_empty_object() {
        let env = StoredSecrets::default();
        assert_eq!(env.to_json().unwrap(), "{}");
    }
}

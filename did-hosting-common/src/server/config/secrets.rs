//! `[secrets]`: which secret-store backend holds the service's keys, and
//! its settings.

use serde::{Deserialize, Serialize};

use super::is_false;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Which backend holds the keys (`keyring`, `aws`, `gcp`, `azure`,
    /// `vault`, `kubernetes`, `plaintext`). When unset, the backend whose
    /// selector field is set is used, and failing that the OS keyring — see
    /// [`crate::server::secret_store::resolve_backend`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<crate::server::secret_store::SecretBackend>,
    pub aws_secret_name: Option<String>,
    pub aws_region: Option<String>,
    pub gcp_project: Option<String>,
    pub gcp_secret_name: Option<String>,
    /// Azure Key Vault DNS URL (e.g. `https://my-vault.vault.azure.net/`).
    /// Required when `azure_secret_name` is set.
    pub azure_vault_url: Option<String>,
    /// Azure Key Vault secret name. Used by `azure-secrets` backend.
    pub azure_secret_name: Option<String>,
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
    /// HashiCorp Vault server URL (vault-secrets feature). Setting this
    /// activates the Vault backend.
    pub vault_addr: Option<String>,
    /// KV v2 mount path (vault-secrets feature). Default `secret`.
    #[serde(default = "default_vault_kv_mount")]
    pub vault_kv_mount: String,
    /// KV v2 secret path under the mount, e.g. `webvh/server-secrets`
    /// (vault-secrets feature). Required when `vault_addr` is set.
    pub vault_secret_path: Option<String>,
    /// Field name within the KV v2 secret that holds the JSON secrets
    /// envelope (vault-secrets feature). Default `seed`.
    #[serde(default = "default_vault_secret_key")]
    pub vault_secret_key: String,
    /// Vault Enterprise namespace, if any (vault-secrets feature).
    pub vault_namespace: Option<String>,
    /// Auth method: `kubernetes` (default), `token`, or `approle`
    /// (vault-secrets feature).
    #[serde(default = "default_vault_auth_method")]
    pub vault_auth_method: String,
    /// Kubernetes auth role name (vault-secrets feature, kubernetes
    /// auth method).
    pub vault_k8s_role: Option<String>,
    /// Kubernetes auth mount path (vault-secrets feature). Default
    /// `kubernetes`.
    #[serde(default = "default_vault_k8s_mount")]
    pub vault_k8s_mount: String,
    /// File holding the ServiceAccount JWT presented to Vault
    /// (vault-secrets feature, kubernetes auth method). Default is the
    /// kubelet-mounted projected volume path.
    #[serde(default = "default_vault_k8s_jwt_path")]
    pub vault_k8s_jwt_path: String,
    /// Static token (vault-secrets feature, token auth method). Prefer
    /// the `VAULT_TOKEN` env var over hard-coding here.
    pub vault_token: Option<String>,
    /// AppRole role_id (vault-secrets feature, approle auth method).
    pub vault_approle_role_id: Option<String>,
    /// AppRole secret_id (vault-secrets feature, approle auth method).
    pub vault_approle_secret_id: Option<String>,
    /// AppRole mount path (vault-secrets feature). Default `approle`.
    #[serde(default = "default_vault_approle_mount")]
    pub vault_approle_mount: String,
    /// Skip TLS certificate verification — dev/test only
    /// (vault-secrets feature).
    #[serde(default, skip_serializing_if = "is_false")]
    pub vault_skip_verify: bool,
    /// Kubernetes `Secret` name holding the JSON secrets envelope
    /// (k8s-secrets feature). Setting this activates the Kubernetes
    /// backend.
    pub k8s_secret_name: Option<String>,
    /// Kubernetes namespace the `Secret` lives in (k8s-secrets feature).
    /// When unset, the in-cluster ServiceAccount namespace (or the
    /// kubeconfig context namespace) is used, falling back to `default`.
    pub k8s_namespace: Option<String>,
    /// Key within the `Secret`'s `data` map that holds the JSON secrets
    /// envelope (k8s-secrets feature). Default `seed`.
    #[serde(default = "default_k8s_secret_key")]
    pub k8s_secret_key: String,
    /// Test-only acknowledgement for `backend = "plaintext"`: the service's
    /// private keys are kept in a clear-text file beside the config. Without
    /// it, the plaintext backend refuses to build.
    #[serde(default, skip_serializing_if = "is_false")]
    pub confirm_plaintext: bool,
}

// Manual `Debug` redacts the Vault credentials. Cloud-secret-name fields are
// non-secret references (operators paste them into config) so they stay.
impl std::fmt::Debug for SecretsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsConfig")
            .field("backend", &self.backend)
            .field("aws_secret_name", &self.aws_secret_name)
            .field("aws_region", &self.aws_region)
            .field("gcp_project", &self.gcp_project)
            .field("gcp_secret_name", &self.gcp_secret_name)
            .field("azure_vault_url", &self.azure_vault_url)
            .field("azure_secret_name", &self.azure_secret_name)
            .field("keyring_service", &self.keyring_service)
            .field("vault_addr", &self.vault_addr)
            .field("vault_kv_mount", &self.vault_kv_mount)
            .field("vault_secret_path", &self.vault_secret_path)
            .field("vault_secret_key", &self.vault_secret_key)
            .field("vault_namespace", &self.vault_namespace)
            .field("vault_auth_method", &self.vault_auth_method)
            .field("vault_k8s_role", &self.vault_k8s_role)
            .field("vault_k8s_mount", &self.vault_k8s_mount)
            .field("vault_k8s_jwt_path", &self.vault_k8s_jwt_path)
            .field(
                "vault_token",
                &self.vault_token.as_ref().map(|_| "<redacted>"),
            )
            .field("vault_approle_role_id", &self.vault_approle_role_id)
            .field(
                "vault_approle_secret_id",
                &self.vault_approle_secret_id.as_ref().map(|_| "<redacted>"),
            )
            .field("vault_approle_mount", &self.vault_approle_mount)
            .field("vault_skip_verify", &self.vault_skip_verify)
            .field("k8s_secret_name", &self.k8s_secret_name)
            .field("k8s_namespace", &self.k8s_namespace)
            .field("k8s_secret_key", &self.k8s_secret_key)
            .field("confirm_plaintext", &self.confirm_plaintext)
            .finish()
    }
}

fn default_keyring_service() -> String {
    "webvh".to_string()
}

fn default_vault_kv_mount() -> String {
    "secret".to_string()
}

fn default_vault_secret_key() -> String {
    "seed".to_string()
}

fn default_vault_auth_method() -> String {
    "kubernetes".to_string()
}

fn default_vault_k8s_mount() -> String {
    "kubernetes".to_string()
}

fn default_vault_k8s_jwt_path() -> String {
    "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
}

fn default_vault_approle_mount() -> String {
    "approle".to_string()
}

fn default_k8s_secret_key() -> String {
    "seed".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            backend: None,
            aws_secret_name: None,
            aws_region: None,
            gcp_project: None,
            gcp_secret_name: None,
            azure_vault_url: None,
            azure_secret_name: None,
            keyring_service: default_keyring_service(),
            vault_addr: None,
            vault_kv_mount: default_vault_kv_mount(),
            vault_secret_path: None,
            vault_secret_key: default_vault_secret_key(),
            vault_namespace: None,
            vault_auth_method: default_vault_auth_method(),
            vault_k8s_role: None,
            vault_k8s_mount: default_vault_k8s_mount(),
            vault_k8s_jwt_path: default_vault_k8s_jwt_path(),
            vault_token: None,
            vault_approle_role_id: None,
            vault_approle_secret_id: None,
            vault_approle_mount: default_vault_approle_mount(),
            vault_skip_verify: false,
            k8s_secret_name: None,
            k8s_namespace: None,
            k8s_secret_key: default_k8s_secret_key(),
            confirm_plaintext: false,
        }
    }
}

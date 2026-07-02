//! Secret store backed by a native Kubernetes `Secret` resource.
//!
//! Ported from the VTA's `vti-secrets` Kubernetes backend: client setup,
//! namespace resolution, error formatting, and the preserve-other-keys
//! update logic are unchanged. The adaptation for did-hosting is the
//! payload — instead of a bare hex-encoded seed, the Secret's data key
//! holds the JSON [`StoredSecrets`] envelope, so `ServerSecrets` and the
//! offline-bootstrap seed share one Secret and one RBAC grant. All five
//! [`SecretStore`](super::SecretStore) methods read-modify-write that
//! envelope, mirroring the cloud backends (`aws`/`gcp`/`azure`).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use kube::{Client, ResourceExt};
use tracing::debug;

use crate::server::config::SecretsConfig;
use crate::server::error::AppError;

use super::{ServerSecrets, StoredSecrets};

/// Format a `kube` error with its full source chain for troubleshooting —
/// the top-level `Display` is usually a terse "ApiError"/"HyperError" that
/// hides the actual cause (RBAC denial, DNS, TLS, …).
fn format_kube_error(context: &str, err: kube::Error) -> AppError {
    let mut msg = format!("{context}: {err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        msg.push_str(&format!("\n  caused by: {cause}"));
        source = cause.source();
    }
    AppError::SecretStore(msg)
}

/// Secret store backed by a Kubernetes `Secret`.
///
/// The JSON [`StoredSecrets`] envelope is stored as a string under
/// `secret_key` inside a namespaced `Secret` resource. Authentication is
/// resolved by [`Client::try_default`]: the in-cluster ServiceAccount when
/// running inside a pod, or the local kubeconfig (`~/.kube/config` /
/// `$KUBECONFIG`) otherwise.
///
/// `namespace` is resolved at call time: the explicit config value if set,
/// otherwise the client's default namespace (the ServiceAccount's namespace
/// in-cluster, or the kubeconfig context's namespace), falling back to
/// `"default"` — all handled by `Client::default_namespace`.
pub struct K8sSecretStore {
    secret_name: String,
    namespace: Option<String>,
    secret_key: String,
}

impl K8sSecretStore {
    pub fn new(secret_name: String, namespace: Option<String>, secret_key: String) -> Self {
        Self {
            secret_name,
            namespace,
            secret_key,
        }
    }

    /// Build a namespaced `Secret` API handle, resolving the namespace and
    /// loading credentials from the in-cluster SA or local kubeconfig.
    async fn api(&self) -> Result<Api<Secret>, AppError> {
        let client = Client::try_default()
            .await
            .map_err(|e| format_kube_error("failed to initialise Kubernetes client", e))?;
        let namespace = self
            .namespace
            .clone()
            .unwrap_or_else(|| client.default_namespace().to_string());
        Ok(Api::namespaced(client, &namespace))
    }

    /// Read the current envelope. Returns `None` when the `Secret` does
    /// not yet exist (the first-boot case). Legacy bare-`ServerSecrets`
    /// blobs migrate transparently on the next write.
    async fn read_envelope(&self) -> Result<Option<StoredSecrets>, AppError> {
        let api = self.api().await?;
        // `get_opt` maps a 404 to `Ok(None)` for us — a missing Secret is
        // the legitimate first-boot case, not an error.
        let secret = api
            .get_opt(&self.secret_name)
            .await
            .map_err(|e| format_kube_error("failed to read Kubernetes Secret", e))?;

        let Some(secret) = secret else {
            debug!(secret = %self.secret_name, "Kubernetes Secret not found");
            return Ok(None);
        };

        let data = secret.data.unwrap_or_default();
        let Some(ByteString(raw)) = data.get(&self.secret_key) else {
            // The Secret exists but lacks our key. Returning `None` here
            // would make the caller think it is first-boot and mint *new*
            // keys, then overwrite — clobbering whatever the Secret
            // actually holds. Fail loudly instead.
            return Err(AppError::SecretStore(format!(
                "Kubernetes Secret '{}' exists but has no '{}' key",
                self.secret_name, self.secret_key
            )));
        };

        let json = std::str::from_utf8(raw).map_err(|e| {
            AppError::SecretStore(format!("Kubernetes Secret value is not valid UTF-8: {e}"))
        })?;
        let env = StoredSecrets::parse(json.trim()).map_err(|e| {
            AppError::SecretStore(format!(
                "failed to deserialize secrets from Kubernetes Secret: {e}"
            ))
        })?;
        Ok(Some(env))
    }

    /// Persist the envelope, creating the `Secret` on first write and
    /// preserving any unrelated data keys on subsequent writes.
    async fn write_envelope(&self, env: &StoredSecrets) -> Result<(), AppError> {
        let json = env
            .to_json()
            .map_err(|e| AppError::Internal(format!("envelope serialization for Kubernetes: {e}")))?;
        let api = self.api().await?;

        match api
            .get_opt(&self.secret_name)
            .await
            .map_err(|e| format_kube_error("failed to read Kubernetes Secret", e))?
        {
            Some(mut existing) => {
                // Preserve any other keys on the Secret (and its
                // resourceVersion, for optimistic concurrency); only
                // touch our own data key. `string_data` is write-only and
                // never round-trips on GET, so clear it before replacing.
                let mut data = existing.data.take().unwrap_or_default();
                data.insert(self.secret_key.clone(), ByteString(json.into_bytes()));
                existing.data = Some(data);
                existing.string_data = None;
                api.replace(&self.secret_name, &PostParams::default(), &existing)
                    .await
                    .map_err(|e| format_kube_error("failed to update Kubernetes Secret", e))?;
                debug!(secret = %self.secret_name, "secrets stored in existing Kubernetes Secret");
                Ok(())
            }
            None => {
                let mut data = BTreeMap::new();
                data.insert(self.secret_key.clone(), ByteString(json.into_bytes()));
                let secret = Secret {
                    metadata: ObjectMeta {
                        name: Some(self.secret_name.clone()),
                        ..Default::default()
                    },
                    data: Some(data),
                    type_: Some("Opaque".to_string()),
                    ..Default::default()
                };
                let created = api
                    .create(&PostParams::default(), &secret)
                    .await
                    .map_err(|e| format_kube_error("failed to create Kubernetes Secret", e))?;
                debug!(secret = %created.name_any(), "secrets created in Kubernetes Secret");
                Ok(())
            }
        }
    }
}

impl super::SecretStore for K8sSecretStore {
    fn get(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ServerSecrets>, AppError>> + Send + '_>> {
        Box::pin(async {
            let env = self.read_envelope().await?;
            let secrets = env.and_then(|e| e.secrets);
            if secrets.is_some() {
                debug!(secret = %self.secret_name, "secrets loaded from Kubernetes Secret");
            }
            Ok(secrets)
        })
    }

    fn set(
        &self,
        secrets: &ServerSecrets,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let secrets = secrets.clone();
        Box::pin(async move {
            // Read-modify-write so a concurrently-stored bootstrap seed
            // (phase 1 of offline-bootstrap) survives this write.
            let mut env = self.read_envelope().await?.unwrap_or_default();
            env.secrets = Some(secrets);
            self.write_envelope(&env).await?;
            debug!(secret = %self.secret_name, "secrets stored in Kubernetes Secret");
            Ok(())
        })
    }

    fn get_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<[u8; 32]>, AppError>> + Send + '_>> {
        Box::pin(async {
            let env = self.read_envelope().await?;
            match env.and_then(|e| e.bootstrap_seed) {
                Some(b64) => {
                    let seed = StoredSecrets::decode_seed(&b64)?;
                    debug!(secret = %self.secret_name, "bootstrap seed loaded from Kubernetes Secret");
                    Ok(Some(seed))
                }
                None => Ok(None),
            }
        })
    }

    fn set_bootstrap_seed(
        &self,
        seed: &[u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let seed_owned = *seed;
        Box::pin(async move {
            let mut env = self.read_envelope().await?.unwrap_or_default();
            env.bootstrap_seed = Some(StoredSecrets::encode_seed(&seed_owned));
            self.write_envelope(&env).await?;
            debug!(secret = %self.secret_name, "bootstrap seed stored in Kubernetes Secret");
            Ok(())
        })
    }

    fn clear_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            let Some(mut env) = self.read_envelope().await? else {
                return Ok(());
            };
            if env.bootstrap_seed.is_none() {
                return Ok(());
            }
            env.bootstrap_seed = None;
            self.write_envelope(&env).await?;
            debug!(secret = %self.secret_name, "bootstrap seed cleared from Kubernetes Secret");
            Ok(())
        })
    }
}

/// Build the `k8s-secrets` backend from config. `k8s_secret_name` activates
/// the backend (checked by the caller); the namespace + data key fall back
/// to sensible defaults when unset.
pub fn from_config(secrets: &SecretsConfig) -> Result<K8sSecretStore, AppError> {
    let secret_name = secrets.k8s_secret_name.clone().ok_or_else(|| {
        AppError::Config("secrets.k8s_secret_name is required for the Kubernetes backend".into())
    })?;
    Ok(K8sSecretStore::new(
        secret_name,
        secrets.k8s_namespace.clone(),
        secrets.k8s_secret_key.clone(),
    ))
}

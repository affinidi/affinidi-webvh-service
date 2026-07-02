//! Secret store backed by HashiCorp Vault's KV v2 engine.
//!
//! Ported from the VTA's `vti-secrets` Vault backend: the connection,
//! authentication, and token-renewal machinery is unchanged. The only
//! adaptation for did-hosting is the payload — instead of a bare
//! hex-encoded seed, a single KV field (`secret_key`, default `seed`)
//! holds the JSON [`StoredSecrets`] envelope, so `ServerSecrets` and the
//! offline-bootstrap seed share one Vault path and one policy grant. All
//! five [`SecretStore`](super::SecretStore) methods read-modify-write
//! that envelope, mirroring the cloud backends (`aws`/`gcp`/`azure`).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OnceCell, RwLock};
use tracing::{debug, error, info, warn};
use vaultrs::auth::approle;
use vaultrs::auth::kubernetes;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

use crate::server::config::SecretsConfig;
use crate::server::error::AppError;

use super::{ServerSecrets, StoredSecrets};

/// Vault recommends renewing well before expiry; renewing at half the
/// lease keeps the token comfortably within its window even if a single
/// renewal request fails. The 10s floor stops very short test TTLs from
/// busy-looping.
const RENEW_FACTOR: u32 = 2;
const RENEW_MIN_INTERVAL: Duration = Duration::from_secs(10);
/// Backoff after a re-auth failure. Long enough that flapping doesn't
/// spam Vault; short enough that the service recovers quickly once it's
/// back.
const RENEW_RETRY_INTERVAL: Duration = Duration::from_secs(30);
/// Polling cadence when Vault returned a non-renewable token (e.g.
/// static token auth). Picks up manual rotations without forcing the
/// renewal task to no-op forever.
const NON_RENEWABLE_POLL_INTERVAL: Duration = Duration::from_secs(300);

/// Authentication method for Vault. Each variant carries everything the
/// renewal task needs to re-authenticate from scratch when a lease can
/// no longer be renewed.
#[derive(Clone)]
enum VaultAuth {
    Kubernetes {
        mount: String,
        role: String,
        jwt_path: String,
    },
    Token {
        token: String,
    },
    AppRole {
        mount: String,
        role_id: String,
        secret_id: String,
    },
}

impl VaultAuth {
    /// Authenticate against Vault and return `(token, lease_secs, renewable)`.
    async fn login(&self, client: &VaultClient) -> Result<(String, u64, bool), ClientError> {
        match self {
            VaultAuth::Kubernetes {
                mount,
                role,
                jwt_path,
            } => {
                // SA JWTs are short-lived (kubelet rotates them ~1h by
                // default) so we re-read the file every time we authenticate.
                let jwt = std::fs::read_to_string(jwt_path).map_err(|e| {
                    ClientError::FileNotFoundError {
                        path: format!("{jwt_path}: {e}"),
                    }
                })?;
                let info = kubernetes::login(client, mount, role, jwt.trim()).await?;
                Ok((info.client_token, info.lease_duration, info.renewable))
            }
            VaultAuth::Token { token } => {
                // Static tokens have no auth-time lease; treat as
                // non-renewable. The renewal task will still poll
                // periodically in case the operator rotates the token.
                Ok((token.clone(), 0, false))
            }
            VaultAuth::AppRole {
                mount,
                role_id,
                secret_id,
            } => {
                let info = approle::login(client, mount, role_id, secret_id).await?;
                Ok((info.client_token, info.lease_duration, info.renewable))
            }
        }
    }
}

/// Connection parameters captured at construction time. The actual
/// `VaultClient` is built lazily on first use so `create_secret_store`
/// can stay synchronous (matching AWS/GCP/Azure).
struct ConnectParams {
    addr: String,
    namespace: Option<String>,
    skip_verify: bool,
    auth: VaultAuth,
}

/// A live Vault connection plus its background token-renewal task.
struct ConnectedState {
    client: Arc<RwLock<VaultClient>>,
    /// Held so we can abort the renewal task on `Drop`.
    renewal_task: tokio::task::JoinHandle<()>,
}

impl Drop for ConnectedState {
    fn drop(&mut self) {
        self.renewal_task.abort();
    }
}

/// Secret store backed by HashiCorp Vault's KV v2 engine.
///
/// Authenticates via Kubernetes ServiceAccount JWT (default), a static
/// token, or AppRole. The Vault token is auto-renewed in a background
/// task; if a renewal fails (max-TTL reached, lease expired) the task
/// re-authenticates from scratch using the configured method.
///
/// The JSON [`StoredSecrets`] envelope is stored as a string under
/// `secret_path` -> `secret_key` (default `seed`).
pub struct VaultSecretStore {
    /// Lazily initialised on first `get` / `set` / ... call.
    state: OnceCell<ConnectedState>,
    params: ConnectParams,
    secret_path: String,
    secret_key: String,
    kv_mount: String,
}

impl VaultSecretStore {
    #[allow(clippy::too_many_arguments)]
    fn new(
        addr: String,
        namespace: Option<String>,
        skip_verify: bool,
        secret_path: String,
        secret_key: String,
        kv_mount: String,
        auth: VaultAuth,
    ) -> Self {
        Self {
            state: OnceCell::new(),
            params: ConnectParams {
                addr,
                namespace,
                skip_verify,
                auth,
            },
            secret_path,
            secret_key,
            kv_mount,
        }
    }

    /// Lazily build the Vault client, authenticate, and spawn the
    /// renewal task. Subsequent calls reuse the same connection.
    async fn connect(&self) -> Result<&Arc<RwLock<VaultClient>>, AppError> {
        let state = self
            .state
            .get_or_try_init(|| async {
                let mut builder = VaultClientSettingsBuilder::default();
                builder
                    .address(self.params.addr.as_str())
                    .verify(!self.params.skip_verify);
                if let Some(ref ns) = self.params.namespace {
                    builder.namespace(Some(ns.clone()));
                }
                let settings = builder
                    .build()
                    .map_err(|e| AppError::Config(format!("invalid Vault settings: {e}")))?;
                let mut client = VaultClient::new(settings).map_err(|e| {
                    AppError::SecretStore(format!("failed to build Vault client: {e}"))
                })?;

                let (token, lease, renewable) =
                    self.params.auth.login(&client).await.map_err(|e| {
                        AppError::SecretStore(format!("Vault authentication failed: {e}"))
                    })?;
                client.set_token(&token);
                info!(
                    addr = %self.params.addr,
                    renewable,
                    lease_secs = lease,
                    "authenticated to Vault"
                );

                let client = Arc::new(RwLock::new(client));
                let renewal_task = spawn_renewal_task(
                    Arc::clone(&client),
                    self.params.auth.clone(),
                    lease,
                    renewable,
                );
                Ok::<_, AppError>(ConnectedState {
                    client,
                    renewal_task,
                })
            })
            .await?;
        Ok(&state.client)
    }

    /// Read the current envelope. Returns `None` when the secret does
    /// not yet exist. Legacy bare-`ServerSecrets` blobs migrate
    /// transparently on the next write.
    async fn read_envelope(&self) -> Result<Option<StoredSecrets>, AppError> {
        let client = self.connect().await?;
        let client = client.read().await;
        let result: Result<HashMap<String, String>, ClientError> =
            kv2::read(&*client, &self.kv_mount, &self.secret_path).await;
        match result {
            Ok(map) => {
                let json = map.get(&self.secret_key).ok_or_else(|| {
                    AppError::SecretStore(format!(
                        "Vault secret at {}/{} has no field '{}'",
                        self.kv_mount, self.secret_path, self.secret_key
                    ))
                })?;
                let env = StoredSecrets::parse(json.trim()).map_err(|e| {
                    AppError::SecretStore(format!("failed to deserialize secrets from Vault: {e}"))
                })?;
                Ok(Some(env))
            }
            Err(ClientError::APIError { code: 404, .. }) => {
                debug!(path = %self.secret_path, "secret not found in Vault");
                Ok(None)
            }
            Err(e) => Err(AppError::SecretStore(format!(
                "failed to read secrets from Vault: {e}"
            ))),
        }
    }

    /// Persist the envelope as a new KV v2 version.
    async fn write_envelope(&self, env: &StoredSecrets) -> Result<(), AppError> {
        let json = env
            .to_json()
            .map_err(|e| AppError::Internal(format!("envelope serialization for Vault: {e}")))?;
        let client = self.connect().await?;
        let client = client.read().await;
        let mut payload = HashMap::new();
        payload.insert(self.secret_key.clone(), json);
        kv2::set(&*client, &self.kv_mount, &self.secret_path, &payload)
            .await
            .map_err(|e| AppError::SecretStore(format!("failed to store secrets in Vault: {e}")))?;
        Ok(())
    }
}

/// Spawn the background task that renews the Vault token before its
/// lease expires, falling back to full re-auth when the lease can no
/// longer be extended.
fn spawn_renewal_task(
    client: Arc<RwLock<VaultClient>>,
    auth: VaultAuth,
    initial_lease: u64,
    renewable: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut current_lease = initial_lease;
        let mut current_renewable = renewable;
        loop {
            let sleep = if current_lease == 0 {
                NON_RENEWABLE_POLL_INTERVAL
            } else {
                Duration::from_secs((current_lease / RENEW_FACTOR as u64).max(1))
                    .max(RENEW_MIN_INTERVAL)
            };
            debug!(?sleep, current_lease, "vault renewal task sleeping");
            tokio::time::sleep(sleep).await;

            if current_renewable {
                let renew_result = {
                    let c = client.read().await;
                    c.renew(None).await
                };
                match renew_result {
                    Ok(info) => {
                        current_lease = info.lease_duration;
                        current_renewable = info.renewable;
                        debug!(lease_secs = current_lease, "vault token renewed");
                        continue;
                    }
                    Err(e) => {
                        warn!("vault token renewal failed: {e} — re-authenticating");
                    }
                }
            }

            // Re-auth from scratch (covers max-TTL exhaustion and the
            // non-renewable poll path).
            let login_result = {
                let c = client.read().await;
                auth.login(&c).await
            };
            match login_result {
                Ok((token, lease, renewable)) => {
                    let mut c = client.write().await;
                    c.set_token(&token);
                    current_lease = lease;
                    current_renewable = renewable;
                    info!(lease_secs = lease, renewable, "vault re-authenticated");
                }
                Err(e) => {
                    error!(
                        "vault re-authentication failed: {e} — retrying in {}s",
                        RENEW_RETRY_INTERVAL.as_secs()
                    );
                    tokio::time::sleep(RENEW_RETRY_INTERVAL).await;
                }
            }
        }
    })
}

impl super::SecretStore for VaultSecretStore {
    fn get(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ServerSecrets>, AppError>> + Send + '_>> {
        Box::pin(async {
            let env = self.read_envelope().await?;
            let secrets = env.and_then(|e| e.secrets);
            if secrets.is_some() {
                debug!(path = %self.secret_path, "secrets loaded from Vault");
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
            debug!(path = %self.secret_path, "secrets stored in Vault");
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
                    debug!(path = %self.secret_path, "bootstrap seed loaded from Vault");
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
            debug!(path = %self.secret_path, "bootstrap seed stored in Vault");
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
            debug!(path = %self.secret_path, "bootstrap seed cleared from Vault");
            Ok(())
        })
    }
}

/// Build a [`VaultSecretStore`] from the [`SecretsConfig`]. Validates the
/// auth-method-specific fields and surfaces actionable errors when
/// something required is missing. The caller has already checked that
/// `vault_addr` is set.
pub fn from_config(secrets: &SecretsConfig) -> Result<VaultSecretStore, AppError> {
    let addr = secrets
        .vault_addr
        .clone()
        .ok_or_else(|| AppError::Config("secrets.vault_addr is required".into()))?;
    let path = secrets.vault_secret_path.clone().ok_or_else(|| {
        AppError::Config(
            "secrets.vault_secret_path is required when secrets.vault_addr is set".into(),
        )
    })?;

    let auth = match secrets.vault_auth_method.as_str() {
        "kubernetes" => {
            let role = secrets.vault_k8s_role.clone().ok_or_else(|| {
                AppError::Config(
                    "secrets.vault_k8s_role is required for kubernetes auth method".into(),
                )
            })?;
            VaultAuth::Kubernetes {
                mount: secrets.vault_k8s_mount.clone(),
                role,
                jwt_path: secrets.vault_k8s_jwt_path.clone(),
            }
        }
        "token" => {
            let token = secrets
                .vault_token
                .clone()
                .or_else(|| std::env::var("VAULT_TOKEN").ok())
                .ok_or_else(|| {
                    AppError::Config(
                        "token auth requires secrets.vault_token or the VAULT_TOKEN env var".into(),
                    )
                })?;
            VaultAuth::Token { token }
        }
        "approle" => {
            let role_id = secrets.vault_approle_role_id.clone().ok_or_else(|| {
                AppError::Config("secrets.vault_approle_role_id is required for approle".into())
            })?;
            let secret_id = secrets.vault_approle_secret_id.clone().ok_or_else(|| {
                AppError::Config("secrets.vault_approle_secret_id is required for approle".into())
            })?;
            VaultAuth::AppRole {
                mount: secrets.vault_approle_mount.clone(),
                role_id,
                secret_id,
            }
        }
        other => {
            return Err(AppError::Config(format!(
                "unknown secrets.vault_auth_method '{other}', expected kubernetes|token|approle"
            )));
        }
    };

    Ok(VaultSecretStore::new(
        addr,
        secrets.vault_namespace.clone(),
        secrets.vault_skip_verify,
        path,
        secrets.vault_secret_key.clone(),
        secrets.vault_kv_mount.clone(),
        auth,
    ))
}

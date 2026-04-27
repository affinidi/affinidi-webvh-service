use std::future::Future;
use std::pin::Pin;

use crate::server::error::AppError;
use tracing::debug;

use super::{ServerSecrets, StoredSecrets};

/// Legacy suffix used by 0.6.0–0.6.1 deployments to store the
/// offline-bootstrap ephemeral seed in a sibling secret. The current
/// envelope-based design keeps the seed inside the same secret as
/// `ServerSecrets`. Filtering siblings out of [`list_secret_names`]
/// keeps the wizard tidy when stragglers exist.
const LEGACY_BOOTSTRAP_SEED_SUFFIX: &str = "-bootstrap-seed";

/// List secret short-names visible in GCP Secret Manager for the configured
/// project.
///
/// Filters out legacy `*-bootstrap-seed` companion entries (see
/// [`LEGACY_BOOTSTRAP_SEED_SUFFIX`]).
pub async fn list_secret_names(project: &str) -> Result<Vec<String>, AppError> {
    let client = google_cloud_secretmanager_v1::client::SecretManagerService::builder()
        .build()
        .await
        .map_err(|e| AppError::SecretStore(format!("GCP Secret Manager client error: {e}")))?;

    let parent = format!("projects/{project}");
    let mut names = Vec::new();
    let mut page_token: Option<String> = None;
    loop {
        let mut req = client.list_secrets().set_parent(parent.clone());
        if let Some(token) = page_token.as_ref() {
            req = req.set_page_token(token.clone());
        }
        let response = req
            .send()
            .await
            .map_err(|e| AppError::SecretStore(format!("GCP list_secrets: {e}")))?;

        for secret in &response.secrets {
            // `secret.name` is a fully-qualified resource path
            // `projects/PROJECT/secrets/NAME`. Strip the prefix to get
            // the short name the wizard prompts on.
            if let Some(short) = secret.name.rsplit('/').next()
                && !short.is_empty()
                && !short.ends_with(LEGACY_BOOTSTRAP_SEED_SUFFIX)
            {
                names.push(short.to_string());
            }
        }

        if response.next_page_token.is_empty() {
            break;
        }
        page_token = Some(response.next_page_token);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// Secret store backed by GCP Secret Manager.
///
/// A single secret holds a JSON [`StoredSecrets`] envelope containing
/// both the long-lived [`ServerSecrets`] and the optional
/// offline-bootstrap ephemeral seed, so a single IAM grant covers both.
/// GCP auth is resolved from the environment (service account, workload
/// identity, application default credentials, etc.).
pub struct GcpSecretStore {
    project: String,
    secret_name: String,
}

impl GcpSecretStore {
    pub fn new(project: String, secret_name: String) -> Self {
        Self {
            project,
            secret_name,
        }
    }

    fn secret_path(&self) -> String {
        format!("projects/{}/secrets/{}", self.project, self.secret_name)
    }

    fn latest_version_path(&self) -> String {
        format!("{}/versions/latest", self.secret_path())
    }

    async fn client(
        &self,
    ) -> Result<google_cloud_secretmanager_v1::client::SecretManagerService, AppError> {
        google_cloud_secretmanager_v1::client::SecretManagerService::builder()
            .build()
            .await
            .map_err(|e| AppError::SecretStore(format!("GCP Secret Manager client error: {e}")))
    }

    /// Read the current envelope. Returns `None` when the secret does
    /// not yet exist. Legacy bare-`ServerSecrets` blobs migrate
    /// transparently on the next write.
    async fn read_envelope(
        &self,
        client: &google_cloud_secretmanager_v1::client::SecretManagerService,
    ) -> Result<Option<StoredSecrets>, AppError> {
        let result = client
            .access_secret_version()
            .set_name(self.latest_version_path())
            .send()
            .await;

        match result {
            Ok(response) => {
                let payload = response.payload.ok_or_else(|| {
                    AppError::SecretStore("GCP secret version has no payload".into())
                })?;
                let json_str = String::from_utf8(payload.data.to_vec()).map_err(|e| {
                    AppError::SecretStore(format!("GCP secret payload is not valid UTF-8: {e}"))
                })?;
                let env = StoredSecrets::parse(json_str.trim()).map_err(|e| {
                    AppError::SecretStore(format!("failed to deserialize secrets from GCP: {e}"))
                })?;
                Ok(Some(env))
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("NOT_FOUND") {
                    Ok(None)
                } else {
                    Err(AppError::SecretStore(format!(
                        "GCP Secret Manager error: {e}"
                    )))
                }
            }
        }
    }

    /// Persist the envelope. Creates the parent secret on first write,
    /// otherwise adds a new version.
    async fn write_envelope(
        &self,
        client: &google_cloud_secretmanager_v1::client::SecretManagerService,
        env: &StoredSecrets,
    ) -> Result<(), AppError> {
        let json_str = env
            .to_json()
            .map_err(|e| AppError::Internal(format!("envelope serialization for GCP: {e}")))?;

        let payload = google_cloud_secretmanager_v1::model::SecretPayload::new()
            .set_data(bytes::Bytes::from(json_str.clone()));

        let result = client
            .add_secret_version()
            .set_parent(self.secret_path())
            .set_payload(payload.clone())
            .send()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("NOT_FOUND") {
                    let secret = google_cloud_secretmanager_v1::model::Secret::new()
                        .set_replication(
                        google_cloud_secretmanager_v1::model::Replication::new().set_automatic(
                            google_cloud_secretmanager_v1::model::replication::Automatic::default(),
                        ),
                    );
                    client
                        .create_secret()
                        .set_parent(format!("projects/{}", self.project))
                        .set_secret_id(&self.secret_name)
                        .set_secret(secret)
                        .send()
                        .await
                        .map_err(|e| {
                            AppError::SecretStore(format!("failed to create GCP secret: {e}"))
                        })?;
                    client
                        .add_secret_version()
                        .set_parent(self.secret_path())
                        .set_payload(payload)
                        .send()
                        .await
                        .map_err(|e| {
                            AppError::SecretStore(format!(
                                "failed to add secret version in GCP: {e}"
                            ))
                        })?;
                    Ok(())
                } else {
                    Err(AppError::SecretStore(format!(
                        "failed to store secrets in GCP: {e}"
                    )))
                }
            }
        }
    }
}

impl super::SecretStore for GcpSecretStore {
    fn get(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ServerSecrets>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let env = self.read_envelope(&client).await?;
            let secrets = env.and_then(|e| e.secrets);
            if secrets.is_some() {
                debug!(secret = %self.secret_name, "secrets loaded from GCP Secret Manager");
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
            let client = self.client().await?;
            // Read-modify-write so a concurrently-stored bootstrap seed
            // (phase 1 of offline-bootstrap) survives this write.
            let mut env = self.read_envelope(&client).await?.unwrap_or_default();
            env.secrets = Some(secrets);
            self.write_envelope(&client, &env).await?;
            debug!(secret = %self.secret_name, "secrets stored in GCP Secret Manager");
            Ok(())
        })
    }

    fn get_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<[u8; 32]>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let env = self.read_envelope(&client).await?;
            match env.and_then(|e| e.bootstrap_seed) {
                Some(b64) => {
                    let seed = StoredSecrets::decode_seed(&b64)?;
                    debug!(secret = %self.secret_name, "bootstrap seed loaded from GCP");
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
            let client = self.client().await?;
            let mut env = self.read_envelope(&client).await?.unwrap_or_default();
            env.bootstrap_seed = Some(StoredSecrets::encode_seed(&seed_owned));
            self.write_envelope(&client, &env).await?;
            debug!(secret = %self.secret_name, "bootstrap seed stored in GCP");
            Ok(())
        })
    }

    fn clear_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let Some(mut env) = self.read_envelope(&client).await? else {
                return Ok(());
            };
            if env.bootstrap_seed.is_none() {
                return Ok(());
            }
            env.bootstrap_seed = None;
            self.write_envelope(&client, &env).await?;
            debug!(secret = %self.secret_name, "bootstrap seed cleared from GCP");
            Ok(())
        })
    }
}

use std::future::Future;
use std::pin::Pin;

use crate::server::error::AppError;
use tracing::debug;

use super::ServerSecrets;

/// List secret short-names visible in GCP Secret Manager for the configured
/// project.
///
/// Filters out `*-bootstrap-seed` companion entries — those are paired
/// with a `ServerSecrets` blob, not standalone candidates the operator
/// should pick from the wizard.
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
                && !short.ends_with(BOOTSTRAP_SEED_SUFFIX)
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
/// Stores a JSON-serialized `ServerSecrets` struct in the named secret.
/// GCP auth is resolved from the environment (service account, workload
/// identity, application default credentials, etc.).
/// Suffix appended to the configured secret name for the
/// offline-bootstrap ephemeral seed. Stored as a separate GCP secret
/// so its lifecycle (created at phase 1, deleted at phase 2) is
/// independent of the long-lived `ServerSecrets` blob.
const BOOTSTRAP_SEED_SUFFIX: &str = "-bootstrap-seed";

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

    fn bootstrap_seed_secret_name(&self) -> String {
        format!("{}{BOOTSTRAP_SEED_SUFFIX}", self.secret_name)
    }

    fn bootstrap_seed_secret_path(&self) -> String {
        format!(
            "projects/{}/secrets/{}",
            self.project,
            self.bootstrap_seed_secret_name()
        )
    }

    fn bootstrap_seed_latest_version_path(&self) -> String {
        format!("{}/versions/latest", self.bootstrap_seed_secret_path())
    }

    async fn client(
        &self,
    ) -> Result<google_cloud_secretmanager_v1::client::SecretManagerService, AppError> {
        google_cloud_secretmanager_v1::client::SecretManagerService::builder()
            .build()
            .await
            .map_err(|e| AppError::SecretStore(format!("GCP Secret Manager client error: {e}")))
    }
}

impl super::SecretStore for GcpSecretStore {
    fn get(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ServerSecrets>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
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
                    let secrets: ServerSecrets =
                        serde_json::from_str(json_str.trim()).map_err(|e| {
                            AppError::SecretStore(format!(
                                "failed to deserialize secrets from GCP: {e}"
                            ))
                        })?;
                    debug!(secret = %self.secret_name, "secrets loaded from GCP Secret Manager");
                    Ok(Some(secrets))
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NOT_FOUND") {
                        debug!(secret = %self.secret_name, "secret not found in GCP Secret Manager");
                        Ok(None)
                    } else {
                        Err(AppError::SecretStore(format!(
                            "GCP Secret Manager error: {e}"
                        )))
                    }
                }
            }
        })
    }

    fn set(
        &self,
        secrets: &ServerSecrets,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let json_str = serde_json::to_string(secrets).expect("ServerSecrets serialization");
        Box::pin(async move {
            let client = self.client().await?;

            // Try to add a new version to the existing secret
            let payload = google_cloud_secretmanager_v1::model::SecretPayload::new()
                .set_data(bytes::Bytes::from(json_str.clone()));
            let result = client
                .add_secret_version()
                .set_parent(self.secret_path())
                .set_payload(payload.clone())
                .send()
                .await;

            match result {
                Ok(_) => {
                    debug!(secret = %self.secret_name, "secrets stored in GCP Secret Manager");
                    Ok(())
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NOT_FOUND") {
                        // Create the secret first
                        let secret = google_cloud_secretmanager_v1::model::Secret::new()
                            .set_replication(
                                google_cloud_secretmanager_v1::model::Replication::new()
                                    .set_automatic(
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

                        // Now add the version
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

                        debug!(secret = %self.secret_name, "secrets created in GCP Secret Manager");
                        Ok(())
                    } else {
                        Err(AppError::SecretStore(format!(
                            "failed to store secrets in GCP: {e}"
                        )))
                    }
                }
            }
        })
    }

    fn get_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<[u8; 32]>, AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let result = client
                .access_secret_version()
                .set_name(self.bootstrap_seed_latest_version_path())
                .send()
                .await;
            match result {
                Ok(response) => {
                    use base64::Engine;
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
                    let payload = response.payload.ok_or_else(|| {
                        AppError::SecretStore("GCP bootstrap-seed payload missing".into())
                    })?;
                    let b64 = String::from_utf8(payload.data.to_vec()).map_err(|e| {
                        AppError::SecretStore(format!(
                            "GCP bootstrap-seed payload is not valid UTF-8: {e}"
                        ))
                    })?;
                    let bytes = B64.decode(b64.trim().as_bytes()).map_err(|e| {
                        AppError::SecretStore(format!(
                            "failed to base64-decode bootstrap seed from GCP: {e}"
                        ))
                    })?;
                    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        AppError::SecretStore(format!(
                            "GCP bootstrap seed has {} bytes, expected 32",
                            bytes.len()
                        ))
                    })?;
                    debug!(secret = %self.bootstrap_seed_secret_name(), "bootstrap seed loaded from GCP");
                    Ok(Some(seed))
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NOT_FOUND") {
                        Ok(None)
                    } else {
                        Err(AppError::SecretStore(format!(
                            "GCP Secret Manager error reading bootstrap seed: {e}"
                        )))
                    }
                }
            }
        })
    }

    fn set_bootstrap_seed(
        &self,
        seed: &[u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        let seed_owned = *seed;
        Box::pin(async move {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
            let b64 = B64.encode(seed_owned);
            let client = self.client().await?;
            let payload = google_cloud_secretmanager_v1::model::SecretPayload::new()
                .set_data(bytes::Bytes::from(b64.clone()));

            let result = client
                .add_secret_version()
                .set_parent(self.bootstrap_seed_secret_path())
                .set_payload(payload.clone())
                .send()
                .await;

            match result {
                Ok(_) => {
                    debug!(secret = %self.bootstrap_seed_secret_name(), "bootstrap seed stored in GCP");
                    Ok(())
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NOT_FOUND") {
                        let secret = google_cloud_secretmanager_v1::model::Secret::new()
                            .set_replication(
                                google_cloud_secretmanager_v1::model::Replication::new()
                                    .set_automatic(
                                        google_cloud_secretmanager_v1::model::replication::Automatic::default(),
                                    ),
                            );
                        client
                            .create_secret()
                            .set_parent(format!("projects/{}", self.project))
                            .set_secret_id(self.bootstrap_seed_secret_name())
                            .set_secret(secret)
                            .send()
                            .await
                            .map_err(|e| {
                                AppError::SecretStore(format!(
                                    "failed to create GCP bootstrap-seed secret: {e}"
                                ))
                            })?;
                        client
                            .add_secret_version()
                            .set_parent(self.bootstrap_seed_secret_path())
                            .set_payload(payload)
                            .send()
                            .await
                            .map_err(|e| {
                                AppError::SecretStore(format!(
                                    "failed to add GCP bootstrap-seed version: {e}"
                                ))
                            })?;
                        debug!(secret = %self.bootstrap_seed_secret_name(), "bootstrap seed created in GCP");
                        Ok(())
                    } else {
                        Err(AppError::SecretStore(format!(
                            "failed to store bootstrap seed in GCP: {e}"
                        )))
                    }
                }
            }
        })
    }

    fn clear_bootstrap_seed(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + '_>> {
        Box::pin(async {
            let client = self.client().await?;
            let result = client
                .delete_secret()
                .set_name(self.bootstrap_seed_secret_path())
                .send()
                .await;
            match result {
                Ok(_) => {
                    debug!(secret = %self.bootstrap_seed_secret_name(), "bootstrap seed cleared from GCP");
                    Ok(())
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("NOT_FOUND") {
                        Ok(())
                    } else {
                        Err(AppError::SecretStore(format!(
                            "failed to clear bootstrap seed from GCP: {e}"
                        )))
                    }
                }
            }
        })
    }
}

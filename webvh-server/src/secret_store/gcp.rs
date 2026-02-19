use std::future::Future;
use std::pin::Pin;

use crate::error::AppError;
use tracing::debug;

use super::ServerSecrets;

/// Secret store backed by GCP Secret Manager.
///
/// Stores a JSON-serialized `ServerSecrets` struct in the named secret.
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
                    let json_str =
                        String::from_utf8(payload.data.to_vec()).map_err(|e| {
                            AppError::SecretStore(format!(
                                "GCP secret payload is not valid UTF-8: {e}"
                            ))
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
                                AppError::SecretStore(format!(
                                    "failed to create GCP secret: {e}"
                                ))
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
}

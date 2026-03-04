use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;

use crate::error::{Result, ServerErrorBody, WebVHError};
use crate::types::*;

// ---------------------------------------------------------------------------
// DID sync types
// ---------------------------------------------------------------------------

/// A DID known to the registering service, reported during registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidSyncEntry {
    pub mnemonic: String,
    pub did_id: Option<String>,
    pub version_count: u64,
    pub updated_at: u64,
}

/// An update the control plane sends back for a DID that needs refreshing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidSyncUpdate {
    pub mnemonic: String,
    pub did_id: String,
    pub log_content: String,
    pub witness_content: Option<String>,
    pub version_count: u64,
}

/// Request body for `POST /api/control/register-service`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterServiceRequest {
    pub service_type: String,
    pub url: String,
    pub label: Option<String>,
    pub preloaded_dids: Vec<DidSyncEntry>,
}

/// Response body from `POST /api/control/register-service`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterServiceResponse {
    pub instance_id: String,
    pub did_updates: Vec<DidSyncUpdate>,
}

// ---------------------------------------------------------------------------
// ControlClient
// ---------------------------------------------------------------------------

/// A client for interacting with a webvh-control service instance.
///
/// Follows the same DIDComm challenge-response authentication pattern
/// as `WitnessClient`.
pub struct ControlClient {
    http: reqwest::Client,
    server_url: String,
    access_token: Option<String>,
}

impl ControlClient {
    /// Create a new client pointing at the given control plane URL.
    pub fn new(server_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            access_token: None,
        }
    }

    /// Authenticate with the control plane using DIDComm challenge-response.
    ///
    /// On success the client stores the access token internally so that
    /// subsequent calls to authenticated endpoints work automatically.
    pub async fn authenticate(
        &mut self,
        did: &str,
        secret: &Secret,
    ) -> Result<AuthenticateResponse> {
        // 1. DID resolver
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .map_err(|e| WebVHError::Resolver(format!("failed to create DID resolver: {e}")))?;

        // 2. Secrets resolver
        let (secrets_resolver, _handle) = ThreadedSecretsResolver::new(None).await;
        secrets_resolver.insert(secret.clone()).await;

        // 3. Request challenge
        let challenge_resp: ChallengeResponse = self
            .http
            .post(format!("{}/api/auth/challenge", self.server_url))
            .json(&ChallengeRequest {
                did: did.to_string(),
            })
            .send()
            .await?
            .error_for_status()
            .map_err(|e| WebVHError::DIDComm(format!("challenge request rejected: {e}")))?
            .json()
            .await?;

        debug!(session_id = %challenge_resp.session_id, "challenge received from control plane");

        // 4. Build DIDComm message
        let created_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();
        let msg = Message::build(
            uuid::Uuid::new_v4().to_string(),
            "https://affinidi.com/webvh/1.0/authenticate".to_string(),
            json!({
                "challenge": challenge_resp.data.challenge,
                "session_id": challenge_resp.session_id,
            }),
        )
        .from(did.to_string())
        .created_time(created_time)
        .finalize();

        // 5. Pack signed
        let (packed, _meta) = msg
            .pack_signed(&secret.id, &did_resolver, &secrets_resolver)
            .await
            .map_err(|e| WebVHError::DIDComm(format!("failed to pack signed message: {e}")))?;

        // 6. Authenticate
        let auth_resp: AuthenticateResponse = self
            .http
            .post(format!("{}/api/auth/", self.server_url))
            .body(packed)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| WebVHError::DIDComm(format!("authentication rejected: {e}")))?
            .json()
            .await?;

        // 7. Store token
        self.access_token = Some(auth_resp.data.access_token.clone());

        debug!("authenticated with control plane");

        Ok(auth_resp)
    }

    // -------------------------------------------------------------------
    // Control API
    // -------------------------------------------------------------------

    /// Register this service with the control plane and receive DID sync updates.
    pub async fn register_service(
        &self,
        req: &RegisterServiceRequest,
    ) -> Result<RegisterServiceResponse> {
        let resp = self
            .auth_post("/api/control/register-service")?
            .json(req)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Returns the server URL this client is configured with.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    // -------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------

    fn token(&self) -> Result<&str> {
        self.access_token
            .as_deref()
            .ok_or(WebVHError::NotAuthenticated)
    }

    fn auth_post(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self.token()?;
        Ok(self
            .http
            .post(format!("{}{path}", self.server_url))
            .bearer_auth(token))
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T> {
        if !resp.status().is_success() {
            return Err(self.extract_server_error(resp).await);
        }
        Ok(resp.json().await?)
    }

    async fn extract_server_error(&self, resp: reqwest::Response) -> WebVHError {
        let status = resp.status().as_u16();
        let message = match resp.json::<ServerErrorBody>().await {
            Ok(body) => body.to_string(),
            Err(_) => format!("HTTP {status}"),
        };
        WebVHError::Server { status, message }
    }
}

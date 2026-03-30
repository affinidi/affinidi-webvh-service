use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::didcomm::message::pack;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::json;
use tracing::debug;

use crate::error::{Result, ServerErrorBody, WebVHError};
use crate::types::*;

/// A client for interacting with a webvh-witness service instance.
pub struct WitnessClient {
    http: reqwest::Client,
    server_url: String,
    access_token: Option<String>,
}

impl WitnessClient {
    /// Create a new client pointing at the given witness server URL.
    pub fn new(server_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            access_token: None,
        }
    }

    /// Authenticate with the witness server using DIDComm challenge-response.
    ///
    /// On success the client stores the access token internally so that
    /// subsequent calls to authenticated endpoints will work automatically.
    pub async fn authenticate(
        &mut self,
        did: &str,
        secret: &Secret,
    ) -> Result<AuthenticateResponse> {
        // 1. Extract private key bytes for signing
        let private_key_bytes: [u8; 32] = secret
            .get_private_bytes()
            .try_into()
            .map_err(|_| WebVHError::DIDComm("signing key must be 32 bytes".into()))?;

        // 2. Request challenge
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

        debug!(session_id = %challenge_resp.session_id, "challenge received");

        // 3. Build DIDComm message
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

        // 4. Pack signed
        let packed = pack::pack_signed(&msg, &secret.id, &private_key_bytes)
            .map_err(|e| WebVHError::DIDComm(format!("failed to pack signed message: {e}")))?;

        // 5. Authenticate
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

        debug!("authenticated with witness server");

        Ok(auth_resp)
    }

    // -------------------------------------------------------------------
    // Witness API
    // -------------------------------------------------------------------

    /// Request a witness proof for a version ID.
    pub async fn request_proof(
        &self,
        witness_id: &str,
        version_id: &str,
    ) -> Result<SignProofResponse> {
        let resp = self
            .auth_post(&format!("/api/proof/{witness_id}"))?
            .json(&SignProofRequest {
                version_id: version_id.to_string(),
            })
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// List all available witnesses.
    pub async fn list_witnesses(&self) -> Result<WitnessListResponse> {
        let resp = self.auth_get("/api/witnesses")?.send().await?;
        self.handle_response(resp).await
    }

    /// Create a new witness identity (admin only).
    pub async fn create_witness(&self, label: Option<&str>) -> Result<WitnessResponse> {
        let resp = self
            .auth_post("/api/witnesses")?
            .json(&CreateWitnessRequest {
                label: label.map(|s| s.to_string()),
            })
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Get a witness by its ID (admin only).
    pub async fn get_witness(&self, witness_id: &str) -> Result<WitnessResponse> {
        let resp = self
            .auth_get(&format!("/api/witnesses/{witness_id}"))?
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Delete a witness identity (admin only).
    pub async fn delete_witness(&self, witness_id: &str) -> Result<()> {
        let resp = self
            .auth_delete(&format!("/api/witnesses/{witness_id}"))?
            .send()
            .await?;
        self.handle_response_no_body(resp).await
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

    fn auth_get(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self.token()?;
        Ok(self
            .http
            .get(format!("{}{path}", self.server_url))
            .bearer_auth(token))
    }

    fn auth_post(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self.token()?;
        Ok(self
            .http
            .post(format!("{}{path}", self.server_url))
            .bearer_auth(token))
    }

    fn auth_delete(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self.token()?;
        Ok(self
            .http
            .delete(format!("{}{path}", self.server_url))
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

    async fn handle_response_no_body(&self, resp: reqwest::Response) -> Result<()> {
        if !resp.status().is_success() {
            return Err(self.extract_server_error(resp).await);
        }
        Ok(())
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

use crate::error::{Result, ServerErrorBody, WebVHError};
use crate::types::{SyncDeleteRequest, SyncDidRequest};

/// A client for interacting with a webvh-watcher service instance.
///
/// Uses a simple bearer token for authentication (no DIDComm).
pub struct WatcherClient {
    http: reqwest::Client,
    server_url: String,
    token: Option<String>,
}

impl WatcherClient {
    /// Create a new client pointing at the given watcher server URL.
    pub fn new(server_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            token: None,
        }
    }

    /// Create a new client with a pre-configured bearer token.
    pub fn with_token(server_url: &str, token: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            token: Some(token.to_string()),
        }
    }

    /// Returns the server URL this client is configured with.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Check the health of the watcher.
    pub async fn health(&self) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(format!("{}/api/health", self.server_url))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Push a DID update to the watcher.
    pub async fn push_did(&self, req: &SyncDidRequest) -> Result<()> {
        let mut builder = self
            .http
            .post(format!("{}/api/sync/did", self.server_url))
            .json(req);
        if let Some(token) = &self.token {
            builder = builder.bearer_auth(token);
        }
        let resp = builder.send().await?;
        self.handle_response_no_body(resp).await
    }

    /// Push a DID deletion to the watcher.
    pub async fn push_delete(&self, req: &SyncDeleteRequest) -> Result<()> {
        let mut builder = self
            .http
            .post(format!("{}/api/sync/delete", self.server_url))
            .json(req);
        if let Some(token) = &self.token {
            builder = builder.bearer_auth(token);
        }
        let resp = builder.send().await?;
        self.handle_response_no_body(resp).await
    }

    // -------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------

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

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use serde_json::json;
use tracing::debug;

use crate::did::{build_did_document, create_log_entry, encode_host};
use crate::error::{Result, ServerErrorBody, WebVHError};
use crate::types::*;

/// A client for interacting with a webvh-server instance.
pub struct WebVHClient {
    http: reqwest::Client,
    server_url: String,
    access_token: Option<String>,
}

impl WebVHClient {
    /// Create a new client pointing at the given server URL.
    pub fn new(server_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
            access_token: None,
        }
    }

    /// Authenticate with the server using DIDComm challenge-response.
    ///
    /// On success the client stores the access token internally so that
    /// subsequent calls to authenticated endpoints will work automatically.
    pub async fn authenticate(&mut self, did: &str, secret: &Secret) -> Result<AuthenticateResponse> {
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

        debug!(session_id = %challenge_resp.session_id, "challenge received");

        // 4. Build DIDComm message
        let msg = Message::build(
            uuid::Uuid::new_v4().to_string(),
            "https://affinidi.com/webvh/1.0/authenticate".to_string(),
            json!({
                "challenge": challenge_resp.data.challenge,
                "session_id": challenge_resp.session_id,
            }),
        )
        .from(did.to_string())
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

        debug!("authenticated successfully");

        Ok(auth_resp)
    }

    // -------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------

    /// Check whether a custom path/name is available.
    pub async fn check_name(&self, path: &str) -> Result<CheckNameResponse> {
        let resp = self
            .auth_post("/api/dids/check")?
            .json(&CheckNameRequest {
                path: path.to_string(),
            })
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Request a new DID URI. If `path` is `Some`, the server will use
    /// that custom path; otherwise it generates a random mnemonic.
    pub async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse> {
        let mut req = self.auth_post("/api/dids")?;
        if let Some(p) = path {
            req = req.json(&CreateDidRequest {
                path: Some(p.to_string()),
            });
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Upload a did.jsonl document for the given mnemonic.
    pub async fn upload_did(&self, mnemonic: &str, content: &str) -> Result<()> {
        let resp = self
            .auth_put(&format!("/api/dids/{mnemonic}"))?
            .header("Content-Type", "text/plain")
            .body(content.to_string())
            .send()
            .await?;
        self.handle_response_no_body(resp).await
    }

    /// Upload a did-witness.json for the given mnemonic.
    pub async fn upload_witness(&self, mnemonic: &str, content: &str) -> Result<()> {
        let resp = self
            .auth_put(&format!("/api/witness/{mnemonic}"))?
            .header("Content-Type", "text/plain")
            .body(content.to_string())
            .send()
            .await?;
        self.handle_response_no_body(resp).await
    }

    /// Delete a DID by its mnemonic.
    pub async fn delete_did(&self, mnemonic: &str) -> Result<()> {
        let resp = self
            .auth_delete(&format!("/api/dids/{mnemonic}"))?
            .send()
            .await?;
        self.handle_response_no_body(resp).await
    }

    /// List all DIDs owned by the authenticated user.
    pub async fn list_dids(&self) -> Result<Vec<DidListEntry>> {
        let resp = self.auth_get("/api/dids")?.send().await?;
        self.handle_response(resp).await
    }

    /// Get statistics for a DID by its mnemonic.
    pub async fn get_stats(&self, mnemonic: &str) -> Result<DidStats> {
        let resp = self
            .auth_get(&format!("/api/stats/{mnemonic}"))?
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Returns the server URL this client is configured with.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// High-level: request a DID URI, build the DID document, create the
    /// WebVH log entry, upload it, and return everything the caller needs.
    ///
    /// This combines `request_uri` + DID doc building + log creation +
    /// `upload_did` into a single call.
    pub async fn create_did(
        &self,
        secret: &Secret,
        path: Option<&str>,
    ) -> Result<CreateDidResult> {
        let create_resp = self.request_uri(path).await?;

        let host = encode_host(&self.server_url)?;
        let public_key_multibase = secret
            .get_public_keymultibase()
            .map_err(|e| WebVHError::DIDComm(format!("failed to get public key: {e}")))?;

        let did_doc =
            build_did_document(&host, &create_resp.mnemonic, &public_key_multibase);
        let (scid, jsonl) = create_log_entry(&did_doc, secret)?;

        self.upload_did(&create_resp.mnemonic, &jsonl).await?;

        let did_path = create_resp.mnemonic.replace('/', ":");
        let did = format!("did:webvh:{scid}:{host}:{did_path}");

        Ok(CreateDidResult {
            mnemonic: create_resp.mnemonic,
            did_url: create_resp.did_url,
            scid,
            did,
            public_key_multibase,
        })
    }

    /// Resolve a DID log (public, no auth required).
    pub async fn resolve_did(&self, mnemonic: &str) -> Result<String> {
        let resp = self
            .http
            .get(format!("{}/{mnemonic}/did.jsonl", self.server_url))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(self.extract_server_error(resp).await);
        }

        Ok(resp.text().await?)
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

    fn auth_put(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self.token()?;
        Ok(self
            .http
            .put(format!("{}{path}", self.server_url))
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

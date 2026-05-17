//! [`Client`] — the thin REST handle that wires together the
//! auth message builders (T45), the transport gate (T46), and the
//! token store (T47).
//!
//! v0.1 surface: the auth round-trips (challenge / authenticate /
//! refresh). DID-management methods (register / publish / delete /
//! request_uri / check_path / get_did) land in T48's follow-up
//! commits — the patterns are the same (Trust-Task header, status-
//! to-`ClientError` mapping) so each one is a small slice on this
//! same scaffolding.

use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use url::Url;

use crate::auth::{HostingSigningIdentity, build_authenticate_message, build_refresh_message};
use crate::error::ClientError;
use crate::token_store::{SharedTokenStore, TokenData};
use crate::transport::enforce_transport_security;
use crate::trust_tasks::{
    TASK_AUTH_AUTHENTICATE_1_0, TASK_AUTH_CHALLENGE_1_0, TASK_AUTH_REFRESH_1_0,
};

/// HTTP header name used for Trust-Task routing on every authed
/// REST call. Daemon-side enforcement uses
/// `did_hosting_common::server::trust_task::HEADER_NAME`; we don't
/// import that to keep the dependency boundary clean.
const TRUST_TASK_HEADER: &str = "trust-task";

/// REST client for a single `did-hosting-server` /
/// `did-hosting-daemon`. Cheap to clone — internal state is an
/// `Arc`-wrapped reqwest pool, base URL, and pluggable token store.
///
/// **Construction enforces HTTPS** (or loopback for dev). Any
/// `Client::new` call with a non-HTTPS base URL on a non-loopback
/// host fails before the integrator gets a chance to send a
/// request — production deployments fail closed.
#[derive(Clone)]
pub struct Client {
    base: Url,
    http: reqwest::Client,
    /// Stable identifier for keying the token store + lock
    /// registry. Conventionally the daemon's DID
    /// (`did:webvh:Q1:example.com:control`).
    server_id: Arc<str>,
    tokens: SharedTokenStore,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Token store + reqwest::Client are opaque internals; the
        // base + server_id are the only fields a debug print needs.
        f.debug_struct("Client")
            .field("base", &self.base.as_str())
            .field("server_id", &&*self.server_id)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Construct a client pointing at `base_url`.
    ///
    /// HTTPS is required except for loopback hosts (see
    /// [`crate::transport::enforce_transport_security`] for the
    /// exact rule). `server_id` keys the token store + per-server
    /// lock registry; conventionally the daemon's `server_did`.
    pub fn new(
        base_url: &str,
        server_id: impl Into<Arc<str>>,
        tokens: SharedTokenStore,
    ) -> Result<Self, ClientError> {
        let base = Url::parse(base_url)
            .map_err(|e| ClientError::Validation(format!("invalid base_url '{base_url}': {e}")))?;
        enforce_transport_security(&base)?;
        let http = reqwest::Client::builder()
            .user_agent(format!("did-hosting-client/{}", super::VERSION))
            .build()
            .map_err(|e| ClientError::Network(e.to_string()))?;
        Ok(Self {
            base,
            http,
            server_id: server_id.into(),
            tokens,
        })
    }

    /// Return the daemon's base URL the client was constructed with.
    pub fn base_url(&self) -> &Url {
        &self.base
    }

    /// Return the `server_id` the client was constructed with.
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Return the pluggable token store.
    pub fn tokens(&self) -> &SharedTokenStore {
        &self.tokens
    }

    /// `POST /api/auth/challenge` — request a challenge nonce. The
    /// returned `(session_id, challenge)` is fed to
    /// [`Self::authenticate`].
    pub async fn challenge(&self, holder_did: &str) -> Result<ChallengeResponse, ClientError> {
        #[derive(serde::Serialize)]
        struct Body<'a> {
            did: &'a str,
        }
        let url = self.url("/api/auth/challenge")?;
        let resp = self
            .http
            .post(url)
            .headers(self.trust_task_headers(TASK_AUTH_CHALLENGE_1_0)?)
            .json(&Body { did: holder_did })
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode::<ChallengeWire>(resp)
            .await
            .map(|w| ChallengeResponse {
                session_id: w.session_id,
                challenge: w.data.challenge,
            })
    }

    /// `POST /api/auth/` — exchange a signed authenticate envelope
    /// for an access + refresh token pair. The caller is expected
    /// to have already called [`Self::challenge`] and built the
    /// envelope via
    /// [`crate::auth::build_authenticate_message`].
    pub async fn authenticate(
        &self,
        identity: &HostingSigningIdentity<'_>,
        session_id: &str,
        challenge: &str,
        now_epoch: u64,
        recipient_did: &str,
    ) -> Result<TokenData, ClientError> {
        let body =
            build_authenticate_message(identity, session_id, challenge, now_epoch, recipient_did)
                .map_err(|e| ClientError::Protocol(format!("pack authenticate message: {e}")))?;
        let url = self.url("/api/auth/")?;
        let resp = self
            .http
            .post(url)
            .headers(self.trust_task_headers(TASK_AUTH_AUTHENTICATE_1_0)?)
            .header("content-type", "application/didcomm-signed+json")
            .body(body)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode::<TokenWire>(resp).await.map(TokenWire::into_data)
    }

    /// `POST /api/auth/refresh` — exchange the cached refresh token
    /// for a fresh access+refresh pair. Per the daemon's contract,
    /// the refresh token rotates atomically: the response always
    /// carries a new value, the old one is invalidated on the
    /// daemon side at the same time.
    pub async fn refresh(
        &self,
        identity: &HostingSigningIdentity<'_>,
        refresh_token: &str,
        now_epoch: u64,
        recipient_did: &str,
    ) -> Result<TokenData, ClientError> {
        let body = build_refresh_message(identity, refresh_token, now_epoch, recipient_did)
            .map_err(|e| ClientError::Protocol(format!("pack refresh message: {e}")))?;
        let url = self.url("/api/auth/refresh")?;
        let resp = self
            .http
            .post(url)
            .headers(self.trust_task_headers(TASK_AUTH_REFRESH_1_0)?)
            .header("content-type", "application/didcomm-signed+json")
            .body(body)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode::<TokenWire>(resp).await.map(TokenWire::into_data)
    }

    // ---- internal plumbing ----

    fn url(&self, path: &str) -> Result<Url, ClientError> {
        self.base
            .join(path)
            .map_err(|e| ClientError::Validation(format!("join '{path}' onto base failed: {e}")))
    }

    fn trust_task_headers(&self, task_url: &str) -> Result<HeaderMap, ClientError> {
        let mut h = HeaderMap::new();
        let name = HeaderName::from_static(TRUST_TASK_HEADER);
        let value = HeaderValue::from_str(task_url)
            .map_err(|e| ClientError::Validation(format!("invalid Trust-Task URL: {e}")))?;
        h.insert(name, value);
        Ok(h)
    }
}

/// Auth challenge response — the integrator-facing flattened form
/// (the wire is `{ session_id, data: { challenge } }`).
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    /// Server-issued session identifier; pass back to
    /// [`Client::authenticate`].
    pub session_id: String,
    /// Hex-encoded challenge nonce; sign in the DIDComm body.
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeWire {
    session_id: String,
    data: ChallengeData,
}

#[derive(Debug, Deserialize)]
struct ChallengeData {
    challenge: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenWire {
    data: TokenWireData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenWireData {
    access_token: String,
    access_expires_at: u64,
    refresh_token: String,
    refresh_expires_at: u64,
}

impl TokenWire {
    fn into_data(self) -> TokenData {
        TokenData {
            access_token: self.data.access_token,
            access_expires_at: self.data.access_expires_at,
            refresh_token: self.data.refresh_token,
            refresh_expires_at: self.data.refresh_expires_at,
        }
    }
}

/// Map an HTTP response to either a deserialised body or a typed
/// [`ClientError`]. Single source of truth for status-code →
/// error-variant routing.
async fn decode<T>(resp: reqwest::Response) -> Result<T, ClientError>
where
    T: serde::de::DeserializeOwned,
{
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ClientError::Network(e.to_string()))?;

    if status.is_success() {
        return serde_json::from_slice::<T>(&bytes).map_err(|e| {
            ClientError::Protocol(format!(
                "response body did not deserialise as expected type: {e}"
            ))
        });
    }

    let body_text = String::from_utf8_lossy(&bytes).into_owned();
    let err = match status.as_u16() {
        400 => ClientError::Validation(body_text),
        401 => ClientError::Auth(body_text),
        403 => ClientError::Forbidden(body_text),
        404 => ClientError::NotFound(body_text),
        409 => ClientError::Conflict(body_text),
        415 => ClientError::Protocol(format!("Trust-Task mismatch: {body_text}")),
        500..=599 => ClientError::Server {
            status: status.as_u16(),
            body: body_text,
        },
        _ => ClientError::Protocol(format!("unexpected status {status}: {body_text}")),
    };
    Err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryTokenStore;

    fn tokens() -> SharedTokenStore {
        Arc::new(InMemoryTokenStore::new())
    }

    #[test]
    fn new_accepts_https_url() {
        let c = Client::new("https://example.com:8443", "did:example:srv", tokens())
            .expect("HTTPS must be accepted");
        assert_eq!(c.base_url().as_str(), "https://example.com:8443/");
        assert_eq!(c.server_id(), "did:example:srv");
    }

    #[test]
    fn new_accepts_loopback_http_for_dev() {
        assert!(Client::new("http://localhost:8530", "did:example:srv", tokens()).is_ok());
        assert!(Client::new("http://127.0.0.1:8530", "did:example:srv", tokens()).is_ok());
        assert!(Client::new("http://[::1]:8530", "did:example:srv", tokens()).is_ok());
    }

    #[test]
    fn new_rejects_http_on_public_host() {
        let err = Client::new("http://example.com", "did:example:srv", tokens())
            .expect_err("plain HTTP on public host must reject");
        assert!(matches!(err, ClientError::Validation(_)));
    }

    #[test]
    fn new_rejects_garbage_url() {
        let err = Client::new("not a url", "did:example:srv", tokens()).expect_err("garbage");
        assert!(matches!(err, ClientError::Validation(_)));
    }

    /// The `trust-task` header is stamped on every authed request.
    /// The builder validates the value and surfaces a clear error
    /// if a future regression replaces the const with garbage.
    #[test]
    fn trust_task_header_carries_canonical_url() {
        let c = Client::new("https://example.com", "did:example:srv", tokens()).unwrap();
        let h = c
            .trust_task_headers(TASK_AUTH_CHALLENGE_1_0)
            .expect("static URL must be valid");
        assert_eq!(
            h.get(TRUST_TASK_HEADER).and_then(|v| v.to_str().ok()),
            Some(TASK_AUTH_CHALLENGE_1_0)
        );
    }

    /// Joining a relative path onto the base URL drops the
    /// trailing slash semantics correctly.
    #[test]
    fn url_joins_paths_under_base() {
        let c = Client::new("https://example.com/", "did:example:srv", tokens()).unwrap();
        let u = c.url("/api/auth/challenge").unwrap();
        assert_eq!(u.as_str(), "https://example.com/api/auth/challenge");
    }
}

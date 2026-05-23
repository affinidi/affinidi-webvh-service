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

use crate::auth::{HostingSigningIdentity, build_authenticate_body, build_refresh_message};
use crate::error::ClientError;
use crate::token_store::{SharedTokenStore, TokenData};
use crate::transport::enforce_transport_security;
use crate::trust_tasks::{
    TASK_AUTH_AUTHENTICATE_0_1, TASK_AUTH_CHALLENGE_0_1, TASK_AUTH_REFRESH_0_1,
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
            .headers(self.trust_task_headers(TASK_AUTH_CHALLENGE_0_1)?)
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

    /// `POST /api/auth/` — exchange a self-issued SIOPv2 `id_token`
    /// (wrapped in a Trust-Task envelope) for an access + refresh
    /// token pair. The caller is expected to have already called
    /// [`Self::challenge`]; the body is built via
    /// [`crate::auth::build_authenticate_body`].
    ///
    /// `recipient_did` is the relying-party DID (the daemon's
    /// `server_did`); it becomes the `id_token`'s `aud`.
    /// `session_pubkey_b58btc` optionally binds an ephemeral session
    /// key to the issued JWT for later Data-Integrity proofs.
    pub async fn authenticate(
        &self,
        identity: &HostingSigningIdentity<'_>,
        session_id: &str,
        challenge: &str,
        now_epoch: u64,
        recipient_did: &str,
        session_pubkey_b58btc: Option<&str>,
    ) -> Result<TokenData, ClientError> {
        let body = build_authenticate_body(
            identity,
            session_id,
            challenge,
            recipient_did,
            now_epoch,
            session_pubkey_b58btc,
        )
        .map_err(|e| ClientError::Protocol(format!("build authenticate body: {e}")))?;
        let url = self.url("/api/auth/")?;
        let resp = self
            .http
            .post(url)
            .headers(self.trust_task_headers(TASK_AUTH_AUTHENTICATE_0_1)?)
            .header("content-type", "application/json")
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
            .headers(self.trust_task_headers(TASK_AUTH_REFRESH_0_1)?)
            .header("content-type", "application/didcomm-signed+json")
            .body(body)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode::<TokenWire>(resp).await.map(TokenWire::into_data)
    }

    // ---- Decision ladder (T49) ------------------------------------------

    /// Spec §7.1 decision ladder under per-server mutual exclusion.
    ///
    /// Returns a fresh access token. The path through the ladder
    /// is invisible to the caller — they just call this and use
    /// the result.
    ///
    /// ## Steps
    ///
    /// 1. Take the per-server lock from `locks` (a `Mutex<()>` —
    ///    the protected region is the read-modify-write below).
    ///    Two concurrent `ensure_token` calls against the same
    ///    server serialise; one wins, the other reads the cache
    ///    the winner populated.
    /// 2. Read cached tokens. If `access_expires_at - now_epoch >
    ///    30`, return the cached `access_token`.
    /// 3. Else try [`Self::refresh`]. On success, persist the new
    ///    pair and return the access token.
    /// 4. On `ClientError::Auth` from refresh — refresh token also
    ///    invalid — invalidate the cache and run the full
    ///    challenge + authenticate dance. Persist + return.
    /// 5. On any other error (network, server, protocol), surface
    ///    to the caller without invalidating the cache.
    ///
    /// `now_epoch` is passed in (not read from `SystemTime`) so
    /// tests can pin a deterministic clock.
    pub async fn ensure_token(
        &self,
        identity: &HostingSigningIdentity<'_>,
        recipient_did: &str,
        locks: &crate::locks::ServerLocks,
        now_epoch: u64,
    ) -> Result<String, ClientError> {
        let lock = locks.for_server(&self.server_id);
        let _guard = lock.lock().await;

        // Step 1: cache lookup.
        if let Some(td) = self.tokens.get(&self.server_id, identity.did).await? {
            if td.access_expires_at.saturating_sub(now_epoch) > 30 {
                // `td` is `ZeroizeOnDrop`, so we clone the token
                // string out before the value drops at the end of
                // this scope.
                return Ok(td.access_token.clone());
            }

            // Step 2: try refresh while we still have a refresh
            // token that hasn't aged out either.
            if td.refresh_expires_at.saturating_sub(now_epoch) > 30 {
                match self
                    .refresh(identity, &td.refresh_token, now_epoch, recipient_did)
                    .await
                {
                    Ok(new) => {
                        let access = new.access_token.clone();
                        self.tokens.put(&self.server_id, identity.did, new).await?;
                        return Ok(access);
                    }
                    Err(ClientError::Auth(_)) => {
                        // refresh token was rejected (revoked, ACL change,
                        // server key rotation); fall through to reauth.
                        self.tokens
                            .invalidate(&self.server_id, identity.did)
                            .await?;
                    }
                    Err(other) => return Err(other),
                }
            }
        }

        // Step 3: full reauth via challenge → authenticate.
        let challenge = self.challenge(identity.did).await?;
        let fresh = self
            .authenticate(
                identity,
                &challenge.session_id,
                &challenge.challenge,
                now_epoch,
                recipient_did,
                None,
            )
            .await?;
        let access = fresh.access_token.clone();
        self.tokens
            .put(&self.server_id, identity.did, fresh)
            .await?;
        Ok(access)
    }

    // ---- DID management (T48 slice 2) -----------------------------------

    /// `POST /api/dids/check` — validate that `path` is available
    /// for reservation. The daemon answers `{ available: bool, path }`;
    /// we surface `available` directly. `domain` is optional per
    /// spec §5.1 — the daemon's T34 resolver picks the ACL default
    /// when absent.
    pub async fn check_path(
        &self,
        access_token: &str,
        path: &str,
        domain: Option<&str>,
    ) -> Result<bool, ClientError> {
        #[derive(serde::Serialize)]
        struct Body<'a> {
            path: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            domain: Option<&'a str>,
        }
        #[derive(Deserialize)]
        struct Wire {
            available: bool,
        }
        let url = self.url("/api/dids/check")?;
        let resp = self
            .http
            .post(url)
            .headers(self.trust_task_headers(crate::trust_tasks::TASK_DID_CHECK_NAME_1_0)?)
            .bearer_auth(access_token)
            .json(&Body { path, domain })
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode::<Wire>(resp).await.map(|w| w.available)
    }

    /// `POST /api/dids` — reserve a path slot. Body is optional;
    /// `path = None` lets the daemon mint a fresh mnemonic. The
    /// response carries the assigned mnemonic + resolution URL.
    pub async fn request_uri(
        &self,
        access_token: &str,
        path: Option<&str>,
        force: bool,
    ) -> Result<RequestUriResponse, ClientError> {
        #[derive(serde::Serialize)]
        struct Body<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            path: Option<&'a str>,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            force: bool,
        }
        let url = self.url("/api/dids")?;
        let resp = self
            .http
            .post(url)
            .headers(self.trust_task_headers(crate::trust_tasks::TASK_DID_REQUEST_1_0)?)
            .bearer_auth(access_token)
            .json(&Body { path, force })
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode::<RequestUriWire>(resp)
            .await
            .map(|w| RequestUriResponse {
                mnemonic: w.mnemonic,
                did_url: w.did_url,
            })
    }

    /// `POST /api/dids/register` — atomic claim-and-publish.
    ///
    /// `did_data` is method-specific: a JSONL string for `webvh`,
    /// a `did.json` object for `web`. `method` defaults to `webvh`
    /// per the daemon's T26 inference rule but the caller may
    /// pass it explicitly. `domain` defers to the daemon's T34
    /// resolver when absent.
    pub async fn register_did_atomic(
        &self,
        access_token: &str,
        req: &RegisterDidRequest<'_>,
    ) -> Result<RequestUriResponse, ClientError> {
        let url = self.url("/api/dids/register")?;
        let resp = self
            .http
            .post(url)
            .headers(self.trust_task_headers(crate::trust_tasks::TASK_DID_REGISTER_1_0)?)
            .bearer_auth(access_token)
            .json(req)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode::<RequestUriWire>(resp)
            .await
            .map(|w| RequestUriResponse {
                mnemonic: w.mnemonic,
                did_url: w.did_url,
            })
    }

    /// `PUT /api/dids/{mnemonic}` — publish a new version of an
    /// existing DID. `content_type` controls the daemon's T26
    /// method discriminator: `application/jsonl` → webvh,
    /// `application/did+json` → web. Returns 204 on success.
    pub async fn publish_did(
        &self,
        access_token: &str,
        mnemonic: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<(), ClientError> {
        let url = self.url(&format!("/api/dids/{}", mnemonic.trim_start_matches('/')))?;
        let resp = self
            .http
            .put(url)
            .headers(self.trust_task_headers(crate::trust_tasks::TASK_DID_PUBLISH_1_0)?)
            .bearer_auth(access_token)
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode_no_body(resp).await
    }

    /// `DELETE /api/dids/{mnemonic}` — delete a DID. Owner-or-
    /// admin authorisation gated by the daemon.
    pub async fn delete_did(&self, access_token: &str, mnemonic: &str) -> Result<(), ClientError> {
        let url = self.url(&format!("/api/dids/{}", mnemonic.trim_start_matches('/')))?;
        let resp = self
            .http
            .delete(url)
            .headers(self.trust_task_headers(crate::trust_tasks::TASK_DID_DELETE_1_0)?)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        decode_no_body(resp).await
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

/// Request body for [`Client::register_did_atomic`]. Mirrors the
/// daemon's T26 `DidRegisterRequest` wire shape — the legacy
/// `did_log: String` form is supported by the daemon for
/// backwards-compat but new clients should use `did_data`.
#[derive(Debug, serde::Serialize)]
pub struct RegisterDidRequest<'a> {
    /// Path / mnemonic to register under.
    pub path: &'a str,
    /// Optional `"webvh"` / `"web"`. When absent, the daemon
    /// infers from `did_data.id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'a str>,
    /// Method-specific payload (JSONL string for webvh, did.json
    /// object for web). Serialised verbatim.
    pub did_data: &'a serde_json::Value,
    /// Override the caller's ACL default domain. Omitted → the
    /// daemon's T34 resolver chooses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<&'a str>,
    /// Admin-only takeover of an existing path. Owners are
    /// implicitly authorised on their own paths.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub force: bool,
}

/// Response from both `request_uri` and `register_did_atomic` —
/// the daemon-assigned mnemonic + the public resolution URL.
#[derive(Debug, Clone)]
pub struct RequestUriResponse {
    /// Mnemonic / path the DID lives at.
    pub mnemonic: String,
    /// Public resolution URL (e.g. `https://example.com/alice/did.jsonl`).
    pub did_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestUriWire {
    mnemonic: String,
    did_url: String,
}

/// Decode a response that's expected to have no body (204 / 201).
/// Maps non-success status codes through the same ladder as
/// [`decode`].
async fn decode_no_body(resp: reqwest::Response) -> Result<(), ClientError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp
        .text()
        .await
        .unwrap_or_else(|_| String::from("<unreadable body>"));
    Err(match status.as_u16() {
        400 => ClientError::Validation(body),
        401 => ClientError::Auth(body),
        403 => ClientError::Forbidden(body),
        404 => ClientError::NotFound(body),
        409 => ClientError::Conflict(body),
        415 => ClientError::Protocol(format!("Trust-Task mismatch: {body}")),
        500..=599 => ClientError::Server {
            status: status.as_u16(),
            body,
        },
        _ => ClientError::Protocol(format!("unexpected status {status}: {body}")),
    })
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
#[serde(rename_all = "camelCase")]
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
            .trust_task_headers(TASK_AUTH_CHALLENGE_0_1)
            .expect("static URL must be valid");
        assert_eq!(
            h.get(TRUST_TASK_HEADER).and_then(|v| v.to_str().ok()),
            Some(TASK_AUTH_CHALLENGE_0_1)
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

    /// `RegisterDidRequest` serialises with optional fields
    /// suppressed when `None` so the daemon's T26 resolver picks
    /// the inference paths.
    #[test]
    fn register_request_minimal_serialisation() {
        let data = serde_json::json!({ "id": "did:webvh:Q1:example.com:alice" });
        let req = RegisterDidRequest {
            path: "alice",
            method: None,
            did_data: &data,
            domain: None,
            force: false,
        };
        let json = serde_json::to_value(&req).unwrap();
        // No `method`, no `domain`, no `force` keys when they're at default.
        let obj = json.as_object().unwrap();
        assert_eq!(obj.get("path"), Some(&serde_json::json!("alice")));
        assert!(obj.contains_key("did_data"));
        assert!(!obj.contains_key("method"));
        assert!(!obj.contains_key("domain"));
        assert!(!obj.contains_key("force"));
    }

    /// Explicit `method` / `domain` / `force` round-trip correctly.
    #[test]
    fn register_request_full_serialisation() {
        let data = serde_json::json!({ "id": "did:web:example.com:bob" });
        let req = RegisterDidRequest {
            path: "bob",
            method: Some("web"),
            did_data: &data,
            domain: Some("example.com"),
            force: true,
        };
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.get("method"), Some(&serde_json::json!("web")));
        assert_eq!(obj.get("domain"), Some(&serde_json::json!("example.com")));
        assert_eq!(obj.get("force"), Some(&serde_json::json!(true)));
    }

    /// Mnemonic path-segment construction trims an accidental
    /// leading slash so an integrator passing `"/alice"` works.
    #[test]
    fn publish_url_handles_leading_slash() {
        let c = Client::new("https://example.com/", "did:example:srv", tokens()).unwrap();
        let u = c.url("/api/dids/alice").unwrap();
        assert_eq!(u.as_str(), "https://example.com/api/dids/alice");
        let u = c
            .url(&format!("/api/dids/{}", "/alice".trim_start_matches('/')))
            .unwrap();
        assert_eq!(u.as_str(), "https://example.com/api/dids/alice");
    }
}

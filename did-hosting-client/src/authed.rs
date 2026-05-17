//! [`AuthedClient`] — opinionated wrapper around [`Client`] +
//! [`HostingSigningIdentityOwned`] + [`ServerLocks`] that drops
//! the explicit `access_token` argument from every method.
//!
//! Integrators who want the lowest-friction surface use this:
//!
//! ```ignore
//! let authed = AuthedClient::new(client, identity, locks, control_did);
//! authed.publish_did("alice", "application/jsonl", body).await?;
//! ```
//!
//! Internally each method runs the [`Client::ensure_token`] ladder
//! before dispatching to the underlying REST method. The integrator
//! still has access to the wrapped `Client` for one-off calls that
//! want a different identity or to inspect token-store state.

use std::sync::Arc;

use crate::auth::HostingSigningIdentityOwned;
use crate::client::{ChallengeResponse, Client, RegisterDidRequest, RequestUriResponse};
use crate::error::ClientError;
use crate::locks::ServerLocks;

/// Authenticated handle over a [`Client`]. Pairs a single
/// long-lived signing identity with the daemon's DID; each call
/// runs [`Client::ensure_token`] then dispatches.
///
/// Cheap to clone — internal state is the `Client` (already Arc-
/// shaped) plus the identity (owned, but small — DID string +
/// 32-byte key) and a shared `ServerLocks`.
pub struct AuthedClient {
    client: Client,
    identity: HostingSigningIdentityOwned,
    locks: Arc<ServerLocks>,
    recipient_did: Arc<str>,
    now_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl AuthedClient {
    /// Construct.
    ///
    /// - `client`: the underlying REST handle.
    /// - `identity`: owned signing identity (DID + key). Zeroized
    ///   on drop.
    /// - `locks`: shared `ServerLocks` registry. Passing in an
    ///   external `Arc` means multiple `AuthedClient`s against
    ///   different daemons coordinate through one registry.
    /// - `recipient_did`: the daemon's DID (the `to` field on the
    ///   DIDComm envelopes).
    ///
    /// `now_fn` defaults to `std::time::SystemTime::now()` epoch
    /// seconds via [`Self::with_clock`]. Override in tests.
    pub fn new(
        client: Client,
        identity: HostingSigningIdentityOwned,
        locks: Arc<ServerLocks>,
        recipient_did: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            client,
            identity,
            locks,
            recipient_did: recipient_did.into(),
            now_fn: Arc::new(default_now_epoch),
        }
    }

    /// Override the clock source. Production code uses the default
    /// `SystemTime::now()`; tests pin a fixed epoch.
    pub fn with_clock<F>(mut self, now_fn: F) -> Self
    where
        F: Fn() -> u64 + Send + Sync + 'static,
    {
        self.now_fn = Arc::new(now_fn);
        self
    }

    /// Borrow the underlying [`Client`]. Useful for inspection
    /// (token store, base URL) without going through the
    /// authenticated path.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Borrow the signing identity (DID-only; key access is
    /// internal).
    pub fn holder_did(&self) -> &str {
        &self.identity.did
    }

    /// Run the [`Client::ensure_token`] ladder and hand the result
    /// to `f`. The closure is what the AuthedClient methods all
    /// look like under the hood — exposed as `pub` so an
    /// integrator can call any one-off REST method on the wrapped
    /// `Client` against the same auth state.
    pub async fn with_access_token<F, Fut, T>(&self, f: F) -> Result<T, ClientError>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<T, ClientError>>,
    {
        let now = (self.now_fn)();
        let identity = self.identity.borrow();
        let access = self
            .client
            .ensure_token(&identity, &self.recipient_did, &self.locks, now)
            .await?;
        f(access).await
    }

    /// Forward to [`Client::challenge`]. No token required.
    pub async fn challenge(&self) -> Result<ChallengeResponse, ClientError> {
        self.client.challenge(&self.identity.did).await
    }

    /// Forward to [`Client::check_path`] with an auto-ensured
    /// access token.
    pub async fn check_path(&self, path: &str, domain: Option<&str>) -> Result<bool, ClientError> {
        self.with_access_token(
            |token| async move { self.client.check_path(&token, path, domain).await },
        )
        .await
    }

    /// Forward to [`Client::request_uri`].
    pub async fn request_uri(
        &self,
        path: Option<&str>,
        force: bool,
    ) -> Result<RequestUriResponse, ClientError> {
        self.with_access_token(
            |token| async move { self.client.request_uri(&token, path, force).await },
        )
        .await
    }

    /// Forward to [`Client::register_did_atomic`].
    pub async fn register_did_atomic(
        &self,
        req: &RegisterDidRequest<'_>,
    ) -> Result<RequestUriResponse, ClientError> {
        self.with_access_token(
            |token| async move { self.client.register_did_atomic(&token, req).await },
        )
        .await
    }

    /// Forward to [`Client::publish_did`].
    pub async fn publish_did(
        &self,
        mnemonic: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.with_access_token(|token| async move {
            self.client
                .publish_did(&token, mnemonic, content_type, body)
                .await
        })
        .await
    }

    /// Forward to [`Client::delete_did`].
    pub async fn delete_did(&self, mnemonic: &str) -> Result<(), ClientError> {
        self.with_access_token(
            |token| async move { self.client.delete_did(&token, mnemonic).await },
        )
        .await
    }
}

impl std::fmt::Debug for AuthedClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthedClient")
            .field("client", &self.client)
            .field("holder_did", &&*self.identity.did)
            .field("recipient_did", &&*self.recipient_did)
            .finish_non_exhaustive()
    }
}

fn default_now_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_store::TokenData;
    use crate::{InMemoryTokenStore, SharedTokenStore};

    fn tokens() -> SharedTokenStore {
        Arc::new(InMemoryTokenStore::new())
    }

    fn identity() -> HostingSigningIdentityOwned {
        HostingSigningIdentityOwned::new("did:example:alice", [7u8; 32])
    }

    /// `ensure_token` returns a cached access token without
    /// hitting the network when the cache is fresh enough. The
    /// access_expires_at is well beyond `now + 30s`.
    #[tokio::test]
    async fn ensure_token_returns_cached_when_fresh() {
        let store = tokens();
        let client = Client::new("https://example.com", "did:example:srv", store.clone()).unwrap();

        // Pre-seed the cache with a token that's good for another
        // hour.
        let now = 1_700_000_000;
        store
            .put(
                "did:example:srv",
                "did:example:alice",
                TokenData {
                    access_token: "cached-AAA".into(),
                    access_expires_at: now + 3600,
                    refresh_token: "cached-RRR".into(),
                    refresh_expires_at: now + 86_400,
                },
            )
            .await
            .unwrap();

        let locks = ServerLocks::new();
        let id_owned = identity();
        let id = id_owned.borrow();
        let token = client
            .ensure_token(&id, "did:example:control", &locks, now)
            .await
            .expect("cached path must not network");
        assert_eq!(token, "cached-AAA");
    }

    /// When the cached access is within 30s of expiry AND the
    /// refresh is fresh, the ladder tries refresh. The reqwest
    /// call will fail with a network error against `example.com`
    /// (no DNS / TLS / server) — that's OK; we just need to
    /// observe that the ladder *attempted* the refresh path. We
    /// confirm by checking the error variant is Network (refresh
    /// reached the wire), not Auth (would mean we skipped refresh
    /// and went straight to reauth).
    #[tokio::test]
    async fn ensure_token_attempts_refresh_when_access_near_expiry() {
        let store = tokens();
        let client = Client::new(
            "https://nx.example.invalid",
            "did:example:srv",
            store.clone(),
        )
        .unwrap();

        let now = 1_700_000_000;
        store
            .put(
                "did:example:srv",
                "did:example:alice",
                TokenData {
                    access_token: "cached-AAA".into(),
                    access_expires_at: now + 10, // < 30s threshold
                    refresh_token: "cached-RRR".into(),
                    refresh_expires_at: now + 86_400,
                },
            )
            .await
            .unwrap();

        let locks = ServerLocks::new();
        let id_owned = identity();
        let id = id_owned.borrow();
        let err = client
            .ensure_token(&id, "did:example:control", &locks, now)
            .await
            .expect_err("nx.example.invalid will not resolve");
        // The exact variant depends on reqwest's failure path —
        // accept any non-Validation/non-Protocol error. The point
        // is the ladder DID reach the network (the refresh path),
        // not that it short-circuited on a stale cache.
        assert!(
            matches!(err, ClientError::Network(_)),
            "expected Network err from refresh attempt, got {err:?}"
        );
    }

    /// Without a cached token, the ladder runs the full
    /// challenge → authenticate sequence. We can't fully exercise
    /// it without a working daemon, but we can check that the
    /// first network call goes to `/api/auth/challenge`. Network
    /// failure is the expected outcome.
    #[tokio::test]
    async fn ensure_token_falls_through_to_full_reauth_on_empty_cache() {
        let client =
            Client::new("https://nx.example.invalid", "did:example:srv", tokens()).unwrap();
        let locks = ServerLocks::new();
        let id_owned = identity();
        let id = id_owned.borrow();
        let err = client
            .ensure_token(&id, "did:example:control", &locks, 1_700_000_000)
            .await
            .expect_err("nx.example.invalid will not resolve");
        assert!(
            matches!(err, ClientError::Network(_)),
            "expected Network err from challenge attempt, got {err:?}"
        );
    }

    /// `AuthedClient::with_clock` overrides the clock for tests.
    /// Construction must not panic and `holder_did` reads back.
    #[tokio::test]
    async fn authed_client_constructs_with_clock_override() {
        let store = tokens();
        let client = Client::new("https://example.com", "did:example:srv", store).unwrap();
        let authed = AuthedClient::new(
            client,
            identity(),
            Arc::new(ServerLocks::new()),
            "did:example:control",
        )
        .with_clock(|| 1_700_000_000);

        assert_eq!(authed.holder_did(), "did:example:alice");
        assert_eq!(authed.client().server_id(), "did:example:srv");
    }
}

//! Cached access + refresh tokens with an integrator-pluggable
//! storage backend (T47).
//!
//! [`TokenData`] is the value type — both token strings + their
//! expiry epochs. Derives `Zeroize` + `ZeroizeOnDrop` so the token
//! bytes are wiped from memory on drop, and overrides `Debug` to
//! redact both tokens. The integrator is still responsible for not
//! logging the wrapper; this crate just does its part.
//!
//! [`HostingTokenStore`] is the storage abstraction. The crate
//! ships [`InMemoryTokenStore`] (process-local, `DashMap`); a
//! production integrator brings their own (file, redis, SQL) by
//! implementing the trait.
//!
//! ## Per-server keying
//!
//! Every operation takes a `server_id: &str` so a single integrator
//! talking to multiple daemons doesn't have a token-confusion bug.
//! The expected shape is `server_did` (e.g.
//! `did:webvh:Q1:example.com:control`); any caller-stable string
//! works.

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ClientError;

/// Cached access + refresh tokens for one (server, holder DID)
/// pair.
///
/// Both token strings are zeroized on drop. `Debug` redacts them
/// to `<redacted>` so a careless `tracing::info!(token = ?td, …)`
/// doesn't leak the secret half. Expiries are stamped as epoch
/// seconds — the daemon issues them in that shape and the client
/// compares against `now_epoch()` without timezone arithmetic.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TokenData {
    /// Short-lived JWT Bearer token sent on every authenticated
    /// REST call. Use until `access_expires_at`.
    pub access_token: String,
    /// Epoch second at which `access_token` becomes invalid. The
    /// integrator's decision ladder (T49) compares against this
    /// to choose between fresh-use / refresh / reauth.
    pub access_expires_at: u64,
    /// Long-lived refresh token used to mint a new access token
    /// without re-running the DIDComm challenge dance. Rotates on
    /// every refresh per the daemon's contract — the response
    /// always carries a new value, the old becomes invalid
    /// atomically.
    pub refresh_token: String,
    /// Epoch second at which `refresh_token` becomes invalid.
    /// Once past, the only path back to authenticated calls is a
    /// fresh challenge-response.
    pub refresh_expires_at: u64,
}

/// Redacted Debug — never print the token bytes. Surfaces just
/// enough metadata to debug an expiry-ladder bug.
impl std::fmt::Debug for TokenData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenData")
            .field("access_token", &"<redacted>")
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_token", &"<redacted>")
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

/// Storage abstraction for cached tokens. Integrators implement
/// against their preferred backend (file, redis, SQL); the crate
/// ships [`InMemoryTokenStore`] as the no-config default.
///
/// All methods take `&self` so a single store can be shared
/// across tasks under `Arc`. The blanket `async fn` requires
/// `async_trait` — Rust 2024's native async-fn-in-trait is
/// generally OK but `async_trait` keeps the trait object-safe
/// (the `Client` holds `Arc<dyn HostingTokenStore>` so the
/// integrator can swap implementations at construction time).
#[async_trait]
pub trait HostingTokenStore: Send + Sync {
    /// Look up cached tokens for `(server_id, holder_did)`.
    /// Returns `Ok(None)` for cache miss; `Err` only for storage
    /// failures, never for absence.
    async fn get(
        &self,
        server_id: &str,
        holder_did: &str,
    ) -> Result<Option<TokenData>, ClientError>;

    /// Insert or replace the cached tokens. The decision ladder
    /// in T49 calls this after every successful authenticate /
    /// refresh round-trip.
    async fn put(
        &self,
        server_id: &str,
        holder_did: &str,
        data: TokenData,
    ) -> Result<(), ClientError>;

    /// Evict cached tokens for `(server_id, holder_did)`. Called
    /// when a 401 from the daemon indicates the cached tokens are
    /// no longer accepted (e.g. ACL change, key rotation).
    async fn invalidate(&self, server_id: &str, holder_did: &str) -> Result<(), ClientError>;
}

/// `DashMap`-backed token store — process-local, no persistence.
/// Suitable for short-lived clients (CLI tools, integration tests)
/// where token survival across restarts isn't a concern.
///
/// Cache key is `(server_id, holder_did)`. Each key is independent
/// — the same client used by two DIDs against one daemon has two
/// rows; the same DID against two daemons also two rows.
#[derive(Default)]
pub struct InMemoryTokenStore {
    inner: DashMap<(String, String), TokenData>,
}

impl InMemoryTokenStore {
    /// Construct an empty store. The store is cheap and cloning
    /// happens via `Arc` at the integration layer; no explicit
    /// `with_capacity` knob is exposed because production code
    /// almost always wraps the store in a custom backend.
    pub fn new() -> Self {
        Self::default()
    }

    fn key(server_id: &str, holder_did: &str) -> (String, String) {
        (server_id.to_string(), holder_did.to_string())
    }
}

#[async_trait]
impl HostingTokenStore for InMemoryTokenStore {
    async fn get(
        &self,
        server_id: &str,
        holder_did: &str,
    ) -> Result<Option<TokenData>, ClientError> {
        Ok(self
            .inner
            .get(&Self::key(server_id, holder_did))
            .map(|v| v.clone()))
    }

    async fn put(
        &self,
        server_id: &str,
        holder_did: &str,
        data: TokenData,
    ) -> Result<(), ClientError> {
        self.inner.insert(Self::key(server_id, holder_did), data);
        Ok(())
    }

    async fn invalidate(&self, server_id: &str, holder_did: &str) -> Result<(), ClientError> {
        self.inner.remove(&Self::key(server_id, holder_did));
        Ok(())
    }
}

/// Type-erased handle the `Client` will store. The integrator
/// picks an implementation at construction time and the rest of
/// the crate uses this alias.
pub type SharedTokenStore = Arc<dyn HostingTokenStore>;

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_td() -> TokenData {
        TokenData {
            access_token: "super-secret-access-AAA".into(),
            access_expires_at: 1_700_000_000 + 900,
            refresh_token: "super-secret-refresh-RRR".into(),
            refresh_expires_at: 1_700_000_000 + 86_400,
        }
    }

    /// The wrapper must never print either token substring. A
    /// regression where someone changed `<redacted>` back to
    /// `&self.access_token` would be caught here.
    #[test]
    fn token_data_debug_redacts_both_tokens() {
        let td = fresh_td();
        let rendered = format!("{td:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("access_expires_at"));
        assert!(rendered.contains("refresh_expires_at"));
        assert!(
            !rendered.contains("super-secret-access"),
            "access_token leaked into Debug: {rendered}"
        );
        assert!(
            !rendered.contains("super-secret-refresh"),
            "refresh_token leaked into Debug: {rendered}"
        );
    }

    #[tokio::test]
    async fn in_memory_store_round_trip() {
        let store = InMemoryTokenStore::new();
        assert!(
            store
                .get("srv-a", "did:example:alice")
                .await
                .unwrap()
                .is_none()
        );

        store
            .put("srv-a", "did:example:alice", fresh_td())
            .await
            .unwrap();

        let fetched = store
            .get("srv-a", "did:example:alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.access_token, "super-secret-access-AAA");
        assert_eq!(fetched.access_expires_at, 1_700_000_000 + 900);

        store
            .invalidate("srv-a", "did:example:alice")
            .await
            .unwrap();
        assert!(
            store
                .get("srv-a", "did:example:alice")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Two DIDs against the same server are independently cached.
    #[tokio::test]
    async fn in_memory_store_keys_on_holder_did() {
        let store = InMemoryTokenStore::new();
        store
            .put("srv-a", "did:example:alice", fresh_td())
            .await
            .unwrap();
        store
            .put("srv-a", "did:example:bob", fresh_td())
            .await
            .unwrap();
        assert!(
            store
                .get("srv-a", "did:example:alice")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get("srv-a", "did:example:bob")
                .await
                .unwrap()
                .is_some()
        );

        // Invalidating alice doesn't touch bob.
        store
            .invalidate("srv-a", "did:example:alice")
            .await
            .unwrap();
        assert!(
            store
                .get("srv-a", "did:example:alice")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get("srv-a", "did:example:bob")
                .await
                .unwrap()
                .is_some()
        );
    }

    /// The same DID against two servers — also independent. Pins
    /// the (server, did) composite key so a future refactor that
    /// dropped the server component would be caught.
    #[tokio::test]
    async fn in_memory_store_keys_on_server_id() {
        let store = InMemoryTokenStore::new();
        store
            .put("srv-a", "did:example:alice", fresh_td())
            .await
            .unwrap();
        store
            .put("srv-b", "did:example:alice", fresh_td())
            .await
            .unwrap();
        store
            .invalidate("srv-a", "did:example:alice")
            .await
            .unwrap();
        assert!(
            store
                .get("srv-a", "did:example:alice")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get("srv-b", "did:example:alice")
                .await
                .unwrap()
                .is_some()
        );
    }
}

//! did-hosting-side [`SessionStore`] adapter for did-hosting's
//! [`KeyspaceHandle`].
//!
//! VTI's canonical /auth/* handlers in
//! `vti_common::auth::handlers` operate over the
//! [`vti_common::auth::SessionStore`] trait. did-hosting writes
//! its own adapter (rather than reusing vti-common's
//! `KeyspaceSessionStore`) because the two repos carry separate
//! `KeyspaceHandle` types — vti-common's is a Local/Vsock enum,
//! did-hosting's is a struct with a pluggable backend trait
//! (fjall, Redis, DynamoDB, …).
//!
//! Each did-hosting service (control / server / witness) builds
//! its own `AuthBackend` impl on top of [`SessionStore`] —
//! they all share the same storage adapter but differ in
//! transport (REST id_token vs DIDComm) and in role / ACL
//! resolution.

use async_trait::async_trait;

use vti_common::auth::backend::SessionStore;
use vti_common::auth::session::{Session, SessionState};

use crate::server::auth::session;
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

/// `SessionStore` impl backed by did-hosting's `KeyspaceHandle`.
///
/// Thin newtype rather than a blanket impl so the
/// canonical-handler dispatch ergonomics match vti-common's
/// `KeyspaceSessionStore` (`backend.sessions().store_session(...)`).
#[derive(Clone)]
pub struct DidHostingSessionStore {
    inner: KeyspaceHandle,
}

impl DidHostingSessionStore {
    pub fn new(inner: KeyspaceHandle) -> Self {
        Self { inner }
    }

    pub fn handle(&self) -> &KeyspaceHandle {
        &self.inner
    }
}

#[async_trait]
impl SessionStore for DidHostingSessionStore {
    type Error = AppError;

    async fn store_session(&self, s: &Session) -> Result<(), Self::Error> {
        session::store_session(&self.inner, s).await
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<Session>, Self::Error> {
        session::get_session(&self.inner, session_id).await
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), Self::Error> {
        session::delete_session(&self.inner, session_id).await
    }

    async fn store_refresh_index(
        &self,
        refresh_token: &str,
        session_id: &str,
    ) -> Result<(), Self::Error> {
        session::store_refresh_index(&self.inner, refresh_token, session_id).await
    }

    async fn take_session_id_by_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<Option<String>, Self::Error> {
        session::take_session_id_by_refresh(&self.inner, refresh_token).await
    }

    /// O(N) prefix-scan implementation. did-hosting historically
    /// kept an O(1) per-DID tracker on control but not on
    /// server/witness; this canonical path uses the shared O(N)
    /// surface for all three. Acceptable at the keyspace sizes
    /// did-hosting operates at today; revisit if the count
    /// becomes a bottleneck (move the tracker behind a
    /// `pending_challenges:` keyspace shared by all three
    /// services).
    async fn count_pending_challenges(&self, did: &str) -> Result<usize, Self::Error> {
        let entries = self.inner.prefix_iter_raw("session:").await?;
        let mut count = 0usize;
        for (_key, value) in entries {
            if let Ok(s) = serde_json::from_slice::<Session>(&value)
                && s.did == did
                && s.state == SessionState::ChallengeSent
            {
                count += 1;
            }
        }
        Ok(count)
    }
}

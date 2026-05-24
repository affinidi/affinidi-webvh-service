//! did-hosting-server `AuthBackend` impl.
//!
//! DIDComm-only (no SIOPv2 surface). Same JwtKeys + storage as
//! did-hosting-control; the canonical handler in vti-common
//! does the heavy lifting. Differences vs control:
//!
//! - Per-DID rate limit applies via the canonical handler's
//!   default (10), backed by `count_pending_challenges` —
//!   server doesn't have a separate O(1) tracker, so this is
//!   the rate-limit mechanism. Closes the H3 gap from the
//!   May 2026 security review (server's O(N) inline scan is
//!   replaced by the canonical handler's count + cap).
//! - DIDComm freshness window: 60s (canonical default), matching
//!   the previous behaviour where the route handler checked
//!   `created_time` against `now - challenge_ttl`.

use async_trait::async_trait;
use std::sync::Arc;

use did_hosting_common::server::auth::DidHostingSessionStore;
use did_hosting_common::server::auth::jwt::JwtKeys;
use vti_common::auth::backend::{AuthBackend, RoleResolution};

use crate::acl::Role;
use crate::error::AppError;
use crate::server::AppState;

pub struct DidHostingServerAuthBackend {
    state: Arc<AppState>,
    sessions: DidHostingSessionStore,
    jwt_keys: Arc<JwtKeys>,
}

impl DidHostingServerAuthBackend {
    pub fn from_state(state: &AppState) -> Result<Self, AppError> {
        let jwt_keys = state
            .jwt_keys
            .clone()
            .ok_or_else(|| AppError::Internal("JWT keys not configured".into()))?;
        let sessions = DidHostingSessionStore::new(state.sessions_ks.clone());
        Ok(Self {
            state: Arc::new(state.clone()),
            sessions,
            jwt_keys,
        })
    }
}

#[async_trait]
impl AuthBackend for DidHostingServerAuthBackend {
    type Store = DidHostingSessionStore;
    type Error = AppError;
    type Role = Role;

    fn sessions(&self) -> &Self::Store {
        &self.sessions
    }

    async fn mint_access_token(
        &self,
        subject: &str,
        session_id: &str,
        role: &Self::Role,
        _contexts: &[String],
        amr: &[String],
        acr: &str,
        _tee_attested: bool,
        ttl_secs: u64,
    ) -> Result<String, Self::Error> {
        let mut claims = JwtKeys::new_claims(
            subject.to_string(),
            session_id.to_string(),
            role.to_string(),
            ttl_secs,
        );
        claims.amr = amr.to_vec();
        claims.acr = acr.to_string();
        self.jwt_keys
            .encode(&claims)
            .map_err(|e| AppError::Internal(format!("jwt encode failed: {e:?}")))
    }

    async fn check_acl(&self, did: &str) -> Result<RoleResolution<Self::Role>, Self::Error> {
        let role = crate::acl::check_acl(&self.state.acl_ks, did).await?;
        Ok(RoleResolution::new(role))
    }

    fn challenge_ttl(&self) -> u64 {
        self.state.config.auth.challenge_ttl
    }

    fn access_token_ttl(&self) -> u64 {
        self.state.config.auth.access_token_expiry
    }

    fn refresh_token_ttl(&self) -> u64 {
        self.state.config.auth.refresh_token_expiry
    }
}

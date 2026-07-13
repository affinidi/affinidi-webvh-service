//! webvh-witness `AuthBackend` impl.
//!
//! Same shape as did-hosting-server: DIDComm-only, JwtKeys from
//! did-hosting-common, ACL flat. The canonical handler in
//! vti-common does the flow; this struct provides the policy hooks.

use async_trait::async_trait;
use std::sync::Arc;

use did_hosting_common::server::auth::DidHostingSessionStore;
use did_hosting_common::server::auth::jwt::JwtKeys;
use vti_common::auth::backend::{AuthBackend, RoleResolution};

use crate::acl::Role;
use crate::error::AppError;
use crate::server::AppState;

pub struct WebvhWitnessAuthBackend {
    state: Arc<AppState>,
    sessions: DidHostingSessionStore,
    jwt_keys: Arc<JwtKeys>,
}

impl WebvhWitnessAuthBackend {
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
impl AuthBackend for WebvhWitnessAuthBackend {
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
        jti: &str,
    ) -> Result<String, Self::Error> {
        let mut claims = JwtKeys::new_claims(
            subject.to_string(),
            session_id.to_string(),
            role.to_string(),
            ttl_secs,
        );
        claims.amr = amr.to_vec();
        claims.acr = acr.to_string();
        // Override `new_claims`' own random `jti`: the caller pins this nonce
        // to the session's `token_id`, and the `AuthClaims` extractor rejects
        // any token whose `jti` doesn't match it.
        claims.jti = jti.to_string();
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

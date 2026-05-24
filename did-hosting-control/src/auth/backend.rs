//! did-hosting-control `AuthBackend` impl.
//!
//! Wires the canonical `/auth/*` handlers in `vti_common::auth::handlers`
//! to did-hosting-control's storage (`sessions_ks`, `acl_ks`), JWT
//! minter, and Role enum.
//!
//! Behaviour vs vti-common's defaults:
//!
//! - Per-DID rate limit is **off** at the canonical-handler level
//!   (`max_pending_challenges_per_did = 0`). did-hosting-control
//!   keeps its existing O(1) `PendingChallengeTracker` on `AppState`,
//!   and the route handler calls `try_issue` + `release` around the
//!   canonical-handler call. The canonical handler's O(N)
//!   prefix-scan rate-limit would be redundant + slower; preserving
//!   the tracker is a deliberate choice (the gating mechanism is
//!   the same, just measured differently).
//! - DID-method allowlist: trait default (accept any).
//! - TEE attestation: trait default (not attested). did-hosting
//!   doesn't run in a TEE.
//! - Audit hook: trait default (`tracing::info!(audit=true)`).

use async_trait::async_trait;
use std::sync::Arc;

use did_hosting_common::server::auth::DidHostingSessionStore;
use did_hosting_common::server::auth::jwt::JwtKeys;
use vti_common::auth::backend::{AuthBackend, RoleResolution};

use crate::acl::Role;
use crate::error::AppError;
use crate::server::AppState;

pub struct DidHostingControlAuthBackend {
    state: Arc<AppState>,
    sessions: DidHostingSessionStore,
    jwt_keys: Arc<JwtKeys>,
}

impl DidHostingControlAuthBackend {
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
impl AuthBackend for DidHostingControlAuthBackend {
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
        // did-hosting's Claims has no `contexts` or `tee_attested`
        // fields — both args are accepted by the canonical
        // signature but ignored here. did-hosting's ACL is flat
        // and there's no TEE deployment surface.
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
        // did-hosting's ACL is flat (no per-context scoping); leave
        // contexts empty so the JWT carries no scope claim.
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

    /// Disable canonical per-DID rate limiting — the existing
    /// O(1) `PendingChallengeTracker` on AppState owns this
    /// concern. See module-level docs.
    fn max_pending_challenges_per_did(&self) -> usize {
        0
    }
}

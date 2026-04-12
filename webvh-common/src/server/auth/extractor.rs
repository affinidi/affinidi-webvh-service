use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use tracing::{debug, warn};

use crate::server::acl::Role;
use crate::server::auth::jwt::JwtKeys;
use crate::server::auth::session::{SessionState, get_session};
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

/// Trait that application states must implement to support auth extractors.
///
/// Both webvh-server and webvh-witness implement this for their respective
/// `AppState` types, allowing `AuthClaims` and `AdminAuth` to be generic.
pub trait AuthState: Clone + Send + Sync + 'static {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>>;
    fn sessions_ks(&self) -> &KeyspaceHandle;
}

/// Extracted from a valid JWT Bearer token on protected routes.
///
/// Add this as a handler parameter to require authentication:
/// ```ignore
/// async fn handler(_auth: AuthClaims, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AuthClaims {
    pub did: String,
    pub role: Role,
}

impl<S: AuthState> FromRequestParts<S> for AuthClaims {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract Bearer token from Authorization header
        let TypedHeader(auth) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    warn!("auth rejected: missing or invalid Authorization header");
                    AppError::Unauthorized("missing or invalid Authorization header".into())
                })?;

        let token = auth.token();

        // Decode and validate JWT
        let jwt_keys = state
            .jwt_keys()
            .ok_or_else(|| AppError::Unauthorized("auth not configured".into()))?;

        let claims = jwt_keys.decode(token)?;

        // Verify session exists and is authenticated
        let session = get_session(state.sessions_ks(), &claims.session_id)
            .await?
            .ok_or_else(|| {
                warn!(session_id = %claims.session_id, "auth rejected: session not found");
                AppError::Unauthorized("session not found".into())
            })?;

        if session.state != SessionState::Authenticated {
            warn!(session_id = %claims.session_id, "auth rejected: session not in authenticated state");
            return Err(AppError::Unauthorized("session not authenticated".into()));
        }

        // Validate token_id matches — prevents use of old tokens after refresh
        if let Some(ref session_token_id) = session.token_id
            && !claims.jti.is_empty()
            && claims.jti != *session_token_id
        {
            warn!(session_id = %claims.session_id, "auth rejected: token revoked (stale jti)");
            return Err(AppError::Unauthorized("token has been revoked".into()));
        }

        let role = claims.role.parse::<Role>()?;

        debug!(did = %claims.sub, role = %claims.role, session_id = %claims.session_id, "request authenticated");

        Ok(AuthClaims {
            did: claims.sub,
            role,
        })
    }
}

/// Extractor that requires the caller to have Service role.
///
/// Use on endpoints that only service accounts should access (e.g. register-service):
/// ```ignore
/// async fn handler(auth: ServiceAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct ServiceAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for ServiceAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Service => Ok(ServiceAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: service role required");
                Err(AppError::Forbidden("service role required".into()))
            }
        }
    }
}

/// Extractor that requires the caller to have Admin role.
///
/// Use on endpoints that manage ACL entries and other admin tasks:
/// ```ignore
/// async fn handler(auth: AdminAuth, ...) { }
/// ```
#[derive(Debug, Clone)]
pub struct AdminAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        match claims.role {
            Role::Admin => Ok(AdminAuth(claims)),
            _ => {
                warn!(did = %claims.did, role = %claims.role, "auth rejected: admin role required");
                Err(AppError::Forbidden("admin role required".into()))
            }
        }
    }
}

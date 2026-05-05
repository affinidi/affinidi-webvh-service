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

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::auth::session::{Session, SessionState, store_session};
    use crate::server::config::StoreConfig;
    use crate::server::store::Store;
    use axum::http::Request;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[derive(Clone)]
    struct TestState {
        keys: Arc<JwtKeys>,
        ks: KeyspaceHandle,
    }

    impl AuthState for TestState {
        fn jwt_keys(&self) -> Option<&Arc<JwtKeys>> {
            Some(&self.keys)
        }
        fn sessions_ks(&self) -> &KeyspaceHandle {
            &self.ks
        }
    }

    async fn make_state() -> (TestState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: PathBuf::from(dir.path()),
            ..StoreConfig::default()
        })
        .await
        .unwrap();
        let ks = store.keyspace("sessions").unwrap();
        let keys = Arc::new(JwtKeys::from_ed25519_bytes(&[9u8; 32]).unwrap());
        (TestState { keys, ks }, dir)
    }

    fn parts_with_bearer(token: &str) -> axum::http::request::Parts {
        let req = Request::builder()
            .header("authorization", format!("Bearer {token}"))
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        parts
    }

    fn parts_without_auth() -> axum::http::request::Parts {
        let req = Request::builder().body(()).unwrap();
        let (parts, _) = req.into_parts();
        parts
    }

    async fn seed_session(state: &TestState, role: Role, jti: &str) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let _ = role; // role lives on the JWT claims, not the session record
        let session = Session {
            session_id: session_id.clone(),
            did: "did:example:caller".into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: 0,
            refresh_token: None,
            refresh_expires_at: None,
            token_id: Some(jti.to_string()),
        };
        store_session(&state.ks, &session).await.unwrap();
        session_id
    }

    fn issue(state: &TestState, session_id: &str, role: &str, jti: &str) -> String {
        let mut claims = JwtKeys::new_claims(
            "did:example:caller".into(),
            session_id.into(),
            role.into(),
            60,
        );
        claims.jti = jti.into();
        state.keys.encode(&claims).unwrap()
    }

    #[tokio::test]
    async fn auth_claims_accepts_well_formed_token() {
        let (state, _dir) = make_state().await;
        let session_id = seed_session(&state, Role::Owner, "tok-1").await;
        let token = issue(&state, &session_id, "owner", "tok-1");
        let mut parts = parts_with_bearer(&token);
        let auth = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(auth.did, "did:example:caller");
        assert_eq!(auth.role, Role::Owner);
    }

    #[tokio::test]
    async fn auth_claims_rejects_missing_authorization_header() {
        let (state, _dir) = make_state().await;
        let mut parts = parts_without_auth();
        let err = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn auth_claims_rejects_stale_jti_after_rotation() {
        // The rotation invariant: when session.token_id is set, the JWT's jti
        // must equal it. An old token with a previous jti must be refused.
        let (state, _dir) = make_state().await;
        let session_id = seed_session(&state, Role::Owner, "current-token-id").await;
        let stale_token = issue(&state, &session_id, "owner", "previous-token-id");
        let mut parts = parts_with_bearer(&stale_token);
        let err = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn auth_claims_rejects_unknown_session() {
        let (state, _dir) = make_state().await;
        // Issue a token for a session that we never seeded into the store.
        let token = issue(&state, "ghost-session", "owner", "tok-1");
        let mut parts = parts_with_bearer(&token);
        let err = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn auth_claims_rejects_session_in_challenge_state() {
        // A ChallengeSent session has not completed authentication; the JWT
        // (which we mint here only to drive the extractor) must be rejected.
        let (state, _dir) = make_state().await;
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            session_id: session_id.clone(),
            did: "did:example:caller".into(),
            challenge: "abc".into(),
            state: SessionState::ChallengeSent,
            created_at: 0,
            refresh_token: None,
            refresh_expires_at: None,
            token_id: Some("tok".into()),
        };
        store_session(&state.ks, &session).await.unwrap();
        let token = issue(&state, &session_id, "owner", "tok");
        let mut parts = parts_with_bearer(&token);
        let err = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn admin_auth_rejects_owner_role() {
        let (state, _dir) = make_state().await;
        let session_id = seed_session(&state, Role::Owner, "tok").await;
        let token = issue(&state, &session_id, "owner", "tok");
        let mut parts = parts_with_bearer(&token);
        let err = AdminAuth::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    #[tokio::test]
    async fn admin_auth_accepts_admin_role() {
        let (state, _dir) = make_state().await;
        let session_id = seed_session(&state, Role::Admin, "tok").await;
        let token = issue(&state, &session_id, "admin", "tok");
        let mut parts = parts_with_bearer(&token);
        let admin = AdminAuth::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(admin.0.role, Role::Admin);
    }

    #[tokio::test]
    async fn service_auth_rejects_owner_role() {
        let (state, _dir) = make_state().await;
        let session_id = seed_session(&state, Role::Owner, "tok").await;
        let token = issue(&state, &session_id, "owner", "tok");
        let mut parts = parts_with_bearer(&token);
        let err = ServiceAuth::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }
}

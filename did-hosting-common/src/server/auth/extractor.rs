use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use tracing::{debug, warn};

use crate::server::acl::Role;
use crate::server::auth::jwt::JwtKeys;
use crate::server::auth::session::{SessionState, get_session, now_epoch, touch_last_seen};
use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

/// Trait that application states must implement to support auth extractors.
///
/// Both did-hosting-server and webvh-witness implement this for their respective
/// `AppState` types, allowing `AuthClaims` and `AdminAuth` to be generic.
pub trait AuthState: Clone + Send + Sync + 'static {
    fn jwt_keys(&self) -> Option<&Arc<JwtKeys>>;
    fn sessions_ks(&self) -> &KeyspaceHandle;

    /// Whether `did` holds at least one step-up-only passkey credential
    /// (`KS_PASSKEY_STEP_UP`).
    ///
    /// Consulted by [`AuthClaims`] to close a TOCTOU on
    /// `demote_non_passkey_step_up_sessions`: a concurrent `/auth/refresh`
    /// can read the session row before demotion and write an `aal2`/
    /// passkey-less row back after it, resurrecting an elevation this
    /// relying party no longer honours for a subject who has since
    /// enrolled a step-up passkey. The store read only happens for an
    /// `aal2` session whose `amr` lacks a passkey factor, so this is rare
    /// on the hot path.
    fn has_step_up_passkey(&self, did: &str) -> impl std::future::Future<Output = bool> + Send;
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
    /// The session this token belongs to. Used by step-up to elevate the
    /// same session in place. Empty for transports without a session
    /// record (e.g. per-message DIDComm auth).
    pub session_id: String,
    /// Ephemeral session pubkey if one was registered during login —
    /// Ed25519 multikey, base58btc-encoded with the `z` prefix.
    /// `dispatch_trust_task` uses this to verify a Data Integrity proof's
    /// `verificationMethod` came from the same session that issued the
    /// JWT.
    pub session_pubkey_b58btc: Option<String>,
    /// Authentication methods on the session (`["did"]` base, plus
    /// `"webauthn"`/`"vta"` after a step-up). Read from the session row,
    /// not the JWT — see [`FromRequestParts`] impl below — so a demotion
    /// (e.g. `demote_non_passkey_step_up_sessions`) is reflected on the
    /// very next request rather than waiting for the token to be refreshed.
    pub amr: Vec<String>,
    /// Assurance level on the session (`"aal1"` base, `"aal2"` after a
    /// step-up). Gated by [`StepUpAuth`]. `"aal2"` only when the JWT, the
    /// session row, and (for a passkey-holding subject) the row's `amr`
    /// all agree — see the extractor impl for the exact rule.
    pub acr: String,
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

        // Validate token_id matches — prevents use of old tokens after refresh.
        //
        // The empty-jti branch is closed: when the session has a `token_id`,
        // the JWT's `jti` MUST be present and equal. Allowing a missing jti to
        // pass would let any future code path that emits jti-less tokens
        // bypass rotation entirely. New code must always include `jti`; any
        // such token is treated as revoked.
        if let Some(ref session_token_id) = session.token_id {
            if claims.jti.is_empty() {
                warn!(session_id = %claims.session_id, "auth rejected: token has empty jti while session has token_id");
                return Err(AppError::Unauthorized("token has been revoked".into()));
            }
            if claims.jti != *session_token_id {
                warn!(session_id = %claims.session_id, "auth rejected: token revoked (stale jti)");
                return Err(AppError::Unauthorized("token has been revoked".into()));
            }
        }

        let role = claims.role.parse::<Role>()?;

        // The session row, not the JWT, is authoritative for assurance.
        //
        // A JWT is a point-in-time snapshot: it keeps whatever `acr`/`amr`
        // it was minted with until it expires, however the session that
        // issued it is demoted in the meantime (e.g. a step-up passkey
        // lands and `demote_non_passkey_step_up_sessions` drops the row to
        // `aal1`). Re-deriving `acr`/`amr` here — the session is already
        // loaded on every request — means a demotion takes effect on the
        // very next request rather than waiting for the token to expire
        // or be refreshed.
        //
        // Effective `acr` is `"aal2"` only when *both* the JWT and the row
        // say so, and the row's `acr_expires_at`, when set, has not yet
        // passed (an unset deadline is a login-time `aal2` with no lapse
        // window, not "never elevated" — see `Session::acr_expires_at`).
        // Otherwise it is `"aal1"`. `amr` always comes from the row: it is
        // the same authority, and a stale JWT's `amr` is exactly what a
        // demotion needs to stop being trusted.
        let now = now_epoch();
        let row_says_aal2 =
            session.acr == "aal2" && session.acr_expires_at.is_none_or(|deadline| now < deadline);
        let mut acr = if claims.acr == "aal2" && row_says_aal2 {
            "aal2".to_string()
        } else {
            "aal1".to_string()
        };
        let amr = session.amr.clone();

        // Close the TOCTOU on that same demotion: a concurrent `/auth/refresh`
        // can read the pre-demotion row and write an `aal2`/passkey-less row
        // back after `demote_non_passkey_step_up_sessions` already ran,
        // resurrecting an elevation this relying party no longer honours for
        // a subject who has since enrolled a step-up passkey. Enforced here,
        // at the point assurance is actually used, rather than relied on
        // demotion alone to have already closed it.
        if acr == "aal2"
            && !amr.iter().any(|m| m == "passkey")
            && state.has_step_up_passkey(&session.did).await
        {
            acr = "aal1".to_string();
        }

        // Record the activity the idle timeout is measured against.
        //
        // Every client here is a bearer client, so unlike a cookie-session
        // console there is no token source to tell a browser from a service
        // integration apart by — the throttle inside `touch_last_seen` is
        // what keeps this from becoming a store write per request.
        //
        // The renewal endpoint deliberately does not pass through this
        // extractor, so a client's refresh timer cannot keep its own session
        // alive: only requests that do actual work count as activity.
        //
        // Best-effort. A failed touch must not fail an otherwise valid
        // request — it costs an early sign-out, never access.
        if let Err(e) = touch_last_seen(state.sessions_ks(), &session, now).await {
            warn!(
                session_id = %claims.session_id,
                error = %e,
                "failed to record session activity; session may idle out early",
            );
        }

        debug!(did = %claims.sub, role = %claims.role, session_id = %claims.session_id, "request authenticated");

        Ok(AuthClaims {
            did: claims.sub,
            role,
            session_id: claims.session_id,
            session_pubkey_b58btc: session.session_pubkey_b58btc,
            amr,
            acr,
        })
    }
}

/// An optional bearer session: `None` when the request carries no
/// `Authorization` header at all, the authenticated claims when it carries a
/// valid one — and a refusal, exactly as [`AuthClaims`] refuses, when it
/// carries one that does not authenticate. A bad credential is never quietly
/// treated as none.
///
/// For the one route that authorises on something other than a bearer
/// session — `POST /api/trust-tasks`, where a signed document is the
/// authorisation and a bearer session only adds the session's context.
impl<S: AuthState> axum::extract::OptionalFromRequestParts<S> for AuthClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        if !parts
            .headers
            .contains_key(axum::http::header::AUTHORIZATION)
        {
            return Ok(None);
        }
        <AuthClaims as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(Some)
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

/// Extractor that requires a **stepped-up** session (`acr == "aal2"`).
///
/// Use on sensitive operations that demand a second factor beyond the
/// base did:key login:
/// ```ignore
/// async fn delete_did(auth: StepUpAuth, ...) { }
/// ```
/// A base (`aal1`) session is rejected with [`AppError::StepUpRequired`]
/// (403, body `{ "error": "step_up_required", "required_acr": "aal2" }`)
/// — a distinct signal the wallet uses to trigger a step-up ceremony,
/// rather than the generic `forbidden` it would get from a role gate.
#[derive(Debug, Clone)]
pub struct StepUpAuth(pub AuthClaims);

impl<S: AuthState> FromRequestParts<S> for StepUpAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = AuthClaims::from_request_parts(parts, state).await?;

        if claims.acr == "aal2" {
            Ok(StepUpAuth(claims))
        } else {
            warn!(did = %claims.did, acr = %claims.acr, "auth rejected: step-up (aal2) required");
            Err(AppError::StepUpRequired(
                "operation requires a stepped-up (aal2) session".into(),
            ))
        }
    }
}

#[cfg(all(test, feature = "store-fjall"))]
mod tests {
    use super::*;
    use crate::server::auth::session::{Session, SessionState, store_session};
    use crate::server::config::StoreConfig;
    use crate::server::store::{KS_SESSIONS, Store};
    use axum::http::Request;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[derive(Clone)]
    struct TestState {
        keys: Arc<JwtKeys>,
        ks: KeyspaceHandle,
        /// Stand-in for `KS_PASSKEY_STEP_UP`: DIDs marked here are reported
        /// by `has_step_up_passkey` as holding a step-up passkey, without
        /// standing up the real WebAuthn credential store.
        step_up_passkey_dids: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    }

    impl TestState {
        fn mark_step_up_passkey(&self, did: &str) {
            self.step_up_passkey_dids
                .lock()
                .unwrap()
                .insert(did.to_string());
        }
    }

    impl AuthState for TestState {
        fn jwt_keys(&self) -> Option<&Arc<JwtKeys>> {
            Some(&self.keys)
        }
        fn sessions_ks(&self) -> &KeyspaceHandle {
            &self.ks
        }
        fn has_step_up_passkey(&self, did: &str) -> impl std::future::Future<Output = bool> + Send {
            let has = self.step_up_passkey_dids.lock().unwrap().contains(did);
            async move { has }
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
        let ks = store.keyspace(KS_SESSIONS).unwrap();
        let keys = Arc::new(JwtKeys::from_ed25519_bytes(&[9u8; 32]).unwrap());
        (
            TestState {
                keys,
                ks,
                step_up_passkey_dids: Arc::new(std::sync::Mutex::new(
                    std::collections::HashSet::new(),
                )),
            },
            dir,
        )
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
            last_seen: 0,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            token_id: Some(jti.to_string()),
            session_pubkey_b58btc: None,
            amr: Vec::new(),
            acr: String::new(),
            acr_expires_at: None,
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

    /// Like [`issue`], but with a caller-chosen `amr`/`acr` — for exercising
    /// a JWT minted at `aal2` before the session it belongs to is demoted.
    fn issue_with_aal(
        state: &TestState,
        session_id: &str,
        role: &str,
        jti: &str,
        amr: Vec<String>,
        acr: &str,
    ) -> String {
        let mut claims = JwtKeys::new_claims(
            "did:example:caller".into(),
            session_id.into(),
            role.into(),
            60,
        );
        claims.jti = jti.into();
        claims.amr = amr;
        claims.acr = acr.into();
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
            last_seen: 0,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            token_id: Some("tok".into()),
            session_pubkey_b58btc: None,
            amr: Vec::new(),
            acr: String::new(),
            acr_expires_at: None,
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
    async fn auth_claims_rejects_empty_jti_when_session_has_token_id() {
        // Regression: empty jti must not bypass rotation. If a future bug
        // emitted tokens without a jti, the rotation check used to short-
        // circuit and accept the token. Now any session with a token_id
        // requires a non-empty matching jti.
        let (state, _dir) = make_state().await;
        let session_id = seed_session(&state, Role::Owner, "expected-jti").await;
        let token = issue(&state, &session_id, "owner", "");
        let mut parts = parts_with_bearer(&token);
        let err = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn service_auth_accepts_service_role() {
        // Positive path for ServiceAuth — the previous round only had a
        // negative case, so a regression that broke Service-role acceptance
        // would not fail any test.
        let (state, _dir) = make_state().await;
        let session_id = seed_session(&state, Role::Service, "tok").await;
        let token = issue(&state, &session_id, "service", "tok");
        let mut parts = parts_with_bearer(&token);
        let svc = ServiceAuth::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(svc.0.role, Role::Service);
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

    /// #192: a JWT minted while a session was `aal2` must not outlive that
    /// session's demotion. Once `demote_non_passkey_step_up_sessions` drops
    /// the row to `aal1` (a step-up passkey landed for the subject), the
    /// still-`aal2` JWT is read back as `aal1` on the very next request —
    /// the session row is authoritative, not the token.
    #[tokio::test]
    async fn a_stale_aal2_jwt_is_aal1_after_demotion() {
        let (state, _dir) = make_state().await;
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            session_id: session_id.clone(),
            did: "did:example:caller".into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: 0,
            last_seen: 0,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            token_id: Some("tok".into()),
            session_pubkey_b58btc: None,
            // Elevated without a passkey factor — exactly what
            // `demote_non_passkey_step_up_sessions` targets.
            amr: vec!["did".to_string()],
            acr: "aal2".into(),
            acr_expires_at: None,
        };
        store_session(&state.ks, &session).await.unwrap();
        // Minted while the row was still aal2.
        let stale_token = issue_with_aal(
            &state,
            &session_id,
            "owner",
            "tok",
            vec!["did".to_string()],
            "aal2",
        );

        let demoted = crate::server::auth::session::demote_non_passkey_step_up_sessions(
            &state.ks,
            "did:example:caller",
        )
        .await
        .unwrap();
        assert_eq!(demoted, 1);

        let mut parts = parts_with_bearer(&stale_token);
        let claims = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(claims.acr, "aal1", "the demoted row must win over the JWT");
        assert_eq!(claims.amr, vec!["did".to_string()]);
    }

    /// #190: closes the TOCTOU on demotion. A concurrent `/auth/refresh` can
    /// read the session before it is demoted and write an `aal2`/passkey-less
    /// row back after — resurrecting an elevation the relying party no
    /// longer honours once the subject holds a step-up passkey. The
    /// extractor must catch this at use-time, not rely on demotion alone.
    #[tokio::test]
    async fn a_refreshed_aal2_row_without_passkey_amr_is_aal1_for_a_passkey_holder() {
        let (state, _dir) = make_state().await;
        state.mark_step_up_passkey("did:example:caller");

        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            session_id: session_id.clone(),
            did: "did:example:caller".into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: 0,
            last_seen: 0,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            token_id: Some("tok".into()),
            session_pubkey_b58btc: None,
            // As if a refresh just re-minted aal2 with the pre-demotion amr —
            // the row and the JWT agree, but neither carries a passkey factor.
            amr: vec!["did".to_string()],
            acr: "aal2".into(),
            acr_expires_at: None,
        };
        store_session(&state.ks, &session).await.unwrap();
        let token = issue_with_aal(
            &state,
            &session_id,
            "owner",
            "tok",
            vec!["did".to_string()],
            "aal2",
        );

        let mut parts = parts_with_bearer(&token);
        let claims = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(
            claims.acr, "aal1",
            "a passkey-holding subject's non-passkey aal2 must not survive, \
             even when the JWT and row agree"
        );
    }

    /// A session whose `amr` already contains `"passkey"` is untouched by
    /// the use-time check, even for a subject who holds a step-up passkey —
    /// it already satisfies the rule that now applies.
    #[tokio::test]
    async fn an_aal2_session_with_passkey_amr_is_left_at_aal2() {
        let (state, _dir) = make_state().await;
        state.mark_step_up_passkey("did:example:caller");

        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            session_id: session_id.clone(),
            did: "did:example:caller".into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: 0,
            last_seen: 0,
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            token_id: Some("tok".into()),
            session_pubkey_b58btc: None,
            amr: vec!["did".to_string(), "passkey".to_string()],
            acr: "aal2".into(),
            acr_expires_at: None,
        };
        store_session(&state.ks, &session).await.unwrap();
        let token = issue_with_aal(
            &state,
            &session_id,
            "owner",
            "tok",
            vec!["did".to_string(), "passkey".to_string()],
            "aal2",
        );

        let mut parts = parts_with_bearer(&token);
        let claims = AuthClaims::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(claims.acr, "aal2");
    }
}

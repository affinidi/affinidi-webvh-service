use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use super::{PasskeyState, store};
use crate::server::acl::{self, AclEntry, Role, check_acl};
use crate::server::auth::extractor::AdminAuth;
use crate::server::auth::session::{TokenResponse, create_authenticated_session, now_epoch};
use crate::server::error::AppError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// First-8-character prefix of a token, for log correlation without exposing the
/// full secret. Tokens are 32 bytes hex-encoded (64 chars), so 8 chars give an
/// adversary 32 bits of identifier — useful for correlation but not enough to
/// guess the remaining 56 chars.
fn token_prefix(token: &str) -> &str {
    &token[..token.len().min(8)]
}

fn require_webauthn<S: PasskeyState>(state: &S) -> Result<&Webauthn, AppError> {
    state.webauthn().map(|w| w.as_ref()).ok_or_else(|| {
        warn!("passkey request rejected: WebAuthn not configured (set public_url)");
        AppError::Authentication("passkey auth not configured (set public_url)".into())
    })
}

fn require_jwt_keys<S: PasskeyState>(
    state: &S,
) -> Result<&crate::server::auth::jwt::JwtKeys, AppError> {
    state
        .jwt_keys()
        .map(|k| k.as_ref())
        .ok_or_else(|| AppError::Authentication("JWT keys not configured".into()))
}

// ---------------------------------------------------------------------------
// POST /auth/passkey/enroll/start
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EnrollStartRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct EnrollStartResponse {
    pub registration_id: String,
    pub options: CreationChallengeResponse,
}

pub async fn enroll_start<S: PasskeyState>(
    State(state): State<S>,
    Json(req): Json<EnrollStartRequest>,
) -> Result<Json<EnrollStartResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let sessions_ks = state.sessions_ks();
    let acl_ks = state.acl_ks();

    // Read (don't consume) the enrollment. The actual `take` happens
    // in `enroll_finish` after the WebAuthn ceremony succeeds — that
    // way a failed ceremony (browser closed, key not present, RP
    // mismatch, attacker decline-after-clicking) leaves the invite
    // intact for the legitimate user to retry. To prevent the race
    // where two concurrent `enroll_start` calls both proceed past
    // this point, we record `claimed_at` and refuse a second
    // start within the claim window.
    let mut enrollment = store::get_enrollment(sessions_ks, &req.token)
        .await?
        .ok_or_else(|| {
            warn!("passkey enrollment rejected: token not found or already used");
            AppError::Authentication("enrollment not found or already used".into())
        })?;

    let now = now_epoch();

    // Expiry runs first — an expired claim is moot.
    if now > enrollment.expires_at {
        warn!(did = %enrollment.did, "passkey enrollment rejected: link expired");
        return Err(AppError::Authentication(
            "enrollment link has expired".into(),
        ));
    }

    // Concurrent-claim check. Within the window, reject; outside the
    // window, the previous claim is stale (failed ceremony) and we
    // overwrite.
    if let Some(claimed_at) = enrollment.claimed_at
        && now.saturating_sub(claimed_at) < store::ENROLLMENT_CLAIM_WINDOW_SECS
    {
        warn!(did = %enrollment.did, "passkey enrollment rejected: ceremony already in progress");
        return Err(AppError::Authentication(
            "enrollment is already in progress; retry after the current ceremony completes or expires".into(),
        ));
    }
    enrollment.claimed_at = Some(now);
    store::store_enrollment(sessions_ks, &enrollment).await?;

    // Ensure DID is in ACL — the enrollment itself is the admin's authorization,
    // so create the ACL entry if it doesn't already exist.
    let role = enrollment.role.parse::<Role>()?;
    if acl::get_acl_entry(acl_ks, &enrollment.did).await?.is_none() {
        let entry = AclEntry {
            did: enrollment.did.clone(),
            role: role.clone(),
            label: Some("enrolled via passkey invite".into()),
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,

            domains: crate::server::domain::DomainScope::All,
        };
        acl::store_acl_entry(acl_ks, &entry).await?;
        info!(did = %enrollment.did, role = %role, "ACL entry created from enrollment");
    }

    // Create or look up PasskeyUser for this DID
    let user = match store::get_passkey_user_by_did(sessions_ks, &enrollment.did).await? {
        Some(u) => u,
        None => store::PasskeyUser {
            user_uuid: Uuid::new_v4(),
            did: enrollment.did.clone(),
            display_name: enrollment.did.clone(),
            credentials: Vec::new(),
        },
    };

    // Collect existing credential IDs to exclude (prevent re-registration)
    let exclude: Option<Vec<CredentialID>> = if user.credentials.is_empty() {
        None
    } else {
        Some(
            user.credentials
                .iter()
                .map(|c| c.cred_id().clone())
                .collect(),
        )
    };

    // Start registration ceremony
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user.user_uuid, &user.did, &user.display_name, exclude)
        .map_err(|e| AppError::Internal(format!("webauthn registration start failed: {e}")))?;

    // Persist the user (so finish can find it), registration state, and user mapping
    store::store_passkey_user(sessions_ks, &user).await?;

    let reg_id = Uuid::new_v4().to_string();
    store::store_registration_state(sessions_ks, &reg_id, &reg_state).await?;
    store::store_registration_user(sessions_ks, &reg_id, &user.user_uuid).await?;
    // Carry the enrollment token forward so `enroll_finish` can
    // consume it after the WebAuthn ceremony succeeds.
    store::store_registration_enrollment(sessions_ks, &reg_id, &req.token).await?;

    info!(did = %user.did, reg_id = %reg_id, "passkey enrollment started");

    Ok(Json(EnrollStartResponse {
        registration_id: reg_id,
        options: ccr,
    }))
}

// ---------------------------------------------------------------------------
// POST /auth/passkey/enroll/finish
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EnrollFinishRequest {
    pub registration_id: String,
    pub credential: RegisterPublicKeyCredential,
}

pub async fn enroll_finish<S: PasskeyState>(
    State(state): State<S>,
    Json(req): Json<EnrollFinishRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let jwt_keys = require_jwt_keys(&state)?;
    let sessions_ks = state.sessions_ks();
    let acl_ks = state.acl_ks();

    // Atomically load and delete registration state (prevents race conditions)
    let reg_state = store::take_registration_state(sessions_ks, &req.registration_id)
        .await?
        .ok_or_else(|| {
            AppError::Authentication("registration state not found or expired".into())
        })?;

    // Complete registration ceremony. If this fails, the enrollment
    // token is NOT consumed — the legitimate user can retry once the
    // claim window expires.
    let passkey = webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            warn!(reg_id = %req.registration_id, error = %e, "passkey registration ceremony failed");
            AppError::Authentication(format!("passkey registration failed: {e}"))
        })?;

    // Now consume the enrollment token. The take is atomic across
    // replicas (refresh-token rotation pattern); a second concurrent
    // finish that races us sees None and would already have failed
    // the registration-state take above.
    if let Some(token) =
        store::take_registration_enrollment(sessions_ks, &req.registration_id).await?
    {
        let _ = store::take_enrollment(sessions_ks, &token).await?;
    }
    // Backwards-compat path: no mapping found (e.g. an in-flight
    // ceremony that started before this version was deployed) — fall
    // through; the next `enroll_start` will re-take it.

    // Load user UUID from registration-to-user mapping
    let user_uuid = store::get_registration_user(sessions_ks, &req.registration_id)
        .await?
        .ok_or_else(|| AppError::Internal("registration user mapping not found".into()))?;
    store::delete_registration_user(sessions_ks, &req.registration_id).await?;

    let mut user = store::get_passkey_user(sessions_ks, &user_uuid)
        .await?
        .ok_or_else(|| AppError::Internal("passkey user not found".into()))?;

    // Store credential mapping
    let cred_id_hex = hex::encode(passkey.cred_id());
    store::store_credential_mapping(sessions_ks, &cred_id_hex, user.user_uuid).await?;

    // Append the new credential
    user.credentials.push(passkey);
    store::store_passkey_user(sessions_ks, &user).await?;

    // Check ACL role
    let role = check_acl(acl_ks, &user.did).await?;

    // Issue session
    let token_resp = create_authenticated_session(
        sessions_ks,
        jwt_keys,
        &user.did,
        &role,
        state.access_token_expiry(),
        state.refresh_token_expiry(),
    )
    .await?;

    info!(did = %user.did, "passkey enrollment completed");

    Ok(Json(token_resp))
}

// ---------------------------------------------------------------------------
// POST /auth/passkey/login/start
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct LoginStartResponse {
    pub auth_id: String,
    pub options: RequestChallengeResponse,
}

pub async fn login_start<S: PasskeyState>(
    State(state): State<S>,
) -> Result<Json<LoginStartResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let sessions_ks = state.sessions_ks();

    // Collect all stored passkeys for discoverable authentication
    let all_passkeys = store::get_all_passkeys(sessions_ks).await?;

    if all_passkeys.is_empty() {
        warn!("passkey login failed: no passkeys registered on this server");
        return Err(AppError::Authentication(
            "no passkeys registered on this server".into(),
        ));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&all_passkeys)
        .map_err(|e| AppError::Internal(format!("webauthn auth start failed: {e}")))?;

    let auth_id = Uuid::new_v4().to_string();
    store::store_auth_state(sessions_ks, &auth_id, &auth_state).await?;

    info!(auth_id = %auth_id, passkey_count = all_passkeys.len(), "passkey login challenge issued");

    Ok(Json(LoginStartResponse {
        auth_id,
        options: rcr,
    }))
}

// ---------------------------------------------------------------------------
// POST /auth/passkey/login/finish
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginFinishRequest {
    pub auth_id: String,
    pub credential: PublicKeyCredential,
}

pub async fn login_finish<S: PasskeyState>(
    State(state): State<S>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let jwt_keys = require_jwt_keys(&state)?;
    let sessions_ks = state.sessions_ks();
    let acl_ks = state.acl_ks();

    // Atomically load and delete auth state (prevents race conditions)
    let auth_state = store::take_auth_state(sessions_ks, &req.auth_id)
        .await?
        .ok_or_else(|| AppError::Authentication("auth state not found or expired".into()))?;

    // Complete authentication ceremony
    let auth_result = webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| {
            warn!(auth_id = %req.auth_id, error = %e, "passkey authentication ceremony failed");
            AppError::Authentication(format!("passkey authentication failed: {e}"))
        })?;

    // Look up user by credential ID
    let cred_id_hex = hex::encode(auth_result.cred_id());
    let mut user = store::get_passkey_user_by_cred(sessions_ks, &cred_id_hex)
        .await?
        .ok_or_else(|| AppError::Authentication("credential not registered".into()))?;

    // Update credential counter (replay protection)
    for cred in &mut user.credentials {
        cred.update_credential(&auth_result);
    }
    store::store_passkey_user(sessions_ks, &user).await?;

    // Check DID still in ACL
    let role = check_acl(acl_ks, &user.did).await?;

    // Issue session
    let token_resp = create_authenticated_session(
        sessions_ks,
        jwt_keys,
        &user.did,
        &role,
        state.access_token_expiry(),
        state.refresh_token_expiry(),
    )
    .await?;

    info!(did = %user.did, "passkey login successful");

    Ok(Json(token_resp))
}

// ---------------------------------------------------------------------------
// POST /auth/passkey/invite  (admin-only)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    pub did: String,
    #[serde(default = "default_invite_role")]
    pub role: String,
}

fn default_invite_role() -> String {
    "owner".into()
}

#[derive(Debug, Serialize)]
pub struct CreateInviteResponse {
    pub token: String,
    pub enrollment_url: String,
    pub expires_at: u64,
}

/// Core logic shared by the REST handler and CLI subcommand.
pub async fn create_enrollment_invite(
    sessions_ks: &crate::server::store::KeyspaceHandle,
    base_url: &str,
    enrollment_ttl: u64,
    did: &str,
    role: &str,
) -> Result<CreateInviteResponse, AppError> {
    // Validate role
    let _ = role.parse::<Role>()?;

    // Generate a 32-byte random token
    let token = {
        use rand::RngExt;
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        hex::encode(bytes)
    };

    let now = now_epoch();
    let enrollment = store::Enrollment {
        token: token.clone(),
        did: did.to_string(),
        role: role.to_string(),
        created_at: now,
        expires_at: now + enrollment_ttl,
        claimed_at: None,
    };

    store::store_enrollment(sessions_ks, &enrollment).await?;

    let enrollment_url = format!("{base_url}/enroll?token={token}");

    info!(did = %did, role = %role, "enrollment invite created");

    Ok(CreateInviteResponse {
        token,
        enrollment_url,
        expires_at: enrollment.expires_at,
    })
}

/// Axum handler — requires admin auth.
pub async fn create_invite<S: PasskeyState>(
    _auth: AdminAuth,
    State(state): State<S>,
    Json(req): Json<CreateInviteRequest>,
) -> Result<Json<CreateInviteResponse>, AppError> {
    let base_url = state
        .public_url()
        .ok_or_else(|| AppError::Config("public_url is required for enrollment invites".into()))?;

    let resp = create_enrollment_invite(
        state.sessions_ks(),
        base_url,
        state.enrollment_ttl(),
        &req.did,
        &req.role,
    )
    .await?;

    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// GET /auth/passkey/invites  (admin-only) — list pending invites
// PUT /auth/passkey/invite/{token}  (admin-only) — change role (or extend TTL)
// DELETE /auth/passkey/invite/{token}  (admin-only) — revoke
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct InviteListItem {
    pub token: String,
    pub did: String,
    pub role: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub enrollment_url: String,
    /// True when `expires_at < now_epoch()` — the invite can no longer
    /// be claimed but is still in the store (the claim path deletes
    /// atomically; expired invites only disappear after a cleanup
    /// pass). Useful so admins see history instead of silent drop.
    pub expired: bool,
}

#[derive(Debug, Serialize)]
pub struct InviteListResponse {
    pub invites: Vec<InviteListItem>,
}

/// List every pending enrollment invite. Admin-only.
pub async fn list_invites<S: PasskeyState>(
    _auth: AdminAuth,
    State(state): State<S>,
) -> Result<Json<InviteListResponse>, AppError> {
    let base_url = state.public_url().unwrap_or("").to_string();
    let now = now_epoch();

    let pairs = store::list_enrollments(state.sessions_ks()).await?;
    let mut invites: Vec<InviteListItem> = pairs
        .into_iter()
        .map(|e| InviteListItem {
            enrollment_url: if base_url.is_empty() {
                format!("/enroll?token={}", e.token)
            } else {
                format!("{base_url}/enroll?token={}", e.token)
            },
            expired: e.expires_at < now,
            token: e.token,
            did: e.did,
            role: e.role,
            created_at: e.created_at,
            expires_at: e.expires_at,
        })
        .collect();

    // Newest first — most recently created invites are what admins
    // want to see at the top of the list.
    invites.sort_by_key(|b| std::cmp::Reverse(b.created_at));

    Ok(Json(InviteListResponse { invites }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateInviteRequest {
    /// New role to assign. If absent, role is left unchanged.
    #[serde(default)]
    pub role: Option<String>,
    /// New absolute expiry (unix seconds). Mutually exclusive with
    /// `extend_ttl`. If both are absent, expiry is left unchanged.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Extend expiry by this many seconds from `now`. Mutually
    /// exclusive with `expires_at`.
    #[serde(default)]
    pub extend_ttl: Option<u64>,
}

/// Update an existing invite's role and/or expiry. Admin-only.
pub async fn update_invite<S: PasskeyState>(
    _auth: AdminAuth,
    State(state): State<S>,
    Path(token): Path<String>,
    Json(req): Json<UpdateInviteRequest>,
) -> Result<Json<InviteListItem>, AppError> {
    if req.expires_at.is_some() && req.extend_ttl.is_some() {
        return Err(AppError::Validation(
            "`expires_at` and `extend_ttl` are mutually exclusive".into(),
        ));
    }

    if let Some(ref role) = req.role {
        role.parse::<Role>()?;
    }

    let sessions_ks = state.sessions_ks();
    let existing = store::get_enrollment(sessions_ks, &token)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("invite not found: {token}")))?;

    let now = now_epoch();
    let new_expires = match (req.expires_at, req.extend_ttl) {
        (Some(ts), None) => ts,
        (None, Some(seconds)) => now + seconds,
        (None, None) => existing.expires_at,
        (Some(_), Some(_)) => unreachable!(),
    };

    let updated = store::Enrollment {
        token: existing.token.clone(),
        did: existing.did.clone(),
        role: req.role.unwrap_or(existing.role),
        created_at: existing.created_at,
        expires_at: new_expires,
        claimed_at: existing.claimed_at,
    };
    store::store_enrollment(sessions_ks, &updated).await?;

    let base_url = state.public_url().unwrap_or("").to_string();
    info!(
        did = %updated.did,
        role = %updated.role,
        token_prefix = %token_prefix(&token),
        "invite updated",
    );

    Ok(Json(InviteListItem {
        enrollment_url: if base_url.is_empty() {
            format!("/enroll?token={}", updated.token)
        } else {
            format!("{base_url}/enroll?token={}", updated.token)
        },
        expired: updated.expires_at < now,
        token: updated.token,
        did: updated.did,
        role: updated.role,
        created_at: updated.created_at,
        expires_at: updated.expires_at,
    }))
}

/// Revoke (delete) a pending invite. Admin-only. 204 on success.
pub async fn revoke_invite<S: PasskeyState>(
    _auth: AdminAuth,
    State(state): State<S>,
    Path(token): Path<String>,
) -> Result<StatusCode, AppError> {
    // `take_enrollment` consumes the token whether or not it exists;
    // return 404 when there was nothing to revoke so the UI can
    // distinguish "already gone" from "just revoked".
    let removed = store::take_enrollment(state.sessions_ks(), &token).await?;
    if removed.is_none() {
        return Err(AppError::NotFound(format!("invite not found: {token}")));
    }
    info!(token_prefix = %token_prefix(&token), "invite revoked");
    Ok(StatusCode::NO_CONTENT)
}

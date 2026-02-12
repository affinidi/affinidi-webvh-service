use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::acl::{self, check_acl, AclEntry, Role};
use crate::auth::session::{create_authenticated_session, now_epoch, TokenResponse};
use crate::error::AppError;
use crate::passkey::store;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_webauthn(state: &AppState) -> Result<&Webauthn, AppError> {
    state
        .webauthn
        .as_deref()
        .ok_or_else(|| AppError::Authentication("passkey auth not configured (set public_url)".into()))
}

fn require_jwt_keys(state: &AppState) -> Result<&crate::auth::jwt::JwtKeys, AppError> {
    state
        .jwt_keys
        .as_deref()
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

pub async fn enroll_start(
    State(state): State<AppState>,
    Json(req): Json<EnrollStartRequest>,
) -> Result<Json<EnrollStartResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;

    // Atomically retrieve and consume enrollment (prevents race conditions)
    let enrollment = store::take_enrollment(&state.sessions_ks, &req.token)
        .await?
        .ok_or_else(|| {
            warn!("passkey enrollment rejected: token not found or already used");
            AppError::Authentication("enrollment not found or already used".into())
        })?;

    // Check expiry
    if now_epoch() > enrollment.expires_at {
        warn!(did = %enrollment.did, "passkey enrollment rejected: link expired");
        return Err(AppError::Authentication("enrollment link has expired".into()));
    }

    // Ensure DID is in ACL — the enrollment itself is the admin's authorization,
    // so create the ACL entry if it doesn't already exist.
    let role = Role::from_str(&enrollment.role)?;
    if acl::get_acl_entry(&state.acl_ks, &enrollment.did)
        .await?
        .is_none()
    {
        let entry = AclEntry {
            did: enrollment.did.clone(),
            role: role.clone(),
            label: Some("enrolled via passkey invite".into()),
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
        };
        acl::store_acl_entry(&state.acl_ks, &entry).await?;
        info!(did = %enrollment.did, role = %role, "ACL entry created from enrollment");
    }

    // Create or look up PasskeyUser for this DID
    let user = match store::get_passkey_user_by_did(&state.sessions_ks, &enrollment.did).await? {
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
        Some(user.credentials.iter().map(|c| c.cred_id().clone()).collect())
    };

    // Start registration ceremony
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            user.user_uuid,
            &user.did,
            &user.display_name,
            exclude,
        )
        .map_err(|e| AppError::Internal(format!("webauthn registration start failed: {e}")))?;

    // Persist the user (so finish can find it), registration state, and user mapping
    store::store_passkey_user(&state.sessions_ks, &user).await?;

    let reg_id = Uuid::new_v4().to_string();
    store::store_registration_state(&state.sessions_ks, &reg_id, &reg_state).await?;
    store::store_registration_user(&state.sessions_ks, &reg_id, &user.user_uuid).await?;

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

pub async fn enroll_finish(
    State(state): State<AppState>,
    Json(req): Json<EnrollFinishRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let jwt_keys = require_jwt_keys(&state)?;

    // Atomically load and delete registration state (prevents race conditions)
    let reg_state = store::take_registration_state(&state.sessions_ks, &req.registration_id)
        .await?
        .ok_or_else(|| AppError::Authentication("registration state not found or expired".into()))?;

    // Complete registration ceremony
    let passkey = webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            warn!(reg_id = %req.registration_id, error = %e, "passkey registration ceremony failed");
            AppError::Authentication(format!("passkey registration failed: {e}"))
        })?;

    // Load user UUID from registration-to-user mapping
    let user_uuid = store::get_registration_user(&state.sessions_ks, &req.registration_id)
        .await?
        .ok_or_else(|| AppError::Internal("registration user mapping not found".into()))?;
    store::delete_registration_user(&state.sessions_ks, &req.registration_id).await?;

    let mut user = store::get_passkey_user(&state.sessions_ks, &user_uuid)
        .await?
        .ok_or_else(|| AppError::Internal("passkey user not found".into()))?;

    // Store credential mapping
    let cred_id_hex = hex::encode(passkey.cred_id());
    store::store_credential_mapping(&state.sessions_ks, &cred_id_hex, user.user_uuid).await?;

    // Append the new credential
    user.credentials.push(passkey);
    store::store_passkey_user(&state.sessions_ks, &user).await?;

    // Check ACL role
    let role = check_acl(&state.acl_ks, &user.did).await?;

    // Issue session
    let token_resp = create_authenticated_session(
        &state.sessions_ks,
        jwt_keys,
        &user.did,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
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

pub async fn login_start(
    State(state): State<AppState>,
) -> Result<Json<LoginStartResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;

    // Collect all stored passkeys for discoverable authentication
    let all_passkeys = store::get_all_passkeys(&state.sessions_ks).await?;

    if all_passkeys.is_empty() {
        return Err(AppError::Authentication(
            "no passkeys registered on this server".into(),
        ));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&all_passkeys)
        .map_err(|e| AppError::Internal(format!("webauthn auth start failed: {e}")))?;

    let auth_id = Uuid::new_v4().to_string();
    store::store_auth_state(&state.sessions_ks, &auth_id, &auth_state).await?;

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

pub async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let webauthn = require_webauthn(&state)?;
    let jwt_keys = require_jwt_keys(&state)?;

    // Atomically load and delete auth state (prevents race conditions)
    let auth_state = store::take_auth_state(&state.sessions_ks, &req.auth_id)
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
    let mut user = store::get_passkey_user_by_cred(&state.sessions_ks, &cred_id_hex)
        .await?
        .ok_or_else(|| AppError::Authentication("credential not registered".into()))?;

    // Update credential counter (replay protection)
    for cred in &mut user.credentials {
        cred.update_credential(&auth_result);
    }
    store::store_passkey_user(&state.sessions_ks, &user).await?;

    // Check DID still in ACL
    let role = check_acl(&state.acl_ks, &user.did).await?;

    // Issue session
    let token_resp = create_authenticated_session(
        &state.sessions_ks,
        jwt_keys,
        &user.did,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
    )
    .await?;

    info!(did = %user.did, "passkey login successful");

    Ok(Json(token_resp))
}

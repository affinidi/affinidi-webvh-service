use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::server::error::AppError;
use crate::server::store::KeyspaceHandle;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One-time enrollment invitation created by the CLI `invite` subcommand.
#[derive(Serialize, Deserialize)]
pub struct Enrollment {
    pub token: String,
    pub did: String,
    pub role: String,
    pub created_at: u64,
    pub expires_at: u64,
}

// Manual `Debug` keeps the diagnostic fields visible while redacting the
// invite token. The token is the bearer credential — leaking it via a stray
// `tracing::debug!(?enrollment, …)` is exactly the regression class the
// rest of the workspace's manual-Debug pattern is set up to prevent.
impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("token", &"<redacted>")
            .field("did", &self.did)
            .field("role", &self.role)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Maps a credential ID (hex-encoded) to a user UUID.
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialMapping {
    pub user_uuid: Uuid,
}

/// A passkey user — may have multiple credentials (devices).
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyUser {
    pub user_uuid: Uuid,
    pub did: String,
    pub display_name: String,
    pub credentials: Vec<Passkey>,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

fn enrollment_key(token: &str) -> String {
    format!("enroll:{token}")
}

fn registration_state_key(id: &str) -> String {
    format!("pk_reg:{id}")
}

fn auth_state_key(id: &str) -> String {
    format!("pk_auth:{id}")
}

fn registration_user_key(reg_id: &str) -> String {
    format!("pk_reg_user:{reg_id}")
}

fn credential_mapping_key(cred_id_hex: &str) -> String {
    format!("pk_cred:{cred_id_hex}")
}

fn passkey_user_key(uuid: &Uuid) -> String {
    format!("pk_user:{uuid}")
}

fn passkey_did_key(did: &str) -> String {
    format!("pk_did:{did}")
}

// ---------------------------------------------------------------------------
// Enrollment CRUD
// ---------------------------------------------------------------------------

pub async fn store_enrollment(
    ks: &KeyspaceHandle,
    enrollment: &Enrollment,
) -> Result<(), AppError> {
    ks.insert(enrollment_key(&enrollment.token), enrollment)
        .await
}

/// Atomically retrieve and delete an enrollment token.
/// Returns the enrollment if it existed, or `None` if already consumed.
pub async fn take_enrollment(
    ks: &KeyspaceHandle,
    token: &str,
) -> Result<Option<Enrollment>, AppError> {
    ks.take(enrollment_key(token)).await
}

/// Retrieve an enrollment by token without consuming it. Used by the
/// admin management endpoints (list / update) where we don't want the
/// side effect of `take_enrollment`.
pub async fn get_enrollment(
    ks: &KeyspaceHandle,
    token: &str,
) -> Result<Option<Enrollment>, AppError> {
    ks.get(enrollment_key(token)).await
}

/// List every enrollment currently in the store. Deserialises each
/// value; silently skips entries that fail to parse (corrupt / old
/// schema) so a bad row can't hide the rest from admins.
pub async fn list_enrollments(ks: &KeyspaceHandle) -> Result<Vec<Enrollment>, AppError> {
    let pairs = ks.prefix_iter_raw(b"enroll:".to_vec()).await?;
    let mut out = Vec::with_capacity(pairs.len());
    for (_key, value) in pairs {
        match serde_json::from_slice::<Enrollment>(&value) {
            Ok(e) => out.push(e),
            Err(e) => tracing::warn!(error = %e, "skipping unparseable enrollment entry"),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Registration state (temporary, during WebAuthn ceremony)
// ---------------------------------------------------------------------------

pub async fn store_registration_state(
    ks: &KeyspaceHandle,
    id: &str,
    state: &PasskeyRegistration,
) -> Result<(), AppError> {
    ks.insert(registration_state_key(id), state).await
}

/// Atomically retrieve and delete a registration state.
pub async fn take_registration_state(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<PasskeyRegistration>, AppError> {
    ks.take(registration_state_key(id)).await
}

// ---------------------------------------------------------------------------
// Authentication state (temporary, during WebAuthn ceremony)
// ---------------------------------------------------------------------------

pub async fn store_auth_state(
    ks: &KeyspaceHandle,
    id: &str,
    state: &PasskeyAuthentication,
) -> Result<(), AppError> {
    ks.insert(auth_state_key(id), state).await
}

/// Atomically retrieve and delete an auth state.
pub async fn take_auth_state(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<PasskeyAuthentication>, AppError> {
    ks.take(auth_state_key(id)).await
}

// ---------------------------------------------------------------------------
// Registration-to-user mapping (links reg_id to user UUID during ceremony)
// ---------------------------------------------------------------------------

pub async fn store_registration_user(
    ks: &KeyspaceHandle,
    reg_id: &str,
    user_uuid: &Uuid,
) -> Result<(), AppError> {
    ks.insert_raw(
        registration_user_key(reg_id),
        user_uuid.to_string().into_bytes(),
    )
    .await
}

pub async fn get_registration_user(
    ks: &KeyspaceHandle,
    reg_id: &str,
) -> Result<Option<Uuid>, AppError> {
    match ks.get_raw(registration_user_key(reg_id)).await? {
        Some(bytes) => {
            let s = String::from_utf8(bytes)
                .map_err(|e| AppError::Internal(format!("invalid registration user UUID: {e}")))?;
            let uuid = Uuid::parse_str(&s)
                .map_err(|e| AppError::Internal(format!("invalid registration user UUID: {e}")))?;
            Ok(Some(uuid))
        }
        None => Ok(None),
    }
}

pub async fn delete_registration_user(ks: &KeyspaceHandle, reg_id: &str) -> Result<(), AppError> {
    ks.remove(registration_user_key(reg_id)).await
}

// ---------------------------------------------------------------------------
// Passkey user CRUD
// ---------------------------------------------------------------------------

pub async fn store_passkey_user(ks: &KeyspaceHandle, user: &PasskeyUser) -> Result<(), AppError> {
    ks.insert(passkey_user_key(&user.user_uuid), user).await?;
    // Maintain DID → user UUID reverse index
    ks.insert_raw(
        passkey_did_key(&user.did),
        user.user_uuid.to_string().into_bytes(),
    )
    .await
}

pub async fn get_passkey_user(
    ks: &KeyspaceHandle,
    uuid: &Uuid,
) -> Result<Option<PasskeyUser>, AppError> {
    ks.get(passkey_user_key(uuid)).await
}

/// Find a PasskeyUser by scanning credential mappings.
pub async fn get_passkey_user_by_cred(
    ks: &KeyspaceHandle,
    cred_id_hex: &str,
) -> Result<Option<PasskeyUser>, AppError> {
    let mapping: Option<CredentialMapping> = ks.get(credential_mapping_key(cred_id_hex)).await?;
    match mapping {
        Some(m) => get_passkey_user(ks, &m.user_uuid).await,
        None => Ok(None),
    }
}

/// Find a PasskeyUser by DID, using the `pk_did:` reverse index.
/// Falls back to a full scan for backward compatibility with existing data.
pub async fn get_passkey_user_by_did(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<PasskeyUser>, AppError> {
    // Try the reverse index first
    if let Some(bytes) = ks.get_raw(passkey_did_key(did)).await? {
        let uuid_str = String::from_utf8(bytes)
            .map_err(|e| AppError::Internal(format!("invalid DID index UUID: {e}")))?;
        let uuid = Uuid::parse_str(&uuid_str)
            .map_err(|e| AppError::Internal(format!("invalid DID index UUID: {e}")))?;
        if let Some(user) = get_passkey_user(ks, &uuid).await? {
            return Ok(Some(user));
        }
    }

    // Fallback: linear scan for pre-index data
    let entries = ks.prefix_iter_raw("pk_user:").await?;
    for (_key, value) in entries {
        if let Ok(user) = serde_json::from_slice::<PasskeyUser>(&value)
            && user.did == did
        {
            return Ok(Some(user));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Credential mapping
// ---------------------------------------------------------------------------

pub async fn store_credential_mapping(
    ks: &KeyspaceHandle,
    cred_id_hex: &str,
    user_uuid: Uuid,
) -> Result<(), AppError> {
    let mapping = CredentialMapping { user_uuid };
    ks.insert(credential_mapping_key(cred_id_hex), &mapping)
        .await
}

/// Collect all stored passkeys from credential mappings (for discoverable login).
pub async fn get_all_passkeys(ks: &KeyspaceHandle) -> Result<Vec<Passkey>, AppError> {
    let entries = ks.prefix_iter_raw("pk_user:").await?;
    let mut passkeys = Vec::new();
    for (_key, value) in entries {
        if let Ok(user) = serde_json::from_slice::<PasskeyUser>(&value) {
            passkeys.extend(user.credentials);
        }
    }
    Ok(passkeys)
}

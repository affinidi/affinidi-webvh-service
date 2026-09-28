//! Passkey credentials and the state of an open WebAuthn ceremony.
//!
//! Credentials live in one of two keyspaces, by purpose, in the same layout:
//!
//! - **login** (`purpose: session`) credentials in
//!   [`KS_SESSIONS`](crate::server::store::KS_SESSIONS) — the only store the
//!   passkey login ceremony reads;
//! - **step-up-only** credentials in
//!   [`KS_PASSKEY_STEP_UP`](crate::server::store::KS_PASSKEY_STEP_UP).
//!
//! Every function here takes the keyspace it works on; which one is the
//! caller's decision, made once from the purpose. Nothing reads both.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use super::invite::Purpose;
use crate::server::error::AppError;
use crate::server::store::{KeyspaceHandle, WriteBatch};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
    /// The label each credential was enrolled under, by hex credential id.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

impl PasskeyUser {
    /// A user for `did` with no credentials yet.
    pub fn new(did: &str) -> Self {
        Self {
            user_uuid: Uuid::new_v4(),
            did: did.to_string(),
            display_name: did.to_string(),
            credentials: Vec::new(),
            labels: Default::default(),
        }
    }
}

/// How an enrolment ceremony was authorised.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum CeremonyOrigin {
    /// `auth/passkey/enroll/redeem/start`: an invite, by its token hash.
    Invite {
        token_hash: String,
        invite_id: String,
        role: Option<String>,
        issued_by: String,
    },
    /// `auth/passkey/enroll/start/0.2`: the subject's own signed request, and
    /// the bearer session it arrived with, when there was one.
    Subject { session_id: Option<String> },
}

/// An open enrolment ceremony, keyed by its `enrollmentId`.
///
/// It binds the registration challenge — and, when the subject already holds
/// credentials of the purpose, a distinct user-verification challenge — to
/// the subject, the purpose and what authorised it. It is taken (consumed) by
/// the first finish that presents its id, whatever the outcome, so neither
/// challenge can be answered twice.
#[derive(Serialize, Deserialize)]
pub struct Ceremony {
    pub enrollment_id: String,
    pub subject: String,
    pub purpose: Purpose,
    pub origin: CeremonyOrigin,
    pub user_uuid: Uuid,
    pub device_label: Option<String>,
    pub registration: PasskeyRegistration,
    pub user_verification: Option<PasskeyAuthentication>,
    pub expires_at: u64,
}

impl std::fmt::Debug for Ceremony {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ceremony")
            .field("enrollment_id", &self.enrollment_id)
            .field("subject", &self.subject)
            .field("purpose", &self.purpose)
            .field("origin", &self.origin)
            .field("uv", &self.user_verification.is_some())
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

fn auth_state_key(id: &str) -> String {
    format!("pk_auth:{id}")
}

fn ceremony_key(id: &str) -> String {
    format!("pk_enrol:{id}")
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

/// A credential id as the store keys it.
pub fn cred_id_hex(id: &CredentialID) -> String {
    hex::encode(AsRef::<[u8]>::as_ref(id))
}

// ---------------------------------------------------------------------------
// Ceremony state
// ---------------------------------------------------------------------------

pub async fn store_ceremony(ks: &KeyspaceHandle, ceremony: &Ceremony) -> Result<(), AppError> {
    ks.insert(ceremony_key(&ceremony.enrollment_id), ceremony)
        .await
}

/// Atomically retrieve and delete a ceremony: exactly one finish gets it.
pub async fn take_ceremony(ks: &KeyspaceHandle, id: &str) -> Result<Option<Ceremony>, AppError> {
    ks.take(ceremony_key(id)).await
}

// ---------------------------------------------------------------------------
// Authentication state (temporary, during a login ceremony)
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
// Passkey users and their credentials
// ---------------------------------------------------------------------------

pub async fn store_passkey_user(ks: &KeyspaceHandle, user: &PasskeyUser) -> Result<(), AppError> {
    ks.insert(passkey_user_key(&user.user_uuid), user).await?;
    ks.insert_raw(
        passkey_did_key(&user.did),
        user.user_uuid.to_string().into_bytes(),
    )
    .await
}

/// Stage `user` — with a credential just added — into `batch`: the user row,
/// its DID index, and the new credential's id mapping. Nothing is written
/// until the batch commits, so the credential appears whole or not at all.
pub fn stage_new_credential(
    batch: &mut WriteBatch,
    ks: &KeyspaceHandle,
    user: &PasskeyUser,
    new_cred_id_hex: &str,
) -> Result<(), AppError> {
    batch.insert(ks, passkey_user_key(&user.user_uuid), user)?;
    batch.insert_raw(
        ks,
        passkey_did_key(&user.did),
        user.user_uuid.to_string().into_bytes(),
    );
    batch.insert(
        ks,
        credential_mapping_key(new_cred_id_hex),
        &CredentialMapping {
            user_uuid: user.user_uuid,
        },
    )?;
    Ok(())
}

pub async fn get_passkey_user(
    ks: &KeyspaceHandle,
    uuid: &Uuid,
) -> Result<Option<PasskeyUser>, AppError> {
    ks.get(passkey_user_key(uuid)).await
}

/// The user a credential id belongs to.
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

/// The user for `did`, by the `pk_did:` index.
pub async fn get_passkey_user_by_did(
    ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<PasskeyUser>, AppError> {
    let Some(bytes) = ks.get_raw(passkey_did_key(did)).await? else {
        return Ok(None);
    };
    let uuid_str = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid DID index UUID: {e}")))?;
    let uuid = Uuid::parse_str(&uuid_str)
        .map_err(|e| AppError::Internal(format!("invalid DID index UUID: {e}")))?;
    get_passkey_user(ks, &uuid).await
}

/// Every credential in `ks` (for discoverable login, over the login store).
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

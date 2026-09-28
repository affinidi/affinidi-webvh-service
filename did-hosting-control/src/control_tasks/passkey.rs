//! Passkey management as Trust Tasks: `auth/passkey/list/0.1` (a subject's
//! own inventory), `auth/passkey/admin-list/0.1` (an administrator reading
//! one subject's inventory, by purpose), and `auth/passkey/revoke/{start,
//! finish}/0.2` (revoking one credential — the caller's own, or, for an
//! administrator, another subject's).
//!
//! **Revoke is a re-authentication ceremony, not a bare delete.** `start`
//! answers a fresh WebAuthn user-verification challenge over the *caller's*
//! own credentials (the person acting proves they are present, whoever owns
//! the credential being revoked); `finish` verifies that assertion and only
//! then unbinds the named credential. This is deliberate even for an
//! administrator: an administrator's own standing can be re-checked at
//! commit time (`notAuthorized`), and nothing is unbound until a real
//! passkey ceremony completes.
//!
//! A lost passkey is recovered by an administrator revoking the missing
//! credential (freeing the subject to enrol a replacement) or, for a locked-
//! out subject with none left, by re-inviting them (`enrol::invite`).

use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::specs::auth::passkey::{admin_list, list, revoke};
use webauthn_rs::prelude::{CredentialID, Passkey, PublicKeyCredential};

use did_hosting_common::server::acl::{Role, get_acl_entry};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::passkey::invite::Purpose;
use did_hosting_common::server::passkey::store::{self as pk, PasskeyUser, cred_id_hex};

use super::enrol::{credential_store, require_webauthn, uv_options};
use super::{Cx, TaskError, at, typed};
use crate::error::AppError;
use crate::server::AppState;

/// How long a revocation's user-verification ceremony stays open.
const CEREMONY_TTL_SECS: u64 = 300;

fn revocation_key(id: &str) -> String {
    format!("pk_revoke:{id}")
}

/// The id a revocation's WebAuthn authentication state is stored under, via
/// the shared `passkey::store` auth-state helpers.
fn revocation_webauthn_id(id: &str) -> String {
    format!("revoke:{id}")
}

/// An open revocation: the producer's own user-verification ceremony, bound
/// server-side to the one credential it authorises unbinding. Taken (and its
/// WebAuthn state with it) by the first finish that presents its id.
#[derive(serde::Serialize, serde::Deserialize)]
struct RevocationCeremony {
    /// Who must answer the user-verification challenge: the caller of
    /// `revoke/start`, whoever the target credential belongs to.
    producer: String,
    target_subject: String,
    target_purpose: Purpose,
    /// Hex-encoded, as the store keys credentials — for lookups.
    target_credential_id_hex: String,
    /// Base64url, exactly as `revoke/start` received it — echoed back at
    /// `finish` rather than re-derived, so the response names the credential
    /// exactly as the producer named it.
    target_credential_id_wire: String,
    expires_at: u64,
}

/// A wire credential id — base64url, the same encoding `serde_json::to_value`
/// gives a `CredentialID` on the way out — decoded to the hex form the store
/// indexes by. `None` for anything that isn't valid base64url.
fn hex_from_wire(wire: &str) -> Option<String> {
    let id: CredentialID = serde_json::from_value(Value::String(wire.to_string())).ok()?;
    Some(cred_id_hex(&id))
}

/// The `RegisteredCredential` / `ListedCredential` shape both list tasks
/// answer: they differ only in title, and in `signCount`, which this service
/// does not track (WebAuthn's own signature counter is `Passkey`-internal and
/// not exposed by the library for reporting — most passkeys never increment
/// it anyway, being synchronised rather than device-bound).
fn credential_summary(user: &PasskeyUser, passkey: &Passkey) -> Result<Value, TaskError> {
    let id = cred_id_hex(passkey.cred_id());
    let mut v = json!({
        "credentialId": serde_json::to_value(passkey.cred_id())?,
        "registeredAt": at(user.registered_at.get(&id).copied().unwrap_or(0)),
    });
    if let Some(label) = user.labels.get(&id) {
        v["deviceLabel"] = json!(label);
    }
    Ok(v)
}

/// `auth/passkey/list/0.1`: the caller's own passkeys, of every purpose —
/// login and step-up alike, since it is the subject's own inventory rather
/// than an administrator's purpose-scoped read (`admin-list`).
pub(crate) async fn list(
    cx: &Cx<'_>,
    _p: list::v0_1::Payload,
) -> Result<list::v0_1::Response, TaskError> {
    use list::v0_1::error_codes;

    let auth = cx.auth().await?;
    let state = cx.state;
    if state.webauthn.is_none() {
        return Err(TaskError::Declared(
            error_codes::PASSKEYS_NOT_SUPPORTED,
            "this service does not manage passkeys".into(),
        ));
    }
    let mut credentials = Vec::new();
    for purpose in [Purpose::Session, Purpose::StepUp] {
        let ks = credential_store(state, purpose)?;
        if let Some(user) = pk::get_passkey_user_by_did(&ks, &auth.did).await? {
            for passkey in &user.credentials {
                credentials.push(credential_summary(&user, passkey)?);
            }
        }
    }
    credentials.sort_by(|a, b| {
        b["registeredAt"]
            .as_str()
            .unwrap_or_default()
            .cmp(a["registeredAt"].as_str().unwrap_or_default())
    });
    typed(
        json!({ "credentials": credentials }),
        "passkey list response",
    )
}

/// `auth/passkey/admin-list/0.1`: one subject's passkeys of one purpose.
/// Administrator only.
pub(crate) async fn admin_list(
    cx: &Cx<'_>,
    p: admin_list::v0_1::Payload,
) -> Result<admin_list::v0_1::Response, TaskError> {
    use admin_list::v0_1::{PayloadPurpose, error_codes};

    let auth = cx.auth().await?;
    if auth.role != Role::Admin {
        return Err(TaskError::Declared(
            error_codes::NOT_ADMINISTRATOR,
            "administrator standing required".into(),
        ));
    }
    let state = cx.state;
    if state.webauthn.is_none() {
        return Err(TaskError::Declared(
            error_codes::PURPOSE_NOT_SUPPORTED,
            "this service does not manage passkeys".into(),
        ));
    }
    let subject = p.subject.to_string();
    if get_acl_entry(&state.acl_ks, &subject).await?.is_none() {
        return Err(TaskError::Declared(
            error_codes::SUBJECT_UNKNOWN,
            "this service does not recognise the subject".into(),
        ));
    }
    let purpose = match p.purpose {
        PayloadPurpose::Session => Purpose::Session,
        PayloadPurpose::StepUp => Purpose::StepUp,
        _ => {
            return Err(TaskError::Declared(
                error_codes::PURPOSE_NOT_SUPPORTED,
                "this service manages session and stepUp credentials only".into(),
            ));
        }
    };
    let ks = credential_store(state, purpose)?;
    let mut credentials = Vec::new();
    if let Some(user) = pk::get_passkey_user_by_did(&ks, &subject).await? {
        for passkey in &user.credentials {
            credentials.push(credential_summary(&user, passkey)?);
        }
    }
    typed(
        json!({ "credentials": credentials, "purpose": purpose.as_str(), "subject": subject }),
        "passkey admin-list response",
    )
}

/// The credential named by `cred_hex`, for `target_subject`, in whichever of
/// the two credential stores holds it.
async fn find_credential(
    state: &AppState,
    target_subject: &str,
    cred_hex: &str,
) -> Result<Option<(Purpose, PasskeyUser)>, AppError> {
    for purpose in [Purpose::Session, Purpose::StepUp] {
        let ks = credential_store(state, purpose)
            .map_err(|_| AppError::Internal("credential store lookup failed".into()))?;
        if let Some(user) = pk::get_passkey_user_by_did(&ks, target_subject).await?
            && user
                .credentials
                .iter()
                .any(|c| cred_id_hex(c.cred_id()) == cred_hex)
        {
            return Ok(Some((purpose, user)));
        }
    }
    Ok(None)
}

/// `auth/passkey/revoke/start/0.2`: open a user-verification ceremony over
/// the caller's own credentials, bound server-side to the credential it will
/// authorise unbinding.
pub(crate) async fn revoke_start(
    cx: &Cx<'_>,
    p: revoke::start::v0_2::Payload,
) -> Result<revoke::start::v0_2::Response, TaskError> {
    use revoke::start::v0_2::error_codes;

    let auth = cx.auth().await?;
    let state = cx.state;
    require_webauthn(state)?;

    let target_subject = match p.subject.as_ref().map(|s| s.to_string()) {
        Some(s) if s != auth.did => {
            if auth.role != Role::Admin {
                return Err(TaskError::Declared(
                    error_codes::NOT_AUTHORIZED,
                    "only an administrator may revoke another subject's passkey".into(),
                ));
            }
            s
        }
        Some(s) => s,
        None => auth.did.clone(),
    };

    let cred_hex = hex_from_wire(p.credential_id.as_str()).ok_or_else(|| {
        TaskError::Declared(
            error_codes::CREDENTIAL_NOT_FOUND,
            "not a recognised credential id".into(),
        )
    })?;
    let Some((purpose, target_user)) = find_credential(state, &target_subject, &cred_hex).await?
    else {
        return Err(TaskError::Declared(
            error_codes::CREDENTIAL_NOT_FOUND,
            "no such credential for that subject".into(),
        ));
    };
    if purpose == Purpose::Session && target_user.credentials.len() <= 1 {
        return Err(TaskError::Declared(
            error_codes::LAST_CREDENTIAL,
            "the subject's last login passkey cannot be revoked this way".into(),
        ));
    }

    // The producer's own presence: a fresh assertion from their login
    // passkey, the credential every enrolled subject can be expected to
    // hold and the one they re-authenticate with elsewhere in this console.
    let producer_ks = credential_store(state, Purpose::Session)?;
    let producer_user = pk::get_passkey_user_by_did(&producer_ks, &auth.did)
        .await?
        .filter(|u| !u.credentials.is_empty())
        .ok_or_else(|| {
            TaskError::Declared(
                error_codes::REAUTH_UNAVAILABLE,
                "you hold no passkey this service can re-verify you with".into(),
            )
        })?;
    let webauthn = require_webauthn(state)?;
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&producer_user.credentials)
        .map_err(|e| AppError::Internal(format!("webauthn revoke start failed: {e}")))?;

    let revocation_id = format!("rvk_{}", uuid::Uuid::new_v4().simple());
    let ceremony = RevocationCeremony {
        producer: auth.did.clone(),
        target_subject: target_subject.clone(),
        target_purpose: purpose,
        target_credential_id_hex: cred_hex,
        target_credential_id_wire: p.credential_id.to_string(),
        expires_at: now_epoch() + CEREMONY_TTL_SECS,
    };
    state
        .sessions_ks
        .insert(revocation_key(&revocation_id), &ceremony)
        .await?;
    pk::store_auth_state(
        &state.sessions_ks,
        &revocation_webauthn_id(&revocation_id),
        &auth_state,
    )
    .await?;
    info!(
        did = %auth.did,
        target_subject = %target_subject,
        purpose = purpose.as_str(),
        "passkey revocation started"
    );
    typed(
        json!({ "revocationId": revocation_id, "uvOptions": uv_options(&rcr)? }),
        "revoke start response",
    )
}

/// `auth/passkey/revoke/finish/0.2`: verify the producer's user-verification
/// assertion and, on success, unbind the credential the matching `start`
/// bound server-side.
pub(crate) async fn revoke_finish(
    cx: &Cx<'_>,
    p: revoke::finish::v0_2::Payload,
) -> Result<revoke::finish::v0_2::Response, TaskError> {
    use revoke::finish::v0_2::error_codes;

    let auth = cx.auth().await?;
    let state = cx.state;
    let revocation_id = p.revocation_id.to_string();
    let not_found = || {
        TaskError::Declared(
            error_codes::REVOCATION_NOT_FOUND,
            "no pending revocation has that id".into(),
        )
    };
    let ceremony: RevocationCeremony = state
        .sessions_ks
        .take(revocation_key(&revocation_id))
        .await?
        .ok_or_else(not_found)?;
    let webauthn_state =
        pk::take_auth_state(&state.sessions_ks, &revocation_webauthn_id(&revocation_id))
            .await?
            .ok_or_else(not_found)?;
    if ceremony.producer != auth.did {
        return Err(not_found());
    }
    if now_epoch() > ceremony.expires_at {
        return Err(TaskError::Declared(
            error_codes::REVOCATION_EXPIRED,
            "the revocation ceremony has expired".into(),
        ));
    }
    let webauthn = require_webauthn(state)?;
    let credential: PublicKeyCredential =
        serde_json::from_value(serde_json::to_value(&p.uv_credential)?).map_err(|e| {
            TaskError::Declared(
                error_codes::USER_VERIFICATION_FAILED,
                format!("unreadable assertion: {e}"),
            )
        })?;
    let result = webauthn
        .finish_passkey_authentication(&credential, &webauthn_state)
        .map_err(|e| {
            warn!(error = %e, "revoke user-verification refused");
            TaskError::Declared(
                error_codes::USER_VERIFICATION_FAILED,
                "the assertion did not verify".into(),
            )
        })?;
    if !result.user_verified() {
        return Err(TaskError::Declared(
            error_codes::USER_VERIFICATION_FAILED,
            "the assertion does not carry user verification".into(),
        ));
    }

    // Re-checked at commit time: administrator standing over another
    // subject can have been withdrawn since `start`.
    if ceremony.target_subject != ceremony.producer {
        let role = did_hosting_common::server::acl::check_acl(&state.acl_ks, &auth.did).await?;
        if role != Role::Admin {
            return Err(TaskError::Declared(
                error_codes::NOT_AUTHORIZED,
                "administrator standing was withdrawn meanwhile".into(),
            ));
        }
    }

    let store = credential_store(state, ceremony.target_purpose)?;
    let mut user = pk::get_passkey_user_by_did(&store, &ceremony.target_subject)
        .await?
        .ok_or_else(not_found)?;
    if ceremony.target_purpose == Purpose::Session && user.credentials.len() <= 1 {
        return Err(TaskError::Declared(
            error_codes::LAST_CREDENTIAL,
            "the subject's last login passkey cannot be revoked".into(),
        ));
    }
    if !user
        .credentials
        .iter()
        .any(|c| cred_id_hex(c.cred_id()) == ceremony.target_credential_id_hex)
    {
        // Already gone — another revocation completed meanwhile.
        return Err(not_found());
    }
    pk::remove_credential(&store, &mut user, &ceremony.target_credential_id_hex).await?;
    let remaining = user.credentials.len();

    // Update the producer's own credential's use record, since it is the one
    // that was just asserted with — mirrors login/step-up's own bookkeeping.
    if let Some(mut producer) =
        pk::get_passkey_user_by_did(&credential_store(state, Purpose::Session)?, &auth.did).await?
    {
        for c in &mut producer.credentials {
            c.update_credential(&result);
        }
        pk::store_passkey_user(&credential_store(state, Purpose::Session)?, &producer).await?;
    }

    info!(
        target: "audit",
        event = "passkey.revoked",
        subject = %ceremony.target_subject,
        purpose = ceremony.target_purpose.as_str(),
        credential_id = %ceremony.target_credential_id_wire,
        revoked_by = %auth.did,
        "passkey revoked"
    );
    typed(
        json!({
            "credentialId": ceremony.target_credential_id_wire,
            "purpose": ceremony.target_purpose.as_str(),
            "remaining": remaining,
            "revokedAt": chrono::Utc::now(),
            "subject": ceremony.target_subject,
        }),
        "revoke finish response",
    )
}

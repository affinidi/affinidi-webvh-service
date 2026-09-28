//! Passkey enrolment as Trust Tasks.
//!
//! - `auth/passkey/enroll/invite/0.2` — an administrator issues a single-use
//!   invite: a token for the URL and a claim code for a second channel, both
//!   returned once and stored only as hashes (`passkey::invite`).
//! - `auth/passkey/enroll/redeem/{start,finish}/0.1` — the invitee, who holds
//!   no key yet, presents both halves and binds a passkey of the invite's
//!   purpose to the invite's subject.
//! - `auth/passkey/enroll/{start,finish}/0.2` — an authenticated subject adds
//!   a login passkey to their own VID.
//! - `auth/passkey/enroll/invite/{list,update,revoke}/0.1` — the invites, by
//!   `inviteId`, never their secrets.
//!
//! WebAuthn's own ceremony data — creation and request options out, the
//! attestation and assertion back — is carried inside these payloads; the
//! browser ceremony itself is WebAuthn's, and the only exception to "every
//! remote call is a Trust Task".
//!
//! **Two credential stores.** A `session` credential is written to the login
//! store (`KS_SESSIONS`); a `stepUp` credential to `KS_PASSKEY_STEP_UP`, which
//! the login ceremony never reads, so a step-up credential can never sign a
//! subject in and a login credential is never taken for a step-up one.
//!
//! **User verification bound to the ceremony.** When the subject already
//! holds credentials of the purpose, the start also returns `uvOptions` over
//! them, with a challenge distinct from the registration one. Both challenges
//! live only in the ceremony record, keyed by `enrollmentId` and bound to the
//! invite (or the subject and session) that opened it. The first finish takes
//! the record whatever the outcome, so a replayed finish — or an assertion
//! made for any other ceremony — has nothing to answer.

use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::StandardCode;
use trust_tasks_rs::specs::auth::passkey::enroll::{
    finish as enroll_finish,
    invite::{
        self as tt_invite, list as invite_list, revoke as invite_revoke, update as invite_update,
    },
    redeem::{finish as redeem_finish, start as redeem_start},
    start as enroll_start,
};
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

use did_hosting_common::server::acl::{self, AclEntry, Role};
use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::didcomm_profile::ObservedTransport;
use did_hosting_common::server::domain::DomainScope;
use did_hosting_common::server::passkey::invite::{self, InviteRequest, Purpose, Redemption};
use did_hosting_common::server::passkey::store::{
    self as pk, Ceremony, CeremonyOrigin, PasskeyUser, cred_id_hex,
};
use did_hosting_common::server::store::{KS_PASSKEY_STEP_UP, KeyspaceHandle};

use super::{Cx, TaskError, at, typed};
use crate::error::AppError;
use crate::server::AppState;

/// How long an enrolment ceremony stays open (the spec RECOMMENDS 5 minutes).
const CEREMONY_TTL_SECS: u64 = 300;

/// The most login passkeys one subject may hold.
pub(crate) const MAX_SESSION_CREDENTIALS: usize = 10;

/// The role a `session` invite grants when it names none.
const DEFAULT_ROLE: &str = "owner";

/// Longest WebAuthn entity name the shared schema allows (and authenticators
/// truncate to).
const MAX_ENTITY_NAME: usize = 64;

fn require_webauthn(state: &AppState) -> Result<&webauthn_rs::Webauthn, TaskError> {
    state.webauthn.as_deref().ok_or_else(|| {
        TaskError::Standard(
            StandardCode::Unavailable,
            "passkeys are not configured on this service".into(),
        )
    })
}

/// The credential store for `purpose`. Nothing else chooses one.
fn credential_store(state: &AppState, purpose: Purpose) -> Result<KeyspaceHandle, TaskError> {
    Ok(match purpose {
        Purpose::Session => state.sessions_ks.clone(),
        Purpose::StepUp => state.store.keyspace(KS_PASSKEY_STEP_UP)?,
    })
}

/// A subject's name as an authenticator will show it, bounded as the schema
/// requires: the VID when it fits, else its tail.
fn entity_name(did: &str) -> String {
    let n = did.chars().count();
    if n <= MAX_ENTITY_NAME {
        return did.to_string();
    }
    let tail: String = did.chars().skip(n - (MAX_ENTITY_NAME - 1)).collect();
    format!("…{tail}")
}

/// Keep only `keys` of `v`, and no nulls.
fn pick(v: &Value, keys: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    for k in keys {
        if let Some(x) = v.get(*k).filter(|x| !x.is_null()) {
            out.insert((*k).into(), x.clone());
        }
    }
    Value::Object(out)
}

fn descriptors(v: Option<&Value>) -> Option<Value> {
    v.and_then(Value::as_array).map(|items| {
        Value::Array(
            items
                .iter()
                .map(|d| pick(d, &["type", "id", "transports"]))
                .collect(),
        )
    })
}

/// Creation options in the shape the shared WebAuthn schema allows. The
/// library adds hints the schema (and the platform API) does not need; they
/// are dropped rather than sent off-schema.
fn creation_options(ccr: &CreationChallengeResponse) -> Result<Value, TaskError> {
    let value = serde_json::to_value(ccr)?;
    let pk = value.get("publicKey").cloned().unwrap_or(value);
    let mut out = pick(
        &pk,
        &[
            "challenge",
            "timeout",
            "attestation",
            "extensions",
            "pubKeyCredParams",
        ],
    );
    let obj = out.as_object_mut().expect("an object");
    if let Some(rp) = pk.get("rp") {
        obj.insert("rp".into(), pick(rp, &["id", "name"]));
    }
    if let Some(user) = pk.get("user") {
        obj.insert("user".into(), pick(user, &["id", "name", "displayName"]));
    }
    if let Some(params) = pk.get("pubKeyCredParams").and_then(Value::as_array) {
        obj.insert(
            "pubKeyCredParams".into(),
            Value::Array(params.iter().map(|p| pick(p, &["type", "alg"])).collect()),
        );
    }
    if let Some(sel) = pk.get("authenticatorSelection") {
        obj.insert(
            "authenticatorSelection".into(),
            pick(
                sel,
                &[
                    "authenticatorAttachment",
                    "requireResidentKey",
                    "residentKey",
                    "userVerification",
                ],
            ),
        );
    }
    if let Some(ex) = descriptors(pk.get("excludeCredentials")) {
        obj.insert("excludeCredentials".into(), ex);
    }
    Ok(out)
}

/// Request options in the shape the shared WebAuthn schema allows.
fn uv_options(rcr: &RequestChallengeResponse) -> Result<Value, TaskError> {
    let value = serde_json::to_value(rcr)?;
    let pk = value.get("publicKey").cloned().unwrap_or(value);
    let mut out = pick(
        &pk,
        &[
            "challenge",
            "timeout",
            "rpId",
            "userVerification",
            "extensions",
        ],
    );
    if let Some(allow) = descriptors(pk.get("allowCredentials")) {
        out.as_object_mut()
            .expect("an object")
            .insert("allowCredentials".into(), allow);
    }
    Ok(out)
}

/// What a start opens: the registration, and — when the subject already holds
/// credentials of the purpose — the user verification over them.
struct Opened {
    ceremony: Ceremony,
    options: Value,
    uv_options: Option<Value>,
}

/// Open an enrolment ceremony for `subject`'s `purpose` credentials and store
/// it under a fresh `enrollmentId`. The registration and user-verification
/// challenges are drawn separately, so neither ceremony's output can answer
/// the other.
async fn open(
    state: &AppState,
    subject: &str,
    purpose: Purpose,
    origin: CeremonyOrigin,
    device_label: Option<String>,
) -> Result<Opened, TaskError> {
    let webauthn = require_webauthn(state)?;
    let store = credential_store(state, purpose)?;
    let user = pk::get_passkey_user_by_did(&store, subject)
        .await?
        .unwrap_or_else(|| PasskeyUser::new(subject));
    let exclude = (!user.credentials.is_empty()).then(|| {
        user.credentials
            .iter()
            .map(|c| c.cred_id().clone())
            .collect()
    });
    let name = entity_name(subject);
    let (ccr, registration) = webauthn
        .start_passkey_registration(user.user_uuid, &name, &name, exclude)
        .map_err(|e| AppError::Internal(format!("webauthn registration start failed: {e}")))?;
    let (uv_options, user_verification) = if user.credentials.is_empty() {
        (None, None)
    } else {
        let (rcr, auth) = webauthn
            .start_passkey_authentication(&user.credentials)
            .map_err(|e| AppError::Internal(format!("webauthn uv start failed: {e}")))?;
        (Some(uv_options(&rcr)?), Some(auth))
    };
    let ceremony = Ceremony {
        enrollment_id: format!("enr_{}", uuid::Uuid::new_v4().simple()),
        subject: subject.to_string(),
        purpose,
        origin,
        user_uuid: user.user_uuid,
        device_label,
        registration,
        user_verification,
        expires_at: now_epoch() + CEREMONY_TTL_SECS,
    };
    pk::store_ceremony(&state.sessions_ks, &ceremony).await?;
    Ok(Opened {
        options: creation_options(&ccr)?,
        uv_options,
        ceremony,
    })
}

/// Why a finish could not bind its credential, for the task to name.
enum Refusal {
    UserVerification(String),
    Attestation(String),
}

/// Verify a finish's user-verification assertion (when the ceremony asked for
/// one) and its attestation, and return the credential and the subject's user
/// record with it added — nothing is written yet.
fn verify(
    state: &AppState,
    ceremony: &Ceremony,
    existing: Option<PasskeyUser>,
    uv: Option<Value>,
    attestation: Value,
) -> Result<(Passkey, PasskeyUser), Refusal> {
    let webauthn = state
        .webauthn
        .as_deref()
        .ok_or_else(|| Refusal::Attestation("passkeys are not configured".into()))?;
    let mut user = existing.unwrap_or_else(|| PasskeyUser {
        user_uuid: ceremony.user_uuid,
        ..PasskeyUser::new(&ceremony.subject)
    });
    match (&ceremony.user_verification, uv) {
        (Some(auth), Some(uv)) => verify_uv(webauthn, auth, &mut user, uv)?,
        (Some(_), None) => {
            return Err(Refusal::UserVerification(
                "this enrolment needs a user-verified assertion from a passkey you already hold"
                    .into(),
            ));
        }
        (None, Some(_)) => {
            return Err(Refusal::UserVerification(
                "no user verification was asked for; send none".into(),
            ));
        }
        (None, None) => {}
    }
    let credential: RegisterPublicKeyCredential = serde_json::from_value(attestation)
        .map_err(|e| Refusal::Attestation(format!("unreadable attestation: {e}")))?;
    let passkey = webauthn
        .finish_passkey_registration(&credential, &ceremony.registration)
        .map_err(|e| {
            warn!(enrollment_id = %ceremony.enrollment_id, error = %e, "passkey attestation refused");
            Refusal::Attestation("the attestation did not verify".into())
        })?;
    user.credentials.push(passkey.clone());
    Ok((passkey, user))
}

/// The assertion must answer this ceremony's own challenge, with the UV flag,
/// from one of `user`'s credentials — which are the subject's, of the
/// ceremony's purpose, because `user` came from that purpose's store.
fn verify_uv(
    webauthn: &webauthn_rs::Webauthn,
    auth: &PasskeyAuthentication,
    user: &mut PasskeyUser,
    uv: Value,
) -> Result<(), Refusal> {
    let credential: PublicKeyCredential = serde_json::from_value(uv)
        .map_err(|e| Refusal::UserVerification(format!("unreadable assertion: {e}")))?;
    let result = webauthn
        .finish_passkey_authentication(&credential, auth)
        .map_err(|e| {
            warn!(error = %e, "enrolment user verification refused");
            Refusal::UserVerification("the user-verification assertion did not verify".into())
        })?;
    if !result.user_verified() {
        return Err(Refusal::UserVerification(
            "the assertion does not carry user verification".into(),
        ));
    }
    let id = cred_id_hex(result.cred_id());
    if !user
        .credentials
        .iter()
        .any(|c| cred_id_hex(c.cred_id()) == id)
    {
        return Err(Refusal::UserVerification(
            "the assertion is not from one of your credentials".into(),
        ));
    }
    for c in &mut user.credentials {
        c.update_credential(&result);
    }
    Ok(())
}

/// Write the credential — and, for a redemption that grants a role, the ACL
/// entry it authorises — in one batch.
async fn persist(
    state: &AppState,
    purpose: Purpose,
    user: &mut PasskeyUser,
    passkey: &Passkey,
    label: Option<&str>,
    acl_entry: Option<AclEntry>,
) -> Result<(), TaskError> {
    let store = credential_store(state, purpose)?;
    let id = cred_id_hex(passkey.cred_id());
    if let Some(label) = label {
        user.labels.insert(id.clone(), label.to_string());
    }
    let mut batch = state.store.batch();
    pk::stage_new_credential(&mut batch, &store, user, &id)?;
    if let Some(entry) = acl_entry.as_ref() {
        acl::stage_acl_entry(&mut batch, &state.acl_ks, entry)?;
    }
    batch.commit().await?;
    Ok(())
}

/// A credential id on the wire: base64url, as WebAuthn encodes it.
fn wire_cred_id(passkey: &Passkey) -> Result<Value, TaskError> {
    Ok(serde_json::to_value(passkey.cred_id())?)
}

// ---------------------------------------------------------------------------
// auth/passkey/enroll/invite/0.2
// ---------------------------------------------------------------------------

/// `auth/passkey/enroll/invite/0.2`: issue an invite. Administrator only.
///
/// `session` invites are for a subject with no login passkey yet; `stepUp`
/// invites for a subject this service already recognises (an ACL entry), and
/// confer no role. The token and the claim code are in this response and
/// nowhere else — the store keeps their hashes.
pub(crate) async fn invite(
    cx: &Cx<'_>,
    p: tt_invite::v0_2::Payload,
) -> Result<tt_invite::v0_2::Response, TaskError> {
    use tt_invite::v0_2::{PayloadPurpose, error_codes};

    let auth = cx.auth().await?;
    if auth.role != Role::Admin {
        return Err(TaskError::Declared(
            error_codes::ROLE_NOT_PERMITTED,
            "only an administrator may issue enrolment invites".into(),
        ));
    }
    let state = cx.state;
    require_webauthn(state)?;
    let base = state
        .config
        .public_url
        .as_deref()
        .ok_or_else(|| AppError::Config("public_url is required for enrolment invites".into()))?
        .trim_end_matches('/')
        .to_string();
    let subject = acl::validate_did_format(&p.subject)?;
    let purpose = match p.purpose {
        PayloadPurpose::Session => Purpose::Session,
        PayloadPurpose::StepUp => Purpose::StepUp,
        _ => {
            return Err(TaskError::Declared(
                error_codes::PURPOSE_NOT_SUPPORTED,
                "this service issues session and stepUp credentials only".into(),
            ));
        }
    };
    let role = match purpose {
        Purpose::StepUp => {
            if p.role.is_some() || !p.scopes.is_empty() {
                return Err(TaskError::Standard(
                    StandardCode::MalformedRequest,
                    "a stepUp invite confers nothing: role and scopes must be absent".into(),
                ));
            }
            if acl::get_acl_entry(&state.acl_ks, &subject).await?.is_none() {
                return Err(TaskError::Declared(
                    error_codes::SUBJECT_UNKNOWN,
                    "this service does not recognise the subject".into(),
                ));
            }
            None
        }
        Purpose::Session => {
            if !p.scopes.is_empty() {
                return Err(TaskError::Declared(
                    error_codes::ROLE_NOT_PERMITTED,
                    "this service grants no scopes".into(),
                ));
            }
            let role = p.role.clone().unwrap_or_else(|| DEFAULT_ROLE.to_string());
            if role.parse::<Role>().is_err() {
                return Err(TaskError::Declared(
                    error_codes::ROLE_NOT_PERMITTED,
                    format!("`{role}` is not a role this service grants"),
                ));
            }
            let enrolled = pk::get_passkey_user_by_did(&state.sessions_ks, &subject)
                .await?
                .is_some_and(|u| !u.credentials.is_empty());
            if enrolled {
                return Err(TaskError::Declared(
                    error_codes::SUBJECT_ALREADY_ENROLLED,
                    "the subject already has a login passkey; they add another with \
                     auth/passkey/enroll/start"
                        .into(),
                ));
            }
            Some(role)
        }
    };
    let ttl = p
        .ttl
        .map(|t| t.get())
        .unwrap_or(invite::DEFAULT_TTL_SECS)
        .min(state.config.auth.passkey_enrollment_ttl.max(1));
    let issued = invite::issue(
        &state.sessions_ks,
        InviteRequest {
            subject: subject.clone(),
            purpose,
            role,
            device_label: p.device_label.as_deref().cloned(),
            issued_by: auth.did.clone(),
            ttl_secs: ttl,
        },
    )
    .await?;
    typed(
        json!({
            "invite": {
                "token": issued.token,
                "url": format!("{base}/enroll?token={}", issued.token),
            },
            "subject": subject,
            "purpose": purpose.as_str(),
            "expiresAt": at(issued.invite.expires_at),
            "claimCode": issued.claim_code,
        }),
        "invite response",
    )
}

// ---------------------------------------------------------------------------
// auth/passkey/enroll/redeem/{start,finish}
// ---------------------------------------------------------------------------

/// `auth/passkey/enroll/redeem/start/0.1`: present the token and the claim
/// code, and open the registration the invite authorises. Accepted unsigned:
/// the invitee holds no key yet, and the two halves are the authorisation.
pub(crate) async fn redeem_start(
    cx: &Cx<'_>,
    p: redeem_start::v0_1::Payload,
) -> Result<redeem_start::v0_1::Response, TaskError> {
    use redeem_start::v0_1::error_codes;

    let state = cx.state;
    // Per source. On HTTPS the route has already counted the client IP; a
    // messaging transport vouches for its sender.
    if cx.via != Some(ObservedTransport::Https) {
        let source = format!("vid:{}", cx.caller.as_deref().unwrap_or_default());
        state
            .redeem_rate_limiter
            .try_consume(&source, now_epoch())?;
    }
    require_webauthn(state)?;
    let invalid = || {
        TaskError::Declared(
            error_codes::INVITE_INVALID,
            "the invite is not redeemable with that token and claim code".into(),
        )
    };
    let invite = match invite::redeem(&state.sessions_ks, &p.token, &p.claim_code).await? {
        Redemption::Valid(invite) => *invite,
        Redemption::Invalid => return Err(invalid()),
        Redemption::TooManyAttempts => {
            return Err(TaskError::Declared(
                error_codes::TOO_MANY_ATTEMPTS,
                "too many wrong claim codes: the invite has been invalidated; ask for a new one"
                    .into(),
            ));
        }
    };
    let opened = open(
        state,
        &invite.subject,
        invite.purpose,
        CeremonyOrigin::Invite {
            token_hash: invite.token_hash.clone(),
            invite_id: invite.invite_id.clone(),
            role: invite.role.clone(),
            issued_by: invite.issued_by.clone(),
        },
        invite.device_label.clone(),
    )
    .await?;
    // The newest ceremony supersedes any earlier one on this invite.
    invite::open_ceremony(
        &state.sessions_ks,
        &invite.token_hash,
        &opened.ceremony.enrollment_id,
    )
    .await
    .map_err(|_| invalid())?;
    info!(
        invite_id = %invite.invite_id,
        subject = %invite.subject,
        purpose = invite.purpose.as_str(),
        uv = opened.uv_options.is_some(),
        "passkey invite redemption started"
    );
    let mut body = json!({
        "enrollmentId": opened.ceremony.enrollment_id,
        "subject": invite.subject,
        "purpose": invite.purpose.as_str(),
        "options": opened.options,
        "expiresAt": at(opened.ceremony.expires_at),
    });
    if let Some(label) = invite.device_label {
        body["deviceLabel"] = json!(label);
    }
    if let Some(uv) = opened.uv_options {
        body["uvOptions"] = uv;
    }
    typed(body, "redeem start response")
}

/// `auth/passkey/enroll/redeem/finish/0.1`: bind the credential to the
/// invite's subject with the invite's purpose, and consume the invite.
pub(crate) async fn redeem_finish(
    cx: &Cx<'_>,
    p: redeem_finish::v0_1::Payload,
) -> Result<redeem_finish::v0_1::Response, TaskError> {
    use redeem_finish::v0_1::error_codes;

    let state = cx.state;
    require_webauthn(state)?;
    let not_found = || {
        TaskError::Declared(
            error_codes::ENROLLMENT_NOT_FOUND,
            "no open redemption has that enrollmentId".into(),
        )
    };
    // Taken now, whatever follows: this enrollmentId answers once.
    let ceremony = pk::take_ceremony(&state.sessions_ks, &p.enrollment_id)
        .await?
        .ok_or_else(not_found)?;
    let CeremonyOrigin::Invite {
        token_hash,
        invite_id,
        role,
        issued_by,
    } = ceremony.origin.clone()
    else {
        return Err(not_found());
    };
    if now_epoch() > ceremony.expires_at {
        return Err(TaskError::Declared(
            error_codes::ENROLLMENT_EXPIRED,
            "the redemption ceremony has expired; start again while the invite is valid".into(),
        ));
    }
    // The invite must still be live, and this must be its current ceremony.
    let live = invite::by_token_hash(&state.sessions_ks, &token_hash)
        .await?
        .filter(|i| !i.is_expired(now_epoch()))
        .is_some_and(|i| i.ceremony.as_deref() == Some(ceremony.enrollment_id.as_str()));
    if !live {
        return Err(not_found());
    }

    let store = credential_store(state, ceremony.purpose)?;
    let existing = pk::get_passkey_user_by_did(&store, &ceremony.subject).await?;
    let uv = p
        .uv_credential
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    let (passkey, mut user) = verify(
        state,
        &ceremony,
        existing,
        uv,
        serde_json::to_value(&p.credential)?,
    )
    .map_err(|r| match r {
        Refusal::UserVerification(m) => {
            TaskError::Declared(error_codes::USER_VERIFICATION_FAILED, m)
        }
        Refusal::Attestation(m) => TaskError::Declared(error_codes::ATTESTATION_INVALID, m),
    })?;

    // Consume the invite. Exactly one finish wins this; the loser binds
    // nothing.
    if invite::take(&state.sessions_ks, &token_hash)
        .await?
        .is_none()
    {
        return Err(not_found());
    }
    let acl_entry = match (ceremony.purpose, role) {
        (Purpose::Session, Some(role)) => {
            match acl::get_acl_entry(&state.acl_ks, &ceremony.subject).await? {
                Some(_) => None,
                None => Some(AclEntry {
                    did: ceremony.subject.clone(),
                    role: role.parse::<Role>()?,
                    label: Some("enrolled via passkey invite".into()),
                    created_at: now_epoch(),
                    max_total_size: None,
                    max_did_count: None,
                    domains: DomainScope::All,
                }),
            }
        }
        _ => None,
    };
    let label = p
        .device_label
        .as_deref()
        .cloned()
        .or(ceremony.device_label.clone());
    persist(
        state,
        ceremony.purpose,
        &mut user,
        &passkey,
        label.as_deref(),
        acl_entry,
    )
    .await?;
    let cred_id = wire_cred_id(&passkey)?;
    info!(
        target: "audit",
        event = "passkey.invite.redeemed",
        invite_id = %invite_id,
        issued_by = %issued_by,
        subject = %ceremony.subject,
        purpose = ceremony.purpose.as_str(),
        credential_id = %cred_id,
        "passkey enrolled by invite"
    );
    let mut body = json!({
        "credentialId": cred_id,
        "subject": ceremony.subject,
        "purpose": ceremony.purpose.as_str(),
        "registeredAt": chrono::Utc::now(),
    });
    if let Some(label) = label {
        body["deviceLabel"] = json!(label);
    }
    typed(body, "redeem finish response")
}

// ---------------------------------------------------------------------------
// auth/passkey/enroll/{start,finish}/0.2
// ---------------------------------------------------------------------------

/// `auth/passkey/enroll/start/0.2`: the proven caller adds a login passkey to
/// their own VID. When they already hold one, the response carries
/// `uvOptions` and the finish must answer them.
pub(crate) async fn start(
    cx: &Cx<'_>,
    p: enroll_start::v0_2::Payload,
) -> Result<enroll_start::v0_2::Response, TaskError> {
    use enroll_start::v0_2::error_codes;

    let auth = cx.auth().await?;
    let state = cx.state;
    require_webauthn(state).map_err(|_| {
        TaskError::Declared(
            error_codes::ENROLLMENT_NOT_SUPPORTED,
            "this service does not enrol passkeys".into(),
        )
    })?;
    let held = pk::get_passkey_user_by_did(&state.sessions_ks, &auth.did)
        .await?
        .map(|u| u.credentials.len())
        .unwrap_or(0);
    if held >= MAX_SESSION_CREDENTIALS {
        return Err(TaskError::Declared(
            error_codes::MAX_CREDENTIALS_REACHED,
            format!("at most {MAX_SESSION_CREDENTIALS} passkeys per subject"),
        ));
    }
    let session_id = cx
        .bearer_session()
        .filter(|b| b.did == auth.did && !b.session_id.is_empty())
        .map(|b| b.session_id.clone());
    let opened = open(
        state,
        &auth.did,
        Purpose::Session,
        CeremonyOrigin::Subject { session_id },
        p.device_label.as_deref().cloned(),
    )
    .await?;
    info!(did = %auth.did, uv = opened.uv_options.is_some(), "passkey enrolment started");
    let mut body = json!({
        "enrollmentId": opened.ceremony.enrollment_id,
        "options": opened.options,
    });
    if let Some(uv) = opened.uv_options {
        body["uvOptions"] = uv;
    }
    typed(body, "enroll start response")
}

/// `auth/passkey/enroll/finish/0.2`: bind the credential to the subject the
/// start was issued to, who must be the one finishing.
pub(crate) async fn finish(
    cx: &Cx<'_>,
    p: enroll_finish::v0_2::Payload,
) -> Result<enroll_finish::v0_2::Response, TaskError> {
    use enroll_finish::v0_2::error_codes;

    let auth = cx.auth().await?;
    let state = cx.state;
    require_webauthn(state)?;
    let not_found = || {
        TaskError::Declared(
            error_codes::ENROLLMENT_NOT_FOUND,
            "no open enrolment has that enrollmentId".into(),
        )
    };
    let ceremony = pk::take_ceremony(&state.sessions_ks, &p.enrollment_id)
        .await?
        .ok_or_else(not_found)?;
    let CeremonyOrigin::Subject { session_id } = &ceremony.origin else {
        return Err(not_found());
    };
    if now_epoch() > ceremony.expires_at {
        return Err(TaskError::Declared(
            error_codes::ENROLLMENT_EXPIRED,
            "the enrolment has expired; start again".into(),
        ));
    }
    let same_session = match session_id {
        Some(sid) => cx.bearer_session().is_some_and(|b| &b.session_id == sid),
        None => true,
    };
    if ceremony.subject != auth.did || !same_session {
        return Err(TaskError::Declared(
            error_codes::SUBJECT_MISMATCH,
            "this enrolment was started by another subject or session".into(),
        ));
    }
    let existing = pk::get_passkey_user_by_did(&state.sessions_ks, &ceremony.subject).await?;
    if existing
        .as_ref()
        .is_some_and(|u| u.credentials.len() >= MAX_SESSION_CREDENTIALS)
    {
        return Err(TaskError::Standard(
            StandardCode::TaskFailed,
            format!("at most {MAX_SESSION_CREDENTIALS} passkeys per subject"),
        ));
    }
    let uv = p
        .uv_credential
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    let (passkey, mut user) = verify(
        state,
        &ceremony,
        existing,
        uv,
        serde_json::to_value(&p.credential)?,
    )
    .map_err(|r| match r {
        Refusal::UserVerification(m) => TaskError::Standard(StandardCode::PermissionDenied, m),
        Refusal::Attestation(m) => TaskError::Declared(error_codes::ATTESTATION_INVALID, m),
    })?;
    let label = p
        .device_label
        .as_deref()
        .cloned()
        .or(ceremony.device_label.clone());
    persist(
        state,
        Purpose::Session,
        &mut user,
        &passkey,
        label.as_deref(),
        None,
    )
    .await?;
    let cred_id = wire_cred_id(&passkey)?;
    info!(
        target: "audit",
        event = "passkey.enrolled",
        subject = %ceremony.subject,
        credential_id = %cred_id,
        "passkey enrolled by its subject"
    );
    let mut body = json!({
        "credentialId": cred_id,
        "subject": ceremony.subject,
        "registeredAt": chrono::Utc::now(),
    });
    if let Some(label) = label {
        body["deviceLabel"] = json!(label);
    }
    typed(body, "enroll finish response")
}

// ---------------------------------------------------------------------------
// Invite management, by inviteId
// ---------------------------------------------------------------------------

/// A stored invite in the shared `InviteSummary` shape — never a secret.
fn summary(i: &invite::Invite, now: u64) -> Value {
    let mut v = json!({
        "inviteId": i.invite_id,
        "subject": i.subject,
        "purpose": i.purpose.as_str(),
        "createdAt": at(i.created_at),
        "expiresAt": at(i.expires_at),
        "expired": i.is_expired(now),
    });
    if let Some(role) = &i.role {
        v["role"] = json!(role);
    }
    v
}

/// `auth/passkey/enroll/invite/list/0.1`. Administrator only.
pub(crate) async fn invite_list(
    cx: &Cx<'_>,
    p: invite_list::v0_1::Payload,
) -> Result<invite_list::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    if auth.role != Role::Admin {
        return Err(TaskError::Declared(
            invite_list::v0_1::error_codes::NOT_ADMINISTRATOR,
            "administrator standing required".into(),
        ));
    }
    let now = now_epoch();
    let include_expired = p.include_expired.unwrap_or(false);
    let invites: Vec<Value> = invite::list(&cx.state.sessions_ks)
        .await?
        .iter()
        .filter(|i| include_expired || !i.is_expired(now))
        .map(|i| summary(i, now))
        .collect();
    typed(json!({ "invites": invites }), "invite list response")
}

/// `auth/passkey/enroll/invite/update/0.1`: change an outstanding invite's
/// role or expiry, by `inviteId`. Administrator only.
///
/// The generated `Payload` is a permissive struct — every member but
/// `inviteId` is `Option` — because the schema's `oneOf` (a role alone, or
/// `expiresAt` XOR `extendBy`, each with an optional role) has no Rust type
/// shape that enforces it. So the payload is validated against the spec's
/// schema here, and refused as `malformedRequest` when it does not conform.
pub(crate) async fn invite_update(
    cx: &Cx<'_>,
    p: invite_update::v0_1::Payload,
) -> Result<invite_update::v0_1::Response, TaskError> {
    use invite_update::v0_1::error_codes;
    use trust_tasks_rs::validate::ValidatedPayload;

    let auth = cx.admin().await?;
    let raw = serde_json::to_value(&p)?;
    if let Err(e) = invite_update::v0_1::Payload::validate_value(&raw) {
        return Err(TaskError::Standard(
            StandardCode::MalformedRequest,
            format!(
                "an update changes at least one of role, expiresAt or extendBy, \
                 and expiresAt/extendBy are mutually exclusive: {e}"
            ),
        ));
    }
    let ks = &cx.state.sessions_ks;
    let now = now_epoch();
    // No invite outlives the longest one this service would issue: an
    // `expiresAt` past that is refused, an `extendBy` clamped to it
    // (Conformance item 5).
    let max = now.saturating_add(cx.state.config.auth.passkey_enrollment_ttl.max(1));
    // Read, checked and rewritten under the invite's guard, so an update
    // racing a redemption cannot bring back an invite that was just consumed.
    let existing = invite::update(ks, &p.invite_id, |existing| {
        if existing.is_expired(now) {
            return Err(TaskError::Declared(
                error_codes::INVITE_LAPSED,
                "the invite has lapsed; issue a new one".into(),
            ));
        }
        if let Some(r) = p.role.as_deref() {
            if existing.purpose == Purpose::StepUp {
                return Err(TaskError::Declared(
                    error_codes::ROLE_NOT_ALLOWED,
                    "a stepUp invite confers no role".into(),
                ));
            }
            if r.parse::<Role>().is_err() {
                return Err(TaskError::Declared(
                    error_codes::ROLE_NOT_ALLOWED,
                    format!("`{r}` is not a role this service grants"),
                ));
            }
            existing.role = Some(r.to_string());
        }
        match (p.expires_at, p.extend_by) {
            (Some(t), _) => {
                let t = t.timestamp().max(0) as u64;
                if t <= now || t > max {
                    return Err(TaskError::Standard(
                        StandardCode::MalformedRequest,
                        format!(
                            "expiresAt must lie in the future and within {}s of now",
                            max - now
                        ),
                    ));
                }
                existing.expires_at = t;
            }
            (None, Some(s)) => existing.expires_at = now.saturating_add(s.get()).min(max),
            (None, None) => {}
        }
        Ok(())
    })
    .await?
    .ok_or_else(|| TaskError::Declared(error_codes::NOT_FOUND, "no such invite".into()))?;
    info!(caller = %auth.did, invite_id = %existing.invite_id, "invite updated");
    typed(
        json!({ "invite": summary(&existing, now) }),
        "invite update response",
    )
}

/// `auth/passkey/enroll/invite/revoke/0.1`: withdraw an invite by `inviteId`.
/// Administrator only.
pub(crate) async fn invite_revoke(
    cx: &Cx<'_>,
    p: invite_revoke::v0_1::Payload,
) -> Result<invite_revoke::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    if !invite::revoke(&cx.state.sessions_ks, &p.invite_id, &auth.did).await? {
        return Err(TaskError::Declared(
            invite_revoke::v0_1::error_codes::NOT_FOUND,
            "no such invite".into(),
        ));
    }
    typed(
        json!({ "inviteId": p.invite_id.as_str(), "revokedAt": chrono::Utc::now() }),
        "invite revoke response",
    )
}

#[cfg(test)]
mod unit {
    use super::entity_name;

    #[test]
    fn entity_names_fit_the_schema() {
        assert_eq!(entity_name("did:key:z6Mk"), "did:key:z6Mk");
        let long = format!("did:webvh:{}", "a".repeat(100));
        let name = entity_name(&long);
        assert_eq!(name.chars().count(), 64);
        assert!(name.ends_with("aaaa"));
    }
}

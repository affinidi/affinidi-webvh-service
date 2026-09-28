//! Step-up (`auth/step-up/start`, `auth/step-up/approve-response/0.5`),
//! passkey login (`auth/passkey/login/{start,finish}/0.2`) and invite
//! management (`auth/passkey/enroll/invite/{list,update,revoke}`).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::specs::auth::{
    passkey::{
        enroll::invite::{list as invite_list, revoke as invite_revoke, update as invite_update},
        login::{finish as login_finish, start as login_start},
    },
    revoke_session,
    step_up::{approve_response, start as step_up_start},
};

use did_hosting_common::server::auth::session::{
    Session, SessionState, create_authenticated_session, delete_session, get_session, now_epoch,
    store_session,
};
use did_hosting_common::server::passkey::{routes as passkey_routes, store as passkey_store};

use super::{Cx, TaskError, at, new_id, typed};
use crate::acl::check_acl;
use crate::error::AppError;
use crate::server::AppState;

/// How long a step-up challenge or a passkey ceremony stays open.
const CEREMONY_TTL_SECS: u64 = 300;

/// The assurance level a step-up grants.
const STEP_UP_ACR: &str = "aal2";

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_hex(bytes: usize) -> String {
    (0..bytes)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// The canonical `Session` shape the auth family's responses carry.
fn wire_session(session: &Session, expires_at: u64) -> Value {
    json!({
        "id": session.session_id,
        "subject": session.did,
        "issuedAt": at(session.created_at),
        "expiresAt": at(expires_at),
        "amr": session.amr,
        "acr": session.acr,
    })
}

// ---------------------------------------------------------------------------
// Step-up
// ---------------------------------------------------------------------------

/// A step-up challenge bound to one session.
#[derive(Serialize, Deserialize)]
struct PendingStepUp {
    challenge: String,
    subject: String,
    expires_at: u64,
}

fn step_up_key(session_id: &str) -> String {
    format!("stepup-task:{session_id}")
}

/// `auth/revoke-session/0.2`: end one of the caller's own sessions. This is
/// the console's logout.
///
/// The session row goes, and with it its refresh token and any session key
/// bound at login. The bearer extractor reads that row on every request, so
/// the access token and the key stop working at once, not at expiry
/// (`auth/authenticate/0.2`: the binding ends on revoke or logout).
///
/// A session key may sign this, since revoking only reduces authority, but
/// only for its own session: it speaks for its subject in that session and no
/// other (`auth/authenticate/0.2` Conformance item 10), so a stolen key cannot
/// sign its subject out of their other devices.
///
/// A session that does not exist, was already revoked, belongs to someone
/// else, or is out of reach of the session key that signed, answers
/// `revokedCount: 0`, identically. That discloses nothing, and a retried
/// logout succeeds (`auth/revoke-session/0.2` Conformance item 2, the
/// RECOMMENDED form). `all` and `subject` are not offered: the console only
/// ever ends the session it holds.
pub(crate) async fn revoke_session(
    cx: &Cx<'_>,
    p: revoke_session::v0_2::Payload,
) -> Result<revoke_session::v0_2::Response, TaskError> {
    let caller = cx.caller()?.to_string();
    if p.all.is_some() || p.subject.is_some() {
        return Err(AppError::Validation(
            "this relying party revokes one session, named by sessionId".into(),
        )
        .into());
    }
    let session_id = p
        .session_id
        .as_ref()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Validation("sessionId is required".into()))?;
    let revoked = |count: u32| typed(json!({ "revokedCount": count }), "revoke-session response");

    // Signed by the bearer session's bound key: that session only.
    let by_session_key_elsewhere = cx.bearer_session().is_some_and(|b| {
        b.session_id != session_id
            && b.session_pubkey_b58btc.as_deref().is_some_and(|pk| {
                cx.proof_vm.as_deref() == Some(format!("did:key:{pk}#{pk}").as_str())
            })
    });
    if by_session_key_elsewhere {
        return revoked(0);
    }
    let Some(session) = get_session(&cx.state.sessions_ks, &session_id).await? else {
        return revoked(0);
    };
    if session.did != caller {
        return revoked(0);
    }
    delete_session(&cx.state.sessions_ks, &session_id).await?;
    info!(
        did = %caller,
        session_id = %session_id,
        reason = p.reason.as_deref().map(String::as_str).unwrap_or(""),
        "session revoked",
    );
    revoked(1)
}

/// `auth/step-up/start/0.1`: bind a fresh challenge to the caller's own
/// session and answer the signed `approve-request/0.3` the approver will
/// answer. Elevates nothing: only a verified `approve-response` does.
///
/// The session must be live and belong to the proven caller, or the proof must
/// have been made with the session's recorded key; the three failing cases
/// (no such session, someone else's, not live) answer alike.
pub(crate) async fn step_up_start(
    cx: &Cx<'_>,
    p: step_up_start::v0_1::Payload,
) -> Result<step_up_start::v0_1::Response, TaskError> {
    use step_up_start::v0_1::error_codes;

    let caller = cx.caller()?.to_string();
    let state = cx.state;
    let session_id = p.session_id.to_string();
    let unknown = || {
        TaskError::Declared(
            error_codes::SESSION_UNKNOWN,
            "no live session of yours has that id".into(),
        )
    };
    let session = get_session(&state.sessions_ks, &session_id)
        .await?
        .ok_or_else(unknown)?;
    let key_matches = session
        .session_pubkey_b58btc
        .as_deref()
        .is_some_and(|pk| cx.proof_vm.as_deref() == Some(format!("did:key:{pk}#{pk}").as_str()));
    if session.state != SessionState::Authenticated || (session.did != caller && !key_matches) {
        return Err(unknown());
    }
    let target = p
        .target_acr
        .as_ref()
        .map(|t| t.to_string())
        .unwrap_or_else(|| STEP_UP_ACR.to_string());
    if target != STEP_UP_ACR && target != "aal1" {
        return Err(AppError::Validation(format!(
            "this relying party offers step-up to {STEP_UP_ACR} only"
        ))
        .into());
    }
    if session.acr == STEP_UP_ACR || target == "aal1" {
        return Err(TaskError::Declared(
            error_codes::NOT_NEEDED,
            "the session is already at the requested assurance level".into(),
        ));
    }

    let challenge = random_hex(32);
    let expires_at = now_epoch() + CEREMONY_TTL_SECS;
    let my_vid = state
        .config
        .server_did
        .clone()
        .ok_or_else(|| AppError::Config("server_did not configured".into()))?;
    let secret = crate::signing::control_signing_secret(state, &my_vid)?;
    let request: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": new_id(),
        "type": <trust_tasks_rs::specs::auth::step_up::approve_request::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI,
        "issuer": my_vid,
        "recipient": session.did,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "expiresAt": at(expires_at).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {
            "subject": session.did,
            "sessionId": session_id,
            "challenge": challenge,
            "reason": "Elevate this session to aal2",
            "targetAcr": STEP_UP_ACR,
            "acceptableEvidence": ["didSigned"],
        },
    }))?;
    // The approve-request is the approver's to verify on its own terms before
    // surfacing its reason, so it is checked here against its own schema too.
    typed::<trust_tasks_rs::specs::auth::step_up::approve_request::v0_3::Payload>(
        request.payload.clone(),
        "approve-request payload",
    )?;
    let signed = did_hosting_common::server::trust_tasks::sign_document(&request, &secret)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Bound only once the request is signed, so a signing failure leaves no
    // orphaned challenge.
    state
        .sessions_ks
        .insert(
            step_up_key(&session_id),
            &PendingStepUp {
                challenge,
                subject: session.did.clone(),
                expires_at,
            },
        )
        .await?;
    info!(did = %session.did, session_id = %session_id, "step-up started");
    typed(
        json!({ "approveRequest": serde_json::to_value(&signed)? }),
        "step-up start response",
    )
}

/// `auth/step-up/approve-response/0.5`: the approver's signed decision. The
/// gate has verified it as an attestation (`assertionMethod`); here it must
/// answer the challenge bound to its session, be made by that session's
/// subject, and — approved — it raises the session's assurance level. Tokens
/// carrying the new level come from `auth/refresh`, which reads the session's
/// current level.
pub(crate) async fn approve_response(
    cx: &Cx<'_>,
    p: approve_response::v0_5::Payload,
) -> Result<approve_response::v0_5::Response, TaskError> {
    use approve_response::v0_5::{Evidence, PayloadDecision, error_codes};

    let approver = cx.caller()?.to_string();
    let state = cx.state;
    let session_id = p
        .session_id
        .as_ref()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            TaskError::Declared(
                error_codes::CHALLENGE_UNKNOWN,
                "this relying party binds every step-up to a session".into(),
            )
        })?;
    let pending: PendingStepUp = state
        .sessions_ks
        .get(step_up_key(&session_id))
        .await?
        .ok_or_else(|| {
            TaskError::Declared(error_codes::CHALLENGE_UNKNOWN, "no pending step-up".into())
        })?;
    if !constant_time_eq(pending.challenge.as_bytes(), p.challenge.as_bytes()) {
        return Err(TaskError::Declared(
            error_codes::CHALLENGE_UNKNOWN,
            "no pending step-up has that challenge".into(),
        ));
    }
    // Single use: consumed whatever the decision.
    state.sessions_ks.remove(step_up_key(&session_id)).await?;
    if now_epoch() > pending.expires_at {
        return Err(TaskError::Declared(
            error_codes::CHALLENGE_EXPIRED,
            "the step-up challenge has expired".into(),
        ));
    }
    if p.subject.as_str() != pending.subject {
        return Err(TaskError::Declared(
            error_codes::SUBJECT_MISMATCH,
            "the response names a different subject".into(),
        ));
    }
    // Self step-up: the approver is the subject. No delegate is recognised.
    if approver != pending.subject {
        return Err(TaskError::Declared(
            error_codes::APPROVER_UNAUTHORIZED,
            "only the session's subject may approve its step-up".into(),
        ));
    }
    if matches!(p.evidence, Some(Evidence::Webauthn(_))) {
        return Err(TaskError::Declared(
            error_codes::NO_GATE,
            "this relying party accepts didSigned evidence only".into(),
        ));
    }

    match p.decision {
        PayloadDecision::Denied => {
            info!(did = %approver, session_id = %session_id, "step-up denied by the approver");
            return typed(json!({ "status": "recorded" }), "approve-response response");
        }
        PayloadDecision::Approved => {}
        _ => return Err(AppError::Validation("unsupported decision".into()).into()),
    }
    if let Some(granted) = p.granted_acr.as_deref()
        && granted != STEP_UP_ACR
    {
        return Err(TaskError::Declared(
            error_codes::ACR_UNSATISFIED,
            format!("the approver granted {granted}; the step-up requires {STEP_UP_ACR}"),
        ));
    }

    let mut session = get_session(&state.sessions_ks, &session_id)
        .await?
        .filter(|s| s.state == SessionState::Authenticated && s.did == pending.subject)
        .ok_or_else(|| {
            TaskError::Declared(
                error_codes::CHALLENGE_UNKNOWN,
                "the session has ended".into(),
            )
        })?;
    // The ACL still gates: elevation does not outlive an ACL entry.
    check_acl(&state.acl_ks, &session.did).await?;
    if !session.amr.iter().any(|m| m == "did") {
        session.amr.push("did".into());
    }
    session.acr = STEP_UP_ACR.to_string();
    session.acr_expires_at = None;
    store_session(&state.sessions_ks, &session).await?;
    info!(did = %session.did, session_id = %session_id, "step-up approved: session elevated to aal2");
    let expires_at = session.refresh_expires_at.unwrap_or(session.created_at);
    typed(
        json!({ "status": "elevated", "session": wire_session(&session, expires_at) }),
        "approve-response response",
    )
}

// ---------------------------------------------------------------------------
// Passkey login
// ---------------------------------------------------------------------------

/// What a passkey ceremony was opened for.
#[derive(Serialize, Deserialize)]
struct CeremonyMeta {
    step_up: bool,
    subject: Option<String>,
    expires_at: u64,
}

fn ceremony_key(auth_id: &str) -> String {
    format!("pk_task_meta:{auth_id}")
}

fn require_webauthn(state: &AppState) -> Result<&webauthn_rs::Webauthn, TaskError> {
    state.webauthn.as_deref().ok_or_else(|| {
        TaskError::Standard(
            trust_tasks_rs::StandardCode::Unavailable,
            "passkeys are not configured on this service".into(),
        )
    })
}

/// The members of a WebAuthn request-options object the shared schema knows.
/// The library adds hints the schema does not (and the platform API does not
/// need); they are dropped rather than sent off-schema.
fn request_options(
    options: &webauthn_rs::prelude::RequestChallengeResponse,
) -> Result<Value, TaskError> {
    let value = serde_json::to_value(options)?;
    let public_key = value.get("publicKey").cloned().unwrap_or(value);
    let mut out = serde_json::Map::new();
    for k in [
        "challenge",
        "timeout",
        "rpId",
        "allowCredentials",
        "userVerification",
        "extensions",
    ] {
        if let Some(v) = public_key.get(k).filter(|v| !v.is_null()) {
            out.insert(k.into(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

/// `auth/passkey/login/start/0.2`: open a login (or, `purpose: stepUp`, a
/// step-up) ceremony. Accepted unsigned — the assertion at finish is the gate.
pub(crate) async fn login_start(
    cx: &Cx<'_>,
    p: login_start::v0_2::Payload,
) -> Result<login_start::v0_2::Response, TaskError> {
    use login_start::v0_2::{PayloadPurpose, error_codes};

    let state = cx.state;
    let webauthn = require_webauthn(state)?;
    let step_up = matches!(p.purpose, Some(PayloadPurpose::StepUp));
    let subject = p.subject.as_ref().map(|s| s.to_string());
    let passkeys = match subject.as_deref() {
        Some(did) => {
            let user = passkey_store::get_passkey_user_by_did(&state.sessions_ks, did)
                .await?
                .ok_or_else(|| {
                    TaskError::Declared(
                        error_codes::SUBJECT_NOT_RECOGNIZED,
                        "unknown subject".into(),
                    )
                })?;
            if user.credentials.is_empty() {
                return Err(TaskError::Declared(
                    error_codes::NO_CREDENTIALS,
                    "the subject has no passkey".into(),
                ));
            }
            user.credentials
        }
        None => {
            let all = passkey_store::get_all_passkeys(&state.sessions_ks).await?;
            if all.is_empty() {
                return Err(TaskError::Declared(
                    error_codes::NO_CREDENTIALS,
                    "no passkeys are registered here".into(),
                ));
            }
            all
        }
    };
    let (options, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(format!("webauthn start failed: {e}")))?;
    let auth_id = uuid::Uuid::new_v4().to_string();
    passkey_store::store_auth_state(&state.sessions_ks, &auth_id, &auth_state).await?;
    state
        .sessions_ks
        .insert(
            ceremony_key(&auth_id),
            &CeremonyMeta {
                step_up,
                subject,
                expires_at: now_epoch() + CEREMONY_TTL_SECS,
            },
        )
        .await?;
    typed(
        json!({ "authId": auth_id, "options": request_options(&options)? }),
        "login start response",
    )
}

/// `auth/passkey/login/finish/0.2`: verify the assertion.
///
/// A login mints a session for the credential's subject, bound to the
/// `did:key` that signed this document — the session key every later request
/// in the session is signed with. A step-up elevates the bearer session the
/// request carries, which must belong to the credential's subject, and
/// issues no tokens (`auth/refresh` reads the new level).
pub(crate) async fn login_finish(
    cx: &Cx<'_>,
    p: login_finish::v0_2::Payload,
) -> Result<login_finish::v0_2::Response, TaskError> {
    use login_finish::v0_2::error_codes;

    let state = cx.state;
    let webauthn = require_webauthn(state)?;
    let auth_id = p.auth_id.to_string();
    let not_found = || {
        TaskError::Declared(
            error_codes::AUTH_NOT_FOUND,
            "no open ceremony has that id".into(),
        )
    };
    let meta: CeremonyMeta = state
        .sessions_ks
        .take(ceremony_key(&auth_id))
        .await?
        .ok_or_else(not_found)?;
    let auth_state = passkey_store::take_auth_state(&state.sessions_ks, &auth_id)
        .await?
        .ok_or_else(not_found)?;
    if now_epoch() > meta.expires_at {
        return Err(TaskError::Declared(
            error_codes::AUTH_EXPIRED,
            "the ceremony has expired".into(),
        ));
    }
    let credential: webauthn_rs::prelude::PublicKeyCredential =
        serde_json::from_value(serde_json::to_value(&p.credential)?).map_err(|e| {
            TaskError::Declared(
                error_codes::ASSERTION_INVALID,
                format!("unreadable assertion: {e}"),
            )
        })?;
    let result = webauthn
        .finish_passkey_authentication(&credential, &auth_state)
        .map_err(|e| {
            warn!(error = %e, "passkey assertion failed");
            TaskError::Declared(
                error_codes::ASSERTION_INVALID,
                "the assertion did not verify".into(),
            )
        })?;
    let cred_id: String = AsRef::<[u8]>::as_ref(result.cred_id())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut user = passkey_store::get_passkey_user_by_cred(&state.sessions_ks, &cred_id)
        .await?
        .ok_or_else(|| {
            TaskError::Declared(error_codes::CREDENTIAL_UNKNOWN, "unknown credential".into())
        })?;
    if meta.subject.as_deref().is_some_and(|s| s != user.did) {
        return Err(TaskError::Declared(
            error_codes::ASSERTION_INVALID,
            "the credential belongs to another subject".into(),
        ));
    }
    for c in &mut user.credentials {
        c.update_credential(&result);
    }
    passkey_store::store_passkey_user(&state.sessions_ks, &user).await?;
    let role = check_acl(&state.acl_ks, &user.did).await?;

    if meta.step_up {
        let caller = cx.caller()?;
        let bearer = cx
            .bearer_session()
            .filter(|b| b.did == caller && b.did == user.did)
            .ok_or_else(|| {
                TaskError::Declared(
                    error_codes::STEP_UP_SESSION_NOT_FOUND,
                    "a step-up needs the subject's own session".into(),
                )
            })?;
        let mut session = get_session(&state.sessions_ks, &bearer.session_id)
            .await?
            .filter(|s| s.state == SessionState::Authenticated)
            .ok_or_else(|| {
                TaskError::Declared(
                    error_codes::STEP_UP_SESSION_NOT_FOUND,
                    "no live session".into(),
                )
            })?;
        for m in ["passkey"] {
            if !session.amr.iter().any(|a| a == m) {
                session.amr.push(m.into());
            }
        }
        session.acr = STEP_UP_ACR.to_string();
        session.acr_expires_at = None;
        store_session(&state.sessions_ks, &session).await?;
        info!(did = %user.did, "passkey step-up complete: session elevated to aal2");
        let expires_at = session.refresh_expires_at.unwrap_or(session.created_at);
        return typed(
            json!({ "purpose": "stepUp", "session": wire_session(&session, expires_at) }),
            "login finish response",
        );
    }

    // A login: the session is bound to the key that signed this document.
    let session_key = cx
        .caller()?
        .strip_prefix("did:key:")
        .filter(|pk| pk.starts_with("z6Mk"))
        .map(str::to_string)
        .ok_or_else(|| {
            TaskError::Standard(
                trust_tasks_rs::StandardCode::PermissionDenied,
                "a login is signed by the Ed25519 did:key its session will be bound to".into(),
            )
        })?;
    let jwt_keys = state
        .jwt_keys
        .as_deref()
        .ok_or_else(|| AppError::Config("auth not configured".into()))?;
    let tokens = create_authenticated_session(
        &state.sessions_ks,
        jwt_keys,
        &user.did,
        &role,
        state.config.auth.access_token_expiry,
        state.config.auth.refresh_token_expiry,
        Some(session_key),
        Some((vec!["passkey".to_string()], STEP_UP_ACR.to_string())),
    )
    .await?;
    info!(did = %user.did, "passkey login complete");
    let canonical = tokens.into_canonical();
    let mut tokens = serde_json::to_value(&canonical.tokens)?;
    if tokens
        .get("scope")
        .is_some_and(|s| s.as_array().is_some_and(Vec::is_empty))
    {
        tokens.as_object_mut().map(|t| t.remove("scope"));
    }
    typed(
        json!({
            "purpose": "login",
            "session": serde_json::to_value(&canonical.session)?,
            "tokens": tokens,
        }),
        "login finish response",
    )
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

/// A pending invite in the shared `InviteSummary` shape — never its token.
fn summary(item: &passkey_routes::InviteListItem) -> Value {
    json!({
        "inviteId": item.invite_id,
        "subject": item.did,
        "purpose": "session",
        "role": item.role,
        "createdAt": at(item.created_at),
        "expiresAt": at(item.expires_at),
        "expired": item.expired,
    })
}

/// `auth/passkey/enroll/invite/list/0.1`. Admin.
pub(crate) async fn invite_list(
    cx: &Cx<'_>,
    p: invite_list::v0_1::Payload,
) -> Result<invite_list::v0_1::Response, TaskError> {
    admin_or(cx, invite_list::v0_1::error_codes::NOT_ADMINISTRATOR).await?;
    let include_expired = p.include_expired.unwrap_or(false);
    let invites: Vec<Value> = passkey_routes::pending_invites(&cx.state.sessions_ks)
        .await?
        .iter()
        .filter(|i| include_expired || !i.expired)
        .map(summary)
        .collect();
    typed(json!({ "invites": invites }), "invite list response")
}

/// `auth/passkey/enroll/invite/update/0.1`: change an outstanding invite's
/// role or expiry, by `inviteId`. Admin.
///
/// The generated `Payload` (trust-tasks 0.24+) is a permissive struct — every
/// member but `inviteId` is `Option` — because the schema's `oneOf` (a role
/// alone with no expiry change, or `expiresAt` XOR `extendBy`, each with an
/// optional role alongside it) has no Rust type shape that enforces it the
/// way `deny_unknown_fields` enforces `additionalProperties: false`. Struct
/// shape alone would accept `{inviteId}` alone (a silent no-op) or
/// `{inviteId, expiresAt, extendBy}` together (two conflicting expiry
/// changes). So this handler re-validates the raw payload against the
/// spec's schema before acting, and refuses with the framework's
/// `malformedRequest` — the same code `Dispatcher::dispatch_or_reject` would
/// have produced for a shape violation, had the schema been representable
/// as one — when it does not conform.
pub(crate) async fn invite_update(
    cx: &Cx<'_>,
    p: invite_update::v0_1::Payload,
) -> Result<invite_update::v0_1::Response, TaskError> {
    use invite_update::v0_1::error_codes;
    use trust_tasks_rs::validate::ValidatedPayload;

    let auth = cx.admin().await?;

    // Re-serialize the typed (already `deny_unknown_fields`-checked) payload
    // and validate it against `PAYLOAD_SCHEMA`. This recovers exactly the
    // `oneOf` the codegen's Rust type cannot express: at least one of
    // `role`/`expiresAt`/`extendBy` present, and `expiresAt`/`extendBy`
    // mutually exclusive.
    let raw = serde_json::to_value(&p).map_err(|e| {
        TaskError::Standard(
            trust_tasks_rs::StandardCode::InternalError,
            format!("invite update payload did not re-serialize: {e}"),
        )
    })?;
    if let Err(e) = invite_update::v0_1::Payload::validate_value(&raw) {
        return Err(TaskError::Standard(
            trust_tasks_rs::StandardCode::MalformedRequest,
            format!(
                "an update changes at least one of role, expiresAt or extendBy, \
                 and expiresAt/extendBy are mutually exclusive: {e}"
            ),
        ));
    }

    let existing = passkey_store::find_enrollment_by_invite_id(&cx.state.sessions_ks, &p.invite_id)
        .await?
        .ok_or_else(|| TaskError::Declared(error_codes::NOT_FOUND, "no such invite".into()))?;
    if existing.expires_at < now_epoch() {
        return Err(TaskError::Declared(
            error_codes::INVITE_LAPSED,
            "the invite has lapsed; issue a new one".into(),
        ));
    }
    if let Some(r) = p.role.as_deref()
        && r.parse::<crate::acl::Role>().is_err()
    {
        return Err(TaskError::Declared(
            error_codes::ROLE_NOT_ALLOWED,
            format!("`{r}` is not a role this service grants"),
        ));
    }
    let item = passkey_routes::update_invite_by_id(
        &cx.state.sessions_ks,
        &p.invite_id,
        p.role.as_deref().cloned(),
        p.expires_at.map(|t| t.timestamp().max(0) as u64),
        p.extend_by.map(|s| s.get()),
    )
    .await
    .map_err(|e| match e {
        AppError::NotFound(m) => TaskError::Declared(error_codes::NOT_FOUND, m),
        other => other.into(),
    })?;
    info!(caller = %auth.did, invite_id = %p.invite_id.as_str(), "invite updated");
    typed(
        json!({ "invite": summary(&item) }),
        "invite update response",
    )
}

/// `auth/passkey/enroll/invite/revoke/0.1`: withdraw an invite by `inviteId`.
/// Admin.
pub(crate) async fn invite_revoke(
    cx: &Cx<'_>,
    p: invite_revoke::v0_1::Payload,
) -> Result<invite_revoke::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    passkey_routes::revoke_invite_by_id(&cx.state.sessions_ks, &p.invite_id)
        .await
        .map_err(|e| match e {
            AppError::NotFound(m) => {
                TaskError::Declared(invite_revoke::v0_1::error_codes::NOT_FOUND, m)
            }
            other => other.into(),
        })?;
    info!(caller = %auth.did, invite_id = %p.invite_id.as_str(), "invite revoked");
    typed(
        json!({ "inviteId": p.invite_id.as_str(), "revokedAt": chrono::Utc::now() }),
        "invite revoke response",
    )
}

/// [`Cx::admin`], refused under `code` rather than `permissionDenied`.
async fn admin_or(
    cx: &Cx<'_>,
    code: trust_tasks_rs::DeclaredErrorCode,
) -> Result<crate::auth::AuthClaims, TaskError> {
    let auth = cx.auth().await?;
    if auth.role != crate::acl::Role::Admin {
        return Err(TaskError::Declared(
            code,
            "administrator standing required".into(),
        ));
    }
    Ok(auth)
}

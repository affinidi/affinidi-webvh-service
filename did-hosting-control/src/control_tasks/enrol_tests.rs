//! Passkey enrolment, end to end, with a software authenticator: hashed
//! invites, the claim-code lockout, expiry and single use, the separation of
//! step-up and login credentials, and user verification bound to its
//! ceremony — on every transport.

use serde_json::{Value, json};

use did_hosting_common::server::acl::{Role, get_acl_entry};
use did_hosting_common::server::passkey::{invite, store as pk};
use did_hosting_common::server::store::KS_PASSKEY_STEP_UP;

use super::harness::{
    Caller, VIAS, Via, code, conforms, member, ok, request, session_for, state, stranger,
};
use super::soft_passkey::SoftPasskey;
use crate::server::AppState;

/// `harness::call`, boxed: these tests chain many ceremonies, and an unboxed
/// future of that depth overflows a test thread's stack in a debug build.
async fn call(
    state: &AppState,
    via: Via,
    caller: &Caller,
    type_uri: &str,
    payload: Value,
) -> Value {
    Box::pin(super::harness::call(state, via, caller, type_uri, payload)).await
}

/// `harness::send`, boxed.
async fn send(state: &AppState, via: Via, sender: &Caller, doc: Value) -> Value {
    Box::pin(super::harness::send(state, via, sender, doc)).await
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn t(slug: &str) -> String {
    format!("https://trusttasks.org/spec/{slug}")
}

const INVITE: &str = "auth/passkey/enroll/invite/0.2";
const REDEEM_START: &str = "auth/passkey/enroll/redeem/start/0.1";
const REDEEM_FINISH: &str = "auth/passkey/enroll/redeem/finish/0.1";
const START: &str = "auth/passkey/enroll/start/0.2";
const FINISH: &str = "auth/passkey/enroll/finish/0.2";
const LOGIN_START: &str = "auth/passkey/login/start/0.2";
const LOGIN_FINISH: &str = "auth/passkey/login/finish/0.2";
const LIST: &str = "auth/passkey/enroll/invite/list/0.1";
const STEP_UP_START: &str = "auth/step-up/start/0.1";
const STEP_UP_APPROVE: &str = "auth/step-up/approve-response/0.5";
const PK_LIST: &str = "auth/passkey/list/0.1";
const PK_ADMIN_LIST: &str = "auth/passkey/admin-list/0.1";
const PK_REVOKE_START: &str = "auth/passkey/revoke/start/0.2";
const PK_REVOKE_FINISH: &str = "auth/passkey/revoke/finish/0.2";

/// An issued invite's two secrets.
struct Issued {
    token: String,
    code: String,
    body: Value,
}

async fn issue(state: &AppState, admin: &Caller, subject: &str, purpose: &str) -> Issued {
    let reply = call(
        state,
        Via::Tsp,
        admin,
        &t(INVITE),
        json!({ "subject": subject, "purpose": purpose }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &t(INVITE));
    Issued {
        token: body["invite"]["token"].as_str().unwrap().into(),
        code: body["claimCode"].as_str().unwrap().into(),
        body,
    }
}

/// An unsigned document from `from`, as a browser (or any holder of no key)
/// sends one. Over HTTPS it names no issuer at all.
async fn unsigned(state: &AppState, via: Via, from: &Caller, slug: &str, payload: Value) -> Value {
    let mut doc = request(&t(slug), &from.did, payload);
    if via == Via::Https {
        doc.as_object_mut().unwrap().remove("issuer");
    }
    send(state, via, from, doc).await
}

async fn redeem_start(state: &AppState, via: Via, from: &Caller, token: &str, code: &str) -> Value {
    unsigned(
        state,
        via,
        from,
        REDEEM_START,
        json!({ "token": token, "claimCode": code }),
    )
    .await
}

/// Redeem `issued` with `passkey` (answering `uv` when the start asks), and
/// return the finish reply.
async fn redeem(
    state: &AppState,
    via: Via,
    from: &Caller,
    issued: &Issued,
    passkey: &mut SoftPasskey,
    uv: Option<&mut SoftPasskey>,
) -> Value {
    let reply = redeem_start(state, via, from, &issued.token, &issued.code).await;
    conforms(&reply);
    let start = ok(&reply, &t(REDEEM_START));
    let mut payload = json!({
        "enrollmentId": start["enrollmentId"],
        "credential": passkey.attest(&start["options"]),
    });
    if let Some(uv) = uv {
        payload["uvCredential"] = uv.assert(&start["uvOptions"]);
    }
    unsigned(state, via, from, REDEEM_FINISH, payload).await
}

/// Sign in with `passkey` over `via`, as the console does: an unsigned start,
/// and a finish signed by a fresh session did:key.
async fn login(state: &AppState, via: Via, passkey: &mut SoftPasskey, seed: u8) -> Value {
    let browser = stranger(seed);
    let reply = unsigned(state, via, &browser, LOGIN_START, json!({})).await;
    let start = ok(&reply, &t(LOGIN_START));
    let assertion = passkey.assert(&start["options"]);
    call(
        state,
        via,
        &browser,
        &t(LOGIN_FINISH),
        json!({ "authId": start["authId"], "credential": assertion }),
    )
    .await
}

async fn store_text(state: &AppState) -> String {
    let mut text = String::new();
    for ks in [
        state.sessions_ks.clone(),
        state.store.keyspace(KS_PASSKEY_STEP_UP).unwrap(),
    ] {
        for (k, v) in ks.iter_all().await.unwrap() {
            text.push_str(&String::from_utf8_lossy(&k));
            text.push_str(&String::from_utf8_lossy(&v));
        }
    }
    text
}

/// The token and claim code are returned once, the code never in the URL, and
/// neither is stored or listed — only their hashes are.
#[tokio::test]
async fn an_invite_discloses_its_secrets_once_and_stores_only_hashes() {
    let (state, _dir) = state().await;
    let admin = member(&state, 1, Role::Admin).await;
    let issued = issue(&state, &admin, "did:example:carol", "session").await;
    let url = issued.body["invite"]["url"].as_str().unwrap();
    assert!(url.starts_with("http://control.test/enroll?token="));
    assert!(url.contains(&issued.token));
    assert!(!url.contains(&issued.code));
    assert_eq!(issued.body["purpose"], "session");
    assert!(issued.token.len() >= 43, "256-bit token");

    let text = store_text(&state).await;
    let bare = invite::normalise_claim_code(&issued.code);
    assert!(!text.contains(&issued.token), "token stored in plaintext");
    assert!(
        !text.contains(&issued.code) && !text.contains(&bare),
        "claim code stored"
    );
    assert!(text.contains(&invite::hash_token(&issued.token)));

    let listed = call(&state, Via::Didcomm, &admin, &t(LIST), json!({})).await;
    conforms(&listed);
    let listed = listed.to_string();
    assert!(!listed.contains(&issued.token) && !listed.contains(&issued.code));
}

/// Wrong claim codes are counted per invite and lock it out; the answer is the
/// same for a wrong code, an unknown token and an expired invite.
#[tokio::test]
async fn wrong_claim_codes_lock_an_invite_out_on_every_transport() {
    let (state, _dir) = state().await;
    let admin = member(&state, 2, Role::Admin).await;
    for (i, via) in VIAS.into_iter().enumerate() {
        let invitee = stranger(20 + i as u8);
        let issued = issue(&state, &admin, &format!("did:example:lock-{i}"), "session").await;
        // Unknown token: the same refusal as a wrong code.
        let reply = redeem_start(
            &state,
            via,
            &invitee,
            "inv_not-a-real-token-at-all",
            &issued.code,
        )
        .await;
        assert_eq!(
            code(&reply),
            "auth/passkey/enroll/redeem/start:inviteInvalid",
            "{via:?} {reply}"
        );
        for n in 1..invite::MAX_WRONG_CODES {
            let reply = redeem_start(&state, via, &invitee, &issued.token, "0000-0000-0000").await;
            assert_eq!(
                code(&reply),
                "auth/passkey/enroll/redeem/start:inviteInvalid",
                "{via:?} wrong code {n}: {reply}"
            );
        }
        let reply = redeem_start(&state, via, &invitee, &issued.token, "0000-0000-0000").await;
        assert_eq!(
            code(&reply),
            "auth/passkey/enroll/redeem/start:tooManyAttempts",
            "{via:?} {reply}"
        );
        // Invalidated: the right code no longer redeems it.
        let reply = redeem_start(&state, via, &invitee, &issued.token, &issued.code).await;
        assert_eq!(
            code(&reply),
            "auth/passkey/enroll/redeem/start:inviteInvalid",
            "{via:?} {reply}"
        );
    }
}

/// A messaging-transport source is rate-limited on redemption attempts.
#[tokio::test]
async fn redemption_is_rate_limited_per_source() {
    let (state, _dir) = state().await;
    let invitee = stranger(30);
    let mut last = Value::Null;
    for _ in 0..=crate::rate_limit::REDEEM_MAX_PER_WINDOW {
        last = redeem_start(
            &state,
            Via::Tsp,
            &invitee,
            "inv_not-a-real-token-at-all",
            "0000-0000-0000",
        )
        .await;
    }
    assert_eq!(code(&last), "unavailable", "{last}");
}

/// A session invite, redeemed on each transport: the credential is bound, the
/// ACL entry the invite names is created, the new passkey signs its subject in
/// — and the invite and the ceremony are each spent.
#[tokio::test]
async fn a_session_invite_redeems_once_on_every_transport() {
    let (state, _dir) = state().await;
    let admin = member(&state, 3, Role::Admin).await;
    for (i, via) in VIAS.into_iter().enumerate() {
        let subject = format!("did:example:session-{i}");
        let invitee = stranger(40 + i as u8);
        let issued = issue(&state, &admin, &subject, "session").await;

        let reply = redeem_start(&state, via, &invitee, &issued.token, &issued.code).await;
        conforms(&reply);
        let start = ok(&reply, &t(REDEEM_START));
        assert_eq!(start["subject"], subject.as_str());
        assert_eq!(start["purpose"], "session");
        assert!(
            start.get("uvOptions").is_none(),
            "a first passkey has nothing to verify with"
        );
        let mut passkey = SoftPasskey::new();
        let finish = json!({
            "enrollmentId": start["enrollmentId"],
            "credential": passkey.attest(&start["options"]),
            "deviceLabel": "Carol's laptop",
        });
        let reply = unsigned(&state, via, &invitee, REDEEM_FINISH, finish.clone()).await;
        conforms(&reply);
        let body = ok(&reply, &t(REDEEM_FINISH));
        assert_eq!(body["credentialId"], passkey.id());
        assert_eq!(body["deviceLabel"], "Carol's laptop");
        assert_eq!(
            get_acl_entry(&state.acl_ks, &subject)
                .await
                .unwrap()
                .unwrap()
                .role,
            Role::Owner
        );

        // Replayed finish: the ceremony is spent.
        let reply = unsigned(&state, via, &invitee, REDEEM_FINISH, finish).await;
        assert_eq!(
            code(&reply),
            "auth/passkey/enroll/redeem/finish:enrollmentNotFound",
            "{reply}"
        );
        // Single use: the invite is spent.
        let reply = redeem_start(&state, via, &invitee, &issued.token, &issued.code).await;
        assert_eq!(
            code(&reply),
            "auth/passkey/enroll/redeem/start:inviteInvalid",
            "{reply}"
        );

        // The passkey is a login credential.
        let reply = login(&state, via, &mut passkey, 50 + i as u8).await;
        let body = ok(&reply, &t(LOGIN_FINISH));
        assert_eq!(body["session"]["subject"], subject.as_str(), "{reply}");
    }
}

/// An expired invite redeems nothing, nor does a ceremony past its expiry,
/// nor one a newer start has superseded.
#[tokio::test]
async fn expired_invites_and_ceremonies_redeem_nothing() {
    let (state, _dir) = state().await;
    let admin = member(&state, 4, Role::Admin).await;
    let invitee = stranger(60);

    let issued = issue(&state, &admin, "did:example:late", "session").await;
    let hash = invite::hash_token(&issued.token);
    let mut stored = invite::by_token_hash(&state.sessions_ks, &hash)
        .await
        .unwrap()
        .unwrap();
    stored.expires_at = 1;
    invite::save(&state.sessions_ks, &stored).await.unwrap();
    let reply = redeem_start(&state, Via::Https, &invitee, &issued.token, &issued.code).await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/redeem/start:inviteInvalid",
        "{reply}"
    );

    // A ceremony past its expiry.
    let issued = issue(&state, &admin, "did:example:slow", "session").await;
    let start = ok(
        &redeem_start(&state, Via::Https, &invitee, &issued.token, &issued.code).await,
        &t(REDEEM_START),
    );
    let id = start["enrollmentId"].as_str().unwrap();
    let mut ceremony = pk::take_ceremony(&state.sessions_ks, id)
        .await
        .unwrap()
        .unwrap();
    ceremony.expires_at = 1;
    pk::store_ceremony(&state.sessions_ks, &ceremony)
        .await
        .unwrap();
    let mut passkey = SoftPasskey::new();
    let reply = unsigned(
        &state,
        Via::Https,
        &invitee,
        REDEEM_FINISH,
        json!({ "enrollmentId": id, "credential": passkey.attest(&start["options"]) }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/redeem/finish:enrollmentExpired",
        "{reply}"
    );

    // Superseded: a newer start on the same invite retires the older one.
    let older = ok(
        &redeem_start(&state, Via::Https, &invitee, &issued.token, &issued.code).await,
        &t(REDEEM_START),
    );
    let newer = ok(
        &redeem_start(&state, Via::Https, &invitee, &issued.token, &issued.code).await,
        &t(REDEEM_START),
    );
    let reply = unsigned(
        &state,
        Via::Https,
        &invitee,
        REDEEM_FINISH,
        json!({ "enrollmentId": older["enrollmentId"], "credential": passkey.attest(&older["options"]) }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/redeem/finish:enrollmentNotFound",
        "{reply}"
    );
    let reply = unsigned(
        &state,
        Via::Https,
        &invitee,
        REDEEM_FINISH,
        json!({ "enrollmentId": newer["enrollmentId"], "credential": passkey.attest(&newer["options"]) }),
    )
    .await;
    ok(&reply, &t(REDEEM_FINISH));
}

/// A step-up credential is stored apart from login credentials: it never
/// signs anyone in, and a login credential never stands in for one.
#[tokio::test]
async fn step_up_and_login_credentials_are_kept_apart() {
    let (state, _dir) = state().await;
    let admin = member(&state, 5, Role::Admin).await;
    let dana = member(&state, 6, Role::Owner).await;
    let invitee = stranger(70);

    // Dana has a login passkey.
    let mut login_key = SoftPasskey::new();
    let issued = issue(&state, &admin, &dana.did, "session").await;
    ok(
        &redeem(&state, Via::Tsp, &invitee, &issued, &mut login_key, None).await,
        &t(REDEEM_FINISH),
    );

    // Her first step-up passkey: no user verification to give — the login
    // passkey is not a step-up credential.
    let mut step_up = SoftPasskey::new();
    let issued = issue(&state, &admin, &dana.did, "stepUp").await;
    assert_eq!(issued.body["purpose"], "stepUp");
    let start = ok(
        &redeem_start(&state, Via::Tsp, &invitee, &issued.token, &issued.code).await,
        &t(REDEEM_START),
    );
    assert_eq!(start["purpose"], "stepUp");
    assert!(start.get("uvOptions").is_none(), "{start}");
    let excluded = start["options"]["excludeCredentials"].to_string();
    assert!(
        !excluded.contains(&login_key.id()),
        "a login credential is not excluded from step-up"
    );
    let reply = unsigned(
        &state,
        Via::Tsp,
        &invitee,
        REDEEM_FINISH,
        json!({ "enrollmentId": start["enrollmentId"], "credential": step_up.attest(&start["options"]) }),
    )
    .await;
    assert_eq!(ok(&reply, &t(REDEEM_FINISH))["purpose"], "stepUp");

    // Stored in the step-up keyspace, and not in the login one.
    let hex_id = hex(&step_up.cred_id);
    let step_up_ks = state.store.keyspace(KS_PASSKEY_STEP_UP).unwrap();
    assert!(
        pk::get_passkey_user_by_cred(&step_up_ks, &hex_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        pk::get_passkey_user_by_cred(&state.sessions_ks, &hex_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        pk::get_passkey_user_by_cred(&step_up_ks, &hex(&login_key.cred_id))
            .await
            .unwrap()
            .is_none()
    );

    // The step-up passkey is never offered at login, and never accepted there.
    for (i, via) in VIAS.into_iter().enumerate() {
        let browser = stranger(80 + i as u8);
        let start = ok(
            &unsigned(&state, via, &browser, LOGIN_START, json!({})).await,
            &t(LOGIN_START),
        );
        assert!(
            !start["options"].to_string().contains(&step_up.id()),
            "{start}"
        );
        let reply = call(
            &state,
            via,
            &browser,
            &t(LOGIN_FINISH),
            json!({ "authId": start["authId"], "credential": step_up.assert(&start["options"]) }),
        )
        .await;
        assert!(
            code(&reply).starts_with("auth/passkey/login/finish:"),
            "{via:?} {reply}"
        );
        // Nor as a session step-up for its subject.
        let start = ok(
            &unsigned(
                &state,
                via,
                &browser,
                LOGIN_START,
                json!({ "purpose": "stepUp", "subject": dana.did }),
            )
            .await,
            &t(LOGIN_START),
        );
        assert!(
            !start["options"].to_string().contains(&step_up.id()),
            "{start}"
        );
    }

    // A second step-up passkey needs a user-verified assertion from the first,
    // and a login passkey's does not count.
    let issued = issue(&state, &admin, &dana.did, "stepUp").await;
    let start = ok(
        &redeem_start(&state, Via::Didcomm, &invitee, &issued.token, &issued.code).await,
        &t(REDEEM_START),
    );
    let allowed = start["uvOptions"]["allowCredentials"].to_string();
    assert!(
        allowed.contains(&step_up.id()) && !allowed.contains(&login_key.id()),
        "{start}"
    );
    let mut second = SoftPasskey::new();
    let reply = unsigned(
        &state,
        Via::Didcomm,
        &invitee,
        REDEEM_FINISH,
        json!({
            "enrollmentId": start["enrollmentId"],
            "credential": second.attest(&start["options"]),
            "uvCredential": login_key.assert(&start["uvOptions"]),
        }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/redeem/finish:userVerificationFailed",
        "{reply}"
    );
    // The invite survives a failed finish; a correct one binds.
    let reply = redeem(
        &state,
        Via::Didcomm,
        &invitee,
        &issued,
        &mut second,
        Some(&mut step_up),
    )
    .await;
    ok(&reply, &t(REDEEM_FINISH));
}

/// A subject adding a passkey to an account that has one must answer the
/// start's own user-verification challenge, with UV, from a passkey it
/// already holds — once.
#[tokio::test]
async fn user_verification_is_bound_to_its_ceremony_and_refused_on_replay() {
    let (state, _dir) = state().await;
    let admin = member(&state, 7, Role::Admin).await;
    let erin = stranger(90);
    let mut first = SoftPasskey::new();
    let issued = issue(&state, &admin, &erin.did, "session").await;
    ok(
        &redeem(&state, Via::Https, &erin, &issued, &mut first, None).await,
        &t(REDEEM_FINISH),
    );

    let start = |via| {
        let state = &state;
        let erin = &erin;
        async move {
            let reply = call(
                state,
                via,
                erin,
                &t(START),
                json!({ "deviceLabel": "phone" }),
            )
            .await;
            conforms(&reply);
            ok(&reply, &t(START))
        }
    };
    let finish = |via, payload: Value| {
        let state = &state;
        let erin = &erin;
        async move { call(state, via, erin, &t(FINISH), payload).await }
    };

    for via in VIAS {
        let s = start(via).await;
        assert!(
            s["uvOptions"].is_object(),
            "{via:?}: the subject has a passkey: {s}"
        );
        assert_ne!(s["uvOptions"]["challenge"], s["options"]["challenge"]);
        assert_eq!(s["uvOptions"]["userVerification"], "required");
        let mut new = SoftPasskey::new();

        // No assertion at all is a failure, never consent.
        let reply = finish(
            via,
            json!({ "enrollmentId": s["enrollmentId"], "credential": new.attest(&s["options"]) }),
        )
        .await;
        assert_eq!(code(&reply), "permissionDenied", "{via:?} {reply}");
        // ...and it spent the ceremony.
        let reply = finish(
            via,
            json!({ "enrollmentId": s["enrollmentId"], "credential": new.attest(&s["options"]) }),
        )
        .await;
        assert_eq!(
            code(&reply),
            "auth/passkey/enroll/finish:enrollmentNotFound",
            "{via:?} {reply}"
        );

        // An assertion over another ceremony's challenge.
        let a = start(via).await;
        let b = start(via).await;
        let reply = finish(
            via,
            json!({
                "enrollmentId": a["enrollmentId"],
                "credential": new.attest(&a["options"]),
                "uvCredential": first.assert(&b["uvOptions"]),
            }),
        )
        .await;
        assert_eq!(code(&reply), "permissionDenied", "{via:?} {reply}");
        // The registration challenge is not the user-verification one.
        let reply = finish(
            via,
            json!({
                "enrollmentId": b["enrollmentId"],
                "credential": new.attest(&b["options"]),
                "uvCredential": first.assert(&json!({ "challenge": b["options"]["challenge"], "rpId": "control.test" })),
            }),
        )
        .await;
        assert_eq!(code(&reply), "permissionDenied", "{via:?} {reply}");

        // Without the UV flag.
        let s = start(via).await;
        first.user_verified = false;
        let uv = first.assert(&s["uvOptions"]);
        first.user_verified = true;
        let reply = finish(
            via,
            json!({ "enrollmentId": s["enrollmentId"], "credential": new.attest(&s["options"]), "uvCredential": uv }),
        )
        .await;
        assert_eq!(code(&reply), "permissionDenied", "{via:?} {reply}");

        // Someone else finishing Erin's enrolment.
        let s = start(via).await;
        let mallory = member(&state, 91, Role::Owner).await;
        let reply = call(
            &state,
            via,
            &mallory,
            &t(FINISH),
            json!({
                "enrollmentId": s["enrollmentId"],
                "credential": new.attest(&s["options"]),
                "uvCredential": first.assert(&s["uvOptions"]),
            }),
        )
        .await;
        assert_eq!(
            code(&reply),
            "auth/passkey/enroll/finish:subjectMismatch",
            "{via:?} {reply}"
        );

        // Done right, it binds — once.
        let s = start(via).await;
        let payload = json!({
            "enrollmentId": s["enrollmentId"],
            "credential": new.attest(&s["options"]),
            "uvCredential": first.assert(&s["uvOptions"]),
        });
        let reply = finish(via, payload.clone()).await;
        conforms(&reply);
        let body = ok(&reply, &t(FINISH));
        assert_eq!(body["subject"], erin.did.as_str());
        assert_eq!(body["deviceLabel"], "phone");
        let reply = finish(via, payload).await;
        assert_eq!(
            code(&reply),
            "auth/passkey/enroll/finish:enrollmentNotFound",
            "{via:?} {reply}"
        );
    }
}

/// The invite's own refusals.
#[tokio::test]
async fn invites_are_refused_as_the_spec_says() {
    let (state, _dir) = state().await;
    let admin = member(&state, 8, Role::Admin).await;
    let owner = member(&state, 9, Role::Owner).await;
    let invitee = stranger(95);

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &t(INVITE),
        json!({ "subject": "did:example:x" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/invite:roleNotPermitted",
        "{reply}"
    );

    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t(INVITE),
        json!({ "subject": owner.did, "purpose": "stepUp", "role": "admin" }),
    )
    .await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");

    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t(INVITE),
        json!({ "subject": "did:example:nobody", "purpose": "stepUp" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/invite:subjectUnknown",
        "{reply}"
    );

    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t(INVITE),
        json!({ "subject": "did:example:x", "role": "emperor" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/invite:roleNotPermitted",
        "{reply}"
    );

    // A session invite for a subject who already has a login passkey.
    let issued = issue(&state, &admin, &owner.did, "session").await;
    ok(
        &redeem(
            &state,
            Via::Tsp,
            &invitee,
            &issued,
            &mut SoftPasskey::new(),
            None,
        )
        .await,
        &t(REDEEM_FINISH),
    );
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t(INVITE),
        json!({ "subject": owner.did }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/invite:subjectAlreadyEnrolled",
        "{reply}"
    );
}

/// Over HTTPS the source is the client IP, counted before dispatch, and the
/// refusal is a routed `unavailable` document with a retry time.
#[tokio::test]
async fn https_redemption_is_rate_limited_per_client_ip() {
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;

    let (state, _dir) = state().await;
    let addr: std::net::SocketAddr = "203.0.113.7:4000".parse().unwrap();
    let mut last = Value::Null;
    for _ in 0..=crate::rate_limit::REDEEM_MAX_PER_WINDOW {
        let mut doc = request(
            &t(REDEEM_START),
            "unused",
            json!({ "token": "inv_not-a-real-token-at-all", "claimCode": "0000-0000-0000" }),
        );
        doc.as_object_mut().unwrap().remove("issuer");
        let response = crate::routes::trust_tasks::trust_tasks_endpoint(
            None,
            axum::extract::State(state.clone()),
            Some(axum::Extension(axum::extract::ConnectInfo(addr))),
            axum::http::HeaderMap::new(),
            axum::body::Bytes::from(serde_json::to_vec(&doc).unwrap()),
        )
        .await
        .into_response();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        last = serde_json::from_slice(&bytes).unwrap();
    }
    assert_eq!(code(&last), "unavailable", "{last}");
    assert!(last["payload"]["retryAfter"].is_string(), "{last}");
}

/// A step-up approve-response's `webauthn` evidence is gated on the
/// subject's step-up-only store: offered only once one is enrolled, bound to
/// the ceremony's own challenge, refused without user verification, and
/// refused for a login passkey's assertion even though it's a real,
/// currently-valid credential for the same subject.
#[tokio::test]
async fn step_up_accepts_its_own_passkey_and_refuses_a_login_one() {
    let (state, _dir) = state().await;
    let admin = member(&state, 100, Role::Admin).await;
    let dana = member(&state, 101, Role::Owner).await;
    let invitee = stranger(102);

    // Dana has a login passkey but, so far, no step-up passkey.
    let mut login_key = SoftPasskey::new();
    let issued = issue(&state, &admin, &dana.did, "session").await;
    ok(
        &redeem(&state, Via::Https, &invitee, &issued, &mut login_key, None).await,
        &t(REDEEM_FINISH),
    );
    let tokens = session_for(&state, &dana).await;
    let session_id = tokens.session_id.clone();

    // No step-up passkey yet: didSigned only, no webauthn gate offered.
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(STEP_UP_START),
        json!({ "sessionId": session_id }),
    )
    .await;
    conforms(&reply);
    let request = ok(&reply, &t(STEP_UP_START))["approveRequest"].clone();
    assert_eq!(
        request["payload"]["acceptableEvidence"],
        json!(["didSigned"]),
        "{request}"
    );
    assert!(request["payload"].get("webauthn").is_none(), "{request}");

    // Give her a step-up passkey.
    let mut step_up = SoftPasskey::new();
    let issued = issue(&state, &admin, &dana.did, "stepUp").await;
    ok(
        &redeem(&state, Via::Https, &invitee, &issued, &mut step_up, None).await,
        &t(REDEEM_FINISH),
    );

    // Now the start offers a WebAuthn gate, bound to the ceremony's own
    // challenge — the same value, not merely an equal-looking one.
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(STEP_UP_START),
        json!({ "sessionId": session_id }),
    )
    .await;
    conforms(&reply);
    let request = ok(&reply, &t(STEP_UP_START))["approveRequest"].clone();
    assert_eq!(
        request["payload"]["acceptableEvidence"],
        json!(["didSigned", "webauthn"]),
        "{request}"
    );
    let challenge = request["payload"]["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let webauthn_options = request["payload"]["webauthn"].clone();
    assert_eq!(webauthn_options["challenge"], challenge, "{request}");

    // A login passkey's assertion over the same options: refused. It's a
    // real, currently-bound credential for this subject — just not one this
    // ceremony was opened for (the ceremony only knows the step-up store's
    // credentials).
    let bad = login_key.assert(&webauthn_options);
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(STEP_UP_APPROVE),
        json!({
            "challenge": challenge,
            "decision": "approved",
            "subject": dana.did,
            "sessionId": session_id,
            "evidence": { "kind": "webauthn", "assertion": bad },
        }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/step-up/approve-response:assertionInvalid",
        "{reply}"
    );

    // Single use: that refusal burned the challenge. A fresh start, and an
    // assertion with no user verification: also refused.
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(STEP_UP_START),
        json!({ "sessionId": session_id }),
    )
    .await;
    let request = ok(&reply, &t(STEP_UP_START))["approveRequest"].clone();
    let challenge = request["payload"]["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    step_up.user_verified = false;
    let no_uv = step_up.assert(&request["payload"]["webauthn"]);
    step_up.user_verified = true;
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(STEP_UP_APPROVE),
        json!({
            "challenge": challenge,
            "decision": "approved",
            "subject": dana.did,
            "sessionId": session_id,
            "evidence": { "kind": "webauthn", "assertion": no_uv },
        }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/step-up/approve-response:assertionInvalid",
        "{reply}"
    );

    // The subject's own step-up passkey, user-verified: accepted.
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(STEP_UP_START),
        json!({ "sessionId": session_id }),
    )
    .await;
    let request = ok(&reply, &t(STEP_UP_START))["approveRequest"].clone();
    let challenge = request["payload"]["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let good = step_up.assert(&request["payload"]["webauthn"]);
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(STEP_UP_APPROVE),
        json!({
            "challenge": challenge,
            "decision": "approved",
            "subject": dana.did,
            "sessionId": session_id,
            "evidence": { "kind": "webauthn", "assertion": good },
        }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &t(STEP_UP_APPROVE));
    assert_eq!(body["status"], "elevated", "{body}");
    assert_eq!(body["session"]["acr"], "aal2", "{body}");
    assert!(
        body["session"]["amr"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "passkey"),
        "{body}"
    );
}

/// `auth/passkey/list` answers only the caller's own credentials, of every
/// purpose; `auth/passkey/admin-list` answers one subject's credentials of
/// one purpose, and only to an administrator.
#[tokio::test]
async fn passkey_list_and_admin_list_answer_the_right_scope() {
    let (state, _dir) = state().await;
    let admin = member(&state, 110, Role::Admin).await;
    let dana = member(&state, 111, Role::Owner).await;
    let erin = member(&state, 112, Role::Owner).await;
    let invitee = stranger(113);

    let mut dana_login = SoftPasskey::new();
    let issued = issue(&state, &admin, &dana.did, "session").await;
    ok(
        &redeem(&state, Via::Https, &invitee, &issued, &mut dana_login, None).await,
        &t(REDEEM_FINISH),
    );
    let mut dana_step_up = SoftPasskey::new();
    let issued = issue(&state, &admin, &dana.did, "stepUp").await;
    ok(
        &redeem(
            &state,
            Via::Https,
            &invitee,
            &issued,
            &mut dana_step_up,
            None,
        )
        .await,
        &t(REDEEM_FINISH),
    );

    // Dana's own list sees both of hers; Erin, who has enrolled nothing,
    // sees none of Dana's.
    let reply = call(&state, Via::Https, &dana, &t(PK_LIST), json!({})).await;
    conforms(&reply);
    let body = ok(&reply, &t(PK_LIST));
    let creds = body["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 2, "{body}");
    assert!(
        creds
            .iter()
            .any(|c| c["credentialId"] == json!(dana_login.id()))
    );
    assert!(
        creds
            .iter()
            .any(|c| c["credentialId"] == json!(dana_step_up.id()))
    );

    let reply = call(&state, Via::Https, &erin, &t(PK_LIST), json!({})).await;
    conforms(&reply);
    let body = ok(&reply, &t(PK_LIST));
    assert!(body["credentials"].as_array().unwrap().is_empty(), "{body}");

    // Erin is not an administrator: she cannot read Dana's inventory.
    let reply = call(
        &state,
        Via::Https,
        &erin,
        &t(PK_ADMIN_LIST),
        json!({ "subject": dana.did, "purpose": "session" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/admin-list:notAdministrator",
        "{reply}"
    );

    // The administrator reads it, purpose by purpose.
    let reply = call(
        &state,
        Via::Https,
        &admin,
        &t(PK_ADMIN_LIST),
        json!({ "subject": dana.did, "purpose": "session" }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &t(PK_ADMIN_LIST));
    assert_eq!(body["purpose"], "session", "{body}");
    let creds = body["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1, "{body}");
    assert_eq!(creds[0]["credentialId"], json!(dana_login.id()));

    let reply = call(
        &state,
        Via::Https,
        &admin,
        &t(PK_ADMIN_LIST),
        json!({ "subject": dana.did, "purpose": "stepUp" }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &t(PK_ADMIN_LIST));
    let creds = body["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1, "{body}");
    assert_eq!(creds[0]["credentialId"], json!(dana_step_up.id()));

    // An unrecognised subject is refused.
    let reply = call(
        &state,
        Via::Https,
        &admin,
        &t(PK_ADMIN_LIST),
        json!({ "subject": "did:example:nobody", "purpose": "session" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/admin-list:subjectUnknown",
        "{reply}"
    );
}

/// Revoke authority: a subject revokes their own credential (re-authenticated
/// with their own login passkey); an administrator revokes another subject's
/// (re-authenticated with *their own* login passkey, never the target's); a
/// non-administrator asking for anyone else's is refused outright; and a
/// subject's last login passkey cannot be revoked this way.
#[tokio::test]
async fn revoke_authority_is_own_or_administrator_others_are_refused() {
    let (state, _dir) = state().await;
    let admin = member(&state, 120, Role::Admin).await;
    let dana = member(&state, 121, Role::Owner).await;
    let erin = member(&state, 122, Role::Owner).await;
    let invitee = stranger(123);

    // The administrator's own login passkey, for re-verifying presence when
    // revoking someone else's credential.
    let mut admin_login = SoftPasskey::new();
    let issued = issue(&state, &admin, &admin.did, "session").await;
    ok(
        &redeem(
            &state,
            Via::Https,
            &invitee,
            &issued,
            &mut admin_login,
            None,
        )
        .await,
        &t(REDEEM_FINISH),
    );

    let mut dana_login = SoftPasskey::new();
    let issued = issue(&state, &admin, &dana.did, "session").await;
    ok(
        &redeem(&state, Via::Https, &invitee, &issued, &mut dana_login, None).await,
        &t(REDEEM_FINISH),
    );
    let mut dana_step_up = SoftPasskey::new();
    let issued = issue(&state, &admin, &dana.did, "stepUp").await;
    ok(
        &redeem(
            &state,
            Via::Https,
            &invitee,
            &issued,
            &mut dana_step_up,
            None,
        )
        .await,
        &t(REDEEM_FINISH),
    );

    let mut erin_login = SoftPasskey::new();
    let issued = issue(&state, &admin, &erin.did, "session").await;
    ok(
        &redeem(&state, Via::Https, &invitee, &issued, &mut erin_login, None).await,
        &t(REDEEM_FINISH),
    );
    let mut erin_step_up = SoftPasskey::new();
    let issued = issue(&state, &admin, &erin.did, "stepUp").await;
    ok(
        &redeem(
            &state,
            Via::Https,
            &invitee,
            &issued,
            &mut erin_step_up,
            None,
        )
        .await,
        &t(REDEEM_FINISH),
    );

    // Erin is not an administrator: she cannot even start a revocation of
    // Dana's credential.
    let reply = call(
        &state,
        Via::Https,
        &erin,
        &t(PK_REVOKE_START),
        json!({ "credentialId": dana_step_up.id(), "subject": dana.did }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/revoke/start:notAuthorized",
        "{reply}"
    );

    // Dana revokes her own step-up passkey, re-authenticating with her own
    // login passkey.
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(PK_REVOKE_START),
        json!({ "credentialId": dana_step_up.id() }),
    )
    .await;
    conforms(&reply);
    let start = ok(&reply, &t(PK_REVOKE_START));
    let uv = dana_login.assert(&start["uvOptions"]);
    let reply = call(
        &state,
        Via::Https,
        &dana,
        &t(PK_REVOKE_FINISH),
        json!({ "revocationId": start["revocationId"], "uvCredential": uv }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &t(PK_REVOKE_FINISH));
    assert_eq!(body["credentialId"], json!(dana_step_up.id()));
    assert_eq!(body["purpose"], "stepUp", "{body}");
    assert_eq!(body["subject"], dana.did.as_str());
    assert_eq!(body["remaining"], 0, "{body}");
    let step_up_ks = state.store.keyspace(KS_PASSKEY_STEP_UP).unwrap();
    assert!(
        pk::get_passkey_user_by_cred(&step_up_ks, &hex(&dana_step_up.cred_id))
            .await
            .unwrap()
            .is_none()
    );

    // The administrator revokes Erin's step-up passkey, re-authenticating
    // with the administrator's own login passkey — not Erin's.
    let reply = call(
        &state,
        Via::Https,
        &admin,
        &t(PK_REVOKE_START),
        json!({ "credentialId": erin_step_up.id(), "subject": erin.did }),
    )
    .await;
    conforms(&reply);
    let start = ok(&reply, &t(PK_REVOKE_START));
    let uv = admin_login.assert(&start["uvOptions"]);
    let reply = call(
        &state,
        Via::Https,
        &admin,
        &t(PK_REVOKE_FINISH),
        json!({ "revocationId": start["revocationId"], "uvCredential": uv }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &t(PK_REVOKE_FINISH));
    assert_eq!(body["subject"], erin.did.as_str());
    assert_eq!(body["purpose"], "stepUp", "{body}");

    // Erin's login passkey is her last: revoking it is refused, even for an
    // administrator.
    let reply = call(
        &state,
        Via::Https,
        &admin,
        &t(PK_REVOKE_START),
        json!({ "credentialId": erin_login.id(), "subject": erin.did }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/revoke/start:lastCredential",
        "{reply}"
    );
}

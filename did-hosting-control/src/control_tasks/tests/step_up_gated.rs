//! Destructive tasks from a console session need it stepped up.

use super::*;

/// A bearer session for `caller` at assurance level `acr`.
fn session(caller: &Caller, acr: &str) -> crate::auth::AuthClaims {
    crate::auth::AuthClaims {
        did: caller.did.clone(),
        role: caller.role.clone(),
        session_id: "console".into(),
        session_pubkey_b58btc: None,
        amr: vec!["did".into()],
        acr: acr.into(),
    }
}

/// Whether `reply` is the refusal the console answers by stepping its
/// session up: `permissionDenied` with the `step_up_required` message.
fn asks_for_step_up(reply: &Value) -> bool {
    reply["type"]
        .as_str()
        .is_some_and(|t| t.starts_with("https://trusttasks.org/spec/trust-task-error/"))
        && reply["payload"]["code"] == "permissionDenied"
        && reply["payload"]["message"] == "step_up_required"
}

/// Send `payload` as `type_uri` from `caller` over HTTPS, presenting a
/// session at `acr` (or none).
async fn send_with(
    state: &AppState,
    caller: &Caller,
    acr: Option<&str>,
    type_uri: &str,
    payload: Value,
) -> Value {
    let doc = signed(request(type_uri, &caller.did, payload), &caller.key).await;
    https(state, acr.map(|acr| session(caller, acr)), doc).await
}

#[tokio::test]
async fn did_delete_needs_a_stepped_up_session() {
    let (state, _dir) = state().await;
    let owner = member(&state, 71, Role::Owner).await;
    for mnemonic in ["gated-one", "gated-two", "gated-three", "gated-four"] {
        seed_did(&state, &owner.did, mnemonic).await;
    }
    let payload = |m: &str| json!({ "mnemonic": m });

    let reply = send_with(&state, &owner, Some("aal1"), DELETE, payload("gated-one")).await;
    assert!(asks_for_step_up(&reply), "{reply}");
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("gated-one"))
            .await
            .unwrap()
            .is_some(),
        "a refused delete leaves the record in place"
    );

    let reply = send_with(&state, &owner, Some("aal2"), DELETE, payload("gated-one")).await;
    assert_eq!(ok(&reply, DELETE)["record"]["mnemonic"], "gated-one");

    // A caller with no session: its own proof is the authority, as before.
    let reply = send_with(&state, &owner, None, DELETE, payload("gated-two")).await;
    assert_eq!(ok(&reply, DELETE)["record"]["mnemonic"], "gated-two");
    for via in [Via::Tsp, Via::Didcomm] {
        let m = if matches!(via, Via::Tsp) {
            "gated-three"
        } else {
            "gated-four"
        };
        let reply = call(&state, via, &owner, DELETE, payload(m)).await;
        assert_eq!(ok(&reply, DELETE)["record"]["mnemonic"], m);
    }
}

#[tokio::test]
async fn identity_retire_needs_a_stepped_up_session() {
    let (state, _dir) = state().await;
    let admin = member(&state, 72, Role::Admin).await;
    let uri = t("did-management/identity/retire/0.1");
    let current = state.identity.as_ref().unwrap().generations()[0].id;
    let payload = json!({ "generationId": current + 100 });

    let reply = send_with(&state, &admin, Some("aal1"), &uri, payload.clone()).await;
    assert!(asks_for_step_up(&reply), "{reply}");

    // Past the session check, the task's own rules answer.
    for acr in [Some("aal2"), None] {
        let reply = send_with(&state, &admin, acr, &uri, payload.clone()).await;
        assert_eq!(
            code(&reply),
            "did-management/identity/retire:notFound",
            "{acr:?}: {reply}"
        );
    }
    let reply = call(&state, Via::Tsp, &admin, &uri, payload).await;
    assert_eq!(code(&reply), "did-management/identity/retire:notFound");
}

#[tokio::test]
async fn registry_purge_domain_needs_a_stepped_up_session() {
    let (state, _dir) = state().await;
    let admin = member(&state, 73, Role::Admin).await;
    let uri = t("did-management/registry/purge-domain/0.1");
    let payload = json!({ "instanceId": "no-such-edge", "domain": "example.com" });

    let reply = send_with(&state, &admin, Some("aal1"), &uri, payload.clone()).await;
    assert!(asks_for_step_up(&reply), "{reply}");

    for acr in [Some("aal2"), None] {
        let reply = send_with(&state, &admin, acr, &uri, payload.clone()).await;
        assert_eq!(
            code(&reply),
            "did-management/registry/purge-domain:notFound",
            "{acr:?}: {reply}"
        );
    }
    let reply = call(&state, Via::Tsp, &admin, &uri, payload).await;
    assert_eq!(
        code(&reply),
        "did-management/registry/purge-domain:notFound"
    );
}

/// A session for one DID lends no assurance to a request another signs.
#[test]
fn a_session_counts_only_for_its_own_subject() {
    use super::super::session_needs_step_up;
    let caller = stranger(74);
    let mut bearer = session(&caller, "aal2");
    assert!(!session_needs_step_up(None, &caller.did));
    assert!(!session_needs_step_up(Some(&bearer), &caller.did));
    bearer.acr = "aal1".into();
    assert!(session_needs_step_up(Some(&bearer), &caller.did));
    bearer.acr = "aal2".into();
    bearer.did = "did:example:someone-else".into();
    assert!(session_needs_step_up(Some(&bearer), &caller.did));
}

fn grant(subject: &str, role: &str) -> Value {
    json!({
        "entry": {
            "subject": subject,
            "role": role,
            "act": { "scope": "all" },
            "keys": { "scope": "none" },
            "capabilities": { "scope": "ceiling" }
        }
    })
}

#[tokio::test]
async fn granting_an_admin_needs_a_stepped_up_session() {
    let (state, _dir) = state().await;
    let admin = member(&state, 75, Role::Admin).await;
    let uri = t("acl/grant/0.2");

    let reply = send_with(
        &state,
        &admin,
        Some("aal1"),
        &uri,
        grant("did:example:new-admin-1", "admin"),
    )
    .await;
    assert!(asks_for_step_up(&reply), "{reply}");
    assert!(
        did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, "did:example:new-admin-1")
            .await
            .unwrap()
            .is_none(),
        "a refused grant writes nothing"
    );
    let reply = send_with(
        &state,
        &admin,
        Some("aal1"),
        &uri,
        grant("did:example:new-service", "service"),
    )
    .await;
    assert!(asks_for_step_up(&reply), "{reply}");

    let reply = send_with(
        &state,
        &admin,
        Some("aal2"),
        &uri,
        grant("did:example:new-admin-1", "admin"),
    )
    .await;
    assert_eq!(ok(&reply, &uri)["entry"]["role"], "admin", "{reply}");

    // No session: the document's own proof authorises it, as before.
    let reply = send_with(
        &state,
        &admin,
        None,
        &uri,
        grant("did:example:new-admin-2", "admin"),
    )
    .await;
    assert_eq!(ok(&reply, &uri)["entry"]["role"], "admin", "{reply}");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &uri,
        grant("did:example:new-admin-3", "admin"),
    )
    .await;
    assert_eq!(ok(&reply, &uri)["entry"]["role"], "admin", "{reply}");

    // A grant that confers no cross-domain role is unchanged.
    let reply = send_with(
        &state,
        &admin,
        Some("aal1"),
        &uri,
        grant("did:example:new-owner", "owner"),
    )
    .await;
    assert_eq!(ok(&reply, &uri)["entry"]["role"], "owner", "{reply}");
}

#[tokio::test]
async fn changing_a_role_to_admin_needs_a_stepped_up_session() {
    let (state, _dir) = state().await;
    let admin = member(&state, 76, Role::Admin).await;
    let owner = member(&state, 77, Role::Owner).await;
    let uri = t("acl/change-role/0.2");
    let payload =
        |from: &str, to: &str| json!({ "subject": owner.did, "fromRole": from, "toRole": to });

    let reply = send_with(
        &state,
        &admin,
        Some("aal1"),
        &uri,
        payload("owner", "admin"),
    )
    .await;
    assert!(asks_for_step_up(&reply), "{reply}");
    assert_eq!(
        did_hosting_common::server::acl::check_acl(&state.acl_ks, &owner.did)
            .await
            .unwrap(),
        Role::Owner
    );

    let reply = send_with(
        &state,
        &admin,
        Some("aal2"),
        &uri,
        payload("owner", "admin"),
    )
    .await;
    assert_eq!(ok(&reply, &uri)["entry"]["role"], "admin", "{reply}");

    // Moving away from a privileged role is not gated.
    let reply = send_with(
        &state,
        &admin,
        Some("aal1"),
        &uri,
        payload("admin", "owner"),
    )
    .await;
    assert_eq!(ok(&reply, &uri)["entry"]["role"], "owner", "{reply}");
}

/// Anyone but an administrator gets the task's own refusal, not a step-up
/// that could not help.
#[tokio::test]
async fn a_non_administrator_is_refused_without_a_step_up() {
    let (state, _dir) = state().await;
    let owner = member(&state, 78, Role::Owner).await;
    let reply = send_with(
        &state,
        &owner,
        Some("aal1"),
        &t("acl/grant/0.2"),
        grant("did:example:hopeful", "admin"),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied", "{reply}");
    assert!(!asks_for_step_up(&reply), "{reply}");
}

//! The rest of the control plane end to end: slots, domains, fleet, service
//! and auth rows.

use super::*;

// ---------------------------------------------------------------------------
// The rest of the control plane: slots, domains, fleet, service, auth
// ---------------------------------------------------------------------------

pub(super) const SPEC: &str = "https://trusttasks.org/spec/";

pub(super) fn t(slug: &str) -> String {
    format!("{SPEC}{slug}")
}

/// Step-up end to end: start answers a signed approve-request 0.3 bound to the
/// session; the subject's assertionMethod-signed approve-response elevates the
/// session; auth/refresh then mints tokens at the session's new level.
#[tokio::test]
async fn step_up_elevates_the_session_and_refresh_reads_the_new_level() {
    let (state, _dir) = state().await;
    let owner = member(&state, 40, Role::Owner).await;
    let tokens = session_for(&state, &owner).await;

    let reply = call(
        &state,
        Via::Didcomm,
        &owner,
        &t("auth/step-up/start/0.2"),
        json!({ "sessionId": tokens.session_id }),
    )
    .await;
    conforms(&reply);
    let request = ok(&reply, &t("auth/step-up/start/0.2"))["approveRequest"].clone();
    assert_eq!(request["type"], t("auth/step-up/approve-request/0.5"));
    assert_eq!(request["issuer"], CONTROL);
    assert_eq!(request["recipient"], owner.did.as_str());
    assert_eq!(request["payload"]["sessionId"], tokens.session_id.as_str());
    assert_eq!(request["proof"]["proofPurpose"], "authentication");
    let challenge = request["payload"]["challenge"]
        .as_str()
        .unwrap()
        .to_string();

    // An operational (authentication) proof is not a decision.
    let decision = json!({
        "challenge": challenge,
        "decision": "approved",
        "subject": owner.did,
        "sessionId": tokens.session_id,
    });
    let wrong = signed(
        request_doc(
            &t("auth/step-up/approve-response/0.7"),
            &owner.did,
            decision.clone(),
        ),
        &owner.key,
    )
    .await;
    assert_eq!(
        code(&send(&state, Via::Https, &owner, wrong).await),
        "proofInvalid"
    );

    let reply = call(
        &state,
        Via::Https,
        &owner,
        &t("auth/step-up/approve-response/0.7"),
        decision.clone(),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &t("auth/step-up/approve-response/0.7"));
    assert_eq!(body["status"], "elevated");
    assert_eq!(body["session"]["acr"], "aal2");

    // The challenge is single use.
    let reply = call(
        &state,
        Via::Https,
        &owner,
        &t("auth/step-up/approve-response/0.7"),
        decision,
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/step-up/approve-response:challengeUnknown",
        "{reply}"
    );

    // Refresh re-reads the session's level.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &t("auth/refresh/0.2"),
        json!({ "refreshToken": tokens.refresh_token }),
    )
    .await;
    let body = ok(&reply, &t("auth/refresh/0.2"));
    assert_eq!(body["session"]["acr"], "aal2", "{body}");
    let access = body["tokens"]["accessToken"].as_str().unwrap();
    let claims = state.jwt_keys.as_deref().unwrap().decode(access).unwrap();
    assert_eq!(claims.acr, "aal2");

    // An elevated session needs no further step-up.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &t("auth/step-up/start/0.2"),
        json!({ "sessionId": tokens.session_id }),
    )
    .await;
    assert_eq!(code(&reply), "auth/step-up/start:notNeeded", "{reply}");
}

/// `approverSigned` evidence (approve-response 0.6) is never offered — this
/// service keeps no step-up approvers — so it is refused `noGate` before the
/// pending step-up is looked up, and the same challenge still completes.
#[tokio::test]
async fn approver_signed_evidence_is_refused_without_spending_the_step_up() {
    let (state, _dir) = state().await;
    let owner = member(&state, 43, Role::Owner).await;
    let tokens = session_for(&state, &owner).await;

    let reply = call(
        &state,
        Via::Https,
        &owner,
        &t("auth/step-up/start/0.2"),
        json!({ "sessionId": tokens.session_id }),
    )
    .await;
    let request = ok(&reply, &t("auth/step-up/start/0.2"))["approveRequest"].clone();
    assert_eq!(request["type"], t("auth/step-up/approve-request/0.5"));
    assert_eq!(
        request["payload"]["accepts"],
        json!(["didSigned"]),
        "{request}"
    );
    let challenge = request["payload"]["challenge"].clone();
    let decision = json!({
        "challenge": challenge,
        "decision": "approved",
        "subject": owner.did,
        "sessionId": tokens.session_id,
    });

    let mut approver_signed = decision.clone();
    approver_signed["evidence"] = json!({
        "kind": "approverSigned",
        "statement": { "type": "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1" },
    });
    let reply = call(
        &state,
        Via::Https,
        &owner,
        &t("auth/step-up/approve-response/0.7"),
        approver_signed,
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/step-up/approve-response:noGate",
        "{reply}"
    );

    let reply = call(
        &state,
        Via::Https,
        &owner,
        &t("auth/step-up/approve-response/0.7"),
        decision,
    )
    .await;
    let body = ok(&reply, &t("auth/step-up/approve-response/0.7"));
    assert_eq!(body["status"], "elevated", "{body}");
}

/// Nobody can open a step-up against a session that is not theirs.
#[tokio::test]
async fn step_up_start_answers_someone_elses_session_as_unknown() {
    let (state, _dir) = state().await;
    let owner = member(&state, 41, Role::Owner).await;
    let other = member(&state, 42, Role::Owner).await;
    let tokens = session_for(&state, &owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &other,
        &t("auth/step-up/start/0.2"),
        json!({ "sessionId": tokens.session_id }),
    )
    .await;
    assert_eq!(code(&reply), "auth/step-up/start:sessionUnknown", "{reply}");
}

/// An unsigned request document from `issuer`, for tests that sign it
/// themselves.
pub(super) fn request_doc(type_uri: &str, issuer: &str, payload: Value) -> Value {
    request(type_uri, issuer, payload)
}

/// `server/info` is the public read: sent with no proof and no issuer, over
/// HTTPS with no session, it is answered — signed by the DID it names, with no
/// recipient.
#[tokio::test]
async fn server_info_answers_an_anonymous_request_signed_by_the_service() {
    let (state, _dir) = state().await;
    let uri = t("did-management/server/info/0.1");
    let mut doc = request(&uri, "unused", json!({}));
    doc.as_object_mut().unwrap().remove("issuer");
    let reply = https(&state, None, doc).await;
    conforms(&reply);
    let body = ok(&reply, &uri);
    assert_eq!(body["serviceDid"], CONTROL);
    assert_eq!(reply["issuer"], CONTROL);
    assert!(reply.get("recipient").is_none(), "{reply}");
    assert!(reply["proof"].is_object());
}

/// Passkey login opens unsigned, and the ceremony it opens is the same
/// whether or not any passkey is registered: no credential list, no
/// `noCredentials`.
#[tokio::test]
async fn passkey_login_start_is_open_to_an_unsigned_request() {
    let (state, _dir) = state().await;
    let uri = t("auth/passkey/login/start/0.2");
    let mut doc = request(&uri, "unused", json!({}));
    doc.as_object_mut().unwrap().remove("issuer");
    let reply = https(&state, None, doc).await;
    conforms(&reply);
    let body = ok(&reply, &uri);
    assert!(body["authId"].is_string(), "{body}");
    assert!(body["options"]["challenge"].is_string(), "{body}");
    assert!(body["options"].get("allowCredentials").is_none(), "{body}");
}

/// Invites are addressed by inviteId, and no read sends a token back.
#[tokio::test]
async fn invites_are_managed_by_invite_id_and_never_disclose_a_token() {
    let (state, _dir) = state().await;
    let admin = member(&state, 43, Role::Admin).await;
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/0.3"),
        json!({ "subject": "did:example:invitee" }),
    )
    .await;
    let issued = ok(&reply, &t("auth/passkey/enroll/invite/0.3"));
    let token = issued["invite"]["token"].as_str().unwrap().to_string();
    let listed = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/list/0.1"),
        json!({}),
    )
    .await;
    let invite_id =
        ok(&listed, &t("auth/passkey/enroll/invite/list/0.1"))["invites"][0]["inviteId"]
            .as_str()
            .unwrap()
            .to_string();
    struct Created {
        token: String,
        invite_id: String,
    }
    let created = Created { token, invite_id };

    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/list/0.1"),
        json!({}),
    )
    .await;
    conforms(&reply);
    let text = reply.to_string();
    assert!(
        !text.contains(&created.token),
        "a list must not carry the token"
    );
    let body = ok(&reply, &t("auth/passkey/enroll/invite/list/0.1"));
    assert_eq!(body["invites"][0]["inviteId"], created.invite_id.as_str());
    assert_eq!(body["invites"][0]["subject"], "did:example:invitee");

    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/update/0.1"),
        json!({ "inviteId": created.invite_id, "role": "admin" }),
    )
    .await;
    conforms(&reply);
    assert!(!reply.to_string().contains(&created.token));
    assert_eq!(
        ok(&reply, &t("auth/passkey/enroll/invite/update/0.1"))["invite"]["role"],
        "admin"
    );

    let later = (chrono::Utc::now() + chrono::Duration::hours(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    // A role change may ride alongside an expiry change — the spec's `oneOf`
    // only pits `expiresAt` against `extendBy`, not either against `role`.
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/update/0.1"),
        json!({ "inviteId": created.invite_id, "role": "owner", "expiresAt": later }),
    )
    .await;
    conforms(&reply);
    assert_eq!(
        ok(&reply, &t("auth/passkey/enroll/invite/update/0.1"))["invite"]["role"],
        "owner"
    );

    // Nothing to change is not an update.
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/update/0.1"),
        json!({ "inviteId": created.invite_id }),
    )
    .await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");

    // `expiresAt` and `extendBy` are mutually exclusive — and a refused
    // update changes nothing, not even the role riding along with it.
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/update/0.1"),
        json!({ "inviteId": created.invite_id, "role": "admin", "expiresAt": later, "extendBy": 60 }),
    )
    .await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/list/0.1"),
        json!({}),
    )
    .await;
    let body = ok(&reply, &t("auth/passkey/enroll/invite/list/0.1"));
    assert_eq!(body["invites"][0]["role"], "owner", "{reply}");
    assert_eq!(body["invites"][0]["expiresAt"], later, "{reply}");

    // Never past the longest invite this service would issue.
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/update/0.1"),
        json!({ "inviteId": created.invite_id, "expiresAt": "2099-01-01T00:00:00Z" }),
    )
    .await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");

    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/revoke/0.1"),
        json!({ "inviteId": created.invite_id }),
    )
    .await;
    conforms(&reply);
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/revoke/0.1"),
        json!({ "inviteId": created.invite_id }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/invite/revoke:notFound",
        "{reply}"
    );

    // Administrators only.
    let owner = member(&state, 44, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &t("auth/passkey/enroll/invite/list/0.1"),
        json!({}),
    )
    .await;
    assert_eq!(
        code(&reply),
        "auth/passkey/enroll/invite/list:notAdministrator",
        "{reply}"
    );
}

/// A suspended slot's state is what the edges are sent.
#[tokio::test]
async fn set_state_suspends_a_slot_and_queues_the_state_to_edges() {
    let (state, _dir) = state().await;
    let owner = member(&state, 45, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha").await;
    let uri = t("did-management/did/set-state/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &uri,
        json!({ "mnemonic": "alpha", "state": "suspended" }),
    )
    .await;
    conforms(&reply);
    assert_eq!(ok(&reply, &uri)["record"]["disabled"], true);
    let record: DidRecord = state.dids_ks.get(did_key("alpha")).await.unwrap().unwrap();
    assert!(record.disabled);
    let body = crate::server_push::sync_update_body(&record, "{}".into(), None).unwrap();
    assert_eq!(body["disabled"], true);
}

#[tokio::test]
async fn rollback_and_log_follow_the_slots_history() {
    let (state, _dir) = state().await;
    let owner = member(&state, 46, Role::Owner).await;
    seed_published(&state, &owner.did, "alpha").await;

    let log = t("did-management/did/log/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &log,
        json!({ "mnemonic": "alpha", "raw": true }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &log);
    assert_eq!(body["entries"].as_array().unwrap().len(), 2);
    assert!(body["logContent"].as_str().unwrap().contains("2-b"));

    let rollback = t("did-management/did/rollback/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &rollback,
        json!({ "mnemonic": "alpha", "targetVersion": 5 }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/did/rollback:invalidTargetVersion",
        "{reply}"
    );
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &rollback,
        json!({ "mnemonic": "alpha", "targetVersion": 1 }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &rollback);
    assert_eq!(body["removedVersions"], 1);
    assert_eq!(body["record"]["versionCount"], 1);

    // Someone else's slot is answered exactly as a missing one.
    let other = member(&state, 47, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &other,
        &log,
        json!({ "mnemonic": "alpha" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management/did/log:notFound");
    let reply = call(
        &state,
        Via::Tsp,
        &other,
        &log,
        json!({ "mnemonic": "nothing" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management/did/log:notFound");
}

/// Resolve answers only for DIDs the caller may read.
#[tokio::test]
async fn agent_name_resolve_does_not_disclose_other_owners_dids() {
    let (state, _dir) = state().await;
    let owner = member(&state, 48, Role::Owner).await;
    let other = member(&state, 49, Role::Owner).await;
    let mut record = seed_did(&state, &owner.did, "alpha").await;
    record.agent_names = vec![AgentNameEntry {
        name: "alice".into(),
        enabled: true,
        created_at: 1,
    }];
    state
        .dids_ks
        .insert(did_key("alpha"), &record)
        .await
        .unwrap();
    let did = record.did_id.clone().unwrap();
    let uri = t("did-management/agent-name/resolve/0.1");

    let body = ok(
        &call(&state, Via::Tsp, &owner, &uri, json!({ "dids": [did] })).await,
        &uri,
    );
    assert_eq!(body["entries"][0]["names"], json!(["alice"]));
    let body = ok(
        &call(&state, Via::Tsp, &other, &uri, json!({ "dids": [did] })).await,
        &uri,
    );
    assert_eq!(body["entries"], json!([]));
}

/// Domains, end to end; purging needs a stepped-up session. Each change
/// reports `CacheChange::Domains` (the daemon's resolution gate drops its
/// copy of the domains on it).
#[tokio::test]
async fn domains_are_administered_over_trust_tasks() {
    let (mut state, _dir) = state().await;
    let changes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = changes.clone();
    state.cache_invalidate = Some(std::sync::Arc::new(move |change| {
        if change == crate::server::CacheChange::Domains {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }));
    let changes = move || changes.load(std::sync::atomic::Ordering::SeqCst);
    let admin = member(&state, 50, Role::Admin).await;
    let create = t("did-management/domain/create/0.1");
    for name in ["a.example.com", "b.example.com"] {
        let reply = call(
            &state,
            Via::Tsp,
            &admin,
            &create,
            json!({ "name": name, "setAsDefault": name == "a.example.com", "label": "A" }),
        )
        .await;
        conforms(&reply);
    }
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &create,
        json!({ "name": "a.example.com", "setAsDefault": false }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/domain/create:domainExists",
        "{reply}"
    );
    assert_eq!(changes(), 2, "one per domain created");

    let list = t("did-management/domain/list/0.1");
    let reply = call(&state, Via::Tsp, &admin, &list, json!({})).await;
    conforms(&reply);
    let body = ok(&reply, &list);
    assert_eq!(body["default"], "a.example.com");
    assert_eq!(body["domains"].as_array().unwrap().len(), 2);

    let update = t("did-management/domain/update/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &update,
        json!({ "name": "b.example.com", "label": "B" }),
    )
    .await;
    conforms(&reply);

    let set_state = t("did-management/domain/set-state/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &set_state,
        json!({ "name": "a.example.com", "state": "disabled" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/domain/set-state:isDefault",
        "{reply}"
    );
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &set_state,
        json!({ "name": "b.example.com", "state": "disabled" }),
    )
    .await;
    conforms(&reply);
    assert_eq!(ok(&reply, &set_state)["entry"]["status"], "disabled");
    assert_eq!(changes(), 4, "updating, then disabling, a domain");

    let set_default = t("did-management/domain/set-default/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &set_default,
        json!({ "name": "b.example.com" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/domain/set-default:domainDisabled",
        "{reply}"
    );

    let purge = t("did-management/domain/purge/0.1");
    let payload = json!({ "name": "b.example.com", "purgeServers": false });
    let reply = call(&state, Via::Tsp, &admin, &purge, payload.clone()).await;
    assert_eq!(
        code(&reply),
        "permissionDenied",
        "a base session cannot purge: {reply}"
    );

    let bearer = crate::auth::AuthClaims {
        did: admin.did.clone(),
        role: Role::Admin,
        session_id: "s".into(),
        session_pubkey_b58btc: None,
        amr: vec!["did".into()],
        acr: "aal2".into(),
    };
    let doc = signed(request(&purge, &admin.did, payload), &admin.key).await;
    let reply = https(&state, Some(bearer), doc).await;
    conforms(&reply);
    assert_eq!(ok(&reply, &purge)["name"], "b.example.com");
    assert_eq!(changes(), 5, "purging a domain");

    // Owners do not administer domains.
    let owner = member(&state, 51, Role::Owner).await;
    let reply = call(&state, Via::Tsp, &owner, &list, json!({})).await;
    assert_eq!(code(&reply), "permissionDenied");
}

#[tokio::test]
async fn the_fleet_is_administered_over_trust_tasks() {
    let (state, _dir) = state().await;
    let admin = member(&state, 52, Role::Admin).await;
    did_hosting_common::server::domain::create_domain(
        &state.store,
        &did_hosting_common::server::domain::DomainEntry {
            name: "example.com".into(),
            label: None,
            scheme: did_hosting_common::server::domain::DomainUrlScheme::Https,
            status: did_hosting_common::server::domain::DomainStatus::Active,
            created_at: 1,
            default_domain: false,
            branding: None,
            witnesses: None,
            watchers: None,
            quota: None,
            well_known_enabled: false,
            disabled_at: None,
            purge_at: None,
        },
    )
    .await
    .unwrap();
    let register = t("did-management/registry/admin-register/0.2");
    let payload = json!({
        "instanceId": "edge-1",
        "did": "did:example:edge-1",
        "publicUrl": "https://edge-1.example.com",
        "servedDomains": ["example.com"],
    });
    let reply = call(&state, Via::Tsp, &admin, &register, payload.clone()).await;
    conforms(&reply);
    let reply = call(&state, Via::Tsp, &admin, &register, payload).await;
    assert_eq!(
        code(&reply),
        "did-management/registry/admin-register:instanceExists"
    );

    for slug in ["registry/get/0.2", "registry/check/0.2"] {
        let uri = t(&format!("did-management/{slug}"));
        let reply = call(
            &state,
            Via::Tsp,
            &admin,
            &uri,
            json!({ "instanceId": "edge-1" }),
        )
        .await;
        conforms(&reply);
        assert_eq!(ok(&reply, &uri)["instance"]["did"], "did:example:edge-1");
    }
    let list = t("did-management/registry/list/0.2");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &list,
        json!({ "serviceType": "server" }),
    )
    .await;
    conforms(&reply);
    assert_eq!(ok(&reply, &list)["instances"].as_array().unwrap().len(), 1);

    // A purge never races an assignment.
    let purge = t("did-management/registry/purge-domain/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &purge,
        json!({ "instanceId": "edge-1", "domain": "example.com" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/registry/purge-domain:stillAssigned",
        "{reply}"
    );

    let deregister = t("did-management/registry/deregister/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &deregister,
        json!({ "instanceId": "edge-1" }),
    )
    .await;
    conforms(&reply);
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &deregister,
        json!({ "instanceId": "edge-1" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management/registry/deregister:notFound");
}

#[tokio::test]
async fn the_service_describes_itself_to_administrators_only() {
    let (state, _dir) = state().await;
    let admin = member(&state, 53, Role::Admin).await;
    let owner = member(&state, 54, Role::Owner).await;
    for slug in [
        "server/config/0.1",
        "server/metrics/0.1",
        "identity/list/0.1",
        "stats/get/0.1",
    ] {
        let uri = t(&format!("did-management/{slug}"));
        let reply = call(&state, Via::Tsp, &admin, &uri, json!({})).await;
        conforms(&reply);
        let reply = call(&state, Via::Tsp, &owner, &uri, json!({})).await;
        assert_eq!(code(&reply), "permissionDenied", "{slug}: {reply}");
    }
    // The harness identity is signing-only, so it lists no rotating
    // generation; its one generation is still the current one.
    let current = state.identity.as_ref().unwrap().generations()[0].id;
    let uri = t("did-management/identity/retire/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &uri,
        json!({ "generationId": current }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/identity/retire:current",
        "{reply}"
    );
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &uri,
        json!({ "generationId": current + 100 }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/identity/retire:notFound",
        "{reply}"
    );

    // An owner reads their own slot's counters, not the aggregate.
    seed_did(&state, &owner.did, "mine").await;
    let uri = t("did-management/stats/get/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &uri,
        json!({ "mnemonic": "mine" }),
    )
    .await;
    conforms(&reply);
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &uri,
        json!({ "mnemonic": "ghost" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management/stats/get:notFound");
    let uri = t("did-management/stats/timeseries/0.2");
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &uri,
        json!({ "range": "lastDay", "mnemonic": "mine" }),
    )
    .await;
    conforms(&reply);
    assert_eq!(ok(&reply, &uri)["bucketSeconds"], 900);
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &uri,
        json!({ "range": "lastDay" }),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied");
}

/// `stats/set-resolution`: an owner may choose less detail for their own
/// slot, never `fine`; an admin may set anything on any slot; a stranger's
/// request is the same `notFound` as a slot that does not exist. The
/// response reports the tier that applies and why.
#[tokio::test]
async fn an_owner_lowers_their_statistics_and_only_an_admin_sets_fine() {
    use did_hosting_common::server::stats_tiers::StatsResolution;

    let (state, _dir) = state().await;
    let admin = member(&state, 55, Role::Admin).await;
    let owner = member(&state, 56, Role::Owner).await;
    let stranger = member(&state, 57, Role::Owner).await;
    seed_did(&state, &owner.did, "mine").await;
    let uri = t("did-management/stats/set-resolution/0.1");
    let set = |who, resolution: &str| {
        let body = json!({ "mnemonic": "mine", "resolution": resolution });
        let (state, uri) = (&state, &uri);
        async move { call(state, Via::Tsp, who, uri, body).await }
    };

    let reply = set(&owner, "off").await;
    conforms(&reply);
    let body = ok(&reply, &uri);
    assert_eq!(body["resolution"], "off");
    assert_eq!(body["previousResolution"], "auto");
    assert_eq!(body["changed"], true);
    assert_eq!(body["tier"], "off");
    assert_eq!(body["tierReason"], "override");
    assert_eq!(
        state.stats_collector.tiers().pin("mine"),
        StatsResolution::Off
    );

    let reply = set(&owner, "off").await;
    assert_eq!(
        ok(&reply, &uri)["changed"],
        false,
        "a repeat changes nothing"
    );

    let reply = set(&owner, "fine").await;
    assert_eq!(code(&reply), "permissionDenied", "{reply}");
    assert_eq!(
        state.stats_collector.tiers().pin("mine"),
        StatsResolution::Off,
        "a refused request changes nothing"
    );

    let reply = set(&stranger, "off").await;
    assert_eq!(
        code(&reply),
        "did-management/stats/set-resolution:notFound",
        "{reply}"
    );
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &uri,
        json!({ "mnemonic": "ghost", "resolution": "off" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/stats/set-resolution:notFound",
        "{reply}"
    );

    let reply = set(&admin, "fine").await;
    conforms(&reply);
    let body = ok(&reply, &uri);
    assert_eq!(body["previousResolution"], "off");
    assert_eq!(body["tier"], "fine");
    assert_eq!(body["tierReason"], "override");

    // Back to the service's own choice: a quiet slot is coarse by traffic.
    let reply = set(&owner, "auto").await;
    conforms(&reply);
    let body = ok(&reply, &uri);
    assert_eq!(body["resolution"], "auto");
    assert_eq!(body["previousResolution"], "fine");
    assert_eq!(body["tier"], "coarse");
    assert_eq!(body["tierReason"], "traffic");
    assert_eq!(
        state.stats_collector.tiers().pin("mine"),
        StatsResolution::Auto
    );
}

/// `MetricsReader` is a counters-only credential. It reads `server/metrics/0.1`
/// — counters present, gauges empty, since replication gauges stay Admin-only —
/// and is refused by the ordinary authenticated task surface, including a
/// slot-claiming `did/check-name` reservation. Its ACL entry carries
/// `DomainScope::All` (what `member`/`add-acl` store), so this proves the
/// central `Cx::auth` boundary, not the stored scope, is what keeps a metrics
/// key off DID-management, enrolment, and admin tasks.
#[tokio::test]
async fn metrics_reader_reads_counters_only_and_is_denied_elsewhere() {
    let (state, _dir) = state().await;
    let reader = member(&state, 71, Role::MetricsReader).await;

    // Reads the aggregate counters; gauges are Admin-only and come back empty.
    let metrics = t("did-management/server/metrics/0.1");
    let reply = call(&state, Via::Tsp, &reader, &metrics, json!({})).await;
    conforms(&reply);
    let snapshot = ok(&reply, &metrics)["snapshot"].clone();
    assert!(snapshot["counters"].is_array(), "counters present: {reply}");
    assert_eq!(
        snapshot["gauges"].as_array().map(Vec::len),
        Some(0),
        "a MetricsReader must not see replication gauges: {reply}"
    );

    // Denied everywhere else — a slot-claiming reservation an owner could make,
    // an admin config read, and the identity listing — despite the
    // `DomainScope::All` its ACL entry carries.
    let reserve = call(
        &state,
        Via::Tsp,
        &reader,
        &t("did-management/did/check-name/0.1"),
        json!({ "reserve": true }),
    )
    .await;
    assert_eq!(code(&reserve), "permissionDenied", "check-name: {reserve}");
    for slug in ["server/config/0.1", "identity/list/0.1"] {
        let uri = t(&format!("did-management/{slug}"));
        let reply = call(&state, Via::Tsp, &reader, &uri, json!({})).await;
        assert_eq!(code(&reply), "permissionDenied", "{slug}: {reply}");
    }
}

/// Seed the slot at `mnemonic` holding `did_id`, with these agent names.
pub(super) async fn seed_named(
    state: &AppState,
    mnemonic: &str,
    did_id: &str,
    names: &[(&str, bool)],
) {
    let mut record = seed_did(state, "did:example:operator", mnemonic).await;
    record.did_id = Some(did_id.into());
    record.agent_names = names
        .iter()
        .map(|(n, enabled)| AgentNameEntry {
            name: (*n).into(),
            enabled: *enabled,
            created_at: 0,
        })
        .collect();
    state
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .unwrap();
}

/// `server/info` asked anonymously over HTTPS, as the login page asks it.
pub(super) async fn anonymous_server_info(state: &AppState) -> Value {
    let uri = t("did-management/server/info/0.1");
    let mut doc = request(&uri, "unused", json!({}));
    doc.as_object_mut().unwrap().remove("issuer");
    ok(&https(state, None, doc).await, &uri)
}

pub(super) fn names_of(info: &Value) -> Vec<String> {
    info["serviceNames"]
        .as_array()
        .expect("serviceNames is always present")
        .iter()
        .map(|v| v.as_str().expect("a name is a string").to_string())
        .collect()
}

/// A client learns whether `/@name` is served before it has a session — it
/// cannot probe for it, because with the feature off `GET /@name` 404s exactly
/// as an unknown name does — and the answer tracks the flag.
#[tokio::test]
async fn server_info_says_whether_agent_names_are_served() {
    let (mut state, _dir) = state().await;
    assert_eq!(anonymous_server_info(&state).await["agentNames"], true);
    let mut config = (*state.config).clone();
    config.features.agent_names = false;
    state.config = std::sync::Arc::new(config);
    assert_eq!(anonymous_server_info(&state).await["agentNames"], false);
}

/// The service's own names come from the slot that holds its DID: the
/// community name is an empty local part, a parked name is omitted, and a
/// service with none reports an empty list.
#[tokio::test]
async fn server_info_names_the_services_own_served_agent_names() {
    let (state, _dir) = state().await;
    assert!(names_of(&anonymous_server_info(&state).await).is_empty());
    seed_named(&state, ".well-known", CONTROL, &[("", true)]).await;
    assert_eq!(names_of(&anonymous_server_info(&state).await), vec![""]);
    seed_named(
        &state,
        ".well-known",
        CONTROL,
        &[("", false), ("live", true)],
    )
    .await;
    assert_eq!(names_of(&anonymous_server_info(&state).await), vec!["live"]);
}

/// Every pathless DID maps to the one `.well-known` slot, so a root slot
/// holding some other DID must not be advertised as this service's — and with
/// agent names off nothing is served, so nothing is advertised.
#[tokio::test]
async fn server_info_does_not_advertise_names_it_would_not_serve() {
    let (mut state, _dir) = state().await;
    seed_named(
        &state,
        ".well-known",
        "did:webvh:other:someone-else.example",
        &[("", true)],
    )
    .await;
    assert!(names_of(&anonymous_server_info(&state).await).is_empty());

    seed_named(&state, ".well-known", CONTROL, &[("", true)]).await;
    let mut config = (*state.config).clone();
    config.features.agent_names = false;
    state.config = std::sync::Arc::new(config);
    assert!(names_of(&anonymous_server_info(&state).await).is_empty());
}

/// `agent-name/resolve` answers a DID's served names: a root DID's community
/// name as an empty local part, parked names omitted, and nothing for a DID
/// with no names, one this service does not host, or a foreign root DID —
/// which must not inherit the local root DID's names.
#[tokio::test]
async fn agent_name_resolve_answers_only_served_names_of_hosted_dids() {
    let (state, _dir) = state().await;
    let admin = member(&state, 60, Role::Admin).await;
    let root = "did:webvh:abc:control.example.com";
    let bob = "did:webvh:abc:control.example.com:bob";
    let quiet = "did:webvh:abc:control.example.com:quiet";
    seed_named(&state, ".well-known", root, &[("", true)]).await;
    seed_named(&state, "bob", bob, &[("parked", false), ("live", true)]).await;
    seed_named(&state, "quiet", quiet, &[]).await;
    let uri = t("did-management/agent-name/resolve/0.1");

    let body = ok(
        &call(
            &state,
            Via::Tsp,
            &admin,
            &uri,
            json!({ "dids": [
                root,
                bob,
                quiet,
                "did:webvh:zzz:someone-else.example",
                "did:web:elsewhere.example",
            ] }),
        )
        .await,
        &uri,
    );
    let mut entries = body["entries"].as_array().unwrap().clone();
    entries.sort_by_key(|e| e["did"].as_str().unwrap().to_string());
    assert_eq!(
        entries,
        vec![
            json!({ "did": root, "names": [""] }),
            json!({ "did": bob, "names": ["live"] }),
        ]
    );
}

/// A registry instance's cached badges reach `registry/list`, and with no
/// resolver the control plane's own advertised services are unknown, so
/// `server/config` omits the member rather than reporting an empty list —
/// "unknown" must never read as "advertises nothing" — while still reporting
/// the transports config turns on.
#[tokio::test]
async fn advertised_services_are_reported_and_unknown_is_omitted() {
    use crate::registry::{self, ServiceInstance, ServiceStatus, ServiceType};

    let (state, _dir) = state().await;
    assert!(state.did_resolver.is_none());
    let admin = member(&state, 61, Role::Admin).await;
    let instance = ServiceInstance {
        instance_id: "srv-1".into(),
        service_type: ServiceType::Server,
        label: Some("edge".into()),
        url: "http://edge.example".into(),
        status: ServiceStatus::Active,
        last_health_check: None,
        registered_at: 1_700_000_000,
        metadata: json!({ "did": "did:webvh:Q1:edge.example" }),
        enabled_methods: vec!["webvh".into()],
        served_domains: vec![],
        protocol_version: "1.0".into(),
        advertised_services: Some(vec!["WebVHHosting".into(), "TSPTransport".into()]),
        services_checked_at: Some(1_700_000_000),
        sync_batch_capable: false,
        last_inbound_transport: None,
        last_inbound_at: None,
        last_outbound_transport: None,
        last_outbound_at: None,
        last_ack_at: None,
        last_reconcile_at: None,
    };
    registry::register_instance(&state.registry_ks, &instance)
        .await
        .unwrap();

    let uri = t("did-management/registry/list/0.2");
    let reply = call(&state, Via::Tsp, &admin, &uri, json!({})).await;
    conforms(&reply);
    let body = ok(&reply, &uri);
    assert_eq!(
        body["instances"][0]["advertisedServices"],
        json!(["WebVHHosting", "TSPTransport"]),
        "{body}"
    );

    let uri = t("did-management/server/config/0.1");
    let reply = call(&state, Via::Tsp, &admin, &uri, json!({})).await;
    conforms(&reply);
    let body = ok(&reply, &uri);
    assert!(body.get("advertisedServices").is_none(), "{body}");
    assert!(body["transports"].get("tsp").is_some(), "{body}");
    assert!(body["transports"].get("didcomm").is_some(), "{body}");
}

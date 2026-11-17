//! `agent-name/*` rows end to end.

use super::*;

// ---------------------------------------------------------------------------
// agent-name/*
// ---------------------------------------------------------------------------

pub(super) async fn seed_names(
    state: &AppState,
    owner: &str,
    mnemonic: &str,
    names: &[(&str, bool)],
) {
    let mut record = seed_did(state, owner, mnemonic).await;
    record.domain = "example.com".into();
    record.agent_names = names
        .iter()
        .map(|(name, enabled)| AgentNameEntry {
            name: (*name).into(),
            enabled: *enabled,
            created_at: 7,
        })
        .collect();
    state
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .unwrap();
}

#[tokio::test]
async fn agent_name_list_answers_the_registry_parked_names_included() {
    let (state, _dir) = state().await;
    let owner = member(&state, 30, Role::Owner).await;
    let attacker = member(&state, 31, Role::Owner).await;
    seed_names(
        &state,
        &owner.did,
        "alpha-beta",
        &[("alice", true), ("parked", false)],
    )
    .await;
    seed_names(&state, &owner.did, "empty", &[]).await;

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        NAME_LIST,
        json!({ "mnemonic": "alpha-beta" }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, NAME_LIST);
    assert_eq!(body["domain"], "example.com");
    assert_eq!(body["agentNames"][0]["name"], "alice");
    assert_eq!(body["agentNames"][0]["createdAt"], "1970-01-01T00:00:07Z");
    assert_eq!(body["agentNames"][1]["enabled"], false);

    let body = ok(
        &call(
            &state,
            Via::Tsp,
            &owner,
            NAME_LIST,
            json!({ "mnemonic": "empty" }),
        )
        .await,
        NAME_LIST,
    );
    assert_eq!(body["agentNames"], json!([]));

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        NAME_LIST,
        json!({ "mnemonic": "alpha-beta", "domain": "other.example" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management:unknownDomain", "{reply}");

    let reply = call(
        &state,
        Via::Tsp,
        &attacker,
        NAME_LIST,
        json!({ "mnemonic": "alpha-beta" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/agent-name/list:notOwner",
        "{reply}"
    );
}

#[tokio::test]
async fn agent_name_check_reports_free_reserved_and_taken() {
    let (state, _dir) = state().await;
    let owner = member(&state, 32, Role::Owner).await;
    // A name is held by a live slot whose record lists it.
    let mut holder = seed_did(&state, "did:example:holder", "alpha-beta").await;
    holder.agent_names.push(AgentNameEntry {
        name: "taken".into(),
        enabled: true,
        created_at: 1,
    });
    state
        .dids_ks
        .insert(did_key("alpha-beta"), &holder)
        .await
        .unwrap();
    for (name, holder) in [("taken", "alpha-beta"), ("leftover", "gone-slot")] {
        state
            .dids_ks
            .insert_raw(
                did_hosting_common::did_ops::agent_name_key("example.com", name),
                holder.as_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
    for (name, available, reserved) in [
        ("alice", true, false),
        ("admin", false, true),
        ("taken", false, false),
        // An index entry left by a slot that no longer exists holds nothing.
        ("leftover", true, false),
    ] {
        let reply = call(
            &state,
            Via::Tsp,
            &owner,
            NAME_CHECK,
            json!({ "name": name, "domain": "example.com" }),
        )
        .await;
        conforms(&reply);
        let body = ok(&reply, NAME_CHECK);
        assert_eq!(body["name"], name);
        assert_eq!(body["domain"], "example.com");
        assert_eq!(body["available"], available, "{name}");
        assert_eq!(body["reserved"], reserved, "{name}");
    }

    // No domain on the wire and no system default: refused, not guessed.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        NAME_CHECK,
        json!({ "name": "alice" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management:unknownDomain", "{reply}");
}

#[tokio::test]
async fn agent_name_update_and_remove_reach_the_engine_as_the_caller() {
    let (state, _dir) = state().await;
    let owner = member(&state, 33, Role::Owner).await;
    let attacker = member(&state, 34, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;

    // A malformed log is refused by the engine: the verb reached it.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        NAME_UPDATE,
        json!({ "mnemonic": "alpha-beta", "name": "alice", "state": "active", "didData": "not-a-valid-log" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/agent-name/update:invalidDidData",
        "{reply}"
    );

    // A reserved name is its own code.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        NAME_UPDATE,
        json!({ "mnemonic": "alpha-beta", "name": "admin", "state": "active", "didData": "x" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/agent-name/update:nameReserved",
        "{reply}"
    );

    // A state outside the schema's enum never reaches the engine.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        NAME_UPDATE,
        json!({ "mnemonic": "alpha-beta", "name": "alice", "state": "released", "didData": "x" }),
    )
    .await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");

    // The owner check is not weakened for the destructive verb.
    let reply = call(
        &state,
        Via::Tsp,
        &attacker,
        NAME_REMOVE,
        json!({ "mnemonic": "alpha-beta", "name": "alice", "didData": "x" }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/agent-name/remove:notOwner",
        "{reply}"
    );
}

#[tokio::test]
async fn me_domains_answers_in_the_shared_domain_entry_shape() {
    let (state, _dir) = state().await;
    let owner = member(&state, 35, Role::Owner).await;
    did_hosting_common::server::domain::create_domain(
        &state.store,
        &did_hosting_common::server::domain::DomainEntry {
            name: "example.com".into(),
            label: Some("Example".into()),
            scheme: did_hosting_common::server::domain::DomainUrlScheme::Https,
            status: did_hosting_common::server::domain::DomainStatus::Active,
            created_at: 7,
            default_domain: true,
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
    let uri = "https://trusttasks.org/spec/did-management/me/domains/0.1";
    let reply = call(&state, Via::Tsp, &owner, uri, json!({})).await;
    conforms(&reply);
    let body = ok(&reply, uri);
    assert_eq!(body["domains"][0]["name"], "example.com");
    assert_eq!(body["domains"][0]["status"], "active");
    assert_eq!(body["domains"][0]["createdAt"], "1970-01-01T00:00:07Z");
    assert_eq!(
        body["domains"][0]["ext"]["vnd.affinidi.webvh"]["scheme"],
        "https"
    );
}

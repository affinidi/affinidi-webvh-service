//! `did/*` rows end to end.

use super::*;

// ---------------------------------------------------------------------------
// did/*
// ---------------------------------------------------------------------------

pub(super) const LIST: &str = "https://trusttasks.org/spec/did-management/did/list/0.2";
pub(super) const INFO: &str = "https://trusttasks.org/spec/did-management/did/info/0.1";
pub(super) const CHECK_NAME: &str = "https://trusttasks.org/spec/did-management/did/check-name/0.1";
pub(super) const DELETE: &str = "https://trusttasks.org/spec/did-management/did/delete/0.1";
pub(super) const CHANGE_OWNER: &str =
    "https://trusttasks.org/spec/did-management/did/change-owner/0.1";
pub(super) const WITNESS: &str = "https://trusttasks.org/spec/webvh/witness/publish/0.1";
pub(super) const NAME_UPDATE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/update/0.1";
pub(super) const NAME_REMOVE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/remove/0.1";
pub(super) const NAME_LIST: &str = "https://trusttasks.org/spec/did-management/agent-name/list/0.1";
pub(super) const NAME_CHECK: &str =
    "https://trusttasks.org/spec/did-management/agent-name/check/0.1";

/// A Type URI no row or family serves is refused as unsupported — once it
/// has been proven, so the refusal says nothing to a stranger.
#[tokio::test]
async fn an_unserved_type_is_refused_as_unsupported() {
    let (state, _dir) = state().await;
    let owner = member(&state, 10, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        "https://trusttasks.org/spec/did-management/not-a-task/0.1",
        json!({}),
    )
    .await;
    assert_eq!(code(&reply), "unsupportedType", "{reply}");
}

/// A payload member the schema does not define is refused, not dropped.
#[tokio::test]
async fn an_unknown_payload_member_is_refused() {
    let (state, _dir) = state().await;
    let owner = member(&state, 11, Role::Owner).await;
    for payload in [
        json!({ "mnemonic": "alpha", "surprise": true }),
        // 0.1's snake_case never matched the schema, and is not read.
        json!({ "mnemonic": "alpha", "new_owner": "did:example:x" }),
    ] {
        let reply = call(&state, Via::Didcomm, &owner, CHANGE_OWNER, payload).await;
        assert_eq!(code(&reply), "malformedRequest", "{reply}");
    }
    let reply = call(&state, Via::Didcomm, &owner, INFO, json!({})).await;
    assert_eq!(
        code(&reply),
        "malformedRequest",
        "a missing mnemonic: {reply}"
    );
}

#[tokio::test]
async fn list_answers_records_scoped_to_the_caller() {
    let (state, _dir) = state().await;
    let owner = member(&state, 12, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;
    seed_did(&state, &owner.did, "gamma-delta").await;
    seed_did(&state, "did:example:other", "eta-theta").await;

    let reply = call(&state, Via::Tsp, &owner, LIST, json!({})).await;
    conforms(&reply);
    let body = ok(&reply, LIST);
    assert!(body.get("nextCursor").is_none(), "one page: {body}");
    let mnemonics: Vec<&str> = body["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["mnemonic"].as_str().unwrap())
        .collect();
    assert_eq!(mnemonics, ["alpha-beta", "gamma-delta"]);
    assert_eq!(body["records"][0]["versionCount"], 1);
    assert_eq!(body["records"][0]["totalResolves"], 0);
    assert_eq!(
        body["records"][0]["didUrl"],
        "http://control.test/alpha-beta/did.jsonl"
    );

    // Paged by cursor: a page that is not the last carries `nextCursor`,
    // and the last carries none.
    let reply = call(&state, Via::Tsp, &owner, LIST, json!({ "limit": 1 })).await;
    conforms(&reply);
    let body = ok(&reply, LIST);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["mnemonic"], "alpha-beta");
    let cursor = body["nextCursor"]
        .as_str()
        .expect("a further page")
        .to_string();
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        LIST,
        json!({ "limit": 1, "cursor": cursor }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, LIST);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["mnemonic"], "gamma-delta");
    assert!(body.get("nextCursor").is_none(), "the last page: {body}");

    // `offset` is 0.1's, and is refused rather than ignored.
    let reply = call(&state, Via::Tsp, &owner, LIST, json!({ "offset": 1 })).await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");
}

/// A cursor this service did not issue — forged, or issued for another
/// caller's listing — is refused, never read.
#[tokio::test]
async fn list_refuses_a_cursor_it_did_not_issue() {
    let (state, _dir) = state().await;
    let owner = member(&state, 16, Role::Owner).await;
    let other = member(&state, 17, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;
    seed_did(&state, &owner.did, "gamma-delta").await;
    let body = ok(
        &call(&state, Via::Tsp, &owner, LIST, json!({ "limit": 1 })).await,
        LIST,
    );
    let cursor = body["nextCursor"].as_str().unwrap().to_string();
    for (who, cursor) in [
        (&other, cursor.clone()),
        (
            &owner,
            "v1.616c7068612d62657461.00000000000000000000000000000000".to_string(),
        ),
        (&owner, "not-a-cursor".to_string()),
    ] {
        let reply = call(&state, Via::Tsp, who, LIST, json!({ "cursor": cursor })).await;
        assert_eq!(code(&reply), "malformedRequest", "{reply}");
    }
}

/// IDOR regression: an owner whose DID prefixes another owner's DID does not
/// see the longer DID's slots through the owner index.
#[tokio::test]
async fn list_does_not_leak_through_an_owner_prefix() {
    let (state, _dir) = state().await;
    let owner = member(&state, 13, Role::Owner).await;
    let longer = format!("{}:server", owner.did);
    seed_did(&state, &owner.did, "short-mn").await;
    seed_did(&state, &longer, "long-mn").await;
    let body = ok(&call(&state, Via::Tsp, &owner, LIST, json!({})).await, LIST);
    assert_eq!(body["records"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["records"][0]["mnemonic"], "short-mn");
}

#[tokio::test]
async fn list_owner_filter_is_admin_only() {
    let (state, _dir) = state().await;
    let owner = member(&state, 14, Role::Owner).await;
    let admin = member(&state, 15, Role::Admin).await;
    seed_did(&state, "did:example:owner-a", "alpha-beta").await;
    seed_did(&state, "did:example:owner-b", "gamma-delta").await;

    // An owner naming someone else is refused, not quietly shown their own.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        LIST,
        json!({ "owner": "did:example:owner-a" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management/did/list:forbidden", "{reply}");

    // An admin sees every owner, or one.
    let body = ok(&call(&state, Via::Tsp, &admin, LIST, json!({})).await, LIST);
    assert_eq!(body["records"].as_array().unwrap().len(), 2);
    let body = ok(
        &call(
            &state,
            Via::Tsp,
            &admin,
            LIST,
            json!({ "owner": "did:example:owner-b" }),
        )
        .await,
        LIST,
    );
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["mnemonic"], "gamma-delta");
}

#[tokio::test]
async fn list_refuses_an_unknown_domain() {
    let (state, _dir) = state().await;
    let owner = member(&state, 16, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        LIST,
        json!({ "domain": "nowhere.example" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management:unknownDomain", "{reply}");
}

#[tokio::test]
async fn info_answers_the_record_to_its_owner_and_to_an_admin_only() {
    let (state, _dir) = state().await;
    let owner = member(&state, 17, Role::Owner).await;
    let attacker = member(&state, 18, Role::Owner).await;
    let admin = member(&state, 19, Role::Admin).await;
    seed_did(&state, &owner.did, "alpha-beta").await;

    let reply = call(
        &state,
        Via::Tsp,
        &attacker,
        INFO,
        json!({ "mnemonic": "alpha-beta" }),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied", "{reply}");

    for who in [&owner, &admin] {
        let reply = call(
            &state,
            Via::Tsp,
            who,
            INFO,
            json!({ "mnemonic": "alpha-beta" }),
        )
        .await;
        conforms(&reply);
        let body = ok(&reply, INFO);
        assert_eq!(body["record"]["mnemonic"], "alpha-beta");
        assert_eq!(body["record"]["owner"], owner.did.as_str());
        assert_eq!(body["record"]["createdAt"], "1970-01-01T00:00:01Z");
    }

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        INFO,
        json!({ "mnemonic": "ghost-token" }),
    )
    .await;
    assert_eq!(code(&reply), "did-management/did/info:notFound", "{reply}");
}

/// A record's agent names travel under this host's extension namespace: the
/// shared `DidRecord` schema is closed.
#[tokio::test]
async fn a_record_carries_its_agent_names_under_the_host_extension() {
    let (state, _dir) = state().await;
    let owner = member(&state, 20, Role::Owner).await;
    let mut record = seed_did(&state, &owner.did, "alpha-beta").await;
    record.agent_names = vec![AgentNameEntry {
        name: "alice".into(),
        enabled: true,
        created_at: 7,
    }];
    state
        .dids_ks
        .insert(did_key("alpha-beta"), &record)
        .await
        .unwrap();

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        INFO,
        json!({ "mnemonic": "alpha-beta" }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, INFO);
    assert!(body["record"].get("agentNames").is_none(), "{body}");
    assert_eq!(
        body["record"]["ext"]["vnd.affinidi.webvh"]["agentNames"][0]["name"],
        "alice"
    );
}

/// `did/info` reports the latest document's did:scid alias state under the
/// host extension, derived on the server so a client never re-derives `src`.
#[tokio::test]
async fn info_reports_the_did_scid_alias_state_of_the_latest_document() {
    let (state, _dir) = state().await;
    let owner = member(&state, 22, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;
    for (aka, status) in [
        (json!([]), "notListed"),
        (
            json!(["did:scid:vh:1:Qm1?src=a.example/alpha-beta"]),
            "stale",
        ),
        (
            json!(["did:scid:vh:1:Qm1?src=b.example/alpha-beta"]),
            "listed",
        ),
    ] {
        let line = json!({
            "versionId": "1-a",
            "state": { "id": "did:webvh:Qm1:b.example:alpha-beta", "alsoKnownAs": aka },
            "parameters": {},
        });
        state
            .dids_ks
            .insert_raw(content_log_key("alpha-beta"), line.to_string().into_bytes())
            .await
            .unwrap();
        let reply = call(
            &state,
            Via::Tsp,
            &owner,
            INFO,
            json!({ "mnemonic": "alpha-beta" }),
        )
        .await;
        conforms(&reply);
        let body = ok(&reply, INFO);
        let alias = &body["record"]["ext"]["vnd.affinidi.webvh"]["scidAlias"];
        assert_eq!(
            alias["didUrl"], "did:scid:vh:1:Qm1?src=b.example/alpha-beta",
            "{body}"
        );
        assert_eq!(alias["status"], status, "{body}");
    }
}

pub(super) const REGISTER: &str = "https://trusttasks.org/spec/did-management/did/register/0.1";

/// A `keri.cesr` stream created for `control.test`, which designates itself
/// there (`webs_continuation`'s `regenerate_control_fixture`), registered over
/// the Trust Task a VTA publishes with.
pub(super) const WEBS_KERI: &[u8] =
    include_bytes!("../../../../did-hosting-common/tests/fixtures/control-test/keri.cesr");
pub(super) const WEBS_AID: &str = "EALTc-6_o3G-p5jx7syeC46vpPAIjk1V58SNR3gyfT3A";

pub(super) fn webs_register(domain: &str) -> Value {
    json!({
        "path": WEBS_AID,
        "method": "webs",
        "didData": String::from_utf8(WEBS_KERI.to_vec()).expect("CESR is text"),
        "force": false,
        "domain": domain,
    })
}

#[cfg(feature = "method-webs")]
#[tokio::test]
async fn register_hosts_a_did_webs_key_event_log() {
    let (state, _dir) = state().await;
    let owner = member(&state, 22, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        REGISTER,
        webs_register("control.test"),
    )
    .await;
    conforms(&reply);
    let record = &ok(&reply, REGISTER)["record"];
    assert_eq!(record["mnemonic"], WEBS_AID, "{reply}");
    let stored: DidRecord = state
        .dids_ks
        .get(did_key(WEBS_AID))
        .await
        .unwrap()
        .expect("record");
    assert_eq!(stored.method, "webs");
    assert_eq!(
        stored.did_id.as_deref(),
        Some(format!("did:webs:control.test:{WEBS_AID}").as_str())
    );
}

/// A did:webs slot is managed through the same tasks as any other: read,
/// its agent names and history, suspend, change owner, delete. Its path ends in a mixed-case AID.
#[cfg(feature = "method-webs")]
#[tokio::test]
async fn a_did_webs_slot_is_read_suspended_transferred_and_deleted() {
    let (state, _dir) = state().await;
    let owner = member(&state, 23, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        REGISTER,
        webs_register("control.test"),
    )
    .await;
    ok(&reply, REGISTER);
    let did = format!("did:webs:control.test:{WEBS_AID}");

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        INFO,
        json!({ "mnemonic": WEBS_AID }),
    )
    .await;
    conforms(&reply);
    assert_eq!(ok(&reply, INFO)["record"]["mnemonic"], WEBS_AID, "{reply}");

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        NAME_LIST,
        json!({ "mnemonic": WEBS_AID }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, NAME_LIST);
    assert_eq!(body["domain"], "control.test", "{reply}");
    assert_eq!(body["agentNames"], json!([]), "{reply}");

    let log = t("did-management/did/log/0.1");

    // A caller that may not read the slot gets the same answer whether or not
    // a did:webs slot is recorded at an AID-shaped path.
    let stranger = member(&state, 26, Role::Owner).await;
    for path in [WEBS_AID, "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        let reply = call(
            &state,
            Via::Tsp,
            &stranger,
            &log,
            json!({ "mnemonic": path }),
        )
        .await;
        assert_eq!(code(&reply), "did-management/did/log:notFound", "{reply}");
    }
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &log,
        json!({ "mnemonic": WEBS_AID, "raw": true }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &log);
    assert_eq!(body["method"], "webs");
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{reply}");
    assert_eq!(entries[0]["state"]["id"], did.as_str(), "{reply}");
    assert_eq!(
        body["logContent"].as_str().unwrap().as_bytes(),
        WEBS_KERI,
        "raw returns the stored stream verbatim"
    );

    let set_state = t("did-management/did/set-state/0.1");
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &set_state,
        json!({ "mnemonic": WEBS_AID, "state": "suspended" }),
    )
    .await;
    conforms(&reply);
    ok(&reply, &set_state);
    let stored: DidRecord = state
        .dids_ks
        .get(did_key(WEBS_AID))
        .await
        .unwrap()
        .expect("record");
    assert!(stored.disabled);

    let admin = member(&state, 24, Role::Admin).await;
    let heir = member(&state, 25, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        CHANGE_OWNER,
        json!({ "mnemonic": WEBS_AID, "newOwner": heir.did }),
    )
    .await;
    conforms(&reply);
    assert_eq!(
        ok(&reply, CHANGE_OWNER)["record"]["owner"],
        heir.did.as_str(),
        "{reply}"
    );

    let reply = call(
        &state,
        Via::Tsp,
        &heir,
        DELETE,
        json!({ "mnemonic": WEBS_AID }),
    )
    .await;
    conforms(&reply);
    ok(&reply, DELETE);
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key(WEBS_AID))
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(not(feature = "method-webs"))]
#[tokio::test]
async fn register_refuses_did_webs_on_a_host_built_without_it() {
    let (state, _dir) = state().await;
    let owner = member(&state, 22, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        REGISTER,
        webs_register("control.test"),
    )
    .await;
    assert!(reply.to_string().contains("method-webs"), "{reply}");
}

#[tokio::test]
async fn delete_answers_the_record_as_it_stood() {
    let (state, _dir) = state().await;
    let owner = member(&state, 21, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        DELETE,
        json!({ "mnemonic": "alpha-beta" }),
    )
    .await;
    conforms(&reply);
    assert_eq!(ok(&reply, DELETE)["record"]["mnemonic"], "alpha-beta");
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("alpha-beta"))
            .await
            .unwrap()
            .is_none()
    );

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        DELETE,
        json!({ "mnemonic": "alpha-beta" }),
    )
    .await;
    assert!(
        is_task_code(&code(&reply)) || code(&reply) == "taskFailed",
        "{reply}"
    );
}

#[tokio::test]
async fn check_name_probe_is_read_only_and_reserve_claims_a_slot() {
    let (state, _dir) = state().await;
    let owner = member(&state, 22, Role::Owner).await;

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        CHECK_NAME,
        json!({ "path": "free-path" }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, CHECK_NAME);
    assert_eq!(body["available"], true);
    assert_eq!(body["reserved"], false);
    assert!(body.get("record").is_none());
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("free-path"))
            .await
            .unwrap()
            .is_none(),
        "a probe reserves nothing"
    );

    // A path-less probe has nothing to probe.
    let reply = call(&state, Via::Tsp, &owner, CHECK_NAME, json!({})).await;
    assert_eq!(
        code(&reply),
        "did-management/did/check-name:invalidPath",
        "{reply}"
    );

    // Auto-assign: two reservations, two distinct slots, owned by the caller.
    let mut minted = Vec::new();
    for _ in 0..2 {
        let reply = call(
            &state,
            Via::Tsp,
            &owner,
            CHECK_NAME,
            json!({ "reserve": true }),
        )
        .await;
        conforms(&reply);
        let body = ok(&reply, CHECK_NAME);
        assert_eq!(body["available"], true);
        assert_eq!(body["reserved"], true);
        assert_eq!(body["record"]["versionCount"], 0);
        let mnemonic = body["record"]["mnemonic"].as_str().unwrap().to_string();
        assert!(
            body["record"]["didUrl"]
                .as_str()
                .unwrap()
                .ends_with(&format!("/{mnemonic}/did.jsonl"))
        );
        let record: DidRecord = state
            .dids_ks
            .get(did_key(&mnemonic))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.owner, owner.did);
        minted.push(mnemonic);
    }
    assert_ne!(minted[0], minted[1]);

    // A taken path is not an error: nothing is available and nothing changes.
    seed_did(&state, "did:example:owner-b", "taken-path").await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        CHECK_NAME,
        json!({ "path": "taken-path", "reserve": true }),
    )
    .await;
    let body = ok(&reply, CHECK_NAME);
    assert_eq!(body["available"], false);
    assert_eq!(body["reserved"], false);
}

#[tokio::test]
async fn check_name_keeps_well_known_for_admins() {
    let (state, _dir) = state().await;
    let owner = member(&state, 23, Role::Owner).await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        CHECK_NAME,
        json!({ "path": ".well-known", "reserve": true }),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied", "{reply}");
}

/// The slot's owner set in the ownership indexes: `(owner rows, heir rows)`.
pub(super) async fn owner_rows(state: &AppState, owner: &str, heir: &str) -> (usize, usize) {
    let rows = |did: String| async move {
        state
            .dids_ks
            .prefix_iter_raw(format!("owner:{did}:"))
            .await
            .unwrap()
            .len()
    };
    (rows(owner.to_string()).await, rows(heir.to_string()).await)
}

/// An ACL member of `role` whose entry carries `max_did_count` and `domains`.
pub(super) async fn limited_member(
    state: &AppState,
    seed: u8,
    role: Role,
    max_did_count: Option<u64>,
    domains: did_hosting_common::server::domain::DomainScope,
) -> Caller {
    let caller = member(state, seed, role.clone()).await;
    did_hosting_common::server::acl::store_acl_entry(
        &state.acl_ks,
        &did_hosting_common::server::acl::AclEntry {
            did: caller.did.clone(),
            role,
            label: None,
            created_at: 1_700_000_000,
            max_total_size: None,
            max_did_count,
            domains,
        },
    )
    .await
    .unwrap();
    caller
}

pub(super) const TARGET_NOT_AUTHORIZED: &str =
    "did-management/did/change-owner:targetNotAuthorized";
pub(super) const NOT_OWNER: &str = "did-management/did/change-owner:notOwner";

/// An owner's change-owner only offers the slot; it moves when the recipient
/// sends the same request naming itself. Nobody else can take it, and the
/// offer is spent by the acceptance.
#[tokio::test]
async fn change_owner_moves_the_slot_only_when_the_recipient_accepts() {
    let (state, _dir) = state().await;
    let owner = member(&state, 24, Role::Owner).await;
    let heir = member(&state, 25, Role::Owner).await;
    let other = member(&state, 26, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;

    let reply = call(
        &state,
        Via::Tsp,
        &other,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": heir.did }),
    )
    .await;
    assert_eq!(code(&reply), NOT_OWNER, "{reply}");

    // The offer: the record is unchanged, and the reply says it is pending.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": heir.did }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, CHANGE_OWNER);
    assert_eq!(body["record"]["owner"], owner.did.as_str());
    let transfer = &body["ext"]["vnd.affinidi.webvh"]["ownerTransfer"];
    assert_eq!(transfer["status"], "offered", "{body}");
    assert_eq!(transfer["newOwner"], heir.did.as_str());
    assert!(transfer["expiresAt"].is_string());
    assert_eq!(owner_rows(&state, &owner.did, &heir.did).await, (1, 0));

    // Another member cannot take an offer made to someone else.
    let reply = call(
        &state,
        Via::Didcomm,
        &other,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": other.did }),
    )
    .await;
    assert_eq!(code(&reply), NOT_OWNER, "{reply}");
    // Nor can the recipient name anyone but itself.
    let reply = call(
        &state,
        Via::Didcomm,
        &heir,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": other.did }),
    )
    .await;
    assert_eq!(code(&reply), NOT_OWNER, "{reply}");

    // The recipient accepts.
    let reply = call(
        &state,
        Via::Https,
        &heir,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": heir.did }),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, CHANGE_OWNER);
    assert_eq!(body["record"]["owner"], heir.did.as_str());
    assert!(body.get("ext").is_none(), "{body}");
    assert_eq!(owner_rows(&state, &owner.did, &heir.did).await, (0, 1));

    // The offer is spent: the old owner cannot take the slot back with it.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": owner.did }),
    )
    .await;
    assert_eq!(code(&reply), NOT_OWNER, "{reply}");
}

/// An offer says nothing about its recipient: one to a DID outside the ACL
/// is recorded like any other (and can never be accepted). Naming the owner
/// withdraws an outstanding offer.
#[tokio::test]
async fn an_offer_discloses_nothing_and_can_be_withdrawn() {
    let (state, _dir) = state().await;
    let owner = member(&state, 27, Role::Owner).await;
    let heir = member(&state, 28, Role::Owner).await;
    seed_did(&state, &owner.did, "gamma-delta").await;

    let outside = call(
        &state,
        Via::Tsp,
        &owner,
        CHANGE_OWNER,
        json!({ "mnemonic": "gamma-delta", "newOwner": "did:example:not-in-acl" }),
    )
    .await;
    let inside = call(
        &state,
        Via::Tsp,
        &owner,
        CHANGE_OWNER,
        json!({ "mnemonic": "gamma-delta", "newOwner": heir.did }),
    )
    .await;
    for reply in [&outside, &inside] {
        let body = ok(reply, CHANGE_OWNER);
        assert_eq!(
            body["ext"]["vnd.affinidi.webvh"]["ownerTransfer"]["status"],
            "offered"
        );
    }

    // Withdrawn by naming the owner; the recipient then has nothing to accept.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        CHANGE_OWNER,
        json!({ "mnemonic": "gamma-delta", "newOwner": owner.did }),
    )
    .await;
    assert!(ok(&reply, CHANGE_OWNER).get("ext").is_none(), "{reply}");
    let reply = call(
        &state,
        Via::Tsp,
        &heir,
        CHANGE_OWNER,
        json!({ "mnemonic": "gamma-delta", "newOwner": heir.did }),
    )
    .await;
    assert_eq!(code(&reply), NOT_OWNER, "{reply}");
}

/// The recipient takes a slot only if it could have registered it: its quota
/// and domain scope are applied when it accepts, and when an administrator
/// moves the slot directly. Each is told which check failed; the recipient
/// is told nothing about the slot's owner.
#[tokio::test]
async fn the_recipients_quota_and_domain_scope_apply_to_a_transfer() {
    use did_hosting_common::server::domain::DomainScope;

    let (state, _dir) = state().await;
    let admin = member(&state, 29, Role::Admin).await;
    let owner = member(&state, 30, Role::Owner).await;
    let full = limited_member(&state, 31, Role::Owner, Some(1), DomainScope::All).await;
    seed_did(&state, &full.did, "full-own").await;
    let elsewhere = limited_member(
        &state,
        32,
        Role::Owner,
        None,
        DomainScope::Allowed {
            domains: vec!["other.example".into()],
        },
    )
    .await;
    let service = member(&state, 33, Role::Service).await;
    let mut record = seed_did(&state, &owner.did, "epsilon-zeta").await;
    record.domain = "control.test".into();
    state
        .dids_ks
        .insert(did_key("epsilon-zeta"), &record)
        .await
        .unwrap();

    for (recipient, why) in [(&full, "count limit"), (&elsewhere, "not scoped")] {
        // Offered by the owner, refused when the recipient accepts.
        ok(
            &call(
                &state,
                Via::Tsp,
                &owner,
                CHANGE_OWNER,
                json!({ "mnemonic": "epsilon-zeta", "newOwner": recipient.did }),
            )
            .await,
            CHANGE_OWNER,
        );
        let reply = call(
            &state,
            Via::Tsp,
            recipient,
            CHANGE_OWNER,
            json!({ "mnemonic": "epsilon-zeta", "newOwner": recipient.did }),
        )
        .await;
        assert_eq!(code(&reply), TARGET_NOT_AUTHORIZED, "{reply}");
        // The recipient is told its own reason, and nothing about the owner.
        let message = reply["payload"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(why) && !message.contains(&owner.did),
            "{why}: {reply}"
        );
    }
    // An administrator's direct transfer is held to the same limits, and says
    // which one.
    for (recipient, why) in [
        (&full.did, "count limit"),
        (&elsewhere.did, "'control.test'"),
        (&service.did, "cannot own DIDs"),
        (&"did:example:not-in-acl".to_string(), "no ACL entry"),
    ] {
        let reply = call(
            &state,
            Via::Tsp,
            &admin,
            CHANGE_OWNER,
            json!({ "mnemonic": "epsilon-zeta", "newOwner": recipient }),
        )
        .await;
        assert_eq!(code(&reply), TARGET_NOT_AUTHORIZED, "{reply}");
        assert!(
            reply["payload"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains(why),
            "{why}: {reply}"
        );
    }
    let record: DidRecord = state
        .dids_ks
        .get(did_key("epsilon-zeta"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.owner, owner.did, "nothing moved");
}

/// Deleting a slot withdraws its offer, even when the path is registered
/// again at once (within the same second as the offer).
#[tokio::test]
async fn deleting_a_slot_withdraws_its_offer() {
    let (state, _dir) = state().await;
    let owner = member(&state, 36, Role::Owner).await;
    let heir = member(&state, 37, Role::Owner).await;
    let mut record = seed_did(&state, &owner.did, "iota-kappa").await;
    let now = did_hosting_common::server::auth::session::now_epoch();
    record.created_at = now;
    state
        .dids_ks
        .insert(did_key("iota-kappa"), &record)
        .await
        .unwrap();
    ok(
        &call(
            &state,
            Via::Tsp,
            &owner,
            CHANGE_OWNER,
            json!({ "mnemonic": "iota-kappa", "newOwner": heir.did }),
        )
        .await,
        CHANGE_OWNER,
    );
    ok(
        &call(
            &state,
            Via::Tsp,
            &owner,
            "https://trusttasks.org/spec/did-management/did/delete/0.1",
            json!({ "mnemonic": "iota-kappa" }),
        )
        .await,
        "https://trusttasks.org/spec/did-management/did/delete/0.1",
    );
    assert!(
        state
            .sessions_ks
            .get_raw("did_xfer:iota-kappa")
            .await
            .unwrap()
            .is_none()
    );
    let mut record = seed_did(&state, &owner.did, "iota-kappa").await;
    record.created_at = now;
    state
        .dids_ks
        .insert(did_key("iota-kappa"), &record)
        .await
        .unwrap();
    let reply = call(
        &state,
        Via::Tsp,
        &heir,
        CHANGE_OWNER,
        json!({ "mnemonic": "iota-kappa", "newOwner": heir.did }),
    )
    .await;
    assert_eq!(code(&reply), NOT_OWNER, "{reply}");
}

/// An offer is for the slot as it stood: once the path is registered again,
/// an earlier offer for it cannot be accepted.
#[tokio::test]
async fn an_offer_does_not_survive_its_slot() {
    let (state, _dir) = state().await;
    let owner = member(&state, 34, Role::Owner).await;
    let heir = member(&state, 35, Role::Owner).await;
    seed_did(&state, &owner.did, "eta-theta").await;
    ok(
        &call(
            &state,
            Via::Tsp,
            &owner,
            CHANGE_OWNER,
            json!({ "mnemonic": "eta-theta", "newOwner": heir.did }),
        )
        .await,
        CHANGE_OWNER,
    );
    // The same owner registers the path afresh, later than the offer.
    let mut record = seed_did(&state, &owner.did, "eta-theta").await;
    record.created_at = did_hosting_common::server::auth::session::now_epoch() + 10;
    state
        .dids_ks
        .insert(did_key("eta-theta"), &record)
        .await
        .unwrap();
    let reply = call(
        &state,
        Via::Tsp,
        &heir,
        CHANGE_OWNER,
        json!({ "mnemonic": "eta-theta", "newOwner": heir.did }),
    )
    .await;
    assert_eq!(code(&reply), NOT_OWNER, "{reply}");
}

/// Seed a slot with a real, signed, single-entry did:webvh log configuring
/// one witness at threshold 1 — the minimum `did_ops::upload_witness` now
/// needs to accept a proof for it (SEC finding #165): the proof must
/// cryptographically verify over the genesis `versionId`, *and* its signer
/// must be the witness this log actually names.
///
/// Returns the genesis `versionId` and the matching witness's signing key.
pub(super) async fn seed_witnessed_genesis(
    state: &AppState,
    owner: &str,
    mnemonic: &str,
) -> (String, affinidi_secrets_resolver::secrets::Secret) {
    use didwebvh_rs::parameters::Parameters;
    use didwebvh_rs::witness::{Witness, Witnesses};
    use didwebvh_rs::{DIDWebVHState, Multibase};

    let mut key = affinidi_secrets_resolver::secrets::Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().expect("update key multibase");
    key.id = format!("did:key:{pk}#{pk}");

    let mut witness_key = affinidi_secrets_resolver::secrets::Secret::generate_ed25519(None, None);
    let witness_pk = witness_key
        .get_public_keymultibase()
        .expect("witness key multibase");
    witness_key.id = format!("did:key:{witness_pk}#{witness_pk}");
    let witness_did = format!("did:key:{witness_pk}");

    let params = Parameters {
        update_keys: Some(std::sync::Arc::new(vec![Multibase::new(pk)])),
        portable: Some(false),
        witness: Some(std::sync::Arc::new(Witnesses::Value {
            threshold: 1,
            witnesses: vec![Witness {
                id: Multibase::new(witness_did),
            }],
        })),
        ..Default::default()
    };
    let did_id = format!("did:webvh:{{SCID}}:control.test:{mnemonic}");
    let doc = json!({
        "id": &did_id,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did_id}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": key.get_public_keymultibase().unwrap(),
            "controller": &did_id,
        }],
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")],
    });

    let mut vh_state = DIDWebVHState::default();
    vh_state
        .create_log_entry(None, &doc, &params, &key)
        .await
        .expect("genesis entry");
    let version_id = vh_state
        .log_entries()
        .last()
        .unwrap()
        .get_version_id()
        .to_string();
    let jsonl = vh_state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");

    seed_did(state, owner, mnemonic).await;
    state
        .dids_ks
        .insert_raw(content_log_key(mnemonic), jsonl.into_bytes())
        .await
        .unwrap();

    (version_id, witness_key)
}

#[tokio::test]
async fn witness_publish_stores_a_proof_that_verifies_against_the_log() {
    let (state, _dir) = state().await;
    let owner = member(&state, 27, Role::Owner).await;
    let (version_id, witness_key) = seed_witnessed_genesis(&state, &owner.did, "alpha-beta").await;

    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &json!({ "versionId": &version_id }),
        &witness_key,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .expect("sign witness proof");

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        WITNESS,
        json!({
            "mnemonic": "alpha-beta",
            "witness": {
                "versionId": version_id,
                "witness": witness_key.id.split('#').next().unwrap(),
                "proof": serde_json::to_value(&proof).unwrap(),
            },
        }),
    )
    .await;
    conforms(&reply);
    assert_eq!(
        ok(&reply, WITNESS)["witnessUrl"],
        "http://control.test/alpha-beta/did-witness.json"
    );
}

/// SEC finding #165: a `did:key` proof is self-certifying — its public key
/// travels inside `verificationMethod`, so it trivially "verifies" against
/// itself no matter who signed it. A proof from a key the log's own
/// `witness` parameter doesn't name must still be refused, not merely
/// signature-checked.
#[tokio::test]
async fn witness_publish_rejects_a_proof_from_a_key_the_log_does_not_name_as_witness() {
    let (state, _dir) = state().await;
    let owner = member(&state, 28, Role::Owner).await;
    let (version_id, _real_witness_key) =
        seed_witnessed_genesis(&state, &owner.did, "gamma-delta").await;

    let mut forger = affinidi_secrets_resolver::secrets::Secret::generate_ed25519(None, None);
    let forger_pk = forger
        .get_public_keymultibase()
        .expect("forger key multibase");
    forger.id = format!("did:key:{forger_pk}#{forger_pk}");
    let bogus_proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &json!({ "versionId": &version_id }),
        &forger,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .expect("sign bogus proof — well-formed, just from the wrong key");

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        WITNESS,
        json!({
            "mnemonic": "gamma-delta",
            "witness": {
                "versionId": version_id,
                "witness": format!("did:key:{forger_pk}"),
                "proof": serde_json::to_value(&bogus_proof).unwrap(),
            },
        }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "webvh/witness/publish:invalidWitness",
        "a proof from a non-witness key must be refused, not stored: {reply}"
    );
    assert!(
        state
            .dids_ks
            .get_raw(did_hosting_common::did_ops::content_witness_key(
                "gamma-delta"
            ))
            .await
            .unwrap()
            .is_none(),
        "a rejected proof must leave no witness-content behind",
    );
}

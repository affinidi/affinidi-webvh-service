//! The control plane's Trust Task table, end to end: every row is served on
//! every transport, refused unsigned, refused under the wrong key
//! relationship, and answers in the shape its schema allows.

use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::{
    did_management::{
        agent_name::{check, list as names_list, remove, update},
        did::{change_owner, check_name, delete, info, list, register},
        me::domains as me_domains,
    },
    webvh::witness::publish as witness_publish,
};

use did_hosting_common::did_ops::{AgentNameEntry, DidRecord, did_key};
use did_hosting_common::server::acl::Role;
use did_hosting_common::server::trust_tasks::ProofRule;

use super::TASKS;
use super::harness::*;
use crate::server::AppState;

/// The URI of a generated request type.
fn uri<P: Payload>() -> &'static str {
    P::TYPE_URI
}

/// A task code is the task's own — declared by its specification or its
/// category — rather than one the framework raises before a handler runs.
fn is_task_code(code: &str) -> bool {
    code.contains(':')
}

/// A request for every row that reaches its handler: either the handler
/// answers, or it refuses under a code the task's specification declares.
/// `n` keeps each transport's run on its own slots.
async fn sample(state: &AppState, admin: &Caller, n: usize, type_uri: &str) -> Value {
    let slot = format!("slot-{n}");
    let seed = |m: String| {
        let admin = admin.did.clone();
        async move { seed_did(state, &admin, &m).await }
    };
    if type_uri == uri::<check_name::v0_1::Payload>() {
        json!({ "path": format!("free-{n}"), "reserve": false })
    } else if type_uri == uri::<register::v0_1::Payload>() {
        json!({ "path": format!("reg-{n}"), "method": "webvh", "didData": "not a log", "force": false })
    } else if type_uri == uri::<info::v0_1::Payload>() {
        seed(slot.clone()).await;
        json!({ "mnemonic": slot })
    } else if type_uri == uri::<list::v0_1::Payload>() {
        json!({})
    } else if type_uri == uri::<delete::v0_1::Payload>() {
        seed(slot.clone()).await;
        json!({ "mnemonic": slot })
    } else if type_uri == uri::<change_owner::v0_1::Payload>() {
        seed(slot.clone()).await;
        let heir = member(state, 100 + (n % 150) as u8, Role::Owner).await;
        json!({ "mnemonic": slot, "newOwner": heir.did })
    } else if type_uri == uri::<witness_publish::v0_1::Payload>() {
        seed(slot.clone()).await;
        json!({ "mnemonic": slot, "witness": {} })
    } else if type_uri == uri::<me_domains::v0_1::Payload>() {
        json!({})
    } else if type_uri == uri::<update::v0_1::Payload>() {
        seed(slot.clone()).await;
        json!({ "mnemonic": slot, "name": "alice", "state": "active", "didData": "not a log" })
    } else if type_uri == uri::<remove::v0_1::Payload>() {
        seed(slot.clone()).await;
        json!({ "mnemonic": slot, "name": "alice", "didData": "not a log" })
    } else if type_uri == uri::<names_list::v0_1::Payload>() {
        seed(slot.clone()).await;
        json!({ "mnemonic": slot })
    } else if type_uri == uri::<check::v0_1::Payload>() {
        json!({ "name": "alice", "domain": "example.com" })
    } else {
        panic!("no sample for {type_uri}: add one when adding a row");
    }
}

#[tokio::test]
async fn every_row_is_served_on_every_transport() {
    let (state, _dir) = state().await;
    let admin = member(&state, 1, Role::Admin).await;
    let mut n = 0;
    for (type_uri, _) in TASKS {
        for via in VIAS {
            n += 1;
            let payload = sample(&state, &admin, n, type_uri).await;
            let reply = call(&state, via, &admin, type_uri, payload).await;
            let reply_type = reply["type"].as_str().unwrap_or_default();
            if reply_type == format!("{type_uri}#response") {
                conforms(&reply);
                assert_eq!(reply["issuer"], CONTROL, "{via:?} {type_uri}: {reply}");
                assert!(
                    reply["proof"].is_object(),
                    "{via:?} {type_uri}: reply is signed"
                );
            } else {
                let code = code(&reply);
                assert!(
                    is_task_code(&code),
                    "{via:?} {type_uri} was not served: {reply}"
                );
            }
        }
    }
}

#[tokio::test]
async fn an_unsigned_request_is_refused_on_every_transport() {
    let (state, _dir) = state().await;
    let admin = member(&state, 2, Role::Admin).await;
    let mut n = 1000;
    for (type_uri, rule) in TASKS {
        if *rule == ProofRule::Optional {
            continue;
        }
        for via in VIAS {
            n += 1;
            let payload = sample(&state, &admin, n, type_uri).await;
            let reply = send(&state, via, &admin, request(type_uri, &admin.did, payload)).await;
            assert_eq!(code(&reply), "proofRequired", "{via:?} {type_uri}: {reply}");
        }
    }
}

#[tokio::test]
async fn a_proof_under_the_wrong_key_relationship_is_refused_on_every_transport() {
    let (state, _dir) = state().await;
    let admin = member(&state, 3, Role::Admin).await;
    let mut n = 2000;
    for (type_uri, rule) in TASKS {
        if *rule != ProofRule::Authentication {
            continue;
        }
        for via in VIAS {
            n += 1;
            let payload = sample(&state, &admin, n, type_uri).await;
            let doc = signed_as_assertion(request(type_uri, &admin.did, payload), &admin.key).await;
            let reply = send(&state, via, &admin, doc).await;
            assert_eq!(code(&reply), "proofInvalid", "{via:?} {type_uri}: {reply}");
        }
    }
}

#[tokio::test]
async fn a_signer_outside_the_acl_is_refused_on_every_transport() {
    let (state, _dir) = state().await;
    let admin = member(&state, 4, Role::Admin).await;
    let outsider = stranger(5);
    let mut n = 3000;
    for (type_uri, rule) in TASKS {
        if *rule == ProofRule::Optional {
            continue;
        }
        for via in VIAS {
            n += 1;
            let payload = sample(&state, &admin, n, type_uri).await;
            let reply = call(&state, via, &outsider, type_uri, payload).await;
            assert_eq!(
                code(&reply),
                "permissionDenied",
                "{via:?} {type_uri}: {reply}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// did/*
// ---------------------------------------------------------------------------

const LIST: &str = "https://trusttasks.org/spec/did-management/did/list/0.1";
const INFO: &str = "https://trusttasks.org/spec/did-management/did/info/0.1";
const CHECK_NAME: &str = "https://trusttasks.org/spec/did-management/did/check-name/0.1";
const DELETE: &str = "https://trusttasks.org/spec/did-management/did/delete/0.1";
const CHANGE_OWNER: &str = "https://trusttasks.org/spec/did-management/did/change-owner/0.1";
const WITNESS: &str = "https://trusttasks.org/spec/webvh/witness/publish/0.1";
const NAME_UPDATE: &str = "https://trusttasks.org/spec/did-management/agent-name/update/0.1";
const NAME_REMOVE: &str = "https://trusttasks.org/spec/did-management/agent-name/remove/0.1";
const NAME_LIST: &str = "https://trusttasks.org/spec/did-management/agent-name/list/0.1";
const NAME_CHECK: &str = "https://trusttasks.org/spec/did-management/agent-name/check/0.1";

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
async fn list_answers_records_and_total_scoped_to_the_caller() {
    let (state, _dir) = state().await;
    let owner = member(&state, 12, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;
    seed_did(&state, &owner.did, "gamma-delta").await;
    seed_did(&state, "did:example:other", "eta-theta").await;

    let reply = call(&state, Via::Tsp, &owner, LIST, json!({})).await;
    conforms(&reply);
    let body = ok(&reply, LIST);
    assert_eq!(body["total"], 2, "{body}");
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

    // Paged: `total` is the whole set, `records` the page.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        LIST,
        json!({ "limit": 1, "offset": 1 }),
    )
    .await;
    let body = ok(&reply, LIST);
    assert_eq!(body["total"], 2);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["mnemonic"], "gamma-delta");
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
    assert_eq!(body["total"], 1, "{body}");
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
    assert_eq!(body["total"], 2);
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
    assert_eq!(body["total"], 1);
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

#[tokio::test]
async fn change_owner_moves_the_slot_to_an_acl_member_only() {
    let (state, _dir) = state().await;
    let owner = member(&state, 24, Role::Owner).await;
    let heir = member(&state, 25, Role::Owner).await;
    let attacker = member(&state, 26, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;

    let reply = call(
        &state,
        Via::Tsp,
        &attacker,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": heir.did }),
    )
    .await;
    assert_eq!(
        code(&reply),
        "did-management/did/change-owner:notOwner",
        "{reply}"
    );

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": "did:example:not-in-acl" }),
    )
    .await;
    assert!(!code(&reply).is_empty(), "{reply}");

    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        CHANGE_OWNER,
        json!({ "mnemonic": "alpha-beta", "newOwner": heir.did }),
    )
    .await;
    conforms(&reply);
    assert_eq!(
        ok(&reply, CHANGE_OWNER)["record"]["owner"],
        heir.did.as_str()
    );
    assert!(
        state
            .dids_ks
            .prefix_iter_raw(format!("owner:{}:", owner.did))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        state
            .dids_ks
            .prefix_iter_raw(format!("owner:{}:", heir.did))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn witness_publish_answers_where_the_proofs_are_served() {
    let (state, _dir) = state().await;
    let owner = member(&state, 27, Role::Owner).await;
    seed_did(&state, &owner.did, "alpha-beta").await;
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        WITNESS,
        json!({ "mnemonic": "alpha-beta", "witness": {} }),
    )
    .await;
    conforms(&reply);
    assert_eq!(
        ok(&reply, WITNESS)["witnessUrl"],
        "http://control.test/alpha-beta/did-witness.json"
    );
}

// ---------------------------------------------------------------------------
// agent-name/*
// ---------------------------------------------------------------------------

async fn seed_names(state: &AppState, owner: &str, mnemonic: &str, names: &[(&str, bool)]) {
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
    state
        .dids_ks
        .insert_raw(
            did_hosting_common::did_ops::agent_name_key("example.com", "taken"),
            b"alpha-beta".to_vec(),
        )
        .await
        .unwrap();
    for (name, available, reserved) in [
        ("alice", true, false),
        ("admin", false, true),
        ("taken", false, false),
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

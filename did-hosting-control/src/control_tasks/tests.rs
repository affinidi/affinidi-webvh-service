//! The control plane's Trust Task table, end to end: every row is served on
//! every transport, refused unsigned, refused under the wrong key
//! relationship, and answers in the shape its schema allows.

use serde_json::{Value, json};

use did_hosting_common::did_ops::{AgentNameEntry, DidRecord, content_log_key, did_key};
use did_hosting_common::server::acl::Role;
use did_hosting_common::server::trust_tasks::ProofRule;

use super::TASKS;
use super::harness::*;
use crate::server::AppState;

/// A task code is the task's own — declared by its specification or its
/// category — rather than one the framework raises before a handler runs.
fn is_task_code(code: &str) -> bool {
    code.contains(':')
}

/// Whether `reply` came from the row's handler rather than from the gate or
/// the narrowing in front of it: a response, or an error that is not one of
/// the refusals the gate and the framework raise before a handler runs.
fn is_served(reply: &Value) -> bool {
    let reply_type = reply["type"].as_str().unwrap_or_default();
    if reply_type.ends_with("#response") {
        return true;
    }
    let code = reply["payload"]["code"].as_str().unwrap_or_default();
    let message = reply["payload"]["message"].as_str().unwrap_or_default();
    !matches!(
        code,
        "proofRequired" | "proofInvalid" | "unsupportedType" | "idConflict" | "wrongRecipient"
    ) && !(code == "permissionDenied" && message.contains("not present in the maintainer's ACL"))
        && !(code == "malformedRequest" && message.contains("payload"))
}

/// A seeded, published slot with a two-entry log.
async fn seed_published(state: &AppState, owner: &str, mnemonic: &str) {
    let mut record = seed_did(state, owner, mnemonic).await;
    record.version_count = 2;
    state
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(
            content_log_key(mnemonic),
            b"{\"versionId\":\"1-a\",\"state\":{},\"parameters\":{}}\n{\"versionId\":\"2-b\",\"state\":{},\"parameters\":{}}".to_vec(),
        )
        .await
        .unwrap();
}

/// A WebAuthn assertion in the shape the schema requires — it will not
/// verify, which is not what these tests are about.
fn assertion() -> Value {
    json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "authenticatorData": "AAAA",
            "clientDataJSON": "AAAA",
            "signature": "AAAA",
        },
    })
}

/// A request for every row that reaches its handler. `n` keeps each
/// transport's run on its own slots.
async fn sample(state: &AppState, admin: &Caller, n: usize, type_uri: &str) -> Value {
    let slot = format!("slot-{n}");
    let slug = type_uri.trim_start_matches("https://trusttasks.org/spec/");
    match slug {
        "did-management/did/check-name/0.1" => {
            json!({ "path": format!("free-{n}"), "reserve": false })
        }
        "did-management/did/register/0.1" => {
            json!({ "path": format!("reg-{n}"), "method": "webvh", "didData": "not a log", "force": false })
        }
        "did-management/did/info/0.1"
        | "did-management/did/delete/0.1"
        | "did-management/agent-name/list/0.1" => {
            seed_did(state, &admin.did, &slot).await;
            json!({ "mnemonic": slot })
        }
        "did-management/did/list/0.1"
        | "did-management/me/domains/0.1"
        | "did-management/domain/list/0.1"
        | "did-management/registry/list/0.1"
        | "did-management/server/info/0.1"
        | "did-management/server/config/0.1"
        | "did-management/server/metrics/0.1"
        | "did-management/stats/get/0.1"
        | "did-management/identity/list/0.1"
        | "auth/passkey/login/start/0.2"
        | "auth/passkey/enroll/invite/list/0.1" => json!({}),
        "did-management/did/change-owner/0.1" => {
            seed_did(state, &admin.did, &slot).await;
            let heir = member(state, 100 + (n % 150) as u8, Role::Owner).await;
            json!({ "mnemonic": slot, "newOwner": heir.did })
        }
        "did-management/did/set-state/0.1" => {
            seed_did(state, &admin.did, &slot).await;
            json!({ "mnemonic": slot, "state": "suspended" })
        }
        "did-management/did/rollback/0.1" => {
            seed_published(state, &admin.did, &slot).await;
            json!({ "mnemonic": slot, "targetVersion": 1 })
        }
        "did-management/did/log/0.1" => {
            seed_published(state, &admin.did, &slot).await;
            json!({ "mnemonic": slot, "raw": true })
        }
        "webvh/witness/publish/0.1" => {
            seed_did(state, &admin.did, &slot).await;
            json!({ "mnemonic": slot, "witness": {} })
        }
        "did-management/agent-name/update/0.1" => {
            seed_did(state, &admin.did, &slot).await;
            json!({ "mnemonic": slot, "name": "alice", "state": "active", "didData": "not a log" })
        }
        "did-management/agent-name/remove/0.1" => {
            seed_did(state, &admin.did, &slot).await;
            json!({ "mnemonic": slot, "name": "alice", "didData": "not a log" })
        }
        "did-management/agent-name/check/0.1" => {
            json!({ "name": "alice", "domain": "example.com" })
        }
        "did-management/agent-name/resolve/0.1" => {
            json!({ "dids": [format!("did:webvh:abc:control.test:{slot}")] })
        }
        "did-management/domain/create/0.1" => {
            json!({ "name": format!("d{n}.example.com"), "setAsDefault": false })
        }
        "did-management/domain/update/0.1" | "did-management/domain/set-default/0.1" => {
            json!({ "name": "nowhere.example.com" })
        }
        "did-management/domain/set-state/0.1" => {
            json!({ "name": "nowhere.example.com", "state": "disabled" })
        }
        "did-management/domain/purge/0.1" => {
            json!({ "name": "nowhere.example.com", "purgeServers": false })
        }
        "did-management/domain/assign/0.1"
        | "did-management/domain/unassign/0.1"
        | "did-management/registry/purge-domain/0.1" => {
            json!({ "domain": "nowhere.example.com", "instanceId": "nobody" })
        }
        "did-management/registry/get/0.1"
        | "did-management/registry/check/0.1"
        | "did-management/registry/deregister/0.1" => json!({ "instanceId": "nobody" }),
        "did-management/registry/admin-register/0.1" => json!({
            "instanceId": format!("edge-{n}"),
            "did": format!("did:example:edge-{n}"),
            "publicUrl": format!("https://edge-{n}.example.com"),
        }),
        "did-management/stats/timeseries/0.1" => json!({ "range": "lastHour" }),
        "did-management/identity/retire/0.1" => json!({ "generationId": 999 }),
        "auth/step-up/start/0.1" => json!({ "sessionId": "no-such-session" }),
        "auth/step-up/approve-response/0.5" => json!({
            "challenge": "0123456789abcdef0123456789abcdef",
            "decision": "approved",
            "subject": admin.did,
            "sessionId": "no-such-session",
        }),
        "auth/passkey/login/finish/0.2" => {
            json!({ "authId": "no-such-ceremony", "credential": assertion() })
        }
        "auth/passkey/enroll/invite/update/0.1" => {
            json!({ "inviteId": "no-such-invite", "role": "owner" })
        }
        "auth/passkey/enroll/invite/revoke/0.1" => json!({ "inviteId": "no-such-invite" }),
        other => panic!("no sample for {other}: add one when adding a row"),
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
            assert!(
                is_served(&reply),
                "{via:?} {type_uri} was not served: {reply}"
            );
            if reply["type"] == format!("{type_uri}#response") {
                conforms(&reply);
                assert_eq!(reply["issuer"], CONTROL, "{via:?} {type_uri}: {reply}");
                assert!(
                    reply["proof"].is_object(),
                    "{via:?} {type_uri}: reply is signed"
                );
            }
        }
    }
}

#[tokio::test]
async fn an_unsigned_request_is_refused_where_a_proof_is_required() {
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

/// An operational request (and a session ceremony) signed as an attestation,
/// and an approver's decision signed as an operational message, are each
/// refused: the proof purpose must match the key relationship the task names.
#[tokio::test]
async fn a_proof_under_the_wrong_key_relationship_is_refused() {
    let (state, _dir) = state().await;
    let admin = member(&state, 3, Role::Admin).await;
    let mut n = 2000;
    for (type_uri, rule) in TASKS {
        if *rule == ProofRule::Optional {
            continue;
        }
        for via in VIAS {
            n += 1;
            let payload = sample(&state, &admin, n, type_uri).await;
            let doc = request(type_uri, &admin.did, payload);
            let doc = match rule {
                ProofRule::AssertionMethod => signed(doc, &admin.key).await,
                _ => signed_as_assertion(doc, &admin.key).await,
            };
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
        if matches!(rule, ProofRule::Optional | ProofRule::SessionKey) {
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

/// A proof that is present is verified even where none is required.
#[tokio::test]
async fn an_optional_proof_that_does_not_verify_is_refused() {
    let (state, _dir) = state().await;
    let admin = member(&state, 6, Role::Admin).await;
    for (type_uri, rule) in TASKS {
        if *rule != ProofRule::Optional {
            continue;
        }
        for via in VIAS {
            // Signed, then altered: the proof no longer covers the document.
            let mut doc = signed(request(type_uri, &admin.did, json!({})), &admin.key).await;
            doc["id"] = json!(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
            let reply = send(&state, via, &admin, doc).await;
            assert!(
                matches!(code(&reply).as_str(), "proofInvalid" | "permissionDenied"),
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

// ---------------------------------------------------------------------------
// The rest of the control plane: slots, domains, fleet, service, auth
// ---------------------------------------------------------------------------

const SPEC: &str = "https://trusttasks.org/spec/";

fn t(slug: &str) -> String {
    format!("{SPEC}{slug}")
}

/// A live session for `caller`, as a login would leave it.
async fn session_for(
    state: &AppState,
    caller: &Caller,
) -> did_hosting_common::server::auth::session::TokenResponse {
    did_hosting_common::server::auth::session::create_authenticated_session(
        &state.sessions_ks,
        state.jwt_keys.as_deref().unwrap(),
        &caller.did,
        &caller.role,
        900,
        3600,
        None,
        None,
    )
    .await
    .unwrap()
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
        &t("auth/step-up/start/0.1"),
        json!({ "sessionId": tokens.session_id }),
    )
    .await;
    conforms(&reply);
    let request = ok(&reply, &t("auth/step-up/start/0.1"))["approveRequest"].clone();
    assert_eq!(request["type"], t("auth/step-up/approve-request/0.3"));
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
            &t("auth/step-up/approve-response/0.5"),
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
        &t("auth/step-up/approve-response/0.5"),
        decision.clone(),
    )
    .await;
    conforms(&reply);
    let body = ok(&reply, &t("auth/step-up/approve-response/0.5"));
    assert_eq!(body["status"], "elevated");
    assert_eq!(body["session"]["acr"], "aal2");

    // The challenge is single use.
    let reply = call(
        &state,
        Via::Https,
        &owner,
        &t("auth/step-up/approve-response/0.5"),
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
        &t("auth/refresh/0.1"),
        json!({ "refreshToken": tokens.refresh_token }),
    )
    .await;
    let body = ok(&reply, &t("auth/refresh/0.1"));
    assert_eq!(body["session"]["acr"], "aal2", "{body}");
    let access = body["tokens"]["accessToken"].as_str().unwrap();
    let claims = state.jwt_keys.as_deref().unwrap().decode(access).unwrap();
    assert_eq!(claims.acr, "aal2");

    // An elevated session needs no further step-up.
    let reply = call(
        &state,
        Via::Tsp,
        &owner,
        &t("auth/step-up/start/0.1"),
        json!({ "sessionId": tokens.session_id }),
    )
    .await;
    assert_eq!(code(&reply), "auth/step-up/start:notNeeded", "{reply}");
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
        &t("auth/step-up/start/0.1"),
        json!({ "sessionId": tokens.session_id }),
    )
    .await;
    assert_eq!(code(&reply), "auth/step-up/start:sessionUnknown", "{reply}");
}

/// An unsigned request document from `issuer`, for tests that sign it
/// themselves.
fn request_doc(type_uri: &str, issuer: &str, payload: Value) -> Value {
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

/// Passkey login opens unsigned; with no passkeys registered it says so.
#[tokio::test]
async fn passkey_login_start_is_open_to_an_unsigned_request() {
    let (state, _dir) = state().await;
    let uri = t("auth/passkey/login/start/0.2");
    let mut doc = request(&uri, "unused", json!({}));
    doc.as_object_mut().unwrap().remove("issuer");
    let reply = https(&state, None, doc).await;
    assert_eq!(
        code(&reply),
        "auth/passkey/login/start:noCredentials",
        "{reply}"
    );
}

/// Invites are addressed by inviteId, and no read sends a token back.
#[tokio::test]
async fn invites_are_managed_by_invite_id_and_never_disclose_a_token() {
    let (state, _dir) = state().await;
    let admin = member(&state, 43, Role::Admin).await;
    let created = did_hosting_common::server::passkey::routes::create_enrollment_invite(
        &state.sessions_ks,
        "http://control.test",
        3600,
        "did:example:invitee",
        "owner",
    )
    .await
    .unwrap();

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

    // A role change may ride alongside an expiry change — the spec's `oneOf`
    // only pits `expiresAt` against `extendBy`, not either against `role`.
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/update/0.1"),
        json!({ "inviteId": created.invite_id, "role": "owner", "expiresAt": "2099-01-01T00:00:00Z" }),
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

    // `expiresAt` and `extendBy` are mutually exclusive.
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("auth/passkey/enroll/invite/update/0.1"),
        json!({ "inviteId": created.invite_id, "expiresAt": "2099-01-01T00:00:00Z", "extendBy": 60 }),
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

/// Domains, end to end; purging needs a stepped-up session.
#[tokio::test]
async fn domains_are_administered_over_trust_tasks() {
    let (state, _dir) = state().await;
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

    let list = t("did-management/domain/list/0.1");
    let reply = call(&state, Via::Tsp, &admin, &list, json!({})).await;
    conforms(&reply);
    let body = ok(&reply, &list);
    assert_eq!(body["default"], "a.example.com");
    assert_eq!(body["domains"].as_array().unwrap().len(), 2);

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
    let register = t("did-management/registry/admin-register/0.1");
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

    for slug in ["registry/get/0.1", "registry/check/0.1"] {
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
    let list = t("did-management/registry/list/0.1");
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
    let uri = t("did-management/stats/timeseries/0.1");
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

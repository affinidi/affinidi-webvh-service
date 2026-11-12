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

/// The rows signed by a DID the service knows — every row but the bound-key
/// ones (`ProofRule::BoundKey`, wallet sign-in), whose parties are keys the
/// exchange binds and which have their own tests below
/// (`bound_key_rows_…`).
fn did_signed_rows() -> impl Iterator<Item = &'static (&'static str, ProofRule)> {
    TASKS
        .iter()
        .filter(|(_, rule)| !matches!(rule, ProofRule::BoundKey(_)))
}

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

/// A WebAuthn attestation in the shape the schema requires — it will not
/// verify either.
fn attestation() -> Value {
    json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": { "attestationObject": "AAAA", "clientDataJSON": "AAAA" },
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
        "did-management/stats/set-resolution/0.1" => {
            seed_did(state, &admin.did, &slot).await;
            json!({ "mnemonic": slot, "resolution": "coarse" })
        }
        "did-management/did/list/0.2"
        | "did-management/me/domains/0.1"
        | "did-management/domain/list/0.1"
        | "did-management/registry/list/0.2"
        | "did-management/server/info/0.1"
        | "did-management/server/config/0.1"
        | "did-management/server/metrics/0.1"
        | "did-management/stats/get/0.1"
        | "did-management/identity/list/0.1"
        | "auth/passkey/login/start/0.2"
        | "auth/passkey/enroll/invite/list/0.1"
        | "auth/passkey/enroll/start/0.2" => json!({}),
        "auth/passkey/enroll/invite/0.3" => {
            json!({ "subject": format!("did:example:invitee-{n}") })
        }
        "auth/passkey/enroll/redeem/start/0.1" => {
            json!({ "token": "inv_no-such-invite-token", "claimCode": "0000-0000-0000" })
        }
        "auth/passkey/enroll/redeem/finish/0.1" | "auth/passkey/enroll/finish/0.2" => {
            json!({ "enrollmentId": "no-such-enrolment", "credential": attestation() })
        }
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
        "did-management/registry/get/0.2"
        | "did-management/registry/check/0.2"
        | "did-management/registry/deregister/0.1" => json!({ "instanceId": "nobody" }),
        "did-management/registry/admin-register/0.2" => json!({
            "instanceId": format!("edge-{n}"),
            "did": format!("did:example:edge-{n}"),
            "publicUrl": format!("https://edge-{n}.example.com"),
        }),
        "did-management/stats/timeseries/0.2" => json!({ "range": "lastHour" }),
        "did-management/identity/retire/0.1" => json!({ "generationId": 999 }),
        "auth/step-up/start/0.2" => json!({ "sessionId": "no-such-session" }),
        "auth/step-up/approve-response/0.7" => json!({
            "challenge": "0123456789abcdef0123456789abcdef",
            "decision": "approved",
            "subject": admin.did,
            "sessionId": "no-such-session",
        }),
        "auth/revoke-session/0.2" => json!({ "sessionId": "no-such-session" }),
        "auth/passkey/login/finish/0.2" => {
            json!({ "authId": "no-such-ceremony", "credential": assertion() })
        }
        "auth/passkey/enroll/invite/update/0.1" => {
            json!({ "inviteId": "no-such-invite", "role": "owner" })
        }
        "auth/passkey/enroll/invite/revoke/0.1" => json!({ "inviteId": "no-such-invite" }),
        "auth/passkey/list/0.1" => json!({}),
        "auth/passkey/admin-list/0.1" => json!({ "subject": admin.did, "purpose": "session" }),
        "auth/passkey/revoke/start/0.2" => json!({ "credentialId": "AAAA" }),
        "auth/passkey/revoke/finish/0.2" => {
            json!({ "revocationId": "no-such-revocation", "uvCredential": assertion() })
        }
        other => panic!("no sample for {other}: add one when adding a row"),
    }
}

#[tokio::test]
async fn every_row_is_served_on_every_transport() {
    let (state, _dir) = state().await;
    let admin = member(&state, 1, Role::Admin).await;
    let mut n = 0;
    for (type_uri, _) in did_signed_rows() {
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
    for (type_uri, rule) in did_signed_rows() {
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
    for (type_uri, rule) in did_signed_rows() {
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
    for (type_uri, rule) in did_signed_rows() {
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

const LIST: &str = "https://trusttasks.org/spec/did-management/did/list/0.2";
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

const REGISTER: &str = "https://trusttasks.org/spec/did-management/did/register/0.1";

/// The `hyperledger-labs/did-webs-resolver` reference publication: a
/// `keri.cesr` stream, registered over the Trust Task a VTA publishes with.
const WEBS_KERI: &[u8] =
    include_bytes!("../../../did-hosting-common/tests/fixtures/ENro7uf0.keri.cesr");
const WEBS_AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

fn webs_register(domain: &str) -> Value {
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
async fn owner_rows(state: &AppState, owner: &str, heir: &str) -> (usize, usize) {
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
async fn limited_member(
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

const TARGET_NOT_AUTHORIZED: &str = "did-management/did/change-owner:targetNotAuthorized";
const NOT_OWNER: &str = "did-management/did/change-owner:notOwner";

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
async fn seed_witnessed_genesis(
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

// ---------------------------------------------------------------------------
// The rest of the control plane: slots, domains, fleet, service, auth
// ---------------------------------------------------------------------------

const SPEC: &str = "https://trusttasks.org/spec/";

fn t(slug: &str) -> String {
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
async fn seed_named(state: &AppState, mnemonic: &str, did_id: &str, names: &[(&str, bool)]) {
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
async fn anonymous_server_info(state: &AppState) -> Value {
    let uri = t("did-management/server/info/0.1");
    let mut doc = request(&uri, "unused", json!({}));
    doc.as_object_mut().unwrap().remove("issuer");
    ok(&https(state, None, doc).await, &uri)
}

fn names_of(info: &Value) -> Vec<String> {
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
        trust_task_capable: false,
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

// ---------------------------------------------------------------------------
// The gate model: bound-key rows, and every other row exactly as before
// ---------------------------------------------------------------------------

/// Every row that is not a bound-key row keeps the rule it had before
/// bound-key rows existed — so the gate refuses for each exactly what it
/// refused (the table-wide tests above run over these same rows).
#[test]
fn existing_rows_keep_their_proof_rules() {
    const BEFORE: &[(&str, ProofRule)] = &[
        (
            "https://trusttasks.org/spec/did-management/did/check-name/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/register/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/info/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/list/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/delete/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/change-owner/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/set-state/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/rollback/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/log/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/webvh/witness/publish/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/update/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/remove/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/check/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/resolve/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/me/domains/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/create/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/update/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/set-state/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/set-default/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/purge/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/assign/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/unassign/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/list/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/get/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/check/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/admin-register/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/deregister/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/purge-domain/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/server/info/0.1",
            ProofRule::Optional,
        ),
        (
            "https://trusttasks.org/spec/did-management/server/config/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/server/metrics/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/stats/get/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/stats/set-resolution/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/stats/timeseries/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/identity/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/identity/retire/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/step-up/start/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/step-up/approve-response/0.7",
            ProofRule::AssertionMethod,
        ),
        (
            "https://trusttasks.org/spec/auth/revoke-session/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/login/start/0.2",
            ProofRule::Optional,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/login/finish/0.2",
            ProofRule::SessionKey,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/invite/0.3",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/redeem/start/0.1",
            ProofRule::Optional,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/redeem/finish/0.1",
            ProofRule::Optional,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/start/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/finish/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/invite/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/invite/update/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/invite/revoke/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/admin-list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/revoke/start/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/revoke/finish/0.2",
            ProofRule::Authentication,
        ),
    ];
    let now: Vec<_> = did_signed_rows().copied().collect();
    assert_eq!(now, BEFORE);
}

/// The bound-key rows are exactly wallet sign-in's six outer tasks, each at
/// its latest version only, each accepting the two proof purposes its
/// clients sign for. `identify` and `grant` are carried, never rows.
#[test]
fn bound_key_rows_are_wallet_sign_in_and_nothing_else() {
    use crate::oob::types::*;
    let bound: Vec<_> = TASKS
        .iter()
        .filter_map(|(uri, rule)| match rule {
            ProofRule::BoundKey(purposes) => Some((*uri, *purposes)),
            _ => None,
        })
        .collect();
    let purposes: &[&str] = &["authentication", "assertionMethod"];
    assert_eq!(
        bound,
        [
            TYPE_REQUEST,
            TYPE_CLAIM,
            TYPE_PROVE,
            TYPE_RESPOND,
            TYPE_REDEEM,
            TYPE_CANCEL
        ]
        .map(|uri| (uri, purposes))
    );
    for carried in [TYPE_IDENTIFY, TYPE_GRANT] {
        assert_eq!(super::proof_rule(carried), None, "{carried} is not a row");
    }
    // Only a bound-key row sets the bearer session and the shared replay
    // cache aside.
    for (uri, rule) in TASKS {
        let bound = matches!(rule, ProofRule::BoundKey(_));
        assert_eq!(rule.admits_bearer(), !bound, "{uri}");
        assert_eq!(rule.uses_shared_replay_cache(), !bound, "{uri}");
        assert_eq!(
            crate::messaging::session_key_may_sign(uri),
            *rule == ProofRule::Authentication,
            "{uri}"
        );
    }
}

/// A `redeem` from a starter key `K_b`, for `request_id`.
async fn redeem_doc(starter: &Caller, request_id: &str, purpose: &str) -> Value {
    let doc = request(
        crate::oob::types::TYPE_REDEEM,
        &starter.did,
        json!({ "requestId": request_id }),
    );
    match purpose {
        "authentication" => signed(doc, &starter.key).await,
        "assertionMethod" => signed_as_assertion(doc, &starter.key).await,
        other => {
            use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
            sign_trust_task(
                &doc,
                &starter.key,
                SignOptions::new()
                    .with_proof_purpose(other)
                    .with_cryptosuite(CryptoSuite::EddsaJcs2022),
            )
            .await
            .expect("sign")
        }
    }
}

const NO_SUCH_REQUEST: &str = "AAAAAAAAAAAAAAAAAAAAAA";

/// A bound-key document reaches its row over HTTPS, and nowhere else: on the
/// messaging transports the gate refuses it before anything else.
#[tokio::test]
async fn bound_key_rows_are_served_over_https_only() {
    let (state, _dir) = state().await;
    let starter = stranger(60);
    for via in VIAS {
        let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
        let reply = send(&state, via, &starter, doc).await;
        match via {
            // Reached the state machine: no such request.
            Via::Https => assert_eq!(code(&reply), "auth/oob:requestNotFound", "{reply}"),
            _ => {
                assert_eq!(code(&reply), "permissionDenied", "{via:?}: {reply}");
                assert!(
                    reply["payload"]["message"]
                        .as_str()
                        .is_some_and(|m| m.contains("HTTPS only")),
                    "{via:?}: {reply}"
                );
            }
        }
    }
}

/// A wallet sends `prove` at the newest version it knows and falls back only
/// on an `unsupportedType` refusal (pnm-browser-plugin `sign-in-flows`). Both
/// versions this service serves reach the state machine over HTTPS, and a
/// version it does not serve, signed by a stranger's `did:key`, must be
/// refused with exactly that code, or the wallet gives up instead of falling
/// back.
#[tokio::test]
async fn an_unserved_prove_version_is_unsupported_so_a_wallet_falls_back() {
    let (state, _dir) = state().await;
    let approver = stranger(64);
    let prove = |type_uri: &'static str| {
        let approver = &approver;
        async move {
            let mut doc = request(type_uri, &approver.did, json!({ "identify": {} }));
            doc["parentThreadId"] = json!(NO_SUCH_REQUEST);
            signed(doc, &approver.key).await
        }
    };
    let served = crate::oob::types::TYPE_PROVE;
    let reply = https(&state, None, prove(served).await).await;
    assert_ne!(code(&reply), "unsupportedType", "{served}: {reply}");
    // Only the latest version is served: an older one is refused exactly as
    // a newer one nobody serves is.
    for unserved in [
        "https://trusttasks.org/spec/auth/oob/prove/0.1",
        "https://trusttasks.org/spec/auth/oob/prove/0.2",
        "https://trusttasks.org/spec/auth/oob/prove/0.99",
    ] {
        let reply = https(&state, None, prove(unserved).await).await;
        assert!(
            code(&reply).ends_with("unsupportedType"),
            "{unserved}: {reply}"
        );
    }
}

/// A bearer session sent with a bound-key document is ignored. Were it
/// context, the session-binding check would refuse a proof by `K_b` — which is
/// neither the session subject's key nor its session key — as `proofInvalid`.
#[tokio::test]
async fn bound_key_rows_ignore_a_bearer_session() {
    let (state, _dir) = state().await;
    let admin = member(&state, 61, Role::Admin).await;
    let bearer = crate::auth::AuthClaims {
        did: admin.did.clone(),
        role: Role::Admin,
        session_id: "s".into(),
        session_pubkey_b58btc: None,
        amr: vec!["did".into()],
        acr: "aal2".into(),
    };
    let starter = stranger(62);
    let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    let reply = https(&state, Some(bearer), doc).await;
    assert_eq!(code(&reply), "auth/oob:requestNotFound", "{reply}");
}

/// The gate's proof check for a bound-key row: an Ed25519 `did:key` issuer,
/// a proof by exactly that key, for a purpose the row lists. Each refusal is
/// in the family's own codes, as the state machine itself would refuse.
#[tokio::test]
async fn bound_key_rows_need_a_proof_by_the_issuer_key_for_a_listed_purpose() {
    let (state, _dir) = state().await;
    let starter = stranger(63);
    for purpose in ["authentication", "assertionMethod"] {
        let doc = redeem_doc(&starter, NO_SUCH_REQUEST, purpose).await;
        let reply = https(&state, None, doc).await;
        assert_eq!(
            code(&reply),
            "auth/oob:requestNotFound",
            "{purpose}: {reply}"
        );
    }
    // A purpose the row does not list.
    let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "capabilityInvocation").await;
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:notAuthorized"
    );
    // Unsigned.
    let doc = request(
        crate::oob::types::TYPE_REDEEM,
        &starter.did,
        json!({ "requestId": NO_SUCH_REQUEST }),
    );
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:notAuthorized"
    );
    // Signed by another key than the one the issuer names.
    let other = stranger(64);
    let mut doc = redeem_doc(&other, NO_SUCH_REQUEST, "authentication").await;
    doc["issuer"] = json!(starter.did);
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:notAuthorized"
    );
    // Tampered after signing.
    let mut doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    doc["payload"]["requestId"] = json!("BBBBBBBBBBBBBBBBBBBBBB");
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:notAuthorized"
    );
    // An issuer that is not an Ed25519 did:key, even one in the ACL: decided
    // from the identifier, before any DID is resolved.
    let admin = member(&state, 65, Role::Admin).await;
    let mut doc = redeem_doc(&admin, NO_SUCH_REQUEST, "authentication").await;
    doc["issuer"] = json!("did:webvh:abc:control.test:alice");
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:keyUnsupported"
    );
}

/// The shared replay cache is not spent by a bound-key document — the row's
/// own cache is (and only for a live request, `oob::tests`): keys like these
/// cost nothing to mint, and the shared cache fails closed for every task.
#[tokio::test]
async fn bound_key_rows_do_not_touch_the_shared_replay_cache() {
    let (state, _dir) = state().await;
    let starter = stranger(66);
    let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    let id = doc["id"].as_str().unwrap().to_string();
    let before = state.replay_cache.len();
    let reply = https(&state, None, doc).await;
    assert_eq!(code(&reply), "auth/oob:requestNotFound", "{reply}");
    assert_eq!(state.replay_cache.len(), before);
    assert!(
        state
            .replay_cache
            .check(&starter.did, &id, Some(chrono::Utc::now()))
            .is_ok()
    );
}

/// A bound-key row's admission runs before the gate does any proof work: past
/// its per-address limit, a document is refused as rate limited whether or
/// not its proof would verify.
#[tokio::test]
async fn bound_key_admission_runs_before_the_proof_check() {
    use crate::oob::http::OTHER_MAX_PER_MINUTE;
    let (state, _dir) = state().await;
    let starter = stranger(67);
    for n in 0..OTHER_MAX_PER_MINUTE {
        let mut doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
        doc["proof"]["proofValue"] = json!("zBad");
        let reply = https(&state, None, doc).await;
        assert_eq!(code(&reply), "auth/oob:notAuthorized", "{n}: {reply}");
    }
    let mut doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    doc["proof"]["proofValue"] = json!("zBad");
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:rateLimited"
    );
}

/// A bound-key document over the family's 32 KiB cap is refused at
/// admission, before its proof is looked at — even one that would verify.
#[tokio::test]
async fn bound_key_rows_refuse_an_oversized_document_before_its_proof() {
    use crate::oob::http::MAX_OOB_DOCUMENT_BYTES;
    let (state, _dir) = state().await;
    let starter = stranger(68);
    let mut doc = request(
        crate::oob::types::TYPE_REDEEM,
        &starter.did,
        json!({ "requestId": NO_SUCH_REQUEST }),
    );
    // Under the router's own 64 KiB default, over the family's cap.
    doc["pad"] = json!("x".repeat(MAX_OOB_DOCUMENT_BYTES));
    let doc = signed(doc, &starter.key).await;
    let reply = https(&state, None, doc).await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");
    assert_eq!(reply["payload"]["message"], "document too large", "{reply}");
}

/// A throttled ACL read says nothing about the caller: it is answered as
/// `unavailable` with a retry time (HTTPS: 503 with `Retry-After`), never as
/// "not present in the maintainer's ACL", which reads as a revoked grant.
#[tokio::test]
async fn a_throttled_acl_lookup_asks_for_a_retry_not_a_new_grant() {
    use axum::response::IntoResponse;

    let (mut state, _dir) = state().await;
    let admin = member(&state, 53, Role::Admin).await;
    state.acl_ks = state.acl_ks.throttled_reads();
    let list = t("did-management/domain/list/0.1");

    let reply = call(&state, Via::Tsp, &admin, &list, json!({})).await;
    assert_eq!(code(&reply), "unavailable", "{reply}");
    assert!(reply["payload"]["retryAfter"].is_string(), "{reply}");

    let doc = signed(request(&list, &admin.did, json!({})), &admin.key).await;
    let response = crate::routes::trust_tasks::dispatch_trust_task(
        None,
        axum::extract::State(state.clone()),
        None,
        &axum::http::HeaderMap::new(),
        axum::body::Bytes::from(serde_json::to_vec(&doc).unwrap()),
    )
    .await
    .into_response();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response.headers().get(axum::http::header::RETRY_AFTER),
        Some(&axum::http::HeaderValue::from(
            did_hosting_common::server::error::STORE_THROTTLED_RETRY_AFTER_SECS
        )),
        "the store's hint, not rounded down"
    );
}

/// Past the gate, a task's own ACL read can still be the one throttled: the
/// shared engine's `cx.admin()` and the `acl/*` handlers answer it the same
/// way as the gate, never as "not in the ACL".
#[tokio::test]
async fn a_throttled_acl_read_after_the_gate_asks_for_a_retry() {
    let (state, _dir) = state().await;
    let admin = member(&state, 54, Role::Admin).await;
    let acl_ks = state.acl_ks.clone();
    for slug in ["did-management/domain/list/0.1", "acl/list/0.3"] {
        let mut state = state.clone();
        // One read for the gate, then throttled.
        state.acl_ks = acl_ks.failing_reads_after(
            1,
            did_hosting_common::server::error::AppError::store_throttled,
        );
        let reply = call(&state, Via::Tsp, &admin, &t(slug), json!({})).await;
        assert_eq!(code(&reply), "unavailable", "{slug}: {reply}");
        assert!(
            reply["payload"]["retryAfter"].is_string(),
            "{slug}: {reply}"
        );
    }
}

/// A lookup that fails for any other reason is the maintainer's fault, not a
/// refusal of the sender: `internalError`, which names nothing internal.
#[tokio::test]
async fn a_failed_acl_lookup_is_an_internal_error_not_a_refusal() {
    let (mut state, _dir) = state().await;
    let admin = member(&state, 55, Role::Admin).await;
    state.acl_ks = state.acl_ks.failing_reads_after(0, || {
        did_hosting_common::server::error::AppError::Store("disk failure".into())
    });
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("did-management/domain/list/0.1"),
        json!({}),
    )
    .await;
    assert_eq!(code(&reply), "internalError", "{reply}");
    assert!(!reply.to_string().contains("disk failure"), "{reply}");
}

/// A document refused as `unavailable` did not run, so sending the very same
/// signed document again is a retry, not a replay.
#[tokio::test]
async fn a_document_refused_as_unavailable_can_be_sent_again() {
    let (state, _dir) = state().await;
    let admin = member(&state, 56, Role::Admin).await;
    let list = t("did-management/domain/list/0.1");
    let doc = signed(request(&list, &admin.did, json!({})), &admin.key).await;

    let mut throttled = state.clone();
    throttled.acl_ks = state.acl_ks.failing_reads_after(
        1,
        did_hosting_common::server::error::AppError::store_throttled,
    );
    let reply = send(&throttled, Via::Tsp, &admin, doc.clone()).await;
    assert_eq!(code(&reply), "unavailable", "{reply}");

    let reply = send(&state, Via::Tsp, &admin, doc.clone()).await;
    conforms(&reply);
    ok(&reply, &list);
    // Run once, it is remembered again.
    assert_eq!(
        code(&send(&state, Via::Tsp, &admin, doc).await),
        "idConflict"
    );
}

/// A task refused as `unavailable` after it attempted a write may have applied
/// part of it, so the same document is not run again: a retry is a new one.
#[tokio::test]
async fn a_document_refused_as_unavailable_after_a_write_is_not_run_again() {
    let (state, _dir) = state().await;
    let admin = member(&state, 57, Role::Admin).await;
    let grant = t("acl/grant/0.2");
    let entry = json!({
        "entry": {
            "subject": "did:example:a-new-member",
            "role": "owner",
            "act": { "scope": "all" },
            "keys": { "scope": "none" },
            "capabilities": { "scope": "ceiling" }
        }
    });
    let doc = signed(request(&grant, &admin.did, entry), &admin.key).await;

    let mut throttled = state.clone();
    throttled.acl_ks = state
        .acl_ks
        .throttled_writes_after(std::sync::Arc::new(0.into()));
    let reply = send(&throttled, Via::Tsp, &admin, doc.clone()).await;
    assert_eq!(code(&reply), "unavailable", "{reply}");

    assert_eq!(
        code(&send(&state, Via::Tsp, &admin, doc).await),
        "idConflict"
    );
}

/// A store's per-item size refusal reaches a task that declares no size code
/// (such as `did/register`) as `taskFailed` with the limit in its message,
/// not as an internal failure that hides why.
#[test]
fn a_store_size_refusal_is_a_task_failure_naming_the_limit() {
    use did_hosting_common::server::error::AppError;
    let payload = super::TaskError::App(AppError::QuotaExceeded(
        "item size 431916 bytes is over the store's per-item limit of 409600 bytes".into(),
    ))
    .payload(&[]);
    let payload = serde_json::to_value(payload).expect("serialise the error payload");
    assert_eq!(payload["code"], "taskFailed", "{payload}");
    let message = payload["message"].as_str().unwrap_or_default();
    assert!(message.contains("409600"), "{payload}");
}

// ---------------------------------------------------------------------------
// Signers the ACL does not list (`crate::unlisted_signers`)
// ---------------------------------------------------------------------------

mod unlisted {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use affinidi_data_integrity::{DataIntegrityError, DidKeyResolver, ResolvedKey};
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use did_hosting_common::server::trust_tasks::TransportBoundVerifier;
    use trust_tasks_proof::affinidi::{ProofPurpose, ProofPurposeResolver};

    use crate::unlisted_signers::{SIGN_IN_PER_SOURCE, UnlistedSigners};

    const SERVER_INFO: &str = "did-management/server/info/0.1";
    const CHALLENGE: &str = "auth/challenge/0.1";

    /// Decodes a `did:key` locally; counts every other DID it is asked to
    /// resolve, and then fails as unreachable — or never answers.
    struct CountingResolver {
        calls: Arc<AtomicUsize>,
        hang: bool,
    }

    #[async_trait::async_trait]
    impl ProofPurposeResolver for CountingResolver {
        async fn resolve_vm_for_purpose(
            &self,
            vm: &str,
            purpose: ProofPurpose,
        ) -> Result<ResolvedKey, DataIntegrityError> {
            if vm.starts_with("did:key:") {
                return DidKeyResolver.resolve_vm_for_purpose(vm, purpose).await;
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.hang {
                std::future::pending::<()>().await;
            }
            Err(DataIntegrityError::Resolver(format!(
                "signer DID unreachable: cannot resolve {vm}"
            )))
        }
    }

    /// `state` with a counting resolver behind its verifier and `limits` on
    /// unlisted signers; the count of network resolutions.
    fn counting(state: &mut AppState, hang: bool, limits: UnlistedSigners) -> Arc<AtomicUsize> {
        let calls = Arc::new(AtomicUsize::new(0));
        state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(
            Arc::new(CountingResolver {
                calls: calls.clone(),
                hang,
            }),
        )));
        state.unlisted_signers = Arc::new(limits);
        calls
    }

    fn default_limits() -> UnlistedSigners {
        UnlistedSigners::default()
    }

    /// A caller whose DID has to be resolved over the network.
    fn web_caller(name: &str, seed: u8) -> Caller {
        let did = format!("did:web:{name}.example");
        let mut key = Secret::generate_ed25519(None, Some(&[seed; 32]));
        key.id = format!("{did}#key-1");
        Caller {
            did,
            key,
            role: Role::Owner,
        }
    }

    async fn send_signed(state: &AppState, via: Via, caller: &Caller, slug: &str) -> Value {
        let doc = signed(request(&t(slug), &caller.did, json!({})), &caller.key).await;
        send(state, via, caller, doc).await
    }

    /// An open read changes nothing, so it is recorded nowhere, whoever signs
    /// it, and a resend is simply answered again.
    #[tokio::test]
    async fn open_reads_are_not_recorded() {
        let (state, _dir) = state().await;
        let uri = t(SERVER_INFO);
        let stranger = stranger(70);
        let admin = member(&state, 71, Role::Admin).await;
        for via in VIAS {
            for caller in [&stranger, &admin] {
                let doc = signed(request(&uri, &caller.did, json!({})), &caller.key).await;
                ok(&send(&state, via, caller, doc.clone()).await, &uri);
                ok(&send(&state, via, caller, doc).await, &uri);
            }
        }
        assert!(state.replay_cache.is_empty());
        assert!(state.unlisted_signers.sign_in.is_empty());
        assert!(state.unlisted_signers.other.is_empty());
    }

    /// A sign-in row signed by a stranger is recorded in the sign-in cache,
    /// never the shared one, and its resend is refused; a member's goes to
    /// the shared cache as before.
    #[tokio::test]
    async fn a_strangers_sign_in_is_recorded_apart_from_members() {
        let (state, _dir) = state().await;
        let stranger = stranger(72);
        let doc = signed(
            request(&t(CHALLENGE), &stranger.did, json!({})),
            &stranger.key,
        )
        .await;
        let first = send(&state, Via::Tsp, &stranger, doc.clone()).await;
        assert_ne!(first["payload"]["code"], "unavailable", "{first}");
        assert_eq!(
            code(&send(&state, Via::Tsp, &stranger, doc).await),
            "idConflict"
        );
        assert!(state.replay_cache.is_empty());
        assert_eq!(state.unlisted_signers.sign_in.len(), 1);

        let admin = member(&state, 73, Role::Admin).await;
        send_signed(&state, Via::Tsp, &admin, CHALLENGE).await;
        assert_eq!(state.replay_cache.len(), 1);
        assert_eq!(state.unlisted_signers.sign_in.len(), 1);
    }

    /// However full the sign-in cache is, members are unaffected: only
    /// strangers are told to retry.
    #[tokio::test]
    async fn a_full_sign_in_cache_does_not_refuse_members() {
        let (state, _dir) = state().await;
        let now = Some(chrono::Utc::now());
        let max = crate::unlisted_signers::SIGN_IN_MAX_ENTRIES;
        for i in 0..2 * max {
            let _ = state.unlisted_signers.sign_in.check(
                &format!("did:key:filler-{}", i / 50),
                &format!("urn:uuid:{i}"),
                now,
            );
        }
        assert_eq!(state.unlisted_signers.sign_in.len(), max);

        let stranger = stranger(74);
        assert_eq!(
            code(&send_signed(&state, Via::Tsp, &stranger, CHALLENGE).await),
            "unavailable"
        );
        let admin = member(&state, 75, Role::Admin).await;
        let reply = send_signed(&state, Via::Tsp, &admin, CHALLENGE).await;
        assert_ne!(reply["payload"]["code"], "unavailable", "{reply}");
        ok(
            &send_signed(&state, Via::Tsp, &admin, "did-management/server/config/0.1").await,
            &t("did-management/server/config/0.1"),
        );
    }

    /// A document recorded in one cache is a replay whichever cache it would
    /// go to now (the signer's ACL entry changed inside the window).
    #[tokio::test]
    async fn a_record_in_another_cache_is_a_replay() {
        let (state, _dir) = state().await;
        let admin = member(&state, 76, Role::Admin).await;
        let doc = signed(request(&t(CHALLENGE), &admin.did, json!({})), &admin.key).await;
        let id = doc["id"].as_str().unwrap();
        state
            .unlisted_signers
            .sign_in
            .check(&admin.did, id, Some(chrono::Utc::now()))
            .unwrap();
        assert_eq!(
            code(&send(&state, Via::Tsp, &admin, doc).await),
            "idConflict"
        );
        assert!(state.replay_cache.is_empty());
    }

    /// One source may add only so many sign-in records per window.
    #[tokio::test]
    async fn sign_in_records_are_limited_per_source() {
        let (state, _dir) = state().await;
        for i in 0..SIGN_IN_PER_SOURCE {
            let caller = stranger((i % 200) as u8);
            let reply = send_signed(&state, Via::Https, &caller, CHALLENGE).await;
            assert_ne!(reply["payload"]["code"], "unavailable", "{i}: {reply}");
        }
        let reply = send_signed(&state, Via::Https, &stranger(201), CHALLENGE).await;
        assert_eq!(code(&reply), "unavailable", "{reply}");
        assert!(reply["payload"]["retryAfter"].is_string(), "{reply}");
        // Another source is unaffected.
        let other = stranger(202);
        let reply = send_signed(&state, Via::Tsp, &other, CHALLENGE).await;
        assert_ne!(reply["payload"]["code"], "unavailable", "{reply}");
    }

    /// A stranger's proof that needs a network resolution waits for a free
    /// slot (refused before any resolution while none is); one that fails
    /// the key-free checks never resolves; a `did:key` needs no slot.
    #[tokio::test]
    async fn unlisted_resolutions_need_a_free_slot() {
        let (mut state, _dir) = state().await;
        let calls = counting(&mut state, false, default_limits());
        let web = web_caller("unlisted", 77);

        let held = state.unlisted_signers.occupy_all();
        assert_eq!(
            code(&send_signed(&state, Via::Tsp, &web, SERVER_INFO).await),
            "unavailable"
        );
        let mut wrong = request(&t(SERVER_INFO), &web.did, json!({}));
        wrong["recipient"] = json!("did:example:elsewhere");
        let wrong = signed(wrong, &web.key).await;
        assert_eq!(
            code(&send(&state, Via::Tsp, &web, wrong).await),
            "wrongRecipient"
        );
        let local = stranger(78);
        ok(
            &send_signed(&state, Via::Tsp, &local, SERVER_INFO).await,
            &t(SERVER_INFO),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(held);

        // With a slot free the resolution is made, once (no forced retry),
        // and its failure is reported as retryable.
        assert_eq!(
            code(&send_signed(&state, Via::Tsp, &web, SERVER_INFO).await),
            "unavailable"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Strangers share a rate of resolutions; past it, a document is refused
    /// with a retry time and nothing is resolved.
    #[tokio::test]
    async fn unlisted_resolutions_share_a_rate() {
        let (mut state, _dir) = state().await;
        let calls = counting(
            &mut state,
            false,
            UnlistedSigners::with_limits(16, 3, Duration::from_secs(10)),
        );
        let web = web_caller("rated", 79);
        for _ in 0..3 {
            send_signed(&state, Via::Tsp, &web, SERVER_INFO).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let reply = send_signed(&state, Via::Tsp, &web, SERVER_INFO).await;
        assert_eq!(code(&reply), "unavailable", "{reply}");
        assert!(reply["payload"]["retryAfter"].is_string(), "{reply}");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// A resolution that never answers is abandoned at the timeout and
    /// reported as retryable.
    #[tokio::test]
    async fn unlisted_resolutions_time_out() {
        let (mut state, _dir) = state().await;
        let calls = counting(
            &mut state,
            true,
            UnlistedSigners::with_limits(16, 300, Duration::from_millis(50)),
        );
        let web = web_caller("silent", 80);
        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            send_signed(&state, Via::Tsp, &web, SERVER_INFO),
        )
        .await
        .expect("the request completes at the verification timeout");
        assert_eq!(code(&reply), "unavailable", "{reply}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A proxied `auth/authenticate/0.3` from `delegate` for `principal`,
    /// carrying a mandate `mandate_signer` signed naming `named_delegate`.
    async fn proxied(
        delegate: &Caller,
        principal: &str,
        mandate_signer: &Secret,
        named_delegate: &str,
    ) -> Value {
        let mandate = signed_as_assertion(
            request(
                "https://trusttasks.org/spec/local/did-hosting-auth-mandate/0.1",
                principal,
                json!({ "delegate": named_delegate }),
            ),
            mandate_signer,
        )
        .await;
        signed(
            request(
                &t("auth/authenticate/0.3"),
                &delegate.did,
                json!({
                    "challenge": "not-a-live-challenge",
                    "sessionId": uuid::Uuid::new_v4().to_string(),
                    "principal": principal,
                    "delegationEvidence": { "kind": "mandateCredential", "credential": mandate },
                }),
            ),
            &delegate.key,
        )
        .await
    }

    /// A proxied login naming a principal outside the ACL is refused before
    /// its evidence is checked: nothing it names is resolved.
    #[tokio::test]
    async fn a_proxied_login_for_a_stranger_resolves_nothing() {
        let (mut state, _dir) = state().await;
        let calls = counting(&mut state, false, default_limits());
        let delegate = stranger(81);
        let principal = web_caller("principal", 82);
        let doc = proxied(&delegate, &principal.did, &principal.key, &delegate.did).await;
        let reply = send(&state, Via::Tsp, &delegate, doc).await;
        assert_eq!(code(&reply), "permissionDenied", "{reply}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// The delegate of a member who signed a mandate naming it is verified
    /// as members are, not under the strangers' resolution slots; a delegate
    /// the mandate does not name is not.
    #[tokio::test]
    async fn a_members_delegate_is_not_held_to_the_strangers_slots() {
        let (mut state, _dir) = state().await;
        let calls = counting(&mut state, false, default_limits());
        let principal = member(&state, 83, Role::Owner).await;
        let delegate = web_caller("delegate", 84);
        let _held = state.unlisted_signers.occupy_all();

        let unnamed = proxied(
            &delegate,
            &principal.did,
            &principal.key,
            "did:web:other.example",
        )
        .await;
        assert_eq!(
            code(&send(&state, Via::Tsp, &delegate, unnamed).await),
            "unavailable"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let vouched = proxied(&delegate, &principal.did, &principal.key, &delegate.did).await;
        send(&state, Via::Tsp, &delegate, vouched).await;
        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "the delegate was resolved"
        );
    }
}

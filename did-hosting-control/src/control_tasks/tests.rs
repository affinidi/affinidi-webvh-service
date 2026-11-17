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

// The table's tests, by family. Helpers shared across them are visible to
// each through `super::*`.
mod agent_name;
mod did;
mod did_list;
mod gate;
mod platform;
mod step_up_gated;
mod unlisted;

#[allow(unused_imports)]
use self::{agent_name::*, did::*, did_list::*, gate::*, platform::*};

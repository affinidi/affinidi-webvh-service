//! Tests for the control plane's inbound dispatch: the trust-task gate, the
//! infra handlers and the DIDComm router.

use std::path::PathBuf;
use std::sync::Arc;

use affinidi_messaging_didcomm::Message;
use did_hosting_common::did_ops::{DidRecord, did_key, owner_key};
use did_hosting_common::server::acl::{AclEntry, Role, store_acl_entry};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};

use did_hosting_common::server::store::Store;
use serde_json::json;

use crate::config::{AppConfig, RegistryConfig};
use crate::server::AppState;

use super::*;

use did_hosting_common::tasks::auth::authenticate::v0_3 as authenticate;
use did_hosting_common::tasks::did_management::did::{check_name, delete};
use trust_tasks_rs::Payload as _;

const AUTHENTICATE: &str = authenticate::Payload::TYPE_URI;
const CHECK_NAME: &str = check_name::v0_1::Payload::TYPE_URI;
const DELETE: &str = delete::v0_1::Payload::TYPE_URI;
const DELETE_RESPONSE: &str = delete::v0_1::Response::TYPE_URI;

#[test]
fn stats_sync_accepts_only_hosted_path_shapes() {
    for ok in [
        "alice",
        "org/team",
        ".well-known",
        "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    ] {
        assert!(is_stats_mnemonic(ok), "{ok} should be accepted");
    }
    for bad in ["", "_all", "a:b", "ts:_all:300", "/alice", "Alice/bob"] {
        assert!(!is_stats_mnemonic(bad), "{bad} should be refused");
    }
}

/// A path outside the current grammar may still be a hosted legacy
/// path, but never one that could break a `ts:` key or alias `_all`.
#[test]
fn legacy_stats_paths_must_be_key_safe() {
    assert!(is_key_safe_stats_path("Alice/bob"));
    for bad in ["", "_all", "a:b", "ts:_all:300", "a\nb"] {
        assert!(!is_key_safe_stats_path(bad), "{bad:?} should be refused");
    }
}

/// Build a minimal `AppState` backed by a tempdir-rooted fjall store. The
/// returned `_dir` guard must outlive `state` — when it drops, fjall
/// removes the partition files on disk.
async fn test_state() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");

    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some("did:webvh:test:control.example.com".into()),
        mediator_did: None,
        public_url: Some("http://control.test".into()),
        did_hosting_url: Some("http://control.test".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        fjall: Default::default(),
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(),
        registry: RegistryConfig::default(),
        trust_tasks: Default::default(),
        hosting: Default::default(),
        identity: Default::default(),
        replay: Default::default(),
        geoip: Default::default(),
        stats_flush: Default::default(),
        stats: Default::default(),
        config_path: PathBuf::new(),
    };

    let identity = did_hosting_common::server::identity::ServiceIdentity::generated_for(
        "did:webvh:test:control.example.com",
    )
    .await
    .unwrap();
    let state = crate::test_support::bare_state(config, store, Some(identity)).await;

    (state, dir)
}

fn build_msg(typ: &str, body: serde_json::Value) -> Message {
    Message::build("msg-id".to_string(), typ.to_string(), body).finalize()
}

/// Seed a fully-formed `DidRecord` with both the `did:` and `owner:`
/// index entries so list/info/delete dispatch arms have data to read.
async fn seed_did(state: &AppState, owner_did: &str, mnemonic: &str) {
    let record = DidRecord {
        services: None,
        owner: owner_did.into(),
        mnemonic: mnemonic.into(),
        created_at: 1,
        updated_at: 1,
        version_count: 1,
        did_id: Some(format!("did:webvh:abc:{mnemonic}")),
        content_size: 42,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,

        // A record from before multi-method hosting: no `domain` yet
        // (the migration fills it).
        method: "webvh".to_string(),
        domain: String::new(),
        agent_names: Vec::new(),
    };
    state
        .dids_ks
        .insert(did_key(mnemonic), &record)
        .await
        .expect("seed did record");
    state
        .dids_ks
        .insert_raw(owner_key(owner_did, mnemonic), mnemonic.as_bytes().to_vec())
        .await
        .expect("seed owner index");
}

/// ACL gate covers DIDComm authentication and DID ops alike. This pins
/// the integration: a DID added to the ACL with role `Owner` resolves
/// through `check_acl` to that role — the input `handle_authenticate`
/// uses to mint a JWT and `handle_webvh_message` uses for dispatch.
#[tokio::test]
async fn check_acl_returns_role_for_seeded_did() {
    use did_hosting_common::server::acl::check_acl;

    let (state, _dir) = test_state().await;
    let did = "did:example:owner-a";
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.into(),
            role: Role::Owner,
            label: None,
            created_at: 0,
            max_total_size: None,
            max_did_count: None,

            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .unwrap();

    let role = check_acl(&state.acl_ks, did).await.unwrap();
    assert_eq!(role, Role::Owner);

    // DID not in ACL → Forbidden.
    let err = check_acl(&state.acl_ks, "did:example:stranger")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        did_hosting_common::server::error::AppError::Forbidden(_)
    ));
}

/// An unrouted type is answered, not dropped. Dropping it is what made the
/// #144 retirements expensive: the caller learned nothing for 30s and then
/// reported a bare gateway timeout. The reply must name the type, or the
/// caller still cannot say which task was refused.
#[test]
fn unsupported_task_reply_names_the_type() {
    let (typ, body) = run_unsupported_task("https://example.org/spec/made-up/0.1");
    assert_eq!(
        typ,
        affinidi_messaging_didcomm_service::transport::PROBLEM_REPORT_TYPE
    );
    assert_eq!(
        body.get("code").and_then(|v| v.as_str()),
        Some("e.p.msg.unsupported-task")
    );
    let comment = body.get("comment").and_then(|v| v.as_str()).unwrap();
    assert!(
        comment.contains("https://example.org/spec/made-up/0.1"),
        "the refused type is the whole diagnostic; got {comment}"
    );
}

/// The reply is itself a problem-report by `is_problem_report`'s reckoning,
/// which is what makes this loop-safe: a peer that cannot route our reply
/// logs and drops it in its own fallback instead of answering back. If the
/// emitted type ever stopped matching, two fallbacks would ping-pong.
#[test]
fn unsupported_task_reply_cannot_start_a_problem_report_loop() {
    let (typ, _) = run_unsupported_task("https://example.org/spec/made-up/0.1");
    assert!(
        did_hosting_common::server::problem_report::is_problem_report(&typ),
        "{typ} must be recognised as a problem-report so peers drop rather than reply"
    );
}

/// The four URIs #144 retired each produce a reply naming them rather than
/// silence — these are the exact tasks a VTA predating the cutover sends,
/// and each one cost a 30s timeout.
///
/// This asserts the *reply*, not that the URIs are unrouted: `Router`
/// exposes no route introspection, so "is it still routed" isn't checkable
/// from here. Re-adding a route would make these URIs bypass the fallback
/// entirely and this test would keep passing while testing nothing about
/// them — it guards the reply shape, which is what the client depends on.
#[test]
fn retired_tasks_are_refused_by_name() {
    for retired in [
        "https://trusttasks.org/spec/did-management/did/publish/0.1",
        "https://trusttasks.org/spec/did-management/agent-name/set/0.1",
        "https://trusttasks.org/spec/did-management/agent-name/enable/0.1",
        "https://trusttasks.org/spec/did-management/agent-name/disable/0.1",
        // Bare-message forms of ops that now travel only as signed Trust
        // Task documents inside the envelope.
        AUTHENTICATE,
        DELETE,
        MSG_SERVER_REGISTER,
    ] {
        let (typ, body) = run_unsupported_task(retired);
        assert_eq!(
            typ,
            affinidi_messaging_didcomm_service::transport::PROBLEM_REPORT_TYPE,
            "{retired}"
        );
        assert!(
            body.get("comment")
                .and_then(|v| v.as_str())
                .is_some_and(|c| c.contains(retired)),
            "{retired} must be named in the reply"
        );
    }
}

// -----------------------------------------------------------------
// run_trust_tasks_envelope tests
//
// The DIDComm-side dispatch was previously uncovered because the
// outer `handle_trust_tasks_envelope` takes `HandlerContext`, which
// an in-process test can't build. The `run_*` extraction lets us
// exercise the unpack + dispatch + repack logic without an
// ATM-backed context.
// -----------------------------------------------------------------

const CONTROL: &str = "did:webvh:test:control.example.com";

/// `test_state` with the production verifier over the local `did:key`
/// resolver, so signed envelopes verify without I/O.
async fn signing_state() -> (AppState, tempfile::TempDir) {
    let (mut state, dir) = test_state().await;
    state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
        DidKeyResolver,
    ))));
    (state, dir)
}

/// An edge whose role cannot be read (a throttled store) is told to retry,
/// on both tasks that answer it; one not in the ACL is still refused.
#[tokio::test]
async fn a_failed_role_lookup_asks_an_edge_to_retry() {
    let (state, _dir) = test_state().await;
    let edge = "did:example:throttled-edge";
    seed_role(&state, edge, Role::Service).await;
    let mut throttled = state.clone();
    throttled.acl_ks = state.acl_ks.throttled_reads();
    let stats = json!({ "server_did": edge, "seq": 1, "did_deltas": [] });

    let Err(rej) = do_stats_sync(&throttled, edge, &stats).await else {
        panic!("stats sync must not succeed without its role");
    };
    assert!(matches!(
        rej.reject_reason(),
        trust_tasks_rs::RejectReason::Unavailable {
            retry_after: Some(_)
        }
    ));
    let Err(rej) = do_server_register(&throttled, edge, &json!({})).await else {
        panic!("registration must not succeed without its role");
    };
    assert!(matches!(
        rej.reject_reason(),
        trust_tasks_rs::RejectReason::Unavailable { .. }
    ));

    let Err(rej) = do_stats_sync(&state, "did:example:stranger", &stats).await else {
        panic!("a stranger's stats sync must be refused");
    };
    assert!(matches!(rej, InfraRejection::NotAuthorised(_)), "{rej}");
    assert_eq!(
        rej.reject_reason().code(),
        trust_tasks_rs::StandardCode::PermissionDenied
    );
}

/// A synced delta for a hosted path that predates the current path
/// grammar still counts; an unhosted path of the same shape does not.
#[tokio::test]
async fn stats_sync_counts_a_hosted_legacy_path() {
    let (state, _dir) = test_state().await;
    let edge = "did:example:stats-legacy-edge";
    seed_role(&state, edge, Role::Service).await;
    state
        .dids_ks
        .insert(
            did_hosting_common::did_ops::did_key("Legacy/Path"),
            &json!({}),
        )
        .await
        .unwrap();

    let body = json!({
        "server_did": edge,
        "seq": 1,
        "did_deltas": [
            {"mnemonic": "Legacy/Path", "resolve_delta": 3, "update_delta": 0},
            {"mnemonic": "Unhosted/Path", "resolve_delta": 5, "update_delta": 0},
        ],
    });
    assert!(do_stats_sync(&state, edge, &body).await.is_ok());

    let deltas = state.stats_collector.drain_for_sync();
    let counted: Vec<_> = deltas
        .iter()
        .map(|d| (d.mnemonic.as_str(), d.resolve_delta))
        .collect();
    assert_eq!(counted, [("Legacy/Path", 3)]);
}

async fn seed_role(state: &AppState, did: &str, role: Role) {
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.into(),
            role,
            label: None,
            created_at: 1_700_000_000,
            max_total_size: None,
            max_did_count: None,
            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .unwrap();
}

/// An unsigned request document from `issuer` to the control plane.
fn request_doc(type_uri: &str, issuer: Option<&str>, payload: Value) -> Value {
    let mut doc = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "recipient": CONTROL,
        // Whole seconds, `Z`: the form the typed document re-serialises
        // to, so the signature over this JSON still covers it.
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    });
    if let Some(issuer) = issuer {
        doc["issuer"] = json!(issuer);
    }
    doc
}

async fn sign(doc: Value, signer: &affinidi_tdk::secrets_resolver::secrets::Secret) -> Value {
    crate::signing::test_util::sign_operational(doc, signer).await
}

fn envelope(body: Value) -> Message {
    // A fresh DIDComm message id each time: replay protection must not
    // depend on the transport's id.
    Message::build(
        uuid::Uuid::new_v4().to_string(),
        trust_tasks_didcomm::ENVELOPE_TYPE.to_string(),
        body,
    )
    .finalize()
}

async fn dispatch_envelope(state: &AppState, sender: &str, body: Value) -> Value {
    let (resp_type, resp_body) = super::run_trust_tasks_envelope(state, sender, &envelope(body))
        .await
        .expect("dispatch returns Ok")
        .expect("envelope produces a response");
    assert_eq!(resp_type, trust_tasks_didcomm::ENVELOPE_TYPE);
    resp_body
}

fn list_payload() -> Value {
    json!({})
}

/// Happy path: an ACL read (`acl/list/0.3`) signed by the Admin it names.
#[tokio::test]
async fn trust_tasks_envelope_happy_path_list_returns_handled_response() {
    let (state, _dir) = signing_state().await;
    let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[21u8; 32]);
    seed_role(&state, &admin, Role::Admin).await;

    let doc = sign(
        request_doc(
            "https://trusttasks.org/spec/acl/list/0.3",
            Some(&admin),
            list_payload(),
        ),
        &admin_key,
    )
    .await;
    let resp = dispatch_envelope(&state, &admin, doc).await;

    let inner_type = resp["type"].as_str().unwrap();
    assert!(
        inner_type.ends_with("/acl/list/0.3#response"),
        "expected acl/list response type, got {inner_type}"
    );
    let entries = resp["payload"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["subject"], admin.as_str());
}

/// An ACL read is privileged: without a proof it is refused even from an
/// Admin sender.
#[tokio::test]
async fn trust_tasks_envelope_unsigned_acl_read_is_refused() {
    let (state, _dir) = signing_state().await;
    let (admin, _) = crate::signing::test_util::did_key_signer(&[21u8; 32]);
    seed_role(&state, &admin, Role::Admin).await;

    let doc = request_doc(
        "https://trusttasks.org/spec/acl/list/0.3",
        Some(&admin),
        list_payload(),
    );
    let resp = dispatch_envelope(&state, &admin, doc).await;
    assert_eq!(resp["payload"]["code"], "proofRequired", "{resp}");
}

#[tokio::test]
async fn trust_tasks_envelope_malformed_inner_body_returns_routed_error() {
    let (state, _dir) = test_state().await;
    // Body is a valid JSON value but not a TrustTask document.
    let msg = build_msg(
        trust_tasks_didcomm::ENVELOPE_TYPE,
        json!({"not": "a-trust-task"}),
    );
    let (resp_type, resp_body) = super::run_trust_tasks_envelope(&state, "did:example:admin", &msg)
        .await
        .expect("dispatch returns Ok")
        .expect("malformed body emits an error doc");

    assert_eq!(resp_type, trust_tasks_didcomm::ENVELOPE_TYPE);
    assert_eq!(
        resp_body["type"].as_str().unwrap(),
        did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string()
    );
    // trust-tasks-rs 0.2 serialises StandardCode in camelCase
    // (`malformedRequest`); it still reads the 0.1 snake_case form on
    // inbound, so peers on either version interoperate.
    assert_eq!(resp_body["payload"]["code"], "malformedRequest");
}

/// A signed DID-management op (`did/check-name`) in the envelope is routed
/// to its `control_tasks` row and answered to its signer.
#[tokio::test]
async fn trust_tasks_envelope_bridges_did_management() {
    let (state, _dir) = signing_state().await;
    let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[22u8; 32]);
    seed_role(&state, &admin, Role::Admin).await;

    let doc = sign(
        request_doc(
            CHECK_NAME,
            Some(&admin),
            json!({ "path": "bob", "reserve": false }),
        ),
        &admin_key,
    )
    .await;
    let resp = dispatch_envelope(&state, &admin, doc).await;

    assert_eq!(
        resp["type"],
        "https://trusttasks.org/spec/did-management/did/check-name/0.1#response"
    );
    assert_eq!(resp["payload"]["available"], true);
    assert_eq!(resp["issuer"], CONTROL);
    assert_eq!(resp["recipient"], admin.as_str());
}

/// The unsigned form of the same op — what every DIDComm client sent before
/// — is refused, and refused *before* the ACL is consulted, so an Admin
/// sender name on the envelope buys nothing.
#[tokio::test]
async fn trust_tasks_envelope_unsigned_did_management_is_refused() {
    let (state, _dir) = signing_state().await;
    let admin = "did:example:admin";
    seed_role(&state, admin, Role::Admin).await;
    seed_did(&state, admin, "victim").await;

    let doc = request_doc(DELETE, Some(admin), json!({ "mnemonic": "victim" }));
    let resp = dispatch_envelope(&state, admin, doc).await;
    assert_eq!(resp["payload"]["code"], "proofRequired", "{resp}");
    assert!(
        state
            .dids_ks
            .get::<did_hosting_common::did_ops::DidRecord>(did_key("victim"))
            .await
            .unwrap()
            .is_some(),
        "nothing was deleted"
    );
}

/// A validly-signed document from one DID, delivered under another DID's
/// name (an Admin's), is refused: the proof's issuer and the transport's
/// reported sender disagree, and the reported sender is never enough.
#[tokio::test]
async fn trust_tasks_envelope_proof_from_someone_else_is_refused() {
    let (state, _dir) = signing_state().await;
    let admin = "did:example:admin";
    seed_role(&state, admin, Role::Admin).await;
    seed_did(&state, admin, "victim").await;
    let (attacker, attacker_key) = crate::signing::test_util::did_key_signer(&[66u8; 32]);

    let doc = sign(
        request_doc(DELETE, Some(&attacker), json!({ "mnemonic": "victim" })),
        &attacker_key,
    )
    .await;
    let resp = dispatch_envelope(&state, admin, doc).await;
    assert_eq!(resp["payload"]["code"], "permissionDenied", "{resp}");
    assert!(
        state
            .dids_ks
            .get::<did_hosting_common::did_ops::DidRecord>(did_key("victim"))
            .await
            .unwrap()
            .is_some(),
        "nothing was deleted"
    );
}

/// The `acl/grant` shape that would otherwise mint a permanent Admin: a
/// valid proof by the attacker, no in-band `issuer`, an Admin's name on the
/// envelope. Refused — an issuer-less proof verifies as nobody.
#[tokio::test]
async fn trust_tasks_envelope_issuerless_grant_under_admin_name_is_refused() {
    let (state, _dir) = signing_state().await;
    let admin = "did:example:admin";
    seed_role(&state, admin, Role::Admin).await;
    let (attacker, attacker_key) = crate::signing::test_util::did_key_signer(&[66u8; 32]);

    // Sign with an issuer (the signer insists), then strip it: the proof
    // is still a valid signature by the attacker over the rest.
    let mut signed = sign(
        request_doc(
            "https://trusttasks.org/spec/acl/grant/0.2",
            Some(&attacker),
            json!({ "entry": { "subject": attacker, "role": "admin", "act": { "scope": "all" }, "keys": { "scope": "none" }, "capabilities": { "scope": "ceiling" } } }),
        ),
        &attacker_key,
    )
    .await;
    signed.as_object_mut().unwrap().remove("issuer");
    let resp = dispatch_envelope(&state, admin, signed).await;
    assert_ne!(
        resp["type"].as_str().unwrap_or(""),
        "https://trusttasks.org/spec/acl/grant/0.2#response",
        "{resp}"
    );
    assert!(
        did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &attacker)
            .await
            .unwrap()
            .is_none(),
        "no ACL entry was created for the attacker"
    );
}

/// Replaying a captured signed document is refused, even wrapped in a fresh
/// DIDComm message — the gate keys on the proven issuer and the document
/// id, both covered by the proof. Uses a destructive op because that is
/// what replay protection exists for.
#[tokio::test]
async fn trust_tasks_envelope_replay_is_refused() {
    let (state, _dir) = signing_state().await;
    let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[23u8; 32]);
    seed_role(&state, &admin, Role::Admin).await;
    seed_did(&state, &admin, "replayed").await;

    let doc = sign(
        request_doc(DELETE, Some(&admin), json!({ "mnemonic": "replayed" })),
        &admin_key,
    )
    .await;

    let first = dispatch_envelope(&state, &admin, doc.clone()).await;
    assert_eq!(
        first["type"], DELETE_RESPONSE,
        "the first delivery must be handled, not rejected: {first}"
    );

    let replayed = dispatch_envelope(&state, &admin, doc).await;
    assert_eq!(replayed["payload"]["code"], "idConflict", "{replayed}");
}

/// The replay gate sits in front of routing: a replayed document is refused
/// before its task runs, so a re-created DID is not deleted by a captured
/// delete. A replay check made after routing would refuse the same document
/// but act on it first.
#[tokio::test]
async fn a_replay_is_refused_before_its_task_runs_again() {
    let (state, _dir) = signing_state().await;
    let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[24u8; 32]);
    seed_role(&state, &admin, Role::Admin).await;
    seed_did(&state, &admin, "recreated").await;

    let doc = sign(
        request_doc(DELETE, Some(&admin), json!({ "mnemonic": "recreated" })),
        &admin_key,
    )
    .await;
    let first = dispatch_envelope(&state, &admin, doc.clone()).await;
    assert_eq!(first["type"], DELETE_RESPONSE, "{first}");

    // Re-created after the delete: the replay must not reach it.
    state.dids_ks.remove(did_key("recreated")).await.unwrap();
    seed_did(&state, &admin, "recreated").await;
    let replayed = dispatch_envelope(&state, &admin, doc).await;
    assert_eq!(replayed["payload"]["code"], "idConflict", "{replayed}");
    let held: DidRecord = state
        .dids_ks
        .get(did_key("recreated"))
        .await
        .unwrap()
        .expect("the re-created DID is untouched");
    assert!(held.deleted_at.is_none(), "{held:?}");
}

/// Over the DIDComm envelope too, a non-error reply is signed by the
/// control plane for the requester; error documents are not.
#[tokio::test]
async fn envelope_replies_are_signed_by_the_control_plane() {
    use did_hosting_common::server::identity::ServiceIdentity;
    use did_hosting_common::server::trust_tasks::verify_sender_bound;

    let (mut state, _dir) = signing_state().await;
    let (control, control_key) = crate::signing::test_util::did_key_signer(&[71u8; 32]);
    let mut cfg = (*state.config).clone();
    cfg.server_did = Some(control.clone());
    state.config = Arc::new(cfg);
    state.identity = Some(
        ServiceIdentity::from_signing_secret(&control, control_key)
            .await
            .unwrap(),
    );
    let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[72u8; 32]);
    seed_role(&state, &admin, Role::Admin).await;

    let mut doc = request_doc(CHECK_NAME, Some(&admin), json!({ "path": "bob" }));
    doc["recipient"] = json!(control);
    let reply = dispatch_envelope(&state, &admin, sign(doc, &admin_key).await).await;
    let reply: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(reply).unwrap();
    assert!(
        reply
            .type_uri
            .to_string()
            .ends_with("check-name/0.1#response")
    );
    verify_sender_bound(
        &reply,
        Some(&control),
        None,
        &admin,
        state.trust_tasks_verifier.as_deref().unwrap(),
    )
    .await
    .expect("reply is signed by the control plane for the requester");

    // An error reply (unsigned request) stays unsigned.
    let mut unsigned = request_doc(CHECK_NAME, Some(&admin), json!({ "path": "bob" }));
    unsigned["recipient"] = json!(control);
    let err = dispatch_envelope(&state, &admin, unsigned).await;
    assert!(err["type"].as_str().unwrap().contains("/trust-task-error/"));
    assert!(err.get("proof").is_none());
}

/// A queued op is settled only by its target's *signed* acknowledgement
/// of the exact document sent; an ack from another Service-role server
/// does not settle it.
#[tokio::test]
async fn an_outbox_entry_is_settled_by_its_targets_signed_ack() {
    let (state, _dir) = signing_state().await;
    let (edge, edge_key) = crate::signing::test_util::did_key_signer(&[81u8; 32]);
    let (other, other_key) = crate::signing::test_util::did_key_signer(&[82u8; 32]);
    seed_role(&state, &edge, Role::Service).await;
    seed_role(&state, &other, Role::Service).await;
    crate::outbox::enqueue(
        &state.store,
        &edge,
        MSG_SYNC_UPDATE,
        json!({"mnemonic": "alice"}),
    )
    .await
    .unwrap();
    let (key, entry) = crate::outbox::list_pending_for_target(&state.store, &edge)
        .await
        .unwrap()
        .remove(0);
    crate::outbox::record_sent(&state.store, key, &entry, "urn:uuid:sent-1")
        .await
        .unwrap();

    let ack = |issuer: &str| {
        let mut doc = request_doc(
            MSG_SYNC_UPDATE_ACK,
            Some(issuer),
            json!({"mnemonic": "alice", "status": "applied"}),
        );
        doc["threadId"] = json!("urn:uuid:sent-1");
        doc
    };
    // Unsigned, and signed by another server: nothing settled.
    super::run_trust_tasks_envelope(&state, &edge, &envelope(ack(&edge)))
        .await
        .unwrap();
    super::run_trust_tasks_envelope(
        &state,
        &other,
        &envelope(sign(ack(&other), &other_key).await),
    )
    .await
    .unwrap();
    assert_eq!(
        crate::outbox::list_pending_for_target(&state.store, &edge)
            .await
            .unwrap()
            .len(),
        1
    );
    // The target's signed ack settles it.
    super::run_trust_tasks_envelope(&state, &edge, &envelope(sign(ack(&edge), &edge_key).await))
        .await
        .unwrap();
    assert!(
        crate::outbox::list_pending_for_target(&state.store, &edge)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Regression: a signer with no ACL entry is turned away before any
/// signature work, and leaves nothing in the replay cache.
#[tokio::test]
async fn an_unauthorised_signer_does_not_populate_the_replay_cache() {
    let (state, _dir) = signing_state().await;
    let (stranger, key) = crate::signing::test_util::did_key_signer(&[83u8; 32]);
    let doc = sign(
        request_doc(CHECK_NAME, Some(&stranger), json!({ "path": "alice" })),
        &key,
    )
    .await;
    for _ in 0..2 {
        let reply = dispatch_envelope(&state, &stranger, doc.clone()).await;
        assert_eq!(reply["payload"]["code"], "permissionDenied", "{reply}");
    }
    assert!(state.replay_cache.is_empty());
}

/// Fail closed: a control plane that cannot sign its replies serves no
/// trust task — not even the proofless ones — and acts on nothing.
#[tokio::test]
async fn a_control_plane_without_a_signing_identity_refuses_every_trust_task() {
    let (mut state, _dir) = signing_state().await;
    state.identity = None;
    let (admin, admin_key) = crate::signing::test_util::did_key_signer(&[95u8; 32]);
    seed_role(&state, &admin, Role::Admin).await;

    let signed = sign(
        request_doc(
            CHECK_NAME,
            Some(&admin),
            json!({ "path": "bob", "reserve": true }),
        ),
        &admin_key,
    )
    .await;
    let challenge = request_doc(
        "https://trusttasks.org/spec/auth/challenge/0.1",
        Some(&admin),
        json!({ "purpose": "login" }),
    );
    for doc in [signed, challenge] {
        let reply = dispatch_envelope(&state, &admin, doc).await;
        assert_eq!(reply["payload"]["code"], "internalError", "{reply}");
        assert!(reply.get("proof").is_none());
    }
    assert!(
        state
            .dids_ks
            .get::<did_hosting_common::did_ops::DidRecord>(did_key("bob"))
            .await
            .unwrap()
            .is_none(),
        "nothing was reserved"
    );
}

fn register_payload(edge: &str) -> Value {
    json!({
        "instanceId": edge.replace(':', "_"),
        "did": edge,
        "publicUrl": "https://edge.example",
        "label": "edge",
        "servedDomains": [],
        "ext": { (REGISTER_EXT_NAMESPACE): {} },
    })
}

/// A server registers only on its own signature. Unsigned, the document is
/// refused even when the reported sender holds the Service role — the
/// registration would otherwise enrol the sender as a sync target for every
/// tenant's DIDs on a name alone.
#[tokio::test]
async fn unsigned_server_registration_is_refused() {
    let (state, _dir) = signing_state().await;
    let edge = "did:example:edge";
    seed_role(&state, edge, Role::Service).await;

    let doc = request_doc(MSG_SERVER_REGISTER, Some(edge), register_payload(edge));
    let resp = dispatch_envelope(&state, edge, doc).await;
    assert_eq!(resp["payload"]["code"], "proofRequired", "{resp}");
    assert!(
        crate::registry::get_instance(&state.registry_ks, &edge.replace(':', "_"))
            .await
            .unwrap()
            .is_none(),
        "no instance was registered"
    );
}

/// The normal flow: a Service-role edge signs its registration and is
/// registered and acknowledged.
#[tokio::test]
async fn signed_server_registration_is_accepted() {
    let (state, _dir) = signing_state().await;
    let (edge, edge_key) = crate::signing::test_util::did_key_signer(&[41u8; 32]);
    seed_role(&state, &edge, Role::Service).await;

    let doc = sign(
        request_doc(MSG_SERVER_REGISTER, Some(&edge), register_payload(&edge)),
        &edge_key,
    )
    .await;
    let resp = dispatch_envelope(&state, &edge, doc).await;
    assert_eq!(resp["type"], MSG_SERVER_REGISTER_ACK, "{resp}");
    assert!(
        crate::registry::get_instance(&state.registry_ks, &edge.replace(':', "_"))
            .await
            .unwrap()
            .is_some(),
        "the signing edge was registered"
    );
}

/// A signed pong from a DID without the Service role changes nothing: the
/// registry's liveness view is not writable by any DID that can sign.
#[tokio::test]
async fn health_pong_from_a_non_service_signer_is_ignored() {
    use crate::registry::{ServiceInstance, ServiceStatus, ServiceType};

    let (state, _dir) = signing_state().await;
    let (edge, edge_key) = crate::signing::test_util::did_key_signer(&[42u8; 32]);
    seed_role(&state, &edge, Role::Owner).await;
    let instance_id = edge.replace(':', "_");
    crate::registry::register_instance(
        &state.registry_ks,
        &ServiceInstance {
            instance_id: instance_id.clone(),
            service_type: ServiceType::Server,
            label: None,
            url: "https://edge.example".into(),
            status: ServiceStatus::Unreachable,
            last_health_check: None,
            registered_at: 0,
            metadata: json!({ "did": edge }),
            enabled_methods: vec![],
            served_domains: vec![],
            protocol_version: "1.0".into(),
            advertised_services: None,
            services_checked_at: None,
            sync_batch_capable: false,
            last_inbound_transport: None,
            last_inbound_at: None,
            last_outbound_transport: None,
            last_outbound_at: None,
            last_ack_at: None,
            last_reconcile_at: None,
        },
    )
    .await
    .unwrap();

    let doc = sign(
        request_doc(MSG_HEALTH_PONG, Some(&edge), json!({ "status": "ok" })),
        &edge_key,
    )
    .await;
    let out = super::run_trust_tasks_envelope(&state, &edge, &envelope(doc))
        .await
        .expect("dispatch ok");
    assert!(out.is_none(), "a pong is terminal");
    let inst = crate::registry::get_instance(&state.registry_ks, &instance_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inst.status, ServiceStatus::Unreachable, "status unchanged");
}

#[tokio::test]
async fn trust_tasks_envelope_returns_none_when_server_did_unconfigured() {
    // server_did = None — the dispatch can't run §7.2 recipient
    // enforcement and bubbles a DIDCommServiceError::Internal.
    let (mut state, _dir) = test_state().await;
    let cfg = AppConfig {
        features: state.config.features.clone(),
        server_did: None,
        mediator_did: None,
        public_url: state.config.public_url.clone(),
        did_hosting_url: state.config.did_hosting_url.clone(),
        server: state.config.server.clone(),
        log: state.config.log.clone(),
        store: state.config.store.clone(),
        fjall: state.config.fjall,
        auth: state.config.auth.clone(),
        secrets: state.config.secrets.clone(),
        vta: state.config.vta.clone(),
        registry: state.config.registry.clone(),
        trust_tasks: state.config.trust_tasks.clone(),
        hosting: state.config.hosting.clone(),
        identity: Default::default(),
        replay: Default::default(),
        geoip: Default::default(),
        stats_flush: Default::default(),
        stats: Default::default(),
        config_path: state.config.config_path.clone(),
    };
    state.config = Arc::new(cfg);

    let msg = envelope(request_doc(
        "https://trusttasks.org/spec/acl/list/0.3",
        Some("did:example:admin"),
        list_payload(),
    ));
    let err = super::run_trust_tasks_envelope(&state, "did:example:admin", &msg)
        .await
        .expect_err("missing server_did should fail");
    match err {
        DIDCommServiceError::Internal(msg) => {
            assert!(msg.contains("server_did"), "operator-actionable: {msg}");
        }
        other => panic!("expected Internal, got {other:?}"),
    }
}

use affinidi_data_integrity::DidKeyResolver;
use did_hosting_common::server::trust_tasks::TransportBoundVerifier;

use crate::signing::test_util::did_key_signer;

// ── Signed REQUIRED-spec envelope dispatch (`acl/grant/0.2`) ──────

/// Build an (unsigned) typed `acl/grant/0.2` document granting
/// `subject` the `owner` role, issued by `admin_did` to this test
/// control plane.
fn unsigned_grant_doc(admin_did: &str, subject: &str) -> Value {
    use did_hosting_common::tasks::acl::grant::v0_2 as grant;
    let entry: grant::AclEntry = serde_json::from_value(json!({
        "subject": subject,
        "role": "owner",
        "act": { "scope": "all" },
        "keys": { "scope": "none" },
        "capabilities": { "scope": "ceiling" },
        "label": "signed e2e grant"
    }))
    .expect("e2e ACL entry is well formed");
    let payload: grant::Payload = grant::Payload::builder()
        .entry(entry)
        .reason(Some(
            "signed end-to-end grant"
                .parse::<grant::PayloadReason>()
                .expect("reason"),
        ))
        .try_into()
        .expect("e2e grant payload is well formed");
    let mut doc = trust_tasks_rs::TrustTask::for_payload(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        payload,
    );
    doc.issuer = Some(admin_did.into());
    doc.recipient = Some("did:webvh:test:control.example.com".into());
    doc.issued_at = Some(chrono::Utc::now());
    serde_json::to_value(&doc).expect("grant document serialises")
}

/// `test_state` + the production `did:key` verifier + `admin_did`
/// seeded as Admin, for the REQUIRED-spec envelope tests.
async fn grant_state(admin_did: &str) -> (AppState, tempfile::TempDir) {
    let (mut state, dir) = test_state().await;
    state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_resolver(Arc::new(
        DidKeyResolver,
    ))));
    assert!(
        state.config.trust_tasks.enforce_proofs,
        "strict proofs are the default"
    );
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: admin_did.into(),
            role: Role::Admin,
            label: None,
            created_at: 1_700_000_000,
            max_total_size: None,
            max_did_count: None,
            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .expect("seed admin");
    (state, dir)
}

/// The signed REQUIRED-spec dispatch the retired deferral named:
/// `acl/grant/0.2` (proof REQUIRED) carrying a *real* Data Integrity
/// proof, dispatched through the DIDComm envelope path under
/// `enforce_proofs = true` and the production verifier, landing the
/// granted entry in the ACL store.
#[tokio::test]
async fn trust_tasks_envelope_signed_acl_grant_verifies_end_to_end() {
    let (admin_did, admin_signer) = did_key_signer(&[41u8; 32]);
    let (state, _dir) = grant_state(&admin_did).await;

    let subject = "did:example:grantee";
    let signed = crate::signing::test_util::sign_operational(
        unsigned_grant_doc(&admin_did, subject),
        &admin_signer,
    )
    .await;
    let msg = build_msg(trust_tasks_didcomm::ENVELOPE_TYPE, signed);

    let (resp_type, resp_body) = super::run_trust_tasks_envelope(&state, &admin_did, &msg)
        .await
        .expect("dispatch ok")
        .expect("a response is emitted");

    assert_eq!(resp_type, trust_tasks_didcomm::ENVELOPE_TYPE);
    let inner = resp_body["type"].as_str().unwrap();
    assert!(
        inner.ends_with("/acl/grant/0.2#response"),
        "expected grant response, got {inner}"
    );
    let stored = did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, subject)
        .await
        .expect("acl read")
        .expect("granted entry stored");
    assert!(
        matches!(stored.role, Role::Owner),
        "granted role is owner, got {:?}",
        stored.role
    );
}

/// Tampering with a signed grant after signing is refused with
/// `proofInvalid` — and nothing lands in the ACL store.
#[tokio::test]
async fn trust_tasks_envelope_signed_acl_grant_tampered_is_rejected() {
    let (admin_did, admin_signer) = did_key_signer(&[42u8; 32]);
    let (state, _dir) = grant_state(&admin_did).await;

    let mut signed = crate::signing::test_util::sign_operational(
        unsigned_grant_doc(&admin_did, "did:example:grantee"),
        &admin_signer,
    )
    .await;
    signed["payload"]["entry"]["subject"] = json!("did:example:mallory");
    let msg = build_msg(trust_tasks_didcomm::ENVELOPE_TYPE, signed);

    let (_, resp_body) = super::run_trust_tasks_envelope(&state, &admin_did, &msg)
        .await
        .expect("dispatch ok")
        .expect("an error document is emitted");

    assert_eq!(
        resp_body["type"],
        // Takes the version from the emitter rather than naming one, so a
        // framework bump moves the assertion with the code under test.
        // What this test is about is the `code`, not the document version.
        did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string()
    );
    assert_eq!(resp_body["payload"]["code"], "proofInvalid");
    for did in ["did:example:mallory", "did:example:grantee"] {
        assert!(
            did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, did)
                .await
                .expect("acl read")
                .is_none(),
            "{did} must not be granted"
        );
    }
}

/// A proofless grant is refused (`proofRequired`) even from a
/// seeded Admin sender — for REQUIRED specs the proof, not the
/// transport session, authorizes.
#[tokio::test]
async fn trust_tasks_envelope_unsigned_acl_grant_is_rejected() {
    let (admin_did, _admin_signer) = did_key_signer(&[43u8; 32]);
    let (state, _dir) = grant_state(&admin_did).await;

    let msg = build_msg(
        trust_tasks_didcomm::ENVELOPE_TYPE,
        unsigned_grant_doc(&admin_did, "did:example:grantee"),
    );
    let (_, resp_body) = super::run_trust_tasks_envelope(&state, &admin_did, &msg)
        .await
        .expect("dispatch ok")
        .expect("an error document is emitted");

    assert_eq!(
        resp_body["type"],
        // Takes the version from the emitter rather than naming one, so a
        // framework bump moves the assertion with the code under test.
        // What this test is about is the `code`, not the document version.
        did_hosting_common::server::trust_tasks::framework_error_type_uri().to_string()
    );
    assert_eq!(resp_body["payload"]["code"], "proofRequired");
    assert!(
        did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, "did:example:grantee")
            .await
            .expect("acl read")
            .is_none(),
        "nothing must be granted"
    );
}

// ── Delta re-sync compares identity, not just version ──────────────

fn record_at(mnemonic: &str, did_id: &str, version_count: u64) -> DidRecord {
    DidRecord {
        services: None,
        owner: "did:example:owner".into(),
        mnemonic: mnemonic.into(),
        created_at: 1,
        updated_at: 1,
        version_count,
        did_id: Some(did_id.into()),
        content_size: 1,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: String::new(),
        agent_names: Vec::new(),
    }
}

#[test]
fn an_edge_is_current_only_for_the_same_did_at_the_same_version() {
    use crate::server_push::{ReportedDid, edge_is_current};
    let record = record_at("alice", "did:webvh:QmNew:host:alice", 2);
    let have = |did_id: Option<&str>, version_count| ReportedDid {
        did_id: did_id.map(String::from),
        version_count,
        disabled: None,
    };
    assert!(edge_is_current(
        &record,
        Some(&have(Some("did:webvh:QmNew:host:alice"), 2))
    ));
    assert!(!edge_is_current(&record, None), "absent → push");
    assert!(
        !edge_is_current(&record, Some(&have(Some("did:webvh:QmNew:host:alice"), 1))),
        "behind → push"
    );
    // Deleted and re-created at the same slot with the same version count:
    // the edge that missed the delete still holds the old DID.
    assert!(
        !edge_is_current(&record, Some(&have(Some("did:webvh:QmOld:host:alice"), 2))),
        "a different DID at the slot → push"
    );
    assert!(
        !edge_is_current(&record, Some(&have(None, 5))),
        "an edge that does not say which DID it holds → push"
    );
    // A disable the edge missed is re-sent with the content.
    let reported = |disabled| ReportedDid {
        disabled: Some(disabled),
        ..have(Some("did:webvh:QmNew:host:alice"), 2)
    };
    assert!(edge_is_current(&record, Some(&reported(false))));
    assert!(
        !edge_is_current(&record, Some(&reported(true))),
        "a different disabled state → push"
    );
}

#[test]
fn preloaded_dids_carry_the_did_identity() {
    let reported = crate::server_push::parse_reported(&json!({
        "preloaded_dids": [
            { "mnemonic": "alice", "did_id": "did:webvh:QmA:h:alice", "version_count": 3 },
            { "mnemonic": "bob", "version_count": 1 },
        ]
    }));
    assert_eq!(
        reported["alice"].did_id.as_deref(),
        Some("did:webvh:QmA:h:alice")
    );
    assert_eq!(reported["alice"].version_count, 3);
    assert_eq!(reported["bob"].did_id, None);
}

/// End to end: an edge reporting the old DID at a re-created slot, at the
/// same version count, is sent the new log.
#[tokio::test]
async fn resync_pushes_a_re_created_did_at_the_same_version() {
    let (state, _dir) = test_state().await;
    let record = record_at("alice", "did:webvh:QmNew:host:alice", 1);
    state
        .dids_ks
        .insert(did_key("alice"), &record)
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(
            did_hosting_common::did_ops::content_log_key("alice"),
            b"{}".to_vec(),
        )
        .await
        .unwrap();
    let edge = "did:example:edge-resync";
    let reported = crate::server_push::parse_reported(&json!({
        "preloaded_dids": [
            { "mnemonic": "alice", "did_id": "did:webvh:QmOld:host:alice", "version_count": 1 },
        ]
    }));
    crate::server_push::sync_all_dids_now(&state, edge, reported.clone()).await;
    let rows = crate::outbox::list_pending_for_target(&state.store, edge)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "the new DID is pushed");
    let sent = crate::outbox::prepare(&state, &rows[0].1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sent.msg_type, MSG_SYNC_UPDATE);
    assert_eq!(sent.body["didId"], "did:webvh:QmNew:host:alice");
    assert_eq!(sent.body["disabled"], false);

    // The edge registers again before the row drained: the same delta is
    // not queued a second time.
    crate::server_push::sync_all_dids_now(&state, edge, reported).await;
    assert_eq!(
        crate::outbox::list_pending_for_target(&state.store, edge)
            .await
            .unwrap()
            .len(),
        1,
        "a resync coalesces onto what is already queued"
    );
}

/// A batch-capable edge's resync is queued as batch rows, and a resync
/// while one is still queued adds nothing.
#[tokio::test]
async fn a_batched_resync_is_not_appended_while_one_is_queued() {
    let (state, _dir) = test_state().await;
    let edge = "did:example:edge-batch";
    for m in ["a", "b", "c"] {
        state
            .dids_ks
            .insert(
                did_key(m),
                &record_at(m, &format!("did:webvh:Q:host:{m}"), 1),
            )
            .await
            .unwrap();
        state
            .dids_ks
            .insert_raw(
                did_hosting_common::did_ops::content_log_key(m),
                b"{}".to_vec(),
            )
            .await
            .unwrap();
    }
    let mut instance: crate::registry::ServiceInstance = serde_json::from_value(json!({
        "instanceId": crate::registry::instance_id_for(edge),
        "serviceType": "server",
        "url": "https://edge.example",
        "status": "active",
        "registeredAt": 1,
        "metadata": { "did": edge },
    }))
    .unwrap();
    instance.sync_batch_capable = true;
    crate::registry::register_instance(&state.registry_ks, &instance)
        .await
        .unwrap();

    crate::server_push::sync_all_dids_now(&state, edge, Default::default()).await;
    let rows = crate::outbox::list_pending_for_target(&state.store, edge)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "three DIDs, one batch row");
    let sent = crate::outbox::prepare(&state, &rows[0].1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sent.msg_type, MSG_SYNC_BATCH);
    assert_eq!(sent.body["updates"].as_array().unwrap().len(), 3);

    crate::server_push::sync_all_dids_now(&state, edge, Default::default()).await;
    assert_eq!(
        crate::outbox::list_pending_for_target(&state.store, edge)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// A registration queues the server's domain rows ahead of its DID rows.
#[tokio::test]
async fn a_resync_queues_domains_before_dids() {
    let (state, _dir) = test_state().await;
    let edge = "did:example:edge-order";
    seed_service(&state, edge).await;
    state
        .dids_ks
        .insert(
            did_key("alice"),
            &record_at("alice", "did:webvh:Q:host:alice", 1),
        )
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(
            did_hosting_common::did_ops::content_log_key("alice"),
            b"{}".to_vec(),
        )
        .await
        .unwrap();
    crate::server_push::send_domain_assign(&state, edge, "a.example")
        .await
        .unwrap();
    clear_outbox(&state, edge).await;

    crate::server_push::resync_server(&state, edge.to_string(), Default::default(), vec![]);
    let mut rows = Vec::new();
    for _ in 0..200 {
        rows = crate::outbox::list_pending_for_target(&state.store, edge)
            .await
            .unwrap();
        if rows.iter().any(|(_, e)| e.msg_type == MSG_SYNC_UPDATE) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let types: Vec<_> = rows.iter().map(|(_, e)| e.msg_type.as_str()).collect();
    assert_eq!(types, vec![MSG_REPLICA_DOMAIN_ASSIGN, MSG_SYNC_UPDATE]);
}

// ── Domain ops are re-sent on registration until settled ───────────

async fn seed_service(state: &AppState, did: &str) {
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.into(),
            role: Role::Service,
            label: None,
            created_at: 1,
            max_total_size: None,
            max_did_count: None,
            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .unwrap();
}

async fn pending_ops(state: &AppState, edge: &str) -> Vec<(String, String)> {
    crate::outbox::list_pending_for_target(&state.store, edge)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, e)| {
            (
                e.msg_type,
                e.body["domain"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

async fn clear_outbox(state: &AppState, edge: &str) {
    for (k, _) in crate::outbox::list_pending_for_target(&state.store, edge)
        .await
        .unwrap()
    {
        crate::outbox::remove(&state.store, k).await.unwrap();
    }
}

#[tokio::test]
async fn unsettled_domain_ops_are_re_sent_on_registration() {
    use crate::server_push::{
        DomainOp, domain_intents, resend_domain_intents, send_domain_assign, send_domain_purge,
        send_domain_unassign,
    };
    let (state, _dir) = test_state().await;
    let edge = "did:example:edge-domains";
    seed_service(&state, edge).await;

    send_domain_assign(&state, edge, "kept.example")
        .await
        .unwrap();
    send_domain_unassign(&state, edge, "gone.example")
        .await
        .unwrap();
    send_domain_purge(&state, edge, "wiped.example")
        .await
        .unwrap();
    // The edge was offline long enough for the outbox to give up.
    clear_outbox(&state, edge).await;

    resend_domain_intents(&state, edge).await;
    let mut ops = pending_ops(&state, edge).await;
    ops.sort();
    let mut want = vec![
        (
            MSG_REPLICA_DOMAIN_ASSIGN.to_string(),
            "kept.example".to_string(),
        ),
        (
            MSG_REPLICA_DOMAIN_UNASSIGN.to_string(),
            "gone.example".to_string(),
        ),
        (
            MSG_REPLICA_DOMAIN_UNASSIGN.to_string(),
            "wiped.example".to_string(),
        ),
        (
            MSG_REPLICA_DOMAIN_PURGE.to_string(),
            "wiped.example".to_string(),
        ),
    ];
    want.sort();
    assert_eq!(ops, want);

    // Acknowledged unassign / purge are settled; the assign stays (it is the
    // desired state).
    do_domain_ack(
        &state,
        edge,
        MSG_REPLICA_DOMAIN_UNASSIGN_ACK,
        &json!({ "domain": "gone.example", "status": "scheduled", "purgeAt": "2026-01-01T00:00:00Z" }),
    )
    .await;
    do_domain_ack(
        &state,
        edge,
        MSG_REPLICA_DOMAIN_PURGE_ACK,
        &json!({ "domain": "wiped.example", "status": "purged", "removed": 0 }),
    )
    .await;
    do_domain_ack(
        &state,
        edge,
        MSG_REPLICA_DOMAIN_ASSIGN_ACK,
        &json!({ "domain": "kept.example", "status": "applied" }),
    )
    .await;
    let intents = domain_intents(&state, edge).await.unwrap();
    assert_eq!(intents.len(), 1, "{intents:?}");
    assert_eq!(intents[0].domain, "kept.example");
    assert_eq!(intents[0].op, DomainOp::Assign);
    assert!(
        intents[0].acked,
        "the applied assign is marked acknowledged"
    );

    // An acknowledged assign is not re-sent to a server that still serves
    // the domain — but is to one that registers without it (wiped).
    clear_outbox(&state, edge).await;
    crate::server_push::resend_domain_intents_for(
        &state,
        edge,
        Some(&["kept.example".to_string()]),
    )
    .await;
    assert!(pending_ops(&state, edge).await.is_empty());
    crate::server_push::resend_domain_intents_for(&state, edge, Some(&[])).await;
    assert_eq!(
        pending_ops(&state, edge).await,
        vec![(
            MSG_REPLICA_DOMAIN_ASSIGN.to_string(),
            "kept.example".to_string()
        )]
    );
    // Re-sent again while still queued: not queued twice.
    crate::server_push::resend_domain_intents_for(&state, edge, Some(&[])).await;
    assert_eq!(pending_ops(&state, edge).await.len(), 1);
}

/// The ack of an older unassign cannot erase a newer assign, and a stranger
/// cannot settle anything.
#[tokio::test]
async fn a_stale_or_foreign_ack_does_not_settle_a_domain_op() {
    use crate::server_push::{DomainOp, domain_intents, send_domain_assign, send_domain_unassign};
    let (state, _dir) = test_state().await;
    let edge = "did:example:edge-stale";
    seed_service(&state, edge).await;

    send_domain_unassign(&state, edge, "a.example")
        .await
        .unwrap();
    send_domain_assign(&state, edge, "a.example").await.unwrap();
    do_domain_ack(
        &state,
        edge,
        MSG_REPLICA_DOMAIN_UNASSIGN_ACK,
        &json!({ "domain": "a.example", "status": "scheduled", "purgeAt": "2026-01-01T00:00:00Z" }),
    )
    .await;
    let intents = domain_intents(&state, edge).await.unwrap();
    assert_eq!(intents[0].op, DomainOp::Assign, "the newer assign stands");

    send_domain_unassign(&state, edge, "a.example")
        .await
        .unwrap();
    do_domain_ack(
        &state,
        "did:example:not-a-service",
        MSG_REPLICA_DOMAIN_UNASSIGN_ACK,
        &json!({ "domain": "a.example", "status": "scheduled", "purgeAt": "2026-01-01T00:00:00Z" }),
    )
    .await;
    assert_eq!(
        domain_intents(&state, edge).await.unwrap()[0].op,
        DomainOp::Unassign,
        "another DID's ack settles nothing"
    );
}

/// Two DIDs whose registry ids collide (`a_b` and `a:b`): the second
/// cannot register over the first, nor mark it alive.
#[tokio::test]
async fn a_registry_id_another_did_holds_is_not_taken_over() {
    let (state, _dir) = test_state().await;
    let first = "did:web:edge.example:a_b";
    let second = "did:web:edge.example:a:b";
    assert_eq!(
        crate::registry::instance_id_for(first),
        crate::registry::instance_id_for(second)
    );
    seed_service(&state, first).await;
    seed_service(&state, second).await;

    assert!(
        do_server_register(&state, first, &register_payload(first))
            .await
            .is_ok()
    );
    let Err(rej) = do_server_register(&state, second, &register_payload(second)).await else {
        panic!("the colliding DID must not register over the first");
    };
    assert!(matches!(rej, InfraRejection::Conflict(_)), "{rej}");

    async fn held(state: &AppState, did: &str) -> crate::registry::ServiceInstance {
        crate::registry::get_instance(&state.registry_ks, &crate::registry::instance_id_for(did))
            .await
            .unwrap()
            .unwrap()
    }
    assert_eq!(held(&state, first).await.did(), Some(first));
    let before = held(&state, first).await.last_health_check;
    do_health_pong(&state, second, &json!({ "status": "ok" })).await;
    assert_eq!(
        held(&state, first).await.last_health_check,
        before,
        "not the second's"
    );
    do_health_pong(&state, first, &json!({ "status": "ok" })).await;
    assert!(held(&state, first).await.last_health_check.is_some());
}

/// The order of a registration's checks, by what each refusal is: the
/// signer's role is decided before its payload is read, the payload before
/// its URL, and nothing refused leaves a registry record. A re-register
/// carries the instance's observed history forward.
#[tokio::test]
async fn server_registration_checks_role_then_payload_then_url() {
    let (state, _dir) = test_state().await;

    // An Owner is refused on its role, whatever its payload says.
    let owner = "did:example:not-a-server";
    seed_role(&state, owner, Role::Owner).await;
    let Err(rej) = do_server_register(&state, owner, &json!({ "not": "a payload" })).await else {
        panic!("an Owner must not register");
    };
    assert!(matches!(rej, InfraRejection::NotAuthorised(_)), "{rej}");
    let Err(rej) = do_server_register(&state, "did:example:unlisted", &json!({})).await else {
        panic!("an unlisted DID must not register");
    };
    assert!(matches!(rej, InfraRejection::NotAuthorised(_)), "{rej}");

    // A Service whose payload names another server is malformed.
    let edge = "did:example:edge-order";
    seed_service(&state, edge).await;
    let Err(rej) =
        do_server_register(&state, edge, &register_payload("did:example:someone-else")).await
    else {
        panic!("a payload naming another server must be refused");
    };
    assert!(matches!(rej, InfraRejection::Malformed(_)), "{rej}");

    // A well-formed payload whose URL is internal is not authorised.
    let mut internal = register_payload(edge);
    internal["publicUrl"] = json!("https://127.0.0.1");
    let Err(rej) = do_server_register(&state, edge, &internal).await else {
        panic!("an internal URL must be refused");
    };
    assert!(matches!(rej, InfraRejection::NotAuthorised(_)), "{rej}");
    let id = crate::registry::instance_id_for(edge);
    assert!(
        crate::registry::get_instance(&state.registry_ks, &id)
            .await
            .unwrap()
            .is_none(),
        "no refused registration was recorded"
    );

    // Registered; an ack is observed; a re-register keeps it.
    let ack = do_server_register(&state, edge, &register_payload(edge))
        .await
        .expect("registered");
    assert!(ack.accepted);
    crate::registry::upsert_instance(&state.registry_ks, &id, |current| {
        current.map(|mut i| {
            i.last_ack_at = Some(42);
            i
        })
    })
    .await
    .unwrap();
    do_server_register(&state, edge, &register_payload(edge))
        .await
        .expect("re-registered");
    let held = crate::registry::get_instance(&state.registry_ks, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.last_ack_at, Some(42));
    assert_eq!(held.did(), Some(edge));
}

/// A server's `servedDomains` claim is kept only for a domain the control
/// plane assigned it.
#[tokio::test]
async fn a_served_domain_is_kept_only_when_it_was_assigned() {
    let (state, _dir) = test_state().await;
    let edge = "did:example:edge-claims";
    seed_service(&state, edge).await;
    for name in ["assigned.example", "claimed.example"] {
        did_hosting_common::server::domain::create_domain(
            &state.store,
            &did_hosting_common::server::domain::DomainEntry {
                name: name.into(),
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
    }
    crate::server_push::send_domain_assign(&state, edge, "assigned.example")
        .await
        .unwrap();

    let mut payload = register_payload(edge);
    payload["servedDomains"] = json!(["assigned.example", "claimed.example"]);
    assert!(do_server_register(&state, edge, &payload).await.is_ok());
    let instance = crate::registry::get_instance_for_did(&state.registry_ks, edge)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(instance.served_domains, ["assigned.example"]);
}

/// A stats sync is a closed shape: an unknown member refuses it. A count
/// no edge could have served in one interval is not added.
#[tokio::test]
async fn stats_sync_is_typed_and_its_counts_bounded() {
    let (state, _dir) = test_state().await;
    let edge = "did:example:stats-typed-edge";
    seed_role(&state, edge, Role::Service).await;

    let extra = json!({ "server_did": edge, "seq": 1, "did_deltas": [], "credit": "all" });
    let Err(rej) = do_stats_sync(&state, edge, &extra).await else {
        panic!("an unknown member must refuse the sync");
    };
    assert!(matches!(rej, InfraRejection::Malformed(_)), "{rej}");

    let body = json!({
        "server_did": edge,
        "seq": 2,
        "did_deltas": [
            {"mnemonic": "counted", "resolve_delta": 3, "update_delta": 0,
             "last_resolved_at": null, "last_updated_at": null},
            {"mnemonic": "inflated", "resolve_delta": u64::MAX, "update_delta": 0},
        ],
    });
    assert!(do_stats_sync(&state, edge, &body).await.is_ok());
    let counted: Vec<_> = state
        .stats_collector
        .drain_for_sync()
        .into_iter()
        .map(|d| (d.mnemonic, d.resolve_delta))
        .collect();
    assert_eq!(counted, [("counted".to_string(), 3)]);
}

/// A domain acknowledgement that is not its task's response is ignored.
#[tokio::test]
async fn a_domain_ack_that_is_not_its_response_type_is_ignored() {
    use crate::server_push::{DomainOp, domain_intents, send_domain_unassign};
    let (state, _dir) = test_state().await;
    let edge = "did:example:edge-ack-shape";
    seed_service(&state, edge).await;
    send_domain_unassign(&state, edge, "a.example")
        .await
        .unwrap();
    do_domain_ack(
        &state,
        edge,
        MSG_REPLICA_DOMAIN_UNASSIGN_ACK,
        &json!({ "domain": "a.example", "status": 7 }),
    )
    .await;
    assert_eq!(
        domain_intents(&state, edge).await.unwrap()[0].op,
        DomainOp::Unassign,
        "a malformed ack settles nothing"
    );
}

/// Each way a stats sync is refused reaches the edge as its own standard
/// code: not authorised, a foreign `server_did`, too many deltas and a
/// malformed body are told apart without reading the message (#366).
#[tokio::test]
async fn stats_sync_refusals_are_distinguishable_on_the_wire() {
    use trust_tasks_rs::StandardCode;
    let (state, _dir) = test_state().await;
    let edge = "did:example:stats-codes-edge";
    seed_role(&state, edge, Role::Service).await;
    let code = |rej: InfraRejection| rej.reject_reason().code();

    let body = json!({ "server_did": edge, "seq": 1, "did_deltas": [] });
    let rej = do_stats_sync(&state, "did:example:nobody", &body)
        .await
        .unwrap_err();
    assert_eq!(code(rej), StandardCode::PermissionDenied);

    let foreign = json!({ "server_did": "did:example:other-edge", "seq": 2 });
    let rej = do_stats_sync(&state, edge, &foreign).await.unwrap_err();
    assert!(
        matches!(rej, InfraRejection::SenderMismatch { .. }),
        "{rej}"
    );
    assert_eq!(code(rej), StandardCode::IdentityMismatch);

    let max = did_hosting_common::server::stats_collector::MAX_STATS_SYNC_DELTAS;
    let deltas: Vec<Value> = (0..=max)
        .map(|i| json!({ "mnemonic": format!("d{i}") }))
        .collect();
    let large = json!({ "server_did": edge, "seq": 3, "did_deltas": deltas });
    let rej = do_stats_sync(&state, edge, &large).await.unwrap_err();
    let reason = rej.reject_reason();
    assert_eq!(reason.code(), StandardCode::TaskFailed);
    assert!(
        matches!(&reason, trust_tasks_rs::RejectReason::TaskFailed { details: Some(d), .. }
            if d["limit"] == json!(max)),
        "{reason:?}"
    );

    let rej = do_stats_sync(&state, edge, &json!({ "seq": "four" }))
        .await
        .unwrap_err();
    assert_eq!(code(rej), StandardCode::MalformedRequest);
}

/// A stats sync is answered with the pinned `server/stats-sync/0.1`
/// response, whichever shape the sync came in: `accepted` counts what was
/// counted, and a stale `seq` is said under our `ext` namespace.
#[tokio::test]
async fn stats_sync_acks_are_the_pinned_response() {
    use did_hosting_common::server::trust_tasks::infra;
    let (state, _dir) = test_state().await;
    let edge = "did:example:stats-ack-edge";
    let id = infra::instance_id_for(edge);
    seed_role(&state, edge, Role::Service).await;

    let deltas = [did_hosting_common::DidStatsDelta {
        mnemonic: "counted".into(),
        resolve_delta: 2,
        update_delta: 0,
        last_resolved_at: None,
        last_updated_at: None,
    }];
    let body = infra::stats_sync_body(&id, 5, &deltas).unwrap();
    let ack = do_stats_sync(&state, edge, &body).await.unwrap();
    assert_eq!(ack, json!({ "instanceId": id, "accepted": 1 }));
    let replayed = do_stats_sync(&state, edge, &body).await.unwrap();
    assert_eq!(
        replayed,
        json!({ "instanceId": id, "accepted": 0,
                "ext": { "vnd.affinidi.webvh": { "skipped": "stale_seq" } } })
    );
    // The legacy shape is answered the same way.
    let legacy = json!({ "server_did": edge, "seq": 9, "did_deltas": [] });
    assert_eq!(
        do_stats_sync(&state, edge, &legacy).await.unwrap(),
        json!({ "instanceId": id, "accepted": 0 })
    );
}

/// A conformant sync is counted, with its latest-event times, and one
/// whose `instanceId` is not the signer's is refused as a mismatch.
#[tokio::test]
async fn a_conformant_stats_sync_is_counted_and_bound_to_its_signer() {
    use did_hosting_common::server::trust_tasks::infra;
    let (state, _dir) = test_state().await;
    let edge = "did:example:stats-conformant-edge";
    seed_role(&state, edge, Role::Service).await;
    let now = crate::auth::session::now_epoch();
    let body = json!({
        "instanceId": infra::instance_id_for(edge),
        "perMnemonic": [{ "mnemonic": "alice", "resolves": 4, "updates": 1 }],
        "ext": { "vnd.affinidi.webvh": {
            "seq": 1,
            "lastSeen": [{ "mnemonic": "alice", "lastResolvedAt": now }],
        } },
    });
    do_stats_sync(&state, edge, &body).await.unwrap();
    let counted = state.stats_collector.drain_for_sync();
    assert_eq!(counted.len(), 1);
    assert_eq!((counted[0].resolve_delta, counted[0].update_delta), (4, 1));
    assert_eq!(counted[0].last_resolved_at, Some(now));

    let foreign = json!({
        "instanceId": infra::instance_id_for("did:example:other-edge"),
        "perMnemonic": [],
    });
    let rej = do_stats_sync(&state, edge, &foreign).await.unwrap_err();
    assert!(
        matches!(rej, InfraRejection::SenderMismatch { .. }),
        "{rej}"
    );

    let buckets = json!({
        "instanceId": infra::instance_id_for(edge),
        "perMnemonic": [],
        "buckets": [{ "mnemonic": "alice", "epoch": 0, "r": 1, "u": 0 }],
    });
    let rej = do_stats_sync(&state, edge, &buckets).await.unwrap_err();
    assert!(matches!(rej, InfraRejection::Malformed(_)), "{rej}");
}

/// A conformant pong marks its instance active; one that reports the edge
/// unhealthy, or names another instance, does not.
#[tokio::test]
async fn a_conformant_pong_marks_only_a_healthy_instance_active() {
    use did_hosting_common::server::trust_tasks::infra;
    let (state, _dir) = test_state().await;
    let edge = "did:example:pong-edge";
    seed_service(&state, edge).await;
    assert!(
        do_server_register(&state, edge, &register_payload(edge))
            .await
            .is_ok()
    );
    let held = || async {
        crate::registry::get_instance_for_did(&state.registry_ks, edge)
            .await
            .unwrap()
            .unwrap()
            .last_health_check
    };
    let before = held().await;
    let id = infra::instance_id_for(edge);
    let now = chrono::Utc::now();

    let mut unhealthy = infra::health_pong_body(&id, now, "1.0.0", 1).unwrap();
    unhealthy["ok"] = json!(false);
    do_health_pong(&state, edge, &unhealthy).await;
    assert_eq!(
        held().await,
        before,
        "an unhealthy edge is not a successful check"
    );

    let other = infra::health_pong_body("did_example_elsewhere", now, "1.0.0", 1).unwrap();
    do_health_pong(&state, edge, &other).await;
    assert_eq!(held().await, before, "another instance's pong");

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let pong = infra::health_pong_body(&id, now, "1.0.0", 1).unwrap();
    do_health_pong(&state, edge, &pong).await;
    assert_ne!(held().await, before);
}

/// The infrastructure tasks state their proof rule rather than taking
/// the dispatcher's default for an unknown Type URI.
#[test]
fn infrastructure_tasks_have_an_explicit_proof_rule() {
    for uri in [
        MSG_SERVER_REGISTER,
        MSG_HEALTH_PONG,
        MSG_STATS_SYNC,
        MSG_SYNC_UPDATE_ACK,
        MSG_SYNC_DELETE_ACK,
        MSG_SYNC_BATCH_ACK,
        MSG_REPLICA_DOMAIN_ASSIGN_ACK,
        MSG_REPLICA_DOMAIN_UNASSIGN_ACK,
        MSG_REPLICA_DOMAIN_PURGE_ACK,
        MSG_REPLICA_DOMAIN_UPSERT_ACK,
    ] {
        assert_eq!(
            crate::messaging::infra::proof_rule(uri),
            Some(ProofRule::Authentication),
            "{uri}"
        );
        assert_eq!(proof_rule(uri), ProofRule::Authentication, "{uri}");
    }
    // A reply this control plane itself emits is not one it routes.
    assert_eq!(
        crate::messaging::infra::proof_rule(MSG_SERVER_REGISTER_ACK),
        None
    );
}

/// A pong from a Service is the end of the exchange: dispatch reports it
/// as terminal (no reply, nothing logged as an invariant break), and the
/// instance is marked active (#359).
#[tokio::test]
async fn a_service_pong_is_terminal_not_suppressed() {
    use crate::registry::ServiceStatus;
    let (state, _dir) = signing_state().await;
    let (edge, edge_key) = crate::signing::test_util::did_key_signer(&[43u8; 32]);
    seed_service(&state, &edge).await;
    let registered = sign(
        request_doc(MSG_SERVER_REGISTER, Some(&edge), register_payload(&edge)),
        &edge_key,
    )
    .await;
    dispatch_envelope(&state, &edge, registered).await;

    let pong = sign(
        request_doc(
            MSG_HEALTH_PONG,
            Some(&edge),
            json!({ "status": "ok", "version": "1.2.3", "did_count": 4 }),
        ),
        &edge_key,
    )
    .await;
    let doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(pong).unwrap();
    let transport = trust_tasks_didcomm::DidcommHandler::new(CONTROL.to_string(), edge.clone());
    let reply = dispatch_trust_task_doc(
        &state,
        &edge,
        None,
        None,
        &transport,
        doc,
        require_verifier(&state).unwrap(),
        None,
    )
    .await
    .unwrap();
    assert!(reply.is_terminal(), "a pong is answered by nothing");

    let instance = crate::registry::get_instance_for_did(&state.registry_ks, &edge)
        .await
        .unwrap()
        .expect("registered");
    assert_eq!(instance.status, ServiceStatus::Active);
}

/// A pong carrying a member this service does not read marks nothing.
#[tokio::test]
async fn a_pong_with_an_unknown_member_marks_nothing() {
    use crate::registry::ServiceStatus;
    let (state, _dir) = signing_state().await;
    let (edge, edge_key) = crate::signing::test_util::did_key_signer(&[44u8; 32]);
    seed_service(&state, &edge).await;
    let registered = sign(
        request_doc(MSG_SERVER_REGISTER, Some(&edge), register_payload(&edge)),
        &edge_key,
    )
    .await;
    dispatch_envelope(&state, &edge, registered).await;
    let mut instance = crate::registry::get_instance_for_did(&state.registry_ks, &edge)
        .await
        .unwrap()
        .unwrap();
    instance.status = ServiceStatus::Unreachable;
    crate::registry::register_instance(&state.registry_ks, &instance)
        .await
        .unwrap();

    do_health_pong(&state, &edge, &json!({ "status": "ok", "load": 9 })).await;
    let instance = crate::registry::get_instance_for_did(&state.registry_ks, &edge)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(instance.status, ServiceStatus::Unreachable);
}

/// The request log keys its quiet list on the document inside a
/// trust-task envelope, which is how every task now arrives (#359).
#[test]
fn the_quiet_list_reads_the_envelopes_inner_type() {
    let pong = envelope(request_doc(MSG_HEALTH_PONG, None, json!({})));
    assert_eq!(logged_type(&pong), MSG_HEALTH_PONG);
    assert!(is_quiet(&logged_type(&pong)));

    let stats = envelope(request_doc(MSG_STATS_SYNC, None, json!({})));
    assert!(is_quiet(&logged_type(&stats)));

    let delete = envelope(request_doc(DELETE, None, json!({})));
    assert_eq!(logged_type(&delete), DELETE);
    assert!(!is_quiet(&logged_type(&delete)));

    let bare = Message::build(
        "m".to_string(),
        "https://example.org/bare".to_string(),
        json!({}),
    )
    .finalize();
    assert_eq!(logged_type(&bare), "https://example.org/bare");
}

/// A registration this control plane cannot store is reported as its own
/// failure, never as the edge being unauthorised.
#[test]
fn a_failed_store_is_not_reported_as_permission_denied() {
    let rej = InfraRejection::lookup_failed(
        &did_hosting_common::server::error::AppError::Internal("x".into()),
    );
    assert_eq!(
        rej.reject_reason().code(),
        trust_tasks_rs::StandardCode::InternalError
    );
}

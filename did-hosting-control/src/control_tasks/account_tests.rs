//! Guest accounts end to end: registration through each transport's own entry
//! point and the one gate they share, the invites and vouchers that admit
//! it, what a guest may not do, and the inactivity lifecycle.
//!
//! Every registrant is a real `did:webvh`, minted here, and signs as its own
//! `#key-0` — a DID that does not resolve, so only its submitted log can
//! authenticate it.

use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::{Value, json};
use trust_tasks_rs::Payload as _;

use did_hosting_common::did::{DidDocumentOptions, build_did_document, create_log_entry};
use did_hosting_common::did_ops::{DidRecord, did_key};
use did_hosting_common::server::account::{self as account, AccountState};
use did_hosting_common::server::acl::{Role, get_acl_entry};
use did_hosting_common::tasks::did_management::{
    account::{
        exempt,
        invite::{issue, list as invite_list, revoke},
        policy::{list as policy_list, set as policy_set},
        register, renew, status,
    },
    domain::create as domain_create,
    server::info,
};

use super::harness::*;
use crate::server::AppState;

/// The hosting domain every registrant registers on: the harness's
/// `did_hosting_url` host.
const DOMAIN: &str = "control.test";

const REGISTER: &str = register::v0_1::Payload::TYPE_URI;

/// A minted `did:webvh` and the keys it signs with.
struct Registrant {
    did: String,
    scid_did: String,
    path: String,
    log: String,
    /// The latest document its log implies.
    document: Value,
    /// The key as the DID's `#key-0`.
    key: Secret,
    /// The same key as the `did:scid` alias's `#key-0`.
    scid_key: Secret,
}

impl Registrant {
    fn caller(&self) -> Caller {
        Caller {
            did: self.did.clone(),
            key: self.key.clone(),
            role: Role::Owner,
        }
    }

    fn scid_caller(&self) -> Caller {
        Caller {
            did: self.scid_did.clone(),
            key: self.scid_key.clone(),
            role: Role::Owner,
        }
    }
}

/// A DID at `path` on [`DOMAIN`], whose document lists its did:scid alias.
async fn registrant(path: &str) -> Registrant {
    registrant_with(path, |_| {}).await
}

async fn registrant_with(path: &str, edit: impl FnOnce(&mut Value)) -> Registrant {
    let seed: [u8; 32] = rand::random();
    let signing = Secret::generate_ed25519(None, Some(&seed));
    let mb = signing.get_public_keymultibase().unwrap();
    let mut doc = build_did_document(DOMAIN, path, &mb, &DidDocumentOptions::default());
    edit(&mut doc);
    let (_scid, log) = create_log_entry(&doc, &signing).await.unwrap();
    let did = did_hosting_common::did_ops::extract_did_id(&log).unwrap();
    let scid_did = did_hosting_common::scid::identity(&did_hosting_common::scid::scid_alias(&did));
    Registrant {
        key: Secret::generate_ed25519(Some(&format!("{did}#key-0")), Some(&seed)),
        scid_key: Secret::generate_ed25519(Some(&format!("{scid_did}#key-0")), Some(&seed)),
        did,
        scid_did,
        path: path.into(),
        document: did_hosting_common::method::publication::verify_publication(
            DOMAIN,
            path,
            log.as_bytes(),
            None,
            None,
        )
        .unwrap()
        .document
        .unwrap(),
        log,
    }
}

/// Resolves `did:key`s itself, and any other DID from documents the test
/// placed in the shared cache — standing in for this host serving the DIDs
/// it publishes, which the harness's `did:key`-only verifier cannot.
struct HostedResolver {
    cache: trust_tasks_proof::affinidi::CachedDidResolver,
}

#[async_trait::async_trait]
impl trust_tasks_proof::affinidi::ProofPurposeResolver for HostedResolver {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: trust_tasks_proof::affinidi::ProofPurpose,
    ) -> Result<affinidi_data_integrity::ResolvedKey, affinidi_data_integrity::DataIntegrityError>
    {
        if vm.starts_with("did:key:") {
            return affinidi_data_integrity::DidKeyResolver
                .resolve_vm_for_purpose(vm, purpose)
                .await;
        }
        self.cache
            .resolve_vm_for_purpose(&did_hosting_common::scid::strip_scid_src(vm), purpose)
            .await
    }
}

/// Make `r`'s DID — and its did:scid alias — resolvable, as it is once this
/// host publishes it.
async fn hosted(state: &AppState, r: &Registrant) {
    let mut client = state.did_resolver.clone().unwrap();
    let webvh: affinidi_did_common::Document = serde_json::from_value(r.document.clone()).unwrap();
    client.add_did_document(&r.did, webvh).await;
    let scid: affinidi_did_common::Document =
        serde_json::from_value(did_hosting_common::scid::scid_document(&r.document).unwrap())
            .unwrap();
    client.add_did_document(&r.scid_did, scid).await;
}

/// The terms the tests open [`DOMAIN`] with: invites and `vtc`'s vouchers,
/// under `agents/`, three accounts of two DIDs each.
fn terms(vtc: &str, enabled: bool) -> Value {
    json!({
        "domain": DOMAIN,
        "enabled": enabled,
        "admissions": ["invite", "voucher"],
        "trustedIssuers": [{ "did": vtc, "label": "Test community" }],
        "pathPrefixes": ["agents"],
        "maxRegistrations": 3,
        "maxDidCount": 2,
        "inactivityDays": 90,
        "graceDays": 30,
        "maxPendingInvites": 100,
    })
}

async fn set_terms(state: &AppState, admin: &Caller, policy: Value) -> Value {
    let reply = call(
        state,
        Via::Https,
        admin,
        policy_set::v0_1::Payload::TYPE_URI,
        json!({ "policy": policy }),
    )
    .await;
    if reply["type"]
        .as_str()
        .is_some_and(|t| t.ends_with("#response"))
    {
        conforms(&reply);
    }
    reply
}

/// A control plane whose [`DOMAIN`] is registered and opened, at runtime, to
/// self-registration by invite and by a voucher from `vtc`, with an
/// administrator to issue invites.
async fn guest_state(vtc: &str) -> (AppState, tempfile::TempDir, Caller) {
    let (mut state, dir) = state().await;
    // One cache for the voucher issuer's did:key and the DIDs the tests host,
    // read by the gate's verifier as well as the voucher check.
    let client = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    .unwrap();
    state.trust_tasks_verifier = Some(Arc::new(
        did_hosting_common::server::trust_tasks::TransportBoundVerifier::with_resolver(Arc::new(
            HostedResolver {
                cache: trust_tasks_proof::affinidi::CachedDidResolver::new(Arc::new(
                    client.clone(),
                )),
            },
        )),
    ));
    state.did_resolver = Some(client);
    let admin = member(&state, 1, Role::Admin).await;
    let created = call(
        &state,
        Via::Https,
        &admin,
        domain_create::v0_1::Payload::TYPE_URI,
        json!({ "name": DOMAIN }),
    )
    .await;
    ok(&created, domain_create::v0_1::Payload::TYPE_URI);
    let reply = set_terms(&state, &admin, terms(vtc, true)).await;
    assert_eq!(
        ok(&reply, policy_set::v0_1::Payload::TYPE_URI)["changed"],
        true
    );
    (state, dir, admin)
}

/// Both halves of a fresh invite for [`DOMAIN`].
async fn invite(state: &AppState, admin: &Caller) -> (String, String, String) {
    let reply = call(
        state,
        Via::Https,
        admin,
        issue::v0_1::Payload::TYPE_URI,
        json!({ "domain": DOMAIN, "pathPrefix": "agents", "ttlSeconds": 3600 }),
    )
    .await;
    conforms(&reply);
    let p = ok(&reply, issue::v0_1::Payload::TYPE_URI);
    (
        p["invite"]["inviteId"].as_str().unwrap().into(),
        p["token"].as_str().unwrap().into(),
        p["claimCode"].as_str().unwrap().into(),
    )
}

fn register_payload(r: &Registrant, admission: Value) -> Value {
    json!({
        "domain": DOMAIN,
        "path": r.path,
        "method": "webvh",
        "didData": r.log,
        "admission": admission,
    })
}

fn invite_admission(token: &str, claim: &str) -> Value {
    json!({ "invite": { "token": token, "claimCode": claim } })
}

fn reason(reply: &Value) -> String {
    reply["payload"]["details"]["reason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn an_invited_stranger_registers_its_own_did_on_every_transport() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    for (n, via) in VIAS.into_iter().enumerate() {
        let r = registrant(&format!("agents/agent-{n}")).await;
        let (invite_id, token, claim) = invite(&state, &admin).await;
        let reply = call(
            &state,
            via,
            &r.caller(),
            REGISTER,
            register_payload(&r, invite_admission(&token, &claim)),
        )
        .await;
        conforms(&reply);
        let p = ok(&reply, REGISTER);
        assert_eq!(p["account"]["subject"], r.did, "{via:?}");
        assert_eq!(p["account"]["role"], "owner");
        assert_eq!(p["account"]["state"], "active");
        assert_eq!(p["account"]["admission"], "invite");
        assert!(p["account"]["disableAt"].is_string());
        assert_eq!(p["record"]["owner"], r.did);
        assert_eq!(p["record"]["didId"], r.did);

        let entry = get_acl_entry(&state.acl_ks, &r.did).await.unwrap().unwrap();
        assert_eq!(entry.role, Role::Owner);
        assert_eq!(entry.max_did_count, Some(2));

        // The invite is spent, and says by whom.
        let listed = call(
            &state,
            Via::Https,
            &admin,
            invite_list::v0_1::Payload::TYPE_URI,
            json!({ "domain": DOMAIN }),
        )
        .await;
        conforms(&listed);
        let invites = ok(&listed, invite_list::v0_1::Payload::TYPE_URI)["invites"].clone();
        let spent = invites
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["inviteId"] == invite_id.as_str())
            .unwrap();
        assert_eq!(spent["state"], "redeemed");
        assert_eq!(spent["redeemedBy"], r.did);

        // Registered once: a second registration is refused.
        let again = call(
            &state,
            via,
            &r.caller(),
            REGISTER,
            register_payload(&r, invite_admission(&token, &claim)),
        )
        .await;
        assert_eq!(
            code(&again),
            register::v0_1::error_codes::ALREADY_REGISTERED.code
        );
    }
}

#[tokio::test]
async fn a_did_scid_registrant_is_its_own_identity() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let r = registrant("agents/scid-agent").await;
    let (_, token, claim) = invite(&state, &admin).await;
    let reply = call(
        &state,
        Via::Https,
        &r.scid_caller(),
        REGISTER,
        register_payload(&r, invite_admission(&token, &claim)),
    )
    .await;
    let p = ok(&reply, REGISTER);
    assert_eq!(p["account"]["subject"], r.scid_did);
    assert_eq!(p["record"]["owner"], r.scid_did);
    // The ACL entry is the form that signed; the did:webvh form has none.
    assert!(
        get_acl_entry(&state.acl_ks, &r.scid_did)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        get_acl_entry(&state.acl_ks, &r.did)
            .await
            .unwrap()
            .is_none()
    );

    // And it signs as that identity from now on.
    hosted(&state, &r).await;
    let reply = call(
        &state,
        Via::Tsp,
        &r.scid_caller(),
        status::v0_1::Payload::TYPE_URI,
        json!({}),
    )
    .await;
    conforms(&reply);
}

#[tokio::test]
async fn a_did_scid_the_document_does_not_list_is_not_the_registrant() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let r = registrant_with("agents/no-alias", |doc| {
        doc.as_object_mut().unwrap().remove("alsoKnownAs");
    })
    .await;
    let (_, token, claim) = invite(&state, &admin).await;
    let reply = call(
        &state,
        Via::Https,
        &r.scid_caller(),
        REGISTER,
        register_payload(&r, invite_admission(&token, &claim)),
    )
    .await;
    assert_eq!(
        code(&reply),
        register::v0_1::error_codes::ISSUER_NOT_SUBJECT.code
    );
}

#[tokio::test]
async fn another_partys_log_cannot_be_registered() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let victim = registrant("agents/victim").await;
    let (_, token, claim) = invite(&state, &admin).await;
    // A stranger presents a valid invite and the victim's log as itself.
    let thief = stranger(42);
    let reply = call(
        &state,
        Via::Https,
        &thief,
        REGISTER,
        register_payload(&victim, invite_admission(&token, &claim)),
    )
    .await;
    assert_eq!(
        code(&reply),
        register::v0_1::error_codes::ISSUER_NOT_SUBJECT.code
    );
    // Or claims to be the victim, signing with its own key.
    let forged = Caller {
        did: victim.did.clone(),
        key: Secret::generate_ed25519(Some(&format!("{}#key-0", victim.did)), Some(&[3; 32])),
        role: Role::Owner,
    };
    let reply = call(
        &state,
        Via::Https,
        &forged,
        REGISTER,
        register_payload(&victim, invite_admission(&token, &claim)),
    )
    .await;
    assert_eq!(code(&reply), "proofInvalid");
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("agents/victim"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn admission_is_checked_before_anything_is_written() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let r = registrant("agents/hopeful").await;
    let (invite_id, token, claim) = invite(&state, &admin).await;

    // A wrong claim code.
    let reply = call(
        &state,
        Via::Https,
        &r.caller(),
        REGISTER,
        register_payload(&r, invite_admission(&token, "0000-0000-0000")),
    )
    .await;
    assert_eq!(
        code(&reply),
        register::v0_1::error_codes::ADMISSION_REFUSED.code
    );
    assert_eq!(reason(&reply), "unknownInvite");

    // A path outside the domain's prefix.
    let outside = registrant("elsewhere").await;
    let reply = call(
        &state,
        Via::Https,
        &outside.caller(),
        REGISTER,
        register_payload(&outside, invite_admission(&token, &claim)),
    )
    .await;
    assert_eq!(
        code(&reply),
        register::v0_1::error_codes::PATH_NOT_ALLOWED.code
    );

    // A revoked invite.
    let revoked = call(
        &state,
        Via::Https,
        &admin,
        revoke::v0_1::Payload::TYPE_URI,
        json!({ "inviteId": invite_id }),
    )
    .await;
    conforms(&revoked);
    assert_eq!(
        ok(&revoked, revoke::v0_1::Payload::TYPE_URI)["changed"],
        true
    );
    let reply = call(
        &state,
        Via::Https,
        &r.caller(),
        REGISTER,
        register_payload(&r, invite_admission(&token, &claim)),
    )
    .await;
    assert_eq!(
        code(&reply),
        register::v0_1::error_codes::ADMISSION_REFUSED.code
    );

    assert!(
        get_acl_entry(&state.acl_ks, &r.did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("agents/hopeful"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_domain_that_admits_no_guests_is_closed() {
    let (state, _dir) = state().await;
    let r = registrant("agents/closed").await;
    let reply = call(
        &state,
        Via::Https,
        &r.caller(),
        REGISTER,
        register_payload(
            &r,
            invite_admission("inv_aaaaaaaaaaaaaaaaaaaa", "AAAA-AAAA-AAAA"),
        ),
    )
    .await;
    assert_eq!(
        code(&reply),
        register::v0_1::error_codes::REGISTRATION_CLOSED.code
    );
}

/// A `DidHostingVoucher` for `subject`, signed by `vtc_key`.
async fn voucher(vtc: &str, vtc_key: &Secret, subject: &str, audience: &str) -> Value {
    use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
    let unsigned = json!({
        "type": ["VerifiableCredential", "DidHostingVoucher"],
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "issuer": vtc,
        "validUntil": (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "credentialSubject": { "id": subject, "hostingService": audience },
    });
    sign_trust_task(
        &unsigned,
        vtc_key,
        SignOptions::new()
            .with_proof_purpose("assertionMethod")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_trusted_communitys_voucher_admits_once() {
    let (vtc, vtc_key) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, _admin) = guest_state(&vtc).await;
    let r = registrant("agents/member").await;
    let v = voucher(&vtc, &vtc_key, &r.did, CONTROL).await;
    let reply = call(
        &state,
        Via::Didcomm,
        &r.caller(),
        REGISTER,
        register_payload(&r, json!({ "voucher": v })),
    )
    .await;
    conforms(&reply);
    assert_eq!(ok(&reply, REGISTER)["account"]["admission"], "voucher");

    // The same voucher admits nobody else, even naming them.
    let other = registrant("agents/member-2").await;
    let reply = call(
        &state,
        Via::Https,
        &other.caller(),
        REGISTER,
        register_payload(&other, json!({ "voucher": v })),
    )
    .await;
    assert_eq!(reason(&reply), "voucherSubject");

    // An untrusted community's, or one for another service, admits no one.
    let (rogue, rogue_key) = crate::signing::test_util::did_key_signer(&[8; 32]);
    let reply = call(
        &state,
        Via::Https,
        &other.caller(),
        REGISTER,
        register_payload(
            &other,
            json!({ "voucher": voucher(&rogue, &rogue_key, &other.did, CONTROL).await }),
        ),
    )
    .await;
    assert_eq!(reason(&reply), "untrustedIssuer");
    let reply = call(
        &state,
        Via::Https,
        &other.caller(),
        REGISTER,
        register_payload(
            &other,
            json!({ "voucher": voucher(&vtc, &vtc_key, &other.did, "did:webvh:x:other.example").await }),
        ),
    )
    .await;
    assert_eq!(reason(&reply), "voucherAudience");

    // A tampered voucher fails its proof.
    let mut tampered = voucher(&vtc, &vtc_key, &other.did, CONTROL).await;
    tampered["validUntil"] = json!(
        (chrono::Utc::now() + chrono::Duration::hours(2))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    let reply = call(
        &state,
        Via::Https,
        &other.caller(),
        REGISTER,
        register_payload(&other, json!({ "voucher": tampered })),
    )
    .await;
    assert_eq!(reason(&reply), "voucherInvalid");
}

#[tokio::test]
async fn a_self_registered_account_holds_no_agent_names() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let r = registrant_with("agents/named", |doc| {
        doc["alsoKnownAs"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!("{DOMAIN}/@grabbed")));
    })
    .await;
    let (_, token, claim) = invite(&state, &admin).await;
    let reply = call(
        &state,
        Via::Https,
        &r.caller(),
        REGISTER,
        register_payload(&r, invite_admission(&token, &claim)),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied");
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("agents/named"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_domain_admits_no_more_than_its_capacity() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    for n in 0..3 {
        let r = registrant(&format!("agents/full-{n}")).await;
        let (_, token, claim) = invite(&state, &admin).await;
        let reply = call(
            &state,
            Via::Https,
            &r.caller(),
            REGISTER,
            register_payload(&r, invite_admission(&token, &claim)),
        )
        .await;
        ok(&reply, REGISTER);
    }
    let r = registrant("agents/full-3").await;
    let (invite_id, token, claim) = invite(&state, &admin).await;
    let reply = call(
        &state,
        Via::Https,
        &r.caller(),
        REGISTER,
        register_payload(&r, invite_admission(&token, &claim)),
    )
    .await;
    assert_eq!(
        code(&reply),
        register::v0_1::error_codes::CAPACITY_REACHED.code
    );
    // The refusal spent nothing.
    let invite = account::invite::by_id(&state.acl_ks, &invite_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        invite.state(did_hosting_common::server::auth::session::now_epoch()),
        account::invite::InviteState::Pending
    );
}

#[tokio::test]
async fn server_info_publishes_the_guest_terms() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, _admin) = guest_state(&vtc).await;
    let reply = https(
        &state,
        None,
        json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "type": info::v0_2::Payload::TYPE_URI,
            "payload": {},
        }),
    )
    .await;
    conforms(&reply);
    let terms = &ok(&reply, info::v0_2::Payload::TYPE_URI)["selfRegistration"][0];
    assert_eq!(terms["domain"], DOMAIN);
    assert_eq!(terms["pathPrefixes"], json!(["agents"]));
    assert_eq!(terms["admissions"], json!(["invite", "voucher"]));
    assert_eq!(terms["trustedVoucherIssuers"], json!([vtc]));
    assert_eq!(terms["inactivityDays"], 90);
}

/// Register `r` with a fresh invite.
async fn registered(state: &AppState, admin: &Caller, r: &Registrant) {
    let (_, token, claim) = invite(state, admin).await;
    let reply = call(
        state,
        Via::Https,
        &r.caller(),
        REGISTER,
        register_payload(r, invite_admission(&token, &claim)),
    )
    .await;
    ok(&reply, REGISTER);
    hosted(state, r).await;
}

/// Move `subject`'s account `days` into the past.
async fn age(state: &AppState, subject: &str, days: u64) {
    let mut record = account::get(&state.acl_ks, subject).await.unwrap().unwrap();
    let shift = days * 24 * 3600;
    record.last_active_at -= shift;
    record.registered_at -= shift;
    if let Some(t) = record.disabled_at.as_mut() {
        *t -= shift;
    }
    account::save(&state.acl_ks, &record).await.unwrap();
}

#[tokio::test]
async fn an_unused_guest_is_disabled_renewed_and_finally_purged() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let r = registrant("agents/sleepy").await;
    Box::pin(registered(&state, &admin, &r)).await;

    // Within its period: nothing happens.
    assert_eq!(
        Box::pin(crate::account_lifecycle::sweep_once(&state)).await,
        0
    );

    // Close to its end: warned.
    age(&state, &r.did, 80).await;
    Box::pin(crate::account_lifecycle::sweep_once(&state)).await;
    let record = account::get(&state.acl_ks, &r.did).await.unwrap().unwrap();
    assert_eq!(record.state, AccountState::Warned);

    // Past it: disabled, and its DID stops resolving.
    age(&state, &r.did, 11).await;
    Box::pin(crate::account_lifecycle::sweep_once(&state)).await;
    let record = account::get(&state.acl_ks, &r.did).await.unwrap().unwrap();
    assert_eq!(record.state, AccountState::Disabled);
    assert_eq!(record.expiry_disabled, vec!["agents/sleepy".to_string()]);
    let slot: DidRecord = state
        .dids_ks
        .get(did_key("agents/sleepy"))
        .await
        .unwrap()
        .unwrap();
    assert!(slot.disabled && !slot.disabled_by_admin);

    // Status says so, and does not keep it alive.
    let reply = call(
        &state,
        Via::Tsp,
        &r.caller(),
        status::v0_1::Payload::TYPE_URI,
        json!({}),
    )
    .await;
    conforms(&reply);
    let account = ok(&reply, status::v0_1::Payload::TYPE_URI)["account"].clone();
    assert_eq!(account["state"], "disabled");
    assert!(account["purgeAt"].is_string());

    // The holder renews: restored.
    let reply = call(
        &state,
        Via::Tsp,
        &r.caller(),
        renew::v0_1::Payload::TYPE_URI,
        json!({}),
    )
    .await;
    conforms(&reply);
    let p = ok(&reply, renew::v0_1::Payload::TYPE_URI);
    assert_eq!(p["changed"], true);
    assert_eq!(p["account"]["state"], "active");
    let slot: DidRecord = state
        .dids_ks
        .get(did_key("agents/sleepy"))
        .await
        .unwrap()
        .unwrap();
    assert!(!slot.disabled);

    // Left unused through its period and its grace: purged.
    age(&state, &r.did, 91).await;
    Box::pin(crate::account_lifecycle::sweep_once(&state)).await;
    age(&state, &r.did, 31).await;
    Box::pin(crate::account_lifecycle::sweep_once(&state)).await;
    assert!(account::get(&state.acl_ks, &r.did).await.unwrap().is_none());
    assert!(
        get_acl_entry(&state.acl_ks, &r.did)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("agents/sleepy"))
            .await
            .unwrap()
            .is_none()
    );

    // It is a stranger again, free to register anew.
    let reply = call(
        &state,
        Via::Tsp,
        &r.caller(),
        status::v0_1::Payload::TYPE_URI,
        json!({}),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied");
}

#[tokio::test]
async fn closing_a_domain_stops_registrations_not_accounts() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let r = registrant("agents/early").await;
    Box::pin(registered(&state, &admin, &r)).await;
    let (_, token, claim) = invite(&state, &admin).await;

    // Closed at runtime, with no restart.
    let reply = set_terms(&state, &admin, terms(&vtc, false)).await;
    assert_eq!(
        ok(&reply, policy_set::v0_1::Payload::TYPE_URI)["changed"],
        true
    );
    let late = registrant("agents/late").await;
    let reply = call(
        &state,
        Via::Https,
        &late.caller(),
        REGISTER,
        register_payload(&late, invite_admission(&token, &claim)),
    )
    .await;
    assert_eq!(
        code(&reply),
        register::v0_1::error_codes::REGISTRATION_CLOSED.code
    );

    // The account registered before keeps working.
    let reply = call(
        &state,
        Via::Tsp,
        &r.caller(),
        renew::v0_1::Payload::TYPE_URI,
        json!({}),
    )
    .await;
    ok(&reply, renew::v0_1::Payload::TYPE_URI);

    // And a closed domain is not published.
    let info = https(
        &state,
        None,
        json!({ "id": "urn:uuid:00000000-0000-4000-8000-000000000002",
                "type": info::v0_2::Payload::TYPE_URI, "payload": {} }),
    )
    .await;
    assert!(
        ok(&info, info::v0_2::Payload::TYPE_URI)
            .get("selfRegistration")
            .is_none()
    );

    // Setting the same terms again changes nothing.
    let reply = set_terms(&state, &admin, terms(&vtc, false)).await;
    assert_eq!(
        ok(&reply, policy_set::v0_1::Payload::TYPE_URI)["changed"],
        false
    );
}

#[tokio::test]
async fn inconsistent_terms_are_refused_and_listed_terms_carry_labels() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let mut bad = terms(&vtc, true);
    bad["trustedIssuers"] = json!([]);
    let reply = set_terms(&state, &admin, bad).await;
    assert_eq!(
        code(&reply),
        policy_set::v0_1::error_codes::INVALID_POLICY.code
    );

    let reply = call(
        &state,
        Via::Https,
        &admin,
        policy_list::v0_1::Payload::TYPE_URI,
        json!({}),
    )
    .await;
    conforms(&reply);
    let listed = &ok(&reply, policy_list::v0_1::Payload::TYPE_URI)["policies"][0];
    assert_eq!(listed["trustedIssuers"][0]["label"], "Test community");
    assert_eq!(listed["updatedBy"], admin.did);

    // An owner may not read or set them.
    let owner = member(&state, 7, Role::Owner).await;
    let reply = call(
        &state,
        Via::Https,
        &owner,
        policy_list::v0_1::Payload::TYPE_URI,
        json!({}),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied");
}

#[tokio::test]
async fn a_referral_is_verified_only_by_the_evidence() {
    let (vtc, vtc_key) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;

    // Stated with an invite that carries none: recorded, unverified.
    let r = registrant("agents/claims").await;
    let (_, token, claim) = invite(&state, &admin).await;
    let mut payload = register_payload(&r, invite_admission(&token, &claim));
    payload["referral"] = json!({ "via": "did:example:somewhere", "label": "word of mouth" });
    let reply = call(&state, Via::Https, &r.caller(), REGISTER, payload).await;
    conforms(&reply);
    let referral = &ok(&reply, REGISTER)["account"]["referral"];
    assert_eq!(referral["via"], "did:example:somewhere");
    assert_eq!(referral["verified"], false);

    // A voucher fills `via` from its issuer, verified.
    let v = registrant("agents/vouched").await;
    let reply = call(
        &state,
        Via::Https,
        &v.caller(),
        REGISTER,
        register_payload(
            &v,
            json!({ "voucher": voucher(&vtc, &vtc_key, &v.did, CONTROL).await }),
        ),
    )
    .await;
    let referral = &ok(&reply, REGISTER)["account"]["referral"];
    assert_eq!(referral["via"], vtc);
    assert_eq!(referral["verified"], true);

    // An invite's own referral replaces the registrant's, verified.
    let i = registrant("agents/invited").await;
    let issued = call(
        &state,
        Via::Https,
        &admin,
        issue::v0_1::Payload::TYPE_URI,
        json!({ "domain": DOMAIN, "ttlSeconds": 3600,
                "referral": { "via": vtc, "label": "pilot" } }),
    )
    .await;
    conforms(&issued);
    let issued = ok(&issued, issue::v0_1::Payload::TYPE_URI);
    let mut payload = register_payload(
        &i,
        invite_admission(
            issued["token"].as_str().unwrap(),
            issued["claimCode"].as_str().unwrap(),
        ),
    );
    payload["referral"] = json!({ "label": "self-reported" });
    let reply = call(&state, Via::Https, &i.caller(), REGISTER, payload).await;
    let referral = &ok(&reply, REGISTER)["account"]["referral"];
    assert_eq!(referral["label"], "pilot");
    assert_eq!(referral["verified"], true);

    // And the invite list filters on it.
    let listed = call(
        &state,
        Via::Https,
        &admin,
        invite_list::v0_1::Payload::TYPE_URI,
        json!({ "referralVia": vtc }),
    )
    .await;
    assert_eq!(
        ok(&listed, invite_list::v0_1::Payload::TYPE_URI)["invites"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_self_registered_account_publishes_further_dids_under_its_prefix_within_its_quota() {
    use did_hosting_common::tasks::did_management::did::register as did_register;
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let r = registrant("agents/vta").await;
    Box::pin(registered(&state, &admin, &r)).await;

    let publish = |path: &'static str| {
        let state = state.clone();
        let caller = r.caller();
        Box::pin(async move {
            let persona = registrant(path).await;
            call(
                &state,
                Via::Https,
                &caller,
                did_register::v0_1::Payload::TYPE_URI,
                json!({
                    "path": path,
                    "method": "webvh",
                    "didData": persona.log,
                    "domain": DOMAIN,
                }),
            )
            .await
        })
    };
    // Outside the domain's prefix: refused.
    assert_eq!(code(&publish("persona-x").await), "permissionDenied");
    // Under it: its second DID, owned by the guest.
    let reply = publish("agents/persona-1").await;
    let p = ok(&reply, did_register::v0_1::Payload::TYPE_URI);
    assert_eq!(p["record"]["owner"], r.did);
    // A third exceeds its `max_did_count` of 2.
    let reply = publish("agents/persona-2").await;
    assert!(
        code(&reply).ends_with("quotaExceeded") || code(&reply) == "taskFailed",
        "{reply}"
    );
}

#[tokio::test]
async fn an_administrator_exempts_an_account_from_its_terms_and_back() {
    use did_hosting_common::tasks::did_management::did::register as did_register;
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    let r = registrant("agents/partner").await;
    Box::pin(registered(&state, &admin, &r)).await;

    // Disabled for inactivity, then exempted: restored, and it never expires.
    age(&state, &r.did, 91).await;
    Box::pin(crate::account_lifecycle::sweep_once(&state)).await;
    let exempt_it = |on: bool| {
        let state = state.clone();
        let did = r.did.clone();
        let admin = Caller {
            did: admin.did.clone(),
            key: admin.key.clone(),
            role: Role::Admin,
        };
        Box::pin(async move {
            call(
                &state,
                Via::Https,
                &admin,
                exempt::v0_1::Payload::TYPE_URI,
                json!({ "subject": did, "exempt": on }),
            )
            .await
        })
    };
    let reply = exempt_it(true).await;
    conforms(&reply);
    let p = ok(&reply, exempt::v0_1::Payload::TYPE_URI);
    assert_eq!(p["changed"], true);
    assert_eq!(p["account"]["exempt"], true);
    assert_eq!(p["account"]["state"], "active");
    assert!(p["account"].get("disableAt").is_none());
    let slot: DidRecord = state
        .dids_ks
        .get(did_key("agents/partner"))
        .await
        .unwrap()
        .unwrap();
    assert!(!slot.disabled);
    age(&state, &r.did, 400).await;
    Box::pin(crate::account_lifecycle::sweep_once(&state)).await;
    assert_eq!(
        account::get(&state.acl_ks, &r.did)
            .await
            .unwrap()
            .unwrap()
            .state,
        AccountState::Active
    );

    // Exempt, it may publish outside the prefixes.
    let elsewhere = registrant("partner-site").await;
    let reply = call(
        &state,
        Via::Https,
        &r.caller(),
        did_register::v0_1::Payload::TYPE_URI,
        json!({ "path": "partner-site", "method": "webvh", "didData": elsewhere.log, "domain": DOMAIN }),
    )
    .await;
    ok(&reply, did_register::v0_1::Payload::TYPE_URI);

    // Held to its terms again, its inactivity period starts afresh.
    let reply = exempt_it(false).await;
    let p = ok(&reply, exempt::v0_1::Payload::TYPE_URI);
    assert_eq!(p["changed"], true);
    assert!(p["account"]["disableAt"].is_string());
    assert_eq!(
        ok(&exempt_it(false).await, exempt::v0_1::Payload::TYPE_URI)["changed"],
        false
    );

    // Only an administrator exempts, and only a self-registered account.
    let reply = call(
        &state,
        Via::Https,
        &r.caller(),
        exempt::v0_1::Payload::TYPE_URI,
        json!({ "subject": r.did, "exempt": true }),
    )
    .await;
    assert_eq!(code(&reply), "permissionDenied");
    let owner = member(&state, 7, Role::Owner).await;
    let reply = call(
        &state,
        Via::Https,
        &admin,
        exempt::v0_1::Payload::TYPE_URI,
        json!({ "subject": owner.did, "exempt": true }),
    )
    .await;
    assert_eq!(code(&reply), exempt::v0_1::error_codes::NO_ACCOUNT.code);
}

/// A disabled account's DID does not resolve (it answers 404), so its
/// holder's `renew` and `status` are verified against the host's stored log
/// for it, not by resolution. Here the registrant is never made resolvable at
/// all: only the stored log can authenticate it, before and after it is
/// disabled.
#[tokio::test]
async fn a_disabled_account_renews_from_its_stored_log() {
    let (vtc, _) = crate::signing::test_util::did_key_signer(&[9; 32]);
    let (state, _dir, admin) = guest_state(&vtc).await;
    for (path, as_scid) in [("agents/stored-webvh", false), ("agents/stored-scid", true)] {
        let r = registrant(path).await;
        let caller = if as_scid { r.scid_caller() } else { r.caller() };
        let subject = caller.did.clone();
        let (_, token, claim) = invite(&state, &admin).await;
        let reply = call(
            &state,
            Via::Https,
            &caller,
            REGISTER,
            register_payload(&r, invite_admission(&token, &claim)),
        )
        .await;
        ok(&reply, REGISTER);

        // Disabled for inactivity: its slot no longer serves.
        age(&state, &subject, 91).await;
        Box::pin(crate::account_lifecycle::sweep_once(&state)).await;
        let slot: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
        assert!(slot.disabled, "{subject}");

        // Status still answers, and says so.
        let reply = call(
            &state,
            Via::Tsp,
            &caller,
            status::v0_1::Payload::TYPE_URI,
            json!({}),
        )
        .await;
        conforms(&reply);
        assert_eq!(
            ok(&reply, status::v0_1::Payload::TYPE_URI)["account"]["state"],
            "disabled",
            "{subject}"
        );

        // And renew restores it.
        let reply = call(
            &state,
            Via::Https,
            &caller,
            renew::v0_1::Payload::TYPE_URI,
            json!({}),
        )
        .await;
        conforms(&reply);
        let p = ok(&reply, renew::v0_1::Payload::TYPE_URI);
        assert_eq!(p["changed"], true, "{subject}");
        assert_eq!(p["account"]["state"], "active", "{subject}");
        let slot: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
        assert!(!slot.disabled, "{subject}");
    }
}

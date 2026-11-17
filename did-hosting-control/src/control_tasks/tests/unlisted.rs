//! Signers the ACL does not list (`crate::unlisted_signers`).

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
    // Every refusal from it is an unreachable signer: its failures stand
    // in for a DID that cannot be resolved.
    state.trust_tasks_verifier = Some(Arc::new(TransportBoundVerifier::with_unreachable_resolver(
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
///
/// The quota is counted over a day here rather than
/// `SIGN_IN_WINDOW_SECS`: at the default a source gets a record back
/// every half second, and these requests (each signed and verified) can
/// take longer than that on a loaded machine, which would admit the one
/// past the quota. A day returns one every 12 minutes.
#[tokio::test]
async fn sign_in_records_are_limited_per_source() {
    let (mut state, _dir) = state().await;
    state.unlisted_signers = Arc::new(UnlistedSigners::default().with_sign_in_window(86_400));
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

/// The ACL pre-filter runs before any proof work: a stranger's operational
/// request is refused for the cost of a key lookup, on every transport —
/// nothing is resolved and no replay cache records it.
#[tokio::test]
async fn a_strangers_operational_request_is_refused_before_any_proof_work() {
    let (mut state, _dir) = state().await;
    let calls = counting(&mut state, false, default_limits());
    let web = web_caller("prefiltered", 85);
    for via in VIAS {
        let reply = send_signed(&state, via, &web, "did-management/server/config/0.1").await;
        assert_eq!(code(&reply), "permissionDenied", "{via:?}: {reply}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(state.replay_cache.is_empty());
    assert!(state.unlisted_signers.sign_in.is_empty());
    assert!(state.unlisted_signers.other.is_empty());
}

/// A session ceremony (`ProofRule::SessionKey`) whose proof is by anything
/// but a `did:key` is refused by name before its proof is verified — even
/// from an ACL member — and so before any resolution or replay record.
#[tokio::test]
async fn a_session_ceremony_not_signed_by_a_did_key_is_refused_before_verification() {
    use did_hosting_common::tasks::auth::passkey::login::finish::v0_2 as finish;
    use trust_tasks_rs::Payload as _;

    let (mut state, _dir) = state().await;
    let calls = counting(&mut state, false, default_limits());
    let web = web_caller("ceremony", 86);
    did_hosting_common::server::acl::store_acl_entry(
        &state.acl_ks,
        &did_hosting_common::server::acl::AclEntry {
            did: web.did.clone(),
            role: Role::Admin,
            label: None,
            created_at: 1_700_000_000,
            max_total_size: None,
            max_did_count: None,
            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .unwrap();
    let doc = signed(
        request(finish::Payload::TYPE_URI, &web.did, json!({})),
        &web.key,
    )
    .await;
    let reply = send(&state, Via::Tsp, &web, doc).await;
    assert_eq!(code(&reply), "permissionDenied", "{reply}");
    assert!(
        reply["payload"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("did:key its session will be bound to")),
        "{reply}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(state.replay_cache.is_empty());
    assert!(state.unlisted_signers.sign_in.is_empty());
}

/// A proxied `auth/authenticate/0.3` from `delegate` for `principal`,
/// carrying a mandate `mandate_signer` signed naming `named_delegate`.
async fn proxied(
    delegate: &Caller,
    principal: &str,
    mandate_signer: &Secret,
    named_delegate: &str,
) -> Value {
    let mut mandate = request(
        "https://trusttasks.org/spec/local/did-hosting-auth-mandate/0.1",
        principal,
        json!({ "delegate": named_delegate }),
    );
    mandate["expiresAt"] = json!(
        (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    let mandate = signed_as_assertion(mandate, mandate_signer).await;
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

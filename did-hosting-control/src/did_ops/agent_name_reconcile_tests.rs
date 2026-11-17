//! Tests for reconciling the agent-name registry on a plain publish, and
//! the preconditions it shares with the explicit verbs.

use super::test_helpers::*;
use super::*;

use crate::server::AppState;

// -----------------------------------------------------------------------
// Registry reconciliation on plain publish (the control plane is the
// source of record for names, not just the explicit agent-name ops).
// -----------------------------------------------------------------------

/// A name bound by a *plain publish* (edit alsoKnownAs, no `set` call) is
/// registered — enabled entry + index — and can then be parked. This is the
/// integration fix: the UI binds via publish and parks via the registry op,
/// which previously failed with `NotFound`.
#[tokio::test]
async fn publish_registers_a_claimed_name_so_park_works() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-recon";
    register_owned(&state, owner, path).await;

    // Simulate the UI bind: publish a version that claims @alice.
    let bind = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    register_did_atomic(&owner_auth(owner), &state, path, &bind, false, None)
        .await
        .expect("publish");
    let rec = get_record(&state, path).await;
    assert!(
        rec.agent_names
            .iter()
            .any(|e| e.name == "alice" && e.enabled),
        "a name claimed by a plain publish must be registered enabled"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some(path),
        "plain publish must write the name index"
    );

    // Parking it now succeeds (previously NotFound — the bug).
    let park = build_test_did_log_with_names("control.test", path, &[]).await;
    let rec = disable_agent_name(&owner_auth(owner), &state, path, "alice", &park, None)
        .await
        .expect("park a publish-bound name");
    assert!(
        rec.agent_names
            .iter()
            .any(|e| e.name == "alice" && !e.enabled)
    );
}

/// A publish that drops a previously-served name releases it (entry + index
/// gone) — served state follows the signed document.
#[tokio::test]
async fn publish_releases_a_dropped_name() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-rel";
    register_owned(&state, owner, path).await;

    let bind = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    register_did_atomic(&owner_auth(owner), &state, path, &bind, false, None)
        .await
        .unwrap();
    let drop = build_test_did_log_with_names("control.test", path, &[]).await;
    register_did_atomic(&owner_auth(owner), &state, path, &drop, false, None)
        .await
        .unwrap();

    let rec = get_record(&state, path).await;
    assert!(!rec.agent_names.iter().any(|e| e.name == "alice"));
    assert_eq!(index_target(&state, "control.test", "alice").await, None);
}

/// A parked (disabled) name is NOT collateral damage of a later plain
/// publish that doesn't claim it — the reservation is held even though the
/// document omits the name.
#[tokio::test]
async fn publish_preserves_a_parked_name() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-park";
    register_owned(&state, owner, path).await;

    let bind = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    register_did_atomic(&owner_auth(owner), &state, path, &bind, false, None)
        .await
        .unwrap();
    let park = build_test_did_log_with_names("control.test", path, &[]).await;
    disable_agent_name(&owner_auth(owner), &state, path, "alice", &park, None)
        .await
        .unwrap();

    // Some later, unrelated publish (still not claiming alice).
    let other = build_test_did_log_with_names("control.test", path, &[]).await;
    register_did_atomic(&owner_auth(owner), &state, path, &other, false, None)
        .await
        .unwrap();

    let rec = get_record(&state, path).await;
    assert!(
        rec.agent_names
            .iter()
            .any(|e| e.name == "alice" && !e.enabled),
        "a parked name survives a plain publish that omits it"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some(path),
        "a parked name keeps its index reservation"
    );
}

// -----------------------------------------------------------------------
// Agent names: the publish path applies the same preconditions as `set`
//
// Reconciling the registry from `alsoKnownAs` must not become a way around
// the checks the explicit verb makes. Each of these mirrors a `set_*` test
// above, driven through a plain publish instead.
// -----------------------------------------------------------------------

/// `set` refuses a reserved name; a publish claiming one must too, or
/// `@admin` is a one-`PUT` phishing primitive.
#[tokio::test]
async fn publish_cannot_capture_a_reserved_name() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-pub-reserved";
    register_owned(&state, owner, path).await;
    let before = get_record(&state, path).await.version_count;

    let log = build_test_did_log_with_names("control.test", path, &["admin"]).await;
    let err = register_did_atomic(&owner_auth(owner), &state, path, &log, false, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::AgentName(AgentNameError::Reserved)),
        "expected Reserved, got {err:?}"
    );

    assert_eq!(
        index_target(&state, "control.test", "admin").await,
        None,
        "a refused publish must not write the index"
    );
    assert_eq!(
        get_record(&state, path).await.version_count,
        before,
        "a refused publish must not advance the version"
    );
}

/// How an operator actually binds the community name: the ordinary `set`
/// verb against the root slot, with a document claiming `control.test/@`.
/// No provisioning-template change is needed for this — the VTA re-signs
/// the document with the `alsoKnownAs` entry exactly as it does for any
/// other name.
#[tokio::test]
async fn set_binds_the_community_name_on_the_root_slot() {
    let (state, _dir) = test_state().await;
    let admin = "did:example:admin";
    let log = build_test_did_log("scid", "control.test", ".well-known").await;
    register_did_atomic(&admin_auth(admin), &state, ".well-known", &log, false, None)
        .await
        .expect("admin registers the root DID");

    let log = build_test_did_log_with_names("control.test", ".well-known", &[""]).await;
    let record = set_agent_name(&admin_auth(admin), &state, ".well-known", "", &log, None)
        .await
        .expect("set should bind the community name on the root slot");

    assert!(
        record
            .agent_names
            .iter()
            .any(|e| e.name.is_empty() && e.enabled),
        "the community name must be present and enabled"
    );
    assert_eq!(
        index_target(&state, "control.test", "").await.as_deref(),
        Some(".well-known"),
        "index must point at the root slot"
    );
}

/// The same call against a tenant slot is refused — the binding rule is
/// structural, so admin authority does not buy a way around it.
#[tokio::test]
async fn set_refuses_the_community_name_on_a_tenant_slot() {
    let (state, _dir) = test_state().await;
    let admin = "did:example:admin";
    let path = "slot-set-community";
    register_owned(&state, "did:example:owner", path).await;

    let log = build_test_did_log_with_names("control.test", path, &[""]).await;
    let err = set_agent_name(&admin_auth(admin), &state, path, "", &log, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::AgentName(AgentNameError::Reserved)),
        "expected Reserved, got {err:?}"
    );
    assert_eq!(
        index_target(&state, "control.test", "").await,
        None,
        "a refused set must not write the community index entry"
    );
}

/// The community name is the domain's own identity, so a tenant claiming
/// `control.test/@` in its `alsoKnownAs` is the sharpest form of the
/// reserved-name attack above: it would make an ordinary hosted DID answer
/// for the whole community.
#[tokio::test]
async fn publish_cannot_capture_the_community_name() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-pub-community";
    register_owned(&state, owner, path).await;
    let before = get_record(&state, path).await.version_count;

    let log = build_test_did_log_with_names("control.test", path, &[""]).await;
    let err = register_did_atomic(&owner_auth(owner), &state, path, &log, false, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::AgentName(AgentNameError::Reserved)),
        "expected Reserved, got {err:?}"
    );

    assert_eq!(
        index_target(&state, "control.test", "").await,
        None,
        "a refused publish must not write the community index entry"
    );
    assert_eq!(
        get_record(&state, path).await.version_count,
        before,
        "a refused publish must not advance the version"
    );
}

/// …and the root DID may. This is the whole point of the binding rule
/// being structural: `.well-known` is the one slot for which the community
/// name is not a capture.
#[tokio::test]
async fn root_did_may_publish_the_community_name() {
    let (state, _dir) = test_state().await;
    // The root slot is admin-only to register, so the whole flow runs as
    // admin — which is also the realistic path: `.well-known` is
    // provisioned by the operator, not by a tenant.
    let admin = "did:example:admin";
    let log = build_test_did_log("scid", "control.test", ".well-known").await;
    register_did_atomic(&admin_auth(admin), &state, ".well-known", &log, false, None)
        .await
        .expect("admin registers the root DID");

    let log = build_test_did_log_with_names("control.test", ".well-known", &[""]).await;
    register_did_atomic(&admin_auth(admin), &state, ".well-known", &log, false, None)
        .await
        .expect("the root DID may claim its domain's community name");

    assert_eq!(
        index_target(&state, "control.test", "").await.as_deref(),
        Some(".well-known"),
        "the community name should index to the root slot"
    );
}

/// `did/register` is the only live publish path, so a register of the
/// control plane's *own* DID must reach the identity reload at once — not
/// wait up to `DEFAULT_RELOAD_INTERVAL` for the backstop while the served
/// document advertises keys the listener has not loaded. A register of
/// any other DID must not.
#[tokio::test]
async fn registering_our_own_did_triggers_the_identity_reload() {
    use crate::identity_rotation::OWN_DID_RELOADS;

    let (state, _dir) = test_state().await;
    // `test_state`'s server DID is pathless, so ours is the root slot.
    assert_eq!(
        did_hosting_common::server::identity::mnemonic_from_did(
            state.config.server_did.as_deref().unwrap()
        )
        .as_deref(),
        Some(".well-known")
    );
    let admin = "did:example:admin";
    OWN_DID_RELOADS.with(|n| n.set(0));

    // Someone else's DID: no reload.
    let other = build_test_did_log("scid", "control.test", "tenant-slot").await;
    register_did_atomic(
        &admin_auth(admin),
        &state,
        "tenant-slot",
        &other,
        false,
        None,
    )
    .await
    .expect("register a tenant DID");
    assert_eq!(OWN_DID_RELOADS.with(|n| n.get()), 0);

    // Ours: first registration, then a republish — each reloads.
    let ours = build_test_did_log("scid", "control.test", ".well-known").await;
    register_did_atomic(
        &admin_auth(admin),
        &state,
        ".well-known",
        &ours,
        false,
        None,
    )
    .await
    .expect("register our own DID");
    assert_eq!(OWN_DID_RELOADS.with(|n| n.get()), 1);
    register_did_atomic(
        &admin_auth(admin),
        &state,
        ".well-known",
        &ours,
        false,
        None,
    )
    .await
    .expect("republish our own DID");
    assert_eq!(OWN_DID_RELOADS.with(|n| n.get()), 2);

    // A refused register commits nothing and so reloads nothing.
    let err = register_did_atomic(
        &owner_auth("did:example:tenant"),
        &state,
        ".well-known",
        &ours,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    assert_eq!(OWN_DID_RELOADS.with(|n| n.get()), 2);
}

/// The hijack. Layer-1 cannot catch this one: after the overwrite the
/// hijacker's document genuinely claims the name and the index genuinely
/// points at them, so a resolver's `alsoKnownAs` round-trip passes and the
/// victim's name simply stops resolving. It has to be refused here.
#[tokio::test]
async fn publish_cannot_hijack_a_name_held_by_another_did() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;

    let log_a = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    register_did_atomic(&owner_auth(owner_a), &state, "slot-a", &log_a, false, None)
        .await
        .expect("owner A binds alice");

    // B publishes a document claiming A's name.
    let log_b = build_test_did_log_with_names("control.test", "slot-b", &["alice"]).await;
    let err = register_did_atomic(&owner_auth(owner_b), &state, "slot-b", &log_b, false, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::AgentName(AgentNameError::Taken)),
        "expected Taken, got {err:?}"
    );

    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-a"),
        "the name must still resolve to its holder"
    );
    assert!(
        get_record(&state, "slot-a")
            .await
            .agent_names
            .iter()
            .any(|e| e.name == "alice" && e.enabled),
        "the holder's registry entry must be untouched"
    );
    assert!(
        !get_record(&state, "slot-b")
            .await
            .agent_names
            .iter()
            .any(|e| e.name == "alice"),
        "the hijacker must not end up registered"
    );

    // The control: the holder re-publishing its own name is not a
    // collision, it is a refresh.
    register_did_atomic(&owner_auth(owner_a), &state, "slot-a", &log_a, false, None)
        .await
        .expect("re-publishing one's own name must still work");
}

/// Parking deliberately keeps the reservation, so a parked name is exactly
/// what an opportunist would try to take — `disable` holds the index for
/// this reason, and the publish path must honour it.
#[tokio::test]
async fn publish_cannot_hijack_a_parked_name() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;

    let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    register_did_atomic(&owner_auth(owner_a), &state, "slot-a", &bind, false, None)
        .await
        .unwrap();
    let park = build_test_did_log_with_names("control.test", "slot-a", &[]).await;
    disable_agent_name(&owner_auth(owner_a), &state, "slot-a", "alice", &park, None)
        .await
        .expect("park");

    let log_b = build_test_did_log_with_names("control.test", "slot-b", &["alice"]).await;
    let err = register_did_atomic(&owner_auth(owner_b), &state, "slot-b", &log_b, false, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AppError::AgentName(AgentNameError::Taken)),
        "expected Taken, got {err:?}"
    );
    assert!(
        get_record(&state, "slot-a")
            .await
            .agent_names
            .iter()
            .any(|e| e.name == "alice" && !e.enabled),
        "the parked reservation must survive the attempt"
    );
}

/// A fresh slot is the easiest place to try a capture — nothing else about
/// registering constrains what the submitted document may claim.
#[tokio::test]
async fn register_cannot_capture_a_held_or_reserved_name() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    register_did_atomic(&owner_auth(owner_a), &state, "slot-a", &bind, false, None)
        .await
        .unwrap();

    // Register a brand-new slot whose first document claims A's name.
    let log_b = build_test_did_log_with_names("control.test", "slot-new", &["alice"]).await;
    let err = register_did_atomic(
        &owner_auth(owner_b),
        &state,
        "slot-new",
        &log_b,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::AgentName(AgentNameError::Taken)),
        "expected Taken, got {err:?}"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-a"),
    );

    // …and the same for a reserved name on a fresh slot.
    let log_r = build_test_did_log_with_names("control.test", "slot-res", &["support"]).await;
    let err = register_did_atomic(
        &owner_auth(owner_b),
        &state,
        "slot-res",
        &log_r,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::AgentName(AgentNameError::Reserved)),
        "expected Reserved, got {err:?}"
    );
}

/// `AgentName::parse` is far laxer than our grammar — it accepts uppercase,
/// single characters, dots. Such an entry is unserveable (the resolve route
/// re-validates and 404s), so it is skipped, not refused: failing the
/// publish would break documents whose `alsoKnownAs` was never meant as an
/// agent name in our sense.
#[tokio::test]
async fn publish_skips_an_unserveable_name_instead_of_failing() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-lax";
    register_owned(&state, owner, path).await;

    // "Bob" is a well-formed agent-name URI but not a valid name here.
    let log = build_test_did_log_with_names("control.test", path, &["Bob", "alice"]).await;
    register_did_atomic(&owner_auth(owner), &state, path, &log, false, None)
        .await
        .expect("an unserveable entry must not fail the publish");

    let rec = get_record(&state, path).await;
    assert!(
        rec.agent_names.iter().any(|e| e.name == "alice"),
        "the valid name still registers"
    );
    assert!(
        !rec.agent_names.iter().any(|e| e.name == "Bob"),
        "the invalid one must not enter the registry"
    );
    assert_eq!(
        index_target(&state, "control.test", "Bob").await,
        None,
        "nor the index"
    );
}

/// Releasing retires the index only while it still points here. A registry
/// entry left over from before the guards existed must not become a way to
/// delete the current holder's index.
#[tokio::test]
async fn publish_release_does_not_retire_another_dids_index() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;

    // A holds alice legitimately.
    let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    register_did_atomic(&owner_auth(owner_a), &state, "slot-a", &bind, false, None)
        .await
        .unwrap();

    // B's record carries a stale enabled entry for alice (the state an
    // earlier hijack would have left behind), while the index points at A.
    let mut rec_b = get_record(&state, "slot-b").await;
    rec_b.agent_names.push(AgentNameEntry {
        name: "alice".to_string(),
        enabled: true,
        created_at: 0,
    });
    state
        .dids_ks
        .insert(did_key("slot-b"), &rec_b)
        .await
        .unwrap();

    // B publishes without claiming alice: its own stale entry goes, but the
    // index belongs to A and must survive.
    let drop = build_test_did_log_with_names("control.test", "slot-b", &[]).await;
    register_did_atomic(&owner_auth(owner_b), &state, "slot-b", &drop, false, None)
        .await
        .unwrap();

    assert!(
        !get_record(&state, "slot-b")
            .await
            .agent_names
            .iter()
            .any(|e| e.name == "alice"),
        "B drops its stale entry"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-a"),
        "A's index entry must survive B's release"
    );
}

/// Give `path`'s record a stale enabled entry for `name` — the state an
/// earlier double claim could leave behind — without touching the index.
async fn plant_stale_name(state: &AppState, path: &str, name: &str) {
    let mut record = get_record(state, path).await;
    record.agent_names.push(AgentNameEntry {
        name: name.to_string(),
        enabled: true,
        created_at: 0,
    });
    state.dids_ks.insert(did_key(path), &record).await.unwrap();
}

/// Two slots claiming the same free name at the same moment: exactly one
/// gets it, and the index and both records agree on which. Covers both
/// the `agent-name/update` path and a plain publish.
#[tokio::test]
async fn concurrent_claims_of_one_name_bind_it_once() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;

    for round in 0..8 {
        let name = format!("name-{round}");
        let log_a = build_test_did_log_with_names("control.test", "slot-a", &[&name]).await;
        let log_b = build_test_did_log_with_names("control.test", "slot-b", &[&name]).await;
        let auth_a = owner_auth(owner_a);
        let auth_b = owner_auth(owner_b);
        let (result_a, result_b): (Result<(), AppError>, Result<(), AppError>) = if round % 2 == 0 {
            let (a, b) = tokio::join!(
                set_agent_name(&auth_a, &state, "slot-a", &name, &log_a, None),
                set_agent_name(&auth_b, &state, "slot-b", &name, &log_b, None),
            );
            (a.map(drop), b.map(drop))
        } else {
            let (a, b) = tokio::join!(
                register_did_atomic(&auth_a, &state, "slot-a", &log_a, false, None),
                register_did_atomic(&auth_b, &state, "slot-b", &log_b, false, None),
            );
            (a.map(drop), b.map(drop))
        };
        let winner = match (&result_a, &result_b) {
            (Ok(_), Err(AppError::AgentName(AgentNameError::Taken))) => "slot-a",
            (Err(AppError::AgentName(AgentNameError::Taken)), Ok(_)) => "slot-b",
            other => panic!("round {round}: expected exactly one claim to win: {other:?}"),
        };
        let loser = if winner == "slot-a" {
            "slot-b"
        } else {
            "slot-a"
        };
        assert_eq!(
            index_target(&state, "control.test", &name).await.as_deref(),
            Some(winner)
        );
        assert!(
            !get_record(&state, loser)
                .await
                .agent_names
                .iter()
                .any(|e| e.name == name),
            "round {round}: the refused slot must not list the name"
        );
    }
}

/// `remove` on a slot whose registry lists a name the index gives to
/// another slot drops its own entry and leaves the other slot's index.
#[tokio::test]
async fn remove_does_not_retire_another_slots_index() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;

    let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    set_agent_name(&owner_auth(owner_a), &state, "slot-a", "alice", &bind, None)
        .await
        .unwrap();
    plant_stale_name(&state, "slot-b", "alice").await;

    let dropped = build_test_did_log_with_names("control.test", "slot-b", &[]).await;
    let record = remove_agent_name(
        &owner_auth(owner_b),
        &state,
        "slot-b",
        "alice",
        &dropped,
        None,
    )
    .await
    .expect("B removes its own entry");
    assert!(!record.agent_names.iter().any(|e| e.name == "alice"));
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-a"),
        "A's index entry must survive B's remove"
    );
}

/// Deleting a DID releases the agent names it held, in the same write, so
/// another slot can claim them.
#[tokio::test]
async fn delete_releases_the_slots_agent_names() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;

    let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice", "bob"]).await;
    register_did_atomic(&owner_auth(owner_a), &state, "slot-a", &bind, false, None)
        .await
        .unwrap();
    let park = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    disable_agent_name(&owner_auth(owner_a), &state, "slot-a", "bob", &park, None)
        .await
        .expect("park bob");

    delete_did(&owner_auth(owner_a), &state, "slot-a", None)
        .await
        .expect("delete");
    for name in ["alice", "bob"] {
        assert_eq!(
            index_target(&state, "control.test", name).await,
            None,
            "{name}: active and parked names are both released"
        );
    }

    let claim = build_test_did_log_with_names("control.test", "slot-b", &["alice"]).await;
    set_agent_name(
        &owner_auth(owner_b),
        &state,
        "slot-b",
        "alice",
        &claim,
        None,
    )
    .await
    .expect("a released name is free");
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-b")
    );
}

/// Deleting a slot whose registry lists a name the index gives to another
/// slot leaves that index entry alone.
#[tokio::test]
async fn delete_does_not_retire_another_slots_index() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;

    let bind = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    set_agent_name(&owner_auth(owner_a), &state, "slot-a", "alice", &bind, None)
        .await
        .unwrap();
    plant_stale_name(&state, "slot-b", "alice").await;

    delete_did(&owner_auth(owner_b), &state, "slot-b", None)
        .await
        .expect("delete");
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-a")
    );
}

/// An index entry pointing at a slot that no longer exists (left by a
/// delete before names were released with it) does not hold the name.
#[tokio::test]
async fn a_leftover_index_entry_does_not_hold_a_name() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    register_owned(&state, owner, "slot-a").await;
    state
        .dids_ks
        .insert_raw(
            agent_name_key("control.test", "alice"),
            b"gone-slot".to_vec(),
        )
        .await
        .unwrap();

    assert!(
        check_agent_name(&state, "control.test", "alice")
            .await
            .unwrap()
            .available
    );
    let claim = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    register_did_atomic(&owner_auth(owner), &state, "slot-a", &claim, false, None)
        .await
        .expect("a leftover entry does not block the claim");
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-a")
    );
}

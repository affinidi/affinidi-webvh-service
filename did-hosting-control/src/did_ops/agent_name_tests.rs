//! Tests for the agent-name verbs, rollback's agent-name reconcile, and
//! the availability probe.

use super::test_helpers::*;
use super::*;

use std::sync::Arc;

use crate::server::AppState;

/// An admin takeover does not hand the new owner the previous holder's
/// parked names: the reservation and its index entry are released, and a
/// name the new document claims is still registered.
#[tokio::test]
async fn an_admin_takeover_releases_the_previous_holders_parked_names() {
    let (state, _dir) = test_state().await;
    let path = "takeover-names";
    let owner = "did:example:names-owner";
    let admin = "did:example:names-admin";
    let named = build_test_did_log_with_names("control.test", path, &["kept", "parked"]).await;
    register_did_atomic(&owner_auth(owner), &state, path, &named, false, None)
        .await
        .expect("register with names");
    // Park one name, as `agent-name/set { state: parked }` leaves it: in
    // the registry, disabled, with its index entry kept.
    let mut record = get_record(&state, path).await;
    for entry in &mut record.agent_names {
        if entry.name == "parked" {
            entry.enabled = false;
        }
    }
    state.dids_ks.insert(did_key(path), &record).await.unwrap();
    assert_eq!(
        index_target(&state, "control.test", "parked")
            .await
            .as_deref(),
        Some(path)
    );

    let takeover = build_test_did_log_with_names("control.test", path, &["kept"]).await;
    register_did_atomic(&admin_auth(admin), &state, path, &takeover, true, None)
        .await
        .expect("admin takeover");

    let record = get_record(&state, path).await;
    assert_eq!(record.owner, admin);
    let names: Vec<&str> = record.agent_names.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["kept"], "{:?}", record.agent_names);
    assert_eq!(index_target(&state, "control.test", "parked").await, None);
    assert_eq!(
        index_target(&state, "control.test", "kept")
            .await
            .as_deref(),
        Some(path)
    );
}

/// Rollback removes did:webvh log entries by line. A did:web slot's
/// did.json may be pretty-printed over several lines; cutting it would
/// leave invalid JSON, so the slot is refused and left as it was.
#[tokio::test]
async fn a_did_web_slot_is_not_rolled_back() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:web-owner";
    let did_json = serde_json::to_string_pretty(&serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:control.test:plain",
    }))
    .unwrap();
    assert!(did_json.lines().count() > 2, "a multi-line document");
    // Stored as a did:web publication stores it: the document's bytes
    // unchanged under the slot's content key, and the record tagged
    // `web`.
    register_owned(&state, owner, "plain").await;
    let mut record = get_record(&state, "plain").await;
    record.method = "web".into();
    record.did_id = Some("did:web:control.test:plain".into());
    record.version_count = 1;
    record.content_size = did_json.len() as u64;
    state
        .dids_ks
        .insert(did_key("plain"), &record)
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(content_log_key("plain"), did_json.as_bytes().to_vec())
        .await
        .unwrap();
    let before = get_record(&state, "plain").await;

    for target in [None, Some(1)] {
        let err = rollback_did_to(&owner_auth(owner), &state, "plain", target)
            .await
            .expect_err("rollback refused");
        assert!(
            matches!(&err, AppError::Validation { message: m, .. } if m.contains("did:web slot")),
            "got {err:?}"
        );
    }
    let stored = state
        .dids_ks
        .get_raw(content_log_key("plain"))
        .await
        .unwrap()
        .expect("stored document");
    assert_eq!(stored, did_json.as_bytes(), "the document is unchanged");
    let after = get_record(&state, "plain").await;
    assert_eq!(after.did_id, before.did_id);
    assert_eq!(after.version_count, before.version_count);
}

/// Store a two-entry log at `path` (`first` then `second`, each a
/// one-entry log) and set the record's version count to match, so a
/// rollback has an entry to drop. The registry is left as it is.
async fn store_two_entry_log(state: &AppState, path: &str, first: &str, second: &str) {
    let content = format!("{}\n{}", first.trim_end(), second.trim_end());
    state
        .dids_ks
        .insert_raw(content_log_key(path), content.as_bytes().to_vec())
        .await
        .unwrap();
    let mut record = get_record(state, path).await;
    record.version_count = 2;
    record.content_size = content.len() as u64;
    state.dids_ks.insert(did_key(path), &record).await.unwrap();
}

/// A rollback that drops the entry which added a name releases it: the
/// registry follows the document the slot now serves.
#[tokio::test]
async fn rollback_releases_a_name_only_the_dropped_entry_claimed() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:a";
    register_owned(&state, owner, "slot-a").await;
    let named = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    register_did_atomic(&owner_auth(owner), &state, "slot-a", &named, false, None)
        .await
        .expect("bind alice");
    let plain = build_test_did_log_with_names("control.test", "slot-a", &[]).await;
    store_two_entry_log(&state, "slot-a", &plain, &named).await;

    let (record, _, removed) = rollback_did_to(&owner_auth(owner), &state, "slot-a", None)
        .await
        .expect("rollback");
    assert_eq!(removed, 1);
    assert!(
        !record.agent_names.iter().any(|e| e.name == "alice"),
        "the returned record no longer lists the name"
    );
    assert!(
        !get_record(&state, "slot-a")
            .await
            .agent_names
            .iter()
            .any(|e| e.name == "alice"),
        "the stored record no longer lists the name"
    );
    assert_eq!(index_target(&state, "control.test", "alice").await, None);
}

/// A rollback to an entry that claims a free name registers it, as a
/// publish of that entry would.
#[tokio::test]
async fn rollback_registers_a_free_name_the_kept_entry_claims() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:a";
    register_owned(&state, owner, "slot-a").await;
    let named = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    let plain = build_test_did_log_with_names("control.test", "slot-a", &[]).await;
    store_two_entry_log(&state, "slot-a", &named, &plain).await;
    assert_eq!(index_target(&state, "control.test", "alice").await, None);

    rollback_did_to(&owner_auth(owner), &state, "slot-a", None)
        .await
        .expect("rollback");
    assert!(
        get_record(&state, "slot-a")
            .await
            .agent_names
            .iter()
            .any(|e| e.name == "alice" && e.enabled),
        "the name the kept entry claims is registered"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-a")
    );
}

/// A rollback to an entry claiming a name another DID now holds is
/// refused and changes nothing: a name changes holder only through an
/// explicit `remove` by its holder.
#[tokio::test]
async fn rollback_is_refused_when_the_kept_entry_claims_a_name_held_elsewhere() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;
    let held = build_test_did_log_with_names("control.test", "slot-b", &["alice"]).await;
    register_did_atomic(&owner_auth(owner_b), &state, "slot-b", &held, false, None)
        .await
        .expect("B binds alice");

    let named = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    let plain = build_test_did_log_with_names("control.test", "slot-a", &[]).await;
    store_two_entry_log(&state, "slot-a", &named, &plain).await;
    let before = state
        .dids_ks
        .get_raw(content_log_key("slot-a"))
        .await
        .unwrap();

    let err = rollback_did_to(&owner_auth(owner_a), &state, "slot-a", None)
        .await
        .expect_err("rollback refused");
    assert!(
        matches!(err, AppError::AgentName(AgentNameError::Taken)),
        "expected Taken, got {err:?}"
    );
    let after = state
        .dids_ks
        .get_raw(content_log_key("slot-a"))
        .await
        .unwrap();
    assert_eq!(after, before, "the log is unchanged");
    assert_eq!(get_record(&state, "slot-a").await.version_count, 2);
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-b"),
        "the name stays with its holder"
    );
}

async fn enable_agent_name(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    domain: Option<&str>,
) -> Result<DidRecord, AppError> {
    set_agent_name(auth, state, mnemonic, name, did_log, domain).await
}

/// Happy path: the document claims the name, so it binds — the entry is
/// enabled, the index points at the slot, and the version advances.
/// An agent-name change commits a new log and may change the record, so
/// it must clear what the daemon's embedded server cached for the DID.
#[tokio::test]
async fn agent_name_changes_call_the_cache_invalidate_hook() {
    let (mut state, _dir) = test_state().await;
    let calls: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = calls.clone();
    state.cache_invalidate = Some(Arc::new(move |change: CacheChange<'_>| {
        recorded.lock().unwrap().push(format!("{change:?}"));
    }));
    let owner = "did:example:owner";
    let path = "slot-hook";
    register_owned(&state, owner, path).await;
    calls.lock().unwrap().clear();

    let log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    set_agent_name(&owner_auth(owner), &state, path, "alice", &log, None)
        .await
        .expect("set");
    assert_eq!(
        *calls.lock().unwrap(),
        vec![format!("{:?}", CacheChange::Did(path))]
    );
}

#[tokio::test]
async fn set_agent_name_binds_when_document_claims_it() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-set";
    register_owned(&state, owner, path).await;
    let before = get_record(&state, path).await.version_count;

    let log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    let record = set_agent_name(&owner_auth(owner), &state, path, "alice", &log, None)
        .await
        .expect("set should bind a claimed name");

    assert!(
        record
            .agent_names
            .iter()
            .any(|e| e.name == "alice" && e.enabled),
        "alice must be present and enabled"
    );
    assert_eq!(
        record.version_count,
        before + 1,
        "publish must bump version"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some(path),
        "index must point at the slot"
    );
    // A leading '@' on the argument is tolerated and canonicalised away.
    let record = get_record(&state, path).await;
    assert!(record.agent_names.iter().any(|e| e.name == "alice"));
}

/// The security test: a document that does not claim the name is rejected,
/// and — because the write is one batch — nothing is committed. No orphaned
/// index entry, no registry entry, no version bump.
#[tokio::test]
async fn set_agent_name_rejects_and_commits_nothing_on_mismatch() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-mismatch";
    register_owned(&state, owner, path).await;
    let before = get_record(&state, path).await.version_count;

    // Document claims a *different* name than the one requested.
    let log = build_test_did_log_with_names("control.test", path, &["bob"]).await;
    let err = set_agent_name(&owner_auth(owner), &state, path, "alice", &log, None)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        AppError::AgentName(AgentNameError::AlsoKnownAsMismatch)
    ));

    let record = get_record(&state, path).await;
    assert!(
        record.agent_names.is_empty(),
        "no registry entry may be written on a rejected set"
    );
    assert_eq!(
        record.version_count, before,
        "a rejected set must not advance the version"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice").await,
        None,
        "no index entry may leak on a rejected set (atomicity)"
    );
}

/// A reserved name is refused up front with the typed error, before any
/// document work.
#[tokio::test]
async fn set_agent_name_rejects_reserved() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-reserved";
    register_owned(&state, owner, path).await;

    let log = build_test_did_log_with_names("control.test", path, &["admin"]).await;
    let err = set_agent_name(&owner_auth(owner), &state, path, "admin", &log, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::AgentName(AgentNameError::Reserved)));
}

/// A name bound to one DID cannot be taken by another on the same domain;
/// the same DID re-setting it is an idempotent refresh.
#[tokio::test]
async fn set_agent_name_collision_is_taken_but_same_owner_refreshes() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:a";
    let owner_b = "did:example:b";
    register_owned(&state, owner_a, "slot-a").await;
    register_owned(&state, owner_b, "slot-b").await;

    let log_a = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    set_agent_name(
        &owner_auth(owner_a),
        &state,
        "slot-a",
        "alice",
        &log_a,
        None,
    )
    .await
    .expect("first bind");

    // A different DID claiming the same name on the same domain is taken.
    let log_b = build_test_did_log_with_names("control.test", "slot-b", &["alice"]).await;
    let err = set_agent_name(
        &owner_auth(owner_b),
        &state,
        "slot-b",
        "alice",
        &log_b,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::AgentName(AgentNameError::Taken)));

    // The original owner re-setting is fine (idempotent refresh).
    let log_a2 = build_test_did_log_with_names("control.test", "slot-a", &["alice"]).await;
    set_agent_name(
        &owner_auth(owner_a),
        &state,
        "slot-a",
        "alice",
        &log_a2,
        None,
    )
    .await
    .expect("idempotent re-set by the same owner");
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some("slot-a")
    );
}

/// Seed a `DidRecord` directly on an arbitrary host. `register_did_atomic`
/// pins the DID host to the server's configured host, so multi-domain
/// tests seed the record rather than register it. The name ops themselves
/// carry no such host-pin — they scope by the record's domain.
async fn seed_record_on_host(state: &AppState, owner: &str, path: &str, host: &str) {
    let record = DidRecord {
        owner: owner.to_string(),
        mnemonic: path.to_string(),
        created_at: 0,
        updated_at: 0,
        version_count: 1,
        did_id: Some(format!("did:webvh:seed:{host}:{path}")),
        content_size: 0,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,
        method: "webvh".to_string(),
        domain: host.to_string(),
        services: None,
        agent_names: Vec::new(),
    };
    state
        .dids_ks
        .insert(did_key(path), &record)
        .await
        .expect("seed record");
}

/// The same name on two different domains does not collide — names are
/// domain-scoped by the `name:{domain}:{name}` index key.
#[tokio::test]
async fn set_agent_name_is_domain_scoped() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";

    for (host, path) in [("one.example", "slot-one"), ("two.example", "slot-two")] {
        seed_record_on_host(&state, owner, path, host).await;
        let named = build_test_did_log_with_names(host, path, &["alice"]).await;
        set_agent_name(&owner_auth(owner), &state, path, "alice", &named, None)
            .await
            .expect("bind alice on this domain");
    }

    assert_eq!(
        index_target(&state, "one.example", "alice")
            .await
            .as_deref(),
        Some("slot-one")
    );
    assert_eq!(
        index_target(&state, "two.example", "alice")
            .await
            .as_deref(),
        Some("slot-two")
    );
}

/// A non-owner (non-admin) cannot bind a name.
#[tokio::test]
async fn set_agent_name_requires_owner() {
    let (state, _dir) = test_state().await;
    register_owned(&state, "did:example:owner", "slot-auth").await;

    let log = build_test_did_log_with_names("control.test", "slot-auth", &["alice"]).await;
    let err = set_agent_name(
        &owner_auth("did:example:intruder"),
        &state,
        "slot-auth",
        "alice",
        &log,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Forbidden(_)));
}

/// Disable parks a name: the entry stays (disabled) and the index is kept
/// so the name remains reserved. The submitting document must drop the
/// name.
#[tokio::test]
async fn disable_agent_name_parks_but_keeps_reservation() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-disable";
    register_owned(&state, owner, path).await;

    let set_log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    set_agent_name(&owner_auth(owner), &state, path, "alice", &set_log, None)
        .await
        .expect("set");

    // Disabling with a document that STILL claims the name is a mismatch.
    let still_claims = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    let err = disable_agent_name(
        &owner_auth(owner),
        &state,
        path,
        "alice",
        &still_claims,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        AppError::AgentName(AgentNameError::AlsoKnownAsMismatch)
    ));

    // Disabling with a document that drops the name parks it.
    let dropped = build_test_did_log_with_names("control.test", path, &[]).await;
    let record = disable_agent_name(&owner_auth(owner), &state, path, "alice", &dropped, None)
        .await
        .expect("disable");
    assert!(
        record
            .agent_names
            .iter()
            .any(|e| e.name == "alice" && !e.enabled),
        "alice must remain present but disabled"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice")
            .await
            .as_deref(),
        Some(path),
        "a parked name keeps its index entry (stays reserved)"
    );

    // Parking again is an idempotent refresh (declarative state), not a
    // conflict — the entry stays parked and the reservation stays.
    let dropped2 = build_test_did_log_with_names("control.test", path, &[]).await;
    let record = disable_agent_name(&owner_auth(owner), &state, path, "alice", &dropped2, None)
        .await
        .expect("idempotent park");
    assert!(
        record
            .agent_names
            .iter()
            .any(|e| e.name == "alice" && !e.enabled)
    );
}

/// Enable resumes a parked name; the document must claim it again.
#[tokio::test]
async fn enable_agent_name_resumes_a_parked_name() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-enable";
    register_owned(&state, owner, path).await;

    let set_log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    set_agent_name(&owner_auth(owner), &state, path, "alice", &set_log, None)
        .await
        .expect("set");

    // Activating an already-active name is an idempotent refresh
    // (declarative state), not a conflict.
    let claims = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    let record = enable_agent_name(&owner_auth(owner), &state, path, "alice", &claims, None)
        .await
        .expect("idempotent activate");
    assert!(
        record
            .agent_names
            .iter()
            .any(|e| e.name == "alice" && e.enabled)
    );

    // Park it, then re-enable with a document that claims it again.
    let dropped = build_test_did_log_with_names("control.test", path, &[]).await;
    disable_agent_name(&owner_auth(owner), &state, path, "alice", &dropped, None)
        .await
        .expect("disable");
    let reclaim = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    let record = enable_agent_name(&owner_auth(owner), &state, path, "alice", &reclaim, None)
        .await
        .expect("enable");
    assert!(
        record
            .agent_names
            .iter()
            .any(|e| e.name == "alice" && e.enabled)
    );
}

/// Parking a name that was never bound is a not-found — there is no
/// reservation to keep. (Activating an unbound name is a bind, per the
/// declarative spec, so the not-found class only exists for `parked`.)
#[tokio::test]
async fn park_agent_name_unknown_is_not_found() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-park-unknown";
    register_owned(&state, owner, path).await;

    let dropped = build_test_did_log_with_names("control.test", path, &[]).await;
    let err = disable_agent_name(&owner_auth(owner), &state, path, "ghost", &dropped, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::AgentName(AgentNameError::NotFound)));
}

/// Remove releases a name: the entry and the index entry both go, freeing
/// the name for anyone to reclaim. The document must drop the name.
#[tokio::test]
async fn remove_agent_name_releases_the_name() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "slot-remove";
    register_owned(&state, owner, path).await;

    let set_log = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    set_agent_name(&owner_auth(owner), &state, path, "alice", &set_log, None)
        .await
        .expect("set");

    // Removing with a document that still claims the name is a mismatch.
    let still_claims = build_test_did_log_with_names("control.test", path, &["alice"]).await;
    let err = remove_agent_name(
        &owner_auth(owner),
        &state,
        path,
        "alice",
        &still_claims,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        AppError::AgentName(AgentNameError::AlsoKnownAsMismatch)
    ));

    // Removing with a document that drops it releases the name.
    let dropped = build_test_did_log_with_names("control.test", path, &[]).await;
    let record = remove_agent_name(&owner_auth(owner), &state, path, "alice", &dropped, None)
        .await
        .expect("remove");
    assert!(
        !record.agent_names.iter().any(|e| e.name == "alice"),
        "alice must be gone from the registry"
    );
    assert_eq!(
        index_target(&state, "control.test", "alice").await,
        None,
        "the index entry must be retired so the name is free"
    );

    // Removing again is not-found.
    let dropped2 = build_test_did_log_with_names("control.test", path, &[]).await;
    let err = remove_agent_name(&owner_auth(owner), &state, path, "alice", &dropped2, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::AgentName(AgentNameError::NotFound)));
}

/// Availability check: reserved → unavailable+reserved; free → available;
/// bound → unavailable; malformed → error.
#[tokio::test]
async fn check_agent_name_reports_availability() {
    let (state, _dir) = test_state().await;

    // A reserved name is unavailable but flagged reserved (not an error).
    let r = check_agent_name(&state, "control.test", "admin")
        .await
        .unwrap();
    assert!(!r.available && r.reserved);

    // A free, well-formed name is available.
    let r = check_agent_name(&state, "control.test", "alice")
        .await
        .unwrap();
    assert!(r.available && !r.reserved);

    // Once bound, it is no longer available (and not reserved).
    let owner = "did:example:owner";
    register_owned(&state, owner, "slot-chk").await;
    let log = build_test_did_log_with_names("control.test", "slot-chk", &["alice"]).await;
    set_agent_name(&owner_auth(owner), &state, "slot-chk", "alice", &log, None)
        .await
        .unwrap();
    let r = check_agent_name(&state, "control.test", "alice")
        .await
        .unwrap();
    assert!(!r.available && !r.reserved);

    // A different domain is unaffected — availability is domain-scoped.
    let r = check_agent_name(&state, "other.test", "alice")
        .await
        .unwrap();
    assert!(r.available);

    // A grammatically invalid name is a client error, not "unavailable".
    assert!(check_agent_name(&state, "control.test", "a").await.is_err());
}

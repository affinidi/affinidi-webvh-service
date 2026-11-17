//! Tests for reserving and registering a slot: atomicity, ownership and
//! takeover, the multi-domain safety check, the root slot, stats, the
//! domain cross-checks and the service badge cache.

use super::test_helpers::*;
use super::*;

use std::sync::Arc;

use did_hosting_common::DidRegisterRequest;

use crate::server::AppState;
use did_hosting_common::server::acl::Role;

/// Reserve, register and set-state return the record they committed, so a caller
/// can answer from it rather than read it back: on an eventually consistent
/// store that read can miss a write that succeeded.
#[tokio::test]
async fn writers_return_the_record_they_committed() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "alpha";
    let did_log = build_test_did_log("scid-alpha", "control.test", path).await;
    let stored = |state: &AppState| {
        let ks = state.dids_ks.clone();
        async move {
            let record: DidRecord = ks.get(did_key(path)).await.unwrap().expect("record");
            serde_json::to_value(record).unwrap()
        }
    };

    // Reserve, then register, as the VTA does.
    let reserved = create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .expect("reserve");
    assert_eq!(
        serde_json::to_value(&reserved).unwrap(),
        stored(&state).await
    );

    let registered = register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("register");
    assert_eq!(
        serde_json::to_value(&registered).unwrap(),
        stored(&state).await
    );

    let disabled = set_did_disabled(&owner_auth(owner), &state, path, true)
        .await
        .expect("disable");
    assert!(disabled.disabled);
    assert_eq!(
        serde_json::to_value(&disabled).unwrap(),
        stored(&state).await
    );
}

/// Fresh slot, well-formed did.jsonl, caller becomes owner.
#[tokio::test]
async fn fresh_slot_succeeds_and_writes_atomically() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "alpha";
    let did_log = build_test_did_log("scid-alpha", "control.test", path).await;

    let result = register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("fresh-slot register should succeed");
    assert_eq!(result.mnemonic, path);

    // Record + log + owner-index all present after the single batch commit.
    let record: DidRecord = state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record");
    assert_eq!(record.owner, owner);
    assert_eq!(record.version_count, 1);
    // SCID is derived from the signed log entry, so its exact
    // value depends on the freshly-generated signing key. Pin
    // the prefix and the host:path suffix instead.
    let did_id = record.did_id.as_deref().expect("did_id present");
    assert!(
        did_id.starts_with("did:webvh:") && did_id.ends_with(":control.test:alpha"),
        "did_id must be did:webvh:<scid>:control.test:alpha; got {did_id}"
    );

    let log = state
        .dids_ks
        .get_raw(content_log_key(path))
        .await
        .unwrap()
        .expect("log");
    assert_eq!(log, did_log.as_bytes());

    let owner_idx = state.dids_ks.get_raw(owner_key(owner, path)).await.unwrap();
    assert!(owner_idx.is_some(), "owner index must be written");
}

/// The unified daemon's mutations (register, publish, disable, delete —
/// rollback follows the identical one-line `invalidate_cached_content`
/// call) must evict the embedded server's resolved-content cache in the
/// same process, since there is no `webvh/sync/*` round-trip within a
/// single process to do it the way a standalone edge does. A standalone
/// control plane leaves `cache_invalidate: None` and none of these calls
/// panic or otherwise misbehave without a hook installed.
#[tokio::test]
async fn mutations_call_the_cache_invalidate_hook_when_one_is_installed() {
    let (mut state, _dir) = test_state().await;
    let calls: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = calls.clone();
    state.cache_invalidate = Some(Arc::new(move |change: CacheChange<'_>| {
        recorded.lock().unwrap().push(format!("{change:?}"));
    }));

    let owner = "did:example:owner";
    let path = "cache-hook";
    let did_log = build_test_did_log("scid-cache-hook", "control.test", path).await;
    let expected = format!("{:?}", CacheChange::Did(path));
    let count = |calls: &std::sync::Mutex<Vec<String>>| {
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == expected)
            .count()
    };

    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("register");
    assert_eq!(count(&calls), 1, "register must invalidate");

    publish_did(&owner_auth(owner), &state, path, &did_log, None)
        .await
        .expect("publish");
    assert_eq!(count(&calls), 2, "publish must invalidate too");

    set_did_disabled(&owner_auth(owner), &state, path, true)
        .await
        .expect("disable");
    assert_eq!(count(&calls), 3, "disable must invalidate too");

    delete_did(&owner_auth(owner), &state, path, None)
        .await
        .expect("delete");
    assert_eq!(count(&calls), 4, "delete must invalidate too");
    assert!(
        calls.lock().unwrap().iter().all(|c| *c == expected),
        "every call must name this mnemonic"
    );
}

/// Two creates of one free path must not both succeed: the check that
/// the path is free and the write are one step under the per-path lock.
/// Unlocked, every racer saw the path free, each overwrote the last, and
/// the losers' owner-index entries were left pointing at a slot they no
/// longer owned.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_creates_of_one_path_admit_exactly_one() {
    let (state, _dir) = test_state().await;
    let state = Arc::new(state);
    const RACERS: usize = 16;
    let mut handles = Vec::new();
    for i in 0..RACERS {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let owner = format!("did:example:racer-{i}");
            create_did(&owner_auth(&owner), &state, Some("contested"), false, None).await
        }));
    }
    let mut created = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => created += 1,
            Err(AppError::Conflict(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert_eq!(created, 1, "exactly one create may claim the path");
    let owner_entries = state
        .dids_ks
        .prefix_iter_raw(b"owner:".to_vec())
        .await
        .unwrap()
        .into_iter()
        .filter(|(k, _)| k.ends_with(b":contested"))
        .count();
    assert_eq!(owner_entries, 1, "no orphaned owner-index entries");
}

/// A force-replace commits the old slot's removal and the new record
/// in one write: after it, the slot has the new owner, no old content,
/// and only the new owner's index entry.
#[tokio::test]
async fn force_replace_is_a_single_write() {
    let (state, _dir) = test_state().await;
    let path = "replaced";
    let log = build_test_did_log("scid-replaced", "control.test", path).await;
    register_did_atomic(
        &owner_auth("did:example:old"),
        &state,
        path,
        &log,
        false,
        None,
    )
    .await
    .unwrap();

    create_did(
        &admin_auth("did:example:admin"),
        &state,
        Some(path),
        true,
        None,
    )
    .await
    .expect("admin force-replace");

    let record: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
    assert_eq!(record.owner, "did:example:admin");
    assert_eq!(record.version_count, 0);
    assert!(
        state
            .dids_ks
            .get_raw(content_log_key(path))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .dids_ks
            .get_raw(owner_key("did:example:old", path))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .dids_ks
            .get_raw(owner_key("did:example:admin", path))
            .await
            .unwrap()
            .is_some()
    );
}

/// `set_did_disabled` writes the whole record back, so it must read it
/// under the per-path lock. Here a publish-like writer holds the lock,
/// has read the record, and commits a new version after the disable
/// request arrives: the disable must apply on top of that version, not
/// revert it — and the publish must not revert the disable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_did_disabled_never_writes_back_a_stale_record() {
    let (state, _dir) = test_state().await;
    let state = Arc::new(state);
    let owner = "did:example:owner";
    let path = "stale-disable";
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();

    let guard = state.path_locks.guard(path).await;
    let mut read: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
    let disabler = {
        let state = state.clone();
        tokio::spawn(async move { set_did_disabled(&owner_auth(owner), &state, path, true).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    read.version_count = 7;
    state.dids_ks.insert(did_key(path), &read).await.unwrap();
    drop(guard);
    disabler.await.unwrap().unwrap();

    let record: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
    assert!(record.disabled, "the disable was lost");
    assert_eq!(
        record.version_count, 7,
        "the concurrent publish was reverted"
    );
}

/// A different non-admin caller hitting an existing slot is forbidden,
/// regardless of force.
#[tokio::test]
async fn other_owner_without_admin_forbidden() {
    let (state, _dir) = test_state().await;
    let path = "gamma";
    let owner_a = "did:example:owner-a";
    let owner_b = "did:example:owner-b";
    let log = build_test_did_log("scid-gamma", "control.test", path).await;

    register_did_atomic(&owner_auth(owner_a), &state, path, &log, false, None)
        .await
        .unwrap();

    // Without force.
    let err = register_did_atomic(&owner_auth(owner_b), &state, path, &log, false, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::Forbidden(_)));

    // With force — still 403, since caller is not admin.
    let err = register_did_atomic(&owner_auth(owner_b), &state, path, &log, true, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::Forbidden(_)));
}

/// Admin without force on a slot owned by someone else is forbidden —
/// `force` is the explicit "yes really take this from the previous
/// owner" gate.
#[tokio::test]
async fn admin_takeover_requires_force() {
    let (state, _dir) = test_state().await;
    let path = "delta";
    let log = build_test_did_log("scid-delta", "control.test", path).await;

    register_did_atomic(
        &owner_auth("did:example:owner-a"),
        &state,
        path,
        &log,
        false,
        None,
    )
    .await
    .unwrap();

    let err = register_did_atomic(
        &admin_auth("did:example:admin"),
        &state,
        path,
        &log,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Forbidden(ref m) if m.contains("force")));
}

/// Admin with force succeeds; caller becomes the new owner; old
/// owner-index entry is removed; old witness is cleared (was signed
/// for the prior DID identifier).
#[tokio::test]
async fn admin_takeover_with_force_succeeds() {
    let (state, _dir) = test_state().await;
    let path = "epsilon";
    let owner_a = "did:example:owner-a";
    let admin = "did:example:admin";
    let log = build_test_did_log("scid-epsilon", "control.test", path).await;

    register_did_atomic(&owner_auth(owner_a), &state, path, &log, false, None)
        .await
        .unwrap();
    // Seed a witness file as if the original owner had uploaded one.
    state
        .dids_ks
        .insert_raw(content_witness_key(path), b"prior-witness".to_vec())
        .await
        .unwrap();

    register_did_atomic(&admin_auth(admin), &state, path, &log, true, None)
        .await
        .expect("admin force takeover should succeed");

    let rec: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
    assert_eq!(rec.owner, admin);
    assert_eq!(rec.version_count, 1, "takeover resets version_count");

    // Old owner-index entry removed; new one present.
    assert!(
        state
            .dids_ks
            .get_raw(owner_key(owner_a, path))
            .await
            .unwrap()
            .is_none(),
        "old owner-index entry must be removed on takeover"
    );
    assert!(
        state
            .dids_ks
            .get_raw(owner_key(admin, path))
            .await
            .unwrap()
            .is_some(),
        "new owner-index entry must be present after takeover"
    );

    // Stale witness cleared.
    assert!(
        state
            .dids_ks
            .get_raw(content_witness_key(path))
            .await
            .unwrap()
            .is_none(),
        "prior witness must be cleared on takeover (signed for prior DID)"
    );
}

/// did_log's path component doesn't match the requested slot — rejected
/// before any storage write.
#[tokio::test]
async fn mismatched_did_path_rejected() {
    let (state, _dir) = test_state().await;
    // Log claims path "wrong-path" but request is for path "right-path".
    let log = build_test_did_log("scid-x", "control.test", "wrong-path").await;
    let err = register_did_atomic(
        &owner_auth("did:example:owner"),
        &state,
        "right-path",
        &log,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Validation { message: ref m, .. } if m.contains("path")));
    assert!(
        state
            .dids_ks
            .get_raw(did_key("right-path"))
            .await
            .unwrap()
            .is_none(),
        "no record must be written when validation fails"
    );
}

/// did_log claims a different host — claim-jumping prevention.
#[tokio::test]
async fn mismatched_did_host_rejected() {
    let (state, _dir) = test_state().await;
    let log = build_test_did_log("scid-x", "other-host.example", "valid-path").await;
    let err = register_did_atomic(
        &owner_auth("did:example:owner"),
        &state,
        "valid-path",
        &log,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Validation { message: ref m, .. } if m.contains("host")));
}

// ---- multi-domain safety check ----

/// Seed an active domain for tests that exercise the new
/// multi-domain safety check. Returns the canonical name.
async fn seed_active_domain(state: &AppState, name: &str) -> String {
    use did_hosting_common::server::domain::{
        create_domain,
        types::{DomainEntry, DomainStatus, DomainUrlScheme},
    };
    let entry = DomainEntry {
        name: name.into(),
        label: None,
        scheme: DomainUrlScheme::Https,
        status: DomainStatus::Active,
        created_at: 0,
        default_domain: true,
        branding: None,
        witnesses: None,
        watchers: None,
        quota: None,
        well_known_enabled: false,
        disabled_at: None,
        purge_at: None,
    };
    create_domain(&state.store, &entry).await.unwrap();
    name.into()
}

/// With a domain configured and the caller's ACL scoped to it,
/// a DID on that domain registers normally.
#[tokio::test]
async fn register_with_domain_seeded_owner_scoped_to_matching_host() {
    use did_hosting_common::server::domain::DomainScope;
    let (state, _dir) = test_state().await;
    let owner = "did:example:scoped";
    seed_active_domain(&state, "control.test").await;
    seed_caller_acl(
        &state,
        owner,
        Role::Owner,
        DomainScope::Allowed {
            domains: vec!["control.test".into()],
        },
    )
    .await;

    let did_log = build_test_did_log("scid-ok", "control.test", "alpha").await;
    let result = register_did_atomic(&owner_auth(owner), &state, "alpha", &did_log, false, None)
        .await
        .expect("scoped owner on matching host must succeed");
    assert_eq!(result.mnemonic, "alpha");
}

/// Same domain configured, but the caller's ACL allows only
/// `domain-a` while the DID is on `domain-b`. The legacy host
/// validator would already reject this (host != public_url),
/// but the safety check fires first and returns Forbidden (403)
/// rather than Validation (400) — distinct error codes are how
/// the UI tells "we don't serve that domain" from "you can't
/// post there".
#[tokio::test]
async fn register_acl_rejects_host_outside_allowed_scope() {
    use did_hosting_common::server::domain::DomainScope;
    let (state, _dir) = test_state().await;
    let owner = "did:example:scoped";
    // Two active domains: control.test AND domain-b.example.
    seed_active_domain(&state, "control.test").await;
    {
        use did_hosting_common::server::domain::{
            create_domain,
            types::{DomainEntry, DomainStatus, DomainUrlScheme},
        };
        create_domain(
            &state.store,
            &DomainEntry {
                name: "domain-b.example".into(),
                label: None,
                scheme: DomainUrlScheme::Https,
                status: DomainStatus::Active,
                created_at: 0,
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
    // Caller's ACL only allows control.test.
    seed_caller_acl(
        &state,
        owner,
        Role::Owner,
        DomainScope::Allowed {
            domains: vec!["control.test".into()],
        },
    )
    .await;

    let did_log = build_test_did_log("scid-evil", "domain-b.example", "alpha").await;
    let err = register_did_atomic(&owner_auth(owner), &state, "alpha", &did_log, false, None)
        .await
        .expect_err("ACL must reject host outside scope");
    assert!(
        matches!(err, AppError::Forbidden(_)),
        "expected Forbidden, got {err:?}"
    );
    // No record written.
    assert!(
        state
            .dids_ks
            .get_raw(did_key("alpha"))
            .await
            .unwrap()
            .is_none(),
        "no record may be written when ACL rejects the host"
    );
}

/// `Admin` role short-circuits the ACL scope check — admins can
/// write to any **active** domain regardless of their ACL
/// `domains` field.
#[tokio::test]
async fn register_admin_can_write_any_active_domain() {
    use did_hosting_common::server::domain::DomainScope;
    let (state, _dir) = test_state().await;
    let admin = "did:example:admin";
    seed_active_domain(&state, "control.test").await;
    seed_caller_acl(
        &state,
        admin,
        Role::Admin,
        DomainScope::Allowed {
            domains: vec!["irrelevant.example".into()],
        },
    )
    .await;

    let did_log = build_test_did_log("scid-admin", "control.test", "alpha").await;
    register_did_atomic(&admin_auth(admin), &state, "alpha", &did_log, false, None)
        .await
        .expect("admin role overrides ACL domain scope");
}

/// Malformed did.jsonl is rejected by `validate_did_jsonl`.
#[tokio::test]
async fn invalid_did_log_rejected() {
    let (state, _dir) = test_state().await;
    let err = register_did_atomic(
        &owner_auth("did:example:owner"),
        &state,
        "any-path",
        "not valid jsonl",
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Validation { .. }));
}

/// A root did:webvh — `did:webvh:{SCID}:<host>`, no path segments,
/// resolving at `https://<host>/.well-known/did.jsonl` — registers at
/// the reserved `.well-known` slot.
///
/// Regression: `register_did_atomic` used to validate `path` with
/// `validate_custom_path`, which rejects `.well-known` by design (the
/// leading dot is not in the `[a-z0-9-]` segment charset). An operator
/// self-hosting their domain therefore could not publish the domain's
/// own DID through register at all — every attempt came back
/// `e.p.did.path-invalid`, and no other `path` value works either
/// (empty is rejected by the dispatcher, and any legal mnemonic would
/// fail the DID↔path equality check below).
#[tokio::test]
async fn register_root_did_at_well_known_as_admin() {
    let (state, _dir) = test_state().await;
    // Empty mnemonic ⇒ root DID for the host.
    let did_log = build_test_did_log("scid-root", "control.test", "").await;

    register_did_atomic(
        &admin_auth("did:example:admin"),
        &state,
        ".well-known",
        &did_log,
        false,
        None,
    )
    .await
    .expect("admin may register the root DID at the .well-known slot");

    let record: DidRecord = state
        .dids_ks
        .get(did_key(".well-known"))
        .await
        .unwrap()
        .expect("root slot record written");
    assert_eq!(record.mnemonic, ".well-known");
    assert_eq!(
        record.did_id.as_deref(),
        extract_did_id(&did_log).as_deref(),
        "the root slot must hold the registered root DID"
    );
}

/// Root is admin-only, mirroring `create_did`'s carve-out — a domain's
/// root slot can belong to only one tenant, so an owner-role caller
/// must not be able to claim it.
#[tokio::test]
async fn register_root_did_forbidden_for_non_admin() {
    let (state, _dir) = test_state().await;
    let did_log = build_test_did_log("scid-root", "control.test", "").await;

    let err = register_did_atomic(
        &owner_auth("did:example:owner"),
        &state,
        ".well-known",
        &did_log,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Forbidden(_)),
        "non-admin root register must be Forbidden, got {err:?}"
    );
}

/// The root carve-out is exactly `.well-known` and nothing else — any
/// other dot-prefixed path still fails the segment charset rules, even
/// for an admin. Guards against widening `validate_mnemonic` into a
/// general escape hatch.
#[tokio::test]
async fn register_rejects_other_dotted_paths_even_for_admin() {
    let (state, _dir) = test_state().await;
    let did_log = build_test_did_log("scid-dot", "control.test", "hidden").await;

    let err = register_did_atomic(
        &admin_auth("did:example:admin"),
        &state,
        ".hidden",
        &did_log,
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Validation { .. }),
        "dotted non-root path must still be rejected, got {err:?}"
    );
}

/// Smoke test: the wire request type round-trips with default `force`
/// and the legacy `did_log` field still parses (backwards-compat).
#[test]
fn did_register_request_round_trip_defaults_force_false() {
    let raw = r#"{"path":"alpha","did_log":"line"}"#;
    let req: DidRegisterRequest = serde_json::from_str(raw).unwrap();
    assert_eq!(req.path, "alpha");
    assert_eq!(req.did_log.as_deref(), Some("line"));
    assert!(!req.force, "force must default to false");
    let (method, payload) = req.resolve().unwrap();
    assert_eq!(method, "webvh");
    assert_eq!(payload, b"line");
}

/// Pin the stats-counter behaviour: every successful
/// `register_did_atomic` advances the aggregate `total_updates` and the
/// per-DID `last_updated_at`. Without this the dashboards / `MSG_INFO`
/// response will report zero updates in self-hosted (control-plane-as-
/// authoritative) deployments. Mirrors did-hosting-server::publish_did's
/// `record_update` call.
#[tokio::test]
async fn register_did_atomic_records_update_stats() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "stats-fresh";
    let did_log = build_test_did_log("scid-stats", "control.test", path).await;

    let before = state.stats_collector.get_aggregate().total_updates;
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .unwrap();
    let after = state.stats_collector.get_aggregate().total_updates;
    assert_eq!(
        after,
        before + 1,
        "fresh atomic register must advance total_updates by 1"
    );

    // A second register by the same owner advances again — the counter
    // tracks log-write operations, not unique DIDs.
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .unwrap();
    let after_two = state.stats_collector.get_aggregate().total_updates;
    assert_eq!(
        after_two,
        after + 1,
        "idempotent re-register must also advance total_updates"
    );
}

/// The hosted-DID count follows creates and deletes without a store scan:
/// a new slot counts once, publishing or replacing an existing slot does
/// not count again, and a delete uncounts it.
#[tokio::test]
async fn did_count_follows_creates_and_deletes() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let total = || state.stats_collector.get_aggregate().total_dids;
    assert_eq!(total(), 0);

    create_did(&owner_auth(owner), &state, Some("reserved"), false, None)
        .await
        .unwrap();
    assert_eq!(total(), 1, "a reserved slot is a hosted DID");

    let log = build_test_did_log("scid-reserved", "control.test", "reserved").await;
    register_did_atomic(&owner_auth(owner), &state, "reserved", &log, false, None)
        .await
        .unwrap();
    assert_eq!(total(), 1, "publishing into a reserved slot adds no DID");

    let log = build_test_did_log("scid-fresh", "control.test", "fresh").await;
    register_did_atomic(&owner_auth(owner), &state, "fresh", &log, false, None)
        .await
        .unwrap();
    assert_eq!(total(), 2, "registering a fresh path adds a DID");

    create_did(
        &admin_auth("did:example:admin"),
        &state,
        Some("fresh"),
        true,
        None,
    )
    .await
    .unwrap();
    assert_eq!(total(), 2, "a force-replace reuses the slot");

    delete_did(&owner_auth(owner), &state, "reserved", None)
        .await
        .unwrap();
    assert_eq!(total(), 1, "a delete removes the DID");
}

/// Mirror coverage for the `publish_did` path. Pre-create a slot via
/// `create_did` (which does NOT bump update stats — it only reserves
/// the mnemonic), then publish a log against it and assert the counter
/// only moves on the publish.
#[tokio::test]
async fn publish_did_records_update_stats() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "stats-publish";
    let did_log = build_test_did_log("scid-publish", "control.test", path).await;

    // Reserve the slot. create_did is the "request URI" step — it
    // doesn't write log content and shouldn't bump update counters.
    let baseline = state.stats_collector.get_aggregate().total_updates;
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();
    assert_eq!(
        state.stats_collector.get_aggregate().total_updates,
        baseline,
        "create_did is a slot reservation; must NOT count as an update"
    );

    // Publish flips the counter.
    publish_did(&owner_auth(owner), &state, path, &did_log, None)
        .await
        .unwrap();
    assert_eq!(
        state.stats_collector.get_aggregate().total_updates,
        baseline + 1,
        "publish_did must record an update on success"
    );

    // Republishing advances again.
    publish_did(&owner_auth(owner), &state, path, &did_log, None)
        .await
        .unwrap();
    assert_eq!(
        state.stats_collector.get_aggregate().total_updates,
        baseline + 2,
        "subsequent publishes must keep advancing total_updates"
    );
}

/// F5: the caller's explicit `?domain=` is cross-checked against the DID's
/// host (a DID's host IS its domain). A mismatch is rejected as
/// `did-management:unknown_domain`; a match or an omitted domain publishes.
#[tokio::test]
async fn publish_cross_checks_explicit_domain_against_did_host() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "domain-xcheck";
    // The DID's host — i.e. its domain — is `control.test`.
    let did_log = build_test_did_log("scid-domain", "control.test", path).await;
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();

    // No domain stated → unchanged behaviour: publishes.
    publish_did(&owner_auth(owner), &state, path, &did_log, None)
        .await
        .expect("omitted domain still publishes");

    // Matching domain → publishes.
    publish_did(
        &owner_auth(owner),
        &state,
        path,
        &did_log,
        Some("control.test"),
    )
    .await
    .expect("matching domain publishes");

    // Mismatched domain → rejected before the log lands.
    let err = publish_did(
        &owner_auth(owner),
        &state,
        path,
        &did_log,
        Some("evil.example"),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Validation { message: ref m, .. } if m.contains("unknown_domain")),
        "mismatched domain must be rejected as unknown_domain, got {err:?}"
    );
}

/// `did/register` enforces the caller's explicit domain exactly as publish
/// does (R3.6): a did:webvh log whose host is not the stated domain is
/// refused as `did-management:unknown_domain` before anything is written;
/// a matching (case-insensitive) or omitted domain registers.
#[tokio::test]
async fn register_cross_checks_explicit_domain_against_did_host() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "register-domain-xcheck";
    let did_log = build_test_did_log("scid-reg-domain", "control.test", path).await;

    // Mismatched domain → rejected, and the slot stays empty.
    let err = register_did_atomic(
        &owner_auth(owner),
        &state,
        path,
        &did_log,
        false,
        Some("evil.example"),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Validation { message: ref m, .. } if m.contains("unknown_domain")),
        "mismatched domain must be rejected as unknown_domain, got {err:?}"
    );
    let record: Option<DidRecord> = state.dids_ks.get(did_key(path)).await.unwrap();
    assert!(record.is_none(), "a refused register must write nothing");
    assert!(
        state
            .dids_ks
            .get_raw(content_log_key(path))
            .await
            .unwrap()
            .is_none(),
        "a refused register must not store the log"
    );

    // Matching domain (any case) → registers.
    register_did_atomic(
        &owner_auth(owner),
        &state,
        path,
        &did_log,
        false,
        Some("Control.Test"),
    )
    .await
    .expect("matching domain registers");

    // Omitted domain → unchanged behaviour: registers.
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("omitted domain still registers");

    // And a mismatch on a re-register of the now-owned slot is refused too.
    let err = register_did_atomic(
        &owner_auth(owner),
        &state,
        path,
        &did_log,
        false,
        Some("evil.example"),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Validation { message: ref m, .. } if m.contains("unknown_domain")),
        "mismatched domain on re-register must be rejected, got {err:?}"
    );
}

/// A webvh record registered through `did/register` carries its domain
/// (the DID's host), and a re-register keeps it rather than wiping it to
/// `""` — the per-domain listing keys on it.
#[tokio::test]
async fn register_records_and_keeps_the_webvh_domain() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "register-keeps-domain";
    let did_log = build_test_did_log("scid-keep-domain", "control.test", path).await;

    let first = register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .unwrap();
    assert_eq!(
        first.domain, "control.test",
        "fresh register records the domain"
    );

    let again = register_did_atomic(
        &owner_auth(owner),
        &state,
        path,
        &did_log,
        false,
        Some("control.test"),
    )
    .await
    .unwrap();
    assert_eq!(again.domain, "control.test", "re-register keeps the domain");

    let stored: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
    assert_eq!(
        stored.domain, "control.test",
        "the stored record keeps it too"
    );
    assert_eq!(stored.version_count, 2);

    // A slot reserved with a domain, then registered into, keeps it.
    let reserved = "register-reserved-domain";
    create_did(&owner_auth(owner), &state, Some(reserved), false, None)
        .await
        .unwrap();
    let log = build_test_did_log("scid-reserved-domain", "control.test", reserved).await;
    let rec = register_did_atomic(&owner_auth(owner), &state, reserved, &log, false, None)
        .await
        .unwrap();
    assert_eq!(rec.domain, "control.test");
}

/// Failed publishes (auth denied, validation error, missing slot) must
/// NOT bump the counter — `record_update` runs only after the storage
/// commit returns Ok. Pinning this prevents drift if someone moves the
/// call earlier in the function.
#[tokio::test]
async fn failed_publish_does_not_record_update() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:owner-a";
    let owner_b = "did:example:owner-b";
    let path = "stats-fail";
    let did_log = build_test_did_log("scid-fail", "control.test", path).await;

    // Reserve as owner-a, then have owner-b try to publish.
    create_did(&owner_auth(owner_a), &state, Some(path), false, None)
        .await
        .unwrap();

    let baseline = state.stats_collector.get_aggregate().total_updates;
    let err = publish_did(&owner_auth(owner_b), &state, path, &did_log, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::Forbidden(_)));
    assert_eq!(
        state.stats_collector.get_aggregate().total_updates,
        baseline,
        "auth-denied publish must NOT record an update"
    );

    // Validation failure on the JSONL body — still no counter movement.
    let err = publish_did(&owner_auth(owner_a), &state, path, "not-jsonl", None)
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::Validation { .. }));
    assert_eq!(
        state.stats_collector.get_aggregate().total_updates,
        baseline,
        "validation-failed publish must NOT record an update"
    );
}

/// Concurrency: two parallel `register_did_atomic` calls on the same
/// fresh path serialise via the per-path write lock — exactly one
/// wins, the other races the lock. Without the lock both could
/// observe `existing == None`, both build version_count=1 records,
/// and both commit; the second silently overwrites the first.
///
/// We can't deterministically pick which caller wins (the loser
/// could be either), but we CAN assert (a) both calls succeed
/// without panicking, (b) the on-disk record reflects exactly one
/// of the two callers (not a mash-up), (c) the version_count is 2
/// (the second call's idempotent re-register bumps it from the
/// first call's 1).
#[tokio::test]
async fn concurrent_register_serialises() {
    let (state, _dir) = test_state().await;
    let owner_a = "did:example:owner-a".to_string();
    let path = "race-path";
    let log_a = build_test_did_log("scid-race", "control.test", path).await;
    let log_b = log_a.clone();

    let auth_a = owner_auth(&owner_a);
    let auth_b = owner_auth(&owner_a); // same owner, different concurrent attempts

    let state_a = state.clone();
    let state_b = state.clone();
    let path_a = path.to_string();
    let path_b = path.to_string();

    let task_a = tokio::spawn(async move {
        register_did_atomic(&auth_a, &state_a, &path_a, &log_a, false, None).await
    });
    let task_b = tokio::spawn(async move {
        register_did_atomic(&auth_b, &state_b, &path_b, &log_b, false, None).await
    });

    let r_a = task_a.await.unwrap();
    let r_b = task_b.await.unwrap();
    // Both calls succeed because they're from the same owner — the
    // second is treated as an idempotent re-publish and bumps
    // version_count.
    assert!(
        r_a.is_ok() && r_b.is_ok(),
        "both same-owner registers should succeed; got a={r_a:?}, b={r_b:?}"
    );

    let record: DidRecord = state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record present after race");
    assert_eq!(record.owner, owner_a);
    // Two sequential commits via the lock => version_count == 2.
    // Without the lock, the race could land on 1 (both observe
    // None and both write version_count=1).
    assert_eq!(
        record.version_count, 2,
        "both register calls must have committed in sequence; got version_count={}",
        record.version_count
    );
}

/// `create_did(..., Some("tenant.example"))` MUST persist the
/// caller-supplied domain on the DidRecord. This is the bug
/// b0e2fb11 fixed: previously `RequestUriRequest` had no
/// `domain` field, every record landed with `domain: ""`, and the
/// per-domain UI filters / dashboard stats hid the freshly-
/// created DID until the M-01 backfill sweep next ran. Pinning
/// the persisted value guards against the next regression in
/// `create_did` or its `did/check-name` row forgetting to thread the
/// resolver output through.
#[tokio::test]
async fn create_did_persists_caller_supplied_domain() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "alpha-domain";

    create_did(
        &owner_auth(owner),
        &state,
        Some(path),
        false,
        Some("tenant.example"),
    )
    .await
    .expect("create_did with domain should succeed");

    let record: DidRecord = state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record");
    assert_eq!(
        record.domain, "tenant.example",
        "domain on the DidRecord MUST equal the caller-supplied value"
    );
}

/// `create_did(..., None)` MUST leave `domain` empty — the field
/// is the resolver's responsibility, not a synthetic default.
/// Older DIDComm paths and tests pass None; the M-01 sweep + the
/// publish-time backfill (see next test) populate it later.
#[tokio::test]
async fn create_did_with_no_domain_leaves_field_empty() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "alpha-no-domain";

    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .expect("create_did without domain should succeed");

    let record: DidRecord = state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record");
    assert_eq!(
        record.domain, "",
        "domain on the DidRecord MUST be empty when create_did was called with None"
    );
}

/// `publish_did` MUST backfill `record.domain` from the
/// `did_id`'s host segment when the persisted field is empty —
/// e.g. for slots created via the older DIDComm `MSG_DID_REQUEST`
/// path that didn't thread a domain through. Idempotent: a
/// record whose `domain` is already populated is unchanged.
#[tokio::test]
async fn publish_did_backfills_empty_domain_from_did_id() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "alpha-backfill";
    let did_log = build_test_did_log("scid-backfill", "control.test", path).await;

    // Reserve the slot with `domain: None` so the persisted value
    // is empty (mirrors the older DIDComm path's behaviour
    // pre-b0e2fb11).
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();
    let before: DidRecord = state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record");
    assert_eq!(before.domain, "", "test precondition: domain starts empty");

    // Publish. The did:webvh log encodes `control.test` as the
    // host, so the backfill should pull it through.
    publish_did(&owner_auth(owner), &state, path, &did_log, None)
        .await
        .unwrap();
    let after: DidRecord = state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record");
    assert_eq!(
        after.domain, "control.test",
        "publish_did must populate domain from the did_id host segment when the persisted value is empty"
    );

    // Subsequent publishes leave the populated value alone —
    // backfill only runs when `record.domain.is_empty()`. Confirm
    // by re-publishing the same log and checking the field
    // didn't change to something else (or get cleared).
    publish_did(&owner_auth(owner), &state, path, &did_log, None)
        .await
        .unwrap();
    let after_again: DidRecord = state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record");
    assert_eq!(
        after_again.domain, "control.test",
        "publish_did backfill must be idempotent — a populated domain stays put"
    );
}

// ---- service badge cache (DidRecord.services) ----

/// An empty slot has no document, so `services` must be `None`
/// ("unknown"), never `Some(vec![])` ("read it, advertises nothing").
#[tokio::test]
async fn create_did_leaves_services_unknown() {
    let (state, _dir) = test_state().await;
    create_did(
        &owner_auth("did:example:owner"),
        &state,
        Some("slot"),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(stored_services(&state, "slot").await, None);
}

/// `register_did_atomic` caches the document's services, in document order
/// (TSP before DIDComm, matching the VTA templates).
#[tokio::test]
async fn register_caches_advertised_services() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "with-transports";
    let did_log = build_test_did_log_with_transports("control.test", path, true, true).await;

    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();
    assert_eq!(
        stored_services(&state, path).await,
        None,
        "precondition: no document yet"
    );

    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .unwrap();

    assert_eq!(
        stored_services(&state, path).await,
        Some(vec![
            "TSPTransport".to_string(),
            "DIDCommMessaging".to_string()
        ])
    );
}

/// A document with no services caches as `Some(vec![])` — we read it and
/// it advertises nothing — which is distinct from the `None` above.
#[tokio::test]
async fn register_caches_empty_services_for_bare_document() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "bare";
    let did_log = build_test_did_log("scid", "control.test", path).await;

    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .unwrap();

    assert_eq!(stored_services(&state, path).await, Some(vec![]));
}

/// The cache is *recomputed* on every publish, not filled-if-empty. A
/// server that stops advertising TSP must lose the badge — a
/// fill-if-empty implementation would keep showing the stale one.
#[tokio::test]
async fn register_retracts_a_dropped_service() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "drops-tsp";

    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();

    let both = build_test_did_log_with_transports("control.test", path, true, true).await;
    register_did_atomic(&owner_auth(owner), &state, path, &both, false, None)
        .await
        .unwrap();
    assert!(
        stored_services(&state, path)
            .await
            .unwrap()
            .contains(&"TSPTransport".to_string()),
        "precondition: TSP advertised"
    );

    // Re-publish a document that advertises DIDComm only.
    let didcomm_only = build_test_did_log_with_transports("control.test", path, false, true).await;
    register_did_atomic(&owner_auth(owner), &state, path, &didcomm_only, false, None)
        .await
        .unwrap();

    assert_eq!(
        stored_services(&state, path).await,
        Some(vec!["DIDCommMessaging".to_string()]),
        "TSPTransport must be retracted once the document stops advertising it"
    );
}

/// A legacy record (pre-`services`) self-heals on its next publish. The
/// M-02 boot sweep normally gets there first; this is the belt-and-braces
/// path for a record the sweep deferred (unparseable log) or one written
/// before the sweep ran.
#[tokio::test]
async fn register_backfills_services_on_legacy_record() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "legacy";
    let did_log = build_test_did_log_with_transports("control.test", path, true, false).await;

    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();
    // Force the on-disk record into the legacy shape.
    let mut rec: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
    rec.services = None;
    state.dids_ks.insert(did_key(path), &rec).await.unwrap();

    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .unwrap();

    assert_eq!(
        stored_services(&state, path).await,
        Some(vec!["TSPTransport".to_string()])
    );
}

/// The cached services reach the records a `did/list` page renders from,
/// without the listing reading any log bytes.
#[tokio::test]
async fn list_dids_surfaces_cached_services() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "listed";
    let did_log = build_test_did_log_with_transports("control.test", path, true, true).await;

    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .unwrap();

    let page = list_dids_page(
        &owner_auth(owner),
        false,
        &state,
        &ListFilter::default(),
        None,
        None,
    )
    .await
    .expect("list_dids_page");
    let (entry, _) = page
        .records
        .iter()
        .find(|(r, _)| r.mnemonic == path)
        .expect("published DID in list");
    assert_eq!(
        entry.services,
        Some(vec![
            "TSPTransport".to_string(),
            "DIDCommMessaging".to_string()
        ])
    );
}

/// Seed `did` as an owner with the given per-account caps.
async fn seed_capped_owner(
    state: &AppState,
    did: &str,
    max_did_count: Option<u64>,
    max_total_size: Option<u64>,
) {
    use did_hosting_common::server::acl::{AclEntry, store_acl_entry};
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.into(),
            role: Role::Owner,
            label: None,
            created_at: 0,
            max_total_size,
            max_did_count,
            domains: did_hosting_common::server::domain::DomainScope::All,
        },
    )
    .await
    .unwrap();
}

/// The DID-count quota counts only a fresh slot: at its cap, an owner may
/// re-register a slot it holds but not claim another, and the refused
/// register writes nothing — no record, no log, no agent-name index.
#[tokio::test]
async fn register_at_the_did_count_cap_refuses_only_a_fresh_slot() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:capped";
    seed_capped_owner(&state, owner, Some(1), None).await;

    let held = build_test_did_log("scid", "control.test", "held").await;
    register_did_atomic(&owner_auth(owner), &state, "held", &held, false, None)
        .await
        .expect("first slot is under the cap");
    register_did_atomic(&owner_auth(owner), &state, "held", &held, false, None)
        .await
        .expect("re-registering a held slot is not a new DID");

    let fresh = build_test_did_log_with_names("control.test", "fresh", &["capped"]).await;
    let err = register_did_atomic(&owner_auth(owner), &state, "fresh", &fresh, false, None)
        .await
        .expect_err("a second slot is over the cap");
    assert!(
        matches!(
            err,
            AppError::QuotaExceeded {
                kind: did_hosting_common::server::error::QuotaKind::Count,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("fresh"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .dids_ks
            .get_raw(content_log_key("fresh"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(index_target(&state, "control.test", "capped").await, None);
}

/// The size quota counts what the slot will hold, net of what it already
/// does: a re-register is charged the difference, and a log past the cap
/// is refused with nothing written.
#[tokio::test]
async fn register_charges_the_size_quota_net_of_the_slot() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:sized";
    let log = build_test_did_log("scid", "control.test", "sized").await;
    let size = log.len() as u64;
    // Room for this log once, not twice.
    seed_capped_owner(&state, owner, None, Some(size + size / 2)).await;

    register_did_atomic(&owner_auth(owner), &state, "sized", &log, false, None)
        .await
        .expect("under the cap");
    register_did_atomic(&owner_auth(owner), &state, "sized", &log, false, None)
        .await
        .expect("a same-size re-register adds nothing");

    let other = build_test_did_log("scid", "control.test", "other").await;
    let err = register_did_atomic(&owner_auth(owner), &state, "other", &other, false, None)
        .await
        .expect_err("a second log is over the cap");
    assert!(
        matches!(
            err,
            AppError::QuotaExceeded {
                kind: did_hosting_common::server::error::QuotaKind::Size,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key("other"))
            .await
            .unwrap()
            .is_none()
    );
}

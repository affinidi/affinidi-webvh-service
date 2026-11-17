//! Tests for suspending, resuming and deleting a slot, and the path lock
//! the lifecycle writes share.

use super::test_helpers::*;
use super::*;

use std::sync::Arc;

use did_hosting_common::server::acl::Role;

/// A slot an admin suspended stays suspended until an admin resumes it:
/// the owner's `active`, a re-register and a forced re-create all leave
/// it suspended.
#[tokio::test]
async fn an_admin_suspension_is_lifted_only_by_an_admin() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let admin = "did:example:admin";
    let path = "held";
    let did_log = build_test_did_log("scid-held", "control.test", path).await;
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .expect("reserve");
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("register");

    let record = set_did_disabled(&admin_auth(admin), &state, path, true)
        .await
        .expect("admin suspends");
    assert!(record.disabled && record.disabled_by_admin);

    let refused = set_did_disabled(&owner_auth(owner), &state, path, false).await;
    assert!(
        matches!(refused, Err(AppError::Forbidden(_))),
        "the owner resumed an admin's suspension: {refused:?}"
    );
    // The owner's own `suspended` changes nothing.
    let record = set_did_disabled(&owner_auth(owner), &state, path, true)
        .await
        .expect("owner suspends again");
    assert!(record.disabled_by_admin);

    let record = register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("re-register");
    assert!(
        record.disabled && record.disabled_by_admin,
        "a re-register resumed the slot"
    );

    let record = create_did(&owner_auth(owner), &state, Some(path), true, None)
        .await
        .expect("forced re-create");
    assert!(
        record.disabled && record.disabled_by_admin,
        "a forced re-create resumed the slot"
    );

    let stored: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
    assert!(stored.disabled && stored.disabled_by_admin);

    let record = set_did_disabled(&admin_auth(admin), &state, path, false)
        .await
        .expect("admin resumes");
    assert!(!record.disabled && !record.disabled_by_admin);
}

/// Deleting a slot and registering it again would start it afresh, so the
/// owner may not delete a slot an admin suspended; an admin may.
#[tokio::test]
async fn an_owner_cannot_delete_its_way_out_of_an_admin_suspension() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let admin = "did:example:admin";
    let path = "held-delete";
    let did_log = build_test_did_log("scid-held-delete", "control.test", path).await;
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .expect("reserve");
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("register");
    set_did_disabled(&admin_auth(admin), &state, path, true)
        .await
        .expect("admin suspends");

    let refused = delete_did(&owner_auth(owner), &state, path, None).await;
    assert!(
        matches!(refused, Err(AppError::Forbidden(_))),
        "the owner deleted an admin-suspended slot: {refused:?}"
    );
    // Still there, and a re-register keeps it suspended.
    let record = register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("re-register");
    assert!(record.disabled && record.disabled_by_admin);

    delete_did(&admin_auth(admin), &state, path, None)
        .await
        .expect("an admin may delete it");
    assert!(
        state
            .dids_ks
            .get::<DidRecord>(did_key(path))
            .await
            .unwrap()
            .is_none()
    );
}

/// A transfer moves the slot with its suspension.
#[tokio::test]
async fn a_transfer_keeps_an_admin_suspension() {
    use did_hosting_common::server::domain::DomainScope;
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let recipient = "did:example:recipient";
    let admin = "did:example:admin";
    let path = "held-transfer";
    seed_caller_acl(&state, recipient, Role::Owner, DomainScope::All).await;
    let did_log = build_test_did_log("scid-held-transfer", "control.test", path).await;
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .expect("reserve");
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("register");
    set_did_disabled(&admin_auth(admin), &state, path, true)
        .await
        .expect("admin suspends");

    // The owner offers the slot; the recipient accepts it.
    change_did_owner(&owner_auth(owner), &state, path, recipient, None)
        .await
        .map_err(|_| "offer")
        .unwrap();
    let moved = change_did_owner(&owner_auth(recipient), &state, path, recipient, None)
        .await
        .map_err(|_| "accept")
        .unwrap();
    assert_eq!(moved.record.owner, recipient);
    assert!(moved.record.disabled && moved.record.disabled_by_admin);

    let refused = set_did_disabled(&owner_auth(recipient), &state, path, false).await;
    assert!(
        matches!(refused, Err(AppError::Forbidden(_))),
        "{refused:?}"
    );
}

/// An owner's own suspension stays the owner's to lift, and a re-register
/// carries it forward rather than resuming the slot.
#[tokio::test]
async fn an_owner_suspension_is_the_owners_to_lift() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "paused";
    let did_log = build_test_did_log("scid-paused", "control.test", path).await;
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .expect("reserve");
    register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("register");

    let record = set_did_disabled(&owner_auth(owner), &state, path, true)
        .await
        .expect("owner suspends");
    assert!(record.disabled && !record.disabled_by_admin);

    let record = register_did_atomic(&owner_auth(owner), &state, path, &did_log, false, None)
        .await
        .expect("re-register");
    assert!(record.disabled, "a re-register resumed the slot");

    let record = set_did_disabled(&owner_auth(owner), &state, path, false)
        .await
        .expect("owner resumes");
    assert!(!record.disabled);
}

/// A record written before the admin marker existed reads as not
/// suspended by an admin, and the marker is left out when unset.
#[test]
fn the_admin_marker_defaults_to_unset() {
    let legacy = serde_json::json!({
        "owner": "did:example:owner",
        "mnemonic": "legacy",
        "created_at": 1,
        "updated_at": 1,
        "version_count": 1,
        "disabled": true,
    });
    let record: DidRecord = serde_json::from_value(legacy).unwrap();
    assert!(record.disabled && !record.disabled_by_admin);
    let back = serde_json::to_value(&record).unwrap();
    assert!(back.get("disabled_by_admin").is_none());
}

/// `delete_did` and `rollback_did_to` wait for the per-path lock before
/// reading the record they act on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_and_rollback_wait_for_the_path_lock() {
    let (state, _dir) = test_state().await;
    let state = Arc::new(state);
    let owner = "did:example:owner";
    let path = "locked";
    create_did(&owner_auth(owner), &state, Some(path), false, None)
        .await
        .unwrap();

    let guard = state.path_locks.guard(path).await;
    let rollback = {
        let state = state.clone();
        tokio::spawn(async move {
            rollback_did_to(&owner_auth(owner), &state, path, None)
                .await
                .map(|_| ())
        })
    };
    let delete = {
        let state = state.clone();
        tokio::spawn(async move { delete_did(&owner_auth(owner), &state, path, None).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !rollback.is_finished(),
        "rollback ran without the path lock"
    );
    assert!(!delete.is_finished(), "delete ran without the path lock");
    drop(guard);
    let _ = rollback.await.unwrap();
    let _ = delete.await.unwrap();
}

/// Same owner re-registering: idempotent path. Slot stays owned by the
/// same DID; version_count bumps; created_at preserved; new content
/// replaces old without ever leaving the slot empty.
#[tokio::test]
async fn owner_re_register_is_idempotent() {
    let (state, _dir) = test_state().await;
    let owner = "did:example:owner";
    let path = "beta";

    let log_v1 = build_test_did_log("scid-beta", "control.test", path).await;
    let r1 = register_did_atomic(&owner_auth(owner), &state, path, &log_v1, false, None)
        .await
        .unwrap();
    let rec_v1: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();

    // Same owner re-registers (potentially with new log content). No
    // intermediate empty state — old content is replaced in-batch.
    let log_v2 = build_test_did_log("scid-beta", "control.test", path).await;
    let r2 = register_did_atomic(&owner_auth(owner), &state, path, &log_v2, false, None)
        .await
        .expect("idempotent re-register should succeed without force");
    assert_eq!(r1.mnemonic, r2.mnemonic);

    let rec_v2: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();
    assert_eq!(rec_v2.owner, owner);
    assert_eq!(rec_v2.version_count, rec_v1.version_count + 1);
    assert_eq!(
        rec_v2.created_at, rec_v1.created_at,
        "owner re-register must preserve created_at"
    );
}

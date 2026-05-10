//! End-to-end ownership-lifecycle coverage with realistic `did:peer`
//! identities minted by `affinidi-messaging-test-mediator`.
//!
//! The unit tests in `messaging::tests` already cover the dispatcher-level
//! decision tree for `MSG_DID_CHANGE_OWNER` and `MSG_DID_REQUEST { force }`
//! using synthetic `did:example:*` strings. This file complements that with:
//!
//! 1. real `did:peer:2.*` identifiers (catches any hidden assumption that
//!    owners are formatted a specific way),
//! 2. multi-step flows that prove the owner-index reverse map stays in
//!    sync — list-by-old-owner returns empty after transfer, list-by-new-
//!    owner returns the DID, info-as-old-owner is forbidden, etc.
//! 3. force-replace clears prior log/witness content so the new slot starts
//!    clean.
//!
//! These exercises the public `did_ops` / DIDComm wire-level types but
//! bypass the mediator transport — the SDK round-trip is covered by
//! `didcomm_e2e_smoke.rs`. The dispatcher contract is covered by the
//! in-crate unit tests; this file proves the lifecycle holds together
//! with realistic identities.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use affinidi_messaging_test_mediator::TestMediator;
use affinidi_webvh_common::did_ops::{
    DidRecord, content_log_key, content_witness_key, did_key, owner_key,
};
use affinidi_webvh_common::server::acl::{AclEntry, Role, store_acl_entry};
use affinidi_webvh_common::server::auth::session::now_epoch;
use affinidi_webvh_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};
use affinidi_webvh_common::server::stats_collector::StatsCollector;
use affinidi_webvh_common::server::store::Store;
use affinidi_webvh_control::auth::AuthClaims;
use affinidi_webvh_control::config::{AppConfig, RegistryConfig};
use affinidi_webvh_control::did_ops::{
    change_did_owner, create_did, delete_did, get_did_info, list_dids,
};
use affinidi_webvh_control::server::AppState;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Build a minimal `AppState` rooted in a tempdir-backed fjall store.
async fn make_state() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_config = StoreConfig {
        data_dir: PathBuf::from(dir.path()),
        ..StoreConfig::default()
    };
    let store = Store::open(&store_config).await.expect("open store");
    let sessions_ks = store.keyspace("sessions").expect("sessions ks");
    let acl_ks = store.keyspace("acl").expect("acl ks");
    let registry_ks = store.keyspace("registry").expect("registry ks");
    let dids_ks = store.keyspace("dids").expect("dids ks");
    let stats_ks = store.keyspace("stats").expect("stats ks");

    let config = AppConfig {
        features: FeaturesConfig::default(),
        server_did: Some("did:webvh:test:control.example.com".into()),
        mediator_did: None,
        public_url: Some("http://control.test".into()),
        did_hosting_url: Some("http://control.test".into()),
        server: ServerConfig::default(),
        log: LogConfig::default(),
        store: store_config,
        auth: AuthConfig::default(),
        secrets: SecretsConfig::default(),
        vta: VtaConfig::default(),
        registry: RegistryConfig::default(),
        config_path: PathBuf::new(),
    };

    let state = AppState {
        store: store.clone(),
        sessions_ks,
        acl_ks,
        registry_ks,
        dids_ks,
        config: Arc::new(config),
        did_resolver: None,
        secrets_resolver: None,
        jwt_keys: None,
        webauthn: None,
        http_client: reqwest::Client::new(),
        didcomm_service: Arc::new(OnceLock::new()),
        stats_collector: Arc::new(StatsCollector::new()),
        stats_ks,
        signing_key_bytes: None,
        replay_cache: Arc::new(affinidi_webvh_control::replay::ReplayCache::new()),
    };

    (state, dir)
}

/// Add an ACL entry with the given role.
async fn acl(state: &AppState, did: &str, role: Role) {
    store_acl_entry(
        &state.acl_ks,
        &AclEntry {
            did: did.into(),
            role,
            label: None,
            created_at: now_epoch(),
            max_total_size: None,
            max_did_count: None,
        },
    )
    .await
    .expect("store ACL entry");
}

fn auth_for(did: &str, role: Role) -> AuthClaims {
    AuthClaims {
        did: did.into(),
        role,
    }
}

// ---------------------------------------------------------------------------
// End-to-end ownership lifecycle
// ---------------------------------------------------------------------------

/// Owner creates a DID, transfers it to NewOwner, and the side-effects on
/// the listing index match: NewOwner sees it, original owner doesn't.
/// Pins the owner-index integrity contract — a regression that left a
/// stale `owner:{old}:{mnemonic}` row after transfer would surface here.
#[tokio::test]
async fn owner_can_transfer_did_and_listing_index_swaps() {
    let (mediator, users) = TestMediator::with_users(["Owner", "NewOwner"])
        .await
        .expect("spawn mediator + users");
    let owner = users[0].did.clone();
    let new_owner = users[1].did.clone();

    let (state, _dir) = make_state().await;
    acl(&state, &owner, Role::Owner).await;
    acl(&state, &new_owner, Role::Owner).await;

    let owner_auth = auth_for(&owner, Role::Owner);

    // 1. Owner creates a DID slot.
    let create = create_did(&owner_auth, &state, Some("tenant/owner-a"), false)
        .await
        .expect("create_did");
    assert_eq!(create.mnemonic, "tenant/owner-a");

    // Pre-transfer sanity — owner sees one entry, new owner sees none.
    let owner_list = list_dids(&owner_auth, &state, None, None, None)
        .await
        .expect("owner list");
    assert_eq!(owner_list.len(), 1);

    let new_owner_auth = auth_for(&new_owner, Role::Owner);
    let new_owner_list = list_dids(&new_owner_auth, &state, None, None, None)
        .await
        .expect("new owner list");
    assert!(new_owner_list.is_empty());

    // 2. Owner transfers the DID.
    let updated = change_did_owner(&owner_auth, &state, &create.mnemonic, &new_owner)
        .await
        .expect("change_did_owner");
    assert_eq!(updated.owner, new_owner);
    assert_ne!(updated.updated_at, 0);

    // 3. Owner index swapped:
    //    - `owner:{old}:` prefix must be empty
    //    - `owner:{new}:` prefix must contain exactly one row
    let old_idx = state
        .dids_ks
        .prefix_iter_raw(format!("owner:{owner}:"))
        .await
        .unwrap();
    assert!(
        old_idx.is_empty(),
        "stale owner-index entry left behind for old owner"
    );
    let new_idx = state
        .dids_ks
        .prefix_iter_raw(format!("owner:{new_owner}:"))
        .await
        .unwrap();
    assert_eq!(new_idx.len(), 1);

    // 4. List operations follow the index swap.
    let owner_list = list_dids(&owner_auth, &state, None, None, None)
        .await
        .expect("owner list after transfer");
    assert!(
        owner_list.is_empty(),
        "old owner should no longer see the DID"
    );

    let new_owner_list = list_dids(&new_owner_auth, &state, None, None, None)
        .await
        .expect("new owner list after transfer");
    assert_eq!(new_owner_list.len(), 1);
    assert_eq!(new_owner_list[0].mnemonic, "tenant/owner-a");
    assert_eq!(new_owner_list[0].owner, new_owner);

    // 5. Old owner is now Forbidden on owner-only operations.
    let info_err = get_did_info(&owner_auth, &state, &create.mnemonic)
        .await
        .expect_err("old owner must lose access");
    assert!(
        matches!(
            info_err,
            affinidi_webvh_control::error::AppError::Forbidden(_)
        ),
        "expected Forbidden, got {info_err:?}"
    );

    // 6. New owner can read info.
    let (record, _meta) = get_did_info(&new_owner_auth, &state, &create.mnemonic)
        .await
        .expect("new owner reads info");
    assert_eq!(record.owner, new_owner);

    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// Admin can transfer a DID owned by anyone — admin override at the public-
/// API layer with realistic identities.
#[tokio::test]
async fn admin_can_transfer_did_owned_by_someone_else() {
    let (mediator, users) = TestMediator::with_users(["Admin", "Owner", "Target"])
        .await
        .expect("spawn mediator + users");
    let admin = users[0].did.clone();
    let owner = users[1].did.clone();
    let target = users[2].did.clone();

    let (state, _dir) = make_state().await;
    acl(&state, &admin, Role::Admin).await;
    acl(&state, &owner, Role::Owner).await;
    acl(&state, &target, Role::Owner).await;

    let owner_auth = auth_for(&owner, Role::Owner);
    create_did(&owner_auth, &state, Some("tenant/admin-flow"), false)
        .await
        .expect("create");

    let admin_auth = auth_for(&admin, Role::Admin);
    let updated = change_did_owner(&admin_auth, &state, "tenant/admin-flow", &target)
        .await
        .expect("admin transfers to target");
    assert_eq!(updated.owner, target);

    let target_auth = auth_for(&target, Role::Owner);
    let target_list = list_dids(&target_auth, &state, None, None, None)
        .await
        .unwrap();
    assert_eq!(target_list.len(), 1);

    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// A stranger (DID not in the ACL) cannot drive the public API at all —
/// `get_authorized_record` returns `Forbidden` regardless of role claims
/// because the caller doesn't own the record. With unrelated identities
/// from the mediator, this also pins that we don't accidentally lean on
/// substring matches against `did:` URIs.
#[tokio::test]
async fn stranger_cannot_change_owner_of_someone_elses_did() {
    let (mediator, users) = TestMediator::with_users(["Owner", "Target", "Stranger"])
        .await
        .expect("spawn mediator + users");
    let owner = users[0].did.clone();
    let target = users[1].did.clone();
    let stranger = users[2].did.clone();

    let (state, _dir) = make_state().await;
    acl(&state, &owner, Role::Owner).await;
    acl(&state, &target, Role::Owner).await;
    // Stranger is intentionally not added to the ACL.

    let owner_auth = auth_for(&owner, Role::Owner);
    create_did(&owner_auth, &state, Some("tenant/protected"), false)
        .await
        .expect("create");

    // Even with an Owner claim, the stranger can't touch a record they
    // don't own.
    let stranger_auth = auth_for(&stranger, Role::Owner);
    let err = change_did_owner(&stranger_auth, &state, "tenant/protected", &target)
        .await
        .expect_err("stranger must be forbidden");
    assert!(matches!(
        err,
        affinidi_webvh_control::error::AppError::Forbidden(_)
    ));

    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// `change_did_owner` must reject transfers to a DID that's not in the
/// ACL — otherwise we'd hand the slot to someone who can never log in to
/// claim it. Pin this with a real DID format so future stricter checks
/// (DID-method allow-listing, etc.) can't mask the ACL gate.
#[tokio::test]
async fn cannot_transfer_to_did_not_in_acl() {
    let (mediator, users) = TestMediator::with_users(["Owner", "Outsider"])
        .await
        .expect("spawn mediator + users");
    let owner = users[0].did.clone();
    let outsider = users[1].did.clone();

    let (state, _dir) = make_state().await;
    acl(&state, &owner, Role::Owner).await;
    // Outsider is intentionally NOT in the ACL.

    let owner_auth = auth_for(&owner, Role::Owner);
    create_did(&owner_auth, &state, Some("tenant/check-acl"), false)
        .await
        .expect("create");

    let err = change_did_owner(&owner_auth, &state, "tenant/check-acl", &outsider)
        .await
        .expect_err("transfer to non-ACL'd DID must fail");
    assert!(
        matches!(err, affinidi_webvh_control::error::AppError::Validation(ref m) if m.contains("not in the ACL")),
        "expected Validation about ACL membership, got {err:?}",
    );

    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// Transferring to the same owner is a no-op — should not create a
/// duplicate index entry, should not error.
#[tokio::test]
async fn transfer_to_self_is_idempotent() {
    let (mediator, users) = TestMediator::with_users(["Owner"])
        .await
        .expect("spawn mediator + users");
    let owner = users[0].did.clone();

    let (state, _dir) = make_state().await;
    acl(&state, &owner, Role::Owner).await;
    let owner_auth = auth_for(&owner, Role::Owner);

    create_did(&owner_auth, &state, Some("tenant/self"), false)
        .await
        .expect("create");

    let result = change_did_owner(&owner_auth, &state, "tenant/self", &owner)
        .await
        .expect("self-transfer ok");
    assert_eq!(result.owner, owner);

    // Owner index unchanged: exactly one row under `owner:{owner}:`.
    let idx = state
        .dids_ks
        .prefix_iter_raw(format!("owner:{owner}:"))
        .await
        .unwrap();
    assert_eq!(idx.len(), 1, "self-transfer should not duplicate index");

    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// Force-replace via `create_did(force=true)` clears the prior log and
/// witness content so the new slot starts fresh. With realistic DIDs this
/// confirms the wipe path doesn't depend on identifier shape.
#[tokio::test]
async fn force_replace_wipes_log_and_witness_content() {
    let (mediator, users) = TestMediator::with_users(["Owner"])
        .await
        .expect("spawn mediator + users");
    let owner = users[0].did.clone();

    let (state, _dir) = make_state().await;
    acl(&state, &owner, Role::Owner).await;
    let owner_auth = auth_for(&owner, Role::Owner);

    let create = create_did(&owner_auth, &state, Some("tenant/force"), false)
        .await
        .expect("create");

    // Seed log + witness content so we can prove force-replace wipes them.
    state
        .dids_ks
        .insert_raw(content_log_key(&create.mnemonic), b"old log".to_vec())
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(
            content_witness_key(&create.mnemonic),
            b"{\"old\":true}".to_vec(),
        )
        .await
        .unwrap();

    // Re-create the same path with force=true.
    let replaced = create_did(&owner_auth, &state, Some("tenant/force"), true)
        .await
        .expect("force replace");
    assert_eq!(replaced.mnemonic, "tenant/force");

    // Log + witness content are cleared.
    let log = state
        .dids_ks
        .get_raw(content_log_key(&create.mnemonic))
        .await
        .unwrap();
    assert!(log.is_none(), "old log content should be wiped");
    let witness = state
        .dids_ks
        .get_raw(content_witness_key(&create.mnemonic))
        .await
        .unwrap();
    assert!(witness.is_none(), "old witness content should be wiped");

    // The DID record itself is replaced — version_count back to 0.
    let record: DidRecord = state
        .dids_ks
        .get(did_key(&create.mnemonic))
        .await
        .unwrap()
        .expect("record present");
    assert_eq!(record.version_count, 0);
    assert_eq!(record.owner, owner);

    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// Force-replace by a non-owner is forbidden, even if the path exists.
/// Pins that `force` is not an authorization escape hatch.
#[tokio::test]
async fn force_replace_forbidden_for_non_owner() {
    let (mediator, users) = TestMediator::with_users(["Owner", "Squatter"])
        .await
        .expect("spawn mediator + users");
    let owner = users[0].did.clone();
    let squatter = users[1].did.clone();

    let (state, _dir) = make_state().await;
    acl(&state, &owner, Role::Owner).await;
    acl(&state, &squatter, Role::Owner).await;

    create_did(
        &auth_for(&owner, Role::Owner),
        &state,
        Some("tenant/no-takeover"),
        false,
    )
    .await
    .expect("create");

    let err = create_did(
        &auth_for(&squatter, Role::Owner),
        &state,
        Some("tenant/no-takeover"),
        true,
    )
    .await
    .expect_err("non-owner force replace must fail");
    assert!(matches!(
        err,
        affinidi_webvh_control::error::AppError::Forbidden(_)
    ));

    // Original owner record still intact.
    let record: DidRecord = state
        .dids_ks
        .get(did_key("tenant/no-takeover"))
        .await
        .unwrap()
        .expect("record present");
    assert_eq!(record.owner, owner);

    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

/// After deleting a transferred DID, the new owner's index entry is
/// removed too — closes the integrity loop on owner-index handling
/// across both the change-owner path and the delete path.
#[tokio::test]
async fn delete_after_transfer_clears_new_owners_index() {
    let (mediator, users) = TestMediator::with_users(["Owner", "NewOwner"])
        .await
        .expect("spawn mediator + users");
    let owner = users[0].did.clone();
    let new_owner = users[1].did.clone();

    let (state, _dir) = make_state().await;
    acl(&state, &owner, Role::Owner).await;
    acl(&state, &new_owner, Role::Owner).await;

    let owner_auth = auth_for(&owner, Role::Owner);
    create_did(&owner_auth, &state, Some("tenant/del-after"), false)
        .await
        .expect("create");
    change_did_owner(&owner_auth, &state, "tenant/del-after", &new_owner)
        .await
        .expect("transfer");

    let new_owner_auth = auth_for(&new_owner, Role::Owner);
    delete_did(&new_owner_auth, &state, "tenant/del-after")
        .await
        .expect("new owner deletes");

    // No `did:` row, no `owner:{new_owner}:` row.
    let did_row = state
        .dids_ks
        .get_raw(did_key("tenant/del-after"))
        .await
        .unwrap();
    assert!(did_row.is_none());
    let owner_row = state
        .dids_ks
        .get_raw(owner_key(&new_owner, "tenant/del-after"))
        .await
        .unwrap();
    assert!(owner_row.is_none());

    mediator.shutdown();
    mediator.join().await.expect("mediator shutdown");
}

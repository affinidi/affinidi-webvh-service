//! DID management business logic for the control plane.
//!
//! The control plane is the source of truth for all DIDs. Functions here
//! operate on the control plane's `dids` keyspace and use the shared types
//! from `webvh-common::did_ops`.

use affinidi_webvh_common::did_ops::{
    self, DidRecord, LogEntryInfo, LogMetadata, content_log_key, content_witness_key, did_key,
    owner_key,
};
use affinidi_webvh_common::server::mnemonic::{validate_custom_path, validate_mnemonic};
use affinidi_webvh_common::{CheckNameResponse, DidListEntry, RequestUriResponse};
use bip39::Language;
use rand::random_range;
use tracing::{debug, info, warn};

use crate::auth::AuthClaims;
use crate::error::AppError;
use crate::server::AppState;
use crate::store::KeyspaceHandle;

// Re-export for convenience
pub use affinidi_webvh_common::did_ops::{extract_did_id, extract_log_metadata};

// ---------------------------------------------------------------------------
// JSONL validation (wraps the common version with AppError)
// ---------------------------------------------------------------------------

fn validate_did_jsonl(content: &str) -> Result<(), AppError> {
    did_ops::validate_did_jsonl(content).map_err(AppError::Validation)
}

// ---------------------------------------------------------------------------
// Mnemonic generation (same logic as webvh-server/src/mnemonic.rs)
// ---------------------------------------------------------------------------

fn random_mnemonic() -> String {
    let wordlist = Language::English.word_list();
    let w1 = wordlist[random_range(0..wordlist.len())];
    let w2 = wordlist[random_range(0..wordlist.len())];
    format!("{w1}-{w2}")
}

async fn generate_unique_mnemonic(dids_ks: &KeyspaceHandle) -> Result<String, AppError> {
    for _ in 0..100 {
        let mnemonic = random_mnemonic();
        let key = format!("did:{mnemonic}");
        if !dids_ks.contains_key(key).await? {
            return Ok(mnemonic);
        }
    }
    Err(AppError::Internal(
        "failed to generate unique mnemonic after 100 attempts".into(),
    ))
}

async fn is_path_available(dids_ks: &KeyspaceHandle, path: &str) -> Result<bool, AppError> {
    Ok(!dids_ks.contains_key(format!("did:{path}")).await?)
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Load a DID record and verify the caller is the owner (or admin).
async fn get_authorized_record(
    dids_ks: &KeyspaceHandle,
    mnemonic: &str,
    auth: &AuthClaims,
) -> Result<DidRecord, AppError> {
    use crate::acl::Role;

    let record: DidRecord = dids_ks
        .get(did_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("DID not found: {mnemonic}")))?;
    if record.owner != auth.did && auth.role != Role::Admin {
        warn!(
            caller = %auth.did,
            owner = %record.owner,
            mnemonic = %mnemonic,
            "access denied: not the owner of this DID"
        );
        return Err(AppError::Forbidden("not the owner of this DID".into()));
    }
    Ok(record)
}

/// Resolve a custom path during create, applying force-replace semantics.
///
/// If the path is free, returns it unchanged. If taken and `force` is false,
/// returns `Conflict(conflict_msg)`. If taken and `force` is true, the caller
/// must be an admin or the current owner of that path; the existing log
/// content, witness, and owner-index are removed so the slot can be
/// reused. Stats are left intact (separate keyspace).
async fn resolve_path_for_create(
    state: &AppState,
    custom_path: &str,
    auth: &AuthClaims,
    force: bool,
    conflict_msg: &str,
) -> Result<String, AppError> {
    use crate::acl::Role;

    if is_path_available(&state.dids_ks, custom_path).await? {
        return Ok(custom_path.to_string());
    }

    if !force {
        return Err(AppError::Conflict(conflict_msg.to_string()));
    }

    let existing: DidRecord = state
        .dids_ks
        .get(did_key(custom_path))
        .await?
        .ok_or_else(|| AppError::Internal("path conflict but record missing".into()))?;

    if existing.owner != auth.did && auth.role != Role::Admin {
        warn!(
            caller = %auth.did,
            owner = %existing.owner,
            mnemonic = %custom_path,
            "force replace denied: not the owner or admin"
        );
        return Err(AppError::Forbidden(
            "force replace requires admin or current owner".into(),
        ));
    }

    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, content_log_key(custom_path));
    batch.remove(&state.dids_ks, content_witness_key(custom_path));
    if existing.owner != auth.did {
        batch.remove(&state.dids_ks, owner_key(&existing.owner, custom_path));
    }
    batch.commit().await?;

    info!(
        caller = %auth.did,
        prev_owner = %existing.owner,
        mnemonic = %custom_path,
        "force-replacing existing DID"
    );

    Ok(custom_path.to_string())
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Create a new DID slot (reserve a mnemonic/path).
///
/// When `force` is true and the requested path already exists, the caller
/// (admin or current owner of that path) replaces the existing slot — the
/// old DID's log content, witness, and owner-index are removed and the
/// caller becomes the new owner. Without `force`, a path collision returns
/// `Conflict` as before.
pub async fn create_did(
    auth: &AuthClaims,
    state: &AppState,
    path: Option<&str>,
    force: bool,
) -> Result<RequestUriResponse, AppError> {
    use crate::acl::Role;
    use crate::auth::session::now_epoch;

    let mnemonic = match path {
        Some(custom_path) if custom_path == ".well-known" => {
            if auth.role != Role::Admin {
                return Err(AppError::Forbidden(
                    "only admins can create the root DID".into(),
                ));
            }
            resolve_path_for_create(
                state,
                custom_path,
                auth,
                force,
                "root DID (.well-known) already exists",
            )
            .await?
        }
        Some(custom_path) => {
            validate_custom_path(custom_path)?;
            let conflict_msg = format!("path '{custom_path}' is already taken");
            resolve_path_for_create(state, custom_path, auth, force, &conflict_msg).await?
        }
        None => generate_unique_mnemonic(&state.dids_ks).await?,
    };

    let now = now_epoch();
    let record = DidRecord {
        owner: auth.did.clone(),
        mnemonic: mnemonic.clone(),
        created_at: now,
        updated_at: now,
        version_count: 0,
        did_id: None,
        content_size: 0,
        disabled: false,
        deleted_at: None,
    };

    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(&mnemonic), &record)?;
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&auth.did, &mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.commit().await?;

    // Build the DID URL using the did_hosting_url if configured, else public_url
    let base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .unwrap_or("http://localhost");
    let did_url = format!("{base_url}/{mnemonic}/did.jsonl");

    info!(did = %auth.did, mnemonic = %mnemonic, "DID URI created on control plane");

    Ok(RequestUriResponse { mnemonic, did_url })
}

/// Atomic claim-and-publish for a DID at a known path.
///
/// Solves the resolvability gap in the two-step
/// `request_uri` → `publish_did` flow: between those two calls a
/// previously-resolvable slot is empty, so any in-flight resolver hits
/// 404. This op writes the new mnemonic record + log content + owner
/// index in a single batch, so a resolver's GET returns either the old
/// content or the new content — never absent.
///
/// Auth model:
/// - Slot does not exist → caller becomes owner (same as
///   `request_uri` for a fresh path).
/// - Slot exists, caller is current owner → idempotent re-publish.
///   Witness is preserved (it's the owner's own).
/// - Slot exists, caller is admin AND `force == true` AND owner
///   differs → admin takeover. Old witness is cleared (it was
///   signed for the prior DID/owner). Old owner-index entry is
///   removed.
/// - Slot exists, any other case → `Forbidden`.
///
/// Content validation:
/// - `did_log` must parse as valid did.jsonl whose latest entry
///   resolves to a `did:webvh:` identifier.
/// - That identifier's host (and optional port) must match this
///   server's hosting URL, AND its path component must match the
///   requested `path`. This stops an admin from uploading
///   arbitrary `did.jsonl` content under a path they happen to own
///   that names a different host or path — claim-jumping.
pub async fn register_did_atomic(
    auth: &AuthClaims,
    state: &AppState,
    path: &str,
    did_log: &str,
    force: bool,
) -> Result<RequestUriResponse, AppError> {
    use crate::acl::Role;
    use crate::auth::session::now_epoch;

    // 1. Cheap validations first — bail out before any storage I/O.
    validate_custom_path(path)?;
    validate_did_jsonl(did_log)?;

    let server_base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .ok_or_else(|| {
            AppError::Internal(
                "server has neither did_hosting_url nor public_url configured; cannot validate DID host"
                    .into(),
            )
        })?;

    let did_id = extract_did_id(did_log).ok_or_else(|| {
        AppError::Validation("did_log's latest entry has no resolvable did:webvh state.id".into())
    })?;

    did_ops::validate_did_id_matches_request(&did_id, path, server_base_url)
        .map_err(AppError::Validation)?;

    // 2. Owner check (and admin-takeover gating).
    let existing: Option<DidRecord> = state.dids_ks.get(did_key(path)).await?;

    let owner_changed = match &existing {
        Some(rec) if rec.owner == auth.did => false,
        Some(rec) => {
            // Slot owned by someone else.
            if auth.role != Role::Admin {
                warn!(
                    caller = %auth.did,
                    owner = %rec.owner,
                    path = %path,
                    "atomic-register denied: not the owner of this slot"
                );
                return Err(AppError::Forbidden(
                    "slot is owned by a different DID".into(),
                ));
            }
            if !force {
                warn!(
                    caller = %auth.did,
                    owner = %rec.owner,
                    path = %path,
                    "atomic-register denied: admin takeover requires force=true"
                );
                return Err(AppError::Forbidden(
                    "admin takeover of a slot owned by another DID requires force=true".into(),
                ));
            }
            true
        }
        None => false,
    };

    // 3. Build the new record. Preserve created_at when the same owner
    //    is re-publishing; reset on takeover or fresh allocation.
    let now = now_epoch();
    let (created_at, version_count) = match (&existing, owner_changed) {
        (Some(rec), false) => (rec.created_at, rec.version_count + 1),
        _ => (now, 1),
    };

    let new_record = DidRecord {
        owner: auth.did.clone(),
        mnemonic: path.to_string(),
        created_at,
        updated_at: now,
        version_count,
        did_id: Some(did_id.clone()),
        content_size: did_log.len() as u64,
        disabled: false,
        deleted_at: None,
    };

    // 4. Single-batch atomic write: record, log content, owner index;
    //    plus old-owner cleanup on takeover. From a resolver's
    //    perspective there is no point at which the slot is
    //    half-updated — either old-content/old-record or
    //    new-content/new-record.
    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(path),
        did_log.as_bytes().to_vec(),
    );
    if owner_changed {
        let prev = existing
            .as_ref()
            .expect("owner_changed => existing record present");
        // Stale witness; signed for the prior DID identifier.
        batch.remove(&state.dids_ks, content_witness_key(path));
        batch.remove(&state.dids_ks, owner_key(&prev.owner, path));
    }
    batch.insert(&state.dids_ks, did_key(path), &new_record)?;
    batch.insert_raw(
        &state.dids_ks,
        owner_key(&auth.did, path),
        path.as_bytes().to_vec(),
    );
    batch.commit().await?;

    // Same rationale as `publish_did`: the atomic register path commits
    // a new log entry, so it must advance the update counters when the
    // control plane is authoritative for stats.
    state.stats_collector.record_update(path);

    let did_url = format!("{}/{path}/did.jsonl", server_base_url.trim_end_matches('/'));

    info!(
        did = %auth.did,
        path = %path,
        version = version_count,
        owner_changed,
        "DID atomically registered on control plane"
    );

    Ok(RequestUriResponse {
        mnemonic: path.to_string(),
        did_url,
    })
}

// ---------------------------------------------------------------------------
// Tests for register_did_atomic
// ---------------------------------------------------------------------------

// Tests are intentionally co-located with `register_did_atomic` for
// readability; the rest of the module's public API follows below.
#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests_atomic {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    use affinidi_webvh_common::DidRegisterRequest;
    use affinidi_webvh_common::server::config::{
        AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
    };
    use affinidi_webvh_common::server::stats_collector::StatsCollector;
    use affinidi_webvh_common::server::store::Store;

    use crate::acl::Role;
    use crate::config::{AppConfig, RegistryConfig};
    use crate::server::AppState;

    /// Build a structurally-valid did.jsonl whose latest entry's
    /// `state.id` is `did:webvh:<scid>:<host_encoded>[:<path>]`. The
    /// proof is real but signs a different identifier — fine for these
    /// tests because `validate_did_jsonl` is structural-only (no
    /// signature verification at the storage layer).
    fn build_test_did_log(scid: &str, host_encoded: &str, path: &str) -> String {
        let did_id = if path.is_empty() {
            format!("did:webvh:{scid}:{host_encoded}")
        } else {
            format!("did:webvh:{scid}:{host_encoded}:{path}")
        };
        // Re-target the upstream fixture by string-replacing the
        // baked-in DID identifier. Keeps `parameters`, `proof`, and
        // verificationMethod shape intact so LogEntry deserialization
        // accepts it.
        const FIXTURE: &str = r#"{"versionId":"1-QmRiFdWdyckg8HETNgZWEXP3LGhEZD9pJBVqFRCRWpUrKh","versionTime":"2025-07-09T21:32:15Z","parameters":{"method":"did:webvh:1.0","scid":"QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia","updateKeys":["z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR"],"portable":true,"nextKeyHashes":["QmUSYM6seDvKtYpSEsr7Y5bmM5owYVGV3EhZ5BCUexrAcR"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/cid/v1"],"assertionMethod":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"authentication":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"capabilityDelegation":[],"capabilityInvocation":[],"id":"PLACEHOLDER_ID","keyAgreement":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"service":[],"verificationMethod":[{"controller":"did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000","id":"did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0","publicKeyMultibase":"z6MkizY3BLE8VwADPdzuhRcsTVDnakfGRNMjWxhk1WJYTjRg","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-09T21:32:15Z","verificationMethod":"did:key:z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR#z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR","proofPurpose":"assertionMethod","proofValue":"z64Ney14a8BVM5XWQ9qHchnmNH2EKwsRpp7y972sxoGc84mDu56Vq8pJHpymZPpcPmcrDPtqKJs1CkapXxc14ZGeM"}]}"#;
        FIXTURE.replace("PLACEHOLDER_ID", &did_id)
    }

    async fn test_state() -> (AppState, tempfile::TempDir) {
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
        };

        (state, dir)
    }

    fn owner_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role: Role::Owner,
        }
    }

    fn admin_auth(did: &str) -> AuthClaims {
        AuthClaims {
            did: did.to_string(),
            role: Role::Admin,
        }
    }

    /// Fresh slot, well-formed did.jsonl, caller becomes owner.
    #[tokio::test]
    async fn fresh_slot_succeeds_and_writes_atomically() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "alpha";
        let did_log = build_test_did_log("scid-alpha", "control.test", path);

        let result = register_did_atomic(&owner_auth(owner), &state, path, &did_log, false)
            .await
            .expect("fresh-slot register should succeed");
        assert_eq!(result.mnemonic, path);
        assert_eq!(result.did_url, "http://control.test/alpha/did.jsonl");

        // Record + log + owner-index all present after the single batch commit.
        let record: DidRecord = state
            .dids_ks
            .get(did_key(path))
            .await
            .unwrap()
            .expect("record");
        assert_eq!(record.owner, owner);
        assert_eq!(record.version_count, 1);
        assert_eq!(
            record.did_id.as_deref(),
            Some("did:webvh:scid-alpha:control.test:alpha")
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

    /// Same owner re-registering: idempotent path. Slot stays owned by the
    /// same DID; version_count bumps; created_at preserved; new content
    /// replaces old without ever leaving the slot empty.
    #[tokio::test]
    async fn owner_re_register_is_idempotent() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "beta";

        let log_v1 = build_test_did_log("scid-beta", "control.test", path);
        let r1 = register_did_atomic(&owner_auth(owner), &state, path, &log_v1, false)
            .await
            .unwrap();
        let rec_v1: DidRecord = state.dids_ks.get(did_key(path)).await.unwrap().unwrap();

        // Same owner re-registers (potentially with new log content). No
        // intermediate empty state — old content is replaced in-batch.
        let log_v2 = build_test_did_log("scid-beta", "control.test", path);
        let r2 = register_did_atomic(&owner_auth(owner), &state, path, &log_v2, false)
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

    /// A different non-admin caller hitting an existing slot is forbidden,
    /// regardless of force.
    #[tokio::test]
    async fn other_owner_without_admin_forbidden() {
        let (state, _dir) = test_state().await;
        let path = "gamma";
        let owner_a = "did:example:owner-a";
        let owner_b = "did:example:owner-b";
        let log = build_test_did_log("scid-gamma", "control.test", path);

        register_did_atomic(&owner_auth(owner_a), &state, path, &log, false)
            .await
            .unwrap();

        // Without force.
        let err = register_did_atomic(&owner_auth(owner_b), &state, path, &log, false)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));

        // With force — still 403, since caller is not admin.
        let err = register_did_atomic(&owner_auth(owner_b), &state, path, &log, true)
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
        let log = build_test_did_log("scid-delta", "control.test", path);

        register_did_atomic(
            &owner_auth("did:example:owner-a"),
            &state,
            path,
            &log,
            false,
        )
        .await
        .unwrap();

        let err = register_did_atomic(&admin_auth("did:example:admin"), &state, path, &log, false)
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
        let log = build_test_did_log("scid-epsilon", "control.test", path);

        register_did_atomic(&owner_auth(owner_a), &state, path, &log, false)
            .await
            .unwrap();
        // Seed a witness file as if the original owner had uploaded one.
        state
            .dids_ks
            .insert_raw(content_witness_key(path), b"prior-witness".to_vec())
            .await
            .unwrap();

        register_did_atomic(&admin_auth(admin), &state, path, &log, true)
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
        let log = build_test_did_log("scid-x", "control.test", "wrong-path");
        let err = register_did_atomic(
            &owner_auth("did:example:owner"),
            &state,
            "right-path",
            &log,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("path")));
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
        let log = build_test_did_log("scid-x", "other-host.example", "valid-path");
        let err = register_did_atomic(
            &owner_auth("did:example:owner"),
            &state,
            "valid-path",
            &log,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("host")));
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
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    /// Smoke test: the wire request type round-trips with default `force`.
    #[test]
    fn did_register_request_round_trip_defaults_force_false() {
        let raw = r#"{"path":"alpha","did_log":"line"}"#;
        let req: DidRegisterRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.path, "alpha");
        assert_eq!(req.did_log, "line");
        assert!(!req.force, "force must default to false");
    }

    /// Pin the stats-counter behaviour: every successful
    /// `register_did_atomic` advances the aggregate `total_updates` and the
    /// per-DID `last_updated_at`. Without this the dashboards / `MSG_INFO`
    /// response will report zero updates in self-hosted (control-plane-as-
    /// authoritative) deployments. Mirrors webvh-server::publish_did's
    /// `record_update` call.
    #[tokio::test]
    async fn register_did_atomic_records_update_stats() {
        let (state, _dir) = test_state().await;
        let owner = "did:example:owner";
        let path = "stats-fresh";
        let did_log = build_test_did_log("scid-stats", "control.test", path);

        let before = state.stats_collector.get_aggregate().total_updates;
        register_did_atomic(&owner_auth(owner), &state, path, &did_log, false)
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
        register_did_atomic(&owner_auth(owner), &state, path, &did_log, false)
            .await
            .unwrap();
        let after_two = state.stats_collector.get_aggregate().total_updates;
        assert_eq!(
            after_two,
            after + 1,
            "idempotent re-register must also advance total_updates"
        );
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
        let did_log = build_test_did_log("scid-publish", "control.test", path);

        // Reserve the slot. create_did is the "request URI" step — it
        // doesn't write log content and shouldn't bump update counters.
        let baseline = state.stats_collector.get_aggregate().total_updates;
        create_did(&owner_auth(owner), &state, Some(path), false)
            .await
            .unwrap();
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline,
            "create_did is a slot reservation; must NOT count as an update"
        );

        // Publish flips the counter.
        publish_did(&owner_auth(owner), &state, path, &did_log)
            .await
            .unwrap();
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline + 1,
            "publish_did must record an update on success"
        );

        // Republishing advances again.
        publish_did(&owner_auth(owner), &state, path, &did_log)
            .await
            .unwrap();
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline + 2,
            "subsequent publishes must keep advancing total_updates"
        );
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
        let did_log = build_test_did_log("scid-fail", "control.test", path);

        // Reserve as owner-a, then have owner-b try to publish.
        create_did(&owner_auth(owner_a), &state, Some(path), false)
            .await
            .unwrap();

        let baseline = state.stats_collector.get_aggregate().total_updates;
        let err = publish_did(&owner_auth(owner_b), &state, path, &did_log)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline,
            "auth-denied publish must NOT record an update"
        );

        // Validation failure on the JSONL body — still no counter movement.
        let err = publish_did(&owner_auth(owner_a), &state, path, "not-jsonl")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
        assert_eq!(
            state.stats_collector.get_aggregate().total_updates,
            baseline,
            "validation-failed publish must NOT record an update"
        );
    }
}

/// Publish (upload) a did.jsonl log for an existing DID slot.
pub async fn publish_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    did_log: &str,
) -> Result<(), AppError> {
    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    validate_did_jsonl(did_log)?;

    let new_size = did_log.len() as u64;
    let did_id_val = extract_did_id(did_log);

    record.updated_at = now_epoch();
    record.version_count += 1;
    record.did_id = did_id_val;
    record.content_size = new_size;

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        did_log.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.commit().await?;

    // Mirror webvh-server's `record_update` call so total_updates /
    // last_updated_at advance when the control plane is the authoritative
    // store (standalone or daemon mode). Without this, updates only
    // surface via stats-sync from a remote server, so they sit at zero
    // in self-hosted deployments.
    state.stats_collector.record_update(mnemonic);

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        size = new_size,
        version = record.version_count,
        "did.jsonl published on control plane"
    );

    Ok(())
}

/// Upload witness content for a DID.
pub async fn upload_witness(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    witness_content: &str,
) -> Result<(), AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    if witness_content.is_empty() {
        return Err(AppError::Validation(
            "did-witness.json content cannot be empty".into(),
        ));
    }

    serde_json::from_str::<serde_json::Value>(witness_content)
        .map_err(|e| AppError::Validation(format!("did-witness.json must be valid JSON: {e}")))?;

    state
        .dids_ks
        .insert_raw(
            content_witness_key(mnemonic),
            witness_content.as_bytes().to_vec(),
        )
        .await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "did-witness.json uploaded on control plane");

    Ok(())
}

/// Get detailed information about a DID.
pub async fn get_did_info(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<(DidRecord, Option<LogMetadata>), AppError> {
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let log_metadata = match state.dids_ks.get_raw(content_log_key(mnemonic)).await? {
        Some(bytes) => {
            let content = String::from_utf8(bytes).unwrap_or_default();
            Some(extract_log_metadata(&content))
        }
        None => None,
    };

    debug!(did = %auth.did, mnemonic = %mnemonic, "DID info retrieved from control plane");

    Ok((record, log_metadata))
}

/// Get parsed log entries for a DID.
pub async fn get_did_log(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<Vec<LogEntryInfo>, AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    let content = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))?;

    Ok(did_ops::parse_log_entries(&content))
}

/// Get the raw JSONL content for a DID log as a plain string.
pub async fn get_raw_log(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<String, AppError> {
    validate_mnemonic(mnemonic)?;
    get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    String::from_utf8(bytes).map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))
}

/// List DIDs owned by the caller (or by a specific owner if admin).
/// When the caller is admin and no `requested_owner` is provided, returns all DIDs.
pub async fn list_dids(
    auth: &AuthClaims,
    state: &AppState,
    requested_owner: Option<&str>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<Vec<DidListEntry>, AppError> {
    use crate::acl::Role;

    if auth.role == Role::Admin && requested_owner.is_none() {
        return list_all_dids(state).await;
    }

    let target_owner = if auth.role == Role::Admin {
        requested_owner.unwrap_or(&auth.did)
    } else {
        &auth.did
    };

    let prefix = format!("owner:{target_owner}:");
    let raw = state.dids_ks.prefix_iter_raw(prefix).await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let mnemonic = String::from_utf8(value)
            .map_err(|e| AppError::Internal(format!("invalid mnemonic bytes: {e}")))?;
        if let Some(record) = state.dids_ks.get::<DidRecord>(did_key(&mnemonic)).await? {
            let stats_key = format!("stats:{mnemonic}");
            let did_stats: affinidi_webvh_common::DidStats =
                state.stats_ks.get(stats_key).await?.unwrap_or_default();
            entries.push(DidListEntry {
                mnemonic: record.mnemonic,
                owner: record.owner,
                created_at: record.created_at,
                updated_at: record.updated_at,
                version_count: record.version_count,
                did_id: record.did_id,
                total_resolves: did_stats.total_resolves,
                disabled: record.disabled,
            });
        }
    }

    // Apply pagination
    let offset = offset.unwrap_or(0);
    let limit = limit.unwrap_or(1000);
    let total = entries.len();
    let entries: Vec<_> = entries.into_iter().skip(offset).take(limit).collect();

    info!(did = %auth.did, owner = %target_owner, total, returned = entries.len(), "DIDs listed on control plane");

    Ok(entries)
}

/// List all DIDs in the store (admin only).
async fn list_all_dids(state: &AppState) -> Result<Vec<DidListEntry>, AppError> {
    let raw = state.dids_ks.prefix_iter_raw("did:").await?;

    let mut entries = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        let record: DidRecord = match serde_json::from_slice(&value) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let stats_key = format!("stats:{}", record.mnemonic);
        let did_stats: affinidi_webvh_common::DidStats =
            state.stats_ks.get(stats_key).await?.unwrap_or_default();
        entries.push(DidListEntry {
            mnemonic: record.mnemonic,
            owner: record.owner,
            created_at: record.created_at,
            updated_at: record.updated_at,
            version_count: record.version_count,
            did_id: record.did_id,
            total_resolves: did_stats.total_resolves,
            disabled: record.disabled,
        });
    }

    info!(
        count = entries.len(),
        "all DIDs listed (admin) on control plane"
    );

    Ok(entries)
}

/// Delete a DID and all its associated data.
pub async fn delete_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<Option<String>, AppError> {
    validate_mnemonic(mnemonic)?;
    let record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let did_id = record.did_id.clone();

    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, did_key(mnemonic));
    batch.remove(&state.dids_ks, content_log_key(mnemonic));
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    batch.remove(&state.dids_ks, owner_key(&record.owner, mnemonic));
    batch.commit().await?;

    info!(did = %auth.did, mnemonic = %mnemonic, "DID deleted on control plane");

    Ok(did_id)
}

/// Transfer ownership of a DID to a different DID.
///
/// The caller must be the current owner or an admin. The new owner must
/// already exist in the ACL — this prevents transferring a DID to an
/// identity that can never authenticate to claim it.
pub async fn change_did_owner(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    new_owner: &str,
) -> Result<DidRecord, AppError> {
    use affinidi_webvh_common::server::acl::get_acl_entry;

    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;

    // Authorize the caller against the existing record first — keeps the
    // error class stable (Forbidden, not Validation) when an unauthorized
    // caller submits a malformed target. Any new-owner format check after
    // this point only runs for authorized callers.
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let new_owner = new_owner.trim();
    if new_owner.is_empty() {
        return Err(AppError::Validation("new owner DID cannot be empty".into()));
    }
    if !new_owner.starts_with("did:") {
        return Err(AppError::Validation(
            "new owner must be a DID (must start with 'did:')".into(),
        ));
    }

    if record.owner == new_owner {
        return Ok(record);
    }

    if get_acl_entry(&state.acl_ks, new_owner).await?.is_none() {
        return Err(AppError::Validation(format!(
            "new owner '{new_owner}' is not in the ACL — add them first"
        )));
    }

    let prev_owner = std::mem::replace(&mut record.owner, new_owner.to_string());
    record.updated_at = now_epoch();

    let mut batch = state.store.batch();
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.remove(&state.dids_ks, owner_key(&prev_owner, mnemonic));
    batch.insert_raw(
        &state.dids_ks,
        owner_key(new_owner, mnemonic),
        mnemonic.as_bytes().to_vec(),
    );
    batch.commit().await?;

    info!(
        caller = %auth.did,
        prev_owner = %prev_owner,
        new_owner = %new_owner,
        mnemonic = %mnemonic,
        "DID owner changed on control plane"
    );

    Ok(record)
}

/// Toggle the `disabled` flag on a DID record.
pub async fn set_did_disabled(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    disabled: bool,
) -> Result<(), AppError> {
    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;
    record.disabled = disabled;
    state.dids_ks.insert(did_key(mnemonic), &record).await?;
    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        disabled,
        "DID disabled state updated on control plane"
    );
    Ok(())
}

/// Roll back (remove) the last log entry from a DID's JSONL content.
pub async fn rollback_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
) -> Result<(DidRecord, Option<LogMetadata>), AppError> {
    use crate::auth::session::now_epoch;

    validate_mnemonic(mnemonic)?;
    let mut record = get_authorized_record(&state.dids_ks, mnemonic, auth).await?;

    let bytes = state
        .dids_ks
        .get_raw(content_log_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::NotFound("no log content for this DID".into()))?;

    let content = String::from_utf8(bytes)
        .map_err(|e| AppError::Internal(format!("invalid log bytes: {e}")))?;

    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 {
        return Err(AppError::Validation(
            "cannot rollback: DID log must have at least 2 entries".into(),
        ));
    }

    let truncated_lines = &lines[..lines.len() - 1];
    let truncated = truncated_lines.join("\n");

    let new_did_id = extract_did_id(&truncated);
    let new_size = truncated.len() as u64;

    record.version_count = truncated_lines.len() as u64;
    record.did_id = new_did_id;
    record.content_size = new_size;
    record.updated_at = now_epoch();

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        truncated.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    batch.remove(&state.dids_ks, content_witness_key(mnemonic));
    batch.commit().await?;

    let log_metadata = Some(extract_log_metadata(&truncated));

    info!(
        did = %auth.did,
        mnemonic = %mnemonic,
        remaining = truncated_lines.len(),
        "DID log entry rolled back on control plane"
    );

    Ok((record, log_metadata))
}

/// Check if a custom path is available.
pub async fn check_name(state: &AppState, path: &str) -> Result<CheckNameResponse, AppError> {
    validate_custom_path(path)?;
    let available = is_path_available(&state.dids_ks, path).await?;
    Ok(CheckNameResponse {
        available,
        path: path.to_string(),
    })
}

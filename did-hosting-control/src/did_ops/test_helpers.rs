//! Helpers the `did_ops` test modules share.

use super::*;

use std::path::PathBuf;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use did_hosting_common::did::{DidDocumentOptions, build_did_document, create_log_entry};
use did_hosting_common::server::config::{
    AuthConfig, FeaturesConfig, LogConfig, SecretsConfig, ServerConfig, StoreConfig, VtaConfig,
};

use did_hosting_common::server::store::Store;

use crate::config::{AppConfig, RegistryConfig};
use crate::server::AppState;
use did_hosting_common::server::acl::Role;

/// Publish a new version of an existing slot through [`prepare_republish`] —
/// **test-only**.
///
/// The `did/publish` task this served has been retired; the only live publish
/// path is `did/register` → [`register_did_atomic`], which carries the
/// agent-name reconcile and the identity-rotation hook. This remains so tests
/// can drive [`prepare_republish`] — the front half the agent-name verbs share
/// — on its own (its `?domain=` cross-check and `record.domain` backfill).
/// Never give it a production caller: a reconcile or a hook added here would
/// not run in production.
pub(super) async fn publish_did(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    did_log: &str,
    request_domain: Option<&str>,
) -> Result<(), AppError> {
    // Serialise the read-modify-write on this slot. `reconcile_agent_names`
    // checks the name index and then writes it, and the agent-name verbs take
    // the same lock — without it a publish and a `set` on the same DID
    // interleave between check and commit. Two slots claiming the same free
    // name are serialised by the per-name locks `reconcile_agent_names` takes.
    validate_slot_path_shape(mnemonic)?;
    let slot_guard = state.path_locks.guard(mnemonic).await;

    let (mut record, domain, publication) =
        prepare_republish(auth, state, mnemonic, did_log, request_domain).await?;
    let new_size = record.content_size;
    let now = record.updated_at;
    let quota_guard = hold_size_quota(state, auth, mnemonic, new_size).await?;

    // Keep the authoritative registry in step with what the document claims —
    // applying the same preconditions `set` does, so this path cannot be used
    // to capture a reserved name or take one from another DID.
    let (claimed, released, name_locks) = reconcile_agent_names(
        state,
        &mut record,
        mnemonic,
        &publication.agent_names(&domain),
        &domain,
        now,
    )
    .await?;

    let mut batch = state.store.batch();
    batch.insert_raw(
        &state.dids_ks,
        content_log_key(mnemonic),
        did_log.as_bytes().to_vec(),
    );
    batch.insert(&state.dids_ks, did_key(mnemonic), &record)?;
    for name in &claimed {
        batch.insert_raw(
            &state.dids_ks,
            agent_name_key(&domain, name),
            mnemonic.as_bytes().to_vec(),
        );
    }
    // The record as it stands under the slot lock, for the derived rows.
    let previous: Option<DidRecord> = state.dids_ks.get(did_key(mnemonic)).await?;
    for name in &released {
        batch.remove(&state.dids_ks, agent_name_key(&domain, name));
    }
    let sync = crate::server_push::stage_did_sync(
        state,
        &mut batch,
        mnemonic,
        crate::server_push::DidChange::Published { log: did_log },
    )
    .await;
    let usage = stage_index(state, &mut batch, previous.as_ref(), Some(&record)).await?;
    batch.commit().await?;
    sync.finish(state).await;
    // Released before the identity check below, which can reach the network
    // when this is the service's own DID; nothing after this point reads or
    // writes the slot or its names.
    drop(name_locks);
    drop(usage);
    drop(slot_guard);
    invalidate_cached_content(state, mnemonic);
    drop(quota_guard);

    // Mirror did-hosting-server's `record_update` call so total_updates /
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

    // If the DID just published was the service's *own*, its keys or services
    // may have changed. Re-resolve and rotate the identity if so.
    //
    // Safe to call on every publish: it compares mnemonics first (no network),
    // and a publish of our own DID that didn't change the identity resolves the
    // document once and no-ops. It deliberately does not fail the publish — the
    // log entry is committed and correct either way, and a rotation that can't
    // proceed logs loudly rather than rolling back a valid publish.
    crate::identity_rotation::on_did_published(state, mnemonic).await;

    Ok(())
}

/// Build a real signed did:webvh log entry for testing.
///
/// Generates a fresh Ed25519 signing key per call, builds the DID
/// document via the same `build_did_document` helper production
/// uses, and signs the log entry via `create_log_entry` — the
/// resulting jsonl passes the cryptographic-proof verifier in
/// `verify_did_log_proofs`. Replaces an earlier static fixture
/// that string-replaced `state.id` and so produced an entry whose
/// proof was correctly-formed but signed for a different DID.
///
/// `scid` parameter is ignored — the SCID is derived from the
/// signed log entry. Kept in the signature for call-site
/// compatibility with the prior helper; tests that asserted a
/// specific scid have been updated to read it from the resulting
/// record's `did_id`.
pub(super) async fn build_test_did_log(_scid: &str, host_encoded: &str, path: &str) -> String {
    let signing = Secret::generate_ed25519(None, None);
    let signing_pub_mb = signing
        .get_public_keymultibase()
        .expect("signing public key multibase");
    let doc = build_did_document(
        host_encoded,
        path,
        &signing_pub_mb,
        &DidDocumentOptions::default(),
    );
    let (_scid, jsonl) = create_log_entry(&doc, &signing)
        .await
        .expect("create_log_entry");
    jsonl
}

/// Same as [`build_test_did_log`] but the document advertises the
/// requested transports, so the `services` cache has something to read.
pub(super) async fn build_test_did_log_with_transports(
    host_encoded: &str,
    path: &str,
    tsp: bool,
    didcomm: bool,
) -> String {
    const MED: &str = "did:webvh:QmMED:mediator.example.com";
    let signing = Secret::generate_ed25519(None, None);
    let signing_pub_mb = signing
        .get_public_keymultibase()
        .expect("signing public key multibase");
    let doc = build_did_document(
        host_encoded,
        path,
        &signing_pub_mb,
        &DidDocumentOptions {
            key_agreement_multibase: None,
            mediator_endpoint: didcomm.then_some(MED),
            tsp_endpoint: tsp.then_some(MED),
            omit_scid_alias: false,
        },
    );
    let (_scid, jsonl) = create_log_entry(&doc, &signing)
        .await
        .expect("create_log_entry");
    jsonl
}

pub(super) async fn stored_services(state: &AppState, path: &str) -> Option<Vec<String>> {
    let record: DidRecord = state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record");
    record.services
}

pub(super) async fn test_state() -> (AppState, tempfile::TempDir) {
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

    let state = crate::test_support::bare_state(config, store, None).await;

    (state, dir)
}

pub(super) fn owner_auth(did: &str) -> AuthClaims {
    AuthClaims {
        did: did.to_string(),
        role: Role::Owner,
        session_pubkey_b58btc: None,
        session_id: String::new(),
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
    }
}

pub(super) fn admin_auth(did: &str) -> AuthClaims {
    AuthClaims {
        did: did.to_string(),
        role: Role::Admin,
        session_pubkey_b58btc: None,
        session_id: String::new(),
        amr: vec!["did".to_string()],
        acr: "aal1".to_string(),
    }
}

/// Seed an ACL entry for a caller with an explicit DomainScope.
pub(super) async fn seed_caller_acl(
    state: &AppState,
    did: &str,
    role: Role,
    scope: did_hosting_common::server::domain::DomainScope,
) {
    use did_hosting_common::server::acl::AclEntry;
    use did_hosting_common::server::acl::store_acl_entry;
    let entry = AclEntry {
        did: did.into(),
        role,
        label: None,
        created_at: 0,
        max_total_size: None,
        max_did_count: None,
        domains: scope,
    };
    store_acl_entry(&state.acl_ks, &entry).await.unwrap();
}

// -----------------------------------------------------------------------
// Agent names
// -----------------------------------------------------------------------

/// A signed did:webvh log whose document claims the given agent names via
/// `alsoKnownAs`. Each name is written as `<host>/@<name>`, the form
/// `agent-names` parses and `extract_agent_names` matches on. `host` is the
/// decoded authority (no port-encoding) so it equals the DID's host.
pub(super) async fn build_test_did_log_with_names(
    host: &str,
    path: &str,
    names: &[&str],
) -> String {
    let signing = Secret::generate_ed25519(None, None);
    let signing_pub_mb = signing
        .get_public_keymultibase()
        .expect("signing public key multibase");
    let mut doc = build_did_document(host, path, &signing_pub_mb, &DidDocumentOptions::default());
    if !names.is_empty() {
        let aka: Vec<String> = names.iter().map(|n| format!("{host}/@{n}")).collect();
        doc["alsoKnownAs"] = serde_json::json!(aka);
    }
    let (_scid, jsonl) = create_log_entry(&doc, &signing)
        .await
        .expect("create_log_entry");
    jsonl
}

pub(super) async fn get_record(state: &AppState, path: &str) -> DidRecord {
    state
        .dids_ks
        .get(did_key(path))
        .await
        .unwrap()
        .expect("record")
}

pub(super) async fn index_target(state: &AppState, domain: &str, name: &str) -> Option<String> {
    state
        .dids_ks
        .get_raw(agent_name_key(domain, name))
        .await
        .unwrap()
        .map(|b| String::from_utf8(b).unwrap())
}

/// Register a fresh DID at `path` on host `control.test`, owned by `owner`.
pub(super) async fn register_owned(state: &AppState, owner: &str, path: &str) {
    let log = build_test_did_log("scid", "control.test", path).await;
    register_did_atomic(&owner_auth(owner), state, path, &log, false, None)
        .await
        .expect("register");
}

/// Test shims over `update_agent_name` keeping the historical verb
/// names readable in the assertions below: `set` / `enable` are both
/// `state: active` (the declarative spec folds bind / refresh / resume
/// into one value), `disable` is `state: parked`.
pub(super) async fn set_agent_name(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    domain: Option<&str>,
) -> Result<DidRecord, AppError> {
    update_agent_name(
        auth,
        state,
        mnemonic,
        name,
        did_log,
        domain,
        AgentNameState::Active,
    )
    .await
}

pub(super) async fn disable_agent_name(
    auth: &AuthClaims,
    state: &AppState,
    mnemonic: &str,
    name: &str,
    did_log: &str,
    domain: Option<&str>,
) -> Result<DidRecord, AppError> {
    update_agent_name(
        auth,
        state,
        mnemonic,
        name,
        did_log,
        domain,
        AgentNameState::Parked,
    )
    .await
}

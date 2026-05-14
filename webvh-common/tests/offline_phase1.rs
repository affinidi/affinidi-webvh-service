//! End-to-end smoke test for the offline-prepare (phase 1) recipe path.
//!
//! Verifies:
//! - `run_vta_for_recipe` writes a non-empty `bootstrap-request.json`.
//! - The seed it surfaces round-trips through the plaintext secret store.
//! - The plaintext backend's seed is what phase 2's `get_bootstrap_seed`
//!   would read against the same config path.
//!
//! Run with:
//!
//!   cargo test -p affinidi-webvh-common --features server-core --test offline_phase1
//!
//! Gated on `server-core` since the recipe + secret-store modules live
//! under `affinidi_webvh_common::server::*`. CI's `test-default` job runs
//! it as part of the recipe-examples step.

#![cfg(feature = "server-core")]

use std::path::PathBuf;
use std::sync::Arc;

use affinidi_webvh_common::server::config::SecretsConfig;
use affinidi_webvh_common::server::operator_messages::WebvhServerMessages;
use affinidi_webvh_common::server::secret_store::create_secret_store;
use affinidi_webvh_common::server::setup_recipe::{
    AdminSection, DaemonSection, DeploymentSection, IdentitySection, OutputSection,
    ReprovisionSection, SecretsSection, ServerSection, ServiceKind, SetupRecipe, VtaMode,
    VtaSection, VtaSetupOutcome, WatcherSection, run_vta_for_recipe,
};
use vta_sdk::provision_client::OperatorMessages;

fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn offline_prepare_recipe(request_path: PathBuf, config_path: PathBuf) -> SetupRecipe {
    SetupRecipe {
        deployment: DeploymentSection {
            service: ServiceKind::Server,
            vta_mode: VtaMode::OfflinePrepare,
        },
        output: OutputSection { config_path },
        server: ServerSection::default(),
        identity: IdentitySection {
            public_url: Some("https://server1.example.com".into()),
            did_hosting_url: Some("https://did.example.com".into()),
            ..Default::default()
        },
        vta: VtaSection {
            request_path: Some(request_path),
            ..Default::default()
        },
        // Plaintext + confirm — the test process has no keyring; this is
        // the only backend that works without external infra.
        secrets: SecretsSection {
            backend: Some(affinidi_webvh_common::server::setup_recipe::SecretsBackend::Plaintext),
            confirm_plaintext: true,
            ..Default::default()
        },
        admin: AdminSection::default(),
        reprovision: ReprovisionSection::default(),
        watcher: WatcherSection::default(),
        daemon: DaemonSection::default(),
    }
}

#[tokio::test]
async fn phase1_writes_request_and_seed_round_trips_via_plaintext_store() {
    let dir = temp_dir();
    let request_path = dir.path().join("bootstrap-request.json");
    let config_path = dir.path().join("config.toml");

    // The plaintext store reads/writes through config.toml. Seed an
    // empty config so phase 1's `set_bootstrap_seed` has a file to
    // append to without create_dir_all surprises.
    std::fs::write(&config_path, "").expect("seed empty config");

    let recipe = offline_prepare_recipe(request_path.clone(), config_path.clone());
    recipe.validate().expect("recipe must validate");

    let messages: Arc<dyn OperatorMessages> = Arc::new(WebvhServerMessages);
    // Vars match what webvh-server's setup_recipe.rs passes for the
    // webvh-daemon template (URL only — no DIDComm/mediator).
    let url = recipe.identity.public_url.clone().unwrap();
    let template_vars = [("URL", url.as_str())];

    let outcome = run_vta_for_recipe(
        &recipe,
        None,
        messages,
        None,
        "webvh-daemon",
        &template_vars,
        Some("webvh-server"),
        None,
    )
    .await
    .expect("offline-prepare must succeed");

    let info = match outcome {
        VtaSetupOutcome::OfflinePreparedOnly(info) => info,
        // VtaSetupOutcome isn't Debug — narrow the diagnostic to a
        // string discriminator the test reader can act on.
        VtaSetupOutcome::Online(_) => panic!("got Online; expected OfflinePreparedOnly"),
        VtaSetupOutcome::Offline(_) => panic!("got Offline; expected OfflinePreparedOnly"),
        VtaSetupOutcome::SelfManaged(_) => {
            panic!("got SelfManaged; expected OfflinePreparedOnly")
        }
    };

    // The request file is on disk + parseable JSON.
    assert_eq!(info.request_path, request_path);
    let raw = std::fs::read_to_string(&request_path).expect("request file readable");
    let _: serde_json::Value = serde_json::from_str(&raw).expect("request is JSON");

    // The ephemeral did:key looks like one. Tighter validation
    // (multibase decode + key length) is the SDK's job; we just want
    // the round-trip surface.
    assert!(
        info.client_did.starts_with("did:key:"),
        "client_did should start with did:key: — got {}",
        info.client_did
    );
    assert!(!info.nonce.is_empty(), "nonce should not be empty");

    // Seed must be non-zero (the SDK generates random bytes; a zero
    // seed would mean the wiring dropped the value).
    assert!(
        info.seed.iter().any(|b| *b != 0),
        "seed bytes were all zero — wiring dropped the value"
    );

    // Persist via the plaintext store the recipe's [secrets] section
    // resolves to. This is the same code path the per-binary
    // `persist_offline_prepare` helper takes.
    let secrets_cfg = secrets_for_test();
    let store = create_secret_store(&secrets_cfg, &config_path).expect("plaintext store");
    store
        .set_bootstrap_seed(&info.seed)
        .await
        .expect("set_bootstrap_seed must succeed");

    // Re-open the store (phase 2's perspective: fresh process, same
    // config + secrets backend) and round-trip.
    let store2 =
        create_secret_store(&secrets_cfg, &config_path).expect("plaintext store (phase 2)");
    let recovered = store2
        .get_bootstrap_seed()
        .await
        .expect("get_bootstrap_seed must succeed")
        .expect("seed should be present after phase 1 set");
    assert_eq!(recovered, info.seed, "seed round-trip failed");
}

/// Helper: matches the SecretsConfig the recipe resolver would produce
/// for `backend = "plaintext"` in this test process. Built explicitly
/// here so the test doesn't depend on which `[secrets]` defaults the
/// schema chooses.
fn secrets_for_test() -> SecretsConfig {
    SecretsConfig {
        keyring_service: "webvh-test".to_string(),
        ..SecretsConfig::default()
    }
}

#[tokio::test]
async fn phase2_seed_missing_when_phase1_not_run_yields_none() {
    // Phase 2 prerequisite: `get_bootstrap_seed` returns `None` against
    // a fresh config (no phase 1 run). This is the failure signal the
    // apply layer maps to the "phase 1 may not have run" error.
    let dir = temp_dir();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "").unwrap();

    let secrets_cfg = secrets_for_test();
    let store = create_secret_store(&secrets_cfg, &config_path).expect("plaintext store");
    assert!(
        store.get_bootstrap_seed().await.unwrap().is_none(),
        "no phase 1 ran — seed must be absent"
    );
}

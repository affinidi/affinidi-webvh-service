//! Backend mapping, the no-keychain refusal, and the plaintext gate.
//!
//! Round-trips use the plaintext backend with `confirm_plaintext`, because CI
//! has no keyring. The keyring round-trip at the bottom runs only where a
//! credential store exists (CI's `keyring-required` job).

use super::*;
use crate::server::setup_recipe::{
    AdminSection, DaemonSection, DeploymentSection, IdentitySection, OutputSection,
    ReprovisionSection, SecretsBackend, SecretsSection, ServerSection, ServiceKind, SetupRecipe,
    VtaMode, VtaSection, WatcherSection,
};

fn recipe_with(secrets: SecretsSection) -> SetupRecipe {
    SetupRecipe {
        deployment: DeploymentSection {
            service: ServiceKind::Server,
            vta_mode: VtaMode::Online,
        },
        output: OutputSection {
            config_path: "config.toml".into(),
        },
        server: ServerSection::default(),
        identity: IdentitySection::default(),
        vta: VtaSection::default(),
        secrets,
        admin: AdminSection::default(),
        reprovision: ReprovisionSection::default(),
        watcher: WatcherSection::default(),
        daemon: DaemonSection::default(),
    }
}

fn sample() -> ServerSecrets {
    ServerSecrets {
        signing_key: "z6Mksigning_test".into(),
        key_agreement_key: "z6LSagreement_test".into(),
        jwt_signing_key: "z6Mkjwt_test".into(),
        vta_credential: Some("test-vta-blob".into()),
        retired: Vec::new(),
    }
}

fn plaintext_config() -> SecretsConfig {
    SecretsConfig {
        backend: Some(SecretBackend::Plaintext),
        confirm_plaintext: true,
        ..SecretsConfig::default()
    }
}

// `Box<dyn SecretStore>` is not `Debug`, so `expect_err` won't compile.
fn store_err(secrets: &SecretsConfig, config_path: &Path) -> AppError {
    match create_secret_store(secrets, config_path) {
        Ok(_) => panic!("expected an error, got a store"),
        Err(e) => e,
    }
}

// ---- config mapping, one test per backend ----

#[test]
fn keyring_maps_service_name() {
    let secrets = SecretsConfig {
        keyring_service: "webvh-a".into(),
        ..SecretsConfig::default()
    };
    let vti = to_vti_config(&secrets).unwrap();
    assert_eq!(
        vti.backend,
        Some(SecretBackend::Keyring),
        "keyring is the default"
    );
    assert_eq!(vti.keyring_service, "webvh-a");
    assert!(!vti.allow_plaintext);
}

#[test]
fn aws_maps_name_and_region() {
    let secrets = SecretsConfig {
        aws_secret_name: Some("webvh/prod".into()),
        aws_region: Some("ap-southeast-1".into()),
        ..SecretsConfig::default()
    };
    let vti = to_vti_config(&secrets).unwrap();
    assert_eq!(vti.backend, Some(SecretBackend::Aws));
    assert_eq!(vti.aws_secret_name.as_deref(), Some("webvh/prod"));
    assert_eq!(vti.aws_region.as_deref(), Some("ap-southeast-1"));
}

#[test]
fn gcp_maps_project_and_name_and_requires_project() {
    let mut secrets = SecretsConfig {
        gcp_secret_name: Some("webvh".into()),
        ..SecretsConfig::default()
    };
    assert!(
        matches!(to_vti_config(&secrets), Err(AppError::Config(m)) if m.contains("gcp_project"))
    );
    secrets.gcp_project = Some("proj-1".into());
    let vti = to_vti_config(&secrets).unwrap();
    assert_eq!(vti.backend, Some(SecretBackend::Gcp));
    assert_eq!(vti.gcp_project.as_deref(), Some("proj-1"));
    assert_eq!(vti.gcp_secret_name.as_deref(), Some("webvh"));
}

#[test]
fn azure_maps_url_and_name_and_requires_url() {
    let mut secrets = SecretsConfig {
        azure_secret_name: Some("webvh".into()),
        ..SecretsConfig::default()
    };
    assert!(
        matches!(to_vti_config(&secrets), Err(AppError::Config(m)) if m.contains("azure_vault_url"))
    );
    secrets.azure_vault_url = Some("https://v.vault.azure.net/".into());
    let vti = to_vti_config(&secrets).unwrap();
    assert_eq!(vti.backend, Some(SecretBackend::Azure));
    assert_eq!(
        vti.azure_vault_url.as_deref(),
        Some("https://v.vault.azure.net/")
    );
    // Our secret name, never vti-secrets' `vta-master-seed` default.
    assert_eq!(vti.azure_secret_name.as_deref(), Some("webvh"));
}

#[test]
fn vault_maps_every_field() {
    let secrets = SecretsConfig {
        vault_addr: Some("https://vault:8200".into()),
        vault_secret_path: Some("webvh/server".into()),
        vault_kv_mount: "kv".into(),
        vault_secret_key: "envelope".into(),
        vault_namespace: Some("ns".into()),
        vault_auth_method: "approle".into(),
        vault_k8s_role: Some("role".into()),
        vault_k8s_mount: "k8s".into(),
        vault_k8s_jwt_path: "/jwt".into(),
        vault_token: Some("tok".into()),
        vault_approle_role_id: Some("rid".into()),
        vault_approle_secret_id: Some("sid".into()),
        vault_approle_mount: "ar".into(),
        vault_skip_verify: true,
        ..SecretsConfig::default()
    };
    let vti = to_vti_config(&secrets).unwrap();
    assert_eq!(vti.backend, Some(SecretBackend::Vault));
    assert_eq!(vti.vault_addr.as_deref(), Some("https://vault:8200"));
    assert_eq!(vti.vault_secret_path.as_deref(), Some("webvh/server"));
    assert_eq!(vti.vault_kv_mount, "kv");
    assert_eq!(vti.vault_secret_key, "envelope");
    assert_eq!(vti.vault_namespace.as_deref(), Some("ns"));
    assert_eq!(vti.vault_auth_method, "approle");
    assert_eq!(vti.vault_k8s_role.as_deref(), Some("role"));
    assert_eq!(vti.vault_k8s_mount, "k8s");
    assert_eq!(vti.vault_k8s_jwt_path, "/jwt");
    assert_eq!(vti.vault_token.as_deref(), Some("tok"));
    assert_eq!(vti.vault_approle_role_id.as_deref(), Some("rid"));
    assert_eq!(vti.vault_approle_secret_id.as_deref(), Some("sid"));
    assert_eq!(vti.vault_approle_mount, "ar");
    assert!(vti.vault_skip_verify);
}

#[test]
fn vault_requires_a_secret_path() {
    let secrets = SecretsConfig {
        vault_addr: Some("https://vault:8200".into()),
        ..SecretsConfig::default()
    };
    assert!(
        matches!(to_vti_config(&secrets), Err(AppError::Config(m)) if m.contains("vault_secret_path"))
    );
}

#[test]
fn kubernetes_maps_name_namespace_and_key() {
    let secrets = SecretsConfig {
        k8s_secret_name: Some("webvh-secrets".into()),
        k8s_namespace: Some("did".into()),
        k8s_secret_key: "envelope".into(),
        ..SecretsConfig::default()
    };
    let vti = to_vti_config(&secrets).unwrap();
    assert_eq!(vti.backend, Some(SecretBackend::Kubernetes));
    assert_eq!(vti.k8s_secret_name.as_deref(), Some("webvh-secrets"));
    assert_eq!(vti.k8s_namespace.as_deref(), Some("did"));
    assert_eq!(vti.k8s_secret_key, "envelope");
}

#[test]
fn plaintext_maps_to_allow_plaintext_only_when_confirmed() {
    let vti = to_vti_config(&plaintext_config()).unwrap();
    assert_eq!(vti.backend, Some(SecretBackend::Plaintext));
    assert!(vti.allow_plaintext);
}

#[test]
fn config_seed_is_refused() {
    let secrets = SecretsConfig {
        backend: Some(SecretBackend::ConfigSeed),
        ..SecretsConfig::default()
    };
    assert!(
        matches!(to_vti_config(&secrets), Err(AppError::Config(m)) if m.contains("config_seed"))
    );
}

#[test]
fn an_explicit_backend_beats_a_stray_selector_field() {
    let secrets = SecretsConfig {
        backend: Some(SecretBackend::Keyring),
        aws_secret_name: Some("left-over".into()),
        ..SecretsConfig::default()
    };
    let vti = to_vti_config(&secrets).unwrap();
    assert_eq!(vti.backend, Some(SecretBackend::Keyring));
    assert!(
        vti.aws_secret_name.is_none(),
        "only the selected backend's fields are copied"
    );
}

#[test]
fn implicit_resolution_follows_the_documented_order() {
    let mut s = SecretsConfig {
        k8s_secret_name: Some("k".into()),
        ..SecretsConfig::default()
    };
    assert_eq!(resolve_backend(&s), SecretBackend::Kubernetes);
    s.vault_addr = Some("v".into());
    assert_eq!(resolve_backend(&s), SecretBackend::Vault);
    s.azure_secret_name = Some("a".into());
    assert_eq!(resolve_backend(&s), SecretBackend::Azure);
    s.gcp_secret_name = Some("g".into());
    assert_eq!(resolve_backend(&s), SecretBackend::Gcp);
    s.aws_secret_name = Some("w".into());
    assert_eq!(resolve_backend(&s), SecretBackend::Aws);
    assert!(!is_plaintext_backend(&SecretsConfig::default()));
}

#[test]
fn every_recipe_backend_maps_onto_its_vti_backend() {
    let cases = [
        (SecretsBackend::Keyring, SecretBackend::Keyring),
        (SecretsBackend::Aws, SecretBackend::Aws),
        (SecretsBackend::Gcp, SecretBackend::Gcp),
        (SecretsBackend::Azure, SecretBackend::Azure),
        (SecretsBackend::Vault, SecretBackend::Vault),
        (SecretsBackend::K8s, SecretBackend::Kubernetes),
        (SecretsBackend::Plaintext, SecretBackend::Plaintext),
    ];
    for (recipe_backend, want) in cases {
        let recipe = recipe_with(SecretsSection {
            backend: Some(recipe_backend),
            gcp_project: Some("proj".into()),
            azure_vault_url: Some("https://v.vault.azure.net/".into()),
            vault_addr: Some("https://vault:8200".into()),
            confirm_plaintext: true,
            ..SecretsSection::default()
        });
        let cfg = crate::server::setup_recipe::resolve_secrets_config(&recipe, "webvh", "webvh");
        assert_eq!(cfg.backend, Some(want), "{recipe_backend:?}");
        let vti = to_vti_config(&cfg).unwrap_or_else(|e| panic!("{recipe_backend:?}: {e}"));
        assert_eq!(vti.backend, Some(want), "{recipe_backend:?}");
    }
}

// ---- a host with no keychain ----

#[test]
fn a_host_without_a_keychain_is_refused_with_the_secure_backends() {
    let err = keyring_gate(|| Err("no D-Bus session bus".into())).unwrap_err();
    let msg = err.to_string();
    for needle in [
        "no D-Bus session bus",
        "vault",
        "k8s",
        "aws",
        "gcp",
        "azure",
        "keyring",
        "Secret Service",
        "will not fall back",
        "confirm_plaintext",
    ] {
        assert!(
            msg.contains(needle),
            "refusal should mention {needle:?}:\n{msg}"
        );
    }
    assert!(keyring_gate(|| Ok(())).is_ok());
}

/// A binary built without `keyring` has no secure default: an unconfigured
/// `[secrets]` is refused, not quietly put in a plaintext file.
#[cfg(not(feature = "keyring"))]
#[test]
fn no_keyring_build_refuses_an_unconfigured_store() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let err = store_err(&SecretsConfig::default(), &config_path);
    assert!(err.to_string().contains("no secure secret store"), "{err}");
    assert!(!plaintext_path(&config_path).exists());
}

// ---- plaintext stays behind confirm_plaintext ----

#[test]
fn plaintext_without_confirmation_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let secrets = SecretsConfig {
        backend: Some(SecretBackend::Plaintext),
        ..SecretsConfig::default()
    };
    let err = store_err(&secrets, &config_path);
    assert!(
        matches!(&err, AppError::Config(m) if m.contains("confirm_plaintext")),
        "{err}"
    );
    // `confirm_plaintext` alone is not a request for plaintext.
    let confirmed_only = SecretsConfig {
        confirm_plaintext: true,
        ..SecretsConfig::default()
    };
    assert!(!is_plaintext_backend(&confirmed_only));
}

#[tokio::test]
async fn plaintext_round_trips_the_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("server.toml");
    let store = create_secret_store(&plaintext_config(), &config_path).unwrap();

    assert!(store.get().await.unwrap().is_none());
    assert!(store.get_bootstrap_seed().await.unwrap().is_none());

    // Phase 1 writes only the seed; the keys arrive later in the same entry.
    store.set_bootstrap_seed(&[7u8; 32]).await.unwrap();
    store.set(&sample()).await.unwrap();

    // A fresh store (a new process) sees both.
    let again = create_secret_store(&plaintext_config(), &config_path).unwrap();
    let got = again.get().await.unwrap().expect("secrets present");
    assert_eq!(got.signing_key, "z6Mksigning_test");
    assert_eq!(got.vta_credential.as_deref(), Some("test-vta-blob"));
    assert_eq!(again.get_bootstrap_seed().await.unwrap(), Some([7u8; 32]));

    // Clearing the seed keeps the keys.
    again.clear_bootstrap_seed().await.unwrap();
    assert!(again.get_bootstrap_seed().await.unwrap().is_none());
    assert!(again.get().await.unwrap().is_some());

    let path = plaintext_path(&config_path);
    assert_eq!(path, dir.path().join("server.secrets.plaintext"));
    assert!(path.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "plaintext secrets must be owner-only");
    }
}

#[test]
fn stored_secrets_debug_redacts_the_seed() {
    let env = StoredSecrets {
        secrets: Some(sample()),
        bootstrap_seed: Some(StoredSecrets::encode_seed(&[9u8; 32])),
    };
    let dbg = format!("{env:?}");
    assert!(!dbg.contains("z6Mksigning_test"), "{dbg}");
    assert!(
        !dbg.contains(&StoredSecrets::encode_seed(&[9u8; 32])),
        "{dbg}"
    );
}

// ---- keyring (CI's keyring-required job) ----

/// Round-trip through the OS credential store. Skipped where there is none,
/// unless `KEYRING_TEST_REQUIRED=1` (CI on macOS, and Linux under
/// gnome-keyring), where a skip is a failure.
#[cfg(feature = "keyring")]
#[tokio::test]
async fn keyring_round_trip_when_backend_available() {
    let required = std::env::var("KEYRING_TEST_REQUIRED").ok().as_deref() == Some("1");
    let secrets = SecretsConfig {
        keyring_service: format!("affinidi-webvh-test-{}", uuid::Uuid::new_v4()),
        ..SecretsConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let store = match create_secret_store(&secrets, &dir.path().join("config.toml")) {
        Ok(s) => s,
        Err(e) => {
            assert!(
                !required,
                "KEYRING_TEST_REQUIRED=1 but backend unavailable: {e}"
            );
            eprintln!("skipping keyring test — backend unavailable: {e}");
            return;
        }
    };
    if let Err(e) = store.set(&sample()).await {
        assert!(
            !required,
            "KEYRING_TEST_REQUIRED=1 but backend refused write: {e}"
        );
        eprintln!("skipping keyring test — backend refused write: {e}");
        return;
    }
    let loaded = store.get().await.unwrap().expect("secrets present");
    assert_eq!(loaded.jwt_signing_key, "z6Mkjwt_test");
    store.set_bootstrap_seed(&[7u8; 32]).await.unwrap();
    assert_eq!(store.get_bootstrap_seed().await.unwrap(), Some([7u8; 32]));
    store.clear_bootstrap_seed().await.unwrap();

    // Leave the operator's keyring tidy.
    let entry = keyring_core::Entry::new(&secrets.keyring_service, KEYRING_USER).unwrap();
    let _ = entry.delete_credential();
}
